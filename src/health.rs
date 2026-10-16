//! Фаза WAN и диагноз (перенос Engine.evaluateHealth): NORMAL → WARNING /
//! CRITICAL по доле успешных проб IPv4 с выдержкой enter_duration_sec,
//! RECOVERY после recovery_duration_sec хороших. Выход решает только IPv4:
//! IPv6 — контрольный канал для диагноза.

use crate::config::ThresholdsConfig;
use crate::prober::ProbeStats;

#[derive(Clone, Debug, PartialEq)]
pub struct Health {
    pub phase: &'static str,
    pub diagnosis: &'static str,
    warning_since: Option<i64>,
    critical_since: Option<i64>,
    good_since: Option<i64>,
}

impl Default for Health {
    fn default() -> Self {
        Health { phase: "NORMAL", diagnosis: "UNKNOWN", warning_since: None, critical_since: None, good_since: None }
    }
}

pub fn v6_healthy(t: &ThresholdsConfig, v6: &ProbeStats) -> bool {
    !v6.available || (v6.count > 0 && v6.success_rate >= t.ipv6_healthy_success)
}

fn track(flag: bool, since: &mut Option<i64>, now: i64) {
    if flag {
        since.get_or_insert(now);
    } else {
        *since = None;
    }
}

impl Health {
    /// now — мс; grace — идёт стартовая выдержка.
    pub fn evaluate(&mut self, t: &ThresholdsConfig, now: i64, grace: bool, v4: &ProbeStats, v6: &ProbeStats, local_pressure: bool) {
        if grace {
            self.diagnosis = "MONITORING_ONLY";
            return;
        }
        if local_pressure {
            self.diagnosis = "LOCAL_PRESSURE";
            self.warning_since = None;
            self.critical_since = None;
            self.good_since = None;
            return;
        }
        if v4.count == 0 {
            self.diagnosis = "UNKNOWN";
            return;
        }
        let v6ok = v6_healthy(t, v6);
        let warning = v4.success_rate < t.warning_enter_success;
        let critical = v4.success_rate < t.critical_enter_success;
        let good = v4.success_rate >= t.recovery_success;
        track(critical, &mut self.critical_since, now);
        track(warning, &mut self.warning_since, now);
        track(good, &mut self.good_since, now);
        let enter = t.enter_duration_sec * 1000;
        let recovery = t.recovery_duration_sec * 1000;
        let held = |s: Option<i64>, d: i64| s.map_or(false, |s| now - s >= d);

        match self.phase {
            "NORMAL" => {
                if held(self.critical_since, enter) {
                    self.phase = "CRITICAL";
                } else if held(self.warning_since, enter) {
                    self.phase = "WARNING";
                }
            }
            "WARNING" => {
                if held(self.critical_since, enter) {
                    self.phase = "CRITICAL";
                }
            }
            "CRITICAL" => {
                if held(self.good_since, recovery) {
                    self.phase = "RECOVERY";
                }
            }
            "RECOVERY" => {
                if warning {
                    self.phase = "WARNING";
                    self.good_since = None;
                }
            }
            _ => self.phase = "NORMAL",
        }
        if (self.phase == "WARNING" || self.phase == "CRITICAL") && held(self.good_since, recovery) {
            self.phase = "RECOVERY";
        }
        self.diagnosis = if self.phase == "WARNING" || self.phase == "CRITICAL" {
            if v6ok {
                "IPV4_EXTERNAL_DEGRADATION"
            } else {
                "UNKNOWN"
            }
        } else if v4.success_rate >= t.warning_enter_success && v6.available && v6.count > 0 && v6.success_rate < t.ipv6_healthy_success {
            "IPV6_DEGRADATION"
        } else if good && v6ok {
            "HEALTHY"
        } else {
            "UNKNOWN"
        };
    }

    /// Лимит снят во время RECOVERY — сразу NORMAL (как в Go applyLimiter).
    pub fn set_normal(&mut self) {
        self.phase = "NORMAL";
    }

    #[cfg(test)]
    pub fn with_phase(phase: &'static str) -> Health {
        Health { phase, ..Default::default() }
    }
}

#[cfg(test)]
mod tests {
    //! Тесты состояний из Go engine_test.go — один в один.
    use super::*;

    fn th() -> ThresholdsConfig {
        let mut c = crate::config::defaults();
        c.normalize();
        let mut t = c.thresholds;
        t.enter_duration_sec = 30;
        t.recovery_duration_sec = 300;
        t
    }

    fn ps(success: f64, count: i64, available: bool) -> ProbeStats {
        ProbeStats { available, count, success_rate: success, ..Default::default() }
    }

    const S: i64 = 1000;

    #[test]
    fn warning_hysteresis() {
        let (t, mut h) = (th(), Health::default());
        let (v4, v6) = (ps(90.0, 10, true), ps(100.0, 10, true));
        h.evaluate(&t, 0, false, &v4, &v6, false);
        assert_eq!(h.phase, "NORMAL");
        h.evaluate(&t, 31 * S, false, &v4, &v6, false);
        assert_eq!(h.phase, "WARNING");
        assert_eq!(h.diagnosis, "IPV4_EXTERNAL_DEGRADATION");
    }

    #[test]
    fn critical_and_recovery() {
        let (t, mut h) = (th(), Health::default());
        let v6 = ps(100.0, 10, true);
        h.evaluate(&t, 0, false, &ps(90.0, 10, true), &v6, false);
        h.evaluate(&t, 31 * S, false, &ps(90.0, 10, true), &v6, false);
        assert_eq!(h.phase, "WARNING");
        h.evaluate(&t, 40 * S, false, &ps(70.0, 10, true), &v6, false);
        h.evaluate(&t, 71 * S, false, &ps(70.0, 10, true), &v6, false);
        assert_eq!(h.phase, "CRITICAL");
        h.evaluate(&t, 110 * S, false, &ps(99.0, 10, true), &v6, false);
        h.evaluate(&t, 411 * S, false, &ps(99.0, 10, true), &v6, false);
        assert_eq!(h.phase, "RECOVERY");
    }

    #[test]
    fn no_ipv6_still_detects_v4() {
        let (t, mut h) = (th(), Health::default());
        let v6 = ProbeStats::default();
        h.evaluate(&t, 0, false, &ps(90.0, 10, true), &v6, false);
        h.evaluate(&t, 31 * S, false, &ps(90.0, 10, true), &v6, false);
        assert_eq!((h.phase, h.diagnosis), ("WARNING", "IPV4_EXTERNAL_DEGRADATION"));
    }

    #[test]
    fn ipv6_bad_makes_unknown() {
        let (t, mut h) = (th(), Health::default());
        let v6 = ps(50.0, 10, true);
        h.evaluate(&t, 0, false, &ps(90.0, 10, true), &v6, false);
        h.evaluate(&t, 31 * S, false, &ps(90.0, 10, true), &v6, false);
        assert_eq!((h.phase, h.diagnosis), ("WARNING", "UNKNOWN"));
    }

    #[test]
    fn local_pressure_blocks_enter() {
        let (t, mut h) = (th(), Health::default());
        let v6 = ps(100.0, 10, true);
        h.evaluate(&t, 0, false, &ps(70.0, 10, true), &v6, true);
        h.evaluate(&t, 31 * S, false, &ps(70.0, 10, true), &v6, true);
        assert_eq!((h.phase, h.diagnosis), ("NORMAL", "LOCAL_PRESSURE"));
    }

    #[test]
    fn startup_grace() {
        let (t, mut h) = (th(), Health::default());
        h.evaluate(&t, 0, true, &ps(50.0, 10, true), &ps(100.0, 10, true), false);
        assert_eq!((h.phase, h.diagnosis), ("NORMAL", "MONITORING_ONLY"));
    }

    #[test]
    fn broken_ipv6_does_not_block_recovery() {
        let (t, mut h) = (th(), Health::with_phase("CRITICAL"));
        let (v4, v6) = (ps(100.0, 10, true), ps(0.0, 10, true));
        h.evaluate(&t, 0, false, &v4, &v6, false);
        h.evaluate(&t, 301 * S, false, &v4, &v6, false);
        assert_eq!((h.phase, h.diagnosis), ("RECOVERY", "IPV6_DEGRADATION"));
    }
}
