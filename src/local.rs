//! Нагрузка самого роутера (перенос local.go) и местная перегрузка
//! (LOCAL_PRESSURE): условия должны держаться не меньше
//! local.pressure_duration_sec — секундные всплески CPU не в счёт.

use crate::config::LocalConfig;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LocalMetrics {
    pub cpu: f64,
    pub load1: f64,
    pub mem_available_mb: i64,
    pub num_cpu: i64,
    /// Самое загруженное ядро: сетевой softirq часто упирается в одно ядро.
    pub max_core_cpu: f64,
    pub max_core: String,
    pub max_core_softirq: f64,
}

#[derive(Clone, Copy, Default)]
struct CpuTimes {
    total: u64,
    idle: u64,
    softirq: u64,
}

/// cpuN user nice system idle iowait irq softirq steal …
fn parse_cpu_line(fields: &[&str]) -> CpuTimes {
    let mut t = CpuTimes::default();
    for (i, f) in fields.iter().enumerate().skip(1) {
        if i >= 9 {
            break; // guest/guest_nice уже входят в user/nice
        }
        let Ok(v) = f.parse::<u64>() else { continue };
        t.total += v;
        match i {
            4 | 5 => t.idle += v,
            7 => t.softirq += v,
            _ => {}
        }
    }
    t
}

#[derive(Default)]
pub struct Local {
    prev: Vec<(String, CpuTimes)>,
    pressure_since: Option<i64>,
    pub pressure_reason: String,
}

impl Local {
    pub fn read(&mut self) -> LocalMetrics {
        let mut m = LocalMetrics { num_cpu: num_cpus(), ..Default::default() };
        if let Ok(data) = std::fs::read_to_string("/proc/stat") {
            self.from_stat(&data, &mut m);
        }
        if let Ok(b) = std::fs::read_to_string("/proc/loadavg") {
            m.load1 = b.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
        }
        if let Ok(b) = std::fs::read_to_string("/proc/meminfo") {
            if let Some(l) = b.lines().find(|l| l.starts_with("MemAvailable:")) {
                m.mem_available_mb = l.split_whitespace().nth(1).and_then(|x| x.parse::<i64>().ok()).map_or(0, |kb| kb / 1024);
            }
        }
        m
    }

    fn from_stat(&mut self, data: &str, m: &mut LocalMetrics) {
        for line in data.lines() {
            if !line.starts_with("cpu") {
                break;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let name = fields[0];
            let cur = parse_cpu_line(&fields);
            let prev = match self.prev.iter_mut().find(|(n, _)| n == name) {
                Some(e) => std::mem::replace(&mut e.1, cur),
                None => {
                    self.prev.push((name.to_string(), cur));
                    continue;
                }
            };
            if cur.total <= prev.total {
                continue;
            }
            let dt = (cur.total - prev.total) as f64;
            let busy = (dt - cur.idle.saturating_sub(prev.idle) as f64) / dt * 100.0;
            if name == "cpu" {
                m.cpu = busy;
                continue;
            }
            if busy > m.max_core_cpu {
                m.max_core_cpu = busy;
                m.max_core = name.to_string();
                m.max_core_softirq = cur.softirq.saturating_sub(prev.softirq) as f64 / dt * 100.0;
            }
        }
    }

    /// Причины перегрузки (пусто — нет). ct: (usage %, текущее, максимум) conntrack.
    pub fn reasons(cfg: &LocalConfig, l: &LocalMetrics, ct: (f64, i64, i64)) -> Vec<String> {
        let mut r = Vec::new();
        if cfg.cpu_threshold_percent > 0.0 && l.cpu > cfg.cpu_threshold_percent {
            r.push(format!("cpu {:.0}% > {:.0}% (avg {} cores)", l.cpu, cfg.cpu_threshold_percent, l.num_cpu));
        }
        if cfg.core_threshold_percent > 0.0 && l.max_core_cpu > cfg.core_threshold_percent {
            r.push(format!("{} {:.0}% > {:.0}% (softirq {:.0}%)", l.max_core, l.max_core_cpu, cfg.core_threshold_percent, l.max_core_softirq));
        }
        if cfg.conntrack_threshold_percent > 0.0 && ct.0 > cfg.conntrack_threshold_percent {
            r.push(format!("conntrack {:.0}% > {:.0}% ({}/{})", ct.0, cfg.conntrack_threshold_percent, ct.1, ct.2));
        }
        if cfg.load_per_core > 0.0 && l.load1 > l.num_cpu as f64 * cfg.load_per_core {
            r.push(format!("load1 {:.2} > {:.2} ({} cores x {:.1})", l.load1, l.num_cpu as f64 * cfg.load_per_core, l.num_cpu, cfg.load_per_core));
        }
        if cfg.min_memory_mb > 0 && l.mem_available_mb > 0 && l.mem_available_mb < cfg.min_memory_mb {
            r.push(format!("mem {} MB < {} MB", l.mem_available_mb, cfg.min_memory_mb));
        }
        r
    }

    /// Перегрузка — только если держится pressure_duration_sec подряд (now — мс).
    pub fn update_pressure(&mut self, cfg: &LocalConfig, now: i64, l: &LocalMetrics, ct: (f64, i64, i64)) -> bool {
        let reasons = Self::reasons(cfg, l, ct);
        if reasons.is_empty() {
            self.pressure_since = None;
            self.pressure_reason.clear();
            return false;
        }
        let since = *self.pressure_since.get_or_insert(now);
        if now - since < cfg.pressure_duration_sec * 1000 {
            self.pressure_reason.clear();
            return false;
        }
        self.pressure_reason = reasons.join("; ");
        true
    }
}

pub fn num_cpus() -> i64 {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 {
        n as i64
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_debounce_and_reason() {
        // TestLocalPressureDebounceAndReason из Go
        let mut c = crate::config::defaults();
        c.normalize();
        let mut cfg = c.local.clone();
        cfg.pressure_duration_sec = 10;
        cfg.core_threshold_percent = 95.0;
        let busy = LocalMetrics { cpu: 97.0, num_cpu: 4, max_core_cpu: 99.0, max_core: "cpu2".into(), max_core_softirq: 80.0, mem_available_mb: 1000, ..Default::default() };
        let idle = LocalMetrics { cpu: 10.0, num_cpu: 4, max_core_cpu: 20.0, max_core: "cpu0".into(), mem_available_mb: 1000, ..Default::default() };
        let mut l = Local::default();
        let ct = (0.0, 0, 0);
        assert!(!l.update_pressure(&cfg, 0, &busy, ct));
        l.update_pressure(&cfg, 5000, &idle, ct);
        assert!(!l.update_pressure(&cfg, 12000, &busy, ct));
        assert!(l.update_pressure(&cfg, 22000, &busy, ct));
        assert_eq!(l.pressure_reason, "cpu 97% > 90% (avg 4 cores); cpu2 99% > 95% (softirq 80%)");
    }

    #[test]
    fn stat_delta() {
        let mut l = Local::default();
        let mut m = LocalMetrics::default();
        l.from_stat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0\n", &mut m);
        l.from_stat("cpu  200 0 200 1000 0 0 0 0 0 0\ncpu0 150 0 50 400 0 0 20 0\ncpu1 50 0 50 500 0 0 0 0\n", &mut m);
        assert!((m.cpu - 50.0).abs() < 0.01);
        assert_eq!(m.max_core, "cpu0");
        assert!((m.max_core_cpu - 100.0).abs() < 0.01);
    }
}
