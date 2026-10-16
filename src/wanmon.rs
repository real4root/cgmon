//! WAN-монитор (перенос wanmon.go): поднят ли WAN (есть устройство маршрута по
//! умолчанию и адреса), смена IP и устройства, «линк есть, пробы 0%».
//! События — в журнал wan_monitor.incidents_file (wan_event).

use crate::incidents::append_jsonl;
use crate::json::J;
use crate::prober::ProbeStats;
use crate::util;

#[derive(Clone, Debug, PartialEq)]
pub struct WanEvent {
    pub time: (i64, u32),
    pub typ: &'static str,
    pub msg: String,
    pub ip: String,
    pub iface: String,
}

#[derive(Default)]
pub struct WanMon {
    pub up: bool,
    last_ip_key: String,
    last_iface: String,
    down_since: Option<i64>,
    probe_down: bool,
    probe_since: Option<i64>,
    pub last_up_at: Option<i64>,
    events: Vec<WanEvent>,
    started: bool,
}

impl WanMon {
    fn push(&mut self, file: &str, ev: WanEvent, out: &mut Vec<WanEvent>) {
        crate::log_info!("wan: {}", ev.msg);
        let mut j = J::new();
        j.obj().key("event").str(ev.typ).key("iface").str(&ev.iface).key("ip").str(&ev.ip).key("msg").str(&ev.msg);
        j.key("time").str(&util::rfc3339_secs(ev.time.0)).key("type").str("wan_event").end_obj();
        append_jsonl(file, &j.b, 2 << 20);
        self.events.push(ev.clone());
        if self.events.len() > 200 {
            self.events.drain(..self.events.len() - 200);
        }
        out.push(ev);
    }

    /// Такт: now — (unix, нс); ips — адреса WAN; iface — устройство маршрута по умолчанию.
    pub fn tick(&mut self, enabled: bool, debounce_sec: i64, file: &str, now: (i64, u32), ips: &[String], iface: &str, v4: &ProbeStats) -> Vec<WanEvent> {
        let mut out = Vec::new();
        if !enabled {
            return out;
        }
        let present = !iface.is_empty() && !ips.is_empty();
        let mut sorted = ips.to_vec();
        sorted.sort();
        let ip_key = sorted.join(",");
        let t = now.0;
        let ev = |typ: &'static str, msg: String, ip: &str, ifc: &str| WanEvent { time: now, typ, msg, ip: ip.into(), iface: ifc.into() };
        // первый такт: запомнить состояние без событий
        if !self.started {
            self.started = true;
            self.up = present;
            self.last_ip_key = ip_key;
            self.last_iface = iface.into();
            if present {
                self.last_up_at = Some(t);
            }
            return out;
        }
        if self.up {
            if !present {
                let since = *self.down_since.get_or_insert(t);
                if t - since >= debounce_sec {
                    self.push(file, ev("down", "INTERNET is DOWN".into(), "", ""), &mut out);
                    self.up = false;
                    self.down_since = None;
                    self.probe_down = false;
                    self.probe_since = None;
                }
            } else {
                self.down_since = None;
                if ip_key != self.last_ip_key {
                    self.push(file, ev("new_ip", format!("NEW IP ({ip_key}) ON INTERFACE {iface}"), &ip_key, iface), &mut out);
                    self.last_ip_key = ip_key.clone();
                    self.last_up_at = Some(t);
                }
                if iface != self.last_iface {
                    self.push(file, ev("iface", format!("DEFAULT WAN IFACE {} -> {}", self.last_iface, iface), "", iface), &mut out);
                    self.last_iface = iface.into();
                    self.last_up_at = Some(t);
                }
                // линк есть, но пробы не проходят вообще
                if v4.count > 0 && v4.success_rate == 0.0 {
                    let since = *self.probe_since.get_or_insert(t);
                    if !self.probe_down && t - since >= debounce_sec {
                        self.push(file, ev("probe_down", "INTERNET UNREACHABLE (ipv4 probes 0%)".into(), "", ""), &mut out);
                        self.probe_down = true;
                    }
                } else {
                    if self.probe_down {
                        self.push(file, ev("probe_up", "INTERNET REACHABLE again (ipv4 probes ok)".into(), "", ""), &mut out);
                        self.probe_down = false;
                    }
                    self.probe_since = None;
                }
            }
        } else if present {
            self.push(file, ev("up", "INTERNET is UP".into(), "", iface), &mut out);
            self.up = true;
            if ip_key != self.last_ip_key {
                self.push(file, ev("new_ip", format!("NEW IP ({ip_key}) ON INTERFACE {iface}"), &ip_key, iface), &mut out);
                self.last_ip_key = ip_key;
            }
            self.last_iface = iface.into();
            self.last_up_at = Some(t);
        }
        out
    }

    /// Окно после WAN UP / смены IP (шторм переподключений): лимитер молчит.
    pub fn post_up_grace(&self, enabled: bool, grace_sec: i64, now: i64) -> bool {
        enabled && grace_sec > 0 && self.last_up_at.map_or(false, |t| now - t < grace_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_up_ip_iface() {
        let mut w = WanMon::default();
        let v4 = ProbeStats { count: 5, success_rate: 100.0, ..Default::default() };
        let ips = vec!["198.51.100.7".to_string()];
        let tk = |w: &mut WanMon, t: i64, ips: &[String], ifc: &str| w.tick(true, 15, "", (t, 0), ips, ifc, &v4);
        assert!(tk(&mut w, 0, &ips, "wan0").is_empty());
        assert!(tk(&mut w, 10, &[], "").is_empty()); // дребезг
        let e = tk(&mut w, 26, &[], "");
        assert_eq!(e[0].typ, "down");
        let e = tk(&mut w, 30, &["198.51.100.8".into()], "wan1");
        assert_eq!(e.iter().map(|x| x.typ).collect::<Vec<_>>(), vec!["up", "new_ip"]);
        let e = tk(&mut w, 40, &["198.51.100.8".into()], "wan2");
        assert_eq!(e[0].msg, "DEFAULT WAN IFACE wan1 -> wan2");
        assert!(w.post_up_grace(true, 60, 50));
    }
}
