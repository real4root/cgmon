//! Активные пробы WAN (перенос prober.go): TCP к целям IPv4/IPv6 (и пиры
//! через overlay — семейство "peer:<имя>", RST = жив), UDP DNS к udp_v4/v6.
//! Раунд — все цели сразу неблокирующими сокетами в общем epoll.
//! IPv6 привязывается к глобальному адресу WAN (DHCPv6 ставит маршруты
//! «default from <префикс>» — без источника пакет уходит по ip rule дальше).

use crate::config::Config;
use crate::evloop::Poller;
use crate::netx;
use crate::probe::{Kind, Outcome, Probe};
use crate::util;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProbeStats {
    pub available: bool,
    pub count: i64,
    pub success_rate: f64,
    pub timeout_rate: f64,
    pub avg_latency_ms: f64,
    /// active | traffic (режим контроля WAN)
    pub source: &'static str,
    pub p90_ms: f64,
    pub loss_pct: f64,
    pub window_sec: i64,
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub mono: u64,
    pub wall: (i64, u32),
    pub family: String,
    pub endpoint: String,
    pub success: bool,
    pub latency_ns: u64,
    pub error: String,
    pub timeout: bool,
    pub refused: bool,
    pub unreachable: bool,
}

struct InFlight {
    p: Probe,
    family: String,
    endpoint: String,
}

pub struct Prober {
    /// режим контроля WAN: active | passive | hybrid (без SynRTT — active)
    pub mode: String,
    last_probe: [u64; 2],
    results: Vec<ProbeResult>,
    flight: HashMap<u64, InFlight>,
    next: u64,
    tok_base: u64,
    pub ipv6_available: bool,
    v6src: Option<IpAddr>,
    v6src_at: u64,
    rng: u64,
}

/// Цель в виде адрес:порт (по умолчанию :443), как normalizeEndpoint в Go.
pub fn normalize_endpoint(ep: &str, v6: bool) -> String {
    let ep = ep.trim();
    if ep.is_empty() {
        return String::new();
    }
    if v6 && !ep.starts_with('[') && ep.matches(':').count() >= 2 {
        return format!("[{ep}]:443");
    }
    if v6 && ep.starts_with('[') && !ep.contains("]:") {
        return format!("{ep}:443");
    }
    if ep.contains(':') {
        return ep.to_string();
    }
    format!("{ep}:443")
}

fn errtext(kind: Kind, family: &str, ep: &str, o: Outcome) -> String {
    let net = match (kind, family) {
        (Kind::Udp, "udp6") => "udp6",
        (Kind::Udp, _) => "udp4",
        (_, "ipv6") => "tcp6",
        (_, "ipv4") => "tcp4",
        _ => "tcp",
    };
    let what = match o {
        Outcome::Timeout => "i/o timeout".to_string(),
        Outcome::Refused => "connect: connection refused".into(),
        Outcome::Unreachable => "connect: network is unreachable".into(),
        Outcome::Fail(e) => format!("connect: {}", std::io::Error::from_raw_os_error(e)),
        Outcome::Ok => String::new(),
    };
    format!("{} {} {}: {}", if kind == Kind::Udp { "read" } else { "dial" }, net, ep, what)
}

impl Prober {
    pub fn new(cfg: &Config, tok_base: u64) -> Prober {
        let mut p = Prober { mode: "active".into(), last_probe: [0; 2], results: Vec::new(), flight: HashMap::new(), next: 0, tok_base, ipv6_available: false, v6src: None, v6src_at: 0, rng: 0x9e3779b97f4a7c15 ^ crate::evloop::now_ms() };
        p.ipv6_available = p.detect_ipv6(cfg, crate::evloop::now_ms());
        p
    }

    pub fn owns(&self, tok: u64) -> bool {
        tok & !0xffff_ffff == self.tok_base
    }

    /// Глобальный IPv6 WAN для привязки (кэш 30 с; None — без привязки).
    pub fn wan_ipv6_src(&mut self, now: u64) -> Option<IpAddr> {
        if self.v6src_at != 0 && now - self.v6src_at < 30_000 {
            return self.v6src;
        }
        self.v6src_at = now.max(1);
        self.v6src = None;
        let mut devs = vec![netx::default_route_interface()];
        devs.extend(netx::ipv6_default_devices());
        let addrs = netx::if_addrs();
        for d in devs {
            if d.is_empty() || d == "lo" || d.starts_with("tailscale") || d.starts_with("zt") || d.starts_with("wg") {
                continue;
            }
            if let Some((_, ip, _)) = addrs.iter().find(|(n, ip, _)| *n == d && netx::is_public_ipv6(ip)) {
                self.v6src = Some(*ip);
                break;
            }
        }
        self.v6src
    }

    fn detect_ipv6(&mut self, cfg: &Config, now: u64) -> bool {
        let src = self.wan_ipv6_src(now);
        let mut literal = false;
        for ep in cfg.probes.ipv6.iter().chain(&cfg.probes.udp_v6) {
            let ep = normalize_endpoint(ep, true);
            let Some((host, _)) = netx::split_host_port(&ep) else { continue };
            let Some(ip @ IpAddr::V6(_)) = netx::parse_ip(host) else { continue };
            if netx::to4(&ip).is_some() {
                continue;
            }
            literal = true;
            if netx::routable_ipv6(&ip, src.as_ref()) {
                return true;
            }
        }
        if literal {
            return false;
        }
        // пробы заданы именами — грубо: глобальный адрес и маршрут ::/0
        netx::if_addrs().iter().any(|(_, ip, _)| netx::is_public_ipv6(ip)) && netx::has_ipv6_default_route()
    }

    fn rand(&mut self) -> f64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    fn push(&mut self, r: ProbeResult) {
        self.results.push(r);
    }

    fn simulate(&mut self, family: &str, success: f64, count: usize, now: u64) {
        let wall = util::now_wall();
        for _ in 0..count {
            let ok = self.rand() * 100.0 < success;
            self.push(ProbeResult { mono: now, wall, family: family.into(), endpoint: "simulation".into(), success: ok, latency_ns: 20_000_000, error: String::new(), timeout: false, refused: false, unreachable: false });
        }
    }

    fn start_one(&mut self, poller: &Poller, kind: Kind, family: &str, endpoint: &str, now: u64) {
        let src = if family == "ipv6" || family == "udp6" { self.wan_ipv6_src(now) } else { None };
        let addr: Option<SocketAddr> = endpoint.parse().ok();
        let res = match addr {
            Some(a) => Probe::start(kind, a, src, now),
            None => Err(Outcome::Unreachable), // имя вместо адреса — в 2.x цели только адресами
        };
        match res {
            Ok(p) => {
                self.next += 1;
                let tok = self.tok_base | (self.next & 0xffff_ffff);
                if poller.add(p.fd, p.events(), tok).is_ok() {
                    self.flight.insert(tok, InFlight { p, family: family.into(), endpoint: endpoint.into() });
                }
            }
            Err(o) => self.done(kind, family, endpoint, o, 0, now),
        }
    }

    fn done(&mut self, kind: Kind, family: &str, endpoint: &str, o: Outcome, lat_ms: u64, now: u64) {
        let peer = family.starts_with("peer:");
        let mut r = ProbeResult { mono: now, wall: util::now_wall(), family: family.into(), endpoint: endpoint.into(), success: o == Outcome::Ok, latency_ns: lat_ms * 1_000_000, error: String::new(), timeout: o == Outcome::Timeout, refused: o == Outcome::Refused, unreachable: o == Outcome::Unreachable };
        if o != Outcome::Ok {
            r.error = errtext(kind, family, endpoint, o);
            // для пиров важна живость пути: RST — пакеты дошли
            if peer && o == Outcome::Refused {
                r.success = true;
            }
        }
        self.push(r);
    }

    /// Исходы рукопожатий реального трафика как ProbeStats.
    pub fn traffic_stats(&self, family: &str, window_sec: i64, now: u64, syn: &crate::synrtt::SynRtt) -> ProbeStats {
        let mut st = ProbeStats { available: family == "ipv4" || self.ipv6_available, window_sec, source: "traffic", ..Default::default() };
        if !st.available {
            return st;
        }
        let ss = syn.stats(family, window_sec as u64 * 1000, now);
        st.count = ss.count;
        st.success_rate = ss.success_rate;
        st.timeout_rate = if ss.count == 0 { 0.0 } else { 100.0 - ss.success_rate };
        st.avg_latency_ms = ss.median_ms;
        st.p90_ms = ss.p90_ms;
        st.loss_pct = ss.loss_pct;
        st
    }

    /// Трафика достаточно и он здоров (хвост задержки < 1 с).
    fn healthy(st: &ProbeStats, min_success: f64) -> bool {
        st.count > 0 && st.success_rate >= min_success && st.p90_ms < 1000.0
    }

    /// Гибрид при здоровом трафике: контрольная проба раз в 30 с.
    fn hybrid_due(&mut self, i: usize, now: u64) -> bool {
        if now - self.last_probe[i] < 30_000 && self.last_probe[i] != 0 {
            return false;
        }
        self.last_probe[i] = now;
        true
    }

    /// Пропустить семейство в этом раунде (passive / здоровый гибрид).
    pub fn skip(&mut self, cfg: &Config, family: &str, now: u64, syn: Option<&crate::synrtt::SynRtt>) -> bool {
        let Some(syn) = syn else { return false };
        match self.mode.as_str() {
            "passive" => true,
            "hybrid" => {
                let tr = self.traffic_stats(family, cfg.stat_window_sec, now, syn);
                Self::healthy(&tr, cfg.thresholds.warning_enter_success) && !self.hybrid_due(if family == "ipv6" { 1 } else { 0 }, now)
            }
            _ => false,
        }
    }

    /// Раунд TCP: IPv4, IPv6 (если доступен), пиры.
    pub fn round_tcp(&mut self, cfg: &Config, poller: &Poller, now: u64, skip4: bool, skip6: bool) {
        if cfg.simulation.enabled {
            let s = &cfg.simulation;
            self.ipv6_available = !cfg.probes.ipv6.is_empty() || s.ipv6_success > 0.0;
            let n4 = if cfg.probes.ipv4.is_empty() { 3 } else { cfg.probes.ipv4.len() };
            self.simulate("ipv4", s.ipv4_success, n4, now);
            if self.ipv6_available {
                let n6 = if cfg.probes.ipv6.is_empty() { 2 } else { cfg.probes.ipv6.len() };
                self.simulate("ipv6", s.ipv6_success, n6, now);
            }
            self.prune(cfg, now);
            return;
        }
        self.ipv6_available = self.detect_ipv6(cfg, now);
        for ep in cfg.probes.ipv4.iter().filter(|_| !skip4) {
            let ep = normalize_endpoint(ep, false);
            if !ep.is_empty() {
                self.start_one(poller, Kind::Tcp, "ipv4", &ep, now);
            }
        }
        if self.ipv6_available && !skip6 {
            for ep in &cfg.probes.ipv6 {
                let ep = normalize_endpoint(ep, true);
                if !ep.is_empty() {
                    self.start_one(poller, Kind::Tcp, "ipv6", &ep, now);
                }
            }
        }
        for p in &cfg.peers.list {
            if !p.name.is_empty() && !p.probe.is_empty() {
                self.start_one(poller, Kind::Tcp, &format!("peer:{}", p.name), &p.probe, now);
            }
        }
        self.prune(cfg, now);
    }

    /// Раунд UDP (DNS-запрос к udp_v4/udp_v6).
    pub fn round_udp(&mut self, cfg: &Config, poller: &Poller, now: u64) {
        if self.mode == "passive" {
            return;
        }
        if cfg.simulation.enabled {
            let s = &cfg.simulation;
            let n4 = if cfg.probes.udp_v4.is_empty() { 3 } else { cfg.probes.udp_v4.len() };
            self.simulate("udp4", s.ipv4_success, n4, now);
            if self.ipv6_available {
                let n6 = if cfg.probes.udp_v6.is_empty() { 2 } else { cfg.probes.udp_v6.len() };
                self.simulate("udp6", s.ipv6_success, n6, now);
            }
            self.prune(cfg, now);
            return;
        }
        self.ipv6_available = self.detect_ipv6(cfg, now);
        for ep in &cfg.probes.udp_v4 {
            let ep = ep.trim().to_string();
            if !ep.is_empty() {
                self.start_one(poller, Kind::Udp, "udp4", &ep, now);
            }
        }
        if self.ipv6_available {
            for ep in &cfg.probes.udp_v6 {
                let ep = ep.trim().to_string();
                if !ep.is_empty() {
                    self.start_one(poller, Kind::Udp, "udp6", &ep, now);
                }
            }
        }
        self.prune(cfg, now);
    }

    /// Событие сокета пробы.
    pub fn on_event(&mut self, tok: u64, poller: &Poller, now: u64) {
        if let Some(f) = self.flight.remove(&tok) {
            poller.del(f.p.fd);
            let o = f.p.finish();
            let lat = now.saturating_sub(f.p.started);
            self.done(f.p.kind, &f.family, &f.endpoint, o, lat, now);
        }
    }

    /// Таймауты (probe_timeout_sec) — ближайший срок для ожидания epoll.
    pub fn sweep(&mut self, cfg: &Config, poller: &Poller, now: u64) -> u64 {
        let to = (cfg.probe_timeout_sec.max(1) as u64) * 1000;
        let late: Vec<u64> = self.flight.iter().filter(|(_, f)| now - f.p.started >= to).map(|(t, _)| *t).collect();
        for t in late {
            if let Some(f) = self.flight.remove(&t) {
                poller.del(f.p.fd);
                self.done(f.p.kind, &f.family, &f.endpoint, Outcome::Timeout, now - f.p.started, now);
            }
        }
        self.flight.values().map(|f| (f.p.started + to).saturating_sub(now)).min().unwrap_or(u64::MAX)
    }

    fn prune(&mut self, cfg: &Config, now: u64) {
        let keep = (cfg.stat_long_window_sec.max(cfg.stat_window_sec) + 120) as u64 * 1000;
        self.results.retain(|r| now.saturating_sub(r.mono) < keep);
    }

    /// Статистика за окно с учётом режима контроля WAN (как Go Prober.Stats).
    pub fn stats_mode(&self, cfg: &Config, family: &str, window_sec: i64, now: u64, syn: Option<&crate::synrtt::SynRtt>) -> ProbeStats {
        if let (Some(syn), true) = (syn, self.mode != "active") {
            if family == "ipv4" || family == "ipv6" {
                let tr = self.traffic_stats(family, window_sec, now, syn);
                if self.mode == "passive" {
                    return tr;
                }
                // гибрид: по трафику, если его хватает; «болеет» — решают пробы
                let mut act = self.active_stats(family, window_sec, now);
                act.source = "active";
                let h = cfg.thresholds.warning_enter_success;
                if Self::healthy(&tr, h) {
                    return tr;
                }
                if tr.count > 0 && act.count > 0 && act.success_rate >= h {
                    return act;
                }
                if tr.count > 0 {
                    return tr;
                }
                return act;
            }
            if self.mode == "passive" {
                return ProbeStats { window_sec, ..Default::default() };
            }
        }
        self.stats(family, window_sec, now)
    }

    /// Статистика активных проб за окно.
    pub fn stats(&self, family: &str, window_sec: i64, now: u64) -> ProbeStats {
        let mut st = self.active_stats(family, window_sec, now);
        if family == "ipv4" || family == "ipv6" {
            st.source = "active";
        }
        st
    }

    pub fn active_stats(&self, family: &str, window_sec: i64, now: u64) -> ProbeStats {
        let mut st = ProbeStats { window_sec, ..Default::default() };
        if family == "ipv6" || family == "udp6" {
            st.available = self.ipv6_available;
            if !self.ipv6_available {
                return st;
            }
        } else {
            st.available = true;
        }
        let min = now.saturating_sub(window_sec as u64 * 1000);
        let (mut total, mut ok, mut to, mut lat) = (0i64, 0i64, 0i64, 0u64);
        for r in &self.results {
            if r.family != family || r.mono < min {
                continue;
            }
            total += 1;
            if r.success {
                ok += 1;
                lat += r.latency_ns / 1_000_000;
            }
            if r.timeout {
                to += 1;
            }
        }
        st.count = total;
        if total > 0 {
            st.success_rate = ok as f64 / total as f64 * 100.0;
            st.timeout_rate = to as f64 / total as f64 * 100.0;
        }
        if ok > 0 {
            st.avg_latency_ms = lat as f64 / ok as f64;
        }
        st
    }

    pub fn recent(&self, n: usize) -> &[ProbeResult] {
        let s = self.results.len().saturating_sub(n);
        &self.results[s..]
    }
}

/// JSON ProbeStats (как Go: числа с округлением делает status — roundedProbeStats).
pub fn stats_json(j: &mut crate::json::J, s: &ProbeStats) {
    use crate::config::go_float;
    j.obj();
    j.key("available").bool(s.available).key("count").int(s.count);
    j.key("success_rate").raw(&go_float(s.success_rate)).key("timeout_rate").raw(&go_float(s.timeout_rate));
    j.key("avg_latency_ms").raw(&go_float(s.avg_latency_ms));
    if !s.source.is_empty() {
        j.key("source").str(s.source);
    }
    if s.p90_ms != 0.0 {
        j.key("p90_ms").raw(&go_float(s.p90_ms));
    }
    if s.loss_pct != 0.0 {
        j.key("loss_pct").raw(&go_float(s.loss_pct));
    }
    j.key("window_sec").int(s.window_sec);
    j.end_obj();
}

/// JSON одного результата (как Go ProbeResult: latency — наносекунды).
pub fn result_json(j: &mut crate::json::J, r: &ProbeResult) {
    j.obj();
    j.key("time").str(&util::rfc3339(r.wall.0, r.wall.1));
    j.key("family").str(&r.family).key("endpoint").str(&r.endpoint).key("success").bool(r.success);
    j.key("latency").uint(r.latency_ns);
    if !r.error.is_empty() {
        j.key("error").str(&r.error);
    }
    if r.timeout {
        j.key("timeout").bool(true);
    }
    if r.refused {
        j.key("refused").bool(true);
    }
    if r.unreachable {
        j.key("unreachable").bool(true);
    }
    j.end_obj();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(normalize_endpoint("1.1.1.1", false), "1.1.1.1:443");
        assert_eq!(normalize_endpoint("1.1.1.1:80", false), "1.1.1.1:80");
        assert_eq!(normalize_endpoint("2606:4700::1111", true), "[2606:4700::1111]:443");
        assert_eq!(normalize_endpoint("[2606:4700::1111]", true), "[2606:4700::1111]:443");
    }

    #[test]
    fn stats_window() {
        let mut c = crate::config::defaults();
        c.normalize();
        let mut p = Prober { mode: "active".into(), last_probe: [0; 2], results: Vec::new(), flight: HashMap::new(), next: 0, tok_base: 1 << 48, ipv6_available: false, v6src: None, v6src_at: 1, rng: 1 };
        let mk = |mono, ok, to| ProbeResult { mono, wall: (0, 0), family: "ipv4".into(), endpoint: "x".into(), success: ok, latency_ns: 40_000_000, error: String::new(), timeout: to, refused: false, unreachable: false };
        p.results = vec![mk(1_000, false, true), mk(100_000, true, false), mk(101_000, true, false), mk(102_000, false, true)];
        let s = p.stats("ipv4", 60, 120_000);
        assert_eq!((s.count, s.success_rate.round(), s.timeout_rate.round(), s.avg_latency_ms), (3, 67.0, 33.0, 40.0));
        assert_eq!(s.source, "active");
        assert!(!p.stats("ipv6", 60, 120_000).available);
        assert!(p.owns((1 << 48) | 5) && !p.owns((2 << 48) | 5));
    }
}
