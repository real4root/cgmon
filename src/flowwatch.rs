//! Наказание провайдера по любому трафику (перенос flowwatch.go).
//!
//! Поток, отдававший больше heavy_mbps, ставится на пробу раз в
//! probe_interval_ms тем же протоколом: tcp — TCP connect к адресу:порту;
//! udp к пиру tailscale — TCP к его tailscale-адресу; прочее — ICMP echo, а
//! если адрес молчит — echo с TTL самого дальнего отвечающего узла (разовая
//! трассировка). Наказание = поток встал (< stall_percent% дольше stall_sec)
//! И проба стала плохой И пока поток быстро отдавал, проба была хорошей И
//! интернет в норме. Сокеты — в общем epoll. Доводы — учителю отдачи.

use crate::config::FlowWatchConfig;
use crate::evloop::Poller;
use crate::json::J;
use crate::probe::{Kind, Outcome, Probe};
use crate::uplearn::UploadLearner;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

const TRACE_MAX_TTL: u8 = 24;
const TRACE_WAIT: u64 = 2500;
const BASE_KEEP: u64 = 10 * 60_000;
const PROBE_TIMEOUT: u64 = 2000;
const TS_PORT: u16 = 80;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Trace,
    Icmp,
    Hop,
    Tcp,
    None,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Trace => "trace",
            Mode::Icmp => "icmp",
            Mode::Hop => "hop",
            Mode::Tcp => "tcp",
            Mode::None => "none",
        }
    }
}

struct Target {
    ip: IpAddr,
    tcp: Option<SocketAddr>,
    mode: Mode,
    ttl: u8,
    until: u64,
    trace_at: u64,
    echo_ok: bool,
    best_hop: u8,
    /// (когда, мс; <0 — потеря)
    samples: Vec<(u64, f64)>,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    mode_none: bool,
    count: usize,
    loss_pct: f64,
    median_ms: f64,
    base: f64,
    mode_trace: bool,
}

struct Pending {
    ip: IpAddr,
    at: u64,
    trace: u8,
}

/// Пробы адресов потоков (ICMP — сырой сокет, TCP — Probe; всё в epoll).
pub struct FlowProber {
    pub iv: u64,
    max: usize,
    targets: HashMap<IpAddr, Target>,
    pending: HashMap<u16, Pending>,
    fd: Option<i32>,
    id: u16,
    seq: u16,
    tcp: HashMap<u64, Probe>,
    tok_base: u64,
    next_tok: u64,
    pub next_round: u64,
}

fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    let mut i = 0;
    while i + 1 < b.len() {
        s += (b[i] as u32) << 8 | b[i + 1] as u32;
        i += 2;
    }
    if b.len() % 2 == 1 {
        s += (b[b.len() - 1] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

impl Target {
    fn stats(&self, from: u64, to: u64) -> Stats {
        let mut st = Stats { mode_none: self.mode == Mode::None, mode_trace: self.mode == Mode::Trace, ..Default::default() };
        let mut rtts = Vec::new();
        let mut lost = 0;
        for &(at, rtt) in &self.samples {
            if rtt >= 0.0 && (st.base == 0.0 || rtt < st.base) {
                st.base = rtt;
            }
            if at < from || at >= to {
                continue;
            }
            st.count += 1;
            if rtt < 0.0 {
                lost += 1;
            } else {
                rtts.push(rtt);
            }
        }
        if st.count > 0 {
            st.loss_pct = lost as f64 * 100.0 / st.count as f64;
        }
        st.median_ms = crate::dgsys::median(&rtts);
        st
    }
}

impl FlowProber {
    pub fn new(iv: u64, max: usize, tok_base: u64) -> FlowProber {
        FlowProber { iv, max, targets: HashMap::new(), pending: HashMap::new(), fd: None, id: std::process::id() as u16, seq: 0, tcp: HashMap::new(), tok_base, next_tok: 0, next_round: 0 }
    }

    pub fn owns(&self, tok: u64) -> bool {
        tok >> 48 == self.tok_base >> 48
    }

    /// Сырой сокет ICMP (нет прав — только TCP-пробы).
    pub fn open(&mut self, poller: &Poller) {
        if self.fd.is_some() {
            return;
        }
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMP) };
        if fd < 0 {
            crate::log_err!("flow watch: icmp socket: {} (TCP probes only)", std::io::Error::last_os_error());
            return;
        }
        if poller.add(fd, libc::EPOLLIN as u32, self.tok_base).is_err() {
            unsafe { libc::close(fd) };
            return;
        }
        self.fd = Some(fd);
    }

    pub fn set_params(&mut self, iv: u64, max: usize) {
        if iv > 0 {
            self.iv = iv;
        }
        if max > 0 {
            self.max = max;
        }
    }

    /// Пробовать ip до until (продлевает); tcp — TCP connect к нему, иначе ICMP.
    pub fn watch(&mut self, ip: IpAddr, tcp: Option<SocketAddr>, until: u64) {
        let icmp = self.fd.is_some();
        let n = self.targets.len();
        let t = match self.targets.get_mut(&ip) {
            Some(t) => t,
            None => {
                if n >= self.max {
                    return;
                }
                let mode = if tcp.is_some() {
                    Mode::Tcp
                } else if ip.is_ipv6() || !icmp {
                    Mode::None // ICMPv6 не шлём
                } else {
                    Mode::Trace
                };
                self.targets.entry(ip).or_insert(Target { ip, tcp, mode, ttl: 0, until: 0, trace_at: 0, echo_ok: false, best_hop: 0, samples: Vec::new() })
            }
        };
        t.until = t.until.max(until);
    }

    fn send_echo(&mut self, ip: IpAddr, ttl: u8) -> Option<u16> {
        let fd = self.fd?;
        let IpAddr::V4(a) = ip else { return None };
        self.seq = self.seq.wrapping_add(1);
        let t = ttl as i32;
        unsafe { libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_TTL, &t as *const i32 as *const libc::c_void, 4) };
        let mut b = [0u8; 16];
        b[0] = 8;
        b[4..6].copy_from_slice(&self.id.to_be_bytes());
        b[6..8].copy_from_slice(&self.seq.to_be_bytes());
        b[8..].copy_from_slice(b"cgmonfw!");
        let c = checksum(&b);
        b[2..4].copy_from_slice(&c.to_be_bytes());
        let (sa, l) = crate::netx::sockaddr_of(&IpAddr::V4(a), 0);
        let n = unsafe { libc::sendto(fd, b.as_ptr() as *const libc::c_void, b.len(), 0, &sa as *const _ as *const libc::sockaddr, l) };
        if n < 0 {
            return None;
        }
        Some(self.seq)
    }

    /// Раунд: таймауты, трассировки, пробы.
    pub fn round(&mut self, now: u64, poller: &Poller) {
        self.next_round = now + self.iv.max(100);
        let expired: Vec<u16> = self.pending.iter().filter(|(_, p)| now - p.at > PROBE_TIMEOUT).map(|(s, _)| *s).collect();
        for s in expired {
            let p = self.pending.remove(&s).unwrap();
            if let Some(t) = self.targets.get_mut(&p.ip) {
                if p.trace == 0 {
                    t.samples.push((p.at, -1.0));
                }
            }
        }
        // TCP-пробы дольше таймаута — потеря
        let late: Vec<u64> = self.tcp.iter().filter(|(_, p)| now - p.started > PROBE_TIMEOUT).map(|(k, _)| *k).collect();
        for k in late {
            let p = self.tcp.remove(&k).unwrap();
            poller.del(p.fd);
            if let Some(t) = self.targets.get_mut(&p.addr.ip()) {
                t.samples.push((p.started, -1.0));
            }
        }
        self.targets.retain(|_, t| now <= t.until);
        let ips: Vec<IpAddr> = self.targets.keys().copied().collect();
        for ip in ips {
            let t = self.targets.get_mut(&ip).unwrap();
            let k = t.samples.iter().position(|s| now - s.0 <= BASE_KEEP).unwrap_or(t.samples.len());
            t.samples.drain(..k);
            if t.mode == Mode::Trace {
                if t.trace_at == 0 {
                    // echo с TTL 1..max и с обычным TTL — за один раунд
                    t.trace_at = now;
                    for ttl in 1..=TRACE_MAX_TTL + 1 {
                        let send = if ttl > TRACE_MAX_TTL { 64 } else { ttl };
                        if let Some(s) = self.send_echo(ip, send) {
                            self.pending.insert(s, Pending { ip, at: now, trace: send });
                        }
                    }
                    continue;
                }
                if now - t.trace_at < TRACE_WAIT {
                    continue;
                }
                if t.echo_ok {
                    t.mode = Mode::Icmp;
                    t.ttl = 64;
                } else if t.best_hop > 0 {
                    t.mode = Mode::Hop;
                    t.ttl = t.best_hop;
                } else {
                    t.mode = Mode::None;
                }
            }
            match t.mode {
                Mode::Icmp | Mode::Hop => {
                    let ttl = t.ttl;
                    if let Some(s) = self.send_echo(ip, ttl) {
                        self.pending.insert(s, Pending { ip, at: now, trace: 0 });
                    }
                }
                Mode::Tcp => {
                    let Some(addr) = t.tcp else { continue };
                    match Probe::start(Kind::Tcp, addr, None, now) {
                        Ok(p) => {
                            self.next_tok += 1;
                            let tok = self.tok_base | 1 << 32 | (self.next_tok & 0xffff_ffff);
                            if poller.add(p.fd, p.events(), tok).is_ok() {
                                self.tcp.insert(tok, p);
                            }
                        }
                        Err(o) => {
                            let ok = o == Outcome::Refused;
                            t.samples.push((now, if ok { 0.1 } else { -1.0 }));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Событие epoll: ответ ICMP или итог TCP-пробы.
    pub fn on_event(&mut self, tok: u64, poller: &Poller, now: u64) {
        if tok == self.tok_base {
            self.read_icmp(now);
            return;
        }
        let Some(p) = self.tcp.remove(&tok) else { return };
        poller.del(p.fd);
        // RST (connection refused) — путь жив
        let ok = matches!(p.finish(), Outcome::Ok | Outcome::Refused);
        if let Some(t) = self.targets.get_mut(&p.addr.ip()) {
            if t.mode == Mode::Tcp {
                t.samples.push((p.started, if ok { (now - p.started) as f64 } else { -1.0 }));
            }
        }
    }

    fn read_icmp(&mut self, now: u64) {
        let Some(fd) = self.fd else { return };
        let mut buf = [0u8; 1500];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                return;
            }
            let mut b = &buf[..n as usize];
            if b.len() >= 20 && b[0] >> 4 == 4 {
                let hl = (b[0] & 0x0f) as usize * 4;
                if hl > b.len() {
                    continue;
                }
                b = &b[hl..];
            }
            if b.len() < 8 {
                continue;
            }
            let (id, seq, exceeded) = match b[0] {
                0 => (u16::from_be_bytes([b[4], b[5]]), u16::from_be_bytes([b[6], b[7]]), false),
                11 => {
                    let q = &b[8..];
                    if q.len() < 20 {
                        continue;
                    }
                    let hl = (q[0] & 0x0f) as usize * 4;
                    if q.len() < hl + 8 || q[hl] != 8 {
                        continue;
                    }
                    (u16::from_be_bytes([q[hl + 4], q[hl + 5]]), u16::from_be_bytes([q[hl + 6], q[hl + 7]]), true)
                }
                _ => continue,
            };
            if id != self.id {
                continue;
            }
            let Some(p) = self.pending.remove(&seq) else { continue };
            let Some(t) = self.targets.get_mut(&p.ip) else { continue };
            if p.trace > 0 && exceeded {
                t.best_hop = t.best_hop.max(p.trace);
            } else if p.trace > 0 {
                t.echo_ok = true;
            } else if exceeded == (t.mode == Mode::Hop) {
                t.samples.push((p.at, (now - p.at) as f64));
            }
        }
    }

    pub fn stats(&self, ip: &IpAddr, window: u64, now: u64) -> Stats {
        self.range(ip, now.saturating_sub(window), now + 1)
    }

    pub fn range(&self, ip: &IpAddr, from: u64, to: u64) -> Stats {
        match self.targets.get(ip) {
            Some(t) => t.stats(from, to),
            None => Stats { mode_none: true, ..Default::default() },
        }
    }

    fn status_json(&self, j: &mut J, window: u64, now: u64) {
        let mut l: Vec<&Target> = self.targets.values().collect();
        l.sort_by_key(|t| t.ip.to_string());
        if l.is_empty() {
            return;
        }
        let r1 = |v: f64| crate::config::go_float((v * 10.0).round() / 10.0);
        j.key("targets").arr();
        for t in l {
            let st = t.stats(now.saturating_sub(window), now + 1);
            j.obj().key("ip").str(&t.ip.to_string()).key("mode").str(t.mode.name());
            if t.mode == Mode::Hop && t.ttl > 0 {
                j.key("hop").int(t.ttl as i64);
            }
            j.key("count").int(st.count as i64).key("loss_pct").raw(&r1(st.loss_pct)).key("median_ms").raw(&r1(st.median_ms)).key("base_ms").raw(&r1(st.base));
            j.end_obj();
        }
        j.end_arr();
    }
}

/// Скорость отдачи WAN-потока (из wan flows).
pub struct Rate {
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub tx: f64,
}

struct Flow {
    proto: &'static str,
    local: String,
    remote: String,
    ip: IpAddr,
    rate: f64,
    peak: f64,
    heavy_at: u64,
    low_since: u64,
    penalized: bool,
}

pub struct FlowWatch {
    pub cfg: FlowWatchConfig,
    pub prober: FlowProber,
    flows: HashMap<String, Flow>,
    pub off: bool,
    ts_peers: Option<HashMap<IpAddr, IpAddr>>,
    ts_at: u64,
    pub learn: Option<UploadLearner>,
    penalty: bool,
    since: u64,
    since_wall: i64,
    bad_ip: Option<IpAddr>,
    good_since: u64,
    suspect: String,
}

/// Разбор `tailscale status`: внешний адрес пира («direct a:p») → его адрес в tailscale.
pub fn parse_tailscale_status(out: &str) -> HashMap<IpAddr, IpAddr> {
    let mut m = HashMap::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        for i in 1..f.len().saturating_sub(1) {
            if f[i] != "direct" {
                continue;
            }
            let hp = f[i + 1].trim_end_matches(',');
            if let (Ok(sa), Ok(ts)) = (hp.parse::<SocketAddr>(), f[0].parse::<IpAddr>()) {
                m.insert(sa.ip(), ts);
            }
        }
    }
    m
}

/// Команда с ограничением времени (вывод stdout; None — не успела/ошибка).
pub fn output_timeout(cmd: &str, args: &[&str], ms: u64) -> Option<String> {
    use std::io::Read;
    let mut ch = std::process::Command::new(cmd).args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().ok()?;
    let t0 = std::time::Instant::now();
    loop {
        match ch.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if t0.elapsed().as_millis() as u64 >= ms => {
                let _ = ch.kill();
                let _ = ch.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    let mut s = String::new();
    ch.stdout.take()?.read_to_string(&mut s).ok()?;
    Some(s)
}

impl FlowWatch {
    pub fn new(cfg: FlowWatchConfig, tok_base: u64) -> FlowWatch {
        let prober = FlowProber::new(cfg.probe_interval_ms.max(100) as u64, cfg.max_targets.max(1) as usize, tok_base);
        FlowWatch { cfg, prober, flows: HashMap::new(), off: false, ts_peers: None, ts_at: 0, learn: None, penalty: false, since: 0, since_wall: 0, bad_ip: None, good_since: 0, suspect: String::new() }
    }

    pub fn set_config(&mut self, c: FlowWatchConfig) {
        self.prober.set_params(c.probe_interval_ms as u64, c.max_targets as usize);
        if let Some(l) = self.learn.as_mut() {
            l.set_config(&c);
        }
        self.cfg = c;
    }

    /// Со страницы. Пробы сами кончатся через hold_sec.
    pub fn set_off(&mut self, off: bool) {
        if off && !self.off {
            self.flows.clear();
            self.penalty = false;
            self.suspect.clear();
        }
        self.off = off;
    }

    fn tailscale_peer(&mut self, ip: &IpAddr, now: u64) -> Option<IpAddr> {
        if self.ts_peers.is_none() || now - self.ts_at > 60_000 {
            self.ts_at = now;
            self.ts_peers = Some(output_timeout("tailscale", &["status"], 3000).map(|o| parse_tailscale_status(&o)).unwrap_or_default());
        }
        self.ts_peers.as_ref()?.get(ip).copied()
    }

    /// Скорости отдачи WAN-потоков из очередного снимка conntrack.
    pub fn observe(&mut self, now: u64, rates: &HashMap<String, Rate>) {
        if self.off {
            return;
        }
        let hold = self.cfg.hold_sec.max(0) as u64 * 1000;
        for (k, r) in rates {
            if r.tx >= self.cfg.heavy_mbps {
                let Ok(sa) = r.remote.parse::<SocketAddr>() else { continue };
                let ip = sa.ip();
                let f = self.flows.entry(k.clone()).or_insert(Flow { proto: r.proto, local: r.local.clone(), remote: r.remote.clone(), ip, rate: 0.0, peak: 0.0, heavy_at: 0, low_since: 0, penalized: false });
                f.rate = r.tx;
                f.heavy_at = now;
                f.low_since = 0;
                f.peak = f.peak.max(r.tx);
                let tcp = match r.proto {
                    "tcp" => Some(sa),
                    "udp" => self.tailscale_peer(&ip, now).map(|ts| SocketAddr::new(ts, TS_PORT)),
                    _ => None,
                };
                self.prober.watch(ip, tcp, now + hold);
                continue;
            }
            let Some(f) = self.flows.get_mut(k) else { continue };
            let low = (f.rate * self.cfg.stall_percent / 100.0).max(0.5);
            if r.tx < low {
                if f.low_since == 0 {
                    f.low_since = now;
                }
            } else {
                f.low_since = 0;
            }
        }
        let gone: Vec<String> = self.flows.iter().filter(|(k, f)| !rates.contains_key(*k) || now - f.heavy_at > hold).map(|(k, _)| k.clone()).collect();
        for k in gone {
            let f = self.flows.remove(&k).unwrap();
            // быстро отдавал и без наказания — довод «так можно»
            if !f.penalized {
                if let Some(l) = self.learn.as_mut() {
                    l.good(now, f.ip, f.proto, &f.remote, f.peak);
                }
            }
        }
    }

    fn bad(&self, st: &Stats) -> bool {
        if st.mode_none || st.mode_trace || st.count < 3 || st.base == 0.0 {
            return false;
        }
        if st.median_ms > 0.0 && st.median_ms >= st.base * self.cfg.latency_factor + self.cfg.latency_add_ms {
            return true;
        }
        // потери без роста задержки: плохо — только когда пропадает почти всё
        st.loss_pct > self.cfg.loss_percent && st.loss_pct >= self.cfg.loss_only_percent
    }

    fn good(&self, st: &Stats) -> bool {
        !st.mode_none && !st.mode_trace && st.count >= 3 && st.loss_pct < self.cfg.loss_percent / 2.0 && !self.bad(st)
    }

    /// Вердикт: сообщение о начале/конце наказания и «началось».
    pub fn evaluate(&mut self, now: u64, wall: i64, internet_ok: bool) -> Option<(String, bool)> {
        if self.off {
            return None;
        }
        let window = self.cfg.probe_window_sec.max(1) as u64 * 1000;
        if self.penalty {
            let ip = self.bad_ip?;
            // наказанный адрес пробуем, пока не восстановится
            self.prober.watch(ip, None, now + self.cfg.hold_sec.max(0) as u64 * 1000);
            let st = self.prober.stats(&ip, window, now);
            if !self.good(&st) {
                self.good_since = 0;
                return None;
            }
            if self.good_since == 0 {
                self.good_since = now;
            }
            if now - self.good_since < self.cfg.recover_sec.max(0) as u64 * 1000 {
                return None;
            }
            self.penalty = false;
            self.suspect.clear();
            return Some((format!("upload path to {ip} recovered after {}", crate::util::go_secs(now - self.since)), false));
        }
        if !internet_ok {
            return None;
        }
        let stall = self.cfg.stall_sec.max(0) as u64 * 1000;
        let mut hit: Option<(String, Stats)> = None;
        let mut stalled: Vec<IpAddr> = Vec::new();
        for (k, f) in &self.flows {
            if f.low_since == 0 || now - f.low_since < stall {
                continue;
            }
            let st = self.prober.stats(&f.ip, window, now);
            if !self.bad(&st) {
                continue;
            }
            let pre = self.prober.range(&f.ip, f.low_since.saturating_sub(window), f.low_since);
            if pre.count >= 3 && !self.good(&pre) {
                continue; // и пока отдавал, проба была плохой — свойство адреса
            }
            if !stalled.contains(&f.ip) {
                stalled.push(f.ip);
            }
            if hit.as_ref().map_or(true, |(hk, _)| f.rate > self.flows[hk].rate) {
                hit = Some((k.clone(), st));
            }
        }
        let (hk, hst) = hit?;
        // общее наказание (лимит абонента) или только этого направления
        let scope = if stalled.len() > 1 { "global" } else { "dest" };
        let mut total = 0.0;
        for f in self.flows.values_mut() {
            if stalled.contains(&f.ip) {
                f.penalized = true;
                total += f.rate;
            }
        }
        let h = &self.flows[&hk];
        if let Some(l) = self.learn.as_mut() {
            l.bad(now, h.ip, h.proto, &h.remote, h.rate, scope, total, stalled.len());
        }
        self.penalty = true;
        self.since = now;
        self.since_wall = wall;
        self.bad_ip = Some(h.ip);
        self.good_since = 0;
        self.suspect = format!("{} {}>{} {:.1} Mbit/s stalled {}s ago", h.proto, h.local, h.remote, h.rate, (now - h.low_since) / 1000);
        let mode = self.prober.targets.get(&h.ip).map_or(Mode::None, |t| t.mode);
        Some((format!("upload path penalty while internet OK: {}; {} probe loss {:.0}%, median {:.0} ms (base {:.0} ms)", self.suspect, mode.name(), hst.loss_pct, hst.median_ms, hst.base), true))
    }

    pub fn status_json(&self, j: &mut J, now: u64) {
        j.obj().key("state").str(if self.penalty { "penalty" } else { "ok" });
        if self.penalty {
            j.key("since").str(&crate::util::rfc3339(self.since_wall, 0));
        }
        if !self.suspect.is_empty() {
            j.key("suspect").str(&self.suspect);
        }
        self.prober.status_json(j, self.cfg.probe_window_sec.max(1) as u64 * 1000, now);
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FlowWatchConfig {
        crate::config::defaults().flow_watch
    }

    #[test]
    fn tailscale_status() {
        let m = parse_tailscale_status("100.64.0.2  router2  routers  linux  active; direct 203.0.113.7:41641, tx 1 rx 2\n100.64.0.3 x y linux active; relay \"fra\"\n");
        assert_eq!(m.get(&"203.0.113.7".parse().unwrap()), Some(&"100.64.0.2".parse().unwrap()));
        assert_eq!(m.len(), 1);
    }

    fn add(w: &mut FlowWatch, ip: &str, from: u64, to: u64, step: u64, rtt: f64) {
        let ip: IpAddr = ip.parse().unwrap();
        let t = w.prober.targets.get_mut(&ip).unwrap();
        let mut at = from;
        while at < to {
            t.samples.push((at, rtt));
            at += step;
        }
    }

    /// Поток встал, проба стала плохой, а до того была хорошей — наказание; потом восстановление.
    #[test]
    fn penalty_and_recover() {
        let mut w = FlowWatch::new(cfg(), 9 << 48);
        let c = w.cfg.clone();
        let remote = "198.51.100.9:443";
        let k = format!("tcp 192.168.1.10:50000>{remote}");
        let mut rates = HashMap::new();
        let mut now = 1_000_000u64;
        let rate = |tx: f64| Rate { proto: "tcp", local: "192.168.1.10:50000".into(), remote: remote.into(), tx };
        rates.insert(k.clone(), rate(c.heavy_mbps * 2.0));
        w.observe(now, &rates);
        assert_eq!(w.prober.targets.len(), 1);
        // пока отдавал — проба хорошая (40 мс)
        add(&mut w, "198.51.100.9", now - 60_000, now, 1000, 40.0);
        now += 1000;
        rates.insert(k.clone(), rate(0.0));
        w.observe(now, &rates);
        let low = now;
        // встал: задержка выросла в разы
        add(&mut w, "198.51.100.9", low, low + c.stall_sec as u64 * 1000 + 10_000, 1000, 900.0);
        now = low + c.stall_sec as u64 * 1000 + 10_000;
        w.observe(now, &rates);
        let (m, started) = w.evaluate(now, 1, true).expect("наказание");
        assert!(started && m.starts_with("upload path penalty while internet OK: tcp 192.168.1.10:50000>198.51.100.9:443"), "{m}");
        // восстановилось
        let t2 = now + c.probe_window_sec as u64 * 1000 + 1000;
        add(&mut w, "198.51.100.9", now, t2 + c.recover_sec as u64 * 1000 + 2000, 1000, 40.0);
        assert!(w.evaluate(t2, 2, true).is_none());
        let (m, started) = w.evaluate(t2 + c.recover_sec as u64 * 1000 + 1000, 3, true).expect("восстановление");
        assert!(!started && m.starts_with("upload path to 198.51.100.9 recovered after"), "{m}");
    }
}
