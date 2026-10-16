//! Поиск виновника (перенос pathtrace.go): при деградации протокола роутер
//! трассирует TCP SYN на 443 (hop limit 1..20, как tcptraceroute) до целей
//! проб и метрик по сайтам. Плохие цели (дошло ≤ 50% SYN) и хорошие (≥ 80%);
//! признак (сеть узла /24 (/64) или AS), который есть во всех плохих маршрутах
//! (≥ 2 разных владельца) и ни в одном хорошем, — общий виновник. Дважды подряд
//! — в журнал. Трассировка — машина состояний в общем epoll.

use crate::evloop::Poller;
use crate::ipowner::IpOwner;
use crate::json::J;
use crate::netx;
use std::collections::HashMap;
use std::net::IpAddr;

const MAX_TTL: u8 = 20;
const PER_HOP: usize = 2;
const FINAL: usize = 6;
const WAIT_MS: u64 = 2500;
const BAD_PCT: i64 = 50;
const GOOD_PCT: i64 = 80;
const BAD_RATE: f64 = 80.0;
const BAD_FOR: u64 = 3 * 60 * 1000;
const EVERY: u64 = 10 * 60 * 1000;
const GOOD_RATE: f64 = 95.0;
const GOOD_FOR: u64 = 10 * 60 * 1000;
pub const MAX_TARGET: usize = 12;
const OWNER_WAIT: u64 = 20_000;

#[derive(Clone, Debug, Default)]
pub struct PtResult {
    pub ip: String,
    pub v6: bool,
    pub owner: String,
    pub asn: String,
    pub hops: Vec<(u8, String)>,
    pub sent: i64,
    pub reached: i64,
}

impl PtResult {
    fn pct(&self) -> i64 {
        if self.sent == 0 {
            0
        } else {
            self.reached * 100 / self.sent
        }
    }
    pub fn bad(&self) -> bool {
        self.sent >= 4 && self.pct() <= BAD_PCT
    }
    pub fn good(&self) -> bool {
        self.sent >= 4 && self.pct() >= GOOD_PCT
    }
}

#[derive(Clone, Debug, Default)]
pub struct Verdict {
    pub family: &'static str,
    pub key: String,
    pub fork: String,
    pub culprit: String,
    pub next: String,
    pub stop: bool,
    pub bad: Vec<String>,
    pub good: Vec<String>,
    pub text: String,
    pub since: i64,
}

/// Сеть узла: /24 или /64; локальные — "".
pub fn pt_net(ip: &str) -> String {
    let Ok(p) = ip.parse::<IpAddr>() else { return String::new() };
    let ll = matches!(p, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80) || matches!(p, IpAddr::V4(a) if a.is_link_local());
    if ll || p.is_loopback() {
        return String::new();
    }
    netx::IpNet::new(p, if p.is_ipv4() { 24 } else { 64 }).to_string()
}

/// AS и имя владельца адреса (None — ещё неизвестен).
pub type OwnerFn<'a> = dyn FnMut(&str) -> Option<(String, String)> + 'a;

#[derive(Clone, Debug)]
struct Key {
    key: String,
    ip: String,
    last: String,
    asn: String,
    name: String,
    is_as: bool,
}

fn keys(r: &PtResult, own: &mut OwnerFn) -> Vec<Key> {
    let mut out: Vec<Key> = Vec::new();
    let add = |k: Key, out: &mut Vec<Key>| {
        if let Some(e) = out.iter_mut().find(|x| x.key == k.key) {
            e.last = k.ip;
        } else {
            let mut k = k;
            k.last = k.ip.clone();
            out.push(k);
        }
    };
    for (_, h) in &r.hops {
        if *h == r.ip {
            break;
        }
        let (asn, name) = own(h).unwrap_or_default();
        let n = pt_net(h);
        if !n.is_empty() {
            add(Key { key: format!("net {n}"), ip: h.clone(), last: String::new(), asn: asn.clone(), name: name.clone(), is_as: false }, &mut out);
        }
        if !asn.is_empty() && asn != r.asn {
            add(Key { key: format!("AS{asn}"), ip: h.clone(), last: String::new(), asn, name, is_as: true }, &mut out);
        }
    }
    out
}

fn who(name: &str, asn: &str) -> String {
    let name = name.trim().trim_end_matches(',');
    match (name.is_empty(), asn.is_empty()) {
        (false, false) => format!("{name} (AS{asn})"),
        (true, false) => format!("AS{asn}"),
        _ => name.to_string(),
    }
}

fn fam_name(f: &str) -> &'static str {
    if f == "ipv6" {
        "IPv6"
    } else {
        "IPv4"
    }
}

/// Общий виновник плохих маршрутов (None — не найден).
pub fn analyze(fam: &'static str, res: &[PtResult], own: &mut OwnerFn) -> Option<Verdict> {
    let mut bad: Vec<&PtResult> = Vec::new();
    let mut good: Vec<&PtResult> = Vec::new();
    let mut owners: Vec<String> = Vec::new();
    for r in res {
        if r.bad() && !r.hops.is_empty() {
            bad.push(r);
            let o = format!("{}|{}", r.asn, r.owner);
            if !owners.contains(&o) {
                owners.push(o);
            }
        } else if r.good() {
            good.push(r);
        }
    }
    if bad.len() < 2 || owners.len() < 2 || good.is_empty() {
        return None;
    }
    let mut in_good: Vec<String> = Vec::new();
    for r in &good {
        for k in keys(r, own) {
            in_good.push(k.key);
        }
    }
    let first = keys(bad[0], own);
    let mut count: HashMap<String, usize> = HashMap::new();
    let bad_keys: Vec<Vec<Key>> = bad.iter().map(|r| keys(r, own)).collect();
    for ks in &bad_keys {
        for k in ks {
            *count.entry(k.key.clone()).or_insert(0) += 1;
        }
    }
    let ci = first.iter().position(|k| count.get(&k.key).copied().unwrap_or(0) == bad.len() && !in_good.contains(&k.key))?;
    let c = &first[ci];
    let mut v = Verdict { family: fam, key: c.key.clone(), ..Default::default() };
    v.culprit = if c.is_as { who(&c.name, &c.asn) } else { format!("{} {}", who(&c.name, &c.asn), c.key.trim_start_matches("net ")).trim().to_string() };
    if let Some(f) = first[..ci].iter().rev().find(|k| !k.is_as) {
        v.fork = f.last.clone();
    }
    if !c.is_as {
        'outer: for ks in &bad_keys {
            for (j, k) in ks.iter().enumerate() {
                if k.key != c.key {
                    continue;
                }
                if let Some(n) = ks[j + 1..].iter().find(|n| n.is_as && n.asn != c.asn && !in_good.contains(&n.key)) {
                    v.next = who(&n.name, &n.asn);
                    break 'outer;
                }
            }
        }
    }
    let mut stop = 0;
    for r in &bad {
        let Some(h) = r.hops.iter().rev().find(|(_, h)| *h != r.ip).map(|x| x.1.clone()) else { continue };
        let by_net = format!("net {}", pt_net(&h)) == c.key;
        let by_as = c.is_as && own(&h).map_or(false, |(a, _)| format!("AS{a}") == c.key);
        if by_net || by_as {
            stop += 1;
        }
    }
    v.stop = stop * 2 >= bad.len();
    let name = |r: &PtResult| {
        if !r.owner.is_empty() && r.owner != r.asn {
            r.owner.clone()
        } else if !r.asn.is_empty() {
            format!("AS{}", r.asn)
        } else {
            r.ip.clone()
        }
    };
    for r in &bad {
        let n = name(r);
        if !v.bad.contains(&n) {
            v.bad.push(n);
        }
    }
    for r in &good {
        let n = name(r);
        if !v.good.contains(&n) {
            v.good.push(n);
        }
    }
    v.bad.sort();
    v.good.sort();
    v.text = text(&v);
    Some(v)
}

fn text(v: &Verdict) -> String {
    let mut b = if v.next.is_empty() { format!("{}: общий виновник — {}", fam_name(v.family), v.culprit) } else { format!("{}: общий виновник — стык {} → {}", fam_name(v.family), v.culprit, v.next) };
    b += &format!(". Через него идут все плохие маршруты ({}), хорошие ({}) — в обход", v.bad.join(", "), v.good.join(", "));
    if !v.fork.is_empty() {
        b += &format!("; развилка после {}", v.fork);
    }
    if v.stop {
        b += "; TCP-соединения дальше этого места почти не проходят";
    }
    b
}

// ---------------- трассировка ----------------

/// Из ICMP time exceeded / unreachable: адрес назначения и порт цитаты TCP.
pub fn quoted(b: &[u8], v6: bool) -> Option<(IpAddr, u16)> {
    if v6 {
        if b.len() < 8 + 40 + 4 || (b[0] != 3 && b[0] != 1) {
            return None;
        }
        let q = &b[8..];
        if q[6] != 6 {
            return None;
        }
        let d: [u8; 16] = q[24..40].try_into().ok()?;
        return Some((IpAddr::from(d), u16::from_be_bytes([q[40], q[41]])));
    }
    let mut b = b;
    if b.len() >= 20 && b[0] >> 4 == 4 {
        let hl = (b[0] & 0x0f) as usize * 4;
        if hl > b.len() {
            return None;
        }
        b = &b[hl..];
    }
    if b.len() < 8 + 20 + 4 || (b[0] != 11 && b[0] != 3) {
        return None;
    }
    let q = &b[8..];
    let hl = (q[0] & 0x0f) as usize * 4;
    if q[9] != 6 || q.len() < hl + 4 {
        return None;
    }
    Some((IpAddr::from([q[16], q[17], q[18], q[19]]), u16::from_be_bytes([q[hl], q[hl + 1]])))
}

/// Неблокирующий connect к ip:443 с hop limit (0 — обычный): (fd, локальный порт).
fn sock(dst: &IpAddr, src: Option<&IpAddr>, ttl: u8) -> Option<(i32, u16)> {
    let v6 = dst.is_ipv6();
    let fd = unsafe { libc::socket(if v6 { libc::AF_INET6 } else { libc::AF_INET }, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let fail = |fd| {
        unsafe { libc::close(fd) };
        None
    };
    if ttl > 0 {
        let t: i32 = ttl as i32;
        let (lvl, opt) = if v6 { (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS) } else { (libc::IPPROTO_IP, libc::IP_TTL) };
        unsafe { libc::setsockopt(fd, lvl, opt, &t as *const _ as *const libc::c_void, 4) };
    }
    if let (true, Some(s)) = (v6, src) {
        let (sa, l) = netx::sockaddr_of(s, 0);
        if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
            return fail(fd);
        }
    }
    let (sa, l) = netx::sockaddr_of(dst, 443);
    if unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
        return fail(fd);
    }
    crate::probe::mark_service(fd, 6, std::net::SocketAddr::new(*dst, 443));
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut sl = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    if unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) } < 0 {
        return fail(fd);
    }
    let port = match ss.ss_family as i32 {
        libc::AF_INET => u16::from_be(unsafe { (*(&ss as *const _ as *const libc::sockaddr_in)).sin_port }),
        _ => u16::from_be(unsafe { (*(&ss as *const _ as *const libc::sockaddr_in6)).sin6_port }),
    };
    Some((fd, port))
}

fn reached(fd: i32) -> bool {
    let mut e: i32 = 0;
    let mut l = 4u32;
    unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut e as *mut _ as *mut libc::c_void, &mut l) };
    if e == libc::ECONNREFUSED {
        return true; // RST — тоже дошёл
    }
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut sl = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    unsafe { libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) == 0 }
}

struct Job {
    dst: IpAddr,
    socks: Vec<(i32, u16, u8)>,
    finals: usize,
    next_final: u64,
    end: u64,
    hops: HashMap<u8, HashMap<String, i64>>,
}

impl Drop for Job {
    fn drop(&mut self) {
        for (fd, _, _) in &self.socks {
            unsafe { libc::close(*fd) };
        }
    }
}

/// Прогон: цели одного семейства, по 2 одновременно, затем владельцы узлов.
pub struct Run {
    pub fam: &'static str,
    queue: Vec<IpAddr>,
    jobs: Vec<Job>,
    pub results: Vec<PtResult>,
    icmp: i32,
    owners_until: u64,
    src: Option<IpAddr>,
}

impl Run {
    pub fn start(fam: &'static str, targets: &[IpAddr], src: Option<IpAddr>, poller: &Poller, tok: u64) -> Option<Run> {
        let v6 = fam == "ipv6";
        let icmp = unsafe { libc::socket(if v6 { libc::AF_INET6 } else { libc::AF_INET }, libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, if v6 { libc::IPPROTO_ICMPV6 } else { libc::IPPROTO_ICMP }) };
        if icmp < 0 {
            crate::log_err!("path trace: icmp socket: {}", std::io::Error::last_os_error());
            return None;
        }
        let _ = poller.add(icmp, libc::EPOLLIN as u32, tok);
        let mut q: Vec<IpAddr> = targets.iter().copied().take(MAX_TARGET).collect();
        q.reverse();
        Some(Run { fam, queue: q, jobs: Vec::new(), results: Vec::new(), icmp, owners_until: 0, src })
    }

    pub fn on_icmp(&mut self) {
        let v6 = self.fam == "ipv6";
        let mut buf = [0u8; 1500];
        loop {
            let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut sl = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            let n = unsafe { libc::recvfrom(self.icmp, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) };
            if n <= 0 {
                break;
            }
            let Some((qd, sport)) = quoted(&buf[..n as usize], v6) else { continue };
            let Some(from) = netx::ip_of_sockaddr(&ss) else { continue };
            for j in self.jobs.iter_mut().filter(|j| j.dst == qd) {
                if let Some((_, _, ttl)) = j.socks.iter().find(|(_, p, t)| *p == sport && *t > 0) {
                    *j.hops.entry(*ttl).or_default().entry(from.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    /// Шаг; true — прогон закончен (результаты в results).
    pub fn step(&mut self, now: u64, owner: &mut IpOwner) -> bool {
        // новые трассы (до 2 одновременно)
        while self.jobs.len() < 2 && self.owners_until == 0 {
            let Some(dst) = self.queue.pop() else { break };
            let mut j = Job { dst, socks: Vec::new(), finals: 0, next_final: now, end: 0, hops: HashMap::new() };
            for ttl in 1..=MAX_TTL {
                for _ in 0..PER_HOP {
                    if let Some((fd, p)) = sock(&dst, self.src.as_ref(), ttl) {
                        j.socks.push((fd, p, ttl));
                    }
                }
            }
            self.jobs.push(j);
        }
        // обычные SYN с шагом 50 мс; итог — через 2,5 с после последнего
        let mut done = Vec::new();
        for (i, j) in self.jobs.iter_mut().enumerate() {
            while j.finals < FINAL && now >= j.next_final {
                if let Some((fd, p)) = sock(&j.dst, self.src.as_ref(), 0) {
                    j.socks.push((fd, p, 0));
                }
                j.finals += 1;
                j.next_final = now + 50;
                if j.finals == FINAL {
                    j.end = now + WAIT_MS;
                }
            }
            if j.end != 0 && now >= j.end {
                done.push(i);
            }
        }
        for i in done.into_iter().rev() {
            let j = self.jobs.remove(i);
            let mut r = PtResult { ip: j.dst.to_string(), v6: j.dst.is_ipv6(), ..Default::default() };
            for (fd, _, ttl) in &j.socks {
                if *ttl == 0 {
                    r.sent += 1;
                    if reached(*fd) {
                        r.reached += 1;
                    }
                }
            }
            for ttl in 1..=MAX_TTL {
                let Some(m) = j.hops.get(&ttl) else { continue };
                let mut best: Option<(&String, &i64)> = None;
                for (h, c) in m {
                    if best.map_or(true, |(bh, bc)| c > bc || (c == bc && h < bh)) {
                        best = Some((h, c));
                    }
                }
                if let Some((h, _)) = best {
                    r.hops.push((ttl, h.clone()));
                    if *h == r.ip {
                        break;
                    }
                }
            }
            self.results.push(r);
        }
        if !self.queue.is_empty() || !self.jobs.is_empty() {
            return false;
        }
        // владельцы узлов и целей (ждём до 20 с)
        if self.owners_until == 0 {
            self.owners_until = now + OWNER_WAIT;
        }
        let mut missing = 0;
        for r in &self.results {
            for ip in std::iter::once(&r.ip).chain(r.hops.iter().map(|x| &x.1)) {
                if pt_net(ip).is_empty() {
                    continue;
                }
                let Ok(a) = ip.parse::<IpAddr>() else { continue };
                if owner.get(&a, now).is_none() {
                    owner.want(a, now);
                    missing += 1;
                }
            }
        }
        if missing > 0 && now < self.owners_until {
            return false;
        }
        for r in self.results.iter_mut() {
            if let Some(i) = r.ip.parse::<IpAddr>().ok().and_then(|a| owner.get(&a, now)) {
                r.asn = i.asn.clone();
                r.owner = i.brand.clone();
            }
        }
        true
    }

    pub fn close(self, poller: &Poller) {
        poller.del(self.icmp);
        unsafe { libc::close(self.icmp) };
    }
}

// ---------------- движок: когда трассировать, подтверждение ----------------

#[derive(Default)]
struct Fam {
    bad_from: u64,
    good_from: u64,
    next_run: u64,
    last: Option<Verdict>,
    open: Option<Verdict>,
    misses: usize,
}

#[derive(Default)]
pub struct PathCulprit {
    fam: [Fam; 2],
}

fn fidx(f: &str) -> usize {
    if f == "ipv6" {
        1
    } else {
        0
    }
}

impl PathCulprit {
    /// Итоги прогона: разбор и подтверждение (дважды подряд) / снятие.
    pub fn finish(&mut self, fam: &'static str, results: &[PtResult], own: &mut OwnerFn, wall: i64) -> Vec<String> {
        let mut msgs = Vec::new();
        let v = analyze(fam, results, own);
        match &v {
            Some(v) => crate::log_info!("path trace {}: {}", fam, v.text),
            None => crate::log_info!("path trace {}: общего виновника нет ({} целей)", fam, results.len()),
        }
        let f = &mut self.fam[fidx(fam)];
        match (f.open.clone(), v.clone()) {
            (Some(o), Some(mut nv)) if nv.key == o.key => {
                nv.since = o.since;
                f.open = Some(nv);
                f.misses = 0;
            }
            (Some(o), _) => {
                f.misses += 1;
                if f.misses >= 2 {
                    msgs.push(format!("{}: общий виновник больше не виден — {}", fam_name(fam), o.culprit));
                    f.open = None;
                    f.misses = 0;
                }
            }
            (None, Some(mut nv)) if f.last.as_ref().map_or(false, |l| l.key == nv.key) => {
                nv.since = wall;
                msgs.push(nv.text.clone());
                f.open = Some(nv);
                f.misses = 0;
            }
            _ => {}
        }
        f.last = v;
        msgs
    }

    /// Такт по протоколу: rate — успешность проб (< 0 — нет данных).
    /// Возвращает (сообщения, пора запустить прогон).
    pub fn tick(&mut self, now: u64, fam: &'static str, rate: f64, n_targets: usize, running: bool) -> (Vec<String>, bool) {
        let mut msgs = Vec::new();
        let f = &mut self.fam[fidx(fam)];
        if rate < 0.0 {
            f.bad_from = 0;
            f.good_from = 0;
        } else if rate < BAD_RATE && rate > 0.0 {
            f.good_from = 0;
            if f.bad_from == 0 {
                f.bad_from = now.max(1);
            }
        } else if rate >= GOOD_RATE {
            f.bad_from = 0;
            if f.good_from == 0 {
                f.good_from = now.max(1);
            }
            if let (Some(o), true) = (&f.open, now - f.good_from >= GOOD_FOR) {
                msgs.push(format!("{}: деградация прошла, общий виновник снят — {}", fam_name(fam), o.culprit));
                f.open = None;
                f.last = None;
                f.misses = 0;
            }
        } else {
            f.good_from = 0;
        }
        let want = f.bad_from != 0 && now - f.bad_from >= BAD_FOR && now >= f.next_run && !running && n_targets >= 3;
        if want {
            f.next_run = now + EVERY;
        }
        (msgs, want)
    }

    /// Действующий общий виновник (первый) — текст для центра сбора.
    pub fn open_first(&self) -> Option<String> {
        self.fam.iter().filter_map(|f| f.open.as_ref()).next().map(|v| format!("{}: общий виновник плохих маршрутов — {}", v.family, v.culprit))
    }

    pub fn open_json(&self, j: &mut J) -> bool {
        let open: Vec<&Verdict> = self.fam.iter().filter_map(|f| f.open.as_ref()).collect();
        if open.is_empty() {
            return false;
        }
        j.arr();
        for v in open {
            j.obj().key("family").str(v.family).key("key").str(&v.key);
            if !v.fork.is_empty() {
                j.key("fork").str(&v.fork);
            }
            j.key("culprit").str(&v.culprit);
            if !v.next.is_empty() {
                j.key("next").str(&v.next);
            }
            if v.stop {
                j.key("stop").bool(true);
            }
            j.key("bad").arr();
            for b in &v.bad {
                j.str(b);
            }
            j.end_arr().key("good").arr();
            for g in &v.good {
                j.str(g);
            }
            j.end_arr().key("text").str(&v.text);
            if v.since != 0 {
                j.key("since").str(&crate::util::rfc3339(v.since, 0));
            }
            j.end_obj();
        }
        j.end_arr();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(ip: &str, owner: &str, asn: &str, hops: &[&str], reached: i64) -> PtResult {
        PtResult { ip: ip.into(), owner: owner.into(), asn: asn.into(), hops: hops.iter().enumerate().map(|(i, h)| (i as u8 + 1, h.to_string())).collect(), sent: 6, reached, ..Default::default() }
    }

    #[test]
    fn culprit_fork_next() {
        // как Go TestPTAnalyze: плохие (Google, Yandex) через сеть провайдера
        // 192.0.2.128/… → AS «Sparkle»; хороший (Cloudflare) — в обход
        let mut own = |ip: &str| -> Option<(String, String)> {
            Some(match ip {
                "198.51.100.1" | "198.51.100.2" => ("100".into(), "ISP".into()),
                "192.0.2.9" => ("100".into(), "ISP".into()),
                "203.0.113.7" => ("6762".into(), "Sparkle".into()),
                _ => (String::new(), String::new()),
            })
        };
        let r = vec![
            res("8.8.4.4", "Google/YouTube", "15169", &["198.51.100.1", "192.0.2.9", "203.0.113.7"], 1),
            res("77.88.55.88", "Yandex", "13238", &["198.51.100.1", "192.0.2.9"], 0),
            res("1.0.0.2", "Cloudflare", "13335", &["198.51.100.1", "198.51.100.2", "1.0.0.2"], 6),
        ];
        let v = analyze("ipv4", &r, &mut own).expect("виновник");
        assert_eq!(v.key, "net 192.0.2.0/24");
        assert_eq!(v.fork, "198.51.100.1");
        assert_eq!(v.next, "Sparkle (AS6762)");
        assert!(v.stop);
        assert!(v.text.starts_with("IPv4: общий виновник — стык ISP (AS100) 192.0.2.0/24 → Sparkle (AS6762)"), "{}", v.text);
        // подтверждение — дважды подряд
        let mut pc = PathCulprit::default();
        assert!(pc.finish("ipv4", &r, &mut own, 100).is_empty());
        assert_eq!(pc.finish("ipv4", &r, &mut own, 200).len(), 1);
        assert!(pc.fam[0].open.is_some());
    }

    #[test]
    fn icmp_quote() {
        // ICMP time exceeded: тип 11 + 4 байта + цитата IPv4 (20) + TCP (порты)
        let mut b = vec![11u8, 0, 0, 0, 0, 0, 0, 0];
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[16..20].copy_from_slice(&[8, 8, 4, 4]);
        b.extend_from_slice(&ip);
        b.extend_from_slice(&[0xc3, 0x50, 1, 187]);
        assert_eq!(quoted(&b, false), Some(("8.8.4.4".parse().unwrap(), 50000)));
    }
}
