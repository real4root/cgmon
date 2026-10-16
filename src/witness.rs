//! Метрики по сайтам — «свидетели» (перенос witness.go, режим observe):
//! оценка IPv4/IPv6 баллами. Свидетели — публичные адреса, куда клиенты ходят
//! (≥ 3 рукопожатий за 5 мин, хотя бы одно удачное), ≤ 1 на /24 (/48) и на
//! владельца (AS); раз в interval_sec роутер сам подключается к каждому
//! (tcp/443, IPv6 — с адреса WAN). Надёжность учится, только пока отвечает
//! ≥ 60% остальных. Балл — меньшая из долей ответивших (взвешенной и простой),
//! медленный ответ — частичный зачёт, +10 за вернувшегося, сглаживание.
//! Без клиентского IPv6 — кандидаты из AAAA самых частых имён (публичные DNS).
//! Раунды и DNS — в общем epoll.

use crate::config::WitnessConfig;
use crate::dns::{self, Client};
use crate::dnswatch::DnsWatch;
use crate::evloop::Poller;
use crate::ipowner::IpOwner;
use crate::json::J;
use crate::netx;
use crate::probe::{Kind, Outcome, Probe};
use crate::synrtt::SynRtt;
use crate::value::{parse_json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

const LEARN_WIN: u64 = 5 * 60 * 1000;
const MIN_HITS: usize = 3;
const WEAK: f64 = 0.3;
const WEAK_FOR: u64 = 3600 * 1000;
const DISAGREE: u64 = 5 * 60 * 1000;
const SAVE_EVERY: u64 = 10 * 60 * 1000;
const PER_OWNER: usize = 1;
const PEND_KEEP: u64 = 10 * 60 * 1000;
const SEED_EVERY: u64 = 5 * 60 * 1000;
const SEED_RETRY: u64 = 6 * 3600 * 1000;
const SEED_NAMES: usize = 8;
const DROP_FOR: u64 = 24 * 3600 * 1000;
const ROUND_TIMEOUT: u64 = 3000;

/// Публичные DNS-серверы: не свидетели (anycast, DoH часто фильтруют).
pub const DNS_IPS: &[&str] = &[
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844", "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "2620:fe::fe", "2620:fe::9", "2620:fe::10", "208.67.222.222", "208.67.220.220",
    "2620:119:35::35", "2620:119:53::53", "77.88.8.8", "77.88.8.1", "2a02:6b8::feed:ff", "2a02:6b8:0:1::feed:ff", "94.140.14.14", "94.140.15.15",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
];

/// Публичные DNS по IPv4 (во время сбоя IPv6 доступны).
const RESOLVERS: [&str; 3] = ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"];

#[derive(Clone, Debug)]
struct Wit {
    ip: IpAddr,
    rel: f64,
    added: i64,
    ok: i64,
    fail: i64,
    name: String,
    as_: String,
    brand: String,
    base: f64,
    credit: f64,
    streak: i64,
    last: bool,
    ms: f64,
    weak: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Fam {
    pub score: f64,
    pub raw: f64,
    pub verdict: &'static str,
    pub n: i64,
    pub answered: i64,
    pub returned: i64,
    pub slow: i64,
    pub rounds: i64,
}

impl Default for Wit {
    fn default() -> Self {
        Wit { ip: IpAddr::from([0, 0, 0, 0]), rel: 0.0, added: 0, ok: 0, fail: 0, name: String::new(), as_: String::new(), brand: String::new(), base: 0.0, credit: 0.0, streak: 0, last: false, ms: 0.0, weak: 0 }
    }
}

struct Round {
    started: u64,
    res: HashMap<IpAddr, (bool, f64)>,
    flight: HashMap<u64, Probe>,
}

struct SeedJob {
    name: String,
    server: usize,
}

pub struct Witness {
    pub cfg: WitnessConfig,
    w: [Vec<Wit>; 2],
    pub fam: [Option<Fam>; 2],
    next_round: u64,
    saved_at: u64,
    dirty: bool,
    loaded: bool,
    since: [u64; 2],
    told: [String; 2],
    dropped: HashMap<IpAddr, u64>,
    probes: Vec<IpAddr>,
    pend: Vec<(IpAddr, String, u64)>,
    round: Option<Round>,
    tok_base: u64,
    next_tok: u64,
    tag_base: u64,
    seed_at: u64,
    tried: HashMap<String, u64>,
    seeds: HashMap<u64, SeedJob>,
}

fn fi(f: usize) -> &'static str {
    if f == 0 {
        "ipv4"
    } else {
        "ipv6"
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// /24 или /48: не больше одного свидетеля на сеть.
pub fn prefix(ip: &IpAddr) -> IpAddr {
    netx::IpNet::new(*ip, if ip.is_ipv4() { 24 } else { 48 }).ip
}

/// Публичный адрес (не частный, не CGNAT, не служебный).
pub fn public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(netx::is_private4(o) || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_multicast() || (o[0] == 100 && o[1] & 0xc0 == 64))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || s[0] & 0xffc0 == 0xfe80 || s[0] & 0xfe00 == 0xfc00)
        }
    }
}

/// Зачёт ответа за задержку: до 2×опорной+50 мс — полный, дальше
/// пропорционально, но не меньше четверти.
pub fn credit(ms: f64, reference: f64) -> f64 {
    if reference <= 0.0 {
        return 1.0;
    }
    let lim = 2.0 * reference + 50.0;
    if ms <= lim {
        1.0
    } else {
        (lim / ms).max(0.25)
    }
}

impl Witness {
    pub fn new(cfg: &WitnessConfig, tok_base: u64, tag_base: u64) -> Witness {
        Witness {
            cfg: cfg.clone(),
            w: [Vec::new(), Vec::new()],
            fam: [None, None],
            next_round: 0,
            saved_at: 0,
            dirty: false,
            loaded: false,
            since: [0; 2],
            told: [String::new(), String::new()],
            dropped: HashMap::new(),
            probes: Vec::new(),
            pend: Vec::new(),
            round: None,
            tok_base,
            next_tok: 0,
            tag_base,
            seed_at: 0,
            tried: HashMap::new(),
            seeds: HashMap::new(),
        }
    }

    pub fn owns(&self, tok: u64) -> bool {
        tok & !0xffff_ffff == self.tok_base
    }

    fn excluded(&self, ip: &IpAddr) -> bool {
        self.probes.contains(ip) || DNS_IPS.iter().any(|d| d.parse::<IpAddr>().map_or(false, |x| x == *ip))
    }

    /// Цели проб cgmon — не свидетели.
    pub fn set_probes(&mut self, ips: &[IpAddr]) {
        self.probes = ips.to_vec();
        let pr = self.probes.clone();
        for l in self.w.iter_mut() {
            l.retain(|w| !pr.contains(&w.ip) && !DNS_IPS.iter().any(|d| d.parse::<IpAddr>().map_or(false, |x| x == w.ip)));
        }
    }

    /// Адреса свидетелей семейства (цели поиска виновника).
    pub fn ips_of(&self, fam: &str) -> Vec<IpAddr> {
        self.w[if fam == "ipv6" { 1 } else { 0 }].iter().map(|w| w.ip).collect()
    }

    /// Адреса свидетелей (SynRTT их не считает).
    pub fn ips(&self) -> Vec<IpAddr> {
        self.w.iter().flatten().map(|w| w.ip).collect()
    }

    /// Владелец: «AS<n>», не выяснилась — «net <сеть>»; выясняется — None.
    fn owner_of(owner: &mut IpOwner, ip: &IpAddr, now: u64) -> Option<(String, String)> {
        match owner.get(ip, now) {
            None => {
                owner.want(*ip, now);
                None
            }
            Some(i) if i.asn.is_empty() => Some((format!("net {}", prefix(ip)), String::new())),
            Some(i) => Some((format!("AS{}", i.asn), i.brand.clone())),
        }
    }

    fn load(&mut self) {
        self.loaded = true;
        let Ok(t) = std::fs::read_to_string(crate::storage::path(&self.cfg.state_file)) else { return };
        let Ok(v) = parse_json(&t) else { return };
        for f in 0..2 {
            let Some(Value::List(l)) = v.get(fi(f)) else { continue };
            for x in l {
                let Some(ip) = x.get("ip").and_then(|s| s.as_str()).and_then(|s| s.parse::<IpAddr>().ok()) else { continue };
                if !public(&ip) || ip.is_ipv6() != (f == 1) || self.excluded(&ip) || self.w[f].len() >= 64 {
                    continue;
                }
                let s = |k: &str| x.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let n = |k: &str| x.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
                let added = x.get("added").and_then(|v| v.as_str()).and_then(crate::util::parse_rfc3339).map_or(0, |t| t.0);
                self.w[f].push(Wit { ip, rel: n("rel"), added, ok: n("ok") as i64, fail: n("fail") as i64, name: s("name"), as_: s("as"), brand: s("brand"), base: n("base"), ..Default::default() });
            }
        }
    }

    fn save(&mut self, now: u64) {
        if !self.dirty || now - self.saved_at < SAVE_EVERY || self.cfg.state_file.is_empty() || crate::util::readonly() {
            return;
        }
        self.dirty = false;
        self.saved_at = now;
        let mut j = J::new();
        j.obj();
        for f in 0..2 {
            j.key(fi(f)).arr();
            for w in &self.w[f] {
                j.obj().key("ip").str(&w.ip.to_string()).key("rel").raw(&crate::config::go_float(w.rel)).key("added").str(&crate::util::rfc3339(w.added, 0));
                j.key("ok").int(w.ok).key("fail").int(w.fail);
                if !w.name.is_empty() {
                    j.key("name").str(&w.name);
                }
                if !w.as_.is_empty() {
                    j.key("as").str(&w.as_);
                }
                if !w.brand.is_empty() {
                    j.key("brand").str(&w.brand);
                }
                if w.base != 0.0 {
                    j.key("base").raw(&crate::config::go_float(w.base));
                }
                j.end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
        let _ = crate::util::write_atomic(&crate::storage::path(&self.cfg.state_file), j.b.as_bytes(), 0o600);
    }

    /// Новые свидетели из рукопожатий клиентов и найденных через DNS.
    fn learn(&mut self, now: u64, wall: i64, syn: &SynRtt, owner: &mut IpOwner) -> bool {
        self.dropped.retain(|_, t| now - *t < DROP_FOR);
        let (mut hits, mut ok_n): (HashMap<IpAddr, usize>, HashMap<IpAddr, usize>) = (HashMap::new(), HashMap::new());
        for o in syn.since(now.saturating_sub(LEARN_WIN)) {
            if public(&o.ip) && !self.excluded(&o.ip) {
                *hits.entry(o.ip).or_insert(0) += 1;
                if o.ok {
                    *ok_n.entry(o.ip).or_insert(0) += 1;
                }
            }
        }
        let mut changed = false;
        self.pend.retain(|c| now - c.2 < PEND_KEEP);
        for f in 0..2 {
            // слабые дольше часа — освобождают место
            let mut keep = Vec::new();
            for mut w in std::mem::take(&mut self.w[f]) {
                if w.weak != 0 && now - w.weak >= WEAK_FOR {
                    changed = true;
                    self.dropped.insert(w.ip, now);
                    continue;
                }
                if w.as_.is_empty() {
                    if let Some((a, b)) = Self::owner_of(owner, &w.ip, now) {
                        w.as_ = a;
                        w.brand = b;
                        changed = true;
                    }
                }
                keep.push(w);
            }
            // не больше PER_OWNER на владельца: остаются самые надёжные
            keep.sort_by(|a, b| b.rel.partial_cmp(&a.rel).unwrap_or(std::cmp::Ordering::Equal));
            let mut per: HashMap<String, usize> = HashMap::new();
            let mut cur = Vec::new();
            for w in keep {
                if !w.as_.is_empty() {
                    let n = per.entry(w.as_.clone()).or_insert(0);
                    if *n >= PER_OWNER {
                        changed = true;
                        continue;
                    }
                    *n += 1;
                }
                cur.push(w);
            }
            self.w[f] = cur;
            if self.w[f].len() >= self.cfg.per_family as usize {
                continue;
            }
            let have: Vec<IpAddr> = self.w[f].iter().map(|w| w.ip).collect();
            let mut nets: Vec<IpAddr> = have.iter().map(prefix).collect();
            let mut cand: Vec<IpAddr> = hits.iter().filter(|(ip, n)| **n >= MIN_HITS && ok_n.get(*ip).copied().unwrap_or(0) > 0 && ip.is_ipv6() == (f == 1) && !have.contains(ip) && !self.dropped.contains_key(*ip)).map(|(ip, _)| *ip).collect();
            cand.sort_by(|a, b| hits[b].cmp(&hits[a]).then(a.to_string().cmp(&b.to_string())));
            let mut names: HashMap<IpAddr, String> = HashMap::new();
            for (ip, name, _) in &self.pend {
                if ip.is_ipv6() == (f == 1) && !have.contains(ip) && !names.contains_key(ip) && !self.dropped.contains_key(ip) {
                    cand.push(*ip);
                    names.insert(*ip, name.clone());
                }
            }
            let mut done: Vec<IpAddr> = Vec::new();
            for ip in cand {
                if self.w[f].len() >= self.cfg.per_family as usize {
                    break;
                }
                if nets.contains(&prefix(&ip)) {
                    done.push(ip);
                    continue;
                }
                let Some((as_, brand)) = Self::owner_of(owner, &ip, now) else { continue };
                done.push(ip);
                let n = per.entry(as_.clone()).or_insert(0);
                if *n >= PER_OWNER {
                    continue;
                }
                *n += 1;
                nets.push(prefix(&ip));
                self.w[f].push(Wit { ip, rel: 0.5, added: wall, last: true, name: names.get(&ip).cloned().unwrap_or_default(), as_, brand, ..Default::default() });
                changed = true;
            }
            self.pend.retain(|c| !done.contains(&c.0));
        }
        if changed {
            self.dirty = true;
        }
        changed
    }

    /// Итоги раунда: надёжность, балл, вердикт.
    fn apply(&mut self, now: u64, res: &HashMap<IpAddr, (bool, f64)>) {
        // самая быстрая задержка владельца по каждому протоколу
        let mut fast: [HashMap<String, f64>; 2] = [HashMap::new(), HashMap::new()];
        for f in 0..2 {
            for w in &self.w[f] {
                if let Some((true, ms)) = res.get(&w.ip) {
                    if !w.as_.is_empty() {
                        let e = fast[f].entry(w.as_.clone()).or_insert(*ms);
                        if *ms < *e {
                            *e = *ms;
                        }
                    }
                }
            }
        }
        for f in 0..2 {
            let n = self.w[f].iter().filter(|w| res.contains_key(&w.ip)).count() as i64;
            let answered = self.w[f].iter().filter(|w| res.get(&w.ip).map_or(false, |r| r.0)).count() as i64;
            if n == 0 {
                continue;
            }
            let (mut sum_w, mut sum_ok) = (0.0, 0.0);
            let (mut returned, mut slow) = (0, 0);
            let other = &fast[1 - f];
            for w in self.w[f].iter_mut() {
                let Some(&(ok, ms)) = res.get(&w.ip) else { continue };
                // остальные отвечают — ответ этого узла говорит о нём самом
                let others = n - 1;
                let others_ok = answered - if ok { 1 } else { 0 };
                if others >= 2 && others_ok as f64 >= 0.6 * others as f64 {
                    w.rel = 0.9 * w.rel + 0.1 * if ok { 1.0 } else { 0.0 };
                }
                if w.rel < WEAK {
                    if w.weak == 0 {
                        w.weak = now.max(1);
                    }
                } else {
                    w.weak = 0;
                }
                sum_w += w.rel;
                if ok {
                    let reference = match other.get(&w.as_) {
                        Some(r) if !w.as_.is_empty() => *r,
                        _ => w.base,
                    };
                    w.credit = credit(ms, reference);
                    if w.credit < 1.0 {
                        slow += 1;
                    }
                    sum_ok += w.rel * w.credit;
                    w.base = if w.base == 0.0 || ms < w.base { round1(ms) } else { round1(w.base + 0.01 * (ms - w.base)) };
                    w.ok += 1;
                    if w.streak >= 2 {
                        returned += 1;
                    }
                    w.streak = 0;
                    w.ms = ms;
                } else {
                    w.fail += 1;
                    w.streak += 1;
                }
                w.last = ok;
            }
            let mut raw = 100.0 * answered as f64 / n as f64;
            if sum_w > 0.0 && 100.0 * sum_ok / sum_w < raw {
                raw = 100.0 * sum_ok / sum_w;
            }
            raw = (raw + 10.0 * returned as f64).min(100.0);
            let fm = self.fam[f].get_or_insert(Fam { score: raw, ..Default::default() });
            if fm.rounds > 0 {
                fm.score = 0.5 * fm.score + 0.5 * raw;
            }
            fm.raw = round1(raw);
            fm.n = n;
            fm.answered = answered;
            fm.returned = returned;
            fm.slow = slow;
            fm.score = round1(fm.score);
            fm.rounds += 1;
            fm.verdict = if n < 3 {
                ""
            } else if fm.score >= 70.0 {
                "ok"
            } else if fm.score >= 40.0 {
                "degraded"
            } else {
                "bad"
            };
        }
        self.dirty = true;
    }

    /// Расхождение оценки со старым диагнозом дольше 5 мин → журнал.
    fn compare(&mut self, now: u64, diag: &str, v6: bool) -> Vec<String> {
        let known = matches!(diag, "HEALTHY" | "IPV6_DEGRADATION" | "IPV4_EXTERNAL_DEGRADATION");
        let mut msgs = Vec::new();
        for f in 0..2 {
            let name = if f == 0 { "IPv4" } else { "IPv6" };
            let mut kind = String::new();
            if let Some(fm) = &self.fam[f] {
                if known && !fm.verdict.is_empty() && (f == 0 || v6) {
                    let old_bad = (f == 1 && diag == "IPV6_DEGRADATION") || (f == 0 && diag == "IPV4_EXTERNAL_DEGRADATION");
                    if old_bad && fm.verdict == "ok" {
                        kind = format!("сайты отвечают, а диагноз — деградация {name}");
                    } else if !old_bad && fm.verdict == "bad" {
                        kind = "сайты не отвечают, а диагноз этого сбоя не видит".into();
                    }
                }
            }
            if kind.is_empty() {
                self.since[f] = 0;
                if !self.told[f].is_empty() && known {
                    self.told[f].clear();
                    if let Some(fm) = &self.fam[f] {
                        msgs.push(format!("Метрики по сайтам: {} — оценка снова совпадает с диагнозом (балл {:.0}, ответили {} из {})", name, fm.score, fm.answered, fm.n));
                    }
                }
                continue;
            }
            if self.since[f] == 0 || (!self.told[f].is_empty() && self.told[f] != kind) {
                self.since[f] = now.max(1);
                if self.told[f] != kind {
                    self.told[f].clear();
                }
            }
            if self.told[f].is_empty() && now - self.since[f] >= DISAGREE {
                self.told[f] = kind.clone();
                let fm = self.fam[f].as_ref().unwrap();
                msgs.push(format!("Метрики по сайтам: {} — {} (балл {:.0}, ответили {} из {})", name, kind, fm.score, fm.answered, fm.n));
            }
        }
        msgs
    }

    /// Такт (после фазы WAN): обучение, поиск IPv6 через DNS, раунд.
    #[allow(clippy::too_many_arguments)]
    pub fn tick(&mut self, now: u64, wall: i64, v6: bool, diag: &str, syn: &SynRtt, dnsw: &DnsWatch, owner: &mut IpOwner, dnsc: &mut Client, poller: &Poller, v6src: Option<IpAddr>) -> (Vec<String>, bool) {
        if self.cfg.mode == "off" {
            return (Vec::new(), false);
        }
        if !self.loaded {
            self.load();
        }
        let mut changed = self.learn(now, wall, syn, owner);
        // ответы поиска IPv6-свидетелей
        let (lo, hi) = (self.tag_base, self.tag_base | 0xffff_ffff);
        for (tag, ans) in dnsc.take(lo, hi) {
            let Some(job) = self.seeds.remove(&tag) else { continue };
            match ans {
                Some(a) if a.rcode == 0 || a.rcode == 3 => {
                    if let Some(ip) = a.ips.into_iter().find(|ip| ip.is_ipv6() && public(ip) && !self.excluded(ip)) {
                        let _ = Self::owner_of(owner, &ip, now); // начать выяснение
                        if self.pend.len() < 64 {
                            self.pend.push((ip, job.name, now));
                        }
                    }
                }
                _ if job.server + 1 < RESOLVERS.len() => {
                    // сервер не ответил — следующий
                    self.next_tok += 1;
                    let tag = self.tag_base | (self.next_tok & 0xffff_ffff);
                    let srv: SocketAddr = RESOLVERS[job.server + 1].parse().unwrap();
                    dnsc.query(poller, srv, &job.name, dns::TYPE_AAAA, tag, 3000, now);
                    self.seeds.insert(tag, SeedJob { name: job.name, server: job.server + 1 });
                }
                _ => {}
            }
        }
        if v6 && self.w[1].len() < self.cfg.per_family as usize && now >= self.seed_at && self.seeds.is_empty() {
            self.seed_at = now + SEED_EVERY;
            self.tried.retain(|_, t| now - *t < SEED_RETRY);
            let mut n = 0;
            for name in dnsw.recent_names(now.saturating_sub(30 * 60 * 1000), 50) {
                if n >= SEED_NAMES {
                    break;
                }
                if self.tried.contains_key(&name) || crate::livecfg::wit_dns_name(&name) {
                    continue;
                }
                self.tried.insert(name.clone(), now);
                n += 1;
                self.next_tok += 1;
                let tag = self.tag_base | (self.next_tok & 0xffff_ffff);
                dnsc.query(poller, RESOLVERS[0].parse().unwrap(), &name, dns::TYPE_AAAA, tag, 3000, now);
                self.seeds.insert(tag, SeedJob { name, server: 0 });
            }
        }
        let msgs = self.compare(now, diag, v6);
        self.save(now);
        // раунд
        if self.round.is_none() && now >= self.next_round {
            self.next_round = now + self.cfg.interval_sec.max(10) as u64 * 1000;
            let mut r = Round { started: now, res: HashMap::new(), flight: HashMap::new() };
            for f in 0..2 {
                if f == 1 && !v6 {
                    continue;
                }
                for w in &self.w[f] {
                    let src = if f == 1 { v6src } else { None };
                    match Probe::start(Kind::Tcp, SocketAddr::new(w.ip, 443), src, now) {
                        Ok(p) => {
                            self.next_tok += 1;
                            let tok = self.tok_base | (self.next_tok & 0xffff_ffff);
                            if poller.add(p.fd, p.events(), tok).is_ok() {
                                r.flight.insert(tok, p);
                            }
                        }
                        Err(_) => {
                            r.res.insert(w.ip, (false, 0.0));
                        }
                    }
                }
            }
            if !r.flight.is_empty() || !r.res.is_empty() {
                self.round = Some(r);
            }
        }
        changed |= self.finish_round(now, poller);
        (msgs, changed)
    }

    /// Событие сокета раунда.
    pub fn on_event(&mut self, tok: u64, poller: &Poller, now: u64) {
        let Some(r) = self.round.as_mut() else { return };
        if let Some(p) = r.flight.remove(&tok) {
            poller.del(p.fd);
            let o = p.finish();
            let ms = (now - p.started) as f64;
            // RST — путь жив
            r.res.insert(p.addr.ip(), (matches!(o, Outcome::Ok | Outcome::Refused), ms));
        }
    }

    /// Раунд закончен (все ответили или таймаут 3 с) — применить.
    fn finish_round(&mut self, now: u64, poller: &Poller) -> bool {
        let Some(r) = self.round.as_mut() else { return false };
        if !r.flight.is_empty() && now - r.started < ROUND_TIMEOUT {
            return false;
        }
        for (_, p) in r.flight.drain() {
            poller.del(p.fd);
            r.res.insert(p.addr.ip(), (false, 0.0));
        }
        let r = self.round.take().unwrap();
        self.apply(r.started, &r.res);
        true
    }

    pub fn verdict(&self, f: &str) -> &'static str {
        if self.cfg.mode == "off" {
            return "";
        }
        self.fam[if f == "ipv6" { 1 } else { 0 }].as_ref().map_or("", |x| x.verdict)
    }

    /// Балл протокола (-1 — нет оценки).
    pub fn score(&self, f: &str) -> f64 {
        match &self.fam[if f == "ipv6" { 1 } else { 0 }] {
            Some(x) if self.cfg.mode != "off" && x.n > 0 => x.score,
            _ => -1.0,
        }
    }

    pub fn status_json(&self, j: &mut J) {
        use crate::config::go_float;
        j.obj().key("mode").str(&self.cfg.mode);
        for (k, f) in [("v4", 0), ("v6", 1)] {
            if let Some(m) = &self.fam[f] {
                j.key(k).obj().key("score").raw(&go_float(m.score)).key("raw").raw(&go_float(m.raw));
                if !m.verdict.is_empty() {
                    j.key("verdict").str(m.verdict);
                }
                j.key("n").int(m.n).key("answered").int(m.answered);
                if m.returned > 0 {
                    j.key("returned").int(m.returned);
                }
                if m.slow > 0 {
                    j.key("slow").int(m.slow);
                }
                j.key("rounds").int(m.rounds).end_obj();
            }
        }
        if self.w.iter().any(|l| !l.is_empty()) {
            j.key("list").arr();
            for f in 0..2 {
                for w in &self.w[f] {
                    j.obj().key("ip").str(&w.ip.to_string()).key("family").str(fi(f)).key("rel").raw(&go_float(round1(w.rel * 100.0))).key("ok").bool(w.last);
                    if w.ms != 0.0 {
                        j.key("ms").raw(&go_float(round1(w.ms)));
                    }
                    if !w.name.is_empty() {
                        j.key("name").str(&w.name);
                    }
                    let owner = if !w.brand.is_empty() { w.brand.clone() } else if w.as_.starts_with("AS") { w.as_.clone() } else { String::new() };
                    if !owner.is_empty() {
                        j.key("owner").str(&owner);
                    }
                    if w.last && w.credit > 0.0 && w.credit < 1.0 {
                        j.key("credit").raw(&go_float(round1(w.credit * 100.0)));
                    }
                    j.end_obj();
                }
            }
            j.end_arr();
        }
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wit(cfg_per: i64) -> Witness {
        let mut c = crate::config::defaults();
        c.normalize();
        c.witness.mode = "observe".into();
        c.witness.per_family = cfg_per;
        Witness::new(&c.witness, 5 << 48, 2 << 40)
    }

    #[test]
    fn credit_and_public() {
        assert_eq!(credit(100.0, 40.0), 1.0);
        assert!((credit(260.0, 40.0) - 130.0 / 260.0).abs() < 1e-9);
        assert_eq!(credit(10000.0, 40.0), 0.25);
        assert!(!public(&"100.64.1.1".parse().unwrap()) && !public(&"fd00::1".parse().unwrap()) && public(&"8.8.4.5".parse().unwrap()));
        assert_eq!(prefix(&"198.51.100.77".parse().unwrap()).to_string(), "198.51.100.0");
    }

    #[test]
    fn score_min_of_weighted_and_plain() {
        // как Go TestWitness*: 8 свидетелей, 4 ответили → балл не выше 50
        let mut x = wit(12);
        let mut res = HashMap::new();
        for i in 0..8u8 {
            let ip: IpAddr = format!("198.51.{}.1", 100 + i).parse().unwrap();
            x.w[0].push(Wit { ip, rel: if i < 4 { 0.9 } else { 0.2 }, as_: format!("AS{i}"), ..Default::default() });
            res.insert(ip, (i < 4, 40.0));
        }
        x.apply(1000, &res);
        let f = x.fam[0].as_ref().unwrap();
        assert_eq!((f.n, f.answered), (8, 4));
        assert!(f.score <= 50.0, "{}", f.score);
        assert_eq!(f.verdict, "degraded");
        // вернувшийся (2 неудачи подряд) — бонус
        for w in x.w[0].iter_mut() {
            w.streak = 2;
        }
        let all: HashMap<IpAddr, (bool, f64)> = res.keys().map(|k| (*k, (true, 40.0))).collect();
        x.apply(2000, &all);
        assert_eq!(x.fam[0].as_ref().unwrap().raw, 100.0);
    }

    #[test]
    fn disagreement() {
        let mut x = wit(12);
        x.fam[1] = Some(Fam { score: 90.0, verdict: "ok", n: 6, answered: 6, ..Default::default() });
        assert!(x.compare(1000, "IPV6_DEGRADATION", true).is_empty());
        let m = x.compare(1000 + DISAGREE, "IPV6_DEGRADATION", true);
        assert_eq!(m, vec!["Метрики по сайтам: IPv6 — сайты отвечают, а диагноз — деградация IPv6 (балл 90, ответили 6 из 6)"]);
        let m = x.compare(1000 + DISAGREE + 10, "HEALTHY", true);
        assert!(m[0].contains("снова совпадает"));
    }
}
