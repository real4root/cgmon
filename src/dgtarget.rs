//! Адресный режим DNS-страховки (перенос dgtarget.go, dns_guard.mode: targeted).
//!
//! Штрафуется не весь протокол, а сеть одного владельца (AS):
//!  1. подозрение — рукопожатия клиентов за 5 мин: у владельца по протоколу
//!     ≥6 попыток и ≥30% без ответа или медиана ≥600 мс;
//!  2. подтверждение — роутер сам 6 раз подключается к адресам владельца по
//!     обоим протоколам (рабочий поток); альтернативы — по порядку настроек
//!     (proto — другой протокол через DNS, устройства — обход, dgroute.rs);
//!  3. штраф target_base_min, каждый следующий вдвое дольше (≤ target_max_hours);
//!     перед снятием — та же проверка; сутки без сбоев — ступень вниз;
//!  4. домены — второго уровня имён плохих адресов (DNSWatch), только если
//!     ≥80% известных адресов домена — того же владельца.
//! Файл targets_file пишет SmartDNS-правила (address /d/#6, nftset);
//! перезапуск SmartDNS: новый штраф/снятие ≥1 мин, только домены ≥10 мин.

use crate::dgsys::{self, Alt, Sys};
#[cfg(test)]
use crate::dnsguard;
use crate::dnsguard::{str_list, time_json, time_parse, vstr, Done, DnsGuard, Feed};
use crate::json::J;
use crate::livecfg::DGR_PROTO;
use crate::value::Value;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;
pub const WINDOW_MS: u64 = 5 * 60 * 1000;
const TEST_EVERY: i64 = 10 * MIN; // один владелец — не чаще
const MAX_TESTS: usize = 2; // проверок за минуту
const MAX_ACTIVE: usize = 20;
const MAX_DOMAINS: usize = 20;
const DECAY: i64 = 24 * HOUR; // сутки без сбоев — ступень штрафа вниз
const RESTART_GAP: i64 = MIN; // новый штраф / снятие
const ADD_GAP: i64 = 10 * MIN; // только дописать домены
pub const PROBE_N: usize = 6;

/// Штраф владельцу (dgTarget; поля без тега — только в памяти).
#[derive(Clone, Debug, Default)]
pub struct Target {
    pub as_: String,
    pub owner: String,
    pub fam: String,
    pub domains: Vec<String>,
    pub names: Vec<String>,
    pub ips: Vec<String>,
    pub alt: Vec<String>,
    pub strikes: i64,
    pub active: bool,
    pub since: i64,
    pub until: i64,
    pub last_bad: i64,
    pub decay: i64,
    pub reason: String,
    pub via: String,
    pub nets: Vec<String>,
    pub nets6: Vec<String>,
    pub tested: i64,
    pub testing: bool,
    pub pend: Vec<String>,
    pub pend6: Vec<String>,
    /// идёт досрочная перепроверка (раз в час): плохо — штраф как был, без новой ступени
    pub early: bool,
}

fn list_json(j: &mut J, k: &str, l: &[String]) {
    if !l.is_empty() {
        j.key(k).arr();
        for s in l {
            j.str(s);
        }
        j.end_arr();
    }
}

impl Target {
    /// Обход маршрутом, а не через DNS другого протокола.
    pub fn via_path(&self) -> bool {
        !self.via.is_empty() && self.via != DGR_PROTO
    }

    pub fn json(&self, j: &mut J) {
        j.obj().key("as").str(&self.as_).key("owner").str(&self.owner).key("fam").str(&self.fam);
        list_json(j, "domains", &self.domains);
        list_json(j, "names", &self.names);
        list_json(j, "ips", &self.ips);
        list_json(j, "alt", &self.alt);
        j.key("strikes").int(self.strikes).key("active").bool(self.active);
        for (k, v) in [("since", self.since), ("until", self.until), ("last_bad", self.last_bad), ("decay", self.decay)] {
            if v != 0 {
                j.key(k).str(&time_json(v));
            }
        }
        if !self.reason.is_empty() {
            j.key("reason").str(&self.reason);
        }
        if !self.via.is_empty() {
            j.key("via").str(&self.via);
        }
        list_json(j, "nets", &self.nets);
        list_json(j, "nets6", &self.nets6);
        j.end_obj();
    }

    pub fn from(v: &Value) -> Target {
        Target {
            as_: vstr(v, "as"),
            owner: vstr(v, "owner"),
            fam: vstr(v, "fam"),
            domains: str_list(v.get("domains")),
            names: str_list(v.get("names")),
            ips: str_list(v.get("ips")),
            alt: str_list(v.get("alt")),
            strikes: v.get("strikes").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64,
            active: v.get("active").and_then(|x| x.as_bool()).unwrap_or(false),
            since: time_parse(v.get("since")),
            until: time_parse(v.get("until")),
            last_bad: time_parse(v.get("last_bad")),
            decay: time_parse(v.get("decay")),
            reason: vstr(v, "reason"),
            via: vstr(v, "via"),
            nets: str_list(v.get("nets")),
            nets6: str_list(v.get("nets6")),
            ..Default::default()
        }
    }
}

pub fn key(as_: &str, fam: &str) -> String {
    format!("{as_}/{fam}")
}

pub fn other(fam: &str) -> &'static str {
    if fam == "ipv6" {
        "ipv4"
    } else {
        "ipv6"
    }
}

pub fn fam_name(fam: &str) -> &'static str {
    if fam == "ipv6" {
        "IPv6"
    } else {
        "IPv4"
    }
}

/// Срок штрафа ступени n (base, 2·base, 4·base… не больше max), мс.
pub fn dur(n: i64, base_min: i64, max_hours: i64) -> i64 {
    let n = n.max(1);
    let max = max_hours * HOUR;
    let mut d = base_min * MIN;
    let mut i = 1;
    while i < n && d < max {
        d *= 2;
        i += 1;
    }
    d.min(max)
}

/// «45 мин» / «2 ч».
pub fn dur_text(ms: i64) -> String {
    if ms < HOUR {
        return format!("{} мин", ms / MIN);
    }
    format!("{} ч", (ms as f64 / HOUR as f64).round() as i64)
}

pub fn list_text(l: &[String]) -> String {
    if l.len() > 6 {
        return format!("{} и ещё {}", l[..6].join(", "), l.len() - 6);
    }
    l.join(", ")
}

/// Итог проверки владельца (dgtTest).
#[derive(Clone, Debug, Default)]
pub struct Test {
    pub key: String,
    pub recheck: bool,
    pub ok_bad: usize,
    pub ok_alt: usize,
    pub med_bad: f64,
    pub med_alt: f64,
    pub n_bad: usize,
    pub n_alt: usize,
    pub ips: Vec<String>,
    pub alt: Vec<String>,
    pub names: Vec<String>,
    pub via: String,
    pub via_name: String,
    pub ok_via: usize,
    pub med_via: f64,
    pub skipped: Vec<String>,
    pub slow_only: bool,
}

impl Test {
    /// Плохой ли протокол владельца и хорош ли другой.
    pub fn verdict(&self) -> (bool, bool) {
        let alt_good = self.n_alt > 0 && self.ok_alt + 1 >= self.n_alt;
        let slow = self.ok_bad > 0 && self.ok_alt > 0 && self.med_bad > 2.0 * self.med_alt + 50.0;
        let bad = self.n_bad > 0 && (self.ok_bad + 2 <= self.n_bad || slow);
        (bad, alt_good)
    }

    pub fn describe_via(&self, fam: &str) -> String {
        let f = fam_name(fam);
        let mut direct = format!("напрямую по {f} ответили {} из {}", self.ok_bad, self.n_bad);
        if self.ok_bad > 0 {
            direct.push_str(&format!(" ({:.0} мс)", self.med_bad));
        }
        let mut s = format!("{direct}, через {} — {} из {} ({:.0} мс)", self.via_name, self.ok_via, PROBE_N, self.med_via);
        if !self.skipped.is_empty() {
            s.push_str(&format!("; пропущены: {}", self.skipped.join(", ")));
        }
        s
    }

    pub fn describe(&self, fam: &str) -> String {
        let (f, o) = (fam_name(fam), fam_name(other(fam)));
        if self.ok_bad + 2 > self.n_bad && self.ok_bad > 0 && self.ok_alt > 0 && self.med_bad > 2.0 * self.med_alt + 50.0 {
            return format!("по {f} медленно: {:.0} мс против {:.0} мс по {o}", self.med_bad, self.med_alt);
        }
        let ms = |ok: usize, m: f64| if ok == 0 { String::new() } else { format!(" ({m:.0} мс)") };
        format!("по {f} ответили {} из {}{}, по {o} — {} из {}{}", self.ok_bad, self.n_bad, ms(self.ok_bad, self.med_bad), self.ok_alt, self.n_alt, ms(self.ok_alt, self.med_alt))
    }
}

/// Домен можно писать в конфиг SmartDNS (имена из DNS-ответов — чужие данные).
pub fn domain_ok(d: &str) -> bool {
    crate::livecfg::domain_ok(d)
}

fn ips_of(l: &[String]) -> Vec<IpAddr> {
    l.iter().filter_map(|s| s.parse().ok()).collect()
}

fn norm_name(n: &str) -> String {
    n.trim_end_matches('.').to_lowercase()
}

/// Имена, под которыми клиенты получили эти адреса.
fn names_of(feed: &dyn Feed, ips: &[String]) -> Vec<String> {
    let mut l: Vec<String> = Vec::new();
    for ip in ips {
        let Ok(a) = ip.parse::<IpAddr>() else { continue };
        if let Some(n) = feed.name_of(&a) {
            let n = norm_name(&n);
            if !n.is_empty() && !l.contains(&n) {
                l.push(n);
            }
        }
    }
    l
}

/// Домены владельца по адресам: домен второго уровня имени, если ≥80%
/// известных адресов этого домена — того же владельца.
fn add_domains(t: &mut Target, ips: &[String], feed: &mut dyn Feed) -> usize {
    let mut cand: Vec<String> = Vec::new();
    for n in names_of(feed, ips) {
        if !t.names.contains(&n) && t.names.len() < 16 {
            t.names.push(n.clone());
        }
        let d = crate::downdet::service_key(&n, "");
        if domain_ok(&d) && !t.domains.contains(&d) && !cand.contains(&d) {
            cand.push(d);
        }
    }
    if cand.is_empty() {
        return 0;
    }
    let mut hits: Vec<(IpAddr, usize)> = Vec::new();
    feed.each_pair(&mut |ip, n| {
        let k = crate::downdet::service_key(&norm_name(n), "");
        if let Some(i) = cand.iter().position(|d| *d == k) {
            hits.push((*ip, i));
        }
    });
    let mut added = 0;
    for (i, d) in cand.iter().enumerate() {
        let (mut mine, mut oth) = (0, 0);
        for (ip, _) in hits.iter().filter(|h| h.1 == i) {
            match feed.owner(ip) {
                Some((asn, _)) if !asn.is_empty() => {
                    if format!("AS{asn}") == t.as_ {
                        mine += 1;
                    } else {
                        oth += 1;
                    }
                }
                _ => {}
            }
        }
        if mine > 0 && mine as f64 >= 0.8 * (mine + oth) as f64 && t.domains.len() < MAX_DOMAINS {
            t.domains.push(d.clone());
            added += 1;
        }
    }
    t.domains.sort();
    added
}

/// Проверка владельца целиком (рабочий поток): адреса мимо местного DNS,
/// пробы по обоим протоколам, выбор альтернативы.
#[allow(clippy::too_many_arguments)]
fn run_test(sys: &dyn Sys, key: String, recheck: bool, mut ips: Vec<String>, mut alt: Vec<String>, names: Vec<String>, fam: String, alts: Vec<Alt>, v6src: Option<IpAddr>) -> Test {
    // при перепроверке клиенты плохих адресов уже не видят — по именам
    for n in &names {
        if ips.len() < 3 {
            for ip in sys.resolve(n, &fam) {
                let s = ip.to_string();
                if crate::witness::public(&ip) && !ips.contains(&s) && ips.len() < 3 {
                    ips.push(s);
                }
            }
        }
        if alt.len() < 3 {
            for ip in sys.resolve(n, other(&fam)) {
                let s = ip.to_string();
                if crate::witness::public(&ip) && !alt.contains(&s) && alt.len() < 3 {
                    alt.push(s);
                }
            }
        }
    }
    let mut r = Test { key, recheck, ips, alt, names, ..Default::default() };
    if !r.ips.is_empty() {
        r.n_bad = PROBE_N;
        (r.ok_bad, r.med_bad) = sys.probe(&ips_of(&r.ips), PROBE_N, 0, v6src);
    }
    if !r.alt.is_empty() {
        r.n_alt = PROBE_N;
        (r.ok_alt, r.med_alt) = sys.probe(&ips_of(&r.alt), PROBE_N, 0, v6src);
    }
    choose_alt(sys, &mut r, &alts, &fam);
    r
}

/// Первая годная альтернатива по порядку настроек.
pub fn choose_alt(sys: &dyn Sys, r: &mut Test, alts: &[Alt], fam: &str) {
    let (bad, alt_good) = r.verdict();
    r.slow_only = !bad && r.ok_bad > 0 && r.med_bad >= 600.0;
    if !bad && !r.slow_only {
        return;
    }
    for a in alts {
        if a.id == DGR_PROTO {
            if bad && alt_good {
                r.via = DGR_PROTO.into();
                return;
            }
            let why = if r.n_alt == 0 {
                "адресов нет"
            } else if !bad {
                "не быстрее"
            } else {
                "тоже плохо"
            };
            r.skipped.push(format!("{} — {}", fam_name(other(fam)), why));
            continue;
        }
        if !a.up {
            r.skipped.push(format!("{} — {}", a.label, a.why));
            continue;
        }
        if r.ips.is_empty() {
            return;
        }
        let (ok, med) = sys.probe(&ips_of(&r.ips), PROBE_N, a.mark, None);
        let good = ok + 1 >= PROBE_N && (r.ok_bad + 1 < PROBE_N || med * 2.0 + 50.0 < r.med_bad);
        if good && !r.names.is_empty() {
            // соединения есть — а данные идут? (зависание после ~16 КБ)
            if let Ok(ip) = r.ips[0].parse::<IpAddr>() {
                let (bok, kb) = sys.bulk(&r.names[0], &ip, a);
                if !bok {
                    r.skipped.push(format!("{} — соединения есть, но загрузка {} замирает на {} КБ", a.label, r.names[0], kb));
                    continue;
                }
            }
        }
        if good {
            r.via = a.id.clone();
            r.via_name = a.label.clone();
            r.ok_via = ok;
            r.med_via = med;
            return;
        }
        r.skipped.push(format!("{} — ответили {} из {}", a.label, ok, PROBE_N));
    }
}

/// Штрафы из файла состояния (Go 1.3.38 или свой — формат один).
pub fn load(m: &[(String, Value)]) -> BTreeMap<String, Target> {
    m.iter().filter(|(_, v)| matches!(v, Value::Map(_))).map(|(k, v)| (k.clone(), Target::from(v))).collect()
}

/// Подпись из чужих данных (sanitizeLabel): без управляющих и HTML, ≤63 знаков.
pub fn sanitize_label(s: &str) -> String {
    let mut b = String::new();
    let mut n = 0;
    for r in s.chars() {
        if (r as u32) < 0x20 || r == '\u{7f}' || "<>\"'`&\\".contains(r) || r == '\u{fffd}' {
            continue;
        }
        if n >= 63 {
            break;
        }
        b.push(r);
        n += 1;
    }
    b.trim().to_string()
}

impl DnsGuard {
    /// Раз в такт в адресном режиме: итоги проверок, раз в минуту оценка, запись файла.
    pub fn targets_tick(&mut self, now: i64, v6: bool, feed: &mut dyn Feed) -> Vec<String> {
        self.t_loaded = true;
        let mut msgs = Vec::new();
        for t in std::mem::take(&mut self.t_results) {
            msgs.extend(self.target_result(now, t, feed));
        }
        if now - self.t_eval_at >= MIN {
            self.t_eval_at = now;
            msgs.extend(self.targets_evaluate(now, v6, feed));
        }
        if let Some(m) = self.targets_apply(now) {
            msgs.push(m);
        }
        if self.route_on() {
            self.route_sync_nets(); // новые сети обхода — сразу, без перезапуска SmartDNS
        }
        msgs
    }

    fn active_targets(&self) -> usize {
        self.targets.values().filter(|t| t.active).count()
    }

    /// Подозрения по трафику клиентов, сроки штрафов, забывание.
    fn targets_evaluate(&mut self, now: i64, v6: bool, feed: &mut dyn Feed) -> Vec<String> {
        #[derive(Default)]
        struct Agg {
            n: usize,
            fail: usize,
            rtt: Vec<f64>,
            fail_ips: Vec<String>,
            ok_ips: Vec<String>,
        }
        let mut stats: BTreeMap<String, Agg> = BTreeMap::new();
        let mut owners: HashMap<String, String> = HashMap::new();
        let mut nets: HashMap<String, Vec<String>> = HashMap::new();
        let mut nets6: HashMap<String, Vec<String>> = HashMap::new();
        // владелец — по одному адресу на сеть /24 (/48): меньше запросов AS
        let mut pfx: HashMap<IpAddr, Option<(String, String)>> = HashMap::new();
        for (ip, ok, rtt) in feed.handshakes(WINDOW_MS) {
            if !crate::witness::public(&ip) {
                continue;
            }
            let p = crate::witness::prefix(&ip);
            if !pfx.contains_key(&p) {
                let o = feed.owner(&ip);
                pfx.insert(p, o);
            }
            let Some((asn, brand)) = pfx[&p].clone() else { continue };
            if asn.is_empty() {
                continue;
            }
            let as_ = format!("AS{asn}");
            if !brand.is_empty() {
                owners.insert(as_.clone(), brand);
            } else if owners.get(&as_).map_or(true, |x| x.is_empty()) {
                owners.insert(as_.clone(), as_.clone());
            }
            let fam = if ip.is_ipv6() { "ipv6" } else { "ipv4" };
            let s = ip.to_string();
            let n4 = crate::dgroute::net4(&s);
            let l = nets.entry(as_.clone()).or_default();
            if !n4.is_empty() && !l.contains(&n4) && l.len() < crate::dgroute::MAX_NETS {
                l.push(n4);
            }
            let n6 = crate::dgv6::net6(&s);
            let l = nets6.entry(as_.clone()).or_default();
            if !n6.is_empty() && !l.contains(&n6) && l.len() < crate::dgv6::MAX_NETS {
                l.push(n6);
            }
            let a = stats.entry(key(&as_, fam)).or_default();
            a.n += 1;
            if ok {
                a.rtt.push(rtt);
                if a.ok_ips.len() < 3 && !a.ok_ips.contains(&s) {
                    a.ok_ips.push(s);
                }
            } else {
                a.fail += 1;
                if a.fail_ips.len() < 3 && !a.fail_ips.contains(&s) {
                    a.fail_ips.push(s);
                }
            }
        }
        for t in self.targets.values_mut() {
            if let Some(o) = owners.get(&t.as_) {
                if *o != t.as_ && t.owner != *o {
                    t.owner = o.clone(); // имя владельца выяснилось позже (было «AS…»)
                }
            }
        }
        let mut tests = 0;
        let route_on = self.route_on();
        for (k, a) in &stats {
            let (as_, fam) = k.split_once('/').unwrap_or((k, ""));
            let suspect = a.n >= 6 && (a.fail as f64 >= 0.3 * a.n as f64 || dgsys::median(&a.rtt) >= 600.0);
            if !suspect || (fam == "ipv4" && !v6 && !route_on) {
                continue;
            }
            let mut t = self.targets.remove(k).unwrap_or_else(|| Target { as_: as_.into(), owner: owners.get(as_).cloned().unwrap_or_default(), fam: fam.into(), ..Default::default() });
            let mut bad = a.fail_ips.clone();
            bad.extend(a.ok_ips.iter().cloned());
            if t.active {
                // штраф действует, а клиенты всё ещё получают плохие адреса — дописать домены
                let mut n = add_domains(&mut t, &bad, feed);
                if t.via_path() || fam == "ipv4" {
                    let was = t.nets.len();
                    t.nets = crate::dgroute::nets_add(std::mem::take(&mut t.nets), nets.get(as_).map_or(&[][..], |v| v));
                    n += t.nets.len() - was;
                }
                if fam == "ipv6" {
                    let was = t.nets6.len();
                    t.nets6 = crate::dgv6::nets6_add(std::mem::take(&mut t.nets6), nets6.get(as_).map_or(&[][..], |v| v));
                    n += t.nets6.len() - was;
                }
                self.targets.insert(k.clone(), t);
                if n > 0 {
                    self.persist();
                }
                continue;
            }
            let skip = t.testing || now - t.tested < TEST_EVERY || tests >= MAX_TESTS || self.active_targets() >= MAX_ACTIVE || (fam == "ipv4" && route_on && self.route_pending());
            if !skip {
                t.alt = stats.get(&key(as_, other(fam))).map(|o| o.ok_ips.clone()).unwrap_or_default();
                t.ips = bad;
                t.names = names_of(feed, &t.ips);
                t.pend = nets.get(as_).cloned().unwrap_or_default();
                t.pend6 = nets6.get(as_).cloned().unwrap_or_default();
                tests += 1;
            }
            self.targets.insert(k.clone(), t);
            if !skip {
                self.target_test(now, k, false);
            }
        }
        // отказ в IPv6: сети /48 действующих штрафов за IPv6 — из плохих адресов и любых рукопожатий с владельцем
        let mut changed = false;
        for t in self.targets.values_mut() {
            if t.active && t.fam == "ipv6" {
                let was = t.nets6.len();
                let l = crate::dgv6::nets6_add(std::mem::take(&mut t.nets6), &t.ips);
                t.nets6 = crate::dgv6::nets6_add(l, nets6.get(&t.as_).map_or(&[][..], |v| v));
                changed |= t.nets6.len() != was;
            }
        }
        if changed {
            self.persist();
        }
        // сроки: перепроверка перед снятием; забывание ступеней
        let keys: Vec<String> = self.targets.keys().cloned().collect();
        for k in keys {
            let t = &self.targets[&k];
            // путь ещё не проверен после старта — ни перепроверки, ни снятия: иначе
            // перезапуск cgmon снимал все обходы (путь «не годится», уйти некуда)
            let unchecked = t.via_path() && self.path_unchecked(&t.via);
            if t.active && now >= t.until && !t.testing && !unchecked {
                self.targets.get_mut(&k).unwrap().early = false;
                self.target_test(now, &k, true);
            } else if t.active && !t.testing && !unchecked && now - t.tested >= HOUR && t.until - now > 10 * MIN {
                // досрочно: раз в час — стало хорошо, снять, не дожидаясь срока (бывало до суток)
                self.targets.get_mut(&k).unwrap().early = true;
                self.target_test(now, &k, true);
            } else if t.active && t.via_path() && !t.testing && !unchecked && !self.path_usable(&t.via) && now - t.tested >= MIN {
                self.target_test(now, &k, true); // путь умер / лимит / стал основным — искать другой
            } else if !t.active && t.strikes > 0 && now - t.last_bad >= DECAY && now - t.decay >= DECAY {
                let t = self.targets.get_mut(&k).unwrap();
                t.strikes -= 1;
                t.decay = now;
                self.persist();
            } else if !t.active && t.strikes == 0 && !t.testing && now - t.tested >= TEST_EVERY {
                self.targets.remove(&k);
            }
        }
        Vec::new()
    }

    /// Проверка владельца в рабочем потоке (тесты — сразу).
    fn target_test(&mut self, now: i64, k: &str, recheck: bool) {
        let alts = if self.cfg.mode == "targeted" && self.cfg.alternatives.is_empty() { Vec::new() } else { self.route_alts(&self.targets[k].fam) };
        let t = self.targets.get_mut(k).unwrap();
        t.testing = true;
        t.tested = now;
        let (ips, alt, names, fam) = (t.ips.clone(), t.alt.clone(), t.names.clone(), t.fam.clone());
        let (key, v6src) = (k.to_string(), self.v6src);
        self.spawn(move |sys| Done::Test(run_test(sys, key, recheck, ips, alt, names, fam, alts, v6src)));
    }

    /// Решение по итогам проверки.
    fn target_result(&mut self, now: i64, r: Test, feed: &mut dyn Feed) -> Vec<String> {
        let Some(mut t) = self.targets.remove(&r.key) else { return Vec::new() };
        let msgs = self.target_decide(now, &mut t, &r, feed);
        self.targets.insert(r.key.clone(), t);
        self.persist();
        msgs
    }

    fn target_decide(&mut self, now: i64, t: &mut Target, r: &Test, feed: &mut dyn Feed) -> Vec<String> {
        t.testing = false;
        let early = std::mem::take(&mut t.early);
        if !r.ips.is_empty() {
            t.ips = r.ips.clone();
        }
        if !r.alt.is_empty() {
            t.alt = r.alt.clone();
        }
        let (bad, _) = r.verdict();
        let (f, o) = (fam_name(&t.fam), fam_name(other(&t.fam)));
        let (prev_via, prev_path) = (t.via.clone(), t.via_path());
        let prev_name = self.path_label(&t.via);
        let (base, maxh) = (self.cfg.target_base_min, self.cfg.target_max_hours);
        let release = |g: &mut DnsGuard, t: &mut Target, why: String| -> Vec<String> {
            t.active = false;
            g.t_urgent = true;
            t.nets.clear();
            t.nets6.clear();
            if prev_path {
                return vec![format!("Обход: {} — {}, обход через {} снят (был {})", t.owner, why, prev_name, dur_text(now - t.since))];
            }
            let next = dur(t.strikes + 1, base, maxh);
            vec![format!("DNS-страховка (адресно): {} — {}, отказ по {} снят (был {}; при повторе в ближайшие сутки — {})", t.owner, why, f, dur_text(now - t.since), dur_text(next))]
        };
        if !r.via.is_empty() && !r.recheck {
            t.via = r.via.clone();
            let ips = t.ips.clone();
            add_domains(t, &ips, feed);
            if t.via_path() || t.fam == "ipv4" {
                let l = crate::dgroute::nets_add(Vec::new(), &t.ips);
                t.nets = crate::dgroute::nets_add(l, &t.pend);
            }
            if t.fam == "ipv6" {
                let l = crate::dgv6::nets6_add(Vec::new(), &t.ips);
                t.nets6 = crate::dgv6::nets6_add(l, &t.pend6);
            }
            // обход — по доменам (SmartDNS nftset) или сетям; перевод на другой протокол — отказ по сетям
            let empty = if t.via_path() { t.domains.is_empty() && t.nets.is_empty() } else if t.fam == "ipv4" { t.nets.is_empty() } else { t.nets6.is_empty() };
            if empty {
                return Vec::new(); // не на что ставить штраф: сетей владельца не знаем
            }
            t.strikes += 1;
            t.active = true;
            t.since = now;
            t.last_bad = now;
            t.decay = now;
            self.t_urgent = true;
            let mut freed = Vec::new();
            if !t.via_path() {
                // оба протокола владельца под отказом — сервис недоступен целиком (Google 15.10 20:13–00:14):
                // другой протокол проверка только что признала хорошим — его штраф снять
                if let Some(o) = self.targets.get_mut(&key(&t.as_, other(&t.fam))) {
                    if o.active && !o.via_path() {
                        o.active = false;
                        o.nets.clear();
                        o.nets6.clear();
                        o.until = now;
                        freed.push(format!("DNS-страховка (адресно): {} — по {} снова в норме ({}), отказ по {} снят — оба протокола сразу не штрафуются", t.owner, fam_name(&o.fam), r.describe(&t.fam), fam_name(&o.fam)));
                    }
                }
            }
            let d = dur(t.strikes, base, maxh);
            t.until = now + d;
            if t.via_path() {
                t.reason = r.describe_via(&t.fam);
                return vec![format!(
                    "Обход: {} — новые соединения по {} идут через {} на {}, {} (штраф {}; сетей: {}, домены: {})",
                    t.owner, f, r.via_name, dur_text(d), t.reason, t.strikes, t.nets.len(), list_text(&t.domains)
                )];
            }
            t.reason = r.describe(&t.fam);
            if !r.skipped.is_empty() {
                t.reason.push_str(&format!("; пропущены: {}", r.skipped.join(", ")));
            }
            let nn = if t.fam == "ipv4" { t.nets.len() } else { t.nets6.len() };
            return freed.into_iter().chain(std::iter::once(format!("DNS-страховка (адресно): {} — новые соединения по {f} к его сетям отклоняются, клиенты сразу уходят на {o}; на {}, {} (штраф {}; сетей: {nn})", t.owner, dur_text(d), t.reason, t.strikes))).collect();
        }
        if !r.via.is_empty() && r.recheck {
            if early {
                return Vec::new(); // досрочная проверка: всё ещё плохо — до срока как было
            }
            t.strikes += 1;
            t.last_bad = now;
            t.decay = now;
            let d = dur(t.strikes, base, maxh);
            t.until = now + d;
            if r.via != prev_via && !(r.via == DGR_PROTO && prev_via.is_empty()) {
                // другая альтернатива: с DNS на путь, с пути на путь или обратно
                t.via = r.via.clone();
                self.t_urgent = true;
                if t.via_path() {
                    let l = crate::dgroute::nets_add(std::mem::take(&mut t.nets), &t.ips);
                    t.nets = crate::dgroute::nets_add(l, &t.pend);
                    t.reason = r.describe_via(&t.fam);
                    return vec![format!("Обход: {} — по {} всё ещё плохо, теперь через {} ещё {} ({}; штраф {})", t.owner, f, r.via_name, dur_text(d), t.reason, t.strikes)];
                }
                if t.fam == "ipv4" {
                    let l = crate::dgroute::nets_add(std::mem::take(&mut t.nets), &t.ips);
                    t.nets = crate::dgroute::nets_add(l, &t.pend);
                } else {
                    t.nets.clear();
                    let l = crate::dgv6::nets6_add(std::mem::take(&mut t.nets6), &t.ips);
                    t.nets6 = crate::dgv6::nets6_add(l, &t.pend6);
                }
                t.reason = r.describe(&t.fam);
                return vec![format!("DNS-страховка (адресно): {} — по {} всё ещё плохо, вместо обхода через {} соединения по {} отклоняются ещё {} (штраф {})", t.owner, f, prev_name, f, dur_text(d), t.strikes)];
            }
            if t.via_path() {
                t.reason = r.describe_via(&t.fam);
                return vec![format!("Обход: {} — по {} всё ещё плохо ({}), через {} ещё {} (штраф {})", t.owner, f, r.describe(&t.fam), r.via_name, dur_text(d), t.strikes)];
            }
            t.reason = r.describe(&t.fam);
            return vec![format!("DNS-страховка (адресно): {} — по {} всё ещё плохо ({}), отказ по {} ещё {} (штраф {})", t.owner, f, t.reason, f, dur_text(d), t.strikes)];
        }
        if r.recheck && r.n_bad > 0 && !bad {
            // просто медленно, а быстрее пути нет — тоже снять
            return release(self, t, format!("по {f} снова в норме ({})", r.describe(&t.fam)));
        }
        if r.recheck && r.n_bad > 0 && early {
            return Vec::new();
        }
        if r.recheck && r.n_bad > 0 {
            // плохо, но уйти некуда
            if prev_path && !self.path_usable(&prev_via) {
                let why = self.path_why(&prev_via);
                return release(self, t, format!("путь {prev_name} больше не годится ({why}), других альтернатив нет"));
            }
            t.until = now + 30 * MIN; // повторить через полчаса
            return Vec::new();
        }
        if r.recheck {
            // адресов владельца не найти — держать запрет без доказательств нельзя
            return release(self, t, format!("проверить по {o} не удалось (адресов нет)"));
        }
        Vec::new()
    }

    /// Содержимое targets_file по действующим штрафам.
    pub fn targets_conf(&self) -> String {
        let mut b = String::from("# cgmon dns_guard: проверочные сайты «мой IP» (файл пишет cgmon; штрафы и обход — в nft, не здесь)\n");
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let targeted = self.cfg.mode == "targeted";
        if self.cfg.check_via == DGR_PROTO && targeted {
            // проверка IPv6: сайтам не отдаём A — браузер идёт к ним только по IPv6
            b.push_str("# проверка: сайты «мой IP» только по IPv6\n");
            for d in &self.cfg.check_domains {
                let d = d.to_lowercase();
                if domain_ok(&d) && seen.insert(format!("{d}#4")) {
                    b.push_str(&format!("address /{d}/#4\n"));
                }
            }
        }
        // сайты «мой IP» и домены обхода попадают в наборы путей по DNS-ответам
        // клиентам (DNSWatch) — в файл SmartDNS не пишем, его не перезапускаем
        b
    }

    /// Файл отличается от нужного — записать и перезапустить SmartDNS (в потоке).
    pub fn targets_apply(&mut self, now: i64) -> Option<String> {
        let targeted = self.cfg.mode == "targeted";
        // файл без правил (только комментарии) — пустой: без обхода SmartDNS не перезапускаем
        let want = if targeted { Some(self.targets_conf()).filter(|c| c.lines().any(|l| !l.is_empty() && !l.starts_with('#'))).unwrap_or_default() } else { String::new() };
        let gap = if self.t_urgent || !targeted { RESTART_GAP } else { ADD_GAP };
        if self.t_writing || want == self.t_written || now - self.t_applied < gap {
            return None;
        }
        if !targeted && self.t_written.is_empty() {
            return None;
        }
        if targeted && !self.t_err.is_empty() {
            return None;
        }
        self.t_applied = now;
        self.t_writing = true;
        let file = self.cfg.targets_file.clone();
        let cache = self.cfg.cache_file.clone();
        // проверка: первый запрещённый домен не должен отдавать запрещённый тип
        let check: Option<(String, String)> = None; // запретов типов в файле больше нет — проверять нечего
        self.spawn(move |sys| {
            let res = write_targets(sys, &file, &cache, &want, check);
            Done::Targets { content: want, res }
        });
        if self.sync_jobs {
            // в тестах — сразу (как запись в Go)
            let m = self.collect_targets();
            return m;
        }
        None
    }

    fn collect_targets(&mut self) -> Option<String> {
        let mut out = None;
        let mut keep = Vec::new();
        for d in std::mem::take(&mut self.inbox) {
            match d {
                Done::Targets { content, res } => {
                    self.t_writing = false;
                    match res {
                        Ok(()) => {
                            self.t_urgent = false;
                            self.t_written = content;
                        }
                        Err(e) => {
                            self.err = format!("адресный режим: {e}");
                            out = Some(format!("DNS-страховка (адресно): не удалось записать {}: {}", self.cfg.targets_file, e));
                        }
                    }
                }
                d => keep.push(d),
            }
        }
        *&mut self.inbox = keep;
        out
    }

    /// Можно ли работать адресно (SmartDNS и файл включён в его конфиг).
    pub fn targets_check(&mut self) {
        self.t_err.clear();
        if self.cfg.mode != "targeted" {
            return;
        }
        let Some(b) = self.backend.clone() else { return };
        // адресный режим и обход DNS-сервер не трогают (отказ в nft, адреса — из
        // DNS-ответов клиентам); правила прежних версий (address, nftset) снять один раз
        if b.name() == "smartdns" && self.t_written.is_empty() {
            if let Some(f) = self.sys.read_file(&self.cfg.targets_file) {
                if f.contains("\naddress /") || f.contains("\nnftset /") {
                    self.t_written = f;
                }
            }
        }
        if self.cfg.check_via != DGR_PROTO {
            return;
        }
        if b.name() != "smartdns" {
            self.t_err = format!("проверка «мой IP» только по IPv6 (check_via: proto) работает только со SmartDNS; сейчас {}", b.name());
            return;
        }
        if !dgsys::includes(&*self.sys).contains(&self.cfg.targets_file) {
            self.t_err = format!("в custom.conf SmartDNS нет строки «conf-file {}» — адресные запреты не действуют", self.cfg.targets_file);
            return;
        }
        // файл должен существовать: SmartDNS без включённого файла не стартует
        if self.sys.read_file(&self.cfg.targets_file).is_none() {
            let _ = self.sys.write_file(&self.cfg.targets_file, &self.targets_conf(), 0o644);
        }
        if self.t_written.is_empty() {
            if let Some(b) = self.sys.read_file(&self.cfg.targets_file) {
                self.t_written = b; // при старте: что уже лежит в файле
            }
        }
    }

    /// Действующие штрафы для статуса.
    pub fn targets_json(&self, j: &mut J) {
        let mut l: Vec<&Target> = self.targets.values().filter(|t| t.active).collect();
        if l.is_empty() {
            return;
        }
        l.sort_by_key(|t| t.since);
        j.key("targets").arr();
        for t in l {
            j.obj().key("owner").str(&t.owner).key("fam").str(&t.fam).key("domains");
            if t.domains.is_empty() {
                j.raw("null");
            } else {
                j.arr();
                for d in &t.domains {
                    j.str(d);
                }
                j.end_arr();
            }
            j.key("since").str(&time_json(t.since)).key("until").str(&time_json(t.until)).key("strikes").int(t.strikes);
            if !t.reason.is_empty() {
                j.key("reason").str(&t.reason);
            }
            if t.via_path() {
                j.key("via").str(&t.via).key("via_name").str(&self.path_label(&t.via));
                if !t.nets.is_empty() {
                    j.key("nets").int(t.nets.len() as i64);
                }
            }
            if !t.via_path() {
                // перевод на другой протокол: сколько сетей под отказом
                let n = if t.fam == "ipv6" { t.nets6.len() } else { t.nets.len() };
                if n > 0 {
                    j.key(if t.fam == "ipv6" { "nets6" } else { "nets4" }).int(n as i64);
                }
            }
            j.end_obj();
        }
        j.end_arr();
    }
}

/// Записать файл, перезапустить SmartDNS, проверить запрет (dgtWriteSmartDNS).
fn write_targets(sys: &dyn Sys, file: &str, cache: &str, content: &str, check: Option<(String, String)>) -> Result<(), String> {
    if file.is_empty() {
        return Err("не задан targets_file".into());
    }
    if sys.read_file(file).as_deref() == Some(content) {
        return Ok(());
    }
    sys.write_file(file, content, 0o644)?;
    let restart = || -> Result<(), String> {
        sys.run(&["/etc/init.d/smartdns", "restart"])?;
        sys.run(&["killall", "-HUP", "dnsmasq"]).map(|_| ())
    };
    restart()?;
    if let Some((d, fam)) = check {
        if sys.leaks(&d, &fam) && !cache.is_empty() {
            sys.remove_file(cache); // старые ответы из кэша на диске
            return restart();
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::dnsguard::tests::{fake, guard, tmp};
    use crate::dnsguard::Health;

    /// Источник для тестов: рукопожатия, имена, владельцы по префиксу.
    pub struct TFeed {
        pub hs: Vec<(IpAddr, bool, f64)>,
        pub names: Vec<(IpAddr, String)>,
        pub own: Vec<(&'static str, &'static str, &'static str)>,
    }

    impl Feed for TFeed {
        fn handshakes(&self, _: u64) -> Vec<(IpAddr, bool, f64)> {
            self.hs.clone()
        }
        fn name_of(&self, ip: &IpAddr) -> Option<String> {
            self.names.iter().find(|x| x.0 == *ip).map(|x| x.1.clone())
        }
        fn each_pair(&self, f: &mut dyn FnMut(&IpAddr, &str)) {
            for (ip, n) in &self.names {
                f(ip, n);
            }
        }
        fn owner(&mut self, ip: &IpAddr) -> Option<(String, String)> {
            let s = ip.to_string();
            self.own.iter().find(|o| s.starts_with(o.0)).map(|o| (o.1.to_string(), o.2.to_string()))
        }
    }

    pub fn google_feed() -> TFeed {
        let (g6, g4, c6): (IpAddr, IpAddr, IpAddr) = ("2a00:1450:4001::1".parse().unwrap(), "142.250.1.1".parse().unwrap(), "2606:4700::1".parse().unwrap());
        let mut hs = Vec::new();
        for _ in 0..8 {
            hs.push((g6, false, 0.0));
            hs.push((g4, true, 40.0));
            hs.push((c6, true, 40.0));
        }
        TFeed {
            hs,
            names: vec![(g6, "rr1---sn-x.googlevideo.com".into()), (g4, "rr1---sn-x.googlevideo.com".into()), (c6, "example.com".into())],
            own: vec![("2a00:1450", "15169", "Google"), ("142.250", "15169", "Google"), ("", "13335", "Cloudflare")],
        }
    }

    #[test]
    fn durations_and_texts() {
        assert_eq!(dur(1, 60, 24), HOUR);
        assert_eq!(dur(3, 60, 24), 4 * HOUR);
        assert_eq!(dur(9, 60, 24), 24 * HOUR);
        assert_eq!(dur_text(45 * MIN), "45 мин");
        assert_eq!(dur_text(2 * HOUR), "2 ч");
        assert_eq!(sanitize_label(" <b>Google\u{1}</b> "), "bGoogle/b");
    }

    #[test]
    fn targeted_penalty_recheck_release() {
        let f = fake("smartdns");
        let file = tmp("t1");
        let _ = std::fs::remove_file(&file);
        let (mut g, sys) = guard("targeted", f.clone(), &file);
        g.cfg.targets_file = "/tmp/targets.conf".into();
        sys.files.lock().unwrap().insert("/etc/smartdns/custom.conf".into(), "conf-file /tmp/targets.conf\n".into());
        let v6bad = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let vb = v6bad.clone();
        *sys.probe.lock().unwrap() = Some(Box::new(move |ips: &[IpAddr], n, _| if ips[0].is_ipv6() && vb.load(std::sync::atomic::Ordering::Relaxed) { (1, 900.0) } else { (n, 40.0) }));
        let mut feed = google_feed();
        let hh = Health { v4_ok: true, v6_ok: true, v6_avail: true, ..Default::default() };
        let mut now = 1_700_000_000_000i64;
        let mut all = Vec::new();
        let mut step = |g: &mut DnsGuard, d: i64, all: &mut Vec<String>| {
            now += d;
            all.extend(g.tick(now, "NORMAL", "HEALTHY", &hh, &mut feed));
        };
        step(&mut g, 0, &mut all);
        step(&mut g, 10_000, &mut all);
        assert!(all.len() == 1 && all[0].contains("Google — новые соединения по IPv6 к его сетям отклоняются") && all[0].contains("на 1 ч"), "{all:?}");
        step(&mut g, MIN, &mut all);
        // перевод на IPv4 — отказ в nft; SmartDNS не трогается
        let written = sys.files.lock().unwrap().get("/tmp/targets.conf").cloned().unwrap_or_default();
        assert!(!written.contains("address"), "{written}");
        assert!(g.targets["AS15169/ipv6"].nets6.contains(&"2a00:1450:4001::/48".to_string()));
        assert!(g.v6_bad().contains(&"2a00:1450:4001::/48".to_string()));
        assert!(!sys.runs.lock().unwrap().iter().any(|r| r.contains("smartdns")), "{:?}", sys.runs.lock().unwrap());
        // через час всё ещё плохо — штраф 2 ч
        all.clear();
        step(&mut g, HOUR, &mut all);
        step(&mut g, 10_000, &mut all);
        assert!(all.len() == 1 && all[0].contains("всё ещё плохо") && all[0].contains("ещё 2 ч (штраф 2)"), "{all:?}");
        // починилось — снятие при перепроверке
        v6bad.store(false, std::sync::atomic::Ordering::Relaxed);
        all.clear();
        step(&mut g, 2 * HOUR, &mut all);
        step(&mut g, 10_000, &mut all);
        step(&mut g, MIN, &mut all);
        let written = sys.files.lock().unwrap().get("/tmp/targets.conf").cloned().unwrap_or_default();
        assert!(all.len() == 1 && all[0].contains("снова в норме") && all[0].contains("отказ по IPv6 снят") && !written.contains("address"), "{all:?} {written}");
        assert!(g.v6_bad().is_empty());
        // ступени переживают перезапуск
        let (mut g2, _) = guard("targeted", f, &file);
        g2.tick(now, "NORMAL", "HEALTHY", &hh, &mut dnsguard::NoFeed);
        let t = &g2.targets["AS15169/ipv6"];
        assert!(t.strikes == 2 && !t.active, "{t:?}");
    }

    #[test]
    fn never_both_families_and_early_release() {
        let f = fake("smartdns");
        let file = tmp("t3");
        let _ = std::fs::remove_file(&file);
        let (mut g, sys) = guard("targeted", f.clone(), &file);
        // вручную — оба протокола владельца под отказом: отказа нет вовсе
        for (fam, net) in [("ipv4", "142.250.1.0/24"), ("ipv6", "2a00:1450:4001::/48")] {
            let mut t = Target { as_: "AS15169".into(), owner: "Google".into(), fam: fam.into(), active: true, until: i64::MAX, ..Default::default() };
            if fam == "ipv4" { t.nets = vec![net.into()]; } else { t.nets6 = vec![net.into()]; }
            g.targets.insert(key("AS15169", fam), t);
        }
        assert!(g.v4_bad().is_empty() && g.v6_bad().is_empty());
        g.targets.clear();
        // штраф за IPv6, через час проверка чистая — снят досрочно (не через 24 ч)
        let v6bad = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let vb = v6bad.clone();
        *sys.probe.lock().unwrap() = Some(Box::new(move |ips: &[IpAddr], n, _| if ips[0].is_ipv6() && vb.load(std::sync::atomic::Ordering::Relaxed) { (1, 900.0) } else { (n, 40.0) }));
        let mut feed = google_feed();
        let hh = Health { v4_ok: true, v6_ok: true, v6_avail: true, ..Default::default() };
        let mut now = 1_700_000_000_000i64;
        let mut all = Vec::new();
        for d in [0, 10_000] {
            now += d;
            all.extend(g.tick(now, "NORMAL", "HEALTHY", &hh, &mut feed));
        }
        assert!(g.targets["AS15169/ipv6"].active, "{all:?}");
        g.targets.get_mut("AS15169/ipv6").unwrap().until = now + 24 * HOUR; // как штраф 7-й ступени
        v6bad.store(false, std::sync::atomic::Ordering::Relaxed);
        all.clear();
        for d in [HOUR + MIN, 10_000, MIN] {
            now += d;
            all.extend(g.tick(now, "NORMAL", "HEALTHY", &hh, &mut feed));
        }
        assert!(!g.targets["AS15169/ipv6"].active && all.iter().any(|m| m.contains("снова в норме")), "{all:?}");
    }

    #[test]
    fn targeted_global_needs_witness() {
        let f = fake("smartdns");
        let (mut g, _) = guard("targeted", f, &tmp("t2"));
        let mut hh = Health { v4_ok: true, v6_avail: true, wit_v6: "degraded".into(), ..Default::default() };
        let (now, m) = dnsguard::tests::steps_h(&mut g, 1_700_000_000_000, 900, "NORMAL", "IPV6_DEGRADATION", &hh);
        assert!(g.saved.state == dnsguard::NORMAL && !m.join("|").contains("только IPv4"), "{m:?}");
        hh.wit_v6 = "bad".into();
        dnsguard::tests::steps_h(&mut g, now, 400, "NORMAL", "IPV6_DEGRADATION", &hh);
        assert_eq!(g.saved.state, dnsguard::NO_AAAA);
        // без обхода SmartDNS адресному режиму не нужен
        assert!(g.t_err.is_empty(), "{}", g.t_err);
    }
}
