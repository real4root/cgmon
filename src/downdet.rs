//! Down detector (перенос downdet.go): какие сервисы не отвечают клиентам,
//! пока пробы WAN в норме. Исходы рукопожатий tcp/443 (synrtt) за 5 мин по
//! сервисам: домен второго уровня спрошенного имени (dnswatch), иначе
//! владелец адреса (AS) или адрес. «Не отвечает» — ≥ 3 без ответа, ответили
//! ≤ 20%, сбои растянуты ≥ 20 с; «медленно» — медиана ≥ 1,5 с; «массовые
//! сбои» — за 2 мин ≥ 20 соединений, ≥ 30% без ответа, ≥ 5 направлений.

use crate::dnswatch::DnsWatch;
use crate::ipowner::IpOwner;
use crate::json::J;
use crate::synrtt::{SynRtt, SynStats};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

const WINDOW: u64 = 5 * 60 * 1000;
const MIN_FAIL: usize = 3;
const SPREAD: u64 = 20 * 1000;
const SLOW_MS: f64 = 1500.0;
const CLEAR: u64 = 60 * 1000;
const QUIET: u64 = 3600 * 1000;
const MASS_WIN: u64 = 2 * 60 * 1000;

#[derive(Clone, Debug, Default)]
pub struct Service {
    pub name: String,
    pub ips: Vec<String>,
    pub state: &'static str,
    pub since: (i64, u32),
    since_ms: u64,
    pub fail: usize,
    pub total: usize,
    pub median_ms: f64,
    pub clients: Vec<String>,
    last_bad: u64,
    by_ip: bool,
    reported: bool,
    silent: bool,
}

#[derive(Default)]
struct Group {
    name: String,
    ips: BTreeSet<String>,
    ok: usize,
    fail: usize,
    first_fail: u64,
    last_fail: u64,
    rtts: Vec<f32>,
    clients: Vec<String>,
}

#[derive(Default)]
pub struct DownDetector {
    pub off: bool,
    open: HashMap<String, Service>,
    closed_at: HashMap<String, u64>,
    mass: bool,
    mass_fam: &'static str,
    mass_bad: u64,
    last: u64,
}

/// «Сервис» адреса: домен второго уровня (co.uk, com.uz… — три метки), иначе адрес.
pub fn service_key(name: &str, ip: &str) -> String {
    if name.is_empty() {
        return ip.to_string();
    }
    let l: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let mut n = 2;
    if l.len() >= 3 && l[l.len() - 2].len() <= 3 && l[l.len() - 1].len() == 2 {
        n = 3;
    }
    if l.len() <= n {
        return name.to_string();
    }
    l[l.len() - n..].join(".")
}

/// Протокол по адресам: «IPv4», «IPv6» или «IPv4 и IPv6».
pub fn family(ips: &[String]) -> &'static str {
    let v6 = ips.iter().any(|i| i.contains(':'));
    let v4 = ips.iter().any(|i| !i.contains(':'));
    match (v4, v6) {
        (true, true) => "IPv4 и IPv6",
        (false, true) => "IPv6",
        (true, false) => "IPv4",
        _ => "",
    }
}

/// Go time.Duration.Round(минута).String(): «4m0s», «1h5m0s», «0s».
pub fn go_minutes(ms: u64) -> String {
    let m = (ms + 30_000) / 60_000;
    if m == 0 {
        return "0s".into();
    }
    if m >= 60 {
        format!("{}h{}m0s", m / 60, m % 60)
    } else {
        format!("{m}m0s")
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Слова названия (буквы ≥ 3) — упоминается ли владелец в домене.
fn brand_said(brand: &str, key: &str) -> bool {
    let k = key.to_lowercase();
    brand.split(|c: char| !c.is_alphabetic()).any(|w| w.chars().count() >= 3 && k.contains(&w.to_lowercase()))
}

impl DownDetector {
    /// Массовые сбои соединений прямо сейчас.
    pub fn mass(&self) -> bool {
        self.mass
    }

    pub fn set_on(&mut self, on: bool) {
        self.off = !on;
        if !on {
            self.open.clear();
            self.mass = false;
        }
    }

    fn group(syn: &SynRtt, dns: &DnsWatch, owner: &mut IpOwner, now: u64) -> (HashMap<String, Group>, usize, usize, usize, usize) {
        let mut groups: HashMap<String, Group> = HashMap::new();
        let (mut total, mut fail, mut fail6) = (0usize, 0usize, 0usize);
        let mut dest: BTreeSet<String> = BTreeSet::new();
        let since = now.saturating_sub(WINDOW);
        for o in syn.since(since) {
            let ips = o.ip.to_string();
            let (name, clients) = dns.lookup(&o.ip).map(|(n, c)| (n.to_string(), c)).unwrap_or_default();
            let mut key = service_key(&name, &ips);
            if name.is_empty() {
                // без имени из DNS: адреса одного владельца (AS) — один сервис
                match owner.get(&o.ip, now) {
                    Some(inf) if !inf.brand.is_empty() => key = inf.brand.clone(),
                    Some(_) => {}
                    None => {
                        if !o.ok {
                            owner.want(o.ip, now);
                        }
                    }
                }
            }
            let g = groups.entry(key.clone()).or_insert_with(|| Group { name: name.clone(), ..Default::default() });
            g.ips.insert(ips.clone());
            for c in clients {
                if !g.clients.contains(&c) {
                    g.clients.push(c);
                }
            }
            if o.ok {
                g.ok += 1;
                g.rtts.push(o.rtt);
            } else {
                g.fail += 1;
                if g.first_fail == 0 || o.at < g.first_fail {
                    g.first_fail = o.at;
                }
                if o.at > g.last_fail {
                    g.last_fail = o.at;
                }
            }
            if now - o.at <= MASS_WIN {
                total += 1;
                if !o.ok {
                    fail += 1;
                    dest.insert(key);
                    if matches!(o.ip, IpAddr::V6(_)) {
                        fail6 += 1;
                    }
                }
            }
        }
        (groups, total, fail, dest.len(), fail6)
    }

    /// Название: домен (+ владелец, если имя о нём не говорит), владелец или адрес (+ PTR).
    fn title(key: &str, g: &Group, ips: &[String], owner: &mut IpOwner, now: u64) -> (String, bool, bool) {
        let mut ready = true;
        let (mut brand, mut ptr) = (String::new(), String::new());
        let mut have = false;
        for s in ips {
            let Ok(ip) = s.parse::<IpAddr>() else { continue };
            match owner.get(&ip, now) {
                Some(i) => {
                    if !have || (brand.is_empty() && !i.brand.is_empty()) {
                        brand = i.brand.clone();
                        ptr = i.ptr.clone();
                        have = true;
                    }
                }
                None => {
                    owner.want(ip, now);
                    ready = false;
                }
            }
        }
        if !g.name.is_empty() {
            if !brand.is_empty() && !brand_said(&brand, key) {
                return (format!("{key} ({brand})"), false, ready);
            }
            return (key.to_string(), false, ready);
        }
        if key.parse::<IpAddr>().is_err() {
            return (key.to_string(), false, ready); // уже владелец: «Telegram»
        }
        let extra: Vec<String> = [brand, ptr].into_iter().filter(|x| !x.is_empty()).collect();
        if extra.is_empty() {
            (key.to_string(), true, ready)
        } else {
            (format!("{} ({})", key, extra.join(", ")), true, ready)
        }
    }

    fn describe(sv: &Service) -> String {
        let fam = family(&sv.ips);
        let what = if sv.state == "slow" { format!("отвечает медленно по {fam} — медиана рукопожатия {:.0} мс", sv.median_ms) } else { format!("не отвечает по {fam} — {} из {} соединений без ответа за 5 мин", sv.fail, sv.total) };
        let mut s = format!("{} {}", sv.name, what);
        if !sv.by_ip {
            s += &format!("; адреса {}", sv.ips.join(", "));
        }
        if !sv.clients.is_empty() {
            s += &format!("; клиенты: {}", sv.clients.join(", "));
        }
        s
    }

    /// Раз в ~10 с; wan_ok — пробы WAN в норме. Возвращает тексты событий.
    pub fn evaluate(&mut self, now: u64, wall: (i64, u32), wan_ok: bool, syn: &SynRtt, dns: &DnsWatch, owner: &mut IpOwner, client_name: &dyn Fn(&str) -> String) -> Vec<String> {
        if self.off || now - self.last < 10_000 {
            return Vec::new();
        }
        self.last = now;
        let (groups, mtotal, mfail, mdest, mfail6) = Self::group(syn, dns, owner, now);
        let mut events = Vec::new();
        for (key, mut g) in groups {
            g.rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let med = if g.rtts.is_empty() { 0.0 } else { round1(g.rtts[g.rtts.len() / 2] as f64) };
            let state = if g.fail >= MIN_FAIL && g.ok * 4 <= g.fail && g.last_fail - g.first_fail >= SPREAD {
                "down"
            } else if g.ok >= 5 && med >= SLOW_MS {
                "slow"
            } else {
                continue;
            };
            if !self.open.contains_key(&key) {
                if !wan_ok {
                    continue; // при беде WAN сбои сайтов — её следствие
                }
                let silent = self.closed_at.get(&key).map_or(false, |t| now - t < QUIET);
                self.open.insert(key.clone(), Service { since: wall, since_ms: now, silent, ..Default::default() });
            }
            let ips: Vec<String> = g.ips.iter().take(4).cloned().collect();
            let (name, by_ip, ready) = Self::title(&key, &g, &ips, owner, now);
            let clients: Vec<String> = g.clients.iter().map(|c| if c == "router" { "роутер".to_string() } else { let n = client_name(c); if n.is_empty() { c.clone() } else { n } }).collect();
            let sv = self.open.get_mut(&key).unwrap();
            sv.state = state;
            sv.fail = g.fail;
            sv.total = g.ok + g.fail;
            sv.median_ms = med;
            sv.last_bad = now;
            sv.ips = ips;
            sv.name = name;
            sv.by_ip = by_ip;
            sv.clients = clients;
            // событие — когда выяснили, чей адрес (или не дождались за 20 с)
            if !sv.reported && !sv.silent && wan_ok && (ready || now - sv.since_ms >= 20_000) {
                sv.reported = true;
                events.push(Self::describe(sv));
            }
        }
        let gone: Vec<String> = self.open.iter().filter(|(_, s)| now - s.last_bad >= CLEAR).map(|(k, _)| k.clone()).collect();
        for k in gone {
            let sv = self.open.remove(&k).unwrap();
            self.closed_at.insert(k, now);
            if sv.reported && now - sv.since_ms >= CLEAR {
                events.push(format!("{} снова в норме по {} (сбой {})", sv.name, family(&sv.ips), go_minutes(now - sv.since_ms - CLEAR)));
            }
        }
        self.closed_at.retain(|_, t| now - *t <= QUIET);
        let pct = if mtotal > 0 { mfail as f64 * 100.0 / mtotal as f64 } else { 0.0 };
        if mtotal >= 20 && pct >= 30.0 && mdest >= 5 {
            self.mass_bad = now;
            if !self.mass && wan_ok {
                self.mass = true;
                let v6 = mfail6 as f64 / mfail as f64;
                self.mass_fam = if v6 >= 0.8 { "IPv6" } else if v6 <= 0.2 { "IPv4" } else { "IPv4 и IPv6" };
                events.push(format!("Массовые сбои соединений по {} — {:.0}% из {} без ответа за 2 мин, направлений: {} (пробы WAN в норме — вероятна частичная беда маршрутов провайдера)", self.mass_fam, pct, mtotal, mdest));
            }
        } else if self.mass && now - self.mass_bad >= CLEAR {
            self.mass = false;
            events.push(format!("Массовые сбои соединений по {} закончились", self.mass_fam));
        }
        events
    }

    pub fn status_json(&self, j: &mut J, syn: &SynRtt, now: u64) {
        let st = |j: &mut J, s: SynStats| {
            use crate::config::go_float;
            j.obj().key("count").int(s.count).key("success_rate").raw(&go_float(s.success_rate)).key("loss_pct").raw(&go_float(s.loss_pct)).key("median_ms").raw(&go_float(s.median_ms)).key("p90_ms").raw(&go_float(s.p90_ms)).end_obj();
        };
        j.obj().key("traffic_v4");
        st(j, syn.stats("ipv4", WINDOW, now));
        j.key("traffic_v6");
        st(j, syn.stats("ipv6", WINDOW, now));
        if self.mass {
            j.key("mass").bool(true).key("mass_family").str(self.mass_fam);
        }
        let mut svs: Vec<&Service> = self.open.values().collect();
        svs.sort_by_key(|s| s.since_ms);
        if !svs.is_empty() {
            j.key("services").arr();
            for s in svs {
                j.obj().key("name").str(&s.name).key("ips").arr();
                for ip in &s.ips {
                    j.str(ip);
                }
                j.end_arr().key("state").str(s.state).key("since").str(&crate::util::rfc3339(s.since.0, s.since.1));
                j.key("fail").int(s.fail as i64).key("total").int(s.total as i64);
                if s.median_ms != 0.0 {
                    j.key("median_ms").raw(&crate::config::go_float(s.median_ms));
                }
                if !s.clients.is_empty() {
                    j.key("clients").arr();
                    for c in &s.clients {
                        j.str(c);
                    }
                    j.end_arr();
                }
                j.end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
    }

    /// Открытые сбои сервисов (по времени начала).
    pub fn services(&self) -> Vec<&Service> {
        let mut svs: Vec<&Service> = self.open.values().collect();
        svs.sort_by_key(|s| s.since_ms);
        svs
    }

    /// Все направления за окно (cgmon sites): сначала с провалами.
    pub fn sites_json(&self, j: &mut J, syn: &SynRtt, dns: &DnsWatch, owner: &mut IpOwner, now: u64, client_name: &dyn Fn(&str) -> String) {
        let (groups, ..) = Self::group(syn, dns, owner, now);
        let mut rows: Vec<(String, Vec<String>, usize, usize, f64, Vec<String>)> = Vec::new();
        for (key, mut g) in groups {
            let ips: Vec<String> = g.ips.iter().take(4).cloned().collect();
            let (name, _, _) = Self::title(&key, &g, &ips, owner, now);
            g.rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let med = if g.rtts.is_empty() { 0.0 } else { round1(g.rtts[g.rtts.len() / 2] as f64) };
            let cl = g.clients.iter().map(|c| { let n = client_name(c); if n.is_empty() { c.clone() } else { n } }).collect();
            rows.push((name, ips, g.ok, g.fail, med, cl));
        }
        rows.sort_by(|a, b| b.3.cmp(&a.3).then((b.2 + b.3).cmp(&(a.2 + a.3))));
        j.arr();
        for (n, ips, ok, fail, med, cl) in rows {
            j.obj().key("name").str(&n).key("ips").arr();
            for ip in &ips {
                j.str(ip);
            }
            j.end_arr().key("ok").int(ok as i64).key("fail").int(fail as i64).key("median_ms").raw(&crate::config::go_float(med));
            if !cl.is_empty() {
                j.key("clients").arr();
                for c in &cl {
                    j.str(c);
                }
                j.end_arr();
            }
            j.end_obj();
        }
        j.end_arr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_text() {
        assert_eq!(service_key("rr3---sn-x.googlevideo.com", "1.2.3.4"), "googlevideo.com");
        assert_eq!(service_key("www.bbc.co.uk", ""), "bbc.co.uk");
        assert_eq!(service_key("a.payme.com.uz", ""), "payme.com.uz");
        assert_eq!(service_key("", "192.0.2.1"), "192.0.2.1");
        assert_eq!(family(&["192.0.2.1".into(), "2001:db8::1".into()]), "IPv4 и IPv6");
        assert_eq!(go_minutes(4 * 60_000 + 10_000), "4m0s");
        assert_eq!(go_minutes(65 * 60_000), "1h5m0s");
        assert!(brand_said("Google/YouTube", "googlevideo.com") && !brand_said("Telegram", "googlevideo.com"));
    }
}
