//! Слежение за ботнетами и угрозами (threat_watch): какие устройства сети ходят к
//! командным серверам ботнетов, узлам раздачи вредоносов и адресам из списков угроз,
//! а также ведут себя как заражённые (сканируют интернет, генерируют домены, держат
//! сотни соединений как прокси). Следим за всеми устройствами: заражённой бывает и
//! приставка, и камера, и компьютер, и пылесос.
//!
//! Списки (без ключей, раз в сутки, в фоне): C2IntelFeeds, Feodo Tracker, SSLBL — командные
//! серверы; URLhaus (зеркало malware-filter) — раздача вредоносов; Spamhaus DROP — сети
//! злоумышленников; HaGeZi TIF — большой список угроз (только full). lite/nano — меньше.
//!
//! Память: домены — только 64-битные хэши в отсортированном массиве (8 байт на домен, +1
//! на источник); адреса — в наборе nft (ядро само отмечает пары «устройство . адрес» в
//! `hits4`, cgmon раз в минуту их забирает); в памяти cgmon — компактная копия для имени
//! источника. CPU: на DNS-ответ — несколько хэшей и двоичный поиск.

use crate::json::J;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{Receiver, Sender};

pub const TABLE: &str = "cgmon_threat";
const DAY_MS: i64 = 24 * 3600_000;
const KEEP_MS: i64 = 7 * DAY_MS;
/// повтор события о том же устройстве и той же угрозе — не чаще
const EVENT_EVERY_MS: i64 = 6 * 3600_000;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cat {
    /// командный сервер ботнета
    C2,
    /// раздача вредоносов
    Mal,
    /// список угроз (фишинг, вредоносы, злоумышленники)
    Bad,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Dom,
    Ip,
    Net,
}

struct Src {
    name: &'static str,
    url: &'static str,
    kind: Kind,
    cat: Cat,
    /// 0 — всем (nano+), 1 — lite и full, 2 — только full (большие списки); 9 — только малый набор
    tier: u8,
}

const SOURCES: &[Src] = &[
    Src { name: "C2IntelFeeds", url: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv", kind: Kind::Dom, cat: Cat::C2, tier: 0 },
    Src { name: "C2IntelFeeds", url: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv", kind: Kind::Ip, cat: Cat::C2, tier: 0 },
    Src { name: "Feodo Tracker", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", kind: Kind::Ip, cat: Cat::C2, tier: 0 },
    Src { name: "SSLBL", url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", kind: Kind::Ip, cat: Cat::C2, tier: 0 },
    Src { name: "URLhaus", url: "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains-online.txt", kind: Kind::Dom, cat: Cat::Mal, tier: 9 },
    Src { name: "URLhaus", url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt", kind: Kind::Dom, cat: Cat::Mal, tier: 1 },
    Src { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v4.json", kind: Kind::Net, cat: Cat::Bad, tier: 1 },
    Src { name: "HaGeZi TIF", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", kind: Kind::Dom, cat: Cat::Bad, tier: 2 },
    Src { name: "HaGeZi TIF", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt", kind: Kind::Ip, cat: Cat::Bad, tier: 2 },
];

/// Размер набора: small (nano) | medium (lite) | large (full); auto — по варианту сборки.
pub fn level(lists: &str) -> u8 {
    match lists {
        "small" => 0,
        "medium" => 1,
        "large" => 2,
        _ => match crate::variant::name() {
            "full" => 2,
            "lite" => 1,
            _ => 0,
        },
    }
}

fn src_on(s: &Src, lvl: u8) -> bool {
    if s.tier == 9 {
        lvl == 0
    } else {
        s.tier <= lvl
    }
}

/// FNV-1a 64 — хэш имени домена (в нижнем регистре).
pub fn h64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Домен из строки списка: «домен», «0.0.0.0 домен», «домен,описание», «*.домен», «||домен^».
pub fn line_domain(l: &str) -> Option<String> {
    let l = l.trim();
    if l.is_empty() || l.starts_with('#') || l.starts_with('!') {
        return None;
    }
    let first = l.split(',').next()?;
    let w: Vec<&str> = first.split_whitespace().collect();
    let d = match w.as_slice() {
        [ip, d, ..] if ip.parse::<IpAddr>().is_ok() => *d,
        [d, ..] => *d,
        _ => return None,
    };
    let d = d.trim_start_matches("||").trim_start_matches("*.").trim_end_matches('^').trim_end_matches('.').to_ascii_lowercase();
    if d.len() < 4 || !d.contains('.') || d.parse::<IpAddr>().is_ok() || !d.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_') {
        return None;
    }
    Some(d)
}

/// Публичный IPv4 (частные, CGNAT, служебные — не берём: они в своей сети).
pub fn public4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_broadcast() || a.is_unspecified() || o[0] == 0 || (o[0] == 100 && o[1] & 0xc0 == 64) || o[0] >= 240)
}

/// IPv4 из строки списка: «1.2.3.4», «1.2.3.4,описание», «1.2.3.4:443».
pub fn line_ip(l: &str) -> Option<Ipv4Addr> {
    let l = l.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let f = l.split([',', ' ', '\t', ';']).next()?;
    let f = f.split(':').next()?;
    let a: Ipv4Addr = f.parse().ok()?;
    public4(a).then_some(a)
}

/// Сеть из Spamhaus DROP (NDJSON: {"cidr":"1.10.16.0/20",…}) или «1.2.3.0/24» в тексте.
pub fn line_net(l: &str) -> Option<(Ipv4Addr, u8)> {
    let c = match l.find("\"cidr\":\"") {
        Some(i) => l[i + 8..].split('"').next()?,
        None => l.trim().split([' ', ';', ',']).next()?,
    };
    let (ip, bits) = c.split_once('/')?;
    let a: Ipv4Addr = ip.parse().ok()?;
    let b: u8 = bits.parse().ok()?;
    ((8..=32).contains(&b) && public4(a)).then_some((a, b))
}

/// Загруженные списки: домены (хэш → источник), адреса и сети (→ источник).
#[derive(Default)]
pub struct Lists {
    dom: Vec<(u64, u8)>,
    ips: Vec<(u32, u8)>,
    nets: Vec<(u32, u32, u8)>,
    pub at: i64,
    /// источник → (записей, ошибка)
    pub stat: Vec<(String, usize, String)>,
}

impl Lists {
    /// Домен (или его родитель, от 2 меток) в списках → источник.
    pub fn dom_src(&self, name: &str) -> Option<(String, u8)> {
        let name = name.trim_end_matches('.');
        let mut s = name;
        loop {
            if s.contains('.') {
                let h = h64(s);
                if let Ok(i) = self.dom.binary_search_by(|x| x.0.cmp(&h)) {
                    return Some((s.to_ascii_lowercase(), self.dom[i].1));
                }
            }
            match s.find('.') {
                Some(i) if s[i + 1..].contains('.') => s = &s[i + 1..],
                _ => return None,
            }
        }
    }

    pub fn ip_src(&self, a: Ipv4Addr) -> Option<u8> {
        let v = u32::from(a);
        if let Ok(i) = self.ips.binary_search_by(|x| x.0.cmp(&v)) {
            return Some(self.ips[i].1);
        }
        self.nets.iter().find(|n| v >= n.0 && v <= n.1).map(|n| n.2)
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (self.dom.len(), self.ips.len(), self.nets.len())
    }
}

fn add_dom(l: &mut Lists, d: &str, src: u8) {
    l.dom.push((h64(d), src));
}

/// Предел записей (защита памяти, если источник внезапно разрастётся или подменён):
/// full — 400 тыс. доменов / 100 тыс. адресов, lite — 60 / 15 тыс., nano — 8 / 3 тыс.
pub fn caps() -> (usize, usize) {
    match crate::variant::name() {
        "full" => (400_000, 100_000),
        "lite" => (60_000, 15_000),
        _ => (8_000, 3_000),
    }
}

/// Находок держим не больше (устройство, что ходит на тысячи доменов из списка, не раздует память).
const MAX_HITS: usize = 500;

/// Разобрать файл списка построчно (без чтения целиком в память).
fn parse_file(path: &str, src: usize, l: &mut Lists) -> usize {
    let (cap_dom, cap_ip) = caps();
    use std::io::BufRead;
    let Ok(f) = std::fs::File::open(path) else { return 0 };
    let s = &SOURCES[src];
    let mut n = 0;
    for line in std::io::BufReader::with_capacity(16 * 1024, f).lines().map_while(Result::ok) {
        match s.kind {
            Kind::Dom => {
                if l.dom.len() >= cap_dom {
                    break;
                }
                if let Some(d) = line_domain(&line) {
                    add_dom(l, &d, src as u8);
                    n += 1;
                }
            }
            Kind::Ip => {
                if l.ips.len() >= cap_ip {
                    break;
                }
                if let Some(a) = line_ip(&line) {
                    l.ips.push((u32::from(a), src as u8));
                    n += 1;
                }
            }
            Kind::Net => {
                if l.nets.len() >= cap_ip {
                    break;
                }
                if let Some((a, b)) = line_net(&line) {
                    let base = u32::from(a) & (u32::MAX << (32 - b as u32));
                    let end = base | !(u32::MAX << (32 - b as u32));
                    l.nets.push((base, end, src as u8));
                    n += 1;
                }
            }
        }
    }
    n
}

/// Отсортировать и убрать повторы (первый источник — самый «точный»: C2 раньше общих списков).
fn finish(l: &mut Lists) {
    l.dom.sort_by_key(|x| (x.0, x.1));
    l.dom.dedup_by_key(|x| x.0);
    l.dom.shrink_to_fit();
    l.ips.sort_by_key(|x| (x.0, x.1));
    l.ips.dedup_by_key(|x| x.0);
    l.ips.shrink_to_fit();
    l.nets.sort();
    l.nets.shrink_to_fit();
}

/// Скрипт nft: наборы адресов и сетей, пары-попадания (ядро отмечает новые соединения
/// LAN и самого роутера к ним).
pub fn nft_script(l: &Lists) -> String {
    let mut b = format!("add table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    b.push_str(&format!("\tset bad4 {{ type ipv4_addr; size {}; }}\n", (l.ips.len() + 64).max(256)));
    b.push_str("\tset badnet4 { type ipv4_addr; flags interval; auto-merge; }\n");
    b.push_str("\tset hits4 { type ipv4_addr . ipv4_addr; flags dynamic,timeout; timeout 1h; size 4096; }\n");
    for (ch, hook) in [("fw_hits", "forward"), ("out_hits", "output")] {
        b.push_str(&format!("\tchain {ch} {{\n\t\ttype filter hook {hook} priority filter - 5; policy accept;\n"));
        b.push_str("\t\tct state new ip daddr @bad4 add @hits4 { ip saddr . ip daddr }\n");
        b.push_str("\t\tct state new ip daddr @badnet4 add @hits4 { ip saddr . ip daddr }\n\t}\n");
    }
    b.push_str("}\n");
    for chunk in l.ips.chunks(2000) {
        b.push_str(&format!("add element inet {TABLE} bad4 {{ {} }}\n", chunk.iter().map(|x| Ipv4Addr::from(x.0).to_string()).collect::<Vec<_>>().join(", ")));
    }
    for chunk in l.nets.chunks(1000) {
        let s: Vec<String> = chunk.iter().map(|n| {
            let bits = 32 - (n.1 - n.0).checked_add(1).map_or(32, |x| x.trailing_zeros());
            format!("{}/{}", Ipv4Addr::from(n.0), bits)
        }).collect();
        b.push_str(&format!("add element inet {TABLE} badnet4 {{ {} }}\n", s.join(", ")));
    }
    b
}

/// Пары «устройство . адрес» из `nft list set … hits4`.
pub fn parse_hits(t: &str) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let Some(body) = t.split("elements = {").nth(1) else { return Vec::new() };
    let body = body.split('}').next().unwrap_or("");
    body.split(',').filter_map(|el| {
        let w: Vec<&str> = el.split_whitespace().collect();
        let i = w.iter().position(|x| *x == ".")?;
        Some((w.get(i.checked_sub(1)?)?.parse().ok()?, w.get(i + 1)?.parse().ok()?))
    }).collect()
}

/// Метка домена похожа на сгенерированную (DGA): длинная, «случайная».
pub fn random_label(name: &str) -> bool {
    let lab = name.split('.').next().unwrap_or("");
    if lab.len() < 10 || lab.len() > 63 {
        return false;
    }
    let (mut vow, mut dig, mut alpha) = (0usize, 0usize, 0usize);
    for c in lab.bytes() {
        match c {
            b'a' | b'e' | b'i' | b'o' | b'u' | b'y' => {
                vow += 1;
                alpha += 1
            }
            b'0'..=b'9' => dig += 1,
            b'a'..=b'z' => alpha += 1,
            b'-' => return false, // слова через дефис — не случайные
            _ => {}
        }
    }
    let n = lab.len();
    // мало гласных среди букв или перемешаны цифры и буквы
    (alpha > 0 && vow * 100 / alpha.max(1) < 22) || (dig * 100 / n >= 25 && alpha * 100 / n >= 30)
}

/// Порты, на которые черви сканируют интернет (telnet, SSH, ADB, TR-069, роутеры Huawei/Realtek,
/// SMB, RDP, VNC, базы). Веб (80/443/8080) — нет: у браузеров тоже бывает много попыток.
pub const SCAN_PORTS: &[u16] = &[22, 23, 2323, 445, 1433, 3306, 3389, 5555, 5900, 6379, 7547, 9200, 37215, 52869];
const SCAN_MIN: usize = 30;
const FANOUT_MIN: usize = 600;
const DGA_MIN: usize = 25;

/// Поведение устройства по одному снимку conntrack.
#[derive(Default, Clone, Debug)]
pub struct Beh {
    /// хэши разных внешних адресов (до FANOUT_CAP)
    pub remotes: HashSet<u64>,
    /// порт сканирования → хэши адресов в SYN_SENT
    pub scan: HashMap<u16, HashSet<u64>>,
}
pub const FANOUT_CAP: usize = 2048;

impl Beh {
    pub fn add(&mut self, dst: &IpAddr, dport: u16, syn_sent: bool) {
        let h = h64(&dst.to_string());
        if self.remotes.len() < FANOUT_CAP {
            self.remotes.insert(h);
        }
        if syn_sent && SCAN_PORTS.contains(&dport) {
            let s = self.scan.entry(dport).or_default();
            if s.len() < 512 {
                s.insert(h);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Hit {
    pub client: IpAddr,
    /// tw_c2 | tw_mal | tw_bad | tw_scan | tw_dga | tw_fanout
    pub code: &'static str,
    /// домен/адрес/порт — что именно
    pub what: String,
    pub source: String,
    pub first: i64,
    pub last: i64,
    pub count: u64,
    pub told: i64,
}

impl Hit {
    pub fn sev(&self) -> &'static str {
        match self.code {
            "tw_c2" | "tw_mal" | "tw_scan" => "high",
            "tw_bad" | "tw_dga" => "med",
            _ => "low",
        }
    }
}

#[derive(Default)]
struct BehState {
    scan_streak: u32,
    scan_port: u16,
    scan_n: usize,
    fan_since: i64,
    fan_n: usize,
    nx_from: i64,
    nx: HashSet<u64>,
}

enum Msg {
    Lists(Box<Lists>, String),
}

pub struct ThreatWatch {
    pub lists: Option<Lists>,
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
    busy: bool,
    next_fetch: i64,
    polled: i64,
    pub hits: Vec<Hit>,
    beh: HashMap<IpAddr, BehState>,
    pub err: String,
    loaded_state: bool,
    dirty: bool,
    saved_at: i64,
    retry_at: i64,
    /// (устройство, вид угрозы) → когда было последнее событие: не чаще раза в 10 мин
    told_kind: HashMap<(IpAddr, &'static str), i64>,
}

impl Default for ThreatWatch {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        ThreatWatch { lists: None, rx, tx, busy: false, next_fetch: 0, polled: 0, hits: Vec::new(), beh: HashMap::new(), err: String::new(), loaded_state: false, dirty: false, saved_at: 0, retry_at: 0, told_kind: HashMap::new() }
    }
}

fn cat_code(c: Cat) -> &'static str {
    match c {
        Cat::C2 => "tw_c2",
        Cat::Mal => "tw_mal",
        Cat::Bad => "tw_bad",
    }
}

/// Скачать и собрать списки (в потоке).
fn fetch(lvl: u8) -> (Lists, String) {
    let mut l = Lists::default();
    let dir = format!("{}/threat", crate::util::RUN_DIR);
    let _ = std::fs::create_dir_all(&dir);
    let mut errs = Vec::new();
    for (i, s) in SOURCES.iter().enumerate() {
        if !src_on(s, lvl) {
            continue;
        }
        let f = format!("{dir}/list{i}");
        match crate::vulnscan::download(s.url, &f) {
            Ok(()) => {
                let n = parse_file(&f, i, &mut l);
                l.stat.push((s.name.to_string(), n, String::new()));
            }
            Err(e) => {
                l.stat.push((s.name.to_string(), 0, e.clone()));
                errs.push(format!("{}: {e}", s.name));
            }
        }
        let _ = std::fs::remove_file(&f);
    }
    let _ = std::fs::remove_dir(&dir);
    finish(&mut l);
    let w = crate::util::now_wall();
    l.at = w.0 * 1000;
    let mut res = String::new();
    if !crate::util::readonly() {
        if let Err(e) = crate::acct::nft_script(&nft_script(&l)) {
            res = format!("nft: {e}");
        }
    }
    if res.is_empty() && !errs.is_empty() && l.dom.is_empty() && l.ips.is_empty() {
        res = errs.join("; ");
    }
    (l, res)
}

fn nft_list(args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(crate::acct::nft_bin()).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Сведения об устройстве для текста: «имя (адрес)», MAC.
pub type Namer<'a> = &'a dyn Fn(&IpAddr) -> (String, String);

impl ThreatWatch {
    /// Такт: раз в сутки — списки (в фоне), раз в минуту — попадания по адресам из ядра.
    /// Возвращает сообщения для журнала и событий.
    pub fn tick(&mut self, now: i64, on: bool, lists: &str, state_file: &str, namer: Namer) -> Vec<String> {
        let mut msgs = Vec::new();
        if !self.loaded_state {
            self.loaded_state = true;
            self.load(state_file, now);
        }
        while let Ok(m) = self.rx.try_recv() {
            let Msg::Lists(l, err) = m;
            self.busy = false;
            let (d, i, n) = l.counts();
            crate::log_info!("threat: lists {} domains, {} IPs, {} nets{}", d, i, n, if err.is_empty() { String::new() } else { format!(" ({err})") });
            self.err = err;
            self.lists = Some(*l);
        }
        if !on {
            if self.lists.take().is_some() && !crate::util::readonly() {
                let _ = crate::acct::nft_script(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
            }
            self.next_fetch = 0;
            self.beh.clear();
            return msgs;
        }
        if !self.busy && now >= self.next_fetch {
            // первый раз — через минуту после запуска (не мешать старту), дальше — раз в сутки
            if self.next_fetch == 0 {
                self.next_fetch = now + 60_000;
            } else {
                self.busy = true;
                self.next_fetch = now + DAY_MS;
                let lvl = level(lists);
                let tx = self.tx.clone();
                let _ = std::thread::Builder::new().name("threatlists".into()).spawn(move || {
                    let (l, e) = fetch(lvl);
                    let _ = tx.send(Msg::Lists(Box::new(l), e));
                });
            }
        }
        // таблица пропала (перезапуск firewall не трогает inet-таблицы, но на всякий) — заново
        if now - self.polled >= 60_000 && self.lists.is_some() {
            self.polled = now;
            match nft_list(&["list", "set", "inet", TABLE, "hits4"]) {
                Some(t) => {
                    for (c, d) in parse_hits(&t) {
                        let src = self.lists.as_ref().and_then(|l| l.ip_src(d));
                        if let Some(s) = src {
                            let sc = &SOURCES[s as usize];
                            msgs.extend(self.record(now, IpAddr::V4(c), cat_code(sc.cat), &d.to_string(), sc.name, namer));
                        }
                    }
                }
                None => {
                    // таблицы нет (или ошибка nft) — переписать, но после ошибки не чаще раза в час
                    if !crate::util::readonly() && !self.busy && (self.err.is_empty() || now - self.retry_at >= 3600_000) {
                        self.retry_at = now;
                        if let Some(l) = &self.lists {
                            match crate::acct::nft_script(&nft_script(l)) {
                                Ok(()) => self.err.clear(),
                                Err(e) => self.err = format!("nft: {e}"),
                            }
                        }
                    }
                }
            }
        }
        self.hits.retain(|h| now - h.last < KEEP_MS);
        if self.dirty && now - self.saved_at >= 600_000 {
            self.save(state_file, now);
        }
        msgs
    }

    /// Учесть попадание; новое (или давно не сообщали) — сообщение.
    fn record(&mut self, now: i64, client: IpAddr, code: &'static str, what: &str, source: &str, namer: Namer) -> Vec<String> {
        let mut out = Vec::new();
        let i = match self.hits.iter().position(|h| h.client == client && h.code == code && h.what == what) {
            Some(i) => i,
            None => {
                if self.hits.len() >= MAX_HITS {
                    // самая давняя по последнему разу — вон
                    if let Some(j) = self.hits.iter().enumerate().min_by_key(|(_, h)| h.last).map(|(j, _)| j) {
                        self.hits.swap_remove(j);
                    }
                }
                self.hits.push(Hit { client, code, what: what.to_string(), source: source.to_string(), first: now, last: now, count: 0, told: i64::MIN / 2 });
                self.hits.len() - 1
            }
        };
        self.dirty = true;
        let h = &mut self.hits[i];
        h.last = now;
        h.count += 1;
        let kind_at = self.told_kind.get(&(client, code)).copied().unwrap_or(i64::MIN / 2);
        if now - h.told >= EVENT_EVERY_MS && now - kind_at >= 600_000 {
            h.told = now;
            self.told_kind.insert((client, code), now);
            if self.told_kind.len() > 4 * MAX_HITS {
                self.told_kind.retain(|_, t| now - *t < EVENT_EVERY_MS);
            }
            let (dev, _) = namer(&client);
            out.push(match code {
                "tw_c2" => tr!("Ботнет: {} обращается к командному серверу {} ({})", dev, what, source).to_string(),
                "tw_mal" => tr!("Угроза: {} обращается к узлу раздачи вредоносов {} ({})", dev, what, source).to_string(),
                "tw_bad" => tr!("Угроза: {} обращается к адресу из списка угроз {} ({})", dev, what, source).to_string(),
                "tw_scan" => tr!("Ботнет: {} сканирует интернет ({}) — так распространяются черви вроде Mirai", dev, what).to_string(),
                "tw_dga" => tr!("Подозрительно: {} запрашивает много случайных несуществующих доменов ({}) — признак генерации доменов (DGA)", dev, what).to_string(),
                _ => tr!("Подозрительно: {} держит соединения с очень многими адресами ({}) — так работают прокси-ботнеты (или торрент)", dev, what).to_string(),
            });
        }
        out
    }

    /// DNS-запросы устройств (из dnswatch): имя в списках — попадание; NXDOMAIN со
    /// «случайными» именами — счёт для DGA.
    pub fn on_dns(&mut self, now: i64, seen: &[(IpAddr, String, u8)], namer: Namer) -> Vec<String> {
        let mut msgs = Vec::new();
        let Some(l) = &self.lists else { return msgs };
        let mut found: Vec<(IpAddr, &'static str, String, &'static str)> = Vec::new();
        for (client, name, _) in seen {
            if let Some((dom, s)) = l.dom_src(name) {
                let sc = &SOURCES[s as usize];
                found.push((*client, cat_code(sc.cat), dom, sc.name));
            }
        }
        for (client, name, rcode) in seen {
            if *rcode == 3 && random_label(name) {
                let b = self.beh.entry(*client).or_default();
                if now - b.nx_from > 3600_000 {
                    b.nx_from = now;
                    b.nx.clear();
                }
                if b.nx.len() < 256 {
                    b.nx.insert(h64(name));
                }
                if b.nx.len() >= DGA_MIN {
                    let n = b.nx.len();
                    b.nx.clear();
                    found.push((*client, "tw_dga", tr!("{} за час", n).to_string(), ""));
                }
            }
        }
        for (c, code, what, src) in found {
            msgs.extend(self.record(now, c, code, &what, src, namer));
        }
        msgs
    }

    /// Поведение по снимку conntrack (раз в несколько секунд): сканирование и «прокси».
    pub fn on_conntrack(&mut self, now: i64, beh: &HashMap<IpAddr, Beh>, namer: Namer) -> Vec<String> {
        let mut found: Vec<(IpAddr, &'static str, String)> = Vec::new();
        for (ip, b) in beh {
            let st = self.beh.entry(*ip).or_default();
            let top = b.scan.iter().map(|(p, s)| (s.len(), *p)).max();
            match top {
                Some((n, p)) if n >= SCAN_MIN => {
                    st.scan_streak += 1;
                    st.scan_port = p;
                    st.scan_n = st.scan_n.max(n);
                    if st.scan_streak >= 2 {
                        found.push((*ip, "tw_scan", tr!("порт {}, {} адресов", p, st.scan_n).to_string()));
                        st.scan_streak = 0;
                        st.scan_n = 0;
                    }
                }
                _ => st.scan_streak = 0,
            }
            let n = b.remotes.len();
            if n >= FANOUT_MIN {
                if st.fan_since == 0 {
                    st.fan_since = now;
                }
                st.fan_n = st.fan_n.max(n);
                if now - st.fan_since >= 10 * 60_000 {
                    found.push((*ip, "tw_fanout", tr!("до {} адресов одновременно", st.fan_n).to_string()));
                    st.fan_since = now; // следующее — не раньше чем через 10 мин
                    st.fan_n = 0;
                }
            } else {
                st.fan_since = 0;
                st.fan_n = 0;
            }
        }
        // забыть устройства без соединений (кроме счёта DGA)
        self.beh.retain(|ip, s| beh.contains_key(ip) || !s.nx.is_empty());
        let mut msgs = Vec::new();
        for (c, code, what) in found {
            msgs.extend(self.record(now, c, code, &what, "", namer));
        }
        msgs
    }

    /// Находки для раздела «Безопасность» (LAN, с кнопкой изоляции).
    pub fn findings(&self, namer: Namer) -> Vec<crate::vulnscan::Finding> {
        self.hits.iter().map(|h| {
            let (dev, mac) = namer(&h.client);
            crate::vulnscan::Finding {
                sev: h.sev().into(),
                area: "lan".into(),
                code: h.code.into(),
                target: dev,
                mac,
                args: vec![h.what.clone(), h.source.clone(), h.count.to_string(), (h.last / 1000).to_string()],
                ..Default::default()
            }
        }).collect()
    }

    pub fn status_json(&self, j: &mut J, on: bool) {
        j.obj().key("on").bool(on).key("busy").bool(self.busy);
        if let Some(l) = &self.lists {
            let (d, i, n) = l.counts();
            j.key("domains").int(d as i64).key("ips").int(i as i64).key("nets").int(n as i64).key("at").int(l.at);
        }
        if !self.err.is_empty() {
            j.key("error").str(&self.err);
        }
        j.key("hits").int(self.hits.len() as i64);
        j.end_obj();
    }

    fn load(&mut self, path: &str, now: i64) {
        let Ok(t) = std::fs::read_to_string(path) else { return };
        let Ok(crate::value::Value::List(list)) = crate::value::parse_json(&t) else { return };
        for x in list {
            let s = |k: &str| x.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let n = |k: &str| x.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0) as i64;
            let code: &'static str = match s("code").as_str() {
                "tw_c2" => "tw_c2",
                "tw_mal" => "tw_mal",
                "tw_bad" => "tw_bad",
                "tw_scan" => "tw_scan",
                "tw_dga" => "tw_dga",
                "tw_fanout" => "tw_fanout",
                _ => continue,
            };
            let Ok(client) = s("client").parse::<IpAddr>() else { continue };
            if now - n("last") >= KEEP_MS {
                continue;
            }
            self.hits.push(Hit { client, code, what: s("what"), source: s("source"), first: n("first"), last: n("last"), count: n("count") as u64, told: n("last") });
        }
    }

    fn save(&mut self, path: &str, now: i64) {
        self.dirty = false;
        self.saved_at = now;
        if crate::util::readonly() {
            return;
        }
        let mut j = J::new();
        j.arr();
        for h in &self.hits {
            j.obj().key("client").str(&h.client.to_string()).key("code").str(h.code).key("what").str(&h.what).key("source").str(&h.source).key("first").int(h.first).key("last").int(h.last).key("count").int(h.count as i64).end_obj();
        }
        j.end_arr();
        let _ = crate::util::write_atomic(path, j.b.as_bytes(), 0o600);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines() {
        assert_eq!(line_domain("0.0.0.0 bad.example.com").as_deref(), Some("bad.example.com"));
        assert_eq!(line_domain("1.win-faw.win,Possible Cobalt Strike C2 Domain").as_deref(), Some("1.win-faw.win"));
        assert_eq!(line_domain("*.evil.org").as_deref(), Some("evil.org"));
        assert_eq!(line_domain("||ads.bad.net^").as_deref(), Some("ads.bad.net"));
        assert!(line_domain("# comment").is_none() && line_domain("1.2.3.4").is_none() && line_domain("localhost").is_none());
        assert_eq!(line_ip("1.117.74.144,Possible Cobaltstrike C2 IP"), Some("1.117.74.144".parse().unwrap()));
        assert_eq!(line_ip("27.133.154.218"), Some("27.133.154.218".parse().unwrap()));
        assert!(line_ip("10.1.2.3").is_none() && line_ip("100.64.1.1").is_none() && line_ip("# Feodo").is_none());
        assert_eq!(line_net(r#"{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}"#), Some(("1.10.16.0".parse().unwrap(), 20)));
        assert!(line_net(r#"{"type":"metadata","timestamp":1}"#).is_none());
    }

    #[test]
    fn lists_match() {
        let mut l = Lists::default();
        add_dom(&mut l, "evil.org", 7);
        add_dom(&mut l, "c2.bad.net", 0);
        l.ips.push((u32::from(Ipv4Addr::new(27, 133, 154, 218)), 2));
        l.nets.push((u32::from(Ipv4Addr::new(1, 10, 16, 0)), u32::from(Ipv4Addr::new(1, 10, 31, 255)), 6));
        finish(&mut l);
        assert_eq!(l.dom_src("evil.org"), Some(("evil.org".into(), 7)));
        assert_eq!(l.dom_src("x.y.EVIL.org."), Some(("evil.org".into(), 7)));
        assert_eq!(l.dom_src("c2.bad.net"), Some(("c2.bad.net".into(), 0)));
        assert!(l.dom_src("bad.net").is_none() && l.dom_src("org").is_none() && l.dom_src("good.com").is_none());
        assert_eq!(l.ip_src("27.133.154.218".parse().unwrap()), Some(2));
        assert_eq!(l.ip_src("1.10.20.5".parse().unwrap()), Some(6));
        assert!(l.ip_src("8.8.8.8".parse().unwrap()).is_none());
        let s = nft_script(&l);
        assert!(s.contains("add element inet cgmon_threat bad4 { 27.133.154.218 }"));
        assert!(s.contains("add element inet cgmon_threat badnet4 { 1.10.16.0/20 }"));
        assert!(s.contains("ct state new ip daddr @bad4 add @hits4 { ip saddr . ip daddr }"));
    }

    #[test]
    fn hits_and_dga() {
        let t = "table inet cgmon_threat {\n\tset hits4 {\n\t\ttype ipv4_addr . ipv4_addr\n\t\tsize 4096\n\t\tflags dynamic,timeout\n\t\ttimeout 1h\n\t\telements = { 192.168.1.50 . 27.133.154.218 expires 59m40s, 192.168.1.211 . 1.10.20.5 expires 3m }\n\t}\n}\n";
        assert_eq!(parse_hits(t), vec![("192.168.1.50".parse().unwrap(), "27.133.154.218".parse().unwrap()), ("192.168.1.211".parse().unwrap(), "1.10.20.5".parse().unwrap())]);
        assert!(random_label("xkqzvbnmtrw.com") && random_label("a8f3k29dk3x9.net"));
        assert!(!random_label("googleapis.com") && !random_label("connectivitycheck.gstatic.com") && !random_label("my-long-domain.org") && !random_label("short.io"));
    }

    #[test]
    fn behavior() {
        let mut tw = ThreatWatch::default();
        let namer = |ip: &IpAddr| (format!("dev ({ip})"), String::new());
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let mut b = Beh::default();
        for i in 0..40u8 {
            b.add(&IpAddr::from([45, 1, i, 7]), 23, true);
        }
        let m: HashMap<IpAddr, Beh> = [(ip, b)].into_iter().collect();
        assert!(tw.on_conntrack(1000, &m, &namer).is_empty()); // один снимок — ещё не тревога
        let msg = tw.on_conntrack(6000, &m, &namer);
        assert_eq!(msg.len(), 1);
        assert!(msg[0].contains("dev (192.168.1.50)") && tw.hits[0].code == "tw_scan" && tw.hits[0].sev() == "high");
        // тот же — не чаще раза в 6 ч
        tw.on_conntrack(11000, &m, &namer);
        assert!(tw.on_conntrack(16000, &m, &namer).is_empty());
        let f = tw.findings(&namer);
        assert_eq!(f[0].area, "lan");
        assert_eq!(f[0].args[0], "порт 23, 40 адресов");
    }
}

#[cfg(test)]
mod dump {
    /// `THREAT_DUMP_DIR=<папка со списками> THREAT_DUMP=<файл> cargo test threat_dump` — скрипт nft
    /// из настоящих списков (для `nft -c -f` на роутере).
    #[test]
    fn threat_dump() {
        let (Ok(dir), Ok(out)) = (std::env::var("THREAT_DUMP_DIR"), std::env::var("THREAT_DUMP")) else { return };
        let mut l = super::Lists::default();
        for (i, f) in [(1, "IPC2s-30day.csv"), (2, "ipblocklist.txt"), (8, "tif.txt"), (6, "drop_v4.json")] {
            super::parse_file(&format!("{dir}/{f}"), i, &mut l);
        }
        super::finish(&mut l);
        std::fs::write(out, super::nft_script(&l)).unwrap();
    }
}
