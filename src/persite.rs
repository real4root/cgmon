//! Per-Site Routing, постоянный список (перенос ручного PBR в cgmon): сайты, сети и AS,
//! которые всегда идут через выбранный гейт — в отличие от unblock.rs, который
//! ловит блокировки сам и уводит на сутки.
//!
//! Список — текстовый файл (dns_guard.persite_file), правится со страницы в отдельном
//! окне: по одному на строку или через «;», комментарии после #. Элементы:
//!   taobao.com         — домен со всеми поддоменами: его IPv4 → гейт (tcp/udp 80, 443),
//!                        IPv6 — отказ (клиент уходит на IPv4); при dnsmasq с nftset адреса
//!                        попадают в набор до ответа клиенту, иначе — из DNS-ответов (DNSWatch);
//!   47.74.0.0/15, 1.2.3.4 — сеть IPv4: все порты tcp/udp → гейт;
//!   2401:b180::/32     — сеть IPv6: отказ новым соединениям (гейты IPv6 не возят);
//!   AS45102            — все анонсированные префиксы AS (RIPEstat, обновление раз в неделю,
//!                        кеш переживает перезапуск и недоступность RIPEstat).
//!
//! nft: своя таблица inet cgmon_persite (наборы dom4/dom6 наполняет dnsmasq — таблицу
//! не пересоздаём, меняем только цепочки и наборы сетей). Метка — метка гейта, маршрут
//! даёт уже готовое ip rule этого гейта (как у unblock.rs).

use crate::json::J;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};

pub const TABLE: &str = "cgmon_persite";
const AS_FILE: &str = "/etc/cgmon/persite_as.json";
const DNSMASQ_FILE: &str = "cgmon-persite.conf";
const AS_REFRESH_MS: i64 = 7 * 86400_000;
const AS_RETRY_MS: i64 = 600_000;
/// пределы: список — до 2000 элементов, AS — до 32, префиксов AS — до 20000
pub const MAX_ITEMS: usize = 2000;
const MAX_AS: usize = 32;
const MAX_AS_NETS: usize = 20000;
pub const MAX_TEXT: usize = 256 * 1024;
const FEED_EVERY_MS: u64 = 5000;
const FEED_AGAIN_MS: u64 = 30 * 60_000;

/// Разобранный список.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct List {
    pub domains: Vec<String>,
    pub net4: Vec<String>,
    pub net6: Vec<String>,
    pub asns: Vec<u32>,
    /// непонятые элементы (показываются в окне списка)
    pub bad: Vec<String>,
}

/// Разбор текста списка: разделители — перевод строки, «;», «,» и пробелы; # — комментарий.
pub fn parse(text: &str) -> List {
    let mut l = List::default();
    let (mut d, mut n4, mut n6, mut a) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        for raw in line.split([';', ',', ' ', '\t', '\r']) {
            let t = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if t.is_empty() {
                continue;
            }
            if d.len() + n4.len() + n6.len() + a.len() >= MAX_ITEMS {
                l.bad.push(t);
                continue;
            }
            if let Some(num) = t.strip_prefix("as").filter(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit())) {
                match num.parse::<u32>() {
                    Ok(n) if n > 0 && a.len() < MAX_AS => {
                        a.insert(n);
                    }
                    _ => l.bad.push(t),
                }
                continue;
            }
            if let Some(net) = net_norm(&t) {
                if net.contains(':') {
                    n6.insert(net);
                } else {
                    n4.insert(net);
                }
                continue;
            }
            let dom = t.trim_start_matches("*.").trim_start_matches('.');
            if crate::unblock::domain_ok(dom) && dom.contains('.') {
                d.insert(dom.to_string());
            } else {
                l.bad.push(t);
            }
        }
    }
    l.domains = d.into_iter().collect();
    l.net4 = collapse(n4.into_iter().collect());
    l.net6 = collapse(n6.into_iter().collect());
    l.asns = a.into_iter().collect();
    l
}

/// Адрес или сеть → каноническая запись (адрес сети без хостовых битов); не сеть — None.
fn net_norm(t: &str) -> Option<String> {
    let (ip, bits) = match crate::netx::parse_cidr(t) {
        Some(x) => x,
        None => {
            let ip = crate::netx::parse_ip(t)?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    let n = crate::netx::IpNet::new(ip, bits);
    if bits == 0 {
        return None; // весь интернет — не per-site (для этого есть шлюз «весь трафик»)
    }
    Some(format!("{}/{}", n.ip, bits))
}

/// Убрать сети, целиком лежащие внутри других: сортировка по (адрес, длина) и один
/// проход — вложенная сеть всегда идёт сразу за своим покрытием.
fn collapse(v: Vec<String>) -> Vec<String> {
    let key = |n: &crate::netx::IpNet| -> (u8, u128, u8) {
        match n.ip {
            IpAddr::V4(a) => (4, u32::from(a) as u128, n.bits),
            IpAddr::V6(a) => (6, u128::from(a), n.bits),
        }
    };
    let mut nets: Vec<crate::netx::IpNet> = v.iter().filter_map(|s| crate::netx::parse_cidr(s).map(|(ip, b)| crate::netx::IpNet::new(ip, b))).collect();
    nets.sort_by_key(|n| key(n));
    let mut out: Vec<String> = Vec::with_capacity(nets.len());
    let mut cover: Option<crate::netx::IpNet> = None;
    for n in nets {
        if let Some(c) = &cover {
            if c.is_v4() == n.is_v4() && c.bits <= n.bits && c.contains(&n.ip) {
                continue;
            }
        }
        out.push(n.to_string());
        cover = Some(n);
    }
    out
}

/// Префиксы одной AS из кеша.
#[derive(Clone, Debug, Default)]
struct AsNets {
    at: i64,
    v4: Vec<String>,
    v6: Vec<String>,
    err: String,
}

type AsResult = (u32, Result<(Vec<String>, Vec<String>), String>);

pub struct PerSite {
    text: String,
    list: List,
    file: String,
    file_sig: (u64, i64),
    asn: BTreeMap<u32, AsNets>,
    as_rx: Option<Receiver<AsResult>>,
    as_tx: Sender<AsResult>,
    as_busy: bool,
    as_tried: HashMap<u32, i64>,
    loaded: bool,
    written: String,
    ensured: u64,
    rules_on: bool,
    gate: u32,
    /// dnsmasq: файл в его conf-dir (пусто — dnsmasq без nftset или не найден)
    dm_path: String,
    dm_written: String,
    dm_checked: u64,
    dm_busy: Option<Receiver<Result<(), String>>>,
    fed: HashMap<IpAddr, u64>,
    fed_at: u64,
    pub err: String,
}

impl Default for PerSite {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        PerSite {
            text: String::new(),
            list: List::default(),
            file: String::new(),
            file_sig: (0, 0),
            asn: BTreeMap::new(),
            as_rx: Some(rx),
            as_tx: tx,
            as_busy: false,
            as_tried: HashMap::new(),
            loaded: false,
            written: String::new(),
            ensured: 0,
            rules_on: false,
            gate: 0,
            dm_path: String::new(),
            dm_written: String::new(),
            dm_checked: 0,
            dm_busy: None,
            fed: HashMap::new(),
            fed_at: 0,
            err: String::new(),
        }
    }
}

fn file_sig(path: &str) -> (u64, i64) {
    std::fs::metadata(path).map(|m| {
        use std::os::unix::fs::MetadataExt;
        (m.len(), m.mtime())
    }).unwrap_or((0, 0))
}

impl PerSite {
    /// Перечитать файл, если он изменился (правка руками тоже подхватывается).
    fn reload(&mut self, file: &str) {
        let path = crate::storage::path(file);
        let sig = file_sig(&path);
        if file == self.file && sig == self.file_sig {
            return;
        }
        self.file = file.to_string();
        self.file_sig = sig;
        let t = crate::textenc::read_normalized(&path).unwrap_or_default();
        self.list = parse(&t);
        self.text = t;
    }

    /// Сохранить новый текст списка (со страницы). Возвращает разобранный список.
    pub fn save(&mut self, file: &str, text: &str) -> Result<List, String> {
        if text.len() > MAX_TEXT {
            return Err(tr!("список слишком большой (больше {} КБ)", MAX_TEXT / 1024));
        }
        let text = text.replace("\r\n", "\n");
        let l = parse(&text);
        let path = crate::storage::path(file);
        if let Some(p) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(p);
        }
        crate::util::write_atomic(&path, text.as_bytes(), 0o644).map_err(|e| format!("{path}: {e}"))?;
        self.file_sig = (0, 0); // перечитать на следующем такте
        self.ensured = 0;
        Ok(l)
    }

    fn load_as(&mut self) {
        let Ok(t) = std::fs::read_to_string(crate::storage::path(AS_FILE)) else { return };
        let Ok(crate::value::Value::List(l)) = crate::value::parse_json(&t) else { return };
        for v in l {
            let Some(n) = v.get("as").and_then(|x| x.as_f64()) else { continue };
            let strs = |k: &str| match v.get(k) {
                Some(crate::value::Value::List(a)) => a.iter().filter_map(|x| x.as_str().and_then(net_norm)).collect::<Vec<String>>(),
                _ => Vec::new(),
            };
            let at = v.get("at").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
            self.asn.insert(n as u32, AsNets { at, v4: strs("v4"), v6: strs("v6"), err: String::new() });
        }
    }

    fn save_as(&self) {
        if crate::util::readonly() {
            return;
        }
        let mut j = J::new();
        j.arr();
        for (n, a) in self.asn.iter().filter(|(_, a)| a.at > 0) {
            j.obj().key("as").int(*n as i64).key("at").int(a.at);
            j.key("v4").arr();
            for s in &a.v4 {
                j.str(s);
            }
            j.end_arr().key("v6").arr();
            for s in &a.v6 {
                j.str(s);
            }
            j.end_arr().end_obj();
        }
        j.end_arr();
        let _ = crate::util::write_atomic(&crate::storage::path(AS_FILE), j.b.as_bytes(), 0o644);
    }

    /// Префиксы AS: устаревшие — по одной в фоне (RIPEstat).
    fn as_tick(&mut self, now: i64) -> Vec<String> {
        let mut msgs = Vec::new();
        if let Some(rx) = &self.as_rx {
            while let Ok((n, r)) = rx.try_recv() {
                self.as_busy = false;
                let e = self.asn.entry(n).or_default();
                match r {
                    Ok((v4, v6)) => {
                        let first = e.at == 0;
                        e.at = now;
                        e.err.clear();
                        if first || e.v4.len() != v4.len() || e.v6.len() != v6.len() {
                            msgs.push(tr!("Per-Site Routing: AS{} — {} сетей IPv4, {} IPv6 (RIPEstat)", n, v4.len(), v6.len()));
                        }
                        e.v4 = v4;
                        e.v6 = v6;
                        self.save_as();
                    }
                    Err(err) => {
                        crate::log_info!("{}", tr!("Per-Site Routing: AS{} — не удалось получить сети: {}", n, err));
                        e.err = err;
                    }
                }
            }
        }
        if self.as_busy {
            return msgs;
        }
        let want = self.list.asns.clone();
        for n in want {
            let at = self.asn.get(&n).map(|a| a.at).unwrap_or(0);
            let tried = self.as_tried.get(&n).copied().unwrap_or(0);
            if now - at < AS_REFRESH_MS || now - tried < AS_RETRY_MS {
                continue;
            }
            self.as_tried.insert(n, now);
            self.as_busy = true;
            let tx = self.as_tx.clone();
            let _ = std::thread::Builder::new().name("persite-as".into()).spawn(move || {
                let _ = tx.send((n, fetch_as(n)));
            });
            break;
        }
        msgs
    }

    /// Такт: mode — dns_guard.persite (off — снять всё), gate — метка гейта (0 — гейта нет:
    /// правила сняты, трафик идёт напрямую), aaaa — пустой AAAA доменам.
    pub fn tick(&mut self, now: i64, now_ms: u64, on: bool, gate: u32, file: &str, aaaa: bool, dnsw: &crate::dnswatch::DnsWatch) -> Vec<String> {
        let mut msgs = Vec::new();
        if !on {
            if self.rules_on {
                self.teardown();
            }
            self.dnsmasq(now_ms, &[], false);
            self.gate = 0;
            return msgs;
        }
        if !self.loaded {
            self.loaded = true;
            self.load_as();
        }
        self.reload(file);
        msgs.extend(self.as_tick(now));
        if gate != self.gate {
            if gate == 0 && self.gate != 0 {
                msgs.push(tr!("Per-Site Routing: гейт недоступен — сайты из списка идут напрямую").to_string());
            } else if gate != 0 && self.gate == 0 && !self.is_empty() {
                msgs.push(tr!("Per-Site Routing: сайты из списка идут через гейт ({} доменов, {} сетей)", self.list.domains.len(), self.nets().0.len() + self.nets().1.len()));
            }
            self.gate = gate;
            self.fed.clear();
        }
        self.apply(now_ms);
        let doms = self.list.domains.clone();
        self.dnsmasq(now_ms, &doms, aaaa);
        if gate != 0 && now_ms.saturating_sub(self.fed_at) >= FEED_EVERY_MS {
            self.fed_at = now_ms;
            self.feed(now_ms, dnsw);
        }
        msgs
    }

    fn is_empty(&self) -> bool {
        self.list.domains.is_empty() && self.list.net4.is_empty() && self.list.net6.is_empty() && self.list.asns.is_empty()
    }

    /// Все сети: из списка и из AS.
    fn nets(&self) -> (Vec<String>, Vec<String>) {
        let (mut v4, mut v6) = (self.list.net4.clone(), self.list.net6.clone());
        let mut n = 0;
        for a in &self.list.asns {
            if let Some(x) = self.asn.get(a) {
                for s in x.v4.iter().chain(&x.v6) {
                    if n >= MAX_AS_NETS {
                        break;
                    }
                    n += 1;
                    if s.contains(':') {
                        v6.push(s.clone());
                    } else {
                        v4.push(s.clone());
                    }
                }
            }
        }
        v4.sort();
        v4.dedup();
        v6.sort();
        v6.dedup();
        (collapse(v4), collapse(v6))
    }

    fn apply(&mut self, now_ms: u64) {
        let (v4, v6) = self.nets();
        let script = nft_script(&v4, &v6, self.gate, !self.list.domains.is_empty());
        // раз в минуту — заново, даже без изменений (таблицу могло смыть: fw4 reload)
        if script == self.written && now_ms.saturating_sub(self.ensured) < 60_000 {
            return;
        }
        if script == self.written && self.table_ok() {
            self.ensured = now_ms;
            return;
        }
        self.ensured = now_ms;
        match crate::acct::nft_script(&script) {
            Ok(_) => {
                self.written = script;
                self.rules_on = true;
                self.err.clear();
                self.fed.clear();
            }
            Err(e) => {
                self.err = tr!("nft: {}", e);
                self.written.clear();
            }
        }
    }

    fn table_ok(&self) -> bool {
        std::process::Command::new("nft").args(["list", "chain", "inet", TABLE, "steer"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map_or(false, |s| s.success())
    }

    fn teardown(&mut self) {
        let _ = crate::acct::nft_script(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
        self.written.clear();
        self.rules_on = false;
        self.fed.clear();
    }

    /// Адреса доменов из DNS-ответов клиентам (кто бы ни отвечал) — в dom4/dom6.
    fn feed(&mut self, now_ms: u64, dnsw: &crate::dnswatch::DnsWatch) {
        if self.list.domains.is_empty() {
            return;
        }
        let set: HashSet<&str> = self.list.domains.iter().map(|s| s.as_str()).collect();
        let (mut a4, mut a6) = (Vec::new(), Vec::new());
        for (ip, name) in dnsw.pairs() {
            if !name_in(&set, name) {
                continue;
            }
            if self.fed.get(ip).map_or(false, |t| now_ms.saturating_sub(*t) < FEED_AGAIN_MS) {
                continue;
            }
            if ip.is_unspecified() || !crate::witness::public(ip) {
                continue;
            }
            self.fed.insert(*ip, now_ms);
            if ip.is_ipv4() { a4.push(ip.to_string()) } else { a6.push(ip.to_string()) }
        }
        if self.fed.len() > 20000 {
            self.fed.retain(|_, t| now_ms.saturating_sub(*t) < FEED_AGAIN_MS);
        }
        let mut s = String::new();
        for (set, l) in [("dom4", &a4), ("dom6", &a6)] {
            for ch in l.chunks(200) {
                s.push_str(&format!("add element inet {TABLE} {set} {{ {} }}\n", ch.join(", ")));
            }
        }
        if !s.is_empty() {
            let _ = crate::acct::nft_script(&s);
        }
    }

    /// Файл dnsmasq (nftset + пустой AAAA) в его conf-dir; изменился — перезапуск dnsmasq в фоне.
    fn dnsmasq(&mut self, now_ms: u64, doms: &[String], aaaa: bool) {
        if let Some(rx) = &self.dm_busy {
            match rx.try_recv() {
                Ok(r) => {
                    if let Err(e) = r {
                        self.err = e;
                    }
                    self.dm_busy = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(_) => self.dm_busy = None,
            }
        }
        if self.dm_path.is_empty() || now_ms.saturating_sub(self.dm_checked) >= 3600_000 {
            if doms.is_empty() && self.dm_written.is_empty() && self.dm_checked > 0 {
                return;
            }
            self.dm_checked = now_ms;
            let p = dnsmasq_dir().map(|d| format!("{d}/{DNSMASQ_FILE}")).unwrap_or_default();
            if p != self.dm_path && !self.dm_path.is_empty() {
                let _ = std::fs::remove_file(&self.dm_path);
            }
            self.dm_path = p;
        }
        if self.dm_path.is_empty() || crate::util::readonly() {
            return;
        }
        let want = dnsmasq_conf(doms, aaaa);
        let cur = std::fs::read_to_string(&self.dm_path).unwrap_or_default();
        if want == cur {
            self.dm_written = want;
            return;
        }
        if want.is_empty() {
            let _ = std::fs::remove_file(&self.dm_path);
        } else if let Err(e) = crate::util::write_atomic(&self.dm_path, want.as_bytes(), 0o644) {
            self.err = format!("{}: {e}", self.dm_path);
            return;
        }
        self.dm_written = want;
        let (tx, rx) = std::sync::mpsc::channel();
        self.dm_busy = Some(rx);
        let _ = std::thread::Builder::new().name("persite-dnsmasq".into()).spawn(move || {
            let r = std::process::Command::new("/etc/init.d/dnsmasq").arg("restart").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
            let _ = tx.send(match r {
                Ok(s) if s.success() => Ok(()),
                _ => Err(tr!("dnsmasq: не удалось перезапустить").to_string()),
            });
        });
        crate::log_info!("{}", tr!("Per-Site Routing: список доменов передан dnsmasq ({}), dnsmasq перезапускается", doms.len()));
    }

    pub fn status_json(&self, j: &mut J, on: bool, gate_name: &str) {
        if !on {
            return;
        }
        let (v4, v6) = self.nets();
        j.obj().key("gate").str(gate_name).key("active").bool(self.gate != 0 && self.rules_on);
        j.key("domains").int(self.list.domains.len() as i64).key("nets4").int(v4.len() as i64).key("nets6").int(v6.len() as i64);
        j.key("bad").int(self.list.bad.len() as i64);
        j.key("dns").str(if self.dm_written.is_empty() { "dnswatch" } else { "dnsmasq" });
        j.key("asn").arr();
        for a in &self.list.asns {
            let x = self.asn.get(a);
            j.obj().key("as").int(*a as i64).key("nets").int(x.map_or(0, |x| (x.v4.len() + x.v6.len()) as i64)).key("at").int(x.map_or(0, |x| x.at));
            if let Some(e) = x.map(|x| &x.err).filter(|e| !e.is_empty()) {
                j.key("err").str(e);
            }
            j.end_obj();
        }
        j.end_arr();
        if !self.err.is_empty() {
            j.key("err").str(&self.err);
        }
        j.end_obj();
    }

    /// Ответ окну списка: текст, разбор, ошибки.
    pub fn get_json(&mut self, file: &str) -> String {
        self.reload(file);
        let mut j = J::new();
        j.obj().key("text").str(&self.text);
        list_json(&mut j, &self.list);
        j.end_obj();
        j.b
    }
}

pub fn list_json(j: &mut J, l: &List) {
    j.key("domains").int(l.domains.len() as i64).key("nets4").int(l.net4.len() as i64).key("nets6").int(l.net6.len() as i64).key("asns").int(l.asns.len() as i64);
    j.key("bad").arr();
    for b in l.bad.iter().take(50) {
        j.str(b);
    }
    j.end_arr();
}

/// Имя или любой его родитель — в списке доменов.
fn name_in(set: &HashSet<&str>, name: &str) -> bool {
    let n = name.trim_end_matches('.');
    let lower;
    let n = if n.bytes().any(|c| c.is_ascii_uppercase()) {
        lower = n.to_ascii_lowercase();
        lower.as_str()
    } else {
        n
    };
    let mut s = n;
    loop {
        if set.contains(s) {
            return true;
        }
        match s.find('.') {
            Some(i) => s = &s[i + 1..],
            None => return false,
        }
    }
}

/// Каталог conf-dir запущенного dnsmasq с поддержкой nftset; None — нет такого.
fn dnsmasq_dir() -> Option<String> {
    let v = crate::flowwatch::output_timeout("dnsmasq", &["--version"], 3000)?;
    let opts = v.lines().find(|l| l.contains("options:")).unwrap_or("");
    if !opts.split_whitespace().any(|w| w == "nftset") {
        return None;
    }
    conf_dir()
}

/// Каталог conf-dir запущенного dnsmasq (из конфигов init-скрипта OpenWrt).
pub fn conf_dir() -> Option<String> {
    // конфиги, которые сгенерировал init-скрипт OpenWrt
    let mut dirs = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/var/etc") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if !n.starts_with("dnsmasq.conf") {
                continue;
            }
            for line in std::fs::read_to_string(e.path()).unwrap_or_default().lines() {
                if let Some(d) = line.trim().strip_prefix("conf-dir=") {
                    let d = d.split(',').next().unwrap_or("").trim().to_string();
                    if !d.is_empty() && !dirs.contains(&d) {
                        dirs.push(d);
                    }
                }
            }
        }
    }
    dirs.sort();
    dirs.into_iter().find(|d| std::path::Path::new(d).is_dir())
}

/// Текст файла dnsmasq: nftset (адреса — в наборы до ответа клиенту) и пустой AAAA.
pub fn dnsmasq_conf(doms: &[String], aaaa: bool) -> String {
    if doms.is_empty() {
        return String::new();
    }
    let mut s = String::from("# cgmon Per-Site Routing (dns_guard.persite) — generated, edit the list on the cgmon page\n");
    for ch in doms.chunks(20) {
        let d = ch.join("/");
        s.push_str(&format!("nftset=/{d}/4#inet#{TABLE}#dom4,6#inet#{TABLE}#dom6\n"));
        if aaaa {
            s.push_str(&format!("address=/{d}/::\n"));
        }
    }
    s
}

/// nft: таблица с наборами (dom4/dom6 не пересоздаются — их наполняет dnsmasq),
/// цепочки и наборы сетей — заново.
pub fn nft_script(v4: &[String], v6: &[String], gate: u32, doms: bool) -> String {
    let t = TABLE;
    let mut b = format!("add table inet {t}\n");
    b.push_str(&format!("add set inet {t} dom4 {{ type ipv4_addr; flags timeout; timeout 1h; }}\n"));
    b.push_str(&format!("add set inet {t} dom6 {{ type ipv6_addr; flags timeout; timeout 1h; }}\n"));
    b.push_str(&format!("add set inet {t} net4 {{ type ipv4_addr; flags interval; auto-merge; }}\n"));
    b.push_str(&format!("add set inet {t} net6 {{ type ipv6_addr; flags interval; auto-merge; }}\n"));
    b.push_str(&format!("add chain inet {t} steer {{ type filter hook prerouting priority mangle - 2; policy accept; }}\n"));
    b.push_str(&format!("add chain inet {t} v6 {{ type filter hook forward priority filter - 5; policy accept; }}\n"));
    b.push_str(&format!("flush chain inet {t} steer\nflush chain inet {t} v6\nflush set inet {t} net4\nflush set inet {t} net6\n"));
    for ch in v4.chunks(500) {
        b.push_str(&format!("add element inet {t} net4 {{ {} }}\n", ch.join(", ")));
    }
    for ch in v6.chunks(500) {
        b.push_str(&format!("add element inet {t} net6 {{ {} }}\n", ch.join(", ")));
    }
    if gate == 0 {
        return b; // гейта нет — ничего не уводим и не запрещаем
    }
    let m = format!("0x{gate:x}");
    let r = |s: &str| format!("add rule inet {t} {s}\n");
    if doms {
        b.push_str(&r(&format!("steer ct direction original ct state new ip daddr @dom4 meta l4proto {{ tcp, udp }} th dport {{ 80, 443 }} meta mark set {m} ct mark set {m}")));
    }
    if !v4.is_empty() {
        b.push_str(&r(&format!("steer ct direction original ct state new ip daddr @net4 meta l4proto {{ tcp, udp }} meta mark set {m} ct mark set {m}")));
    }
    // метку восстанавливаем только для направления клиент→сайт (ответ — в LAN, не в туннель)
    b.push_str(&r(&format!("steer ct direction original ct mark {m} meta mark set {m}")));
    // IPv6: гейты его не возят — отказ, клиент сразу переходит на IPv4
    if doms {
        b.push_str(&r("v6 ct state new ip6 daddr @dom6 tcp dport { 80, 443 } counter reject with tcp reset"));
        b.push_str(&r("v6 ct state new ip6 daddr @dom6 udp dport 443 counter reject with icmpv6 type admin-prohibited"));
    }
    if !v6.is_empty() {
        b.push_str(&r("v6 ct state new ip6 daddr @net6 meta l4proto tcp counter reject with tcp reset"));
        b.push_str(&r("v6 ct state new ip6 daddr @net6 meta l4proto udp counter reject with icmpv6 type admin-prohibited"));
    }
    b
}

/// Анонсированные префиксы AS из RIPEstat.
fn fetch_as(n: u32) -> Result<(Vec<String>, Vec<String>), String> {
    let url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{n}&sourceapp=cgmon");
    let (bin, kind) = crate::report::https_tool();
    // ответ 100+ КБ — больше буфера канала: только через файл (вывод в pipe заблокировал
    // бы curl до таймаута — output_timeout читает вывод после завершения процесса)
    let _ = std::fs::create_dir_all(crate::util::RUN_DIR);
    let tmp = format!("{}/persite_as{n}.json", crate::util::RUN_DIR);
    if kind.is_empty() {
        return Err(tr!("нет curl, uclient-fetch или wget").to_string());
    }
    // до 3 попыток: RIPEstat отвечает отказом на частые запросы
    let mut why = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(5 * attempt as u64));
        }
        let _ = std::fs::remove_file(&tmp);
        let code = match kind {
            "curl" => crate::flowwatch::output_timeout(bin, &["-s", "-m", "40", "-o", &tmp, "-w", "%{http_code}", &url], 45_000),
            _ => crate::flowwatch::output_timeout(bin, &["-q", "-T", "40", "-O", &tmp, &url], 45_000),
        }
        .unwrap_or_default();
        let body = std::fs::read_to_string(&tmp).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp);
        if !body.is_empty() && (code.is_empty() || code.starts_with('2')) {
            return parse_ripe(&body);
        }
        why = if code.is_empty() || code == "000" { tr!("RIPEstat не ответил").to_string() } else { format!("RIPEstat: HTTP {code}") };
    }
    Err(why)
}

pub fn parse_ripe(body: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let v = crate::value::parse_json(body).map_err(|_| tr!("RIPEstat: непонятный ответ").to_string())?;
    let Some(crate::value::Value::List(l)) = v.get("data").and_then(|d| d.get("prefixes")) else {
        return Err(tr!("RIPEstat: непонятный ответ").to_string());
    };
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for p in l {
        if let Some(s) = p.get("prefix").and_then(|x| x.as_str()).and_then(net_norm) {
            if s.contains(':') { v6.push(s) } else { v4.push(s) }
        }
        if v4.len() + v6.len() >= MAX_AS_NETS {
            break;
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    Ok((collapse(v4), collapse(v6)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list() {
        let l = parse("taobao.com; *.tmall.com\n# comment\n47.74.0.0/15 47.74.1.0/24, 1.2.3.4\n2401:b180::/32\nAS45102 as24429\nbad_thing\n0.0.0.0/0\nalicdn.com. # cdn\n");
        assert_eq!(l.domains, vec!["alicdn.com", "taobao.com", "tmall.com"]);
        assert_eq!(l.net4, vec!["1.2.3.4/32", "47.74.0.0/15"]);
        assert_eq!(l.net6, vec!["2401:b180::/32"]);
        assert_eq!(l.asns, vec![24429, 45102]);
        assert_eq!(l.bad, vec!["bad_thing", "0.0.0.0/0"]);
    }

    #[test]
    fn host_bits_cleared() {
        assert_eq!(net_norm("10.1.2.3/8").as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn suffix_match() {
        let s: HashSet<&str> = ["taobao.com"].into_iter().collect();
        assert!(name_in(&s, "g.Taobao.com."));
        assert!(name_in(&s, "taobao.com"));
        assert!(!name_in(&s, "nottaobao.com"));
    }

    #[test]
    fn dnsmasq_lines() {
        let c = dnsmasq_conf(&["a.com".into(), "b.org".into()], true);
        assert!(c.contains("nftset=/a.com/b.org/4#inet#cgmon_persite#dom4,6#inet#cgmon_persite#dom6\n"), "{c}");
        assert!(c.contains("address=/a.com/b.org/::\n"), "{c}");
        assert!(dnsmasq_conf(&[], true).is_empty());
    }

    #[test]
    fn nft_rules() {
        let s = nft_script(&["47.74.0.0/15".into()], &["2401:b180::/32".into()], 0x1000, true);
        assert!(s.contains("add element inet cgmon_persite net4 { 47.74.0.0/15 }"), "{s}");
        assert!(s.contains("ip daddr @net4 meta l4proto { tcp, udp } meta mark set 0x1000 ct mark set 0x1000"), "{s}");
        assert!(s.contains("ct direction original ct mark 0x1000 meta mark set 0x1000"), "{s}");
        assert!(s.contains("ip6 daddr @net6 meta l4proto tcp counter reject"), "{s}");
        assert!(!s.contains("delete table"), "dnsmasq fills dom4 — table must survive: {s}");
        let off = nft_script(&["47.74.0.0/15".into()], &[], 0, true);
        assert!(!off.contains("add rule"), "{off}");
    }

    #[test]
    fn ripe_answer() {
        let (v4, v6) = parse_ripe(r#"{"data":{"prefixes":[{"prefix":"47.74.0.0/15"},{"prefix":"47.74.0.0/16"},{"prefix":"2401:b180::/32"}]}}"#).unwrap();
        assert_eq!(v4, vec!["47.74.0.0/15"]);
        assert_eq!(v6, vec!["2401:b180::/32"]);
    }

    #[test]
    fn collapse_nested() {
        assert_eq!(collapse(vec!["10.0.0.0/8".into(), "10.1.0.0/16".into(), "11.0.0.0/8".into()]), vec!["10.0.0.0/8", "11.0.0.0/8"]);
    }
}
