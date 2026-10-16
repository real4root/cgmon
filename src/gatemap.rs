//! Карты шлюзов (2.4): кому из LAN каким выходом в интернет ходить.
//!
//! Карта — кто (интерфейс VLAN/моста, сеть, MAC, адрес) и куда: шлюзы по
//! порядку (WAN-каналы, туннели, свои роутеры в ZeroTier «@имя»); новые
//! IPv4-соединения идут через первый живой. Все мёртвы — по основному
//! маршруту или, с kill, без интернета. Так делаются и «два провайдера»
//! (lan → [INTERNET, mobile], tenants → [mobile, INTERNET]), и шлюз для одного
//! устройства (телевизор → [@node1, wan]).
//!
//! Своя таблица inet cgmon_gw: ct mark idx<<24 (биты 0x0f000000 — 0x100 у PBR
//! на роутерах, 0xf000 у обхода dgroute, 0xff0000 у tailscale) только новым
//! соединениям из LAN во внешний мир, и только если пакет ещё никто не пометил;
//! ip rule fwmark → таблица 2200+idx (default через шлюз), свой masquerade и MSS.
//! Без ip-full (штатный busybox ip: таблицы только до 255) — таблицы 230+idx.
//! Уже открытые соединения не переезжают. Живость шлюза — раз в 30 с TCP 443 к
//! 1.1.1.1/8.8.8.8 с меткой шлюза (в потоке), мёртв после 2 промахов подряд.

use crate::dgroute::{parse_labels, parse_routes, route_get_dev, Path};
use crate::json::J;
use crate::value::Value;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub const TABLE: &str = "cgmon_gw";
pub const MASK: u32 = 0x0f00_0000;
pub const RT_BASE: u32 = 2200;
/// busybox ip: номер таблицы ≤ 255 (231..245 — мимо 252–255 и tailscale 52)
pub const RT_BASE_LOW: u32 = 230;

/// Правила ip с приоритетом pref (busybox ip не фильтрует «rule show pref N» — сами).
fn rules_at(pref: u32) -> String {
    let all = std::process::Command::new("ip").args(["-4", "rule", "show"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    filter_pref(&all, pref)
}

fn filter_pref(all: &str, pref: u32) -> String {
    let p = format!("{pref}:");
    all.lines().filter(|l| l.trim_start().starts_with(&p)).map(|l| format!("{l}\n")).collect()
}

/// База таблиц под имеющийся ip.
pub fn rt_base() -> u32 {
    if crate::deps::IPFULL.load(std::sync::atomic::Ordering::Relaxed) { RT_BASE } else { RT_BASE_LOW }
}
pub const PREF: u32 = 86;
/// все шлюзы карты мертвы, kill — таблица с unreachable
const KILL_IDX: u32 = 15;
const MAX_MAPS: usize = 16;
const MAX_GATES: usize = 8;
const MAX_MATCH: usize = 32;
const HEALTH_EVERY: i64 = 30_000;
const FIND_EVERY: i64 = 60_000;
const DOWN_AFTER: u32 = 2;
/// локальное и служебное — мимо карт
const LOCAL4: &str = "10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3";

pub fn mark(idx: u32) -> u32 {
    idx << 24
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GateMap {
    pub name: String,
    /// dev:<интерфейс> | net:<сеть IPv4> | mac:<MAC> | ip:<адрес IPv4>
    pub matches: Vec<String>,
    /// по порядку: устройство (pppoe-wan, eth3, tailscale0) или ретранслятор «@имя»
    pub gates: Vec<String>,
    pub kill: bool,
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 32 && s.chars().all(|c| c.is_alphanumeric() || " -_.".contains(c))
}

fn mac_ok(s: &str) -> bool {
    let p: Vec<&str> = s.split(':').collect();
    p.len() == 6 && p.iter().all(|x| x.len() == 2 && x.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Проверка одного «кто» (то, что попадёт в nft, — только из безопасных символов).
pub fn match_ok(m: &str) -> bool {
    let Some((k, v)) = m.split_once(':') else { return false };
    match k {
        "dev" => crate::livecfg::path_id_ok(v),
        "mac" => mac_ok(v),
        "ip" => matches!(v.parse::<IpAddr>(), Ok(IpAddr::V4(_))),
        "net" => crate::netx::parse_nets(&[v.to_string()]).map_or(false, |n| n.len() == 1 && n[0].ip.is_ipv4() && n[0].bits >= 8),
        _ => false,
    }
}

fn gate_ok(g: &str) -> bool {
    match g.strip_prefix('@') {
        Some(n) => !n.is_empty() && n.len() <= 15 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        None => crate::livecfg::path_id_ok(g),
    }
}

/// Значение ключа gate_maps (список карт) с проверкой.
pub fn parse_maps(v: &Value) -> Result<Vec<GateMap>, String> {
    let Value::List(l) = v else { return Err("list of maps expected".into()) };
    if l.len() > MAX_MAPS {
        return Err(format!("at most {MAX_MAPS} maps"));
    }
    let strs = |x: Option<&Value>| -> Vec<String> {
        match x {
            Some(Value::List(a)) => a.iter().filter_map(|s| s.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
            _ => Vec::new(),
        }
    };
    let mut out = Vec::new();
    for m in l {
        let name = m.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if !name_ok(&name) {
            return Err(format!("map name «{name}»: letters, digits, space, - _ . (≤32)"));
        }
        let matches = strs(m.get("match"));
        let gates = strs(m.get("gates"));
        if matches.len() > MAX_MATCH || gates.len() > MAX_GATES {
            return Err(format!("{name}: too many entries"));
        }
        if let Some(b) = matches.iter().find(|x| !match_ok(x)) {
            return Err(format!("{name}: «{b}» — dev:/net:/mac:/ip:"));
        }
        if let Some(b) = gates.iter().find(|x| !gate_ok(x)) {
            return Err(format!("{name}: gate «{b}»"));
        }
        out.push(GateMap { name, matches, gates, kill: m.get("kill").and_then(|x| x.as_bool()).unwrap_or(false) });
    }
    Ok(out)
}

pub fn maps_json(maps: &[GateMap], j: &mut J) {
    j.arr();
    for m in maps {
        j.obj().key("name").str(&m.name).key("match").arr();
        for x in &m.matches {
            j.str(x);
        }
        j.end_arr().key("gates").arr();
        for g in &m.gates {
            j.str(g);
        }
        j.end_arr().key("kill").bool(m.kill).end_obj();
    }
    j.end_arr();
}

/// Пакет nft: кто → метка шлюза; masquerade и MSS для помеченных.
pub fn table_script(rules: &[(String, u32)], gates: &[(u32, String)]) -> String {
    let t = format!("inet {TABLE}");
    let mut b = format!("add table {t}\ndelete table {t}\ntable {t} {{\n");
    b.push_str("\tchain gw_pre {\n\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
    for (sel, idx) in rules {
        b.push_str(&format!(
            "\t\tct state new ct direction original ct mark & 0x{MASK:x} == 0 meta mark == 0 meta nfproto ipv4 {sel} ip daddr != {{ {LOCAL4} }} fib daddr type != local ct mark set ct mark | 0x{:x}\n",
            mark(*idx)
        ));
    }
    let mut idxs: Vec<u32> = rules.iter().map(|r| r.1).collect();
    idxs.sort();
    idxs.dedup();
    for idx in &idxs {
        b.push_str(&format!("\t\tct direction original ct mark & 0x{MASK:x} == 0x{:x} meta mark == 0 meta mark set 0x{:x}\n", mark(*idx), mark(*idx)));
    }
    b.push_str("\t}\n\tchain gw_mss {\n\t\ttype filter hook forward priority mangle; policy accept;\n");
    b.push_str(&format!("\t\tct mark & 0x{MASK:x} != 0 tcp flags syn tcp option maxseg size set rt mtu\n\t}}\n"));
    b.push_str("\tchain gw_nat {\n\t\ttype nat hook postrouting priority srcnat - 1; policy accept;\n");
    for (idx, dev) in gates {
        b.push_str(&format!("\t\tct mark & 0x{MASK:x} == 0x{:x} oifname \"{dev}\" masquerade\n", mark(*idx)));
    }
    b.push_str("\t}\n}\n");
    b
}

/// «кто» карты → выражение nft.
fn selector(m: &str) -> Option<String> {
    let (k, v) = m.split_once(':')?;
    Some(match k {
        "dev" => format!("iifname \"{v}\""),
        "net" => format!("ip saddr {v}"),
        "ip" => format!("ip saddr {v}"),
        "mac" => format!("ether saddr {}", v.to_lowercase()),
        _ => return None,
    })
}

#[derive(Clone, Debug, Default)]
pub struct Gate {
    pub id: String,
    pub dev: String,
    pub gw: String,
    pub label: String,
    pub idx: u32,
    pub alive: bool,
    pub checked: bool,
    pub fails: u32,
    pub ms: f64,
    pub primary: bool,
}

#[derive(Default)]
pub struct GateMaps {
    pub maps: Vec<GateMap>,
    gates: BTreeMap<String, Gate>,
    /// карта → действующий шлюз ("" — основной маршрут, "kill" — без интернета)
    active: Vec<String>,
    find_at: i64,
    health_at: i64,
    checking: bool,
    inbox: Arc<Mutex<Vec<(String, bool, f64)>>>,
    written: String,
    rules: Vec<(u32, u32)>,
    routes: Vec<(u32, String)>,
    /// база таблиц, под которую написаны routes
    base: u32,
    labels: HashMap<String, String>,
    pub err: String,
    /// остатки прошлого запуска (правила pref 86, таблицы 2201–2215, cgmon_gw) убраны
    cleaned: bool,
}

impl GateMaps {
    pub fn on(&self) -> bool {
        !self.maps.is_empty()
    }

    pub fn set_maps(&mut self, maps: Vec<GateMap>) {
        if maps != self.maps {
            self.maps = maps;
            self.find_at = 0;
        }
    }

    /// Такт: найти шлюзы, проверить живость, выбрать по картам, применить.
    pub fn tick(&mut self, now: i64, relays: &[String]) -> Vec<String> {
        let mut msgs = Vec::new();
        if !self.cleaned {
            // после перезапуска (или падения) — с чистого листа: свои правила, таблицы, nft
            self.cleaned = true;
            if !crate::util::readonly() {
                self.cleanup();
            }
        }
        if !self.on() {
            if !self.written.is_empty() || !self.rules.is_empty() {
                self.teardown();
            }
            return msgs;
        }
        if now - self.find_at >= FIND_EVERY {
            self.find_at = now;
            self.find(relays);
        }
        for (id, ok, ms) in std::mem::take(&mut *self.inbox.lock().unwrap_or_else(|e| e.into_inner())) {
            if let Some(g) = self.gates.get_mut(&id) {
                g.checked = true;
                if ok {
                    g.fails = 0;
                    g.ms = ms;
                    if !g.alive {
                        msgs.push(format!("Шлюз {}: работает ({} мс)", g.label_or_id(), ms.round()));
                    }
                    g.alive = true;
                } else {
                    g.fails += 1;
                    if g.alive && g.fails >= DOWN_AFTER {
                        g.alive = false;
                        msgs.push(format!("Шлюз {}: не отвечает", g.label_or_id()));
                    }
                }
            }
            self.checking = false;
        }
        // маршруты таблиц — до проверок: проба с меткой идёт через таблицу шлюза
        if let Err(e) = self.apply_routes() {
            self.err = e;
        }
        if !self.checking && now - self.health_at >= HEALTH_EVERY {
            self.health_at = now;
            self.check();
        }
        // выбор: первый живой шлюз карты
        let mut act = Vec::new();
        for m in &self.maps {
            let g = m.gates.iter().find(|g| self.gates.get(*g).map_or(false, |x| x.alive));
            act.push(match g {
                Some(g) => g.clone(),
                None if m.kill => "kill".into(),
                None => String::new(),
            });
        }
        for (i, (m, a)) in self.maps.iter().zip(act.iter()).enumerate() {
            let was = self.active.get(i).cloned();
            if was.as_deref() != Some(a.as_str()) && was.is_some() {
                let to = match a.as_str() {
                    "" => "основной маршрут (все шлюзы карты не отвечают)".to_string(),
                    "kill" => "без интернета (все шлюзы не отвечают, kill)".to_string(),
                    g => format!("через {}", self.gates.get(g).map(|x| x.label_or_id()).unwrap_or_else(|| g.to_string())),
                };
                msgs.push(format!("Карта шлюзов «{}»: {}", m.name, to));
            }
        }
        self.active = act;
        if let Err(e) = self.apply() {
            self.err = e;
        } else if self.err.starts_with("nft") {
            self.err.clear();
        }
        msgs
    }

    fn find(&mut self, relays: &[String]) {
        let q = |a: &[&str]| std::process::Command::new(a[0]).args(&a[1..]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        let mut found: BTreeMap<String, Path> = parse_routes(&q(&["ip", "-4", "route", "show", "table", "all"]));
        // свои таблицы карт — не шлюзы
        found.retain(|_, p| p.dev != "lo");
        for r in relays {
            let Some((name, ip)) = crate::livecfg::parse_relay(r) else { continue };
            let dev = route_get_dev(&q(&["ip", "-4", "route", "get", &ip]));
            if !dev.is_empty() {
                let id = format!("@{name}");
                found.insert(id.clone(), Path { id, dev, gw: ip, relay: true, ..Default::default() });
            }
        }
        self.labels = parse_labels(&q(&["ubus", "call", "network.interface", "dump"]));
        // индексы: стабильные, пока шлюз существует (метка открытых соединений)
        let used: Vec<u32> = self.gates.values().filter(|g| found.contains_key(&g.id)).map(|g| g.idx).collect();
        self.gates.retain(|id, _| found.contains_key(id));
        for (id, p) in found {
            let label = if p.relay { id.trim_start_matches('@').to_string() } else { self.labels.get(&id).cloned().unwrap_or_default() };
            match self.gates.get_mut(&id) {
                Some(g) => {
                    g.dev = p.dev;
                    g.gw = p.gw;
                    g.label = label;
                    g.primary = p.primary;
                }
                None => {
                    let Some(idx) = (1..KILL_IDX).find(|i| !used.contains(i) && !self.gates.values().any(|g| g.idx == *i)) else { continue };
                    self.gates.insert(id.clone(), Gate { id, dev: p.dev, gw: p.gw, label, idx, primary: p.primary, ..Default::default() });
                }
            }
        }
    }

    /// Проверка шлюзов карт: TCP 443 с меткой (через таблицу шлюза), в потоке.
    fn check(&mut self) {
        let want: Vec<(String, u32)> = self.gates.values().filter(|g| self.maps.iter().any(|m| m.gates.contains(&g.id))).map(|g| (g.id.clone(), mark(g.idx))).collect();
        if want.is_empty() {
            return;
        }
        self.checking = true;
        let inbox = self.inbox.clone();
        let spawned = std::thread::Builder::new().name("cgmon-gw".into()).stack_size(256 << 10).spawn(move || {
            let ips: Vec<IpAddr> = [[1, 1, 1, 1], [8, 8, 8, 8]].iter().map(|o| IpAddr::from(*o)).collect();
            for (id, m) in want {
                let (n, ms) = crate::dgsys::probe_many(&ips, 2, m, None, 3000);
                inbox.lock().unwrap_or_else(|e| e.into_inner()).push((id, n > 0, ms));
            }
        });
        if spawned.is_err() {
            self.checking = false;
        }
    }

    /// Таблицы маршрутов шлюзов (2200+idx) и правила fwmark → таблица.
    fn apply_routes(&mut self) -> Result<(), String> {
        if crate::util::readonly() {
            return Ok(());
        }
        let mut want: Vec<(u32, String)> = Vec::new();
        for g in self.gates.values().filter(|g| self.maps.iter().any(|m| m.gates.contains(&g.id))) {
            want.push((g.idx, if g.gw.is_empty() { format!("dev {}", g.dev) } else { format!("via {} dev {}", g.gw, g.dev) }));
        }
        if self.maps.iter().any(|m| m.kill) {
            want.push((KILL_IDX, "unreachable".into()));
        }
        want.sort();
        let base = rt_base();
        if base != self.base {
            // поставили/сняли ip-full: старые таблицы — очистить, всё заново
            for (_, t) in &self.rules {
                let _ = std::process::Command::new("ip").args(["-4", "route", "flush", "table", &t.to_string()]).output();
            }
            self.routes.clear();
            self.base = base;
        }
        if want == self.routes {
            return Ok(());
        }
        let run = |a: &[&str]| std::process::Command::new(a[0]).args(&a[1..]).output().map_err(|e| e.to_string()).and_then(|o| if o.status.success() { Ok(()) } else { Err(format!("{}: {}", a.join(" "), String::from_utf8_lossy(&o.stderr).trim())) });
        let mut errs = Vec::new();
        for (idx, r) in &want {
            let table = (base + idx).to_string();
            let mut a = vec!["ip", "-4", "route", "replace"];
            if r == "unreachable" {
                a.extend(["unreachable", "default"]);
            } else {
                a.push("default");
                a.extend(r.split_whitespace());
            }
            a.extend(["table", &table]);
            if let Err(e) = run(&a) {
                errs.push(e);
            }
        }
        // правила: ровно для нужных индексов
        let pref = PREF.to_string();
        let have = rules_at(PREF);
        let wanted: Vec<(String, String)> = want.iter().map(|(i, _)| (format!("0x{:x}/0x{MASK:x}", mark(*i)), (base + i).to_string())).collect();
        for ln in have.lines() {
            let f: Vec<&str> = ln.split_whitespace().collect();
            let pos = |k: &str| f.iter().position(|x| *x == k).and_then(|i| f.get(i + 1)).map(|s| s.to_string());
            let (Some(m), Some(t)) = (pos("fwmark"), pos("lookup")) else { continue };
            if !wanted.iter().any(|w| w.0 == m && w.1 == t) {
                let _ = run(&["ip", "-4", "rule", "del", "pref", &pref, "fwmark", &m, "lookup", &t]);
            }
        }
        for (m, t) in &wanted {
            if !have.contains(&format!("fwmark {m} lookup {t}")) {
                if let Err(e) = run(&["ip", "-4", "rule", "add", "pref", &pref, "fwmark", m, "lookup", t]) {
                    errs.push(e);
                }
            }
        }
        // таблицы ушедших шлюзов — очистить
        for (idx, _) in &self.routes {
            if !want.iter().any(|w| w.0 == *idx) {
                let _ = run(&["ip", "-4", "route", "flush", "table", &(base + idx).to_string()]);
            }
        }
        self.rules = want.iter().map(|(i, _)| (*i, base + i)).collect();
        if errs.is_empty() {
            self.routes = want;
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }

    /// Таблица nft по картам и выбранным шлюзам.
    fn apply(&mut self) -> Result<(), String> {
        let mut rules: Vec<(String, u32)> = Vec::new();
        let mut gates: Vec<(u32, String)> = Vec::new();
        for (m, a) in self.maps.iter().zip(self.active.iter()) {
            let idx = match a.as_str() {
                "" => continue, // основной маршрут — без метки
                "kill" => KILL_IDX,
                g => match self.gates.get(g) {
                    Some(x) => {
                        if !gates.iter().any(|y| y.0 == x.idx) {
                            gates.push((x.idx, x.dev.clone()));
                        }
                        x.idx
                    }
                    None => continue,
                },
            };
            for sel in m.matches.iter().filter_map(|x| selector(x)) {
                rules.push((sel, idx));
            }
        }
        let script = table_script(&rules, &gates);
        if script == self.written {
            return Ok(());
        }
        crate::acct::nft_script(&script).map_err(|e| format!("nft: {e}"))?;
        self.written = script;
        Ok(())
    }

    /// Всё своё по признакам, без памяти о прошлом запуске.
    fn cleanup(&mut self) {
        let _ = crate::acct::nft_script(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
        let pref = PREF.to_string();
        let have = rules_at(PREF);
        for ln in have.lines() {
            let f: Vec<&str> = ln.split_whitespace().collect();
            let pos = |k: &str| f.iter().position(|x| *x == k).and_then(|i| f.get(i + 1)).map(|s| s.to_string());
            if let (Some(m), Some(t)) = (pos("fwmark"), pos("lookup")) {
                let _ = std::process::Command::new("ip").args(["-4", "rule", "del", "pref", &pref, "fwmark", &m, "lookup", &t]).output();
            }
        }
        for idx in 1..=KILL_IDX {
            for b in [RT_BASE, RT_BASE_LOW] {
                let _ = std::process::Command::new("ip").args(["-4", "route", "flush", "table", &(b + idx).to_string()]).output();
            }
        }
    }

    fn teardown(&mut self) {
        let _ = crate::acct::nft_script(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
        let pref = PREF.to_string();
        for (idx, t) in &self.rules {
            let _ = std::process::Command::new("ip").args(["-4", "rule", "del", "pref", &pref, "fwmark", &format!("0x{:x}/0x{MASK:x}", mark(*idx)), "lookup", &t.to_string()]).output();
            let _ = std::process::Command::new("ip").args(["-4", "route", "flush", "table", &t.to_string()]).output();
        }
        self.rules.clear();
        self.routes.clear();
        self.written.clear();
        self.active.clear();
    }

    /// Статус для страницы: карты с действующим шлюзом и найденные шлюзы.
    pub fn status_json(&self, j: &mut J) {
        j.obj().key("maps").arr();
        for (i, m) in self.maps.iter().enumerate() {
            j.obj().key("name").str(&m.name).key("active").str(self.active.get(i).map(|s| s.as_str()).unwrap_or("")).end_obj();
        }
        j.end_arr().key("gates").arr();
        for g in self.gates.values() {
            j.obj().key("id").str(&g.id).key("dev").str(&g.dev).key("label").str(&g.label).key("alive").bool(g.alive).key("checked").bool(g.checked);
            if g.primary {
                j.key("primary").bool(true);
            }
            if g.ms > 0.0 {
                j.key("ms").int(g.ms.round() as i64);
            }
            // счётчики устройства — страница рисует график шлюза
            let rd = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{}/statistics/{f}", g.dev)).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            j.key("rx").uint(rd("rx_bytes")).key("tx").uint(rd("tx_bytes"));
            j.end_obj();
        }
        j.end_arr();
        if !self.err.is_empty() {
            j.key("error").str(&self.err);
        }
        j.end_obj();
    }
}

impl Gate {
    fn label_or_id(&self) -> String {
        if self.label.is_empty() || self.label == self.id {
            self.id.clone()
        } else {
            format!("{} ({})", self.label, self.id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::parse_json;

    #[test]
    fn maps_validate() {
        let v = parse_json(r#"[{"name":"tenants","match":["dev:vlan2","net:192.0.2.0/24","mac:aa:bb:cc:dd:ee:ff"],"gates":["eth3","pppoe-wan"],"kill":false},{"name":"tv","match":["ip:192.0.2.7"],"gates":["@node1"],"kill":true}]"#).unwrap();
        let m = parse_maps(&v).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[1].gates, vec!["@node1".to_string()]);
        for bad in [r#"[{"name":"x","match":["dev:a b"],"gates":[]}]"#, r#"[{"name":"x","match":["net:0.0.0.0/0"],"gates":[]}]"#, r#"[{"name":"x;","match":[],"gates":[]}]"#, r#"[{"name":"x","match":[],"gates":["a\"b"]}]"#] {
            assert!(parse_maps(&parse_json(bad).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn script_marks_new_lan_connections() {
        let s = table_script(&[("iifname \"vlan2\"".into(), 2)], &[(2, "eth3".into())]);
        assert!(s.contains("ct state new ct direction original ct mark & 0xf000000 == 0 meta mark == 0 meta nfproto ipv4 iifname \"vlan2\""), "{s}");
        assert!(s.contains("ct mark set ct mark | 0x2000000"));
        assert!(s.contains("ct mark & 0xf000000 == 0x2000000 oifname \"eth3\" masquerade"));
        assert!(s.contains("ip daddr != { 10.0.0.0/8"));
        assert_eq!(selector("mac:AA:BB:CC:DD:EE:FF").unwrap(), "ether saddr aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn busybox_rules_filter() {
        let all = "0:\tfrom all lookup local \n86:\tfrom all fwmark 0x1000000/0xf000000 lookup 231 \n860:\tfrom all lookup 5\n32766:\tfrom all lookup main\n";
        let f = filter_pref(all, 86);
        assert_eq!(f.lines().count(), 1);
        assert!(f.contains("fwmark 0x1000000/0xf000000 lookup 231"));
    }
}
