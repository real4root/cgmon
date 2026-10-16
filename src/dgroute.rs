//! Адресный обход (перенос dgroute.go; dns_guard.mode: targeted + alternatives).
//!
//! Плохая сеть владельца уходит по первой годной альтернативе: proto — другой
//! протокол через DNS (dgtarget.rs) или устройство (eth3, tailscale0, узел
//! «@имя») — новые IPv4-соединения к его сетям идут через этот путь. Путь жив —
//! сквозная проба через него раз в минуту (в потоке). Своя таблица
//! inet cgmon_route (fw4 не трогается): ct mark пути только НОВЫМ соединениям,
//! ip rule fwmark → таблица 2100+N, свой masquerade и MSS clamp; наборы pN_net
//! (сети /24 владельца) и pN_ip (SmartDNS nftset + адреса из DNSWatch).
//! Лимитированные пути (metered) считают байты, сверх суточного лимита — до полуночи.

use crate::dgsys::Alt;
use crate::dnsguard::{DnsGuard, Done, Feed};
use crate::json::J;
use crate::livecfg::{path_id_ok, DGR_MAX_PATHS, DGR_PROTO};
use crate::value::{parse_json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

pub const TABLE: &str = "cgmon_route";
pub const MASK: u32 = 0xf000;
pub const RT_BASE: u32 = 2100;
pub const PREF: u32 = 85;
pub const UID_PREF: u32 = 84;
pub const MAX_NETS: usize = 64;
const CHECK_EVERY: i64 = 60_000;
const DOWN_AFTER: i64 = 2; // проверок подряд без ответа — путь мёртв
const USAGE_SAVE: i64 = 10 * 60_000;
/// цели сквозной проверки пути (TCP 443)
const HEALTH_TARGETS: [[u8; 4]; 2] = [[1, 1, 1, 1], [8, 8, 8, 8]];

#[derive(Clone, Debug, Default)]
pub struct Path {
    /// устройство; ретранслятор — «@имя»
    pub id: String,
    /// устройство маршрута (у ретранслятора — до узла)
    pub dev: String,
    pub relay: bool,
    /// интерфейс netifd
    pub label: String,
    pub gw: String,
    /// через него основной маршрут — не обход
    pub primary: bool,
    /// метка idx<<12, таблица RT_BASE+idx
    pub idx: u32,
    pub up: bool,
    pub checked: bool,
    pub fails: i64,
    pub ms: f64,
    pub checking: bool,
}

#[derive(Clone, Debug)]
pub struct PathHealth {
    pub id: String,
    pub ok: bool,
    pub ms: f64,
}

/// Трафик путей за день (лимит).
#[derive(Clone, Debug, Default)]
pub struct Usage {
    pub day: String,
    pub bytes: BTreeMap<String, u64>,
}

impl Usage {
    pub fn json(&self, j: &mut J) {
        j.obj().key("day").str(&self.day);
        if !self.bytes.is_empty() {
            j.key("bytes").obj();
            for (k, v) in &self.bytes {
                j.key(k).uint(*v);
            }
            j.end_obj();
        }
        j.end_obj();
    }

    pub fn from(v: &Value) -> Usage {
        let mut u = Usage { day: crate::dnsguard::vstr(v, "day"), ..Default::default() };
        if let Some(Value::Map(m)) = v.get("bytes") {
            for (k, x) in m {
                if let Some(n) = x.as_f64() {
                    u.bytes.insert(k.clone(), n as u64);
                }
            }
        }
        u
    }
}

pub fn mark(idx: u32) -> u32 {
    idx << 12
}

/// Сеть /24 публичного IPv4-адреса.
pub fn net4(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) if crate::witness::public(&IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        _ => String::new(),
    }
}

pub fn nets_add(mut nets: Vec<String>, ips: &[String]) -> Vec<String> {
    for ip in ips {
        let n = if ip.ends_with("/24") { ip.clone() } else { net4(ip) };
        if !n.is_empty() && !nets.contains(&n) && nets.len() < MAX_NETS {
            nets.push(n);
        }
    }
    nets.sort();
    nets
}

/// Маршруты по умолчанию из «ip -4 route show table all»: устройство, шлюз, основной.
pub fn parse_routes(out: &str) -> BTreeMap<String, Path> {
    let mut m: BTreeMap<String, Path> = BTreeMap::new();
    let (mut best, mut best_metric) = (String::new(), -1i64);
    for ln in out.lines() {
        let f: Vec<&str> = ln.split_whitespace().collect();
        if f.len() < 3 || f[0] != "default" || ln.contains("linkdown") {
            continue;
        }
        let (mut dev, mut gw, mut table, mut metric) = ("", "", "main", 0i64);
        for i in 1..f.len() - 1 {
            match f[i] {
                "dev" => dev = f[i + 1],
                "via" => gw = f[i + 1],
                "table" => table = f[i + 1],
                "metric" => metric = f[i + 1].parse().unwrap_or(0),
                _ => {}
            }
        }
        if let Ok(n) = table.parse::<u32>() {
            if n > RT_BASE && n <= RT_BASE + DGR_MAX_PATHS as u32 {
                continue; // свои таблицы
            }
        }
        if table == "local" || !path_id_ok(dev) || (!gw.is_empty() && !matches!(gw.parse::<IpAddr>(), Ok(IpAddr::V4(_)))) {
            continue;
        }
        let replace = match m.get(dev) {
            None => true,
            Some(p) => table == "main" && p.gw.is_empty(),
        };
        if replace {
            m.insert(dev.into(), Path { id: dev.into(), dev: dev.into(), gw: gw.into(), ..Default::default() });
        }
        if table == "main" && (best_metric < 0 || metric < best_metric) {
            best = dev.into();
            best_metric = metric;
        }
    }
    if let Some(p) = m.get_mut(&best) {
        p.primary = true;
    }
    m
}

/// Устройство до узла из «ip -4 route get», если он в соседней сети (без via).
pub fn route_get_dev(out: &str) -> String {
    let f: Vec<&str> = out.lines().next().unwrap_or("").split_whitespace().collect();
    let mut dev = "";
    for i in 0..f.len().saturating_sub(1) {
        match f[i] {
            "via" => return String::new(),
            "dev" => dev = f[i + 1],
            _ => {}
        }
    }
    if !path_id_ok(dev) || dev == "lo" {
        return String::new();
    }
    dev.into()
}

/// Устройство → интерфейс netifd (ubus network.interface dump), без «_6», если есть другой.
pub fn parse_labels(out: &str) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::new();
    let Ok(v) = parse_json(out) else { return m };
    if let Some(Value::List(l)) = v.get("interface") {
        for i in l {
            let (n, d) = (crate::dnsguard::vstr(i, "interface"), crate::dnsguard::vstr(i, "l3_device"));
            if !d.is_empty() && m.get(&d).map_or(true, |x| x.is_empty() || x.ends_with("_6")) {
                m.insert(d, n);
            }
        }
    }
    m
}

/// Таблица inet cgmon_route целиком (без delete table: pN_ip наполняет SmartDNS).
pub fn table_script(act: &[&Path], relay_mbit: i64) -> String {
    let t = format!("inet {TABLE}");
    let mut b = format!("add table {t}\n");
    for p in act {
        b.push_str(&format!("add set {t} p{}_net {{ type ipv4_addr; flags interval; }}\n", p.idx));
        b.push_str(&format!("add set {t} p{}_ip {{ type ipv4_addr; flags timeout; timeout 1h; size 65535; }}\n", p.idx));
        b.push_str(&format!("add counter {t} p{}\n", p.idx));
    }
    for c in [
        "rt_pre { type filter hook prerouting priority mangle - 2; policy accept; }",
        "rt_mss { type filter hook forward priority mangle; policy accept; }",
        "rt_nat { type nat hook postrouting priority srcnat - 2; policy accept; }",
        "rt_lim { type filter hook forward priority filter - 2; policy accept; }",
    ] {
        let name = c.split_whitespace().next().unwrap();
        b.push_str(&format!("add chain {t} {c}\nflush chain {t} {name}\n"));
    }
    b.push_str(&format!("table {t} {{\n\tchain rt_pre {{\n"));
    for p in act {
        let m = mark(p.idx);
        for s in ["net", "ip"] {
            b.push_str(&format!("\t\tct state new ct direction original ct mark & 0x{MASK:x} == 0 ip daddr @p{}_{s} ct mark set ct mark & 0x{:x} | 0x{m:x}\n", p.idx, !MASK));
        }
        b.push_str(&format!("\t\tct mark & 0x{MASK:x} == 0x{m:x} counter name \"p{}\"\n", p.idx));
    }
    b.push_str(&format!("\t\tct direction original ct mark & 0x{MASK:x} != 0 meta mark set ct mark & 0x{MASK:x}\n\t}}\n"));
    b.push_str(&format!("\tchain rt_mss {{\n\t\tct mark & 0x{MASK:x} != 0 tcp flags syn tcp option maxseg size set rt mtu\n\t}}\n"));
    b.push_str("\tchain rt_nat {\n");
    for p in act {
        b.push_str(&format!("\t\tct mark & 0x{MASK:x} == 0x{:x} oifname \"{}\" masquerade\n", mark(p.idx), p.dev));
    }
    b.push_str("\t}\n");
    // ретрансляторы — чужой канал: скорость ограничена в каждую сторону
    b.push_str("\tchain rt_lim {\n");
    if relay_mbit > 0 {
        let kb = relay_mbit * 1000 / 8;
        for p in act.iter().filter(|p| p.relay) {
            for dir in ["original", "reply"] {
                b.push_str(&format!("\t\tct mark & 0x{MASK:x} == 0x{:x} ct direction {dir} limit rate over {kb} kbytes/second burst {} kbytes drop\n", mark(p.idx), kb / 2 + 64));
            }
        }
    }
    b.push_str("\t}\n}\n");
    b
}

/// Ключи ip rule (значение после `key`, `lookup`) из вывода «ip rule show pref N».
fn rule_keys(out: &str, key: &str) -> Vec<(String, String)> {
    let mut l = Vec::new();
    for ln in out.lines() {
        let f: Vec<&str> = ln.split_whitespace().collect();
        let (mut a, mut t) = ("", "");
        for i in 0..f.len().saturating_sub(1) {
            if f[i] == key {
                a = f[i + 1];
            } else if f[i] == "lookup" {
                t = f[i + 1];
            }
        }
        if !a.is_empty() && !t.is_empty() {
            l.push((a.to_string(), t.to_string()));
        }
    }
    l
}

impl DnsGuard {
    /// В настройках есть хотя бы один путь обхода.
    pub fn route_on(&self) -> bool {
        self.cfg.mode == "targeted" && self.cfg.alternatives.iter().any(|a| a != DGR_PROTO)
    }

    fn alt_used(&self, id: &str) -> bool {
        self.cfg.alternatives.iter().any(|a| a == id)
    }

    pub fn path_label(&self, id: &str) -> String {
        match self.r_paths.get(id) {
            Some(p) if p.relay => format!("узел {} ({})", p.label, p.dev),
            Some(p) if !p.label.is_empty() && p.label != id => format!("{} ({id})", p.label),
            _ => id.to_string(),
        }
    }

    fn over_limit(&self, id: &str) -> bool {
        if !self.cfg.metered.iter().any(|m| m == id) || self.cfg.metered_day_mb <= 0 {
            return false;
        }
        self.r_usage.bytes.get(id).copied().unwrap_or(0) >= (self.cfg.metered_day_mb as u64) << 20
    }

    /// Через путь сейчас можно уводить.
    pub fn path_usable(&self, id: &str) -> bool {
        self.r_paths.get(id).map_or(false, |p| p.idx > 0 && !p.primary && p.up) && !self.r_table.is_empty() && self.alt_used(id) && !self.over_limit(id)
    }

    /// Путь есть и в работе, но после старта ещё не проверен.
    pub fn path_unchecked(&self, id: &str) -> bool {
        self.r_paths.get(id).map_or(false, |p| p.idx > 0 && !p.primary && !p.checked) && !self.over_limit(id)
    }

    /// Почему путь сейчас не годится.
    pub fn path_why(&self, id: &str) -> String {
        match self.r_paths.get(id) {
            None => "нет маршрута",
            Some(p) if p.primary => "сейчас основной",
            Some(_) if self.over_limit(id) => "лимит на сегодня исчерпан",
            Some(p) if !p.checked => "ещё не проверен",
            Some(p) if !p.up => "путь не работает",
            _ => "не настроен",
        }
        .into()
    }

    /// Альтернативы для владельца в порядке настроек.
    pub fn route_alts(&self, fam: &str) -> Vec<Alt> {
        let mut l = Vec::new();
        for a in &self.cfg.alternatives {
            if a == DGR_PROTO {
                l.push(Alt { id: DGR_PROTO.into(), up: true, ..Default::default() });
                continue;
            }
            if fam != "ipv4" {
                continue; // обход IPv6 — позже
            }
            let mut x = Alt { id: a.clone(), label: self.path_label(a), ..Default::default() };
            match self.r_paths.get(a) {
                Some(p) if self.path_usable(a) => {
                    x.up = true;
                    x.mark = mark(p.idx);
                    x.dev = p.dev.clone();
                    x.relay = p.relay;
                    x.idx = p.idx;
                }
                _ => x.why = self.path_why(a),
            }
            l.push(x);
        }
        l
    }

    /// Итоги проверок путей, раз в минуту поиск путей, таблица, учёт, проверки; наборы адресов.
    pub fn route_tick(&mut self, now: i64, feed: &mut dyn Feed) -> Vec<String> {
        let mut msgs = self.route_health_all(now);
        if now - self.r_at >= CHECK_EVERY {
            self.r_at = now;
            msgs.extend(self.route_find(now));
            if self.route_on() {
                msgs.extend(self.route_discover());
                msgs.extend(self.route_usage(now));
                self.route_check_paths();
                msgs.extend(self.route_health_all(now)); // проверки сразу (тесты)
            }
        }
        if !self.route_on() {
            self.route_teardown();
            return msgs;
        }
        self.route_sync_nets();
        self.route_sync_ips(now, feed);
        msgs
    }

    fn route_health_all(&mut self, now: i64) -> Vec<String> {
        let mut msgs = Vec::new();
        for h in std::mem::take(&mut self.r_health) {
            msgs.extend(self.route_health(now, h));
        }
        msgs
    }

    /// Пути из таблиц маршрутов и их имена netifd.
    fn route_find(&mut self, now: i64) -> Vec<String> {
        let mut msgs = Vec::new();
        let mut found = parse_routes(&self.sys.query(&["ip", "-4", "route", "show", "table", "all"]).unwrap_or_default());
        for r in &self.cfg.relays {
            let Some((name, ip)) = crate::livecfg::parse_relay(r) else { continue };
            // узел должен быть в соседней сети (ZeroTier, LAN) — не через шлюз
            let dev = route_get_dev(&self.sys.query(&["ip", "-4", "route", "get", &ip]).unwrap_or_default());
            if !dev.is_empty() && !found.contains_key(&dev) {
                let id = format!("@{name}");
                found.insert(id.clone(), Path { id, dev, gw: ip, relay: true, ..Default::default() });
            }
        }
        if now - self.r_label_at >= 5 * CHECK_EVERY || self.r_label_map.is_none() {
            self.r_label_at = now;
            self.r_label_map = Some(parse_labels(&self.sys.query(&["ubus", "call", "network.interface", "dump"]).unwrap_or_default()));
        }
        let on = self.route_on();
        for (id, mut p) in found.clone() {
            let lbl = if p.relay { id.trim_start_matches('@').to_string() } else { self.r_label_map.as_ref().and_then(|m| m.get(&id).cloned()).unwrap_or_default() };
            let Some(old) = self.r_paths.get_mut(&id) else {
                p.label = lbl;
                self.r_paths.insert(id, p);
                continue;
            };
            old.gw = p.gw;
            old.dev = p.dev;
            old.relay = p.relay;
            old.label = lbl;
            let became = !old.primary && p.primary;
            old.primary = p.primary;
            if became && on && self.alt_used(&id) {
                self.route_lost(now, &id);
                msgs.push(format!("Обход: {} стал основным каналом — для обхода не используется", self.path_label(&id)));
            }
        }
        let gone: Vec<String> = self.r_paths.keys().filter(|id| !found.contains_key(*id)).cloned().collect();
        for id in gone {
            if self.r_paths[&id].up && on && self.alt_used(&id) {
                self.route_lost(now, &id);
                msgs.push(format!("Обход: путь {} пропал (нет маршрута) — его сети перепроверяются", self.path_label(&id)));
            }
            self.r_paths.remove(&id);
        }
        msgs
    }

    /// Номера путей (стабильны, пока путь в настройках), таблица nft, ip rule/route.
    fn route_discover(&mut self) -> Vec<String> {
        let keep: Vec<String> = self.r_idx.keys().filter(|id| self.alt_used(id) && self.r_paths.contains_key(*id)).cloned().collect();
        self.r_idx.retain(|id, _| keep.contains(id));
        for id in self.cfg.alternatives.clone() {
            if id == DGR_PROTO || !self.r_paths.contains_key(&id) || self.r_idx.contains_key(&id) {
                continue;
            }
            if let Some(n) = (1..=DGR_MAX_PATHS as u32).find(|n| !self.r_idx.values().any(|v| v == n)) {
                self.r_idx.insert(id, n);
            }
        }
        for (id, p) in self.r_paths.iter_mut() {
            p.idx = self.r_idx.get(id).copied().unwrap_or(0);
        }
        match self.route_setup() {
            Err(e) => {
                let mut msgs = Vec::new();
                if self.r_err != e {
                    msgs.push(format!("Обход: не удалось настроить маршруты: {e}"));
                }
                self.r_err = e;
                msgs
            }
            Ok(()) => {
                self.r_err.clear();
                Vec::new()
            }
        }
    }

    /// Пути с номерами по возрастанию.
    pub fn route_active(&self) -> Vec<&Path> {
        let mut l: Vec<&Path> = self.r_paths.values().filter(|p| p.idx > 0).collect();
        l.sort_by_key(|p| p.idx);
        l
    }

    /// Таблица nft (при смене путей), правила и маршруты.
    fn route_setup(&mut self) -> Result<(), String> {
        let act: Vec<Path> = self.route_active().into_iter().cloned().collect();
        let refs: Vec<&Path> = act.iter().collect();
        let desc = act.iter().map(|p| format!("{}:{}:{}", p.idx, p.id, p.dev)).collect::<Vec<_>>().join(",") + &format!("|{}", self.cfg.relay_mbit);
        if desc != self.r_table {
            if let Err(e) = self.sys.nft(&table_script(&refs, self.cfg.relay_mbit)) {
                self.r_table.clear();
                return Err(e);
            }
            self.r_table = desc;
            self.r_nets.clear();
        }
        self.route_uid_rules(&refs);
        // правила: свои (pref 85) — ровно для действующих путей
        let mut want: Vec<(String, String)> = act.iter().map(|p| (format!("0x{:x}/0x{MASK:x}", mark(p.idx)), (RT_BASE + p.idx).to_string())).collect();
        let pref = PREF.to_string();
        for (m, t) in rule_keys(&self.sys.query(&["ip", "-4", "rule", "show", "pref", &pref]).unwrap_or_default(), "fwmark") {
            if let Some(i) = want.iter().position(|w| w.0 == m && w.1 == t) {
                want.remove(i);
            } else {
                let _ = self.sys.run(&["ip", "-4", "rule", "del", "pref", &pref, "fwmark", &m, "lookup", &t]);
            }
        }
        let mut errs = Vec::new();
        for (m, t) in want {
            if let Err(e) = self.sys.run(&["ip", "-4", "rule", "add", "pref", &pref, "fwmark", &m, "lookup", &t]) {
                errs.push(e);
            }
        }
        for p in &act {
            let table = (RT_BASE + p.idx).to_string();
            let mut a = vec!["ip", "-4", "route", "replace", "default"];
            if !p.gw.is_empty() {
                a.extend(["via", &p.gw]);
            }
            a.extend(["dev", &p.dev, "table", &table]);
            if let Err(e) = self.sys.run(&a) {
                errs.push(e);
            }
        }
        if !errs.is_empty() {
            return Err(errs.join("; "));
        }
        Ok(())
    }

    /// ip rule uidrange для проверки загрузкой через ретрансляторы (пусто — убрать свои).
    fn route_uid_rules(&self, act: &[&Path]) {
        let mut want: Vec<(String, String)> = act.iter().filter(|p| p.relay).map(|p| {
            let u = crate::dgsys::UID_BASE + p.idx;
            (format!("{u}-{u}"), (RT_BASE + p.idx).to_string())
        }).collect();
        let pref = UID_PREF.to_string();
        for (u, t) in rule_keys(&self.sys.query(&["ip", "-4", "rule", "show", "pref", &pref]).unwrap_or_default(), "uidrange") {
            if let Some(i) = want.iter().position(|w| w.0 == u && w.1 == t) {
                want.remove(i);
            } else {
                let _ = self.sys.run(&["ip", "-4", "rule", "del", "pref", &pref, "uidrange", &u, "lookup", &t]);
            }
        }
        for (u, t) in want {
            let _ = self.sys.run(&["ip", "-4", "rule", "add", "pref", &pref, "uidrange", &u, "lookup", &t]);
        }
    }

    /// Обход выключен: убрать таблицу, правила, маршруты. Без своей таблицы в
    /// этом процессе — один раз проверить остатки (cgmon упал).
    pub fn route_teardown(&mut self) {
        if self.r_table.is_empty() && self.r_cleaned {
            return;
        }
        self.r_cleaned = true;
        self.route_uid_rules(&[]);
        let pref = PREF.to_string();
        let rules = self.sys.query(&["ip", "-4", "rule", "show", "pref", &pref]).unwrap_or_default();
        let exists = !self.r_table.is_empty() || self.sys.query(&[crate::acct::nft_bin(), "list", "tables"]).map_or(false, |o| o.contains(&format!(" {TABLE}")));
        if exists {
            let _ = self.sys.nft(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
        }
        if !rules.trim().is_empty() || !self.r_table.is_empty() {
            for _ in rules.lines().filter(|l| !l.trim().is_empty()) {
                let _ = self.sys.run(&["ip", "-4", "rule", "del", "pref", &pref]);
            }
            for n in 1..=DGR_MAX_PATHS as u32 {
                let _ = self.sys.run(&["ip", "-4", "route", "flush", "table", &(RT_BASE + n).to_string()]);
            }
        }
        self.r_table.clear();
        self.r_nets.clear();
        self.r_last = None;
        for p in self.r_paths.values_mut() {
            p.idx = 0;
            p.up = false;
            p.checked = false;
            p.fails = 0;
        }
        self.r_idx.clear();
    }

    /// Путь из настроек ещё ни разу не проверен: решать по владельцам рано.
    pub fn route_pending(&self) -> bool {
        self.route_active().iter().any(|p| !p.primary && !p.checked && !self.over_limit(&p.id))
    }

    /// Сквозная проверка путей из настроек (в потоках).
    fn route_check_paths(&mut self) {
        if self.r_table.is_empty() {
            return;
        }
        let ids: Vec<(String, u32)> = self.route_active().iter().filter(|p| !p.primary && !p.checking && !self.over_limit(&p.id)).map(|p| (p.id.clone(), mark(p.idx))).collect();
        for (id, m) in ids {
            self.r_paths.get_mut(&id).unwrap().checking = true;
            self.spawn(move |sys| {
                let targets: Vec<IpAddr> = HEALTH_TARGETS.iter().map(|a| IpAddr::from(*a)).collect();
                let (ok, ms) = sys.probe(&targets, targets.len(), m, None);
                Done::Health(PathHealth { id, ok: ok > 0, ms })
            });
        }
    }

    /// Итог проверки пути: переходы жив/мёртв.
    fn route_health(&mut self, now: i64, h: PathHealth) -> Vec<String> {
        let Some(p) = self.r_paths.get_mut(&h.id) else { return Vec::new() };
        p.checking = false;
        let was = p.up;
        if h.ok {
            p.fails = 0;
            p.up = true;
            p.ms = h.ms;
        } else {
            p.fails += 1;
            if p.fails >= DOWN_AFTER || !p.checked {
                p.up = false;
            }
        }
        let first = !p.checked;
        p.checked = true;
        let up = p.up;
        if was && !up {
            self.route_lost(now, &h.id);
            return vec![format!("Обход: путь {} не работает (проверка через него без ответа) — его сети перепроверяются", self.path_label(&h.id))];
        }
        if !was && up && !first {
            return vec![format!("Обход: путь {} снова работает ({:.0} мс)", self.path_label(&h.id), h.ms)];
        }
        Vec::new()
    }

    /// Путь больше не годится: его владельцы перепроверяются сразу.
    fn route_lost(&mut self, now: i64, id: &str) {
        for t in self.targets.values_mut() {
            if t.active && t.via == id {
                t.until = now;
            }
        }
        self.t_urgent = true; // убрать nftset из файла SmartDNS
    }

    /// Счётчики nft → байты за день по путям; лимит лимитированных.
    fn route_usage(&mut self, now: i64) -> Vec<String> {
        let t = crate::util::local(now.div_euclid(1000));
        let day = format!("{:04}-{:02}-{:02}", t.year, t.mon, t.day);
        if self.r_usage.day != day {
            self.r_usage = Usage { day, ..Default::default() };
            self.r_usage_saved = 0;
        }
        if self.r_table.is_empty() {
            return Vec::new();
        }
        let cur = self.sys.counters(TABLE);
        let mut last = self.r_last.take().unwrap_or_default();
        let mut msgs = Vec::new();
        let act: Vec<(String, u32)> = self.route_active().iter().map(|p| (p.id.clone(), p.idx)).collect();
        for (id, idx) in act {
            let name = format!("p{idx}");
            let Some(&v) = cur.get(&name) else { continue };
            let Some(prev) = last.insert(format!("{name}/{id}"), v) else { continue }; // первое чтение после создания таблицы
            let d = if v < prev { v } else { v - prev };
            if d == 0 {
                continue;
            }
            let over = self.over_limit(&id);
            *self.r_usage.bytes.entry(id.clone()).or_insert(0) += d;
            if !over && self.over_limit(&id) {
                self.route_lost(now, &id);
                self.persist();
                msgs.push(format!("Обход: {} — лимит трафика на сегодня исчерпан ({} МБ), путь не используется до полуночи", self.path_label(&id), self.cfg.metered_day_mb));
            }
        }
        self.r_last = Some(last);
        if now - self.r_usage_saved >= USAGE_SAVE {
            self.r_usage_saved = now;
            self.persist();
        }
        msgs
    }

    /// Наборы pN_net по действующим обходам; у негодных путей наборы пустые.
    pub fn route_sync_nets(&mut self) {
        if self.r_table.is_empty() {
            return;
        }
        let mut b = String::new();
        for p in self.route_active() {
            b.push_str(&format!("flush set inet {TABLE} p{}_net\n", p.idx));
            if !self.path_usable(&p.id) {
                // адреса от SmartDNS — только если путь правда негоден (не просто не проверен после старта)
                if p.checked || p.primary || self.over_limit(&p.id) {
                    b.push_str(&format!("flush set inet {TABLE} p{}_ip\n", p.idx));
                }
                continue;
            }
            let mut nets: Vec<&String> = Vec::new();
            for t in self.targets.values().filter(|t| t.active && t.via == p.id) {
                for n in &t.nets {
                    if !nets.contains(&n) {
                        nets.push(n);
                    }
                }
            }
            nets.sort();
            if !nets.is_empty() {
                b.push_str(&format!("add element inet {TABLE} p{}_net {{ {} }}\n", p.idx, nets.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
            }
        }
        if b == self.r_nets {
            return;
        }
        if let Err(e) = self.sys.nft(&b) {
            crate::log_err!("route guard: {}", e);
            return;
        }
        self.r_nets = b;
    }

    /// Путь для сайтов проверки: выбранный в check_via или первый рабочий (None — напрямую).
    pub fn check_path(&self) -> Option<&Path> {
        let v = &self.cfg.check_via;
        if !self.route_on() || self.cfg.check_domains.is_empty() || v == "direct" || v == DGR_PROTO {
            return None;
        }
        if !v.is_empty() {
            return if self.path_usable(v) { self.r_paths.get(v) } else { None };
        }
        self.cfg.alternatives.iter().find(|a| *a != DGR_PROTO && self.path_usable(a)).and_then(|a| self.r_paths.get(a))
    }

    /// Домены обхода и проверочных сайтов по индексам путей.
    fn route_want(&self) -> BTreeMap<u32, Vec<String>> {
        let mut want: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        if self.r_table.is_empty() {
            return want;
        }
        for t in self.targets.values().filter(|t| t.active && t.via_path() && self.path_usable(&t.via)) {
            want.entry(self.r_paths[&t.via].idx).or_default().extend(t.domains.iter().map(|d| d.to_lowercase()));
        }
        if let Some(p) = self.check_path() {
            want.entry(p.idx).or_default().extend(self.cfg.check_domains.iter().map(|d| d.to_lowercase()));
        }
        want
    }

    /// Адреса (из DNS-ответов клиентам) доменов обхода — в pN_ip: новые и не
    /// обновлявшиеся 30 мин (таймаут элемента 1 ч). Без SmartDNS: адреса берёт
    /// DNSWatch, кто бы ни отвечал клиентам (dnsmasq, AdGuard, SmartDNS).
    fn route_add_ips<'a>(&mut self, now: i64, want: &BTreeMap<u32, Vec<String>>, pairs: impl Iterator<Item = (&'a IpAddr, &'a str)>) {
        let mut add: BTreeMap<u32, Vec<std::net::Ipv4Addr>> = BTreeMap::new();
        for (ip, name) in pairs {
            let IpAddr::V4(v4) = ip else { continue };
            if !crate::witness::public(ip) {
                continue;
            }
            let n = name.trim_end_matches('.').to_lowercase();
            for (idx, doms) in want {
                if doms.iter().any(|d| n == *d || n.ends_with(&format!(".{d}"))) {
                    let k = format!("{idx} {ip}");
                    if self.r_ips.get(&k).map_or(true, |at| now - at >= 30 * 60_000) {
                        self.r_ips.insert(k, now);
                        add.entry(*idx).or_default().push(*v4);
                    }
                }
            }
        }
        for (idx, mut ips) in add {
            ips.sort();
            ips.dedup();
            if let Err(e) = self.sys.set_add4(TABLE, &format!("p{idx}_ip"), &ips, 3600) {
                crate::log_err!("route guard: {}", e);
            }
        }
    }

    /// Новый DNS-ответ клиенту (сразу, не дожидаясь такта): адрес домена
    /// обхода должен попасть в набор раньше первого SYN клиента. Не успел —
    /// одно первое соединение уйдёт напрямую, следующие — через путь.
    pub fn route_fresh(&mut self, now: i64, pairs: &[(IpAddr, std::rc::Rc<str>)]) {
        if self.r_table.is_empty() || pairs.is_empty() {
            return;
        }
        let want = self.route_want();
        if want.is_empty() {
            return;
        }
        self.route_add_ips(now, &want, pairs.iter().map(|(ip, n)| (ip, &**n)));
    }

    /// Раз в 10 с: все адреса, что DNSWatch помнит (пропущенное мгновенным путём,
    /// продление таймаута раз в 30 мин, новые штрафы с уже известными адресами).
    fn route_sync_ips(&mut self, now: i64, feed: &mut dyn Feed) {
        if self.r_table.is_empty() || now - self.r_ips_at < 10_000 {
            return;
        }
        self.r_ips_at = now;
        let want = self.route_want();
        if want.is_empty() {
            return;
        }
        let mut pairs: Vec<(IpAddr, String)> = Vec::new();
        feed.each_pair(&mut |ip, name| pairs.push((*ip, name.to_string())));
        self.route_add_ips(now, &want, pairs.iter().map(|(ip, n)| (ip, n.as_str())));
        self.r_ips.retain(|_, at| now - *at < 60 * 60_000);
    }

    /// Пути для страницы: сначала в порядке настроек, потом остальные.
    pub fn paths_json(&self, j: &mut J) {
        let mut ids: Vec<String> = Vec::new();
        for id in &self.cfg.alternatives {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        if !ids.iter().any(|x| x == DGR_PROTO) {
            ids.push(DGR_PROTO.into());
        }
        let rest: Vec<String> = self.r_paths.keys().filter(|id| !ids.contains(id)).cloned().collect();
        ids.extend(rest);
        j.key("paths").arr();
        for id in &ids {
            let metered = self.cfg.metered.iter().any(|m| m == id);
            j.obj().key("id").str(id);
            let (mut up, mut checked) = (false, false);
            if id == DGR_PROTO {
                up = true;
                checked = true;
            } else if let Some(p) = self.r_paths.get(id) {
                if !p.label.is_empty() {
                    j.key("label").str(&p.label);
                }
                if p.primary {
                    j.key("primary").bool(true);
                }
                up = p.up;
                checked = p.checked;
            }
            j.key("use").bool(self.alt_used(id)).key("up").bool(up).key("checked").bool(checked);
            if let Some(p) = self.r_paths.get(id).filter(|p| p.ms != 0.0) {
                j.key("ms").raw(&crate::config::go_float(p.ms));
            }
            if metered {
                j.key("metered").bool(true);
                let used = self.r_usage.bytes.get(id).copied().unwrap_or(0) as f64 / (1u64 << 20) as f64;
                if used != 0.0 {
                    j.key("used_mb").raw(&crate::config::go_float(used));
                }
                if self.cfg.metered_day_mb != 0 {
                    j.key("limit_mb").int(self.cfg.metered_day_mb);
                }
                if self.over_limit(id) {
                    j.key("over").bool(true);
                }
            }
            j.end_obj();
        }
        j.end_arr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgtarget::tests::google_feed;
    use crate::dnsguard::tests::{fake, guard, tmp};
    use crate::dnsguard::Health;

    #[test]
    fn routes_and_helpers() {
        let out = "default via 10.0.0.1 dev pppoe-wan proto static metric 10\ndefault via 192.168.8.1 dev eth3 proto static metric 20\ndefault dev tun0 table 52\ndefault via 10.1.1.1 dev eth3 table 2101\ndefault dev wg1 linkdown\n";
        let m = parse_routes(out);
        assert!(m["pppoe-wan"].primary && !m["eth3"].primary && m["eth3"].gw == "192.168.8.1" && m.contains_key("tun0") && !m.contains_key("wg1"), "{m:?}");
        assert_eq!(route_get_dev("10.147.17.5 dev ztabc src 10.147.17.1 uid 0\n    cache"), "ztabc");
        assert_eq!(route_get_dev("10.2.2.2 via 10.0.0.1 dev eth0 src 10.0.0.2"), "");
        assert_eq!(net4("142.250.1.7"), "142.250.1.0/24");
        assert_eq!(net4("10.0.0.1"), "");
        let s = table_script(&[&Path { id: "@n1".into(), dev: "zt0".into(), relay: true, idx: 1, ..Default::default() }], 50);
        assert!(s.contains("ct mark set ct mark & 0xffff0fff | 0x1000") && s.contains("limit rate over 6250 kbytes/second burst 3189 kbytes drop") && s.contains("oifname \"zt0\" masquerade"), "{s}");
    }

    /// Плохой IPv4 у владельца, путь eth3 жив и быстр — обход через него.
    #[test]
    fn reroute_via_path() {
        let f = fake("smartdns");
        let (mut g, sys) = guard("targeted", f, &tmp("r1"));
        g.cfg.alternatives = vec!["eth3".into(), DGR_PROTO.into()];
        g.cfg.targets_file = "/tmp/t.conf".into();
        sys.files.lock().unwrap().insert("/etc/smartdns/custom.conf".into(), "conf-file /tmp/t.conf\n".into());
        sys.queries.lock().unwrap().insert("ip -4 route show table all".into(), "default via 10.0.0.1 dev pppoe-wan metric 10\ndefault via 192.168.8.1 dev eth3 metric 20\n".into());
        // напрямую по IPv4 к Google — 1 из 6; через путь (метка) и по IPv6 — все
        *sys.probe.lock().unwrap() = Some(Box::new(|ips: &[IpAddr], n, m| if ips[0].is_ipv4() && m == 0 && ips[0].to_string().starts_with("142.") { (1, 900.0) } else { (n, 30.0) }));
        let mut feed = google_feed();
        // IPv4 Google плохой: рукопожатия без ответа
        for x in feed.hs.iter_mut() {
            if x.0.is_ipv4() {
                x.1 = false;
            }
            if x.0.to_string().starts_with("2a00") {
                x.1 = true;
            }
        }
        let hh = Health { v4_ok: true, v6_ok: true, v6_avail: true, ..Default::default() };
        let mut now = 1_700_000_000_000i64;
        let mut all = Vec::new();
        for _ in 0..4 {
            all.extend(g.tick(now, "NORMAL", "HEALTHY", &hh, &mut feed));
            now += 61_000;
        }
        assert!(all.iter().any(|m| m.starts_with("Обход: Google — новые соединения по IPv4 идут через eth3")), "{all:?}");
        let t = &g.targets["AS15169/ipv4"];
        assert!(t.via == "eth3" && t.nets == vec!["142.250.1.0/24".to_string()], "{t:?}");
        let nfts = sys.nfts.lock().unwrap().join("\n");
        assert!(nfts.contains("add element inet cgmon_route p1_net { 142.250.1.0/24 }"), "{nfts}");
        assert!(sys.runs.lock().unwrap().iter().any(|r| r == "ip -4 rule add pref 85 fwmark 0x1000/0xf000 lookup 2101"));
        // адреса доменов — в p1_ip из DNS-ответов клиентам; SmartDNS не трогаем
        assert!(nfts.contains("add element inet cgmon_route p1_ip {"), "{nfts}");
        let conf = sys.files.lock().unwrap().get("/tmp/t.conf").cloned().unwrap_or_default();
        assert!(!conf.contains("nftset"), "{conf}");
        assert!(!sys.runs.lock().unwrap().iter().any(|r| r.contains("smartdns")));
        // «перезапуск»: путь ещё не проверен — обход держится, пока проверка не пройдёт
        for p in g.r_paths.values_mut() {
            p.checked = false;
            p.up = false;
        }
        g.r_at = now;
        g.t_eval_at = 0;
        let m = g.tick(now, "NORMAL", "HEALTHY", &hh, &mut feed);
        assert!(g.targets["AS15169/ipv4"].active && !m.iter().any(|x| x.contains("снят")), "{m:?}");
    }
}
