//! Обход блокировок по имени сайта (TLS-reset), без подделки и нарезки пакетов.
//!
//! Провайдер с DPI часто блокирует сайт по имени в TLS (SNI): TCP до адреса
//! устанавливается (SYN-ACK приходит), а как только клиент отправляет имя сайта —
//! соединение сбрасывают. Обычные пробы cgmon этого не видят: рукопожатие удалось.
//! Поэтому cgmon проверяет сайт активно, обычным curl, и смотрит, каким путём он
//! открывается: напрямую по IPv4, по IPv6 или через VPN (узел-ретранслятор в ZeroTier).
//! Признак блокировки по имени: прямой IPv4 — TCP есть, TLS рвётся; через VPN — всё
//! открывается (в туннеле DPI имя не видит). Такой сайт cgmon помечает меткой 0x100
//! и уводит в VPN тем же путём, что и per-site VPN (ip rule fwmark 0x100 → таблица VPN).
//! Никаких сторонних программ и модулей ядра: только curl и уже настроенный VPN.
//!
//! Схемы, которые cgmon перебирает (от дешёвой к дорогой): прямой IPv6 (если у сайта
//! он есть и работает — трафик никуда не уводится), затем VPN. Выбранная схема и
//! параметры пишутся в журнал и «События».

use crate::json::J;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender};

/// Таблица для метки заблокированных сайтов.
pub const TABLE: &str = "cgmon_unblock";
/// Метка legacy per-site VPN (таблица 53, ip rule pref 100) — гейт «vpn»/«active».
pub const VPN_MARK_U: u32 = 0x100;

const CHECK_GAP_MS: u64 = 30_000; // не чаще одной проверки за 30 с
const RECHECK_MS: i64 = 6 * 3600_000; // известное — перепроверять раз в 6 ч
const FORGET_MS: i64 = 24 * 3600_000; // домен не нужен клиентам сутки — забыть
const LIFE_MS: i64 = 24 * 3600_000; // увод живёт сутки с подтверждения, потом снимаем и переучиваемся (сайт могли разблокировать, CDN сменить пул)
const FILE: &str = "/etc/cgmon/unblock.json"; // пойманные заблокированные сайты — переживают рестарт
const MAX: usize = 200;
const TIMEOUT_S: u64 = 8;

/// Как открывается сайт (итог одной curl-проверки по одному адресу).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Probe {
    /// TLS прошёл — сайт ответил
    Ok,
    /// TCP установился, а TLS оборвался — блокировка по имени (SNI)
    SniReset,
    /// TCP не установился — адрес недоступен (не наш случай: это к down detector)
    NoTcp,
    /// не проверяли (нет адреса этого протокола)
    Skip,
}

/// Вывод проверки одного домена по всем путям.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub domain: String,
    pub v4: Vec<IpAddr>,
    pub v6: Vec<IpAddr>,
    pub direct4: Probe,
    pub direct6: Probe,
    pub vpn4: Probe,
}

impl Verdict {
    /// Заблокирован по имени на IPv4 (TCP есть, TLS рвётся).
    pub fn blocked_v4(&self) -> bool {
        self.direct4 == Probe::SniReset
    }
    /// Рабочая схема обхода: "" — не нужен обход (или не нашли), "ipv6", "vpn".
    pub fn scheme(&self) -> &'static str {
        if !self.blocked_v4() {
            return "";
        }
        if self.direct6 == Probe::Ok {
            return "ipv6"; // по IPv6 открывается напрямую — уводить в VPN не нужно
        }
        if self.vpn4 == Probe::Ok {
            return "vpn";
        }
        ""
    }
}

/// Запись о домене.
#[derive(Clone, Debug, Default)]
struct Entry {
    v4: Vec<IpAddr>,
    v6: Vec<IpAddr>,
    blocked: bool,
    /// принудительный (сайт проверки) — уводим без проверки на блокировку
    forced: bool,
    /// пойман по сбросу реального трафика клиента (а не по плановому обходу списка)
    reset: bool,
    scheme: String,
    checked: i64,
    seen: i64,
}

pub struct Unblock {
    pub mode: String, // off | observe | active
    entries: std::collections::BTreeMap<String, Entry>,
    last_check: u64,
    busy: bool,
    rx: Option<Receiver<Verdict>>,
    tx: Sender<Verdict>,
    written: String,
    rules_on: bool,
    /// метка выбранного гейта (куда уводить): 0x100 — per-site VPN, idx<<12 — reroute-путь; 0 — нет
    gate: u32,
    /// домены для срочной проверки (сброс пойман в реальном трафике) — вне очереди
    urgent: std::collections::VecDeque<String>,
    ensured: u64,
    loaded: bool,
    /// домены проверки «мой IP» (check_domains): всегда через VPN + отказ их IPv6,
    /// чтобы ipleak и т. п. показывали адрес туннеля независимо от DNS и IPv6 клиента
    force: std::collections::BTreeSet<String>,
}

impl Default for Unblock {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Unblock { mode: "off".into(), entries: Default::default(), last_check: 0, busy: false, rx: Some(rx), tx, written: String::new(), rules_on: false, gate: 0, urgent: Default::default(), ensured: 0, loaded: false, force: Default::default() }
    }
}

impl Unblock {
    pub fn on(&self) -> bool {
        self.mode != "off" && !self.mode.is_empty()
    }

    /// Уводить (а не только наблюдать): режим не off и не observe (т. е. выбран гейт/active).
    fn routes(&self) -> bool {
        self.on() && self.mode != "observe"
    }

    /// Домены, у которых в реальном трафике поймали сброс DPI, — проверить срочно, вне очереди.

    /// Домены, которыми недавно пользовались клиенты (DNSWatch) — кандидаты на проверку;
    /// now — настенное время, мс.
    /// Добавить к записи реальные адреса клиента (из DNSWatch и из пойманного сброса),
    /// чтобы увод совпал с тем, куда ходит клиент (CDN отдаёт разные IP разным резолверам).
    fn merge_ip(&mut self, domain: &str, ip: IpAddr) {
        if !domain_ok(domain) {
            return;
        }
        let e = self.entries.entry(domain.to_string()).or_default();
        let list = if ip.is_ipv6() { &mut e.v6 } else { &mut e.v4 };
        if !list.contains(&ip) && list.len() < 16 {
            list.push(ip);
        }
    }

    pub fn tick(&mut self, now: i64, now_ms: u64, gate: u32, candidates: &[String], active: &[String], force: &[String], resets: &[(IpAddr, String)], known: &[(String, IpAddr)]) -> Vec<String> {
        let mut msgs = Vec::new();
        self.gate = gate; // метка выбранного гейта (демон вычисляет из dns_guard.unblock)
        if !self.loaded {
            self.loaded = true;
            self.load(now);
        }
        if !self.on() {
            if self.rules_on {
                self.teardown();
            }
            return msgs;
        }
        // отметить замеченные домены
        for d in candidates {
            if !domain_ok(d) || skip_domain(d) {
                continue;
            }
            let e = self.entries.entry(d.clone()).or_default();
            e.seen = now;
        }
        // активно используемые адреса (клиент долбится) — ни разу не проверенные ставим
        // в очередь вне плана: «тихий» дроп TLS не даёт ни RST, ни неотвеченных SYN, и
        // плановая (алфавитная) очередь дошла бы до сайта через минуты. Один раз на сайт:
        // проверенный (рабочий или заблокированный) повторно сюда не попадает.
        for d in active {
            if !domain_ok(d) || skip_domain(d) {
                continue;
            }
            let e = self.entries.entry(d.clone()).or_default();
            e.seen = now;
            if !e.blocked && e.checked == 0 && !self.urgent.contains(d) && self.urgent.len() < 64 {
                self.urgent.push_back(d.clone());
            }
        }
        // сайты проверки «мой IP»: всегда через VPN, резолвим сами (без проверки на блок)
        self.force = force.iter().filter(|d| domain_ok(d)).cloned().collect();
        for d in &self.force.clone() {
            let e = self.entries.entry(d.clone()).or_default();
            e.seen = now;
            e.forced = true;
            if e.v4.is_empty() && e.checked == 0 && !self.urgent.contains(d) && self.urgent.len() < 64 {
                self.urgent.push_back(d.clone()); // срочно резолвить и увести
            }
        }
        // пойманные сбросы реального трафика: запись по ИМЕНИ сайта (одна на сайт, обе семьи).
        // Сам адрес клиента запоминаем (уводим /32 именно его), но перед уводом ПОДТВЕРЖДАЕМ
        // блок прямой SNI-пробой (check) — телеметрия (googleapis/apple…) шлёт RST при закрытии
        // соединения, похоже на DPI, но при переобходе отдаёт HTTP-код и уводиться не должна.
        for (ip, name) in resets {
            if name.is_empty() || !domain_ok(name) || skip_domain(name) || !crate::witness::public(ip) {
                continue; // без имени блок не подтвердить; резолверы и приватные адреса не трогаем
            }
            let e = self.entries.entry(name.clone()).or_default();
            e.seen = now;
            e.reset = true;
            let list = if ip.is_ipv6() { &mut e.v6 } else { &mut e.v4 };
            if !list.contains(ip) && list.len() < 16 { list.push(*ip); }
            if !e.blocked && e.checked == 0 && !self.urgent.contains(name) && self.urgent.len() < 64 {
                self.urgent.push_back(name.clone()); // подтвердить и увести
            }
        }
        // реальные адреса клиента (DNSWatch) — для заблокированных/принудительных доменов
        for (d, ip) in known {
            let routed = self.force.contains(d) || self.entries.get(d).map_or(false, |e| e.blocked);
            if routed {
                self.merge_ip(d, *ip);
            }
        }
        // забыть: не нужен клиентам сутки, ЛИБО увод прожил сутки с подтверждения (переучиваемся —
        // если всё ещё блокируется, клиент снова словит сброс и cgmon переловит за секунды).
        // Принудительные (сайты проверки) не стареют — они каждый тик подтверждаются заново.
        self.entries.retain(|_, e| {
            if now - e.seen >= FORGET_MS {
                return false;
            }
            !(e.blocked && !e.forced && e.checked > 0 && now - e.checked >= LIFE_MS)
        });
        if self.entries.len() > MAX {
            let mut v: Vec<(String, i64)> = self.entries.iter().map(|(k, e)| (k.clone(), e.seen)).collect();
            v.sort_by_key(|x| x.1);
            for (k, _) in v.into_iter().take(self.entries.len() - MAX) {
                self.entries.remove(&k);
            }
        }
        // забрать готовую проверку
        if let Some(rx) = &self.rx {
            if let Ok(v) = rx.try_recv() {
                self.busy = false;
                msgs.extend(self.apply(now, v));
            }
        }
        // запустить следующую проверку: срочные (пойманный сброс — подтвердить и увести)
        // вне очереди, затем плановая перепроверка раз в 30 с
        if !self.busy {
            if let Some(d) = self.urgent.pop_front().or_else(|| if now_ms - self.last_check >= CHECK_GAP_MS { self.pick(now) } else { None }) {
                self.last_check = now_ms;
                self.busy = true;
                let tx = self.tx.clone();
                let g = self.gate;
                std::thread::spawn(move || {
                    let _ = tx.send(check(&d, g));
                });
            }
        }
        if self.apply_sets() {
            // набор изменился — метка применена
        }
        msgs
    }

    /// Домен для проверки: новый (ещё не проверяли) или пора перепроверить.
    fn pick(&self, now: i64) -> Option<String> {
        // сперва ни разу не проверенные, затем самые давние
        let mut best: Option<(&String, i64)> = None;
        for (d, e) in &self.entries {
            let due = if e.checked == 0 { i64::MIN } else if now - e.checked >= RECHECK_MS { e.checked } else { continue };
            if best.map_or(true, |b| due < b.1) {
                best = Some((d, due));
            }
        }
        best.map(|b| b.0.clone())
    }

    fn apply(&mut self, now: i64, v: Verdict) -> Vec<String> {
        let forced = self.force.contains(&v.domain);
        let scheme = if forced && !v.v4.is_empty() { "vpn" } else { v.scheme() };
        let e = self.entries.entry(v.domain.clone()).or_default();
        e.checked = now;
        // сливаем адреса (не затираем): к адресам из проверки добавляем реальные адреса
        // клиента, пойманные по сбросу (merge_ip) — уводим именно те, куда он ходит
        for ip in &v.v4 { if !e.v4.contains(ip) && e.v4.len() < 16 { e.v4.push(*ip); } }
        for ip in &v.v6 { if !e.v6.contains(ip) && e.v6.len() < 16 { e.v6.push(*ip); } }
        e.forced = forced;
        let was = e.blocked;
        e.blocked = scheme == "vpn";
        e.scheme = scheme.into();
        if forced {
            if e.blocked && !was {
                self.save();
                return vec![format!("Проверка «мой IP»: {} идёт через VPN (сайт покажет адрес туннеля)", v.domain)];
            }
            return Vec::new();
        }
        let changed = e.blocked != was;
        if changed {
            self.save();
        }
        // подтверждено прямой пробой: блок по имени есть и напрямую (в т. ч. по IPv4) не
        // открывается — только тогда уводим. Ложные (телеметрия с RST) сюда не попадают.
        if v.blocked_v4() && !was {
            let via = match scheme {
                "vpn" if self.routes() => "направлен через туннель (напрямую не открывался)",
                "vpn" => "направил бы через туннель (режим наблюдения)",
                "ipv6" => "открывается по IPv6 напрямую — туннель не нужен",
                _ => "через туннель тоже не открылся",
            };
            return vec![format!("Per-Site VPN: {} — {via}", v.domain)];
        }
        if !v.blocked_v4() && was {
            return vec![format!("Per-Site VPN: {} снова открывается напрямую — убран из туннеля", v.domain)];
        }
        Vec::new()
    }

    /// Пересобрать набор адресов заблокированных сайтов и метку.
    fn apply_sets(&mut self) -> bool {
        // уводим только когда выбран рабочий гейт; в observe (gate==0) — набор пуст
        let active = self.routes() && self.gate != 0;
        let (mut v4, mut v6): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        if active {
            for e in self.entries.values().filter(|e| e.blocked) {
                // IPv4 — точечно (/32 именно те адреса, куда ходит клиент)
                v4.extend(e.v4.iter().map(|ip| ip.to_string()));
                // IPv6 — отказ всему /48 владельца: VPN IPv6 не умеет, а браузер по
                // Happy-Eyeballs пробует IPv6 первым и залипает на нём после рукопожатия;
                // отказ /48 на SYN гонит все IPv6 владельца на IPv4 (рабочий IPv4 — напрямую)
                v6.extend(e.v6.iter().map(prefix));
            }
        }
        v4.sort();
        v4.dedup();
        v6.sort();
        v6.dedup();
        let script = nft_script(&v4, &v6, self.gate);
        // раз в минуту применить заново даже без изменений — вдруг таблицу смыло (fw4 reload и т. п.)
        let now_ms = crate::evloop::now_ms();
        let refresh = !(v4.is_empty() && v6.is_empty()) && now_ms - self.ensured >= 60_000;
        if script == self.written && !refresh {
            return false;
        }
        self.ensured = now_ms;
        if crate::acct::nft_script(&script).is_ok() {
            self.written = script;
            self.rules_on = true; // таблица тронута — при выключении её снимет teardown
            return true;
        }
        false
    }

    fn teardown(&mut self) {
        let _ = crate::acct::nft_script(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
        self.written.clear();
        self.rules_on = false;
    }

    fn save(&self) {
        if crate::util::readonly() {
            return;
        }
        let mut j = J::new();
        j.arr();
        for (d, e) in self.entries.iter().filter(|(_, e)| e.blocked) {
            j.obj().key("domain").str(d).key("scheme").str(&e.scheme).key("checked").int(e.checked).key("reset").bool(e.reset);
            j.key("v4").arr();
            for ip in &e.v4 { j.str(&ip.to_string()); }
            j.end_arr().key("v6").arr();
            for ip in &e.v6 { j.str(&ip.to_string()); }
            j.end_arr().end_obj();
        }
        j.end_arr();
        let _ = crate::util::write_atomic(&crate::storage::path(FILE), j.b.as_bytes(), 0o600);
    }

    fn load(&mut self, now: i64) {
        let Ok(t) = std::fs::read_to_string(crate::storage::path(FILE)) else { return };
        let Ok(crate::value::Value::List(l)) = crate::value::parse_json(&t) else { return };
        for v in l {
            let Some(d) = v.get("domain").and_then(|x| x.as_str()).filter(|x| domain_ok(x) || x.parse::<IpAddr>().is_ok()) else { continue };
            let ips = |k: &str| v.get(k).and_then(|x| if let crate::value::Value::List(a) = x { Some(a) } else { None })
                .map(|a| a.iter().filter_map(|x| x.as_str().and_then(|s| s.parse().ok())).collect::<Vec<IpAddr>>()).unwrap_or_default();
            let e = self.entries.entry(d.to_string()).or_default();
            e.v4 = ips("v4");
            e.v6 = ips("v6");
            e.scheme = v.get("scheme").and_then(|x| x.as_str()).unwrap_or("vpn").into();
            e.blocked = e.scheme == "vpn";
            e.checked = v.get("checked").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
            e.reset = v.get("reset").and_then(|x| x.as_bool()).unwrap_or(false);
            e.seen = now; // чтобы не забылся сразу после старта
        }
    }

    pub fn status_json(&self, j: &mut J) {
        if !self.routes() {
            return; // off/observe — ещё не уводим, на странице не показываем как увод
        }
        let blocked: Vec<(&String, &Entry)> = self.entries.iter().filter(|(_, e)| e.blocked).collect();
        if blocked.is_empty() {
            return;
        }
        j.arr();
        for (d, e) in blocked {
            let ips = if e.v4.is_empty() { e.v6.len() } else { e.v4.len() };
            // since — время подтверждения (мс настенного времени) для показа даты в блоке
            j.obj().key("domain").str(d).key("via").str(&e.scheme).key("ips").int(ips as i64).key("since").int(e.checked).end_obj();
        }
        j.end_arr();
    }

    /// Домены, которые уводятся (заблокированные + принудительные) — демон добавит их
    /// реальные адреса из DNSWatch через known.
    pub fn routed_domains(&self) -> Vec<String> {
        let mut v: Vec<String> = self.force.iter().cloned().collect();
        v.extend(self.entries.iter().filter(|(_, e)| e.blocked).map(|(d, _)| d.clone()));
        v.sort();
        v.dedup();
        v
    }
}

/// Префикс владельца адреса для набора: /24 для IPv4, /48 для IPv6 (покрывает пул CDN).
fn prefix(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => { let o = a.octets(); format!("{}.{}.{}.0/24", o[0], o[1], o[2]) }
        IpAddr::V6(a) => { let s = a.segments(); format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]) }
    }
}

/// nft: своя таблица, метка выбранного гейта на новые соединения к заблокированным адресам.
/// gate — метка гейта (0x100 per-site VPN, idx<<12 reroute-путь); маршрут даёт уже готовое
/// ip rule этого гейта (pref 100 → таблица 53, либо pref 85 → таблица 2100+idx).
pub fn nft_script(v4: &[String], v6: &[String], gate: u32) -> String {
    let mark = format!("0x{gate:x}");
    let mut b = format!("add table inet {TABLE}\ndelete table inet {TABLE}\n");
    if v4.is_empty() && v6.is_empty() {
        return b;
    }
    b.push_str(&format!("table inet {TABLE} {{\n"));
    if !v4.is_empty() {
        b.push_str("\tset blk4 { type ipv4_addr; flags interval; auto-merge;\n\t\telements = { ");
        b.push_str(&v4.join(", "));
        b.push_str(" }\n\t}\n");
    }
    if !v6.is_empty() {
        b.push_str("\tset blk6 { type ipv6_addr; flags interval; auto-merge;\n\t\telements = { ");
        b.push_str(&v6.join(", "));
        b.push_str(" }\n\t}\n");
    }
    // новые соединения из LAN к заблокированным IPv4 — метка VPN (как per-site VPN), только 443
    b.push_str("\tchain steer {\n\t\ttype filter hook prerouting priority mangle - 2; policy accept;\n");
    if !v4.is_empty() {
        b.push_str(&format!("\t\tct direction original ct state new ip daddr @blk4 meta l4proto {{ tcp, udp }} th dport 443 meta mark set {mark} ct mark set {mark}\n"));
        // метку восстанавливаем ТОЛЬКО для прямого направления (клиент→сайт): иначе ответ
        // сайт→клиент тоже получит метку и уйдёт обратно в туннель вместо LAN (клиент — таймаут)
        b.push_str(&format!("\t\tct direction original ct mark {mark} meta mark set {mark}\n"));
    }
    b.push_str("\t}\n");
    // IPv6 заблокированного сайта: отказ новым соединениям (VPN IPv6 не умеет) — клиент сразу на IPv4
    if !v6.is_empty() {
        b.push_str("\tchain v6 {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n");
        b.push_str("\t\tct state new ip6 daddr @blk6 tcp dport 443 counter reject with tcp reset\n");
        b.push_str("\t\tct state new ip6 daddr @blk6 udp dport 443 counter reject with icmpv6 type admin-prohibited\n");
        b.push_str("\t}\n");
    }
    b.push_str("}\n");
    b
}

/// Проверка одного домена (фоновый поток). gate — метка выбранного гейта (0 — гейт не задан).
pub fn check(domain: &str, gate: u32) -> Verdict {
    let v4 = crate::dgsys::resolve_public(domain, "ipv4");
    let v6 = crate::dgsys::resolve_public(domain, "ipv6");
    let direct4 = v4.first().map(|ip| curl_probe(domain, ip)).unwrap_or(Probe::Skip);
    // IPv6 и достижимость через гейт проверяем только если прямой IPv4 заблокирован — экономия
    let (direct6, vpn4) = if direct4 == Probe::SniReset {
        let d6 = v6.first().map(|ip| curl_probe(domain, ip)).unwrap_or(Probe::Skip);
        // открывается ли адрес через выбранный гейт: маркированный TCP-connect (SO_MARK = метка
        // гейта → ip rule → его таблица). Годится для любого гейта (VPN/реле/устройство) без uid
        let vp = if d6 != Probe::Ok && gate != 0 {
            match v4.first() {
                Some(ip) => {
                    let (ok, _) = crate::dgsys::probe_many(&[*ip], 2, gate, None, 4000);
                    if ok > 0 { Probe::Ok } else { Probe::NoTcp }
                }
                None => Probe::Skip,
            }
        } else {
            Probe::Skip
        };
        (d6, vp)
    } else {
        (Probe::Skip, Probe::Skip)
    };
    Verdict { domain: domain.into(), v4, v6, direct4, direct6, vpn4 }
}

/// curl к адресу с именем сайта напрямую: прошёл ли TLS (без маршрутизации).
fn curl_probe(name: &str, ip: &IpAddr) -> Probe {
    if !crate::util::have_bin("curl") {
        return Probe::Skip;
    }
    let host = if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() };
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "-o", "/dev/null", "-k", "--resolve", &format!("{name}:443:{host}"), "--connect-timeout", "4", "-m", &TIMEOUT_S.to_string(), "-w", "%{http_code} %{time_connect}", &format!("https://{name}/")]);
    let Ok(o) = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).output() else { return Probe::Skip };
    classify(&String::from_utf8_lossy(&o.stdout))
}

/// Разбор `%{http_code} %{time_connect}` от curl: прошёл ли TLS / установился ли TCP.
pub fn classify(w: &str) -> Probe {
    let mut it = w.split_whitespace();
    let code: u32 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let tconn: f64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
    if code != 0 {
        Probe::Ok // получили ответ HTTP — TLS прошёл
    } else if tconn > 0.0 {
        Probe::SniReset // TCP установился, а ответа по TLS нет — сброс по имени
    } else {
        Probe::NoTcp // не подключились — это не блокировка по имени
    }
}

/// Публичные DNS/DoH-резолверы (dns.google, one.one.one.one, *dns*) — не трогаем:
/// их блокировка провайдером — дело DNS-страховки, а не увода «сайта» в VPN.
pub fn skip_domain(d: &str) -> bool {
    crate::livecfg::wit_dns_name(d)
}

/// Имя домена безопасно для curl/nft (без спецсимволов).
pub fn domain_ok(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    (3..=253).contains(&d.len())
        && d.contains('.')
        && d.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        && !d.starts_with('.')
        && !d.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_outcomes() {
        assert_eq!(classify("200 0.045"), Probe::Ok);
        assert_eq!(classify("301 0.040"), Probe::Ok);
        assert_eq!(classify("000 0.038"), Probe::SniReset); // TCP есть, TLS нет — блок по имени
        assert_eq!(classify("000 0.000"), Probe::NoTcp); // не подключились
        assert_eq!(classify(""), Probe::NoTcp);
    }

    #[test]
    fn scheme_choice() {
        let ip: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        // заблокирован v4, по v6 открывается — обход не нужен
        let v = Verdict { domain: "x.org".into(), v4: ip.clone(), v6: vec![], direct4: Probe::SniReset, direct6: Probe::Ok, vpn4: Probe::Skip };
        assert!(v.blocked_v4() && v.scheme() == "ipv6");
        // заблокирован v4, v6 нет, VPN открывает — через VPN
        let v = Verdict { domain: "x.org".into(), v4: ip.clone(), v6: vec![], direct4: Probe::SniReset, direct6: Probe::Skip, vpn4: Probe::Ok };
        assert_eq!(v.scheme(), "vpn");
        // не заблокирован — схема пустая
        let v = Verdict { domain: "x.org".into(), v4: ip, v6: vec![], direct4: Probe::Ok, direct6: Probe::Skip, vpn4: Probe::Skip };
        assert!(!v.blocked_v4() && v.scheme().is_empty());
    }

    #[test]
    fn nft_marks_vpn() {
        assert!(nft_script(&[], &[], 0x100).contains("delete table inet cgmon_unblock") && !nft_script(&[], &[], 0x100).contains("blk4 {"));
        let s = nft_script(&["1.2.3.4".into()], &["2001:db8::1".into()], 0x100);
        assert!(s.contains("set blk4 {") && s.contains("1.2.3.4") && s.contains("set blk6 {") && s.contains("2001:db8::1"));
        assert!(s.contains("chain steer") && s.contains("ip daddr @blk4 meta l4proto { tcp, udp } th dport 443 meta mark set 0x100"), "{s}");
        // IPv6 заблокированного — отказ, чтобы клиент упал на IPv4 (который в VPN)
        assert!(s.contains("ip6 daddr @blk6 tcp dport 443 counter reject with tcp reset"), "{s}");
        assert!(s.contains("priority mangle - 2") && s.contains("priority filter - 5"));
    }

    #[test]
    fn skip_resolvers() {
        assert!(skip_domain("dns.google") && skip_domain("one.one.one.one") && skip_domain("dns.cloudflare.com"));
        assert!(!skip_domain("example.org") && !skip_domain("news.example.com"));
    }

    #[test]
    fn domain_charset() {
        assert!(domain_ok("example.org") && domain_ok("www.example.com."));
        assert!(!domain_ok("x") && !domain_ok("a b.com") && !domain_ok("bad;.com") && !domain_ok(".com"));
    }

    #[test]
    fn apply_events() {
        let mut u = Unblock { mode: "active".into(), ..Default::default() };
        let ip: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let v = Verdict { domain: "example.org".into(), v4: ip.clone(), v6: vec!["2001:db8::1".parse().unwrap()], direct4: Probe::SniReset, direct6: Probe::SniReset, vpn4: Probe::Ok };
        let m = u.apply(1000, v);
        assert!(m[0].contains("Per-Site VPN") && m[0].contains("через туннель"), "{m:?}");
        // запись помечена как заблокированная, её адрес попадёт в набор метки VPN
        let e = u.entries.get("example.org").unwrap();
        assert!(e.blocked && e.scheme == "vpn" && !e.v6.is_empty());
        let sc = nft_script(&[e.v4[0].to_string()], &[e.v6[0].to_string()], 0x100);
        assert!(sc.contains("1.2.3.4") && sc.contains("reject with tcp reset"));
    }
}
