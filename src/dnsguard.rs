//! DNS-страховка (перенос dnsguard.go): при сбое одного протокола у
//! провайдера DNS роутера уводит клиентов на живой.
//!
//!   - IPv6 плохой, IPv4 живой (IPV6_DEGRADATION дольше v6_enter_sec) —
//!     клиентам не отдаются AAAA (и с withdraw_ra — RA без шлюза);
//!   - IPv4 сломан, IPv6 жив (WARNING/CRITICAL с IPV4_EXTERNAL_DEGRADATION
//!     дольше v4_enter_sec) — вышестоящие DNS заменяются на DNS64;
//!   - HEALTHY дольше recover_sec — обычные настройки обратно.
//!
//! «Обычные» — снимок того, что страховка меняет; правка во время аварии =
//! ручное вмешательство (становится обычной). state_file — в формате Go
//! (dgSaved): перезапуск продолжает аварию, только если на диске ровно
//! записанное. Адресный режим — dgtarget.rs, обход — dgroute.rs, отказ в
//! IPv6 — dgv6.rs. Долгое (перезапуск SmartDNS, проверки) — в рабочих
//! потоках; итоги забираются в начале такта.

use crate::config::DNSGuardConfig;
use crate::dgsys::{self, Sys};
use crate::json::J;
use crate::value::{parse_json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

pub const NORMAL: &str = "normal";
pub const NO_AAAA: &str = "no_aaaa";
pub const DNS64: &str = "dns64";

const MIN: i64 = 60_000;
pub const CHECK_EVERY: i64 = MIN;
/// между переключениями не меньше (кроме выхода из DNS64)
pub const DWELL: i64 = 10 * MIN;
/// «не навреди»: режим, который навредил, не включается столько
pub const BLOCK_FOR: i64 = 60 * MIN;

pub const RA_TEXT: &str = "DHCP: IPv6 шлюз отключен (клиентам не раздаётся IPv6-маршрут) из-за деградации IPv6 провайдера";
pub const RA_BACK: &str = "DHCP: IPv6 шлюз снова включен";

/// Здоровье протоколов по пробам cgmon (dgHealth).
#[derive(Clone, Debug, Default)]
pub struct Health {
    pub v4_ok: bool,
    pub v6_ok: bool,
    pub outage: bool,
    pub v6_avail: bool,
    pub wit_v4: String,
    pub wit_v6: String,
    pub v6_rate: f64,
    pub wit_v6_score: f64,
}

/// Данные для адресного режима: рукопожатия клиентов, имена, владельцы.
pub trait Feed {
    /// Рукопожатия клиентов за окно: (адрес, ответил, мс).
    fn handshakes(&self, window_ms: u64) -> Vec<(IpAddr, bool, f64)>;
    fn name_of(&self, ip: &IpAddr) -> Option<String>;
    fn each_pair(&self, f: &mut dyn FnMut(&IpAddr, &str));
    /// (номер AS, бренд), None — ещё выясняется (тогда выяснение начато).
    fn owner(&mut self, ip: &IpAddr) -> Option<(String, String)>;
}

/// Пустой источник (адресный режим без данных).
#[cfg(test)]
pub struct NoFeed;

#[cfg(test)]
impl Feed for NoFeed {
    fn handshakes(&self, _: u64) -> Vec<(IpAddr, bool, f64)> {
        Vec::new()
    }
    fn name_of(&self, _: &IpAddr) -> Option<String> {
        None
    }
    fn each_pair(&self, _: &mut dyn FnMut(&IpAddr, &str)) {}
    fn owner(&mut self, _: &IpAddr) -> Option<(String, String)> {
        None
    }
}

/// Настройки, которые страховка меняет (dgSnap); пустое = nil в Go.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snap {
    pub files: BTreeMap<String, String>,
    pub servers: Vec<String>,
    pub noresolv: String,
    pub filter_aaaa: String,
    pub ra: BTreeMap<String, String>,
}

impl Snap {
    pub fn same(&self, o: &Snap) -> bool {
        self == o
    }

    fn json(&self, j: &mut J) {
        j.obj();
        if !self.files.is_empty() {
            j.key("files").obj();
            for (k, v) in &self.files {
                j.key(k).str(v);
            }
            j.end_obj();
        }
        if !self.servers.is_empty() {
            j.key("servers").arr();
            for s in &self.servers {
                j.str(s);
            }
            j.end_arr();
        }
        if !self.noresolv.is_empty() {
            j.key("noresolv").str(&self.noresolv);
        }
        if !self.filter_aaaa.is_empty() {
            j.key("filter_aaaa").str(&self.filter_aaaa);
        }
        if !self.ra.is_empty() {
            j.key("ra").obj();
            for (k, v) in &self.ra {
                j.key(k).str(v);
            }
            j.end_obj();
        }
        j.end_obj();
    }

    fn from(v: Option<&Value>) -> Snap {
        let Some(v) = v else { return Snap::default() };
        let map = |k: &str| -> BTreeMap<String, String> {
            match v.get(k) {
                Some(Value::Map(m)) => m.iter().map(|(a, b)| (a.clone(), b.as_str().unwrap_or("").to_string())).collect(),
                _ => BTreeMap::new(),
            }
        };
        Snap { files: map("files"), servers: str_list(v.get("servers")), noresolv: vstr(v, "noresolv"), filter_aaaa: vstr(v, "filter_aaaa"), ra: map("ra") }
    }
}

pub fn vstr(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

pub fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::List(l)) => l.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    }
}

/// Время в JSON (мс unix → RFC 3339 с долями, как Go time.Time).
pub fn time_json(ms: i64) -> String {
    crate::util::rfc3339(ms.div_euclid(1000), (ms.rem_euclid(1000) * 1_000_000) as u32)
}

pub fn time_parse(v: Option<&Value>) -> i64 {
    match v.and_then(|x| x.as_str()).and_then(crate::util::parse_rfc3339) {
        Some((s, n)) if s > 0 => s * 1000 + (n / 1_000_000) as i64,
        _ => 0,
    }
}

/// Чтение и запись того, что меняет страховка (dgBackend).
pub trait Backend: Send + Sync {
    fn name(&self) -> String;
    fn read(&self, sys: &dyn Sys) -> Result<Snap, String>;
    /// Записать состояние поверх обычных; вернуть записанное.
    fn write(&self, sys: &dyn Sys, state: &str, base: &Snap) -> Result<Snap, String>;
}

// ---- RA (odhcpd) поверх backend DNS ----

pub struct WithRa {
    pub inner: Box<dyn Backend>,
    pub on: bool,
}

/// ra_lifetime для состояния поверх обычных.
pub fn ra_target(state: &str, base: &BTreeMap<String, String>, on: bool) -> BTreeMap<String, String> {
    base.iter().map(|(k, v)| (k.clone(), if on && state == NO_AAAA { "0".to_string() } else { v.clone() })).collect()
}

pub fn ra_cmds(ra: &BTreeMap<String, String>) -> Vec<Vec<String>> {
    let mut c: Vec<Vec<String>> = Vec::new();
    for (k, v) in ra {
        if v.is_empty() {
            c.push(vec!["uci".into(), "-q".into(), "delete".into(), format!("dhcp.{k}.ra_lifetime")]);
        } else {
            c.push(vec!["uci".into(), "set".into(), format!("dhcp.{k}.ra_lifetime={v}")]);
        }
    }
    c.push(vec!["uci".into(), "commit".into(), "dhcp".into()]);
    c.push(vec!["/etc/init.d/odhcpd".into(), "reload".into()]);
    c
}

/// Команды подряд; ошибка «uci -q delete» (нечего удалять) не считается.
fn run_cmds(sys: &dyn Sys, cmds: &[Vec<String>]) -> Result<(), String> {
    for c in cmds {
        let a: Vec<&str> = c.iter().map(|s| s.as_str()).collect();
        if let Err(e) = sys.run(&a) {
            if !(a.len() > 2 && a[1] == "-q" && a[2] == "delete") {
                return Err(e);
            }
        }
    }
    Ok(())
}

impl Backend for WithRa {
    fn name(&self) -> String {
        self.inner.name()
    }
    fn read(&self, sys: &dyn Sys) -> Result<Snap, String> {
        let mut s = self.inner.read(sys)?;
        s.ra = dgsys::ra_read(sys);
        Ok(s)
    }
    fn write(&self, sys: &dyn Sys, state: &str, base: &Snap) -> Result<Snap, String> {
        let mut w = self.inner.write(sys, state, base)?;
        w.ra = ra_target(state, &base.ra, self.on);
        if w.ra == dgsys::ra_read(sys) {
            return Ok(w); // уже так — odhcpd не трогаем
        }
        run_cmds(sys, &ra_cmds(&w.ra))?;
        Ok(w)
    }
}

// ---- SmartDNS ----

pub struct SmartDns {
    pub upstream_file: String,
    pub guard_file: String,
    pub cache_file: String,
    pub dns64: Vec<String>,
}

impl Backend for SmartDns {
    fn name(&self) -> String {
        "smartdns".into()
    }
    fn read(&self, sys: &dyn Sys) -> Result<Snap, String> {
        let mut s = Snap::default();
        for f in [&self.upstream_file, &self.guard_file] {
            s.files.insert(f.clone(), sys.read_file(f).unwrap_or_default());
        }
        Ok(s)
    }
    fn write(&self, sys: &dyn Sys, state: &str, base: &Snap) -> Result<Snap, String> {
        let mut up = base.files.get(&self.upstream_file).cloned().unwrap_or_default();
        let mut guard = base.files.get(&self.guard_file).cloned().unwrap_or_default();
        match state {
            NO_AAAA => guard.push_str("\n# cgmon dns_guard: у провайдера плохой IPv6 — без AAAA\nforce-AAAA-SOA yes\n"),
            DNS64 => {
                up = "# cgmon dns_guard: у провайдера сломан IPv4 — DNS64 (обычные серверы вернутся сами)\n".into();
                for s in &self.dns64 {
                    up.push_str(&format!("server {s}\n"));
                }
            }
            _ => {}
        }
        let mut w = Snap::default();
        w.files.insert(self.upstream_file.clone(), up);
        w.files.insert(self.guard_file.clone(), guard);
        for (f, d) in &w.files {
            sys.write_file(f, d, 0o644)?;
        }
        if !self.cache_file.is_empty() {
            sys.remove_file(&self.cache_file); // иначе после перезапуска вернутся старые ответы
        }
        sys.run(&["/etc/init.d/smartdns", "restart"])?;
        sys.run(&["killall", "-HUP", "dnsmasq"])?; // сброс кэша dnsmasq
        Ok(w)
    }
}

// ---- dnsmasq ----

pub struct Dnsmasq {
    pub dns64: Vec<String>,
}

/// Значения в кавычках из вывода uci show.
fn uci_vals(out: &str) -> Vec<String> {
    let mut l = Vec::new();
    let mut rest = out;
    while let Some(i) = rest.find('\'') {
        let r = &rest[i + 1..];
        let Some(j) = r.find('\'') else { break };
        l.push(r[..j].to_string());
        rest = &r[j + 1..];
    }
    l
}

pub fn dnsmasq_servers(sys: &dyn Sys) -> Vec<String> {
    sys.query(&["uci", "-q", "show", "dhcp.@dnsmasq[0].server"]).map(|o| uci_vals(&o)).unwrap_or_default()
}

/// Настройки dnsmasq для состояния поверх обычных.
pub fn dnsmasq_target(state: &str, base: &Snap, dns64: &[String]) -> Snap {
    let mut w = Snap { servers: base.servers.clone(), noresolv: base.noresolv.clone(), filter_aaaa: base.filter_aaaa.clone(), ..Default::default() };
    match state {
        NO_AAAA => w.filter_aaaa = "1".into(),
        DNS64 => {
            // для отдельных доменов (.lan, туннели) — как были
            let mut keep: Vec<String> = base.servers.iter().filter(|s| s.starts_with('/')).cloned().collect();
            for s in dns64 {
                let s = match crate::netx::split_host_port(s) {
                    Some((h, p)) => format!("{}#{}", h.trim_matches(['[', ']']), p),
                    None => s.clone(),
                };
                keep.push(s);
            }
            w.servers = keep;
            w.noresolv = "1".into();
        }
        _ => {}
    }
    w
}

/// Команды uci, приводящие dnsmasq к w.
pub fn dnsmasq_cmds(w: &Snap) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut c = vec![s(&["uci", "-q", "delete", "dhcp.@dnsmasq[0].server"])];
    for x in &w.servers {
        c.push(vec!["uci".into(), "add_list".into(), format!("dhcp.@dnsmasq[0].server={x}")]);
    }
    for (k, v) in [("noresolv", &w.noresolv), ("filter_aaaa", &w.filter_aaaa)] {
        if v.is_empty() {
            c.push(vec!["uci".into(), "-q".into(), "delete".into(), format!("dhcp.@dnsmasq[0].{k}")]);
        } else {
            c.push(vec!["uci".into(), "set".into(), format!("dhcp.@dnsmasq[0].{k}={v}")]);
        }
    }
    c.push(s(&["uci", "commit", "dhcp"]));
    c.push(s(&["/etc/init.d/dnsmasq", "restart"]));
    c
}

impl Backend for Dnsmasq {
    fn name(&self) -> String {
        "dnsmasq".into()
    }
    fn read(&self, sys: &dyn Sys) -> Result<Snap, String> {
        Ok(Snap {
            servers: dnsmasq_servers(sys),
            noresolv: sys.query(&["uci", "-q", "get", "dhcp.@dnsmasq[0].noresolv"]).unwrap_or_default(),
            filter_aaaa: sys.query(&["uci", "-q", "get", "dhcp.@dnsmasq[0].filter_aaaa"]).unwrap_or_default(),
            ..Default::default()
        })
    }
    fn write(&self, sys: &dyn Sys, state: &str, base: &Snap) -> Result<Snap, String> {
        let w = dnsmasq_target(state, base, &self.dns64);
        run_cmds(sys, &dnsmasq_cmds(&w))?;
        Ok(w)
    }
}

/// auto: SmartDNS, если он и правда обслуживает DNS и подготовлен; иначе dnsmasq.
pub fn choose_backend(c: &DNSGuardConfig, sys: &dyn Sys) -> (Arc<dyn Backend>, String) {
    let (b, hint) = choose_dns(c, sys);
    (Arc::new(WithRa { inner: b, on: c.withdraw_ra }), hint)
}

fn choose_dns(c: &DNSGuardConfig, sys: &dyn Sys) -> (Box<dyn Backend>, String) {
    let smart = || -> Box<dyn Backend> { Box::new(SmartDns { upstream_file: c.upstream_file.clone(), guard_file: c.guard_file.clone(), cache_file: c.cache_file.clone(), dns64: c.dns64_servers.clone() }) };
    let dm = || -> Box<dyn Backend> { Box::new(Dnsmasq { dns64: c.dns64_servers.clone() }) };
    // сборка без SmartDNS (lite, nano) — только dnsmasq
    if !crate::variant::SMARTDNS {
        return (dm(), String::new());
    }
    match c.backend.as_str() {
        "smartdns" => return (smart(), String::new()),
        "dnsmasq" => return (dm(), String::new()),
        _ => {}
    }
    if sys.query(&["pidof", "smartdns"]).unwrap_or_default().is_empty() {
        return (dm(), String::new());
    }
    let port = sys.query(&["uci", "-q", "get", "smartdns.@smartdns[0].port"]).unwrap_or_default();
    let used = dnsmasq_servers(sys).iter().any(|s| *s == format!("127.0.0.1#{port}") || *s == format!("::1#{port}"));
    if !used || port.is_empty() {
        return (dm(), String::new());
    }
    let inc = dgsys::includes(sys);
    if !inc.contains(&c.upstream_file) || !inc.contains(&c.guard_file) {
        return (dm(), format!("SmartDNS работает, но в его custom.conf нет строк «conf-file {}» и «conf-file {}» (вышестоящие серверы — в первом файле); пока через dnsmasq — при DNS64 запросы пойдут мимо SmartDNS", c.upstream_file, c.guard_file));
    }
    (smart(), String::new())
}

/// Какое состояние DNS просит диагноз ("" — данных нет).
pub fn signal(phase: &str, diag: &str) -> &'static str {
    match diag {
        "IPV6_DEGRADATION" => NO_AAAA,
        "IPV4_EXTERNAL_DEGRADATION" if phase == "WARNING" || phase == "CRITICAL" => DNS64,
        "HEALTHY" => NORMAL,
        _ => "",
    }
}

pub fn text(state: &str) -> &'static str {
    match state {
        NO_AAAA => "DNS: клиентам отдаем только IPv4 адрес, у провайдера деградация IPv6",
        DNS64 => "DNS: клиентам отдаем IPv6 адреса через DNS64, у провайдера деградация IPv4",
        _ => "DNS: обычные настройки восстановлены",
    }
}

/// state_file (dgSaved).
#[derive(Clone, Debug, Default)]
pub struct Saved {
    pub backend: String,
    pub baseline: Snap,
    pub state: String,
    pub written: Snap,
    pub since: i64,
}

/// Итог фоновой задачи.
pub enum Done {
    Live(String),
    Switch { at: i64, sig: String, was_ra: bool, res: Result<Snap, String>, live: String },
    Rollback { at: i64, msg: String, was_ra: bool, res: Result<(), String> },
    Test(crate::dgtarget::Test),
    Health(crate::dgroute::PathHealth),
    Targets { content: String, res: Result<(), String> },
}

/// Сколько раз проверять ответы DNS после переключения (тесты — 1).
pub static VERIFY_TRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(5);

pub struct DnsGuard {
    pub cfg: DNSGuardConfig,
    pub sys: Arc<dyn Sys>,
    pub backend: Option<Arc<dyn Backend>>,
    pub saved: Saved,
    pub since: i64,
    pub want: String,
    want_from: i64,
    want_at: i64,
    pub check_at: i64,
    switched: i64,
    harm_from: i64,
    pub blocked: HashMap<String, i64>,
    pub live: String,
    pub err: String,
    started: bool,
    hinted: bool,
    /// выбор backend (тесты подменяют)
    pub chooser: Option<Box<dyn Fn(&DNSGuardConfig) -> (Arc<dyn Backend>, String)>>,
    /// фоновые задачи выполняются сразу (тесты)
    pub sync_jobs: bool,
    busy: bool,
    tx: Sender<Done>,
    rx: Receiver<Done>,
    pub inbox: Vec<Done>,
    /// адрес WAN для проб IPv6
    pub v6src: Option<IpAddr>,

    // адресный режим (dgtarget.rs)
    pub targets: BTreeMap<String, crate::dgtarget::Target>,
    pub t_loaded: bool,
    pub t_results: Vec<crate::dgtarget::Test>,
    pub t_eval_at: i64,
    pub t_written: String,
    pub t_applied: i64,
    pub t_urgent: bool,
    pub t_err: String,
    pub t_writing: bool,

    // обход (dgroute.rs)
    pub r_paths: BTreeMap<String, crate::dgroute::Path>,
    pub r_idx: BTreeMap<String, u32>,
    pub r_at: i64,
    pub r_label_at: i64,
    pub r_label_map: Option<HashMap<String, String>>,
    pub r_table: String,
    pub r_nets: String,
    pub r_err: String,
    pub r_cleaned: bool,
    pub r_health: Vec<crate::dgroute::PathHealth>,
    pub r_usage: crate::dgroute::Usage,
    pub r_usage_saved: i64,
    pub r_last: Option<HashMap<String, u64>>,
    pub r_ips: HashMap<String, i64>,
    pub r_ips_at: i64,
    /// LAN-сети и «не-интернет» сети для overlay-шлюза (catch-all весь трафик через туннель)
    pub r_lan: Vec<crate::netx::IpNet>,
    pub r_excl: Vec<crate::netx::IpNet>,
    /// последняя быстрая проба overlay-пути
    pub r_ov_at: i64,
    /// начало непрерывного молчания overlay-туннеля (0 — отвечает)
    pub r_ov_fail: i64,

    // отказ в IPv6 (dgv6.rs)
    pub v6_all: i64,
    pub v6_bad_from: i64,
    pub v6_good_from: i64,
    pub v6_devs: Option<Vec<String>>,
    pub v6_devs_at: i64,
    pub v6_written: String,
    pub v6_cleaned: bool,
}

impl DnsGuard {
    pub fn new(cfg: DNSGuardConfig, sys: Arc<dyn Sys>) -> DnsGuard {
        let (tx, rx) = channel();
        let mut g = DnsGuard {
            cfg: DNSGuardConfig::default(),
            sys,
            backend: None,
            saved: Saved { state: NORMAL.into(), ..Default::default() },
            since: 0,
            want: String::new(),
            want_from: 0,
            want_at: 0,
            check_at: 0,
            switched: 0,
            harm_from: 0,
            blocked: HashMap::new(),
            live: String::new(),
            err: String::new(),
            started: false,
            hinted: false,
            chooser: None,
            sync_jobs: false,
            busy: false,
            tx,
            rx,
            inbox: Vec::new(),
            v6src: None,
            targets: BTreeMap::new(),
            t_loaded: false,
            t_results: Vec::new(),
            t_eval_at: 0,
            t_written: String::new(),
            t_applied: 0,
            t_urgent: false,
            t_err: String::new(),
            t_writing: false,
            r_paths: BTreeMap::new(),
            r_idx: BTreeMap::new(),
            r_at: 0,
            r_label_at: 0,
            r_label_map: None,
            r_table: String::new(),
            r_nets: String::new(),
            r_err: String::new(),
            r_cleaned: false,
            r_health: Vec::new(),
            r_usage: Default::default(),
            r_usage_saved: 0,
            r_last: None,
            r_ips: HashMap::new(),
            r_ips_at: 0,
            r_lan: Vec::new(),
            r_excl: Vec::new(),
            r_ov_at: 0,
            r_ov_fail: 0,
            v6_all: 0,
            v6_bad_from: 0,
            v6_good_from: 0,
            v6_devs: None,
            v6_devs_at: 0,
            v6_written: String::new(),
            v6_cleaned: false,
        };
        g.set_config(cfg);
        g
    }

    /// Включение/смена настроек: при переходе из off или смене backend — снять обычные заново.
    pub fn set_config(&mut self, c: DNSGuardConfig) {
        if self.cfg.mode == "off" || self.cfg.backend != c.backend {
            self.started = false;
        }
        // смена маршрутных настроек (overlay «весь трафик», обход, реле, лимиты) — пересобрать
        // маршруты на следующем тике, не ждать периодической переоценки (CHECK_EVERY = 60 с)
        if self.cfg.overlay != c.overlay || self.cfg.alternatives != c.alternatives || self.cfg.relays != c.relays || self.cfg.metered != c.metered {
            self.r_at = 0;
            self.r_table.clear();
        }
        self.cfg = c;
    }

    /// Режим, в котором страховка правда меняет DNS.
    pub fn acts(&self) -> bool {
        self.cfg.mode == "active" || self.cfg.mode == "targeted"
    }

    /// Фоновая задача: поток (тесты — сразу).
    pub fn spawn(&mut self, f: impl FnOnce(&dyn Sys) -> Done + Send + 'static) {
        if self.sync_jobs {
            let d = f(&*self.sys);
            self.deliver(d);
            return;
        }
        let (tx, sys) = (self.tx.clone(), self.sys.clone());
        let r = std::thread::Builder::new().name("cgmon-dg".into()).stack_size(256 << 10).spawn(move || {
            let _ = tx.send(f(&*sys));
        });
        if let Err(e) = r {
            crate::log_err!("dns guard: thread: {}", e);
        }
    }

    fn deliver(&mut self, d: Done) {
        match d {
            Done::Test(t) => self.t_results.push(t),
            Done::Health(h) => self.r_health.push(h),
            d => self.inbox.push(d),
        }
    }

    /// Готовые фоновые задачи: переключения, запись файла, ответы DNS.
    fn collect(&mut self, now: i64) -> Vec<String> {
        while let Ok(d) = self.rx.try_recv() {
            self.deliver(d);
        }
        let mut msgs = Vec::new();
        for d in std::mem::take(&mut self.inbox) {
            match d {
                Done::Live(s) => self.live = s,
                Done::Switch { at, sig, was_ra, res, live } => {
                    self.busy = false;
                    msgs.extend(self.switch_done(at, &sig, was_ra, res, live));
                }
                Done::Rollback { at, msg, was_ra, res } => {
                    self.busy = false;
                    msgs.extend(self.rollback_done(at, msg, was_ra, res));
                }
                Done::Targets { content, res } => {
                    self.t_writing = false;
                    match res {
                        Ok(()) => {
                            if self.cfg.mode != "targeted" || self.targets_conf() == content {
                                self.t_urgent = false;
                            }
                            self.t_written = content;
                        }
                        Err(e) => {
                            self.err = format!("адресный режим: {e}");
                            msgs.push(format!("DNS-страховка (адресно): не удалось записать {}: {}", self.cfg.targets_file, e));
                        }
                    }
                }
                Done::Test(_) | Done::Health(_) => {}
            }
        }
        let _ = now;
        msgs
    }

    /// Объявление IPv6-шлюза снято (записано ra_lifetime=0 там, где обычно не 0).
    pub fn ra_off(&self) -> bool {
        if !self.acts() || self.saved.state == NORMAL {
            return false;
        }
        self.saved.written.ra.iter().any(|(k, v)| v == "0" && self.saved.baseline.ra.get(k).map(|x| x.as_str()) != Some("0"))
    }

    fn detect_live(&mut self) {
        self.spawn(|sys| Done::Live(sys.live_state()));
    }

    /// Выбрать backend, прочитать фактические настройки и сохранённое.
    fn start(&mut self, now: i64) -> Vec<String> {
        let mut msgs = Vec::new();
        self.started = true;
        self.since = now;
        self.check_at = now;
        let (b, hint) = match &self.chooser {
            Some(f) => f(&self.cfg),
            None => choose_backend(&self.cfg, &*self.sys),
        };
        self.backend = Some(b.clone());
        if !hint.is_empty() && !self.hinted {
            self.hinted = true;
            msgs.push(format!("DNS-страховка: {hint}"));
        }
        let cur = match b.read(&*self.sys) {
            Ok(c) => c,
            Err(e) => {
                self.err = e;
                return msgs;
            }
        };
        let file = self.sys.read_file(&self.cfg.state_file).and_then(|t| parse_json(&t).ok());
        if let Some(v) = &file {
            if !self.t_loaded {
                if let Some(Value::Map(m)) = v.get("targets") {
                    self.targets = crate::dgtarget::load(m); // штрафы и ступени переживают перезапуск
                    self.t_loaded = true;
                }
            }
            if let Some(u) = v.get("usage").filter(|u| !matches!(u, Value::Null)) {
                self.r_usage = crate::dgroute::Usage::from(u); // расход лимитированных путей за день
            }
        }
        let sv = file.as_ref().map(|v| Saved { backend: vstr(v, "backend"), baseline: Snap::from(v.get("baseline")), state: vstr(v, "state"), written: Snap::from(v.get("written")), since: time_parse(v.get("since")) }).unwrap_or_default();
        if file.is_some() && sv.backend == b.name() && sv.state != NORMAL && !sv.state.is_empty() && cur.same(&sv.written) {
            // на диске ровно то, что cgmon записал в аварию: продолжаем с этого состояния
            if sv.since != 0 {
                self.since = sv.since;
            }
            let st = sv.state.clone();
            self.saved = sv;
            msgs.push(format!("DNS-страховка: при старте DNS в аварийном режиме ({}) — обычные настройки вернутся, когда провайдер будет в норме", text(&st)));
            if self.ra_off() {
                msgs.push(format!("{} (действует с {})", RA_TEXT, hhmm(self.since)));
            }
        } else {
            // иначе текущие настройки и есть обычные
            self.saved = Saved { backend: b.name(), baseline: cur, state: NORMAL.into(), ..Default::default() };
        }
        self.persist();
        self.detect_live();
        self.targets_check();
        msgs
    }

    /// Раз в минуту: правки пользователя.
    fn recheck(&mut self, now: i64) -> Vec<String> {
        self.check_at = now;
        self.targets_check();
        let Some(b) = self.backend.clone() else { return Vec::new() };
        let Ok(cur) = b.read(&*self.sys) else { return Vec::new() };
        // наблюдение ничего не пишет: состояние там «на бумаге», сверяем с обычными
        if self.saved.state == NORMAL || !self.acts() {
            if !cur.same(&self.saved.baseline) {
                self.saved.baseline = cur;
                self.persist();
                crate::log_info!("dns guard: настройки DNS изменены — сохранены как обычные");
            }
            return Vec::new();
        }
        if !cur.same(&self.saved.written) {
            // во время аварии настройки поменяли вручную — это и есть новые обычные
            self.saved = Saved { backend: b.name(), baseline: cur, state: NORMAL.into(), ..Default::default() };
            self.since = now;
            self.persist();
            self.detect_live();
            return vec!["DNS-страховка: настройки DNS изменены вручную во время аварийного режима — приняты как обычные".into()];
        }
        Vec::new()
    }

    pub fn persist(&self) {
        if self.cfg.state_file.is_empty() || crate::util::readonly() {
            return;
        }
        let (mut state, mut written) = (self.saved.state.clone(), self.saved.written.clone());
        if !self.acts() {
            // в наблюдении аварийный режим только «на бумаге»
            state = NORMAL.into();
            written = Snap::default();
        }
        let mut j = J::new();
        j.obj().key("backend").str(&self.saved.backend).key("baseline");
        self.saved.baseline.json(&mut j);
        j.key("state").str(&state).key("written");
        written.json(&mut j);
        if self.saved.since != 0 {
            j.key("since").str(&time_json(self.saved.since));
        }
        if !self.targets.is_empty() {
            j.key("targets").obj();
            for (k, t) in &self.targets {
                j.key(k);
                t.json(&mut j);
            }
            j.end_obj();
        }
        if !self.r_usage.day.is_empty() {
            j.key("usage");
            self.r_usage.json(&mut j);
        }
        j.end_obj();
        if let Err(e) = crate::util::write_atomic(&self.cfg.state_file, j.b.as_bytes(), 0o600) {
            crate::log_err!("dns guard: {}: {}", self.cfg.state_file, e);
        }
    }

    /// Такт (лёгкий блок, после оценки здоровья): сообщения в журнал.
    pub fn tick(&mut self, now: i64, phase: &str, diag: &str, h: &Health, feed: &mut dyn Feed) -> Vec<String> {
        let mut msgs = self.collect(now);
        if self.cfg.mode == "off" {
            if !self.t_written.is_empty() {
                self.targets_apply(now); // адресный режим выключили — запреты снять
            }
            self.route_teardown();
            self.v6_all = 0;
            self.v6_apply(now);
            return msgs;
        }
        if !self.v6_cleaned {
            // остаток после падения cgmon (отказ всем IPv6) — снять
            self.v6_cleaned = true;
            let _ = self.sys.nft(&format!("add table inet {t}\ndelete table inet {t}\n", t = crate::dgv6::TABLE));
        }
        if !self.started {
            msgs.extend(self.start(now));
        } else if !self.busy && now - self.check_at >= CHECK_EVERY {
            msgs.extend(self.recheck(now));
        }
        let targeted = self.cfg.mode == "targeted";
        if targeted || !self.t_written.is_empty() {
            if targeted {
                msgs.extend(self.route_tick(now, feed)); // пути обхода — до решений по владельцам
            }
            msgs.extend(self.targets_tick(now, h.v6_avail, feed));
        }
        if !targeted {
            self.route_teardown();
        }
        msgs.extend(self.v6_tick(now, h));
        if self.busy || self.backend.is_none() {
            return msgs; // переключение ещё идёт
        }
        let state = self.saved.state.clone();

        // «не навреди»: протокол, на который ушли клиенты, стал плохим (не полный обрыв канала)
        let harm = !h.outage && ((state == NO_AAAA && !h.v4_ok) || (state == DNS64 && !h.v6_ok));
        if !harm {
            self.harm_from = 0;
        } else if self.harm_from == 0 {
            self.harm_from = now;
        } else if now - self.harm_from >= self.cfg.v4_enter_sec * 1000 {
            msgs.extend(self.rollback(now, &state));
            return msgs;
        }

        let mut sig = signal(phase, diag);
        if targeted {
            // адресно: общий режим — только когда и свидетели видят плохим весь протокол
            if sig == NO_AAAA && (h.wit_v6 == "ok" || h.wit_v6 == "degraded") || sig == DNS64 && (h.wit_v4 == "ok" || h.wit_v4 == "degraded") {
                sig = NORMAL;
            }
        }
        if sig == DNS64 && !h.v6_ok {
            sig = ""; // без живого IPv6 DNS64 оставил бы клиентов без DNS
        }
        if let Some(until) = self.blocked.get(sig) {
            if now < *until {
                sig = ""; // недавно не помогло — не включать
            }
        }
        if sig.is_empty() || sig == state {
            self.want.clear();
            self.want_from = 0;
            self.want_at = 0;
            return msgs;
        }
        if sig != self.want {
            self.want = sig.into();
            self.want_from = now;
        }
        let escape = state == DNS64; // IPv4 снова в порядке — из DNS64 быстро
        let need = if escape || sig == DNS64 {
            self.cfg.v4_enter_sec
        } else if sig == NO_AAAA {
            self.cfg.v6_enter_sec
        } else {
            self.cfg.recover_sec
        } * 1000;
        self.want_at = self.want_from + need;
        if !escape && self.switched != 0 && self.switched + DWELL > self.want_at {
            self.want_at = self.switched + DWELL;
        }
        if now - self.want_from < need {
            return msgs;
        }
        if !escape && self.switched != 0 && now - self.switched < DWELL {
            return msgs;
        }

        if self.cfg.mode == "observe" {
            msgs.push(format!("DNS-страховка (наблюдение): сделал бы — {}", text(sig)));
            self.saved.state = sig.into(); // виртуально: чтобы не повторять
            self.since = now;
            self.switched = now;
            self.want.clear();
            self.want_from = 0;
            self.want_at = 0;
            self.check_at = now;
            return msgs;
        }
        let b = self.backend.clone().unwrap();
        let base = self.saved.baseline.clone();
        let was_ra = self.ra_off();
        let sig_s = sig.to_string();
        self.busy = true;
        self.spawn(move |sys| {
            let res = b.write(sys, &sig_s, &base);
            let mut live = String::new();
            if res.is_ok() {
                // после переключения DNS перезапускается: несколько попыток
                let tries = VERIFY_TRIES.load(std::sync::atomic::Ordering::Relaxed);
                for i in 0..tries {
                    live = sys.live_state();
                    if live == sig_s {
                        break;
                    }
                    if i + 1 < tries {
                        sys.sleep(1000);
                    }
                }
            }
            Done::Switch { at: now, sig: sig_s, was_ra, res, live }
        });
        if self.sync_jobs {
            msgs.extend(self.collect(now));
        }
        msgs
    }

    fn switch_done(&mut self, now: i64, sig: &str, was_ra: bool, res: Result<Snap, String>, live: String) -> Vec<String> {
        let w = match res {
            Ok(w) => w,
            Err(e) => {
                crate::log_err!("dns guard: {}: {}", sig, e);
                self.err = e.clone();
                self.want_from = now; // повторить через тот же срок
                return vec![format!("DNS-страховка: не удалось переключить ({sig}): {e}")];
            }
        };
        self.err.clear();
        self.saved.state = sig.into();
        self.saved.written = if sig == NORMAL { Snap::default() } else { w };
        self.saved.since = now;
        self.persist();
        let mut msg = text(sig).to_string();
        // DHCP — отдельной записью журнала (тип dhcp_guard)
        let ra_msg = if self.ra_off() {
            RA_TEXT
        } else if was_ra {
            RA_BACK
        } else {
            ""
        };
        self.live = live;
        if self.live != sig && !self.live.is_empty() {
            msg.push_str(&format!(" (проверка: DNS отвечает как «{}»)", self.live));
        }
        let mut msgs = vec![msg];
        if !ra_msg.is_empty() {
            msgs.push(ra_msg.into());
        }
        self.since = now;
        self.switched = now;
        self.want.clear();
        self.want_from = 0;
        self.want_at = 0;
        self.check_at = now;
        msgs
    }

    /// Аварийный режим навредил: обычные настройки, режим заблокирован на BLOCK_FOR.
    fn rollback(&mut self, now: i64, bad: &str) -> Vec<String> {
        let what = if bad == DNS64 { "IPv6" } else { "IPv4" };
        self.blocked.insert(bad.into(), now + BLOCK_FOR);
        self.harm_from = 0;
        self.want.clear();
        self.want_from = 0;
        self.want_at = 0;
        let mut msg = format!("DNS-страховка не помогла: после переключения стал плохим {what} — обычные настройки DNS, этот режим не включится ещё 1h0m0s");
        let was_ra = self.ra_off();
        if self.acts() {
            let b = self.backend.clone().unwrap();
            let base = self.saved.baseline.clone();
            self.busy = true;
            self.spawn(move |sys| Done::Rollback { at: now, msg, was_ra, res: b.write(sys, NORMAL, &base).map(|_| ()) });
            if self.sync_jobs {
                return self.collect(now);
            }
            return Vec::new();
        }
        msg = format!("DNS-страховка (наблюдение): {msg}");
        self.rollback_done(now, msg, was_ra, Ok(()))
    }

    fn rollback_done(&mut self, now: i64, msg: String, was_ra: bool, res: Result<(), String>) -> Vec<String> {
        if self.acts() {
            if let Err(e) = res {
                self.err = e.clone();
                return vec![format!("DNS-страховка: не удалось вернуть обычные настройки: {e}")];
            }
            self.err.clear();
            self.saved.written = Snap::default();
        }
        self.saved.state = NORMAL.into();
        self.persist();
        self.since = now;
        self.switched = now;
        self.check_at = now;
        if was_ra {
            return vec![msg, RA_BACK.into()];
        }
        vec![msg]
    }

    /// Статус для страницы (None — выключена).
    pub fn status_json(&self, j: &mut J) -> bool {
        if self.cfg.mode == "off" {
            return false;
        }
        j.obj().key("mode").str(&self.cfg.mode).key("backend").str(&self.backend.as_ref().map(|b| b.name()).unwrap_or_default()).key("state").str(&self.saved.state);
        if !self.live.is_empty() {
            j.key("live").str(&self.live);
        }
        if self.since != 0 {
            j.key("since").str(&time_json(self.since));
        }
        if !self.want.is_empty() {
            j.key("want").str(&self.want);
        }
        if !self.want.is_empty() && self.want_at != 0 {
            j.key("want_at").str(&time_json(self.want_at));
            if self.want == NO_AAAA && self.cfg.withdraw_ra && self.acts() {
                j.key("ra_will").bool(true);
            }
        }
        if !self.err.is_empty() {
            j.key("error").str(&self.err);
        }
        if self.ra_off() {
            j.key("ra_off").bool(true);
        }
        if self.cfg.mode == "targeted" {
            self.targets_json(j);
            if !self.t_err.is_empty() {
                j.key("targets_error").str(&self.t_err);
            }
            self.paths_json(j);
            if !self.r_err.is_empty() {
                j.key("route_error").str(&self.r_err);
            }
            let via = match self.check_path() {
                Some(p) => self.path_label(&p.id),
                None if self.cfg.check_via == crate::livecfg::DGR_PROTO => "IPv6 (без IPv4)".into(),
                None => "напрямую".into(),
            };
            j.key("check_via").str(&via);
            if !self.cfg.check_via.is_empty() {
                j.key("check_mode").str(&self.cfg.check_via);
            }
            if !self.cfg.check_domains.is_empty() {
                j.key("check_domains").arr();
                for d in &self.cfg.check_domains {
                    j.str(d);
                }
                j.end_arr();
            }
        }
        if self.v6_all != 0 {
            j.key("v6_reject_all").str(&time_json(self.v6_all));
        }
        if self.cfg.mode == "targeted" {
            let n = self.v6_bad().len();
            if n > 0 {
                j.key("v6_rejected").int(n as i64);
            }
        }
        j.end_obj();
        true
    }

    #[cfg(test)]
    pub fn want_at(&self) -> i64 {
        self.want_at
    }
}

/// ЧЧ:ММ местного времени.
pub fn hhmm(ms: i64) -> String {
    let t = crate::util::local(ms.div_euclid(1000));
    format!("{:02}:{:02}", t.hour, t.min)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    /// «Роутер» для тестов: файлы, ответы команд, что записывали.
    #[derive(Default)]
    pub struct FakeSys {
        pub files: Mutex<HashMap<String, String>>,
        pub runs: Mutex<Vec<String>>,
        pub nfts: Mutex<Vec<String>>,
        pub queries: Mutex<HashMap<String, String>>,
        pub probe: Mutex<Option<Box<dyn Fn(&[IpAddr], usize, u32) -> (usize, f64) + Send>>>,
        pub bulk_ok: Mutex<Option<(bool, i64)>>,
        pub counters: Mutex<HashMap<String, u64>>,
    }

    impl Sys for FakeSys {
        fn run(&self, args: &[&str]) -> Result<String, String> {
            self.runs.lock().unwrap().push(args.join(" "));
            Ok(String::new())
        }
        fn query(&self, args: &[&str]) -> Result<String, String> {
            let k = args.join(" ");
            self.queries.lock().unwrap().get(&k).cloned().ok_or_else(|| "нет".to_string())
        }
        fn read_file(&self, p: &str) -> Option<String> {
            self.files.lock().unwrap().get(p).cloned()
        }
        fn write_file(&self, p: &str, d: &str, _: u32) -> Result<(), String> {
            self.files.lock().unwrap().insert(p.into(), d.into());
            Ok(())
        }
        fn remove_file(&self, p: &str) {
            self.files.lock().unwrap().remove(p);
        }
        fn nft(&self, s: &str) -> Result<(), String> {
            self.nfts.lock().unwrap().push(s.into());
            Ok(())
        }
        fn counters(&self, _: &str) -> HashMap<String, u64> {
            self.counters.lock().unwrap().clone()
        }
        fn probe(&self, ips: &[IpAddr], n: usize, mark: u32, _: Option<IpAddr>) -> (usize, f64) {
            match &*self.probe.lock().unwrap() {
                Some(f) => f(ips, n, mark),
                None => (n, 40.0),
            }
        }
        fn resolve(&self, _: &str, _: &str) -> Vec<IpAddr> {
            Vec::new()
        }
        fn bulk(&self, _: &str, _: &IpAddr, _: &dgsys::Alt) -> (bool, i64) {
            self.bulk_ok.lock().unwrap().unwrap_or((true, -1))
        }
        fn live_state(&self) -> String {
            String::new()
        }
        fn leaks(&self, _: &str, _: &str) -> bool {
            false
        }
        fn sleep(&self, _: u64) {}
    }

    /// Backend «роутера»: текущие настройки и что в них писали.
    pub struct FakeDg {
        pub name: &'static str,
        pub cur: Mutex<Snap>,
        pub writes: Mutex<Vec<String>>,
        pub fail: bool,
        pub ra: bool,
    }

    impl Backend for FakeDg {
        fn name(&self) -> String {
            self.name.into()
        }
        fn read(&self, _: &dyn Sys) -> Result<Snap, String> {
            Ok(self.cur.lock().unwrap().clone())
        }
        fn write(&self, _: &dyn Sys, state: &str, base: &Snap) -> Result<Snap, String> {
            if self.fail {
                return Err("сбой".into());
            }
            let mut w = dnsmasq_target(state, base, &["2001:db8::64".to_string()]);
            if self.ra {
                w.ra = ra_target(state, &base.ra, true);
            }
            *self.cur.lock().unwrap() = w.clone();
            self.writes.lock().unwrap().push(state.into());
            Ok(w)
        }
    }

    pub fn user() -> Snap {
        Snap { servers: vec!["127.0.0.1#5399".into(), "/lan/127.0.0.1".into()], noresolv: "1".into(), filter_aaaa: "0".into(), ..Default::default() }
    }

    pub fn fake(name: &'static str) -> Arc<FakeDg> {
        Arc::new(FakeDg { name, cur: Mutex::new(user()), writes: Mutex::new(Vec::new()), fail: false, ra: false })
    }

    pub fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("cgmon-dg-{}-{}", std::process::id(), name));
        let _ = std::fs::create_dir_all(&d);
        let f = d.join("dnsguard.json").to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&f);
        f
    }

    pub fn guard(mode: &str, f: Arc<FakeDg>, state_file: &str) -> (DnsGuard, Arc<FakeSys>) {
        VERIFY_TRIES.store(1, std::sync::atomic::Ordering::Relaxed);
        let mut c = crate::config::defaults().dns_guard;
        c.mode = mode.into();
        c.state_file = state_file.into();
        let sys = Arc::new(FakeSys::default());
        // файл состояния — настоящий (persist пишет через util::write_atomic)
        let real = std::fs::read_to_string(state_file).ok();
        if let Some(t) = real {
            sys.files.lock().unwrap().insert(state_file.into(), t);
        }
        let mut g = DnsGuard::new(c, sys.clone());
        g.sync_jobs = true;
        let fb = f.clone();
        g.chooser = Some(Box::new(move |_| (fb.clone() as Arc<dyn Backend>, String::new())));
        (g, sys)
    }

    pub fn h(phase: &str, diag: &str) -> Health {
        match diag {
            "IPV6_DEGRADATION" => Health { v4_ok: true, ..Default::default() },
            "IPV4_EXTERNAL_DEGRADATION" => Health { v6_ok: true, ..Default::default() },
            "UNKNOWN" => Health { outage: phase == "CRITICAL", ..Default::default() },
            _ => Health { v4_ok: true, v6_ok: true, ..Default::default() },
        }
    }

    /// Прогон: phase/diag каждые 10 с в течение sec.
    pub fn steps_h(g: &mut DnsGuard, t0: i64, sec: i64, phase: &str, diag: &str, hh: &Health) -> (i64, Vec<String>) {
        let mut all = Vec::new();
        let mut i = 0;
        while i < sec {
            all.extend(g.tick(t0 + i * 1000, phase, diag, hh, &mut NoFeed));
            i += 10;
        }
        (t0 + sec * 1000, all)
    }

    pub fn steps(g: &mut DnsGuard, t0: i64, sec: i64, phase: &str, diag: &str) -> (i64, Vec<String>) {
        let hh = h(phase, diag);
        steps_h(g, t0, sec, phase, diag, &hh)
    }

    const T0: i64 = 1_000_000;

    #[test]
    fn no_aaaa_and_back() {
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("a"));
        let (now, _) = steps(&mut g, T0, 120, "NORMAL", "HEALTHY");
        let (now, m) = steps(&mut g, now, 290, "NORMAL", "IPV6_DEGRADATION");
        assert!(f.writes.lock().unwrap().is_empty() && m.is_empty(), "рано: {m:?}");
        let (now, m) = steps(&mut g, now, 30, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(f.writes.lock().unwrap().len(), 1);
        assert_eq!(f.cur.lock().unwrap().filter_aaaa, "1");
        assert!(m.len() == 1 && m[0].contains("IPv6"), "{m:?}");
        let (now, _) = steps(&mut g, now, 590, "NORMAL", "HEALTHY");
        assert_eq!(g.saved.state, NO_AAAA, "вернулся раньше recover_sec");
        steps(&mut g, now, 30, "NORMAL", "HEALTHY");
        assert_eq!(g.saved.state, NORMAL);
        assert!(f.cur.lock().unwrap().same(&user()));
    }

    #[test]
    fn no_internet_holds_and_flapping() {
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("b"));
        let (now, _) = steps(&mut g, T0, 400, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NO_AAAA);
        let (now, _) = steps(&mut g, now, 3600, "CRITICAL", "UNKNOWN");
        let (now, _) = steps(&mut g, now, 300, "NORMAL", "MONITORING_ONLY");
        let (now, _) = steps(&mut g, now, 60, "NORMAL", "LOCAL_PRESSURE");
        assert!(g.saved.state == NO_AAAA && f.writes.lock().unwrap().len() == 1);
        steps(&mut g, now, 610, "NORMAL", "HEALTHY");
        assert!(g.saved.state == NORMAL && f.writes.lock().unwrap().len() == 2);
        // мигает около порога — не включается
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("b2"));
        let mut now = T0;
        for _ in 0..30 {
            now = steps(&mut g, now, 120, "NORMAL", "IPV6_DEGRADATION").0;
            now = steps(&mut g, now, 20, "NORMAL", "HEALTHY").0;
        }
        assert!(f.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn dns64_fast_escape() {
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("c"));
        let (now, _) = steps(&mut g, T0, 70, "CRITICAL", "IPV4_EXTERNAL_DEGRADATION");
        assert_eq!(g.saved.state, DNS64);
        assert_eq!(f.cur.lock().unwrap().servers.join(" "), "/lan/127.0.0.1 2001:db8::64");
        let (now, _) = steps(&mut g, now, 70, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NORMAL, "выход из DNS64");
        steps(&mut g, now, 620, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NO_AAAA);
        assert_eq!(signal("NORMAL", "IPV4_EXTERNAL_DEGRADATION"), "");
        assert!(g.blocked.contains_key(DNS64));
    }

    #[test]
    fn user_edits_and_restart() {
        let f = fake("fake");
        let file = tmp("d");
        let _ = std::fs::remove_file(&file);
        let (mut g, _) = guard("active", f.clone(), &file);
        let (now, _) = steps(&mut g, T0, 20, "NORMAL", "HEALTHY");
        let edited = Snap { servers: vec!["127.0.0.1#5300".into()], noresolv: "1".into(), filter_aaaa: "0".into(), ..Default::default() };
        *f.cur.lock().unwrap() = edited.clone();
        let (now, _) = steps(&mut g, now, 70, "NORMAL", "HEALTHY");
        assert!(g.saved.baseline.same(&edited));
        let (now, _) = steps(&mut g, now, 610, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NO_AAAA);
        // перезапуск: на диске ровно записанное — продолжить
        let (mut g2, _) = guard("active", f.clone(), &file);
        let m = g2.tick(now, "NORMAL", "IPV6_DEGRADATION", &Health { v4_ok: true, ..Default::default() }, &mut NoFeed);
        assert!(g2.saved.state == NO_AAAA && g2.saved.baseline.same(&edited) && m.len() == 1, "{m:?}");
        // ручная правка в аварии
        let manual = Snap { servers: vec!["9.9.9.9".into()], noresolv: "1".into(), ..Default::default() };
        *f.cur.lock().unwrap() = manual.clone();
        let (_, m) = steps(&mut g, now, 70, "NORMAL", "IPV6_DEGRADATION");
        assert!(g.saved.state == NORMAL && g.saved.baseline.same(&manual) && m.iter().any(|x| x.contains("вручную")), "{m:?}");
    }

    #[test]
    fn observe_fail_off() {
        let f = fake("fake");
        let (mut g, _) = guard("observe", f.clone(), &tmp("e"));
        let (_, m) = steps(&mut g, T0, 400, "NORMAL", "IPV6_DEGRADATION");
        assert!(f.writes.lock().unwrap().is_empty() && m.len() == 1 && m[0].contains("наблюдение"), "{m:?}");
        let f = Arc::new(FakeDg { name: "fake", cur: Mutex::new(user()), writes: Mutex::new(Vec::new()), fail: true, ra: false });
        let (mut g, _) = guard("active", f, &tmp("e2"));
        let (_, m) = steps(&mut g, T0, 400, "NORMAL", "IPV6_DEGRADATION");
        assert!(g.saved.state == NORMAL && m.first().map_or(false, |x| x.contains("не удалось")), "{m:?}");
        let (mut g, _) = guard("off", fake("fake"), &tmp("e3"));
        assert!(g.tick(T0, "NORMAL", "IPV6_DEGRADATION", &Health::default(), &mut NoFeed).is_empty());
        assert!(!g.status_json(&mut J::new()));
    }

    #[test]
    fn dnsmasq_cmds_text() {
        let base = Snap { servers: vec!["127.0.0.1#5300".into(), "/zzz/100.100.100.100".into()], filter_aaaa: "0".into(), ..Default::default() };
        let w = dnsmasq_target(DNS64, &base, &["2001:67c:2960::64".into(), "[2001:db8::1]:5353".into()]);
        let got: String = dnsmasq_cmds(&w).iter().map(|c| c.join(" ") + "\n").collect();
        assert_eq!(
            got,
            "uci -q delete dhcp.@dnsmasq[0].server\nuci add_list dhcp.@dnsmasq[0].server=/zzz/100.100.100.100\nuci add_list dhcp.@dnsmasq[0].server=2001:67c:2960::64\nuci add_list dhcp.@dnsmasq[0].server=2001:db8::1#5353\nuci set dhcp.@dnsmasq[0].noresolv=1\nuci set dhcp.@dnsmasq[0].filter_aaaa=0\nuci commit dhcp\n/etc/init.d/dnsmasq restart\n"
        );
    }

    #[test]
    fn do_no_harm_and_outage() {
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("f"));
        let (now, _) = steps(&mut g, T0, 310, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NO_AAAA);
        let (now, m) = steps_h(&mut g, now, 70, "WARNING", "UNKNOWN", &Health::default());
        assert!(g.saved.state == NORMAL && f.cur.lock().unwrap().same(&user()) && m.len() == 1 && m[0].contains("не помогла"), "{m:?}");
        let (now, _) = steps(&mut g, now, 3000, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NORMAL, "включился во время блока");
        steps(&mut g, now, 1000, "NORMAL", "IPV6_DEGRADATION");
        assert_eq!(g.saved.state, NO_AAAA);
        // полный обрыв — не откат
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("f2"));
        let (now, _) = steps(&mut g, T0, 310, "NORMAL", "IPV6_DEGRADATION");
        steps_h(&mut g, now, 1800, "CRITICAL", "UNKNOWN", &Health { outage: true, ..Default::default() });
        assert!(g.saved.state == NO_AAAA && f.writes.lock().unwrap().len() == 1);
        // DNS64 без живого IPv6 — не включать
        let f = fake("fake");
        let (mut g, _) = guard("active", f.clone(), &tmp("f3"));
        steps_h(&mut g, T0, 600, "CRITICAL", "IPV4_EXTERNAL_DEGRADATION", &Health::default());
        assert!(g.saved.state == NORMAL && f.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn ra_parse_and_withdraw() {
        let out = "dhcp.lan=dhcp\ndhcp.lan.ra='server'\ndhcp.lan.ra_lifetime='1800'\ndhcp.guest.ra='server'\ndhcp.wan.ra='disabled'\ndhcp.wan.ra_lifetime='0'\n";
        let ra = dgsys::ra_parse(out);
        assert!(ra.len() == 2 && ra["lan"] == "1800" && ra["guest"].is_empty(), "{ra:?}");
        let w = ra_target(NO_AAAA, &ra, true);
        assert!(w["lan"] == "0" && w["guest"] == "0");
        assert_eq!(ra_target(NO_AAAA, &ra, false)["lan"], "1800");
        let c = ra_cmds(&ra_target(NORMAL, &ra, true));
        assert_eq!(c[0].join(" "), "uci -q delete dhcp.guest.ra_lifetime");
        assert_eq!(c[1].join(" "), "uci set dhcp.lan.ra_lifetime=1800");
        assert_eq!(c[c.len() - 1].join(" "), "/etc/init.d/odhcpd reload");
        // backend с RA: в no_aaaa ra_lifetime=0, потом как было
        let mut u = user();
        u.ra.insert("lan".into(), String::new());
        let f = Arc::new(FakeDg { name: "fake", cur: Mutex::new(u), writes: Mutex::new(Vec::new()), fail: false, ra: true });
        let (mut g, _) = guard("active", f.clone(), &tmp("g"));
        let (now, m) = steps(&mut g, T0, 320, "NORMAL", "IPV6_DEGRADATION");
        assert!(f.cur.lock().unwrap().ra["lan"] == "0" && g.ra_off() && m.len() == 2 && m[1].starts_with("DHCP:"), "{m:?}");
        let (_, m) = steps(&mut g, now, 700, "NORMAL", "HEALTHY");
        assert!(f.cur.lock().unwrap().ra["lan"].is_empty() && !g.ra_off() && m.len() == 2 && m[1].contains("снова"), "{m:?}");
    }

    #[test]
    fn want_at_and_since() {
        let f = fake("fake");
        let file = tmp("h");
        let _ = std::fs::remove_file(&file);
        let (mut g, _) = guard("active", f.clone(), &file);
        g.cfg.withdraw_ra = true;
        let (now, _) = steps(&mut g, T0, 100, "NORMAL", "IPV6_DEGRADATION");
        assert!(g.saved.state == NORMAL && g.want == NO_AAAA && g.want_at() == T0 + 300_000);
        let mut j = J::new();
        g.status_json(&mut j);
        assert!(j.b.contains("\"ra_will\":true"), "{}", j.b);
        let (now, _) = steps(&mut g, now, 250, "NORMAL", "IPV6_DEGRADATION");
        assert!(g.saved.state == NO_AAAA && g.want.is_empty() && g.since != 0);
        let since = g.since;
        let (mut g2, _) = guard("active", f.clone(), &file);
        g2.tick(now + 3_600_000, "NORMAL", "MONITORING_ONLY", &Health { v4_ok: true, ..Default::default() }, &mut NoFeed);
        assert_eq!(g2.since, since, "время после перезапуска");
    }
}
