//! Резервный канал — gate selector (перенос gatesel.go): пробы через каждый
//! WAN-интерфейс (SO_BINDTODEVICE, в общем epoll), оценки, переключение
//! маршрута по умолчанию (`ip route replace`, метрика в UCI), ремонт
//! интерфейса через ubus/ifup (в потоке: ожидание разборки до 10 с).
//! Шлюзы — gate_selector.interfaces или зона wan из UCI; из конструктора путей
//! (from_alternatives) — основной + отмеченные устройства.

use crate::config::{Config, GateIfaceConfig};
use crate::evloop::Poller;
use crate::json::J;
use crate::probe::{Kind, Outcome, Probe};
use crate::topo::parse_uci;
use std::collections::HashMap;
use std::net::SocketAddr;

struct State {
    cfg: GateIfaceConfig,
    link_up: bool,
    has_v4: bool,
    has_v6: bool,
    ubus_up: bool,
    ubus_pending: bool,
    ubus_errors: usize,
    s4: f64,
    s6: f64,
    score: f64,
    v4res: Vec<(u64, bool)>,
    v6res: Vec<(u64, bool)>,
    pending_since: u64,
    no_ip_since: u64,
    repairs: Vec<u64>,
    consecutive: i64,
    backoff_until: u64,
    grace_until: u64,
    want_up: bool,
}

/// Сообщение для движка: событие ленты и (если есть) запись журнала.
pub struct Msg {
    pub journal: &'static str,
    pub text: String,
}

pub struct GateSelector {
    ifaces: Vec<State>,
    active: String,
    last_switch: u64,
    last_propose: u64,
    last_propose_key: String,
    degraded_recorded: bool,
    fail_since: u64,
    failback_since: u64,
    ubus_counter: i64,
    events: Vec<(i64, String, String)>,
    backups_key: String,
    inited: bool,
    /// когда собран список шлюзов (при одном — пересборка раз в 5 мин)
    init_at: u64,
    pub next_eval: u64,
    pub next_probe: u64,
    round: Option<(u64, HashMap<u64, (usize, bool, Probe)>)>,
    tok_base: u64,
    next_tok: u64,
}

fn backups_key(c: &Config) -> String {
    format!("{} {:?}", c.gate_selector.from_alternatives, c.gate_selector.backups)
}

fn ubus_dump() -> String {
    std::process::Command::new("ubus").args(["call", "network.interface", "dump"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Сети зоны wan из /etc/config/firewall.
fn wan_zone_nets() -> Vec<String> {
    let fw = parse_uci(&std::fs::read_to_string("/etc/config/firewall").unwrap_or_default());
    let mut out: Vec<String> = Vec::new();
    for s in fw.iter().filter(|s| s.typ == "zone" && s.opt("name") == "wan") {
        // network — список или строка через пробел (firewall3)
        for v in s.values("network") {
            out.extend(v.split_whitespace().map(String::from));
        }
    }
    out
}

/// Протоколы, которые дают выход в интернет (резервный канал может быть и выключен).
const UPLINK_PROTO: &[&str] = &["pppoe", "pppoa", "dhcp", "3g", "qmi", "ncm", "mbim", "wwan", "modemmanager", "directip", "l2tp", "pptp"];

/// Шлюзы по netifd (`ubus call network.interface dump`): интерфейс с маршрутом по
/// умолчанию (то, что реально даёт интернет сейчас) или интерфейс зоны wan вида
/// PPPoE/DHCP/LTE (резерв, который может лежать). Устройство — l3_device
/// (pppoe-wan, а не vlan10 под ним). Не шлюзы: туннели (tailscale, zerotier, wg —
/// их маршруты в своих таблицах), IPv6-спутники (dhcpv6), запасная настройка на
/// порту, который уже занят живым интерфейсом (DHCP «local» на том же VLAN, что и
/// PPPoE). Основной — живой с наименьшей метрикой.
pub fn gates_from_netifd(dump: &str, wan_nets: &[String]) -> Vec<GateIfaceConfig> {
    use crate::value::{parse_json, Value};
    let Ok(v) = parse_json(dump) else { return Vec::new() };
    let Some(Value::List(l)) = v.get("interface") else { return Vec::new() };
    let s = |i: &Value, k: &str| crate::dnsguard::vstr(i, k);
    let num = |i: &Value, k: &str| i.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
    // (имя, устройство L3, порт под ним, поднят, есть маршрут по умолчанию, метрика)
    let mut c: Vec<(String, String, String, bool, bool, i64)> = Vec::new();
    for i in l {
        let (name, proto) = (s(i, "interface"), s(i, "proto"));
        let up = i.get("up").and_then(|x| x.as_bool()).unwrap_or(false);
        let (l3, port) = (s(i, "l3_device"), s(i, "device"));
        let mut def_metric = None;
        if let Some(Value::List(rs)) = i.get("route") {
            for r in rs {
                if s(r, "target") == "0.0.0.0" && num(r, "mask") == 0 {
                    def_metric = Some(num(r, "metric"));
                }
            }
        }
        if name == "loopback" || matches!(proto.as_str(), "none" | "dhcpv6" | "6in4" | "6to4" | "6rd" | "dslite" | "wireguard" | "map") {
            continue;
        }
        let dev = if !l3.is_empty() {
            l3
        } else if proto == "pppoe" || proto == "pppoa" {
            format!("{proto}-{name}")
        } else {
            port.clone()
        };
        if dev.is_empty() || crate::netx::is_tunnel_dev(&dev) {
            continue;
        }
        let wan_uplink = wan_nets.contains(&name) && UPLINK_PROTO.contains(&proto.as_str());
        if def_metric.is_none() && !wan_uplink {
            continue;
        }
        let metric = def_metric.unwrap_or(0).max(num(i, "metric"));
        c.push((name, dev, port, up, def_metric.is_some() && up, metric));
    }
    // запасная настройка того же порта (выключена, порт занят живым шлюзом) — не шлюз
    let live_ports: Vec<String> = c.iter().filter(|x| x.3 && !x.2.is_empty()).map(|x| x.2.clone()).collect();
    c.retain(|x| x.3 || !live_ports.contains(&x.2));
    // живые с маршрутом — по метрике первыми, потом остальные
    c.sort_by_key(|x| (!x.4, x.5));
    c.into_iter()
        .enumerate()
        .map(|(n, (name, device, _, _, _, metric))| GateIfaceConfig { name, device, priority: n as i64 + 1, metric: if metric > 0 { metric } else if n == 0 { 10 } else { 20 } })
        .collect()
}

/// Шлюзы: из конфига или сами (netifd; без ubus — по зоне wan в UCI).
pub fn detect(cfg: &Config) -> Vec<GateIfaceConfig> {
    let gs = &cfg.gate_selector;
    let dump = ubus_dump();
    if !gs.interfaces.is_empty() {
        let found = gates_from_netifd(&dump, &wan_zone_nets());
        return gs.interfaces.iter().enumerate().map(|(i, ic)| {
            let mut ic = ic.clone();
            if ic.priority <= 0 {
                ic.priority = i as i64 + 1;
            }
            if ic.metric <= 0 {
                ic.metric = if ic.priority == 1 { 10 } else { 20 };
            }
            // устройство из конфига пропало (LTE-модем переехал с eth3 на VLAN) —
            // нынешнее устройство интерфейса с тем же именем
            if !std::path::Path::new(&format!("/sys/class/net/{}", ic.device)).exists() {
                if let Some(f) = found.iter().find(|f| f.name == ic.name) {
                    crate::log_info!("gate: {}: device {} is gone, using {}", ic.name, ic.device, f.device);
                    ic.device = f.device.clone();
                }
            }
            ic
        }).collect();
    }
    let out = gates_from_netifd(&dump, &wan_zone_nets());
    if !out.is_empty() || !dump.is_empty() {
        return out;
    }
    let wan_nets = wan_zone_nets();
    let nw = parse_uci(&std::fs::read_to_string("/etc/config/network").unwrap_or_default());
    let mut out = Vec::new();
    let mut prio = 1;
    for name in &wan_nets {
        for s in nw.iter().filter(|s| s.typ == "interface") {
            let sname = if s.name.is_empty() { s.opt("name").to_string() } else { s.name.clone() };
            if sname != *name {
                continue;
            }
            let mut dev = s.opt("device").to_string();
            if dev.is_empty() {
                dev = s.opt("ifname").to_string();
            }
            if dev.is_empty() {
                dev = name.clone();
            }
            let mut metric: i64 = s.opt("metric").parse().unwrap_or(0);
            if metric <= 0 {
                metric = if prio == 1 { 10 } else { 20 };
            }
            out.push(GateIfaceConfig { name: sname, device: dev, priority: prio, metric });
            prio += 1;
        }
    }
    out
}

/// Шлюзы из конструктора путей: `backups` задаёт порядок целиком — первый = основной
/// (приоритет 1), дальше резервы. Туннели и ретрансляторы не берутся. Пустой список —
/// авто (основной с наименьшим приоритетом). Физический авто-основной всегда присутствует
/// как фолбэк связности, даже если его не перетащили в список.
pub fn apply_backups(list: Vec<GateIfaceConfig>, backups: &[String], labels: &HashMap<String, String>) -> Vec<GateIfaceConfig> {
    let Some(auto_main) = list.iter().min_by_key(|c| c.priority).cloned() else { return list };
    let base = auto_main.metric.max(10);
    let want: Vec<&String> = backups.iter().filter(|d| !crate::netx::is_tunnel_dev(d) && !d.starts_with('@') && crate::livecfg::path_id_ok(d)).collect();
    if want.is_empty() {
        let mut m = auto_main;
        m.priority = 1;
        return vec![m];
    }
    let mut out: Vec<GateIfaceConfig> = Vec::new();
    for dev in want {
        if out.iter().any(|g| &g.device == dev) {
            continue;
        }
        let mut ic = list.iter().find(|c| &c.device == dev).cloned().unwrap_or_else(|| GateIfaceConfig { name: labels.get(dev).cloned().unwrap_or_default(), device: dev.clone(), priority: 0, metric: 0 });
        if ic.name.is_empty() {
            ic.name = dev.clone();
        }
        ic.priority = out.len() as i64 + 1;
        ic.metric = if out.is_empty() { base } else { base + 5 * out.len() as i64 };
        out.push(ic);
    }
    // авто-основной (физический uplink) обязан присутствовать — иначе можно остаться без связи
    if !out.iter().any(|g| g.device == auto_main.device) {
        let mut m = auto_main;
        m.priority = out.len() as i64 + 1;
        m.metric = base + 5 * out.len() as i64;
        out.push(m);
    }
    out
}

/// Устройство маршрута по умолчанию с наименьшей метрикой (/proc/net/route).
fn default_dev() -> String {
    let Ok(t) = std::fs::read_to_string("/proc/net/route") else { return String::new() };
    let mut best = (String::new(), i64::MAX);
    for l in t.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000" {
            let m: i64 = f[6].parse().unwrap_or(0);
            if m < best.1 {
                best = (f[0].to_string(), m);
            }
        }
    }
    best.0
}

fn rate(marks: &[(u64, bool)], window: u64, now: u64) -> f64 {
    let l: Vec<&(u64, bool)> = marks.iter().filter(|m| now - m.0 <= window).collect();
    if l.is_empty() {
        return -1.0;
    }
    l.iter().filter(|m| m.1).count() as f64 / l.len() as f64 * 100.0
}

fn ip_bin() -> &'static str {
    for c in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if std::fs::symlink_metadata(c).map_or(false, |m| !m.file_type().is_symlink()) {
            return c;
        }
    }
    "ip"
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    if crate::util::readonly() {
        return Ok(String::new());
    }
    let o = std::process::Command::new(cmd).args(args).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("exit status {}: {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Шлюз по умолчанию на устройстве (via), если есть.
fn default_via(dev: &str) -> Option<String> {
    let o = std::process::Command::new(ip_bin()).args(["route", "list"]).output().ok()?;
    for l in String::from_utf8_lossy(&o.stdout).lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.first() != Some(&"default") || !f.windows(2).any(|w| w[0] == "dev" && w[1] == dev) {
            continue;
        }
        if let Some(w) = f.windows(2).find(|w| w[0] == "via") {
            return Some(w[1].to_string());
        }
    }
    None
}

/// ubus network.interface.<name> status: (up, pending, ошибок).
fn ubus_status(name: &str) -> Option<(bool, bool, usize)> {
    let o = std::process::Command::new("ubus").args(["call", &format!("network.interface.{name}"), "status"]).output().ok()?;
    let v = crate::value::parse_json(&String::from_utf8_lossy(&o.stdout)).ok()?;
    let b = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let errs = match v.get("errors") {
        Some(crate::value::Value::List(l)) => l.len(),
        _ => 0,
    };
    Some((b("up"), b("pending"), errs))
}

/// Ремонт в потоке: down → ждать разборки (≤ 10 с) → up.
fn repair_thread(name: String, method: String) {
    let _ = std::thread::Builder::new().name("cgmon-gate".into()).stack_size(128 << 10).spawn(move || {
        let ctl = |up: bool| {
            let (a, tool) = if up { ("up", "ifup") } else { ("down", "ifdown") };
            if method == "ubus" {
                let _ = run("ubus", &["call", &format!("network.interface.{name}"), a]);
            } else {
                let _ = run(tool, &[&name]);
            }
        };
        ctl(false);
        let t0 = std::time::Instant::now();
        while t0.elapsed().as_secs() < 10 {
            if let Some((up, pending, _)) = ubus_status(&name) {
                if !up && !pending {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        ctl(true);
    });
}

/// При одном шлюзе — как часто искать второй.
const SINGLE_RECHECK: u64 = 300_000;

impl GateSelector {
    pub fn new(tok_base: u64) -> GateSelector {
        GateSelector { ifaces: Vec::new(), active: String::new(), last_switch: 0, last_propose: 0, last_propose_key: String::new(), degraded_recorded: false, fail_since: 0, failback_since: 0, ubus_counter: 0, events: Vec::new(), backups_key: String::new(), inited: false, init_at: 0, next_eval: 0, next_probe: 0, round: None, tok_base, next_tok: 0 }
    }

    pub fn owns(&self, tok: u64) -> bool {
        tok >> 48 == self.tok_base >> 48
    }

    fn dry(cfg: &Config) -> bool {
        cfg.dry_run || cfg.gate_selector.dry_run
    }

    fn init(&mut self, cfg: &Config) {
        let mut list = detect(cfg);
        if cfg.gate_selector.from_alternatives {
            let labels = crate::dgroute::parse_labels(&std::process::Command::new("ubus").args(["call", "network.interface", "dump"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default());
            list = apply_backups(list, &cfg.gate_selector.backups, &labels);
        }
        self.backups_key = backups_key(cfg);
        self.ifaces = list.into_iter().map(|ic| State { want_up: ic.priority == 1, cfg: ic, link_up: false, has_v4: false, has_v6: false, ubus_up: false, ubus_pending: false, ubus_errors: 0, s4: -1.0, s6: -1.0, score: -1.0, v4res: Vec::new(), v6res: Vec::new(), pending_since: 0, no_ip_since: 0, repairs: Vec::new(), consecutive: 0, backoff_until: 0, grace_until: 0 }).collect();
        let dev = default_dev();
        self.active = self.ifaces.iter().find(|s| s.cfg.device == dev).or(self.ifaces.first()).map(|s| s.cfg.name.clone()).unwrap_or_default();
        self.inited = true;
    }

    /// Шлюз один (или ни одного): выбирать не из чего — ни проб, ни оценки;
    /// канал и так проверяют основные пробы через маршрут по умолчанию.
    pub fn single(&self) -> bool {
        self.inited && self.ifaces.len() < 2
    }

    /// Раунд проб: tcp к первым двум целям v4 и первой v6 через каждое устройство.
    pub fn probe_round(&mut self, cfg: &Config, poller: &Poller, now: u64) {
        self.next_probe = now + cfg.gate_selector.probes.interval_sec.max(1) as u64 * 1000;
        if self.single() {
            self.next_probe = self.next_eval.max(now + 1000);
            return;
        }
        if !self.inited || self.round.is_some() {
            return;
        }
        let gp = &cfg.gate_selector.probes;
        let mut flight = HashMap::new();
        for (i, st) in self.ifaces.iter_mut().enumerate() {
            if now < st.grace_until {
                continue;
            }
            let mut targets: Vec<(&String, bool)> = gp.ipv4.iter().take(2).map(|a| (a, false)).collect();
            if st.has_v6 {
                targets.extend(gp.ipv6.iter().take(1).map(|a| (a, true)));
            }
            for (a, v6) in targets {
                let Ok(addr) = a.parse::<SocketAddr>() else {
                    if v6 { st.v6res.push((now, false)) } else { st.v4res.push((now, false)) }
                    continue;
                };
                match Probe::start_dev(Kind::Tcp, addr, None, &st.cfg.device, now) {
                    Ok(p) => {
                        self.next_tok += 1;
                        let tok = self.tok_base | (self.next_tok & 0xffff_ffff);
                        if poller.add(p.fd, p.events(), tok).is_ok() {
                            flight.insert(tok, (i, v6, p));
                        }
                    }
                    Err(_) => {
                        if v6 { st.v6res.push((now, false)) } else { st.v4res.push((now, false)) }
                    }
                }
            }
        }
        self.round = Some((now, flight));
    }

    /// Событие пробы.
    pub fn on_event(&mut self, tok: u64, poller: &Poller, now: u64, cfg: &Config) {
        let Some((_, fl)) = self.round.as_mut() else { return };
        let Some((i, v6, p)) = fl.remove(&tok) else { return };
        poller.del(p.fd);
        let ok = p.finish() == Outcome::Ok;
        let started = p.started;
        if let Some(st) = self.ifaces.get_mut(i) {
            if v6 { st.v6res.push((started, ok)) } else { st.v4res.push((started, ok)) }
        }
        self.finish_round(now, poller, cfg);
    }

    /// Все ответили или таймаут — оценки.
    pub fn finish_round(&mut self, now: u64, poller: &Poller, cfg: &Config) {
        let Some((t0, fl)) = self.round.as_mut() else { return };
        let timeout = cfg.probe_timeout_sec.max(1) as u64 * 1000;
        if !fl.is_empty() && now - *t0 < timeout {
            return;
        }
        let t0 = *t0;
        for (_, (i, v6, p)) in fl.drain() {
            poller.del(p.fd);
            if let Some(st) = self.ifaces.get_mut(i) {
                if v6 { st.v6res.push((t0, false)) } else { st.v4res.push((t0, false)) }
            }
        }
        self.round = None;
        let window = cfg.gate_selector.probes.decision_window_sec.max(1) as u64 * 1000;
        for st in self.ifaces.iter_mut() {
            st.v4res.retain(|m| now - m.0 < 2 * window);
            st.v6res.retain(|m| now - m.0 < 2 * window);
            st.s4 = rate(&st.v4res, window, now);
            st.s6 = rate(&st.v6res, window, now);
            st.score = if st.s4 < 0.0 { -1.0 } else { st.s4 + 0.3 * st.s6.max(0.0) };
        }
    }

    fn event(&mut self, cfg: &Config, typ: &str, msg: String, out: &mut Vec<Msg>, journal: &'static str) {
        let (s, _) = crate::util::now_wall();
        self.events.push((s, typ.to_string(), msg.clone()));
        if self.events.len() > 100 {
            self.events.remove(0);
        }
        crate::log_info!("gate: {}", msg);
        let mut j = J::new();
        j.obj().key("event").str(typ).key("msg").str(&msg).key("time").str(&crate::util::rfc3339_secs(s)).key("type").str("gate_event").end_obj();
        crate::incidents::append_jsonl(&cfg.wan_monitor.incidents_file, &j.b, 2 << 20);
        out.push(Msg { journal, text: msg });
    }

    fn refresh_links(&mut self) {
        self.ubus_counter += 1;
        let ubus = self.ubus_counter >= 5;
        if ubus {
            self.ubus_counter = 0;
        }
        for st in self.ifaces.iter_mut() {
            let flags = std::fs::read_to_string(format!("/sys/class/net/{}/flags", st.cfg.device)).ok().and_then(|s| i64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok());
            let Some(fl) = flags else {
                st.link_up = false;
                st.has_v4 = false;
                st.has_v6 = false;
                continue;
            };
            st.link_up = fl & 1 != 0;
            let addrs = crate::netx::addrs_of(&st.cfg.device);
            st.has_v4 = addrs.iter().any(|(a, _)| a.is_ipv4());
            st.has_v6 = addrs.iter().any(|(a, _)| matches!(a, std::net::IpAddr::V6(x) if x.segments()[0] & 0xffc0 != 0xfe80));
            if ubus {
                if let Some((up, pending, errs)) = ubus_status(&st.cfg.name) {
                    st.ubus_up = up;
                    st.ubus_pending = pending;
                    st.ubus_errors = errs;
                }
            }
        }
    }

    fn switch_to(&mut self, cfg: &Config, target: usize, reason: &str, now: u64, out: &mut Vec<Msg>) {
        let from = self.active.clone();
        let tname = self.ifaces[target].cfg.name.clone();
        if Self::dry(cfg) {
            let key = format!("{tname}/{reason}");
            if self.last_propose_key == key && now - self.last_propose < cfg.gate_selector.switching.cooldown_sec.max(0) as u64 * 1000 {
                return;
            }
            self.last_propose = now;
            self.last_propose_key = key;
            self.event(cfg, "switch", format!("WOULD SWITCH {from} -> {tname} ({reason})"), out, "");
            return;
        }
        let sw = &cfg.gate_selector.switching;
        for (i, st) in self.ifaces.iter().enumerate() {
            let m = if i == target { st.cfg.metric } else { sw.inactive_metric };
            let mut a: Vec<String> = vec!["route".into(), "replace".into(), "default".into()];
            if let Some(via) = default_via(&st.cfg.device) {
                a.extend(["via".into(), via]);
            }
            a.extend(["dev".into(), st.cfg.device.clone(), "metric".into(), m.to_string()]);
            let args: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
            if let Err(e) = run(ip_bin(), &args) {
                crate::log_err!("gate: replace default on {} failed: {}", st.cfg.device, e);
            }
            if sw.sync_uci_metric {
                let _ = run("uci", &["set", &format!("network.{}.metric={m}", st.cfg.name)]);
                let _ = run("uci", &["commit", "network"]);
            }
        }
        self.active = tname.clone();
        self.last_switch = now;
        self.ifaces[target].want_up = true;
        let j = if reason == "failback" { "failback" } else { "failover" };
        self.event(cfg, "switch", format!("SWITCH {from} -> {tname} ({reason})"), out, j);
        for c in &sw.on_switch {
            let _ = run("sh", &["-c", c]);
        }
    }

    fn maybe_repair(&mut self, cfg: &Config, i: usize, now: u64, out: &mut Vec<Msg>) {
        let rp = cfg.gate_selector.repair.clone();
        if !rp.enabled || now < self.ifaces[i].backoff_until {
            return;
        }
        let window = rp.window_sec.max(0) as u64 * 1000;
        if self.ifaces[i].repairs.iter().filter(|t| now - **t <= window).count() as i64 >= rp.max_per_window {
            return;
        }
        let name = self.ifaces[i].cfg.name.clone();
        if self.ifaces[i].ubus_errors > 0 {
            self.ifaces[i].backoff_until = now + rp.auth_fail_pause_sec.max(0) as u64 * 1000;
            self.event(cfg, "repair", format!("auth/padt errors on {name}, pause {}s", rp.auth_fail_pause_sec), out, "");
            return;
        }
        self.event(cfg, "repair", format!("force repair {name} (method={})", rp.method), out, "");
        if !Self::dry(cfg) {
            repair_thread(name, rp.method.clone());
        }
        let st = &mut self.ifaces[i];
        st.consecutive += 1;
        let max = rp.backoff_max_sec.max(0) as u64 * 1000;
        let mut b = rp.backoff_initial_sec.max(0) as u64 * 1000;
        for _ in 1..st.consecutive {
            b *= 2;
            if b > max {
                b = max;
                break;
            }
        }
        st.backoff_until = now + b;
        st.grace_until = now + rp.post_repair_grace_sec.max(0) as u64 * 1000;
        st.repairs.push(now);
        st.repairs.retain(|t| now - *t <= window.max(1));
        st.pending_since = 0;
        st.no_ip_since = 0;
    }

    fn best(&self, active: usize, min: f64) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, st) in self.ifaces.iter().enumerate() {
            if i == active || !st.link_up || !st.has_v4 || st.score < min {
                continue;
            }
            if best.map_or(true, |b| st.score > self.ifaces[b].score) {
                best = Some(i);
            }
        }
        best
    }

    /// Оценка (evaluation_interval_sec): g4/g6 — общие пробы за окно решения.
    pub fn evaluate(&mut self, cfg: &Config, now: u64, g4: f64, g6: f64) -> Vec<Msg> {
        self.next_eval = now + cfg.gate_selector.evaluation_interval_sec.max(1) as u64 * 1000;
        let mut out = Vec::new();
        if !self.inited || backups_key(cfg) != self.backups_key || (self.single() && now - self.init_at >= SINGLE_RECHECK) {
            self.init(cfg); // резервные шлюзы поменяли на странице — пересобрать
            self.init_at = now;
        }
        if self.single() {
            if self.ifaces.len() == 1 {
                self.active = self.ifaces[0].cfg.name.clone();
            }
            self.next_eval = self.init_at + SINGLE_RECHECK; // появится второй WAN — проснёмся
            return out;
        }
        let gs = cfg.gate_selector.clone();
        self.refresh_links();
        if self.ifaces.is_empty() {
            return out;
        }
        // маршрут по умолчанию мог поменять netifd (переподключение, руками)
        let real = default_dev();
        if !real.is_empty() {
            if let Some(st) = self.ifaces.iter().find(|s| s.cfg.device == real && s.cfg.name != self.active) {
                crate::log_info!("gate: sync active {} -> {} (external route change)", self.active, st.cfg.name);
                self.active = st.cfg.name.clone();
                self.fail_since = 0;
                self.failback_since = 0;
                self.degraded_recorded = false;
            }
        }
        let active = match self.ifaces.iter().position(|s| s.cfg.name == self.active) {
            Some(i) => i,
            None => {
                self.active = self.ifaces[0].cfg.name.clone();
                0
            }
        };
        let primary = self.ifaces.iter().position(|s| s.cfg.priority == 1);
        // зависшие состояния и ремонт
        for i in 0..self.ifaces.len() {
            if !self.ifaces[i].want_up && self.ifaces[i].cfg.priority != 1 {
                continue;
            }
            let name = self.ifaces[i].cfg.name.clone();
            if self.ifaces[i].ubus_pending {
                if self.ifaces[i].pending_since == 0 {
                    self.ifaces[i].pending_since = now;
                } else if now - self.ifaces[i].pending_since >= gs.repair.setup_stuck_sec.max(0) as u64 * 1000 {
                    self.event(cfg, "stuck", format!("{name} stuck in setup >= {}s", gs.repair.setup_stuck_sec), &mut out, "");
                    self.maybe_repair(cfg, i, now, &mut out);
                    self.ifaces[i].pending_since = 0;
                }
            } else {
                self.ifaces[i].pending_since = 0;
            }
            if self.ifaces[i].link_up && !self.ifaces[i].has_v4 {
                if self.ifaces[i].no_ip_since == 0 {
                    self.ifaces[i].no_ip_since = now;
                } else if now - self.ifaces[i].no_ip_since >= gs.repair.no_ip_stuck_sec.max(0) as u64 * 1000 {
                    self.event(cfg, "stuck", format!("{name} link up but no ipv4 >= {}s", gs.repair.no_ip_stuck_sec), &mut out, "");
                    self.maybe_repair(cfg, i, now, &mut out);
                    self.ifaces[i].no_ip_since = 0;
                }
            } else {
                self.ifaces[i].no_ip_since = 0;
            }
            if self.ifaces[i].score >= gs.thresholds.ok_score {
                self.ifaces[i].consecutive = 0;
            }
        }
        let th = &gs.thresholds;
        // A: линк активного упал
        if !self.ifaces[active].link_up || !self.ifaces[active].has_v4 {
            if let Some(c) = self.best(active, th.ok_score) {
                self.switch_to(cfg, c, "link_down", now, &mut out);
            }
            return out;
        }
        // B: активный деградировал
        let a = &self.ifaces[active];
        if a.score >= 0.0 && a.score < th.bad_score {
            if self.fail_since == 0 {
                self.fail_since = now;
            }
            if now - self.fail_since >= th.fail_hold_sec.max(0) as u64 * 1000 {
                if !self.degraded_recorded {
                    self.degraded_recorded = true;
                    let a = &self.ifaces[active];
                    out.push(Msg { journal: "wan_degradation", text: format!("{} s4={:.0} s6={:.0}", a.cfg.name, a.s4, a.s6) });
                }
                let cand = self.best(active, th.ok_score);
                let (ascore, alink, as4) = (self.ifaces[active].score, self.ifaces[active].link_up, self.ifaces[active].s4);
                match cand {
                    Some(c) if self.ifaces[c].score - ascore >= th.margin => {
                        self.switch_to(cfg, c, "degraded", now, &mut out);
                        if alink && as4 < th.bad_score {
                            self.maybe_repair(cfg, active, now, &mut out);
                        }
                        self.fail_since = 0;
                        self.degraded_recorded = false;
                    }
                    _ if alink && as4 < th.bad_score => self.maybe_repair(cfg, active, now, &mut out),
                    _ => {}
                }
            }
        } else {
            self.fail_since = 0;
            self.degraded_recorded = false;
        }
        // C: v4 умер, v6 жив
        let a = &self.ifaces[active];
        if g4 < th.bad_score && g6 >= th.ok_score && a.s4 >= 0.0 && a.s4 < th.bad_score && a.s6 >= th.ok_score {
            if let Some(c) = self.best(active, th.ok_score).filter(|c| self.ifaces[*c].s4 >= th.ok_score) {
                self.switch_to(cfg, c, "v4_outage", now, &mut out);
            }
            self.maybe_repair(cfg, active, now, &mut out);
        }
        // D: возврат на основной
        if let Some(p) = primary.filter(|p| gs.switching.prefer_primary && *p != active) {
            let cooldown_ok = now - self.last_switch >= gs.switching.cooldown_sec.max(0) as u64 * 1000 || self.last_switch == 0;
            let ps = &self.ifaces[p];
            if cooldown_ok && ps.link_up && ps.has_v4 && ps.score >= th.failback_score {
                if self.failback_since == 0 {
                    self.failback_since = now;
                }
                if now - self.failback_since >= th.failback_hold_sec.max(0) as u64 * 1000 {
                    self.switch_to(cfg, p, "failback", now, &mut out);
                    if self.ifaces[active].cfg.priority != 1 {
                        self.ifaces[active].want_up = false;
                        if Self::dry(cfg) {
                            crate::log_info!("gate DRY-RUN: would ifdown {}", self.ifaces[active].cfg.name);
                        } else {
                            let (n, m) = (self.ifaces[active].cfg.name.clone(), gs.repair.method.clone());
                            if m == "ubus" {
                                let _ = run("ubus", &["call", &format!("network.interface.{n}"), "down"]);
                            } else {
                                let _ = run("ifdown", &[&n]);
                            }
                        }
                    }
                    self.failback_since = 0;
                }
            } else {
                self.failback_since = 0;
            }
        }
        out
    }

    /// Шторм переподключений сразу после переключения: ограничителю пауза.
    pub fn post_switch_grace(&self, cfg: &Config, now: u64) -> bool {
        let g = cfg.gate_selector.switching.post_switch_grace_sec;
        g > 0 && self.last_switch != 0 && now - self.last_switch < g as u64 * 1000
    }

    /// Активный шлюз и резервный ли он (для отчёта на центр сбора).
    pub fn link(&self) -> Option<(String, bool)> {
        let prim = self.ifaces.iter().min_by_key(|s| s.cfg.priority)?;
        let act = self.ifaces.iter().find(|s| s.cfg.name == self.active)?;
        Some((act.cfg.name.clone(), act.cfg.name != prim.cfg.name))
    }

    pub fn status_json(&self, j: &mut J) {
        let r1 = |v: f64| crate::config::go_float((v * 10.0).round() / 10.0);
        let prim = self.ifaces.iter().min_by_key(|s| s.cfg.priority).map(|s| s.cfg.name.clone()).unwrap_or_default();
        if self.single() {
            j.key("gate_single").bool(true);
        }
        j.key("gate");
        if self.ifaces.is_empty() || self.single() {
            j.raw("null");
        } else {
            j.arr();
            for st in &self.ifaces {
                j.obj().key("name").str(&st.cfg.name).key("device").str(&st.cfg.device).key("link").bool(st.link_up).key("has_ipv4").bool(st.has_v4).key("has_ipv6").bool(st.has_v6);
                j.key("s4").raw(&r1(st.s4)).key("s6").raw(&r1(st.s6)).key("score").raw(&r1(st.score)).key("pending").bool(st.ubus_pending).key("active").bool(st.cfg.name == self.active);
                if st.cfg.name == prim {
                    j.key("primary").bool(true);
                }
                j.end_obj();
            }
            j.end_arr();
        }
        j.key("gate_events");
        if self.events.is_empty() {
            j.raw("null");
        } else {
            j.arr();
            for (t, typ, msg) in self.events.iter().rev().take(30).rev() {
                j.obj().key("time").str(&crate::util::rfc3339(*t, 0)).key("type").str(typ).key("msg").str(msg).end_obj();
            }
            j.end_arr();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netifd_gates() {
        // PPPoE на vlan10, LTE на vlan20, «local» — выключенный DHCP на том же vlan10
        let dump = r#"{"interface":[
            {"interface":"wan","up":true,"proto":"pppoe","device":"vlan10","l3_device":"pppoe-wan","metric":10,"route":[{"target":"0.0.0.0","mask":0,"nexthop":"198.51.100.1","metric":10}]},
            {"interface":"dvr","up":true,"proto":"static","device":"vlan30","l3_device":"vlan30","metric":0,"route":[]},
            {"interface":"local","up":false,"proto":"dhcp","device":"vlan10","route":[]},
            {"interface":"loopback","up":true,"proto":"static","l3_device":"lo"},
            {"interface":"mobile","up":true,"proto":"static","device":"vlan20-mobile","l3_device":"vlan20-mobile","metric":15,"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.168.8.1","metric":15}]},
            {"interface":"wan_6","up":false,"proto":"dhcpv6","device":"pppoe-wan"},
            {"interface":"tailscale","up":true,"proto":"none","l3_device":"tailscale0"},
            {"interface":"zerotier","up":true,"proto":"static","l3_device":"ztugaszbw5","route":[]}]}"#;
        let wan: Vec<String> = ["INTERNET", "mobile", "local", "wan_6"].iter().map(|x| x.to_string()).collect();
        let g = gates_from_netifd(dump, &wan);
        let names: Vec<(&str, &str, i64)> = g.iter().map(|x| (x.name.as_str(), x.device.as_str(), x.priority)).collect();
        assert_eq!(names, vec![("wan", "pppoe-wan", 1), ("mobile", "vlan20-mobile", 2)]);
        // один PPPoE, «wan»/«wan6» на том же eth1 выключены — шлюз один
        let dump = r#"{"interface":[{"interface":"wan","up":true,"proto":"pppoe","device":"eth1","l3_device":"pppoe-wan","route":[{"target":"0.0.0.0","mask":0,"metric":0}]},
            {"interface":"wan","up":false,"proto":"dhcp","device":"eth1"},{"interface":"wan6","up":false,"proto":"dhcpv6","device":"eth1"}]}"#;
        let wan: Vec<String> = ["wan", "wan6", "INTERNET"].iter().map(|x| x.to_string()).collect();
        assert_eq!(gates_from_netifd(dump, &wan).len(), 1);
        // резервный LTE лежит (порт свой) — всё равно шлюз, вторым
        let dump = r#"{"interface":[{"interface":"wan","up":true,"proto":"dhcp","device":"eth0","l3_device":"eth0","route":[{"target":"0.0.0.0","mask":0,"metric":5}]},
            {"interface":"lte","up":false,"proto":"qmi","device":"wwan0"}]}"#;
        let wan: Vec<String> = ["wan", "lte"].iter().map(|x| x.to_string()).collect();
        let g = gates_from_netifd(dump, &wan);
        assert_eq!((g.len(), g[1].device.as_str(), g[0].priority), (2, "wwan0", 1));
    }

    #[test]
    fn backups_from_constructor() {
        let list = vec![GateIfaceConfig { name: "wan".into(), device: "pppoe-wan".into(), priority: 1, metric: 10 }];
        let mut labels = HashMap::new();
        labels.insert("eth3".to_string(), "mobile".to_string());
        // порядок задаёт backups: eth3 первым → он основной (приоритет 1); туннели/реле отброшены;
        // физический авто-основной pppoe-wan добавлен фолбэком в конец
        let out = apply_backups(list.clone(), &["eth3".into(), "tailscale0".into(), "@node".into()], &labels);
        assert_eq!(out.len(), 2);
        assert!(out[0].name == "mobile" && out[0].device == "eth3" && out[0].priority == 1 && out[0].metric == 10, "{:?}", out[0]);
        assert!(out[1].device == "pppoe-wan" && out[1].priority == 2 && out[1].metric == 15, "{:?}", out[1]);
        // пустой список — авто-основной
        let auto = apply_backups(list, &[], &labels);
        assert!(auto.len() == 1 && auto[0].device == "pppoe-wan" && auto[0].priority == 1, "{:?}", auto);
    }
}
