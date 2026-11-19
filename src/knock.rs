//! Стук (port-knocking): доступ к роутеру и пробросы открываются тому адресу, что
//! «постучал» — прислал ping нужных размеров по порядку (`ping -s 100`, `-s 100`, `-s 122`).
//! Ping есть везде (телефон, ПК), отдельный клиент не нужен.
//!
//! Своя таблица `inet cgmon_knock`:
//! * цепочка input: эхо-запросы с разрешённых интерфейсов (WAN IPv4/IPv6, ZeroTier, Tailscale) —
//!   в цепочку стука; каждый шаг держит адрес в своём наборе `step_sec`, последний —
//!   кладёт его в `open4/open6` на `open_min` минут; неверный размер — сброс;
//! * цепочка pre (dstnat): открытому адресу порты роутера переводятся на его LAN-адрес
//!   (SSH обычно слушает только LAN — так он доступен и с WAN/ZeroTier/Tailscale), пробросы —
//!   на устройства LAN. Такие соединения помечаются битом `MARK`;
//! * в цепочки fw4 input/forward вставляется «помеченное — пропустить» (fw4 после перезагрузки
//!   файрвола их теряет — проверка раз в 30 с возвращает).

use crate::config::KnockConfig;
use std::net::Ipv4Addr;

pub const TABLE: &str = "cgmon_knock";
/// бит метки пакета «открыто стуком» (не пересекается с метками tailscale 0xff0000 и PBR 0x100)
pub const MARK: u32 = 0x0800_0000;
const FW4_TAG: &str = "!cgmon: knock";

/// Проброс после стука: «порты=адрес[:порт]», напр. `3389,5650=192.168.1.201`, `8080=192.168.1.5:80`.
#[derive(Clone, Debug, PartialEq)]
pub struct Fwd {
    pub ports: Vec<u16>,
    pub ip: Ipv4Addr,
    pub to_port: Option<u16>,
}

pub fn parse_forward(s: &str) -> Option<Fwd> {
    let (ports, dst) = s.trim().split_once('=')?;
    let ports: Vec<u16> = ports.split(',').map(|p| p.trim().parse::<u16>().ok().filter(|p| *p > 0)).collect::<Option<Vec<_>>>()?;
    if ports.is_empty() || ports.len() > 16 {
        return None;
    }
    let (ip, to_port) = match dst.trim().split_once(':') {
        Some((ip, p)) => (ip, Some(p.parse::<u16>().ok().filter(|p| *p > 0)?)),
        None => (dst.trim(), None),
    };
    let ip: Ipv4Addr = ip.parse().ok()?;
    if !crate::netx::is_private4(ip.octets()) {
        return None; // пробросы — только в свою сеть
    }
    if to_port.is_some() && ports.len() != 1 {
        return None; // «порт:порт» — только для одного порта
    }
    Some(Fwd { ports, ip, to_port })
}

/// Шаг стука: ping заданного размера данных, TCP SYN или UDP на порт.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    Ping(i64),
    Tcp(u16),
    Udp(u16),
}

/// «ping:100» (или просто «100»), «tcp:7000», «udp:8000».
pub fn parse_step(s: &str) -> Option<Step> {
    let s = s.trim().to_ascii_lowercase();
    let (kind, v) = s.split_once(':').unwrap_or(("ping", s.as_str()));
    match kind {
        "ping" | "icmp" => v.parse::<i64>().ok().filter(|n| (16..=1400).contains(n)).map(Step::Ping),
        "tcp" => v.parse::<u16>().ok().filter(|p| *p > 0).map(Step::Tcp),
        "udp" => v.parse::<u16>().ok().filter(|p| *p > 0).map(Step::Udp),
        _ => None,
    }
}

/// Шаги из настроек: `steps`, а если пусто — старое `sizes` (только ping).
pub fn steps(c: &KnockConfig) -> Vec<Step> {
    if !c.steps.is_empty() {
        return c.steps.iter().filter_map(|s| parse_step(s)).collect();
    }
    c.sizes.iter().filter(|n| (16..=1400).contains(*n)).map(|n| Step::Ping(*n)).collect()
}

/// Имя устройства: буквы, цифры, «-», «_», «.», «@» (как у netifd), не длиннее 15.
fn dev_ok(d: &str) -> bool {
    !d.is_empty() && d.len() <= 15 && d.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c))
}

/// Проверка настроек (для livecfg): пусто — ок.
pub fn validate(c: &KnockConfig) -> Result<(), String> {
    for x in &c.steps {
        if parse_step(x).is_none() {
            return Err(tr!("knock.steps: {} — нужно ping:размер, tcp:порт или udp:порт", format!("{:?}", x)).to_string());
        }
    }
    let n = steps(c).len();
    if c.enabled && !(2..=6).contains(&n) {
        return Err(tr!("knock.steps: нужно от 2 до 6 шагов").to_string());
    }
    for f in &c.forwards {
        if parse_forward(f).is_none() {
            return Err(tr!("knock.forwards: {} — нужно «порты=адрес», напр. 3389=192.168.1.10", format!("{:?}", f)).to_string());
        }
    }
    for x in &c.from {
        if !dev_ok(x) {
            return Err(tr!("knock.from: {} — нужно имя интерфейса", format!("{:?}", x)).to_string());
        }
    }
    Ok(())
}

/// Интерфейсы стука: имена устройств; старые значения (до 2.7.38) — wan4/wan6 → устройства WAN,
/// zerotier → zt*, tailscale → tailscale*.
pub fn resolve_from(from: &[String], wan_devs: &[String], all: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |x: &str| {
        if !out.iter().any(|y| y == x) {
            out.push(x.to_string());
        }
    };
    for f in from {
        match f.as_str() {
            // в «устройствах WAN» бывают и имена netifd (INTERNET, @INTERNET) — только настоящие устройства
            "wan4" | "wan6" => wan_devs.iter().filter(|d| all.contains(d)).for_each(|d| push(d)),
            "zerotier" => all.iter().filter(|d| d.starts_with("zt")).for_each(|d| push(d)),
            "tailscale" => all.iter().filter(|d| d.starts_with("tailscale")).for_each(|d| push(d)),
            d if dev_ok(d) => push(d),
            _ => {}
        }
    }
    out
}

/// Устройство — VPN/туннель (OpenVPN tun/tap, WireGuard, ZeroTier, Tailscale, IPsec, GRE…).
pub fn is_vpn(d: &str) -> bool {
    ["zt", "tailscale", "wg", "tun", "tap", "ipsec", "xfrm", "vti", "gre", "l2tp", "ovpn", "nebula", "netbird", "ts"].iter().any(|p| d.starts_with(p))
}

fn ports_set(p: &[u16]) -> String {
    format!("{{ {} }}", p.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "))
}

/// Условие шага для семейства (`4`/`6`).
fn step_match(st: &Step, sfx: &str) -> String {
    match st {
        Step::Ping(n) if sfx == "4" => format!("icmp type echo-request meta length {}", n + 28),
        Step::Ping(n) => format!("icmpv6 type echo-request meta length {}", n + 48),
        Step::Tcp(p) => format!("tcp dport {p} tcp flags & (fin | syn | rst | ack) == syn"),
        Step::Udp(p) => format!("udp dport {p}"),
    }
}

/// Цепочка стука одного семейства: шаги — с конца (адрес держится только в наборе своего шага,
/// `return` — дальше не смотреть), в конце — сброс: сюда попадают только «похожие на стук» пакеты.
fn knock_chain(sfx: &str, st: &[Step]) -> String {
    let saddr = if sfx == "4" { "ip saddr" } else { "ip6 saddr" };
    let n = st.len();
    let mut b = format!("\tchain knock{sfx} {{\n");
    for i in (0..n).rev() {
        let m = step_match(&st[i], sfx);
        if i == n - 1 {
            b.push_str(&format!("\t\t{m} {saddr} @k{sfx}_{i} delete @k{sfx}_{i} {{ {saddr} }} add @open{sfx} {{ {saddr} }} log prefix \"cgmon-knock open \" level info return\n"));
        } else if i > 0 {
            b.push_str(&format!("\t\t{m} {saddr} @k{sfx}_{i} delete @k{sfx}_{i} {{ {saddr} }} add @k{sfx}_{} {{ {saddr} }} return\n", i + 1));
        } else {
            b.push_str(&format!("\t\t{m} add @k{sfx}_1 {{ {saddr} }} return\n"));
        }
    }
    for i in 1..n {
        b.push_str(&format!("\t\tdelete @k{sfx}_{i} {{ {saddr} }}\n"));
    }
    b.push_str("\t}\n");
    b
}

/// Весь скрипт nft (начинается с удаления старой таблицы). Выключено — только удаление.
pub fn script(c: &KnockConfig, devs: &[String], lan_ip: Option<Ipv4Addr>) -> String {
    let mut b = format!("add table inet {TABLE}\ndelete table inet {TABLE}\n");
    let st = steps(c);
    if !c.enabled || st.len() < 2 || devs.is_empty() {
        return b;
    }
    let step = c.step_sec.clamp(5, 300);
    let open = c.open_min.clamp(1, 24 * 60);
    let ports: Vec<u16> = c.ports.iter().filter_map(|p| u16::try_from(*p).ok().filter(|p| *p > 0)).collect();
    let fwds: Vec<Fwd> = c.forwards.iter().filter_map(|f| parse_forward(f)).collect();
    let n = st.len();
    b.push_str(&format!("table inet {TABLE} {{\n"));
    for (sfx, ty) in [("4", "ipv4_addr"), ("6", "ipv6_addr")] {
        for i in 1..n {
            b.push_str(&format!("\tset k{sfx}_{i} {{ type {ty}; flags dynamic,timeout; timeout {step}s; }}\n"));
        }
        b.push_str(&format!("\tset open{sfx} {{ type {ty}; flags dynamic,timeout; timeout {open}m; }}\n"));
    }
    b.push_str(&knock_chain("4", &st));
    b.push_str(&knock_chain("6", &st));
    let m = format!("0x{MARK:08x}");
    let ping = st.iter().any(|x| matches!(x, Step::Ping(_)));
    let tcp: Vec<u16> = st.iter().filter_map(|x| if let Step::Tcp(p) = x { Some(*p) } else { None }).collect();
    let udp: Vec<u16> = st.iter().filter_map(|x| if let Step::Udp(p) = x { Some(*p) } else { None }).collect();
    b.push_str("\tchain input {\n\t\ttype filter hook input priority filter - 10; policy accept;\n");
    for d in devs {
        // в цепочку стука — только то, что похоже на стук (иначе обычный трафик сбивал бы шаги)
        if ping {
            b.push_str(&format!("\t\tiifname \"{d}\" icmp type echo-request jump knock4\n"));
            b.push_str(&format!("\t\tiifname \"{d}\" icmpv6 type echo-request jump knock6\n"));
        }
        for (proto, list) in [("tcp", &tcp), ("udp", &udp)] {
            if list.is_empty() {
                continue;
            }
            let syn = if proto == "tcp" { " tcp flags & (fin | syn | rst | ack) == syn" } else { "" };
            for (fam, sfx) in [("ipv4", "4"), ("ipv6", "6")] {
                b.push_str(&format!("\t\tiifname \"{d}\" meta nfproto {fam} {proto} dport {}{syn} jump knock{sfx}\n", ports_set(list)));
            }
        }
    }
    // службы роутера по IPv6 (перевести на LAN-адрес нельзя) — пропустить, если слушают все адреса
    if !ports.is_empty() {
        for d in devs {
            b.push_str(&format!("\t\tiifname \"{d}\" ip6 saddr @open6 tcp dport {} meta mark set meta mark | {m}\n", ports_set(&ports)));
        }
    }
    b.push_str("\t}\n");
    b.push_str("\tchain pre {\n\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n");
    for d in devs {
        if let (Some(lan), false) = (lan_ip, ports.is_empty()) {
            b.push_str(&format!("\t\tiifname \"{d}\" ip saddr @open4 tcp dport {} meta mark set meta mark | {m} dnat ip to {lan}\n", ports_set(&ports)));
        }
        for f in &fwds {
            let to = match f.to_port {
                Some(p) => format!("{}:{p}", f.ip),
                None => f.ip.to_string(),
            };
            for proto in ["tcp", "udp"] {
                b.push_str(&format!("\t\tiifname \"{d}\" ip saddr @open4 {proto} dport {} meta mark set meta mark | {m} dnat ip to {to}\n", ports_set(&f.ports)));
            }
        }
    }
    b.push_str("\t}\n}\n");
    b
}

/// Кандидат для стука: устройство с маршрутом в интернет (default в любой таблице) или VPN-сеть.
#[derive(Clone, Debug, Default)]
pub struct Cand {
    pub dev: String,
    pub label: String,
    /// gw — шлюз (есть default), vpn — VPN-сеть без своего default
    pub kind: &'static str,
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

/// Устройства с default-маршрутом из `ip route show table all`.
pub fn default_devs(t: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in t.lines().filter(|l| l.starts_with("default")) {
        let w: Vec<&str> = l.split_whitespace().collect();
        if let Some(d) = w.iter().position(|x| *x == "dev").and_then(|i| w.get(i + 1)) {
            if dev_ok(d) && !out.iter().any(|x| x == d) {
                out.push(d.to_string());
            }
        }
    }
    out
}

/// `ip -o addr`: устройство → (IPv4, IPv6 global).
fn addrs(t: &str) -> std::collections::HashMap<String, (Vec<String>, Vec<String>)> {
    let mut m: std::collections::HashMap<String, (Vec<String>, Vec<String>)> = std::collections::HashMap::new();
    for l in t.lines() {
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.len() < 4 {
            continue;
        }
        let dev = w[1].split('@').next().unwrap_or("").trim_end_matches(':').to_string();
        let ip = w[3].split('/').next().unwrap_or("").to_string();
        let e = m.entry(dev).or_default();
        if w[2] == "inet" {
            e.0.push(ip);
        } else if w[2] == "inet6" && l.contains("scope global") && !l.contains("deprecated") {
            e.1.push(ip);
        }
    }
    m
}

fn run(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Кандидаты: шлюзы (default в любой таблице, WAN) и VPN-сети, с адресами и именами netifd.
pub fn candidates(wan_devs: &[String]) -> Vec<Cand> {
    let mut gw = default_devs(&run("ip", &["-4", "route", "show", "table", "all"]));
    for d in default_devs(&run("ip", &["-6", "route", "show", "table", "all"])).into_iter().chain(wan_devs.iter().cloned()) {
        if !gw.contains(&d) {
            gw.push(d);
        }
    }
    let links: Vec<String> = std::fs::read_dir("/sys/class/net").map(|r| r.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    gw.retain(|d| links.contains(d) && d != "lo");
    let mut vpn: Vec<String> = links.iter().filter(|d| is_vpn(d) && !gw.contains(d)).cloned().collect();
    vpn.sort();
    let labels = crate::dgroute::parse_labels(&run("ubus", &["call", "network.interface", "dump"]));
    let ad = addrs(&run("ip", &["-o", "addr", "show"]));
    gw.into_iter().map(|d| (d, "gw")).chain(vpn.into_iter().map(|d| (d, "vpn"))).map(|(d, kind)| {
        let (v4, v6) = ad.get(&d).cloned().unwrap_or_default();
        Cand { label: labels.get(&d).cloned().unwrap_or_default(), dev: d, kind, v4, v6 }
    }).collect()
}

/// LAN-адрес роутера (IPv4): network.lan.ipaddr (первый, без маски).
pub fn lan_ip() -> Option<Ipv4Addr> {
    let o = std::process::Command::new("uci").args(["-q", "get", "network.lan.ipaddr"]).output().ok()?;
    String::from_utf8_lossy(&o.stdout).split_whitespace().next()?.split('/').next()?.parse().ok()
}

/// Адреса из набора `open4/open6` с оставшимися секундами (`nft list set`).
pub fn parse_open(t: &str) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let Some(body) = t.split("elements = {").nth(1) else { return out };
    let body = body.split('}').next().unwrap_or("");
    for el in body.split(',') {
        let w: Vec<&str> = el.split_whitespace().collect();
        let Some(ip) = w.first() else { continue };
        let left = w.iter().position(|x| *x == "expires").and_then(|i| w.get(i + 1)).map(|d| dur_sec(d)).unwrap_or(0);
        out.push((ip.to_string(), left));
    }
    out
}

/// «9m58s», «1h2m3s», «58s» → секунды.
fn dur_sec(d: &str) -> i64 {
    // «…s440ms» — миллисекунды отбросить (иначе «m» прочтётся как минуты)
    let d = match d.strip_suffix("ms") {
        Some(x) => x.trim_end_matches(|c: char| c.is_ascii_digit()),
        None => d,
    };
    let (mut total, mut num) = (0i64, String::new());
    for ch in d.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
        } else {
            let v: i64 = num.parse().unwrap_or(0);
            num.clear();
            total += match ch {
                'd' => v * 86400,
                'h' => v * 3600,
                'm' => v * 60,
                's' => v,
                _ => 0,
            };
        }
    }
    total
}

#[derive(Default)]
pub struct Knock {
    applied: String,
    checked_at: i64,
    polled_at: i64,
    open: Vec<(String, i64)>,
    pub err: String,
    /// для страницы: внешний IPv4 и за CGNAT ли он, кандидаты и выбранные устройства
    wan4: String,
    cgnat: bool,
    cands: Vec<Cand>,
    devs: Vec<String>,
}

fn nft_ok(args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(crate::acct::nft_bin()).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Правила fw4 «помеченное стуком — пропустить» (input и forward); `on` — поставить, иначе убрать.
fn fw4_rules(on: bool) {
    if crate::util::readonly() {
        return;
    }
    for chain in ["input", "forward"] {
        let Some(t) = nft_ok(&["-a", "list", "chain", "inet", "fw4", chain]) else { continue };
        let handles: Vec<String> = t.lines().filter(|l| l.contains(FW4_TAG)).filter_map(|l| l.rsplit("# handle ").next().map(|h| h.trim().to_string())).collect();
        if on && handles.len() == 1 {
            continue;
        }
        for h in &handles {
            let _ = nft_ok(&["delete", "rule", "inet", "fw4", chain, "handle", h]);
        }
        if on {
            let m = format!("0x{MARK:08x}");
            let _ = crate::acct::nft_script(&format!("insert rule inet fw4 {chain} meta mark & {m} == {m} accept comment \"{FW4_TAG}\"\n"));
        }
    }
}

impl Knock {
    /// Раз в 30 с: таблица по настройкам (переписать, если изменилась или пропала), правила fw4;
    /// раз в 5 с — кому открыт доступ (новые — в события).
    pub fn tick(&mut self, now_ms: i64, c: &KnockConfig, wan_devs: &[String], wan_ips: &[std::net::IpAddr]) -> Vec<String> {
        let mut msgs = Vec::new();
        if now_ms - self.checked_at >= 30_000 || self.checked_at == 0 {
            self.checked_at = now_ms;
            self.addresses(wan_ips);
            self.cands = candidates(wan_devs);
            let all: Vec<String> = self.cands.iter().map(|x| x.dev.clone()).collect();
            self.devs = resolve_from(&c.from, wan_devs, &all);
            let want = script(c, &self.devs, lan_ip());
            let present = nft_ok(&["list", "table", "inet", TABLE]).is_some();
            let need = want != self.applied || (c.enabled && !present);
            if need && !crate::util::readonly() {
                match crate::acct::nft_script(&want) {
                    Ok(()) => {
                        if self.applied.is_empty() != want.is_empty() || !self.err.is_empty() {
                            crate::log_info!("knock: {}", if c.enabled { "table cgmon_knock applied" } else { "off" });
                        }
                        self.applied = want;
                        self.err.clear();
                    }
                    Err(e) => {
                        if self.err != e {
                            crate::log_err!("knock: nft: {e}");
                        }
                        self.err = e;
                    }
                }
            }
            if !crate::util::readonly() {
                fw4_rules(c.enabled && self.err.is_empty());
            }
        }
        if c.enabled && now_ms - self.polled_at >= 5000 {
            self.polled_at = now_ms;
            let mut now_open = Vec::new();
            for s in ["open4", "open6"] {
                if let Some(t) = nft_ok(&["list", "set", "inet", TABLE, s]) {
                    now_open.extend(parse_open(&t));
                }
            }
            for (ip, left) in &now_open {
                if !self.open.iter().any(|(x, _)| x == ip) {
                    msgs.push(tr!("Стук: доступ открыт для {} на {} мин", ip, (left + 59) / 60).to_string());
                }
            }
            self.open = now_open;
        } else if !c.enabled {
            self.open.clear();
        }
        msgs
    }

    fn addresses(&mut self, wan_ips: &[std::net::IpAddr]) {
        // внешний IPv4: сначала не из домашних сетей (PPPoE, а не модем 192.168.x за ним)
        let v4: Vec<[u8; 4]> = wan_ips.iter().filter_map(|ip| crate::netx::to4(ip)).collect();
        let main = v4.iter().find(|a| !crate::netx::is_private4(**a)).or(v4.first()).copied();
        self.wan4 = main.map(|a| std::net::Ipv4Addr::from(a).to_string()).unwrap_or_default();
        self.cgnat = main.map_or(false, |a| crate::netx::is_private4(a) || (a[0] == 100 && a[1] & 0xc0 == 64));
    }

    pub fn status_json(&self, j: &mut crate::json::J, c: &KnockConfig) {
        j.obj().key("enabled").bool(c.enabled).key("wan4").str(&self.wan4).key("cgnat").bool(self.cgnat);
        if !self.err.is_empty() {
            j.key("error").str(&self.err);
        }
        j.key("from").arr();
        for d in &self.devs {
            j.str(d);
        }
        j.end_arr();
        j.key("ifaces").arr();
        for x in &self.cands {
            j.obj().key("dev").str(&x.dev).key("label").str(&x.label).key("kind").str(x.kind);
            j.key("v4").arr();
            for a in &x.v4 {
                j.str(a);
            }
            j.end_arr().key("v6").arr();
            for a in &x.v6 {
                j.str(a);
            }
            j.end_arr().end_obj();
        }
        j.end_arr();
        j.key("open").arr();
        for (ip, left) in &self.open {
            j.obj().key("ip").str(ip).key("left").int(*left).end_obj();
        }
        j.end_arr().end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> KnockConfig {
        KnockConfig { enabled: true, sizes: vec![], steps: vec!["ping:100".into(), "tcp:7000".into(), "udp:8000".into()], step_sec: 30, open_min: 10, from: vec!["pppoe-wan".into(), "zt0".into()], ports: vec![22, 80], forwards: vec!["3389,5650=192.168.1.201".into(), "34567=192.168.1.114".into()] }
    }

    #[test]
    fn steps_and_forwards() {
        assert_eq!(parse_step("ping:100"), Some(Step::Ping(100)));
        assert_eq!(parse_step("122"), Some(Step::Ping(122)));
        assert_eq!(parse_step("TCP:7000"), Some(Step::Tcp(7000)));
        assert_eq!(parse_step("udp:8000"), Some(Step::Udp(8000)));
        assert!(parse_step("tcp:0").is_none() && parse_step("ping:5").is_none() && parse_step("x:1").is_none());
        let old = KnockConfig { sizes: vec![100, 122], ..Default::default() };
        assert_eq!(steps(&old), vec![Step::Ping(100), Step::Ping(122)]);
        assert_eq!(parse_forward("3389,5650=192.168.1.201"), Some(Fwd { ports: vec![3389, 5650], ip: "192.168.1.201".parse().unwrap(), to_port: None }));
        assert_eq!(parse_forward("8080=192.168.1.5:80").unwrap().to_port, Some(80));
        assert!(parse_forward("8080,81=192.168.1.5:80").is_none());
        assert!(parse_forward("22=8.8.8.8").is_none());
        assert!(validate(&cfg()).is_ok());
        let mut bad = cfg();
        bad.steps.push("tcp:x".into());
        assert!(validate(&bad).is_err());
        assert!(is_vpn("tun0") && is_vpn("wg0") && is_vpn("ztabc") && !is_vpn("eth0") && !is_vpn("pppoe-wan"));
        assert_eq!(resolve_from(&["wan4".into(), "zerotier".into(), "tun0".into()], &["pppoe-wan".into(), "INTERNET".into()], &["pppoe-wan".into(), "ztab".into(), "tun0".into()]), vec!["pppoe-wan", "ztab", "tun0"]);
        assert_eq!(default_devs("default via 1.2.3.4 dev pppoe-wan proto static\ndefault via 10.8.0.1 dev tun0 table 100\n10.0.0.0/8 dev br-lan\n"), vec!["pppoe-wan", "tun0"]);
    }

    #[test]
    fn nft_script_shape() {
        let s = script(&cfg(), &["pppoe-wan".into(), "zt0".into()], Some("192.168.1.211".parse().unwrap()));
        assert!(s.starts_with("add table inet cgmon_knock\ndelete table inet cgmon_knock\ntable inet cgmon_knock {"));
        // шаги с конца: udp 8000 (открыть) → tcp 7000 → ping 100 (128 / 148 байт)
        let k4 = s.split("chain knock4").nth(1).unwrap();
        let first = k4.lines().nth(1).unwrap();
        assert!(first.contains("udp dport 8000 ip saddr @k4_2") && first.contains("add @open4"));
        assert!(k4.contains("tcp dport 7000 tcp flags & (fin | syn | rst | ack) == syn ip saddr @k4_1 delete @k4_1 { ip saddr } add @k4_2"));
        assert!(k4.contains("icmp type echo-request meta length 128 add @k4_1"));
        assert!(s.contains("icmpv6 type echo-request meta length 148 add @k6_1"));
        assert!(s.contains("iifname \"zt0\" meta nfproto ipv4 tcp dport { 7000 } tcp flags & (fin | syn | rst | ack) == syn jump knock4"));
        assert!(s.contains("iifname \"pppoe-wan\" meta nfproto ipv6 udp dport { 8000 } jump knock6"));
        assert!(s.contains("tcp dport { 22, 80 } meta mark set meta mark | 0x08000000 dnat ip to 192.168.1.211"));
        let mut off = cfg();
        off.enabled = false;
        assert_eq!(script(&off, &["x".into()], None), "add table inet cgmon_knock\ndelete table inet cgmon_knock\n");
    }

    #[test]
    fn open_list() {
        let t = "table inet cgmon_knock {\n\tset open4 {\n\t\ttype ipv4_addr\n\t\tsize 65535\n\t\tflags dynamic,timeout\n\t\ttimeout 10m\n\t\telements = { 10.147.17.101 timeout 10m expires 9m58s, 1.2.3.4 timeout 10m expires 41s }\n\t}\n}\n";
        assert_eq!(parse_open(t), vec![("10.147.17.101".to_string(), 598), ("1.2.3.4".to_string(), 41)]);
        assert!(parse_open("set open4 { type ipv4_addr }").is_empty());
        assert_eq!(parse_open("elements = { 10.147.17.71 expires 9m58s440ms }"), vec![("10.147.17.71".to_string(), 598)]);
        assert_eq!(dur_sec("440ms"), 0);
    }
}

#[cfg(test)]
mod dump {
    /// `cargo test knock_dump -- --nocapture` — скрипт для проверки на роутере (`nft -c -f`)
    #[test]
    fn knock_dump() {
        let c = crate::config::KnockConfig { enabled: true, sizes: vec![], steps: vec!["ping:100".into(), "tcp:7000".into(), "udp:8000".into()], step_sec: 30, open_min: 10, from: vec![], ports: vec![22, 80], forwards: vec!["3389,5650=192.168.1.201".into(), "34567=192.168.1.114".into()] };
        if let Ok(path) = std::env::var("KNOCK_DUMP") {
            std::fs::write(path, super::script(&c, &["pppoe-wan".into(), "eth2".into(), "zt0abcdef".into(), "tailscale0".into()], Some("192.168.1.211".parse().unwrap()))).unwrap();
        }
    }
}
