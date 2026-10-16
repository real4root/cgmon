//! Топология (перенос DetectTopology, extraZoneInfo, routedLocalNets,
//! lanChoices, publishStatsDevice): зоны LAN/WAN из UCI firewall + network,
//! живые адреса интерфейсов, сети за туннелями и прочими не-WAN устройствами.

use crate::config::Config;
use crate::json::J;
use crate::netx::{self, IpNet};
use std::net::IpAddr;

// ---------------- UCI ----------------

#[derive(Clone, Debug, Default)]
pub struct UciSection {
    pub typ: String,
    pub name: String,
    pub options: Vec<(String, String)>,
    pub lists: Vec<(String, Vec<String>)>,
}

impl UciSection {
    pub fn opt(&self, k: &str) -> &str {
        self.options.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str()).unwrap_or("")
    }
    pub fn list(&self, k: &str) -> &[String] {
        self.lists.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_slice()).unwrap_or(&[])
    }
    /// Значения ключа: list или option (option network 'a b' — тоже список).
    pub fn values(&self, k: &str) -> Vec<String> {
        let l = self.list(k);
        if !l.is_empty() {
            return l.to_vec();
        }
        self.opt(k).split_whitespace().map(String::from).collect()
    }
}

fn unq(s: &str) -> String {
    s.trim_matches(['\'', '"']).to_string()
}

pub fn parse_uci(text: &str) -> Vec<UciSection> {
    let mut out: Vec<UciSection> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "config" if f.len() >= 2 => out.push(UciSection { typ: f[1].to_string(), name: f.get(2).map(|x| unq(x)).unwrap_or_default(), ..Default::default() }),
            "option" if f.len() >= 3 => {
                if let Some(s) = out.last_mut() {
                    let v = unq(&f[2..].join(" "));
                    match s.options.iter_mut().find(|(k, _)| k == f[1]) {
                        Some(e) => e.1 = v,
                        None => s.options.push((f[1].to_string(), v)),
                    }
                }
            }
            "list" if f.len() >= 3 => {
                if let Some(s) = out.last_mut() {
                    let v = unq(&f[2..].join(" "));
                    match s.lists.iter_mut().find(|(k, _)| k == f[1]) {
                        Some(e) => e.1.push(v),
                        None => s.lists.push((f[1].to_string(), vec![v])),
                    }
                }
            }
            _ => {}
        }
    }
    out
}

pub fn read_uci(path: &str) -> Vec<UciSection> {
    std::fs::read_to_string(path).map(|t| parse_uci(&t)).unwrap_or_default()
}

fn iface_name(s: &UciSection) -> String {
    if s.name.is_empty() {
        s.opt("name").to_string()
    } else {
        s.name.clone()
    }
}

/// Устройство UCI-интерфейса (device / ifname / list ifname).
pub fn uci_network_device(name: &str) -> String {
    for s in read_uci("/etc/config/network") {
        if s.typ != "interface" || iface_name(&s) != name {
            continue;
        }
        for k in ["device", "ifname"] {
            if !s.opt(k).is_empty() {
                return s.opt(k).to_string();
            }
        }
        if let Some(d) = s.list("ifname").first() {
            return d.clone();
        }
    }
    String::new()
}

/// Интерфейс netifd → L3-устройство (ubus network.interface dump, кэш 30 с).
pub struct Netifd {
    at: u64,
    pub map: Vec<(String, String)>,
}

impl Netifd {
    pub const fn new() -> Netifd {
        Netifd { at: 0, map: Vec::new() }
    }

    pub fn l3(&mut self, now: u64) -> &[(String, String)] {
        if self.at != 0 && now - self.at < 30_000 {
            return &self.map;
        }
        self.at = now.max(1);
        self.map.clear();
        if let Ok(out) = std::process::Command::new("ubus").args(["call", "network.interface", "dump"]).output() {
            if let Ok(v) = crate::value::parse_json(&String::from_utf8_lossy(&out.stdout)) {
                if let Some(crate::value::Value::List(l)) = v.get("interface") {
                    for i in l {
                        let n = i.get("interface").and_then(|x| x.as_str()).unwrap_or("");
                        let d = i.get("l3_device").and_then(|x| x.as_str()).unwrap_or("");
                        if !n.is_empty() && !d.is_empty() {
                            self.map.push((n.into(), d.into()));
                        }
                    }
                }
            }
        }
        &self.map
    }

    pub fn get(&mut self, name: &str, now: u64) -> String {
        self.l3(now).iter().find(|(n, _)| n == name).map(|(_, d)| d.clone()).unwrap_or_default()
    }
}

// ---------------- топология ----------------

#[derive(Clone, Debug, Default)]
pub struct Tracked {
    pub name: String,
    pub zone: String,
    pub ips: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Topology {
    pub lan_ips: Vec<IpAddr>,
    pub wan_ips: Vec<IpAddr>,
    pub ignored_ips: Vec<IpAddr>,
    pub lan_nets: Vec<IpNet>,
    pub tracked: Vec<Tracked>,
    /// устройства зоны wan (PPPoE, DHCP, резервные) и маршрута по умолчанию
    pub wan_devs: Vec<String>,
}

/// Сеть LAN: IPv4 /31–/32 → /24, IPv6 длиннее /64 → /64.
pub fn normalize_lan(n: &IpNet) -> IpNet {
    if n.is_v4() {
        IpNet::new(n.ip, if n.bits >= 31 { 24 } else { n.bits })
    } else {
        IpNet::new(n.ip, n.bits.min(64))
    }
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

pub fn detect(cfg: &Config, exclude: &[IpNet]) -> Topology {
    let mut t = Topology::default();
    let cfg_lan = netx::parse_nets(&cfg.lan_networks).unwrap_or_default();
    let fw = read_uci("/etc/config/firewall");
    let (mut lan_networks, mut wan_networks) = (Vec::new(), Vec::new());
    for s in fw.iter().filter(|s| s.typ == "zone") {
        match s.opt("name") {
            "lan" => lan_networks.extend(s.values("network")),
            "wan" => wan_networks.extend(s.values("network")),
            _ => {}
        }
    }
    let (mut lan_devs, mut wan_devs): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for s in read_uci("/etc/config/network").iter().filter(|s| s.typ == "interface") {
        let name = iface_name(s);
        let mut dev = s.opt("device").to_string();
        if dev.is_empty() {
            dev = s.opt("ifname").to_string();
        }
        if dev.is_empty() {
            dev = name.clone();
        }
        if lan_networks.contains(&name) {
            push_unique(&mut lan_devs, &dev);
            push_unique(&mut lan_devs, &name);
        }
        if wan_networks.contains(&name) {
            push_unique(&mut wan_devs, &dev);
            push_unique(&mut wan_devs, &name);
            if s.opt("proto") == "pppoe" {
                push_unique(&mut wan_devs, &format!("pppoe-{name}"));
                if dev != name {
                    push_unique(&mut wan_devs, &format!("pppoe-{dev}"));
                }
            }
        }
    }
    for d in &cfg.lan_interfaces {
        push_unique(&mut lan_devs, d);
    }
    for d in &cfg.wan.interfaces {
        push_unique(&mut wan_devs, d);
    }
    if cfg.wan.auto_detect_default_route {
        let d = netx::default_route_interface();
        if !d.is_empty() {
            push_unique(&mut wan_devs, &d);
        }
    }
    t.wan_devs = wan_devs.clone();
    let (mut seen_ips, mut seen_ign, mut seen_nets) = (Vec::<IpAddr>::new(), Vec::<IpAddr>::new(), Vec::<IpNet>::new());
    let all = netx::if_addrs();
    for (name, _, flags) in netx::interfaces() {
        if flags & libc::IFF_LOOPBACK as u32 != 0 || flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        let zone = if lan_devs.iter().any(|d| *d == name) {
            "lan"
        } else if wan_devs.iter().any(|d| *d == name) {
            "wan"
        } else {
            "ignored"
        };
        let mut addrs: Vec<(IpAddr, u8)> = all.iter().filter(|(n, _, _)| *n == name).map(|(_, ip, b)| (*ip, *b)).collect();
        addrs.sort_by_key(|(ip, _)| ip.is_ipv6());
        let mut ip_strs = Vec::new();
        let mut tracked_zone = zone;
        for (ip, bits) in addrs {
            if netx::is_unwanted(&ip) {
                continue;
            }
            if netx::in_nets(&ip, exclude) {
                if !seen_ign.contains(&ip) {
                    seen_ign.push(ip);
                    t.ignored_ips.push(ip);
                }
                continue;
            }
            let mut eff = zone;
            if zone == "ignored" && netx::in_nets(&ip, &cfg_lan) {
                eff = "lan";
                tracked_zone = "lan";
            }
            if eff == "ignored" {
                if !seen_ign.contains(&ip) {
                    seen_ign.push(ip);
                    t.ignored_ips.push(ip);
                }
                continue;
            }
            if seen_ips.contains(&ip) {
                continue;
            }
            seen_ips.push(ip);
            if eff == "lan" {
                t.lan_ips.push(ip);
                let n = normalize_lan(&IpNet::new(ip, bits));
                if !seen_nets.contains(&n) {
                    seen_nets.push(n);
                    t.lan_nets.push(n);
                }
            } else {
                t.wan_ips.push(ip);
            }
            ip_strs.push(ip.to_string());
        }
        if !ip_strs.is_empty() && tracked_zone != "ignored" {
            t.tracked.push(Tracked { name, zone: tracked_zone.into(), ips: ip_strs });
        }
    }
    t
}

/// Живые адреса интерфейсов зон из lan_zones (динамический IPv6 квартирантов
/// подхватывается сам при каждом обновлении).
pub fn extra_zone_info(cfg: &Config, netifd: &mut Netifd, now: u64) -> (Vec<IpNet>, Vec<IpAddr>) {
    let (mut nets, mut ips) = (Vec::new(), Vec::new());
    if cfg.lan_zones.is_empty() {
        return (nets, ips);
    }
    let all = netx::if_addrs();
    for s in read_uci("/etc/config/firewall").iter().filter(|s| s.typ == "zone") {
        if !cfg.lan_zones.iter().any(|z| z == s.opt("name")) {
            continue;
        }
        for nname in s.values("network") {
            let mut dev = uci_network_device(&nname);
            let l3 = netifd.get(&nname, now);
            if !l3.is_empty() && (dev.is_empty() || dev == format!("br-{nname}")) {
                dev = l3; // Wi-Fi-сеть без device в UCI
            }
            if dev.is_empty() {
                dev = nname.clone();
            }
            let mut addrs: Vec<(IpAddr, u8)> = all.iter().filter(|(n, _, _)| *n == dev).map(|(_, ip, b)| (*ip, *b)).collect();
            addrs.sort_by_key(|(ip, _)| ip.is_ipv6());
            for (ip, bits) in addrs {
                if netx::is_unwanted(&ip) {
                    continue;
                }
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
                let n = normalize_lan(&IpNet::new(ip, bits));
                if !nets.contains(&n) {
                    nets.push(n);
                }
            }
        }
    }
    (nets, ips)
}

pub fn is_tunnel_dev(d: &str) -> bool {
    ["tailscale", "zt", "wg", "tun"].iter().any(|p| d.starts_with(p))
}

/// Из `ip route show table all`: unicast-маршруты не по умолчанию через
/// устройства не из wan → (сеть, устройство).
pub fn parse_local_routes(out: &str, wan: &[String]) -> Vec<(IpNet, String)> {
    const SKIP: &[&str] = &["local", "broadcast", "unreachable", "prohibit", "blackhole", "throw", "multicast", "anycast", "nat"];
    let mut res = Vec::new();
    for line in out.lines() {
        let mut f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        if f[0] == "unicast" {
            f.remove(0);
        }
        if SKIP.contains(&f[0]) || f[0] == "default" {
            continue;
        }
        let dev = f.windows(2).skip(1).find(|w| w[0] == "dev").map(|w| w[1]).unwrap_or("");
        if dev.is_empty() || dev == "lo" || wan.iter().any(|w| w == dev) {
            continue;
        }
        let dst = if f[0].contains('/') { f[0].to_string() } else if f[0].contains(':') { format!("{}/128", f[0]) } else { format!("{}/32", f[0]) };
        let Some((ip, bits)) = netx::parse_cidr(&dst) else { continue };
        let n = IpNet::new(ip, bits);
        let link_local = matches!(n.ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80) || matches!(n.ip, IpAddr::V4(a) if a.is_link_local());
        if bits == 0 || link_local || n.ip.is_multicast() {
            continue;
        }
        res.push((n, dev.to_string()));
    }
    res
}

/// Сети не через WAN (учёт) и только за туннелями (conntrack их отбрасывает).
pub fn routed_local_nets(wan_devs: &[String]) -> (Vec<IpNet>, Vec<IpNet>) {
    let (mut all, mut tun) = (Vec::new(), Vec::new());
    for fam in ["-4", "-6"] {
        let Ok(o) = std::process::Command::new("ip").args([fam, "route", "show", "table", "all"]).output() else { continue };
        for (n, dev) in parse_local_routes(&String::from_utf8_lossy(&o.stdout), wan_devs) {
            if !all.contains(&n) {
                all.push(n);
                if is_tunnel_dev(&dev) {
                    tun.push(n);
                }
            }
        }
    }
    (all, tun)
}

fn private4(ip: &IpAddr) -> bool {
    netx::to4(ip).map_or(false, netx::is_private4)
}

pub fn fallback_wan_ips(cfg: &Config) -> Vec<IpAddr> {
    let mut names = cfg.wan.interfaces.clone();
    if cfg.wan.auto_detect_default_route {
        let d = netx::default_route_interface();
        if !d.is_empty() {
            push_unique(&mut names, &d);
        }
    }
    let mut out = Vec::new();
    for n in names {
        for (ip, _) in netx::addrs_of(&n) {
            if !netx::is_unwanted(&ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

pub fn fallback_local_ips() -> Vec<IpAddr> {
    let mut out = Vec::new();
    for (_, ip, _) in netx::if_addrs() {
        if !netx::is_unwanted(&ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

pub fn fallback_lan_networks() -> Vec<IpNet> {
    let mut out = Vec::new();
    let all = netx::if_addrs();
    for (name, _, flags) in netx::interfaces() {
        if flags & libc::IFF_LOOPBACK as u32 != 0 || flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        for (_, ip, bits) in all.iter().filter(|(n, _, _)| *n == name) {
            if netx::is_unwanted(ip) || (ip.is_ipv4() && !private4(ip)) {
                continue;
            }
            let n = normalize_lan(&IpNet::new(*ip, *bits));
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Цели проб как (адрес, порт) — их соединения не считаются клиентскими.
pub fn probe_endpoints(cfg: &Config) -> Vec<(IpAddr, u16)> {
    let mut out = Vec::new();
    let lists: [(&[String], &str); 4] = [(&cfg.probes.ipv4, "443"), (&cfg.probes.ipv6, "443"), (&cfg.probes.udp_v4, "53"), (&cfg.probes.udp_v6, "53")];
    for (l, dp) in lists {
        for ep in l {
            let ep = ep.trim();
            if ep.is_empty() {
                continue;
            }
            let full = if ep.contains(':') { ep.to_string() } else { format!("{ep}:{dp}") };
            if let Some((h, p)) = netx::split_host_port(&full) {
                if let (Some(ip), Ok(port)) = (netx::parse_ip(h), p.parse::<u16>()) {
                    if port > 0 {
                        out.push((ip, port));
                    }
                }
            }
        }
    }
    out
}

/// Интерфейсы с IPv4 из сетей LAN (ловец устройств, прослушивание mDNS).
pub fn lan_interface_names(lan_nets: &[IpNet]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (name, ip, _) in netx::if_addrs() {
        if ip.is_ipv4() && netx::in_nets(&ip, lan_nets) && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

// ---------------- устройство счётчиков WAN для страницы ----------------

pub const WAN_STATS_DEV_FILE: &str = "/tmp/cgmon/wan_stats_dev";

/// Устройство маршрута по умолчанию с наименьшей метрикой.
pub fn current_default_device() -> String {
    let Ok(t) = std::fs::read_to_string("/proc/net/route") else { return String::new() };
    let mut best = (i64::MAX, String::new());
    for l in t.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000" {
            if let Ok(m) = f[6].parse::<i64>() {
                if m < best.0 {
                    best = (m, f[0].to_string());
                }
            }
        }
    }
    best.1
}

pub fn flow_offload_enabled() -> bool {
    read_uci("/etc/config/firewall").iter().any(|s| s.typ == "defaults" && (s.opt("flow_offloading") == "1" || s.opt("flow_offloading_hw") == "1"))
}

/// Родитель ppp-устройства по секции UCI (одна ppp-секция — её устройство).
pub fn ppp_parent_device(netdev: &str) -> String {
    let mut ppp = Vec::new();
    for s in read_uci("/etc/config/network").iter().filter(|s| s.typ == "interface") {
        let proto = s.opt("proto").to_lowercase();
        if !matches!(proto.as_str(), "pppoe" | "ppp" | "pptp" | "l2tp") {
            continue;
        }
        let dev = if s.opt("device").is_empty() { s.opt("ifname") } else { s.opt("device") };
        if dev.is_empty() {
            continue;
        }
        ppp.push(dev.to_string());
        let name = iface_name(s);
        if !name.is_empty() && (name == netdev || format!("pppoe-{name}") == netdev || format!("{proto}-{name}") == netdev) {
            return dev.to_string();
        }
    }
    if ppp.len() == 1 {
        ppp.remove(0)
    } else {
        String::new()
    }
}

/// Состояние публикации: (устройство L3, когда проверяли).
#[derive(Default)]
pub struct StatsDev {
    l3: String,
    at: u64,
    /// устройство, чьи байты — «WAN» на странице (тот же выбор, что для api_router)
    pub dev: String,
}

impl StatsDev {
    /// Записать устройство для api_router (байты WAN): без flow offload — сам
    /// L3 (pppoe-*), с offload — родитель (ускоренные пакеты идут мимо ppp).
    pub fn publish(&mut self, now: u64) {
        let dev = current_default_device();
        if dev.is_empty() || (dev == self.l3 && now - self.at < 60_000) {
            return;
        }
        self.l3 = dev.clone();
        self.at = now;
        let mut stats = dev.clone();
        if flow_offload_enabled() && dev.starts_with("ppp") {
            let p = ppp_parent_device(&dev);
            if !p.is_empty() {
                stats = p;
            }
        }
        self.dev = stats.clone();
        if crate::util::readonly() || std::fs::read_to_string(WAN_STATS_DEV_FILE).map(|c| c.trim() == stats).unwrap_or(false) {
            return;
        }
        if std::fs::write(WAN_STATS_DEV_FILE, format!("{stats}\n")).is_ok() {
            crate::log_info!("wan stats device: {} (default via {})", stats, dev);
        }
    }
}

// ---------------- выбор подсетей для страницы ----------------

const LAN_HIDDEN: &[&str] = &["docker", "voip", "tailscale", "zerotier"];

/// Интерфейс UCI → устройство ядра (как uciNetDevices в Go), в порядке файла.
pub fn uci_net_devices(netifd: &mut Netifd, now: u64) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for s in read_uci("/etc/config/network").iter().filter(|s| s.typ == "interface") {
        let name = iface_name(s);
        let mut dev = if s.opt("device").is_empty() { s.opt("ifname").to_string() } else { s.opt("device").to_string() };
        if s.opt("proto") == "pppoe" {
            dev = format!("pppoe-{name}");
        }
        if dev.is_empty() {
            dev = netifd.get(&name, now);
        }
        if name.is_empty() || name == "loopback" || dev.starts_with('@') || dev == "lo" {
            continue;
        }
        out.push((name, dev));
    }
    out
}

/// Сети на устройстве (без link-local).
pub fn dev_cidrs(dev: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (ip, bits) in netx::addrs_of(dev) {
        if ip.is_loopback() || matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80) || matches!(ip, IpAddr::V4(a) if a.is_link_local()) {
            continue;
        }
        let n = IpNet::new(ip, bits).to_string();
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct LanChoice {
    pub kind: &'static str, // zone | iface
    pub name: String,
    pub networks: Vec<String>,
    pub devices: Vec<String>,
    pub cidrs: Vec<String>,
    pub on: bool,
    pub isolated: bool,
    pub fixed: bool,
}

/// Подсети для страницы: зоны firewall (кроме wan и служебных) и сети без зоны.
pub fn lan_choices(cfg: &Config, netifd: &mut Netifd, now: u64) -> Vec<LanChoice> {
    let devs = uci_net_devices(netifd, now);
    let dev_of = |n: &str| devs.iter().find(|(x, _)| x == n).map(|(_, d)| d.clone()).unwrap_or_default();
    let mut in_zone: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for s in read_uci("/etc/config/firewall").iter().filter(|s| s.typ == "zone") {
        let name = s.opt("name");
        let nets = s.values("network");
        in_zone.extend(nets.iter().cloned());
        if name.is_empty() || name == "wan" || LAN_HIDDEN.contains(&name) {
            continue;
        }
        let fixed = name == "lan";
        let mut c = LanChoice { kind: "zone", name: name.into(), networks: nets.clone(), fixed, ..Default::default() };
        c.on = fixed || cfg.lan_zones.iter().any(|z| z == name);
        c.isolated = !fixed && cfg.isolated_zones.iter().any(|z| z == name);
        for n in &nets {
            let d = dev_of(n);
            if !d.is_empty() {
                push_unique(&mut c.devices, &d);
                c.cidrs.extend(dev_cidrs(&d));
            }
        }
        out.push(c);
    }
    for (n, d) in &devs {
        if in_zone.contains(n) || LAN_HIDDEN.contains(&n.as_str()) {
            continue;
        }
        out.push(LanChoice { kind: "iface", name: n.clone(), devices: vec![d.clone()], cidrs: dev_cidrs(d), on: cfg.lan_interfaces.contains(d), isolated: cfg.isolated_zones.contains(n), ..Default::default() });
    }
    out
}

/// «lan» для config_get.
pub fn lan_choices_json(cfg: &Config, netifd: &mut Netifd, now: u64, j: &mut J) {
    j.arr();
    for c in lan_choices(cfg, netifd, now) {
        j.obj().key("kind").str(c.kind).key("name").str(&c.name);
        str_list(j, "networks", &c.networks);
        str_list(j, "devices", &c.devices);
        str_list(j, "cidrs", &c.cidrs);
        j.key("on").bool(c.on);
        if c.isolated {
            j.key("isolated").bool(true);
        }
        if c.fixed {
            j.key("fixed").bool(true);
        }
        j.end_obj();
    }
    j.end_arr();
}

fn str_list(j: &mut J, k: &str, l: &[String]) {
    if l.is_empty() {
        return;
    }
    j.key(k).arr();
    for s in l {
        j.str(s);
    }
    j.end_arr();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uci() {
        let t = "config interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n\tlist ipaddr '192.168.1.1/24'\n\nconfig zone\n\toption name 'lan'\n\tlist network 'lan'\n\tlist network 'iot'\nconfig zone\n\toption name 'wan'\n\toption network 'wan wan6'\n";
        let s = parse_uci(t);
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].typ.as_str(), s[0].name.as_str(), s[0].opt("device")), ("interface", "lan", "br-lan"));
        assert_eq!(s[1].values("network"), vec!["lan", "iot"]);
        assert_eq!(s[2].values("network"), vec!["wan", "wan6"]);
    }

    #[test]
    fn local_routes() {
        let out = "default via 198.51.100.1 dev pppoe-wan\n10.147.17.0/24 dev ztabc proto kernel scope link src 10.147.17.18\n192.168.7.0/24 dev vlan2 proto kernel\n198.51.100.0/24 dev pppoe-wan\nunicast 172.17.0.0/16 dev docker0\nlocal 192.168.7.1 dev vlan2 table local\n100.64.0.5 dev tailscale0 table 52\nfe80::/64 dev br-lan\n";
        let r = parse_local_routes(out, &["pppoe-wan".to_string()]);
        let got: Vec<String> = r.iter().map(|(n, d)| format!("{n} {d}")).collect();
        assert_eq!(got, vec!["10.147.17.0/24 ztabc", "192.168.7.0/24 vlan2", "172.17.0.0/16 docker0", "100.64.0.5/32 tailscale0"]);
    }

    #[test]
    fn lan_normalize() {
        assert_eq!(normalize_lan(&IpNet::new("192.0.2.5".parse().unwrap(), 32)).to_string(), "192.0.2.0/24");
        assert_eq!(normalize_lan(&IpNet::new("2001:db8:1:2:3::1".parse().unwrap(), 128)).to_string(), "2001:db8:1:2::/64");
    }
}
