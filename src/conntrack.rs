//! Чтение conntrack (перенос conntrack.go): потоково, строка за строкой.
//! Классификация: клиент LAN → WAN, сам роутер, входящие проброшенные, к
//! роутеру, локальные; счётчики по протоколам/состояниям; клиенты по IP.
//! WAN-потоки (для flow watch / расширенного режима) — только если нужны.

use crate::netx::{self, IpNet};
use std::collections::HashMap;
use std::io::BufRead;
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientStats {
    pub ip: String,
    pub hostname: String,
    pub mac: String,
    pub total: i64,
    pub wan: i64,
    pub incoming: i64,
    pub router: i64,
    pub local: i64,
    pub tcp: i64,
    pub udp: i64,
    pub icmp: i64,
    pub established: i64,
    pub syn_sent: i64,
    pub syn_recv: i64,
    pub time_wait: i64,
    pub new_rate: f64,
    pub new_wan_rate: f64,
    pub rate_down_mbps: f64,
    pub rate_up_mbps: f64,
    /// накопленные байты устройства (acct) — скорость на странице по разнице
    pub cum_down: u64,
    pub cum_up: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub watching_tv: bool,
    pub hour_down: u64,
    pub hour_up: u64,
    pub day_down: u64,
    pub day_up: u64,
    pub max: i64,
    pub max_wan: i64,
    pub avg: f64,
    pub last_seen: (i64, u32),
}

#[derive(Clone, Debug, Default)]
pub struct WanFlow {
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub tx: u64,
    pub rx: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub current: i64,
    pub max: i64,
    pub usage_pct: f64,
    pub parsed_total: i64,
    pub ignored_total: i64,
    pub tcp: i64,
    pub udp: i64,
    pub icmp: i64,
    pub established: i64,
    pub syn_sent: i64,
    pub syn_recv: i64,
    pub time_wait: i64,
    pub lan_to_wan: i64,
    pub lan_to_router: i64,
    pub lan_to_local: i64,
    pub router_own: i64,
    pub incoming_forwarded: i64,
    pub lan_to_wan_ipv4: i64,
    pub lan_to_wan_ipv6: i64,
    pub lan_to_wan_tcp: i64,
    pub lan_to_wan_udp: i64,
    pub lan_to_wan_icmp: i64,
    pub router_own_ipv4: i64,
    pub router_own_ipv6: i64,
    pub router_own_tcp: i64,
    pub router_own_udp: i64,
    pub router_own_icmp: i64,
    pub incoming_ipv4: i64,
    pub incoming_ipv6: i64,
    pub incoming_tcp: i64,
    pub incoming_udp: i64,
    pub incoming_icmp: i64,
    pub router_own_tunnel: i64,
    pub router_own_probe: i64,
    pub router_own_tunnel_tcp: i64,
    pub router_own_tunnel_udp: i64,
    pub router_own_tunnel_ipv4: i64,
    pub router_own_tunnel_ipv6: i64,
    pub router_own_probe_tcp: i64,
    pub router_own_probe_udp: i64,
    pub router_own_probe_ipv4: i64,
    pub router_own_probe_ipv6: i64,
    pub clients: HashMap<String, ClientStats>,
    /// «proto local>remote» → счётчики
    pub wan_flows: HashMap<String, WanFlow>,
}

/// Что нужно разбору: сети и адреса роутера.
pub struct Ctx<'a> {
    pub lan_nets: &'a [IpNet],
    pub wan_ips: &'a [IpAddr],
    pub local_ips: &'a [IpAddr],
    pub ignored_ips: &'a [IpAddr],
    pub tunnel_nets: &'a [IpNet],
    pub probes: &'a [(IpAddr, u16)],
    /// all | lan_only | lan_to_wan
    pub mode: &'a str,
    pub tv_ports: &'a [u16],
    pub want_flows: bool,
}

#[derive(Clone, Copy, Default)]
struct Tuple {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: u16,
    dport: u16,
}

#[derive(Default)]
struct Line {
    v6: bool,
    proto: &'static str,
    state: &'static str,
    orig: Tuple,
    reply: Tuple,
    orig_bytes: u64,
    reply_bytes: u64,
}

fn tcp_state(s: &str) -> Option<&'static str> {
    Some(match s {
        "ESTABLISHED" => "ESTABLISHED",
        "SYN_SENT" => "SYN_SENT",
        "SYN_RECV" => "SYN_RECV",
        "FIN_WAIT" => "FIN_WAIT",
        "CLOSE_WAIT" => "CLOSE_WAIT",
        "LAST_ACK" => "LAST_ACK",
        "TIME_WAIT" => "TIME_WAIT",
        "CLOSE" => "CLOSE",
        "LISTEN" => "LISTEN",
        _ => return None,
    })
}

fn proto_of(s: &str) -> &'static str {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        "icmp" => "icmp",
        "ipv6-icmp" => "ipv6-icmp",
        _ => "other",
    }
}

fn is_icmp(p: &str) -> bool {
    p == "icmp" || p == "ipv6-icmp"
}

/// Разбор строки /proc/net/nf_conntrack (None — не ipv4/ipv6 или без адресов).
fn parse_line(line: &str) -> Option<Line> {
    let mut it = line.split_ascii_whitespace();
    let fam = it.next()?;
    if fam != "ipv4" && fam != "ipv6" {
        return None;
    }
    it.next()?;
    let proto = proto_of(it.next()?);
    let mut l = Line { v6: fam == "ipv6", proto, ..Default::default() };
    let (mut ns, mut nd, mut nsp, mut ndp, mut nb) = (0, 0, 0, 0, 0);
    for tok in it {
        if let Some(v) = tok.strip_prefix("src=") {
            if let Ok(ip) = v.parse() {
                if ns == 0 {
                    l.orig.src = Some(ip);
                } else if ns == 1 {
                    l.reply.src = Some(ip);
                }
                ns += 1;
            }
        } else if let Some(v) = tok.strip_prefix("dst=") {
            if let Ok(ip) = v.parse() {
                if nd == 0 {
                    l.orig.dst = Some(ip);
                } else if nd == 1 {
                    l.reply.dst = Some(ip);
                }
                nd += 1;
            }
        } else if let Some(v) = tok.strip_prefix("sport=") {
            if let Ok(p) = v.parse::<u16>() {
                if nsp == 0 {
                    l.orig.sport = p;
                } else if nsp == 1 {
                    l.reply.sport = p;
                }
                nsp += 1;
            }
        } else if let Some(v) = tok.strip_prefix("dport=") {
            if let Ok(p) = v.parse::<u16>() {
                if ndp == 0 {
                    l.orig.dport = p;
                } else if ndp == 1 {
                    l.reply.dport = p;
                }
                ndp += 1;
            }
        } else if let Some(v) = tok.strip_prefix("bytes=") {
            if let Ok(b) = v.parse::<u64>() {
                if nb == 0 {
                    l.orig_bytes = b;
                } else if nb == 1 {
                    l.reply_bytes = b;
                }
                nb += 1;
            }
        } else if proto == "tcp" {
            if let Some(s) = tcp_state(tok) {
                l.state = s;
            }
        }
    }
    if l.orig.src.is_none() || l.orig.dst.is_none() {
        return None;
    }
    Some(l)
}

fn in_list(ip: &Option<IpAddr>, l: &[IpAddr]) -> bool {
    ip.map_or(false, |a| l.iter().any(|x| eq_ip(x, &a)))
}

/// Равенство как Go IP.Equal (IPv4 и IPv4-mapped IPv6 — одно и то же).
fn eq_ip(a: &IpAddr, b: &IpAddr) -> bool {
    match (netx::to4(a), netx::to4(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

fn in_nets(ip: &Option<IpAddr>, n: &[IpNet]) -> bool {
    ip.map_or(false, |a| netx::in_nets(&a, n))
}

fn ignored(ips: [&Option<IpAddr>; 4], c: &Ctx) -> bool {
    if c.ignored_ips.is_empty() && c.tunnel_nets.is_empty() {
        return false;
    }
    for ip in ips {
        if ip.is_none() || in_list(ip, c.wan_ips) {
            continue;
        }
        if in_list(ip, c.ignored_ips) || in_nets(ip, c.tunnel_nets) {
            return true;
        }
    }
    false
}

fn is_external(ip: &Option<IpAddr>, c: &Ctx) -> bool {
    let Some(a) = ip else { return false };
    let ll = match a {
        IpAddr::V4(x) => x.is_link_local(),
        IpAddr::V6(x) => x.segments()[0] & 0xffc0 == 0xfe80,
    };
    if a.is_loopback() || a.is_multicast() || ll || a.is_unspecified() {
        return false;
    }
    !(in_nets(ip, c.lan_nets) || in_list(ip, c.local_ips) || in_list(ip, c.wan_ips) || in_nets(ip, c.tunnel_nets))
}

fn host_port(ip: &Option<IpAddr>, port: u16) -> String {
    match ip {
        Some(IpAddr::V6(a)) => format!("[{a}]:{port}"),
        Some(a) => format!("{a}:{port}"),
        None => format!(":{port}"),
    }
}

fn add_wan_flow(m: &mut HashMap<String, WanFlow>, l: &Line, c: &Ctx) {
    if l.proto != "tcp" && l.proto != "udp" {
        return;
    }
    let (local, remote, tx, rx) = if is_external(&l.orig.dst, c) {
        (host_port(&l.orig.src, l.orig.sport), host_port(&l.orig.dst, l.orig.dport), l.orig_bytes, l.reply_bytes)
    } else if is_external(&l.orig.src, c) {
        (host_port(&l.orig.dst, l.orig.dport), host_port(&l.orig.src, l.orig.sport), l.reply_bytes, l.orig_bytes)
    } else {
        return;
    };
    let key = format!("{} {}>{}", l.proto, local, remote);
    let e = m.entry(key).or_insert_with(|| WanFlow { proto: l.proto, local, remote, tx: 0, rx: 0 });
    e.tx += tx;
    e.rx += rx;
}

fn is_tunnel_port(proto: &str, port: u16) -> bool {
    (proto == "udp" && matches!(port, 41641 | 51820 | 51821 | 9993 | 1194 | 500 | 4500 | 1701)) || (proto == "tcp" && port == 1194)
}

fn update_proto(c: &mut ClientStats, proto: &str, st: &str) {
    match proto {
        "tcp" => {
            c.tcp += 1;
            match st {
                "ESTABLISHED" => c.established += 1,
                "SYN_SENT" => c.syn_sent += 1,
                "SYN_RECV" => c.syn_recv += 1,
                "TIME_WAIT" => c.time_wait += 1,
                _ => {}
            }
        }
        "udp" => c.udp += 1,
        p if is_icmp(p) => c.icmp += 1,
        _ => {}
    }
}

fn client<'a>(m: &'a mut HashMap<String, ClientStats>, ip: &IpAddr) -> &'a mut ClientStats {
    let k = ip.to_string();
    m.entry(k.clone()).or_insert_with(|| ClientStats { ip: k, ..Default::default() })
}

fn read_int(path: &str) -> i64 {
    std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// Разобрать текст conntrack (тесты и чтение файла).
pub fn parse<R: BufRead>(r: R, c: &Ctx) -> Snapshot {
    let mut s = Snapshot::default();
    let mut r = r;
    let mut buf = String::with_capacity(512);
    loop {
        buf.clear();
        match r.read_line(&mut buf) {
            Ok(0) | Err(_) => break,
            _ => {}
        }
        let Some(l) = parse_line(&buf) else { continue };
        add(&mut s, l, c);
    }
    s
}

/// Учесть одну запись conntrack (из /proc или из netlink).
fn add(s: &mut Snapshot, l: Line, c: &Ctx) {
    s.parsed_total += 1;
    match l.proto {
        "tcp" => {
            s.tcp += 1;
            match l.state {
                "ESTABLISHED" => s.established += 1,
                "SYN_SENT" => s.syn_sent += 1,
                "SYN_RECV" => s.syn_recv += 1,
                "TIME_WAIT" => s.time_wait += 1,
                _ => {}
            }
        }
        "udp" => s.udp += 1,
        p if is_icmp(p) => s.icmp += 1,
        _ => {}
    }
    if ignored([&l.orig.src, &l.orig.dst, &l.reply.src, &l.reply.dst], c) {
        s.ignored_total += 1;
        return;
    }
    if c.want_flows {
        add_wan_flow(&mut s.wan_flows, &l, c);
    }
    let src_lan = in_nets(&l.orig.src, c.lan_nets);
    let dst_lan = in_nets(&l.orig.dst, c.lan_nets);
    let rsrc_lan = in_nets(&l.reply.src, c.lan_nets);
    let rdst_lan = in_nets(&l.reply.dst, c.lan_nets);
    let has_lan = src_lan || dst_lan || rsrc_lan || rdst_lan;
    let dst_router = in_list(&l.orig.dst, c.local_ips);
    let src_router = in_list(&l.orig.src, c.local_ips) || in_list(&l.orig.src, c.wan_ips);
    let cat = if src_router && !dst_lan && !dst_router {
        "router_own"
    } else if src_lan && !src_router && !dst_router && !dst_lan {
        "wan"
    } else if !src_lan && !src_router && has_lan && !dst_router {
        "incoming_forwarded"
    } else if src_lan && dst_router {
        "router"
    } else if src_lan && dst_lan {
        "local"
    } else if src_lan && !src_router && (c.mode == "all" || c.mode == "lan_only") {
        "wan"
    } else {
        ""
    };
    match cat {
        "wan" => {
            s.lan_to_wan += 1;
            if l.v6 { s.lan_to_wan_ipv6 += 1 } else { s.lan_to_wan_ipv4 += 1 }
            match l.proto {
                "tcp" => s.lan_to_wan_tcp += 1,
                "udp" => s.lan_to_wan_udp += 1,
                p if is_icmp(p) => s.lan_to_wan_icmp += 1,
                _ => {}
            }
        }
        "router_own" => {
            s.router_own += 1;
            if l.v6 { s.router_own_ipv6 += 1 } else { s.router_own_ipv4 += 1 }
            match l.proto {
                "tcp" => s.router_own_tcp += 1,
                "udp" => s.router_own_udp += 1,
                p if is_icmp(p) => s.router_own_icmp += 1,
                _ => {}
            }
            // служебное cgmon: метка сокета (пробы, свидетели, трассировка, проверки, DNS cgmon)
            // или цель проб WAN из настроек
            let probe = l.orig.dst.map_or(false, |d| crate::probe::is_service(l.proto, &d, l.orig.dport, l.orig.sport) || c.probes.iter().any(|(ip, p)| eq_ip(ip, &d) && *p == l.orig.dport));
            if probe {
                s.router_own_probe += 1;
                if l.proto == "tcp" { s.router_own_probe_tcp += 1 } else if l.proto == "udp" { s.router_own_probe_udp += 1 }
                if l.v6 { s.router_own_probe_ipv6 += 1 } else { s.router_own_probe_ipv4 += 1 }
            } else if is_tunnel_port(l.proto, l.orig.dport) {
                s.router_own_tunnel += 1;
                if l.proto == "tcp" { s.router_own_tunnel_tcp += 1 } else if l.proto == "udp" { s.router_own_tunnel_udp += 1 }
                if l.v6 { s.router_own_tunnel_ipv6 += 1 } else { s.router_own_tunnel_ipv4 += 1 }
            }
        }
        "incoming_forwarded" => {
            s.incoming_forwarded += 1;
            if l.v6 { s.incoming_ipv6 += 1 } else { s.incoming_ipv4 += 1 }
            match l.proto {
                "tcp" => s.incoming_tcp += 1,
                "udp" => s.incoming_udp += 1,
                p if is_icmp(p) => s.incoming_icmp += 1,
                _ => {}
            }
        }
        "router" => s.lan_to_router += 1,
        "local" => s.lan_to_local += 1,
        _ => {}
    }
    if src_lan && !src_router {
        let src = l.orig.src.unwrap();
        // «смотрит ТВ» — до фильтра режимов (router-потоки к портам ТВ)
        if cat == "router" && c.tv_ports.contains(&l.orig.dport) && l.proto == "tcp" && l.state == "ESTABLISHED" {
            client(&mut s.clients, &src).watching_tv = true;
        }
        if (c.mode == "lan_to_wan" && cat != "wan" && cat != "incoming_forwarded") || cat.is_empty() {
            return;
        }
        let cl = client(&mut s.clients, &src);
        cl.total += 1;
        match cat {
            "wan" => {
                cl.wan += 1;
                cl.bytes_up += l.orig_bytes;
                cl.bytes_down += l.reply_bytes;
            }
            "router" => cl.router += 1,
            "local" => cl.local += 1,
            _ => {}
        }
        update_proto(cl, l.proto, l.state);
    } else if cat == "incoming_forwarded" {
        let lan_ip = if dst_lan {
            l.orig.dst
        } else if rsrc_lan {
            l.reply.src
        } else if rdst_lan {
            l.reply.dst
        } else {
            None
        };
        if let Some(ip) = lan_ip {
            let cl = client(&mut s.clients, &ip);
            cl.total += 1;
            cl.incoming += 1;
            cl.bytes_down += l.orig_bytes;
            cl.bytes_up += l.reply_bytes;
            update_proto(cl, l.proto, l.state);
        }
    }
}

// ctnetlink (NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET) и его атрибуты
const SUBSYS_CTNETLINK: u16 = 1;
const CT_GET: u16 = 1;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_PROTOINFO: u16 = 4;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;
const TCP_STATES: [&str; 10] = ["NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2"];

fn nl_ip(d: &[u8]) -> Option<IpAddr> {
    match d.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(d).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(d).ok()?)),
        _ => None,
    }
}

fn nl_port(d: &[u8]) -> u16 {
    if d.len() >= 2 { u16::from_be_bytes([d[0], d[1]]) } else { 0 }
}

/// Кортеж ctnetlink → Tuple; номер протокола (из исходного кортежа).
fn nl_tuple(b: &[u8], t: &mut Tuple) -> u8 {
    let mut proto = 0;
    for (typ, d) in crate::nfnl::attrs(b) {
        match typ {
            CTA_TUPLE_IP => {
                for (k, v) in crate::nfnl::attrs(d) {
                    match k {
                        1 | 3 => t.src = nl_ip(v),
                        2 | 4 => t.dst = nl_ip(v),
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for (k, v) in crate::nfnl::attrs(d) {
                    match k {
                        CTA_PROTO_NUM => proto = v.first().copied().unwrap_or(0),
                        CTA_PROTO_SRC_PORT => t.sport = nl_port(v),
                        CTA_PROTO_DST_PORT => t.dport = nl_port(v),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    proto
}

fn nl_bytes(b: &[u8]) -> u64 {
    crate::nfnl::attrs(b).find(|(k, v)| *k == CTA_COUNTERS_BYTES && v.len() == 8).map(|(_, v)| u64::from_be_bytes(v.try_into().unwrap_or([0; 8]))).unwrap_or(0)
}

/// Запись ctnetlink → Line (None — не IPv4/IPv6 или без адресов).
fn nl_line(family: u8, p: &[u8]) -> Option<Line> {
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return None;
    }
    let mut l = Line { v6: family == libc::AF_INET6 as u8, ..Default::default() };
    let mut num = 0;
    let mut st: Option<u8> = None;
    for (typ, d) in crate::nfnl::attrs(p) {
        match typ {
            CTA_TUPLE_ORIG => num = nl_tuple(d, &mut l.orig),
            CTA_TUPLE_REPLY => {
                nl_tuple(d, &mut l.reply);
            }
            CTA_PROTOINFO => {
                for (k, v) in crate::nfnl::attrs(d) {
                    if k == CTA_PROTOINFO_TCP {
                        st = crate::nfnl::attrs(v).find(|(k, _)| *k == CTA_PROTOINFO_TCP_STATE).and_then(|(_, x)| x.first().copied());
                    }
                }
            }
            CTA_COUNTERS_ORIG => l.orig_bytes = nl_bytes(d),
            CTA_COUNTERS_REPLY => l.reply_bytes = nl_bytes(d),
            _ => {}
        }
    }
    l.proto = match num {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "ipv6-icmp",
        _ => "other",
    };
    if l.proto != "tcp" && l.proto != "udp" {
        // у ICMP нет портов (в /proc — type/code/id)
        l.orig.sport = 0;
        l.orig.dport = 0;
        l.reply.sport = 0;
        l.reply.dport = 0;
    }
    if l.proto == "tcp" {
        if let Some(s) = st.and_then(|i| TCP_STATES.get(i as usize)).and_then(|n| tcp_state(n)) {
            l.state = s;
        }
    }
    if l.orig.src.is_none() || l.orig.dst.is_none() {
        return None;
    }
    Some(l)
}

/// Таблица conntrack через ctnetlink: ядро помнит позицию между порциями
/// дампа. /proc/net/nf_conntrack на каждые 4 КБ вывода заново проходит хеш-
/// таблицу с начала: при 262144 корзинах это ~90 мс ядра на чтение даже при
/// тысяче записей. None — ctnetlink недоступен (нет модуля).
fn read_netlink(c: &Ctx) -> Option<Snapshot> {
    let mut s = Snapshot::default();
    let mut buf = Vec::new();
    crate::nfnl::dump_subsys(SUBSYS_CTNETLINK, CT_GET, libc::AF_UNSPEC as u8, &[], &mut buf, |fam, p| {
        if let Some(l) = nl_line(fam, p) {
            add(&mut s, l, c);
        }
    })
    .ok()?;
    Some(s)
}

/// Прочитать таблицу conntrack: ctnetlink, иначе /proc/net/nf_conntrack (или ip_conntrack).
pub fn read(c: &Ctx) -> Result<Snapshot, String> {
    let mut s = match read_netlink(c) {
        Some(s) => s,
        None => {
            let f = std::fs::File::open("/proc/net/nf_conntrack").or_else(|_| std::fs::File::open("/proc/net/ip_conntrack")).map_err(|e| e.to_string())?;
            parse(std::io::BufReader::with_capacity(64 * 1024, f), c)
        }
    };
    s.current = read_int("/proc/sys/net/netfilter/nf_conntrack_count");
    if s.current == 0 {
        s.current = s.parsed_total;
    }
    s.max = read_int("/proc/sys/net/netfilter/nf_conntrack_max");
    if s.max > 0 {
        s.usage_pct = s.current as f64 / s.max as f64 * 100.0;
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=198.51.100.9 sport=50000 dport=443 packets=5 bytes=1000 src=198.51.100.9 dst=203.0.113.2 sport=443 dport=50000 packets=6 bytes=5000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 20 src=192.168.1.10 dst=192.168.1.1 sport=5353 dport=53 packets=1 bytes=60 src=192.168.1.1 dst=192.168.1.10 sport=53 dport=5353 packets=1 bytes=120 mark=0 zone=0 use=2
ipv4     2 tcp      6 100 SYN_SENT src=203.0.113.2 dst=1.1.1.1 sport=40000 dport=443 packets=1 bytes=60 [UNREPLIED] src=1.1.1.1 dst=203.0.113.2 sport=443 dport=40000 packets=0 bytes=0 mark=0 zone=0 use=2
ipv4     2 tcp      6 300 ESTABLISHED src=198.51.100.50 dst=203.0.113.2 sport=60000 dport=8080 packets=3 bytes=300 src=192.168.1.20 dst=198.51.100.50 sport=80 dport=60000 packets=3 bytes=900 [ASSURED] mark=0 zone=0 use=2
ipv6     10 tcp      6 16 ESTABLISHED src=2001:0db8:0001:0000:0000:0000:0000:0005 dst=2a00:1450:4010:0c0a:0000:0000:0000:0064 sport=48336 dport=443 packets=1 bytes=80 src=2a00:1450:4010:0c0a:0000:0000:0000:0064 dst=2001:0db8:0001:0000:0000:0000:0000:0005 sport=443 dport=48336 packets=2 bytes=200 mark=0 zone=0 use=2
ipv4     2 udp      17 20 src=192.168.1.30 dst=100.64.0.7 sport=41641 dport=41641 packets=1 bytes=60 src=100.64.0.7 dst=192.168.1.30 sport=41641 dport=41641 packets=1 bytes=60 mark=0 zone=0 use=2
garbage line
";

    #[test]
    fn classify() {
        let lan = vec![IpNet::new("192.168.1.0".parse().unwrap(), 24), IpNet::new("2001:db8:1::".parse().unwrap(), 64)];
        let wan: Vec<IpAddr> = vec!["203.0.113.2".parse().unwrap()];
        let local: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        let tun = vec![IpNet::new("100.64.0.0".parse().unwrap(), 10)];
        let probes = vec![("1.1.1.1".parse().unwrap(), 443u16)];
        let c = Ctx { lan_nets: &lan, wan_ips: &wan, local_ips: &local, ignored_ips: &[], tunnel_nets: &tun, probes: &probes, mode: "lan_to_wan", tv_ports: &[], want_flows: true };
        let s = parse(SAMPLE.as_bytes(), &c);
        assert_eq!(s.parsed_total, 6);
        assert_eq!(s.ignored_total, 1); // туннель
        assert_eq!((s.lan_to_wan, s.lan_to_router, s.router_own, s.incoming_forwarded), (2, 1, 1, 1));
        assert_eq!((s.router_own_probe, s.lan_to_wan_ipv6), (1, 1));
        let a = &s.clients["192.168.1.10"];
        assert_eq!((a.wan, a.total, a.bytes_up, a.bytes_down, a.established), (1, 1, 1000, 5000, 1)); // router-поток в lan_to_wan не считается
        let b = &s.clients["192.168.1.20"];
        assert_eq!((b.incoming, b.bytes_down, b.bytes_up), (1, 300, 900));
        assert!(s.clients.contains_key("2001:db8:1::5"));
        assert!(s.wan_flows.contains_key("tcp 192.168.1.10:50000>198.51.100.9:443"));
        assert!(s.wan_flows.contains_key("tcp [2001:db8:1::5]:48336>[2a00:1450:4010:c0a::64]:443"));
    }

    fn nla(typ: u16, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        b.extend_from_slice(&typ.to_ne_bytes());
        b.extend_from_slice(data);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn nl_tuple_attr(typ: u16, src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Vec<u8> {
        let ip = [nla(1, &src), nla(2, &dst)].concat();
        let pr = [nla(1, &[6]), nla(2, &sp.to_be_bytes()), nla(3, &dp.to_be_bytes())].concat();
        nla(typ | 0x8000, &[nla(1 | 0x8000, &ip), nla(2 | 0x8000, &pr)].concat())
    }

    #[test]
    fn netlink_entry_same_as_proc_line() {
        let p = [
            nl_tuple_attr(1, [192, 168, 1, 10], [198, 51, 100, 9], 50000, 443),
            nl_tuple_attr(2, [198, 51, 100, 9], [203, 0, 113, 2], 443, 50000),
            nla(4 | 0x8000, &nla(1 | 0x8000, &nla(1, &[3]))),
            nla(9 | 0x8000, &[nla(1, &5u64.to_be_bytes()), nla(2, &1000u64.to_be_bytes())].concat()),
            nla(10 | 0x8000, &[nla(1, &6u64.to_be_bytes()), nla(2, &5000u64.to_be_bytes())].concat()),
        ]
        .concat();
        let a = nl_line(libc::AF_INET as u8, &p).unwrap();
        let b = parse_line(SAMPLE.lines().next().unwrap()).unwrap();
        assert_eq!((a.proto, a.state, a.v6, a.orig_bytes, a.reply_bytes), (b.proto, b.state, b.v6, b.orig_bytes, b.reply_bytes));
        assert_eq!((a.orig.src, a.orig.dst, a.orig.sport, a.orig.dport), (b.orig.src, b.orig.dst, b.orig.sport, b.orig.dport));
        assert_eq!((a.reply.src, a.reply.dst, a.reply.sport, a.reply.dport), (b.reply.src, b.reply.dst, b.reply.sport, b.reply.dport));
        // мусор и чужие семейства — не паника и не запись
        assert!(nl_line(7, &p).is_none());
        assert!(nl_line(libc::AF_INET as u8, &[1, 0, 0xff, 0xff, 9]).is_none());
    }
}
