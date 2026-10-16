//! Ловец устройств (перенос l2watch.go, devices.l2_watch), как IP Scan в
//! MikroTik: AF_PACKET на LAN слушает ARP, IPv6 NDP и широковещание /
//! link-local multicast; устройство с адресом не из подсети порта (камера со
//! статическим 192.168.1.64, 169.254.x.x) — в status `l2` (MAC, адрес, кого
//! ищет в ARP → подсказка подсети). Свои молчащие — тоже (own).
//! Побудка раз в 10 мин (l2_probe): ARP-обход своих подсетей порта, ping на
//! 255.255.255.255, WS-Discovery, SSDP, SADP. Скан типовых заводских сетей —
//! ARP-пробы от 0.0.0.0. Побудка и скан — в коротких потоках (паузы между
//! пакетами). «Открыть доступ»: адрес роутера в сети устройства + таблица
//! inet cgmon_l2 (masquerade, запрет ICMP redirect), на час.

use crate::json::J;
use crate::netx::IpNet;
use crate::synrtt::SockFilter;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const KEEP: i64 = 24 * 3600;
const MAX: usize = 512;
const SHOW: usize = 50;
const SHOW_OWN: usize = 150;
const PROBE_GAP: i64 = 600;
const ACCESS_FOR: i64 = 3600;
const ACCESS_MAX: usize = 4;
const ACCESS_FILE: &str = "/tmp/cgmon/l2access.json";

/// ARP; IPv4 на 239.255.255.250, 255.255.255.255, 224.0.0.0/24; ICMPv6 133–136.
const FILTER: [SockFilter; 16] = [
    SockFilter { code: 0x28, jt: 0, jf: 0, k: 0xfffff000 },
    SockFilter { code: 0x15, jt: 12, jf: 0, k: 0x0806 },
    SockFilter { code: 0x15, jt: 0, jf: 5, k: 0x0800 },
    SockFilter { code: 0x20, jt: 0, jf: 0, k: 0x10 },
    SockFilter { code: 0x15, jt: 9, jf: 0, k: 0xeffffffa },
    SockFilter { code: 0x15, jt: 8, jf: 0, k: 0xffffffff },
    SockFilter { code: 0x54, jt: 0, jf: 0, k: 0xffffff00 },
    SockFilter { code: 0x15, jt: 6, jf: 7, k: 0xe0000000 },
    SockFilter { code: 0x15, jt: 0, jf: 6, k: 0x86dd },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x06 },
    SockFilter { code: 0x15, jt: 0, jf: 4, k: 0x3a },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x28 },
    SockFilter { code: 0x35, jt: 0, jf: 2, k: 0x85 },
    SockFilter { code: 0x25, jt: 1, jf: 0, k: 0x88 },
    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x60 },
    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 },
];

/// Типовые заводские сети (роутеры, коммутаторы, камеры).
pub const SCAN_NETS: [&str; 25] = [
    "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.5.0/24",
    "192.168.8.0/24", "192.168.10.0/24", "192.168.11.0/24", "192.168.20.0/24", "192.168.31.0/24",
    "192.168.50.0/24", "192.168.88.0/24", "192.168.100.0/24", "192.168.123.0/24", "192.168.188.0/24",
    "192.168.199.0/24", "192.168.254.0/24", "192.0.0.0/24", "10.0.0.0/24", "10.0.1.0/24",
    "10.1.1.0/24", "10.10.10.0/24", "10.10.100.0/24", "172.16.0.0/24", "172.16.1.0/24",
];

#[derive(Clone, Debug, Default)]
pub struct Access {
    pub ip: String,
    pub dev: String,
    pub addr: String,
    pub net: String,
    pub until: i64,
}

#[derive(Clone, Debug, Default)]
pub struct Dev {
    pub mac: String,
    pub ip: String,
    pub dev: String,
    pub want: String,
    pub how: &'static str,
    pub tr: String,
    pub first: i64,
    pub last: i64,
    pub count: i64,
    pub own: bool,
}

#[derive(Clone)]
struct If {
    name: String,
    index: i32,
    mac: Option<[u8; 6]>,
    /// (свой адрес, его сеть)
    nets: Vec<(Ipv4Addr, IpNet)>,
}

pub struct L2Watch {
    pub on: bool,
    pub probe: bool,
    fd: Option<i32>,
    ifs: HashMap<i32, If>,
    self_mac: Vec<String>,
    routes: String,
    names: Vec<String>,
    devs: HashMap<String, Dev>,
    ll: HashMap<String, String>,
    probe_at: i64,
    access: HashMap<String, Access>,
    scanning: Arc<AtomicBool>,
    scan_at: i64,
    sweep_at: i64,
}

fn mac_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn read_mac(dev: &str) -> Option<[u8; 6]> {
    crate::devid::mac_bytes(std::fs::read_to_string(format!("/sys/class/net/{dev}/address")).ok()?.trim())
}

/// Адрес для компьютера в сети устройства: .250 в его /24 (не он и не шлюз); 169.254 — 169.254.1.250/16.
pub fn try_addr(ip: Ipv4Addr, want: Option<Ipv4Addr>) -> String {
    let v = ip.octets();
    if v[0] == 169 && v[1] == 254 {
        return "169.254.1.250/16".into();
    }
    for last in [250u8, 251, 252] {
        let c = Ipv4Addr::new(v[0], v[1], v[2], last);
        if c == ip || Some(c) == want {
            continue;
        }
        return format!("{c}/24");
    }
    String::new()
}

fn parse_net(s: &str) -> Option<IpNet> {
    let (ip, bits) = crate::netx::parse_cidr(s)?;
    Some(IpNet::new(ip, bits))
}

fn overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.ip) || b.contains(&a.ip)
}

/// Маршрут из «ip -4 route show table all», пересекающийся с n (кроме default); "" — свободно.
pub fn route_busy(out: &str, n: &IpNet) -> String {
    for line in out.lines() {
        let mut f: Vec<&str> = line.split_whitespace().collect();
        while let Some(x) = f.first() {
            if ["local", "broadcast", "unicast", "multicast", "unreachable", "blackhole", "prohibit", "throw", "nat", "anycast"].contains(x) {
                f.remove(0);
            } else {
                break;
            }
        }
        let Some(d) = f.first() else { continue };
        if *d == "default" {
            continue;
        }
        let d = if d.contains('/') { d.to_string() } else { format!("{d}/32") };
        let Some(rn) = parse_net(&d) else { continue };
        if !rn.is_v4() || rn.bits == 0 {
            continue;
        }
        if overlap(&rn, n) {
            return line.trim().to_string();
        }
    }
    String::new()
}

/// Устройство маршрута (не default), которым роутер уже достаёт ip.
pub fn route_dev(routes: &str, ip: &str) -> String {
    let Ok(a) = ip.parse::<IpAddr>() else { return String::new() };
    if !a.is_ipv4() || routes.is_empty() {
        return String::new();
    }
    let line = route_busy(routes, &IpNet::new(a, 32));
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.first() == Some(&"throw") {
        return String::new();
    }
    f.windows(2).find(|w| w[0] == "dev").map(|w| w[1].to_string()).unwrap_or_default()
}

/// Таблица inet cgmon_l2 под открытые доступы (пусто — удалить).
pub fn nft_script(acc: &[Access]) -> String {
    let mut b = String::from("table inet cgmon_l2\ndelete table inet cgmon_l2\n");
    if acc.is_empty() {
        return b;
    }
    let mut post: Vec<String> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    for a in acc {
        let p = format!("\t\toifname \"{}\" ip daddr {} masquerade\n", a.dev, a.net);
        if !post.contains(&p) {
            post.push(p);
        }
        let o = format!("\t\toifname \"{}\" icmp type redirect drop\n", a.dev);
        if !out.contains(&o) {
            out.push(o);
        }
    }
    post.sort();
    out.sort();
    b.push_str("table inet cgmon_l2 {\n\tchain post {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n");
    b.push_str(&post.concat());
    b.push_str("\t}\n\tchain out {\n\t\ttype filter hook output priority filter; policy accept;\n");
    b.push_str(&out.concat());
    b.push_str("\t}\n}\n");
    b
}

/// ARP who-has ко всем узлам n от адреса spa (0.0.0.0 — проба RFC 5227), сеть /22–/30.
pub fn arps(mac: [u8; 6], spa: Ipv4Addr, n: &IpNet) -> Vec<[u8; 28]> {
    let IpAddr::V4(base) = n.ip else { return Vec::new() };
    if n.bits < 22 || n.bits > 30 {
        return Vec::new();
    }
    let mask = u32::MAX << (32 - n.bits);
    let base = u32::from(base) & mask;
    let me = u32::from(spa);
    let size = 1u32 << (32 - n.bits);
    let mut out = Vec::new();
    for i in 1..size - 1 {
        let ip = base + i;
        if ip == me {
            continue;
        }
        let mut p = [0u8; 28];
        p[0..2].copy_from_slice(&1u16.to_be_bytes());
        p[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        p[4] = 6;
        p[5] = 4;
        p[6..8].copy_from_slice(&1u16.to_be_bytes());
        p[8..14].copy_from_slice(&mac);
        p[14..18].copy_from_slice(&spa.octets());
        p[24..28].copy_from_slice(&ip.to_be_bytes());
        out.push(p);
    }
    out
}

/// ARP-кадры на порт с паузой между ними (поток).
fn send_arps(index: i32, frames: &[[u8; 28]], gap_ms: u64) -> usize {
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (0x0806u16).to_be() as i32) };
    if fd < 0 {
        return 0;
    }
    let mut to: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    to.sll_family = libc::AF_PACKET as u16;
    to.sll_protocol = (0x0806u16).to_be();
    to.sll_ifindex = index;
    to.sll_halen = 6;
    to.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    let mut n = 0;
    for p in frames {
        if unsafe { libc::sendto(fd, p.as_ptr() as *const libc::c_void, p.len(), 0, &to as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) } > 0 {
            n += 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(gap_ms));
    }
    unsafe { libc::close(fd) };
    n
}

fn uuid() -> String {
    let (s, ns) = crate::util::now_wall();
    let a = (s as u64) << 32 | ns as u64;
    let b = (s as u64).wrapping_mul(2654435761);
    let x = [a.to_be_bytes(), b.to_be_bytes()].concat();
    let h = |r: std::ops::Range<usize>| x[r].iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("{}-{}-{}-{}-{}", h(0..4), h(4..6), h(6..8), h(8..10), h(10..16))
}

/// Побудка молчунов на портах (поток).
fn wake(ifs: Vec<If>) {
    let u = uuid();
    let wsd = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><e:Header><w:MessageID>uuid:{u}</w:MessageID><w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>");
    let ssdp = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    let sadp = format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>{u}</Uuid><Types>inquiry</Types></Probe>");
    for x in ifs {
        if let Some(mac) = x.mac {
            for (me, n) in &x.nets {
                send_arps(x.index, &arps(mac, *me, n), 20); // ~50/с: дешёвые коммутаторы режут частые ARP
            }
        }
        unsafe {
            let dev = x.name.as_bytes();
            // широковещательный ping
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMP);
            if fd >= 0 {
                let one: i32 = 1;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, &one as *const i32 as *const libc::c_void, 4);
                if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr() as *const libc::c_void, dev.len() as u32) == 0 {
                    let mut m = [8u8, 0, 0, 0, 0x6c, 0x32, 0, 1];
                    let mut s: u32 = 0;
                    for i in (0..8).step_by(2) {
                        s += (m[i] as u32) << 8 | m[i + 1] as u32;
                    }
                    while s >> 16 != 0 {
                        s = (s & 0xffff) + (s >> 16);
                    }
                    let cs = !(s as u16);
                    m[2..4].copy_from_slice(&cs.to_be_bytes());
                    let (sa, l) = crate::netx::sockaddr_of(&IpAddr::V4(Ipv4Addr::BROADCAST), 0);
                    libc::sendto(fd, m.as_ptr() as *const libc::c_void, m.len(), 0, &sa as *const _ as *const libc::sockaddr, l);
                }
                libc::close(fd);
            }
            // WS-Discovery (ONVIF), SSDP, Hikvision SADP
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if fd >= 0 {
                let mr = libc::ip_mreqn { imr_multiaddr: libc::in_addr { s_addr: 0 }, imr_address: libc::in_addr { s_addr: 0 }, imr_ifindex: x.index };
                if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr() as *const libc::c_void, dev.len() as u32) == 0
                    && libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &mr as *const _ as *const libc::c_void, std::mem::size_of::<libc::ip_mreqn>() as u32) == 0
                {
                    let g = IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250));
                    for (port, msg) in [(3702u16, wsd.as_bytes()), (1900, ssdp.as_bytes()), (37020, sadp.as_bytes())] {
                        let (sa, l) = crate::netx::sockaddr_of(&g, port);
                        libc::sendto(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0, &sa as *const _ as *const libc::sockaddr, l);
                    }
                }
                libc::close(fd);
            }
        }
    }
}

fn run(args: &[&str]) -> Result<(), String> {
    if crate::util::readonly() {
        return Ok(());
    }
    let o = std::process::Command::new(args[0]).args(&args[1..]).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("exit status {} {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(())
}

impl L2Watch {
    pub fn new() -> L2Watch {
        L2Watch { on: false, probe: false, fd: None, ifs: HashMap::new(), self_mac: Vec::new(), routes: String::new(), names: Vec::new(), devs: HashMap::new(), ll: HashMap::new(), probe_at: 0, access: HashMap::new(), scanning: Arc::new(AtomicBool::new(false)), scan_at: 0, sweep_at: 0 }
    }

    pub fn set_config(&mut self, on: bool, probe: bool) {
        if self.on && !on {
            self.devs.clear();
            self.ll.clear();
        }
        self.on = on;
        self.probe = probe;
    }

    /// Открыть/закрыть сокет по флагу. Возвращает (закрытый, новый) fd.
    pub fn ensure(&mut self) -> (Option<i32>, Option<i32>) {
        match (self.on, self.fd) {
            (true, None) => match crate::synrtt::packet_socket(FILTER.as_ptr() as *const u8, FILTER.len(), 0) {
                Ok(fd) => {
                    crate::log_info!("l2watch: listening for devices with foreign addresses on LAN");
                    self.fd = Some(fd);
                    (None, Some(fd))
                }
                Err(e) => {
                    crate::log_err!("l2watch: {}", e);
                    (None, None)
                }
            },
            (false, Some(fd)) => {
                self.fd = None;
                unsafe { libc::close(fd) };
                (Some(fd), None)
            }
            _ => (None, None),
        }
    }

    /// LAN-интерфейсы и их IPv4-подсети (при обновлении топологии).
    pub fn set_ifaces(&mut self, names: &[String]) {
        let mut m = HashMap::new();
        let mut selfm = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
            for e in rd.flatten() {
                if let Some(b) = read_mac(&e.file_name().to_string_lossy()) {
                    selfm.push(mac_str(&b));
                }
            }
        }
        // сеть, открытая для доступа, — всё ещё «чужая»
        let opened: Vec<String> = self.access.values().map(|a| a.addr.split('/').next().unwrap_or("").to_string()).collect();
        for n in names {
            let Ok(c) = std::ffi::CString::new(n.as_str()) else { continue };
            let idx = unsafe { libc::if_nametoindex(c.as_ptr()) } as i32;
            if idx == 0 {
                continue;
            }
            let nets = crate::netx::addrs_of(n).into_iter().filter_map(|(a, b)| match a {
                IpAddr::V4(v) if !opened.contains(&v.to_string()) => Some((v, IpNet::new(a, b))),
                _ => None,
            }).collect();
            m.insert(idx, If { name: n.clone(), index: idx, mac: read_mac(n), nets });
        }
        self.ifs = m;
        self.names = names.to_vec();
        self.self_mac = selfm;
    }

    /// Сокет готов: кадры; раз в минуту — маршруты и забывание; побудка по сроку.
    pub fn on_readable(&mut self, unix: i64) {
        let Some(fd) = self.fd else { return };
        let mut buf = [0u8; 128];
        loop {
            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut l = std::mem::size_of::<libc::sockaddr_ll>() as u32;
            let n = unsafe { libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT, &mut sll as *mut _ as *mut libc::sockaddr, &mut l) };
            if n < 0 {
                break;
            }
            if sll.sll_pkttype == libc::PACKET_OUTGOING as u8 || sll.sll_halen != 6 {
                continue;
            }
            let mac = mac_str(&sll.sll_addr[..6]);
            let p = buf[..n as usize].to_vec();
            self.on_packet(unix, sll.sll_ifindex, &mac, u16::from_be(sll.sll_protocol), &p);
        }
    }

    /// Такт: забывание, маршруты (раз в минуту), побудка (раз в 10 мин).
    pub fn tick(&mut self, unix: i64) {
        if !self.on {
            return;
        }
        if unix - self.sweep_at >= 60 {
            self.sweep_at = unix;
            self.routes = std::process::Command::new("ip").args(["-4", "route", "show", "table", "all"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
            self.devs.retain(|_, d| unix - d.last <= KEEP);
            let live: Vec<String> = self.devs.values().map(|d| d.mac.clone()).collect();
            self.ll.retain(|m, _| live.contains(m));
        }
        if self.probe && unix - self.probe_at >= PROBE_GAP && !self.ifs.is_empty() {
            self.probe_at = unix;
            let ifs: Vec<If> = self.ifs.values().cloned().collect();
            let _ = std::thread::Builder::new().name("cgmon-l2wake".into()).stack_size(128 << 10).spawn(move || wake(ifs));
        }
    }

    pub fn on_packet(&mut self, now: i64, ifindex: i32, mac: &str, proto: u16, p: &[u8]) {
        let Some(ifc) = self.ifs.get(&ifindex) else { return };
        if self.self_mac.iter().any(|m| m == mac) {
            return;
        }
        let (ip, mut want, how): (Ipv4Addr, Option<Ipv4Addr>, &'static str) = match proto {
            0x0806 => {
                if p.len() < 28 || u16::from_be_bytes([p[2], p[3]]) != 0x0800 || p[4] != 6 || p[5] != 4 {
                    return;
                }
                let (mut ip, mut want) = (Ipv4Addr::new(p[14], p[15], p[16], p[17]), Some(Ipv4Addr::new(p[24], p[25], p[26], p[27])));
                let mut how = "arp";
                if ip.is_unspecified() {
                    // проба DAD: адрес, который устройство хочет занять
                    ip = want.unwrap();
                    want = None;
                    how = "probe";
                }
                if u16::from_be_bytes([p[6], p[7]]) != 1 || want == Some(ip) {
                    want = None; // ответ или gratuitous
                }
                (ip, want, how)
            }
            0x0800 => {
                if p.len() < 20 {
                    return;
                }
                (Ipv4Addr::new(p[12], p[13], p[14], p[15]), None, "mcast")
            }
            0x86dd => {
                if p.len() >= 40 && p[8] == 0xfe && p[9] & 0xc0 == 0x80 {
                    let a: [u8; 16] = p[8..24].try_into().unwrap();
                    self.ll.insert(mac.to_string(), std::net::Ipv6Addr::from(a).to_string());
                }
                return;
            }
            _ => return,
        };
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() {
            return;
        }
        let own = ifc.nets.iter().any(|(_, n)| n.contains(&IpAddr::V4(ip)));
        let name = ifc.name.clone();
        let k = format!("{mac}|{ip}");
        if !self.devs.contains_key(&k) {
            if self.devs.len() >= MAX {
                if let Some(old) = self.devs.iter().min_by_key(|(_, d)| d.last).map(|(k, _)| k.clone()) {
                    self.devs.remove(&old);
                }
            }
            let mut d = Dev { mac: mac.to_string(), ip: ip.to_string(), first: now, own, ..Default::default() };
            if !own {
                d.tr = try_addr(ip, want);
                crate::log_info!("l2watch: {} {} on {} (foreign address, seen by {})", mac, d.ip, name, how);
            }
            self.devs.insert(k.clone(), d);
        }
        let d = self.devs.get_mut(&k).unwrap();
        d.dev = name;
        d.last = now;
        d.how = how;
        d.own = own;
        if own {
            d.tr.clear();
            d.want.clear();
        }
        d.count += 1;
        if let Some(w) = want.take().filter(|w| !own && !w.is_unspecified()) {
            d.want = w.to_string();
            if d.tr.is_empty() || try_addr(ip, None) == d.tr {
                d.tr = try_addr(ip, Some(w));
            }
        }
    }

    fn save_access(&self) {
        if crate::util::readonly() {
            return;
        }
        if self.access.is_empty() {
            let _ = std::fs::remove_file(ACCESS_FILE);
            return;
        }
        let mut j = J::new();
        j.arr();
        for a in self.access.values() {
            j.obj().key("ip").str(&a.ip).key("dev").str(&a.dev).key("addr").str(&a.addr).key("net").str(&a.net).key("until").int(a.until).end_obj();
        }
        j.end_arr();
        let _ = crate::util::write_atomic(ACCESS_FILE, j.b.as_bytes(), 0o600);
    }

    fn access_list(&self) -> Vec<Access> {
        let mut l: Vec<Access> = self.access.values().cloned().collect();
        l.sort_by(|a, b| a.ip.cmp(&b.ip));
        l
    }

    /// Открыть (или продлить) доступ к пойманному устройству.
    pub fn open(&mut self, ip: &str, now: i64) -> Result<Access, String> {
        if !self.on {
            return Err("cgfinder выключен".into());
        }
        let Ok(IpAddr::V4(v)) = ip.parse::<IpAddr>() else { return Err("нужен IPv4-адрес".into()) };
        let o = v.octets();
        let private = v.is_private() || (o[0] == 169 && o[1] == 254);
        if !private {
            return Err(format!("{ip} не из частных сетей — доступ не открываю"));
        }
        if let Some(a) = self.access.get_mut(ip) {
            a.until = now + ACCESS_FOR;
            let c = a.clone();
            self.save_access();
            return Ok(c);
        }
        let Some(dev) = self.devs.values().filter(|d| d.ip == ip && !d.own).max_by_key(|d| d.last).cloned() else {
            return Err(format!("{ip} нет среди пойманных устройств"));
        };
        if self.access.len() >= ACCESS_MAX {
            return Err(format!("открыто уже {ACCESS_MAX} доступа — закройте лишний"));
        }
        let mut a = Access { ip: ip.into(), dev: dev.dev.clone(), addr: dev.tr.clone(), net: String::new(), until: now + ACCESS_FOR };
        if a.addr.is_empty() {
            a.addr = try_addr(v, dev.want.parse().ok());
        }
        let mut shared = false; // сеть уже открыта для соседнего устройства — тот же адрес
        for x in self.access.values() {
            if parse_net(&x.net).map_or(false, |n| n.contains(&IpAddr::V4(v))) {
                if x.dev != a.dev {
                    return Err(format!("сеть {} уже открыта на {}", x.net, x.dev));
                }
                a.addr = x.addr.clone();
                shared = true;
            }
        }
        let Some((aip, bits)) = crate::netx::parse_cidr(&a.addr) else { return Err(format!("не подобрать адрес роутеру в сети {ip}")) };
        if aip == IpAddr::V4(v) {
            return Err(format!("не подобрать адрес роутеру в сети {ip}"));
        }
        let an = IpNet::new(aip, bits);
        a.net = format!("{}/{}", an.ip, an.bits);
        if !shared {
            let why = net_busy(&an);
            if !why.is_empty() {
                return Err(format!("сеть {} уже используется на роутере ({why}) — доступ не открываю", a.net));
            }
            run(&["ip", "addr", "add", &a.addr, "dev", &a.dev]).map_err(|e| format!("ip addr add: {e}"))?;
        }
        self.access.insert(ip.into(), a.clone());
        if let Err(e) = crate::acct::nft_script(&nft_script(&self.access_list())) {
            self.access.remove(ip);
            if !shared {
                let _ = run(&["ip", "addr", "del", &a.addr, "dev", &a.dev]);
            }
            return Err(format!("nft: {e}"));
        }
        self.save_access();
        crate::log_info!("l2watch: access to {} opened: router {} on {}, NAT into {} for 1h", ip, a.addr, a.dev, a.net);
        Ok(a)
    }

    pub fn close(&mut self, ip: &str) -> Result<(), String> {
        let Some(a) = self.access.remove(ip) else { return Err(format!("доступ к {ip} не открыт")) };
        if let Err(e) = crate::acct::nft_script(&nft_script(&self.access_list())) {
            crate::log_err!("l2watch: nft on close: {}", e);
        }
        if !self.access.values().any(|x| x.addr == a.addr && x.dev == a.dev) {
            let _ = run(&["ip", "addr", "del", &a.addr, "dev", &a.dev]);
        }
        self.save_access();
        crate::log_info!("l2watch: access to {} closed", ip);
        Ok(())
    }

    /// Истёкшие (и все, если ловец выключен) — закрыть; каждый такт.
    pub fn expire(&mut self, now: i64) {
        let due: Vec<String> = self.access.values().filter(|a| now >= a.until || !self.on).map(|a| a.ip.clone()).collect();
        for ip in due {
            let _ = self.close(&ip);
        }
    }

    /// При старте: закрыть доступы, оставшиеся от прошлого запуска.
    pub fn cleanup() {
        let Ok(t) = std::fs::read_to_string(ACCESS_FILE) else { return };
        if let Ok(crate::value::Value::List(l)) = crate::value::parse_json(&t) {
            for v in l {
                let (addr, dev) = (crate::dnsguard::vstr(&v, "addr"), crate::dnsguard::vstr(&v, "dev"));
                if !addr.is_empty() && !dev.is_empty() {
                    let _ = run(&["ip", "addr", "del", &addr, "dev", &dev]);
                }
            }
        }
        let _ = crate::acct::nft_script(&nft_script(&[]));
        if !crate::util::readonly() {
            let _ = std::fs::remove_file(ACCESS_FILE);
        }
        crate::log_info!("l2watch: closed device access left from the previous run");
    }

    /// Скан типовых заводских сетей (ARP-пробы от 0.0.0.0) на каждом порту, в потоке.
    pub fn scan(&mut self, now: i64) -> Result<usize, String> {
        if !self.on {
            return Err("cgfinder выключен".into());
        }
        if self.scanning.load(Ordering::Relaxed) || now - self.scan_at < 30 {
            return Err("скан уже идёт или был меньше 30 с назад".into());
        }
        self.scan_at = now;
        self.scanning.store(true, Ordering::Relaxed);
        let ifs: Vec<If> = self.ifs.values().cloned().collect();
        let flag = self.scanning.clone();
        let r = std::thread::Builder::new().name("cgmon-l2scan".into()).stack_size(128 << 10).spawn(move || {
            let mut sent = 0;
            for x in &ifs {
                let Some(mac) = x.mac else { continue };
                for c in SCAN_NETS {
                    let n = parse_net(c).unwrap();
                    if x.nets.iter().any(|(_, m)| overlap(m, &n)) {
                        continue;
                    }
                    sent += send_arps(x.index, &arps(mac, Ipv4Addr::UNSPECIFIED, &n), 8);
                }
            }
            crate::log_info!("l2watch: scanned typical networks: {} ARP probes on {} ports", sent, ifs.len());
            flag.store(false, Ordering::Relaxed);
        });
        if r.is_err() {
            self.scanning.store(false, Ordering::Relaxed);
        }
        Ok(SCAN_NETS.len())
    }

    /// Найденные за сутки: чужие, потом свои, свежие первыми.
    pub fn status_json(&self, j: &mut J, name: &dyn Fn(&str, &str, bool) -> String) {
        j.obj().key("on").bool(true);
        if !self.names.is_empty() {
            j.key("ifs").arr();
            for n in &self.names {
                j.str(n);
            }
            j.end_arr();
        }
        if self.probe_at != 0 {
            j.key("probe").int(self.probe_at);
        }
        let mut l: Vec<&Dev> = self.devs.values().collect();
        l.sort_by(|a, b| a.own.cmp(&b.own).then(b.last.cmp(&a.last)).then(a.ip.cmp(&b.ip)));
        let (mut nf, mut no) = (0, 0);
        let keep: Vec<&Dev> = l.into_iter().filter(|d| {
            if d.own && no < SHOW_OWN {
                no += 1;
                true
            } else if !d.own && nf < SHOW {
                nf += 1;
                true
            } else {
                false
            }
        }).collect();
        if !keep.is_empty() {
            j.key("devs").arr();
            for d in keep {
                j.obj().key("mac").str(&d.mac).key("ip").str(&d.ip).key("dev").str(&d.dev);
                if !d.want.is_empty() {
                    j.key("want").str(&d.want);
                }
                if let Some(ll) = self.ll.get(&d.mac) {
                    j.key("ll").str(ll);
                }
                j.key("how").str(d.how);
                let n = name(&d.ip, &d.mac, d.own);
                if !n.is_empty() {
                    j.key("name").str(&n);
                }
                if !d.tr.is_empty() {
                    j.key("try").str(&d.tr);
                }
                j.key("first").int(d.first).key("last").int(d.last).key("count").int(d.count);
                if d.own {
                    j.key("own").bool(true);
                } else {
                    let via = route_dev(&self.routes, &d.ip);
                    if !via.is_empty() {
                        j.key("via").str(&via);
                    }
                }
                j.end_obj();
            }
            j.end_arr();
        }
        let acc = self.access_list();
        if !acc.is_empty() {
            j.key("access").arr();
            for a in acc {
                j.obj().key("ip").str(&a.ip).key("dev").str(&a.dev).key("addr").str(&a.addr).key("net").str(&a.net).key("until").int(a.until).end_obj();
            }
            j.end_arr();
        }
        if self.scan_at != 0 {
            j.key("scan_at").int(self.scan_at);
        }
        if self.scanning.load(Ordering::Relaxed) {
            j.key("scanning").bool(true);
        }
        j.key("scan_nets").int(SCAN_NETS.len() as i64);
        j.end_obj();
    }

    pub fn access_json(a: &Access) -> String {
        let mut j = J::new();
        j.obj().key("ip").str(&a.ip).key("dev").str(&a.dev).key("addr").str(&a.addr).key("net").str(&a.net).key("until").int(a.until).end_obj();
        j.b
    }
}

/// Сеть уже есть на роутере (адрес интерфейса или маршрут).
fn net_busy(n: &IpNet) -> String {
    for (name, ip, bits) in crate::netx::if_addrs() {
        if ip.is_ipv4() && !ip.is_loopback() && overlap(&IpNet::new(ip, bits), n) {
            return format!("{ip}/{bits} на {name}");
        }
    }
    match std::process::Command::new("ip").args(["-4", "route", "show", "table", "all"]).output() {
        Ok(o) => route_busy(&String::from_utf8_lossy(&o.stdout), n),
        Err(_) => "маршруты не прочитать".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(try_addr(Ipv4Addr::new(192, 168, 1, 64), Some(Ipv4Addr::new(192, 168, 1, 250))), "192.168.1.251/24");
        assert_eq!(try_addr(Ipv4Addr::new(169, 254, 3, 4), None), "169.254.1.250/16");
        let n = parse_net("192.168.1.0/24").unwrap();
        assert!(route_busy("default via 10.0.0.1 dev eth0\n192.168.0.0/16 dev tailscale0 table 52\n", &n).contains("tailscale0"));
        assert_eq!(route_dev("throw 192.168.1.0/24 table 52\n", "192.168.1.5"), "");
        assert_eq!(arps([2, 0, 0, 0, 0, 1], Ipv4Addr::UNSPECIFIED, &n).len(), 254);
        assert!(nft_script(&[Access { ip: "192.168.1.64".into(), dev: "lan1".into(), addr: "192.168.1.250/24".into(), net: "192.168.1.0/24".into(), until: 0 }]).contains("oifname \"lan1\" ip daddr 192.168.1.0/24 masquerade"));
    }

    #[test]
    fn catches_foreign_arp() {
        let mut w = L2Watch::new();
        w.on = true;
        w.ifs.insert(3, If { name: "lan1".into(), index: 3, mac: None, nets: vec![(Ipv4Addr::new(10, 10, 0, 1), parse_net("10.10.0.1/24").unwrap())] });
        let mut p = [0u8; 28];
        p[0..2].copy_from_slice(&1u16.to_be_bytes());
        p[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        p[4] = 6;
        p[5] = 4;
        p[6..8].copy_from_slice(&1u16.to_be_bytes());
        p[14..18].copy_from_slice(&[192, 168, 1, 64]);
        p[24..28].copy_from_slice(&[192, 168, 1, 1]);
        w.on_packet(100, 3, "02:00:00:00:00:09", 0x0806, &p);
        let d = &w.devs["02:00:00:00:00:09|192.168.1.64"];
        assert!(!d.own && d.want == "192.168.1.1" && d.tr == "192.168.1.250/24" && d.how == "arp", "{d:?}");
    }
}
