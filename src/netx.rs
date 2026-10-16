//! Сетевые мелочи с семантикой Go (net.SplitHostPort, net.ParseCIDR, url.Parse).

use std::net::IpAddr;

/// "host:port" / "[v6]:port" → (host, port), как net.SplitHostPort.
pub fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        if port.contains(':') {
            return None;
        }
        return Some((host, port));
    }
    let i = s.rfind(':')?;
    let (h, p) = (&s[..i], &s[i + 1..]);
    if h.contains(':') {
        return None; // IPv6 без скобок
    }
    Some((h, p))
}

pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// Адрес как IPv4 (включая IPv4-mapped IPv6, как Go To4).
pub fn to4(ip: &IpAddr) -> Option<[u8; 4]> {
    match ip {
        IpAddr::V4(a) => Some(a.octets()),
        IpAddr::V6(a) => a.to_ipv4_mapped().map(|x| x.octets()),
    }
}

/// "a.b.c.d/n" или "x::/n" → (адрес, длина префикса).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, n) = s.split_once('/')?;
    let ip: IpAddr = a.parse().ok()?;
    let n: u8 = n.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if n > max || n.to_string() != s.split_once('/')?.1 {
        return None;
    }
    Some((ip, n))
}

/// Частный IPv4 (RFC1918) — как Go IP.IsPrivate для IPv4.
pub fn is_private4(a: [u8; 4]) -> bool {
    a[0] == 10 || (a[0] == 172 && a[1] & 0xf0 == 16) || (a[0] == 192 && a[1] == 168)
}

/// Схема и хост ссылки (как url.Parse для простых http(s)://host[:port]/…).
pub fn url_scheme_host(u: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = u.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.') {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    if host.contains(char::is_whitespace) {
        return None;
    }
    Some((scheme, host))
}

/// Адреса интерфейсов (getifaddrs): (имя, адрес, длина префикса).
pub fn if_addrs() -> Vec<(String, IpAddr, u8)> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut p = ifap;
    while !p.is_null() {
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        let fam = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        let (ip, bits) = match fam {
            libc::AF_INET => {
                let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let m = if ifa.ifa_netmask.is_null() { 0 } else { u32::from_be(unsafe { (*(ifa.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr }).count_ones() };
                (IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))), m as u8)
            }
            libc::AF_INET6 => {
                let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let m = if ifa.ifa_netmask.is_null() { 0 } else { unsafe { (*(ifa.ifa_netmask as *const libc::sockaddr_in6)).sin6_addr.s6_addr }.iter().map(|b| b.count_ones()).sum() };
                (IpAddr::V6(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr)), m as u8)
            }
            _ => continue,
        };
        out.push((name, ip, bits));
    }
    unsafe { libc::freeifaddrs(ifap) };
    out
}

/// Устройство IPv4-маршрута по умолчанию (/proc/net/route).
pub fn default_route_interface() -> String {
    let Ok(t) = std::fs::read_to_string("/proc/net/route") else { return String::new() };
    for l in t.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000" {
            return f[0].to_string();
        }
    }
    String::new()
}

/// Устройства маршрутов ::/0 (включая «default from …»).
pub fn ipv6_default_devices() -> Vec<String> {
    let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") else { return Vec::new() };
    t.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 10 && f[0] == "00000000000000000000000000000000" && f[1] == "00").then(|| f[9].to_string())
        })
        .collect()
}

/// Рабочий ::/0 (не «unreachable default» через lo с RTF_REJECT).
pub fn has_ipv6_default_route() -> bool {
    let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") else { return true };
    t.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 10 && f[0] == "00000000000000000000000000000000" && f[1] == "00" && u32::from_str_radix(f[8], 16).map_or(true, |fl| fl & 0x0200 == 0) && f[9] != "lo"
    })
}

/// Глобальный unicast IPv6, не ULA (fc00::/7: LAN, tailscale fd7a::).
pub fn is_public_ipv6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.to_ipv4_mapped().is_some() || a.is_loopback() || a.is_unspecified() || a.is_multicast() {
                return false;
            }
            let link_local = s[0] & 0xffc0 == 0xfe80;
            let ula = s[0] & 0xfe00 == 0xfc00;
            !link_local && !ula
        }
        _ => false,
    }
}

/// Туннели (tailscale, ZeroTier, WireGuard, tun): не WAN.
pub fn is_tunnel_dev(d: &str) -> bool {
    d.starts_with("tailscale") || d.starts_with("zt") || d.starts_with("wg") || d.starts_with("tun")
}

/// Источник для привязки сокета (sockaddr) и длина.
pub fn sockaddr_of(ip: &IpAddr, port: u16) -> (libc::sockaddr_storage, u32) {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match ip {
        IpAddr::V4(a) => {
            let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as u16;
            sin.sin_port = port.to_be();
            sin.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        IpAddr::V6(a) => {
            let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as u16;
            sin6.sin6_port = port.to_be();
            sin6.sin6_addr = libc::in6_addr { s6_addr: a.octets() };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as u32)
}

pub fn ip_of_sockaddr(ss: &libc::sockaddr_storage) -> Option<IpAddr> {
    match ss.ss_family as i32 {
        libc::AF_INET => {
            let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Маршрут до dst у ядра (connect UDP без отправки, с учётом ip rule):
/// рабочий, если выбран публичный источник; src — привязка (WAN IPv6).
pub fn routable_ipv6(dst: &IpAddr, src: Option<&IpAddr>) -> bool {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return false;
    }
    let ok = (|| {
        if let Some(s) = src {
            let (sa, l) = sockaddr_of(s, 0);
            if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
                return false;
            }
        }
        let (sa, l) = sockaddr_of(dst, 53);
        if unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
            return false;
        }
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut sl = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        if unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) } < 0 {
            return false;
        }
        ip_of_sockaddr(&ss).map_or(false, |ip| is_public_ipv6(&ip))
    })();
    unsafe { libc::close(fd) };
    ok
}

/// Сеть (адрес уже с маской) как Go net.IPNet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub ip: IpAddr,
    pub bits: u8,
}

fn v4u(ip: &IpAddr) -> Option<u32> {
    to4(ip).map(u32::from_be_bytes)
}

impl IpNet {
    /// Сеть по адресу и длине префикса (адрес маскируется).
    pub fn new(ip: IpAddr, bits: u8) -> IpNet {
        match ip {
            IpAddr::V4(a) => {
                let b = bits.min(32);
                let m = if b == 0 { 0 } else { u32::MAX << (32 - b) };
                IpNet { ip: IpAddr::V4((u32::from(a) & m).into()), bits: b }
            }
            IpAddr::V6(a) => {
                let b = bits.min(128);
                let m = if b == 0 { 0 } else { u128::MAX << (128 - b) };
                IpNet { ip: IpAddr::V6((u128::from(a) & m).into()), bits: b }
            }
        }
    }

    pub fn is_v4(&self) -> bool {
        self.ip.is_ipv4()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self.ip {
            IpAddr::V4(n) => match v4u(ip) {
                Some(a) => {
                    let m = if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits) };
                    a & m == u32::from(n)
                }
                None => false,
            },
            IpAddr::V6(n) => match ip {
                IpAddr::V6(a) => {
                    let m = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits) };
                    u128::from(*a) & m == u128::from(n)
                }
                _ => false,
            },
        }
    }

    /// Пересекаются (одна содержит другую).
    pub fn overlaps(&self, o: &IpNet) -> bool {
        self.contains(&o.ip) || o.contains(&self.ip)
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.bits)
    }
}

/// Список сетей как Go parseCIDRs: адрес без маски — /32 (/128); ошибка — Err.
pub fn parse_nets(list: &[String]) -> Result<Vec<IpNet>, String> {
    let mut out = Vec::new();
    for s in list {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let full = if s.contains('/') { s.to_string() } else if s.contains(':') { format!("{s}/128") } else { format!("{s}/32") };
        let (ip, bits) = parse_cidr(&full).ok_or(format!("invalid CIDR address: {s}"))?;
        out.push(IpNet::new(ip, bits));
    }
    Ok(out)
}

pub fn in_nets(ip: &IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// Служебный адрес: loopback, link-local, мультикаст link-local, нулевой.
pub fn is_unwanted(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_link_local() || a.is_unspecified() || (a.octets()[0] == 224 && a.octets()[1] == 0 && a.octets()[2] == 0),
        IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || (a.segments()[0] & 0xffc0 == 0xfe80) || (a.segments()[0] & 0xff0f == 0xff02),
    }
}

/// Интерфейсы ядра: (имя, индекс, флаги IFF_*), по индексу.
pub fn interfaces() -> Vec<(String, u32, u32)> {
    let mut out: Vec<(String, u32, u32)> = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut p = ifap;
    while !p.is_null() {
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        if out.iter().any(|(n, _, _)| *n == name) {
            continue;
        }
        let idx = unsafe { libc::if_nametoindex(ifa.ifa_name) };
        out.push((name, idx, ifa.ifa_flags));
    }
    unsafe { libc::freeifaddrs(ifap) };
    out.sort_by_key(|x| x.1);
    out
}

/// Адреса одного интерфейса: сначала IPv4, потом IPv6 (как Go Interface.Addrs).
pub fn addrs_of(dev: &str) -> Vec<(IpAddr, u8)> {
    let mut v: Vec<(IpAddr, u8)> = if_addrs().into_iter().filter(|(n, _, _)| n == dev).map(|(_, ip, b)| (ip, b)).collect();
    v.sort_by_key(|(ip, _)| ip.is_ipv6());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("1.1.1.1:443"), Some(("1.1.1.1", "443")));
        assert_eq!(split_host_port("[2606:4700::1111]:443"), Some(("2606:4700::1111", "443")));
        assert_eq!(split_host_port("2606::1:443"), None);
        assert_eq!(split_host_port("x"), None);
        assert_eq!(parse_cidr("192.0.2.0/24").map(|x| x.1), Some(24));
        assert!(parse_cidr("192.0.2.0/33").is_none());
        assert!(parse_cidr("192.0.2.0").is_none());
        assert_eq!(url_scheme_host("http://192.0.2.1:7788/api/v1/report"), Some(("http", "192.0.2.1:7788")));
        assert!(is_private4([172, 20, 0, 1]) && !is_private4([172, 32, 0, 1]));
        let n = IpNet::new("192.168.7.99".parse().unwrap(), 24);
        assert_eq!(n.to_string(), "192.168.7.0/24");
        assert!(n.contains(&"192.168.7.1".parse().unwrap()) && !n.contains(&"192.168.8.1".parse().unwrap()));
        assert!(n.contains(&"::ffff:192.168.7.5".parse().unwrap()));
        assert_eq!(parse_nets(&["10.0.0.1".into(), " ".into(), "2001:db8::/32".into()]).unwrap().iter().map(|x| x.to_string()).collect::<Vec<_>>(), vec!["10.0.0.1/32", "2001:db8::/32"]);
        assert!(parse_nets(&["x".into()]).is_err());
        // TestIsPublicIPv6 из Go
        for (s, want) in [("2a05:45c2:5000:f376::1", true), ("fd5f:312:d4bb::1", false), ("fd7a:115c:a1e0::40", false), ("fe80::1", false), ("::1", false), ("100.64.236.92", false)] {
            assert_eq!(is_public_ipv6(&s.parse().unwrap()), want, "{s}");
        }
    }
}
