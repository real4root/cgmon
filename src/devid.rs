//! Опознавание устройств без имени в DHCP (перенос devid.go).
//! Пробы по IP: обратный DNS у местного dnsmasq, unicast mDNS PTR на ip:5353,
//! NetBIOS NBSTAT udp/137; иначе производитель по OUI MAC (онлайн, кеш на
//! роутере) — «*Espressif (smart home)»; частный MAC — «*Телефон/планшет».
//! Пробы и запросы производителя — в рабочем потоке, пока есть очередь
//! (потом он завершается). Пассивно: mDNS (224.0.0.251:5353) и SSDP
//! (239.255.255.250:1900) на LAN — сокеты в общем epoll; описание UPnP
//! (friendlyName) — только с самого объявившего устройства, ≤ 4 сразу.

use crate::config::DeviceIDConfig;
use crate::dns;
use crate::json::J;
use crate::value::{parse_json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROBE_OK: i64 = 24 * 3600 * 1000;
const PROBE_FAIL: i64 = 3600 * 1000;
const VENDOR_RETRY: i64 = 7 * 24 * 3600;
const MAX_HEARD: usize = 2000;
const MAX_QUEUE: usize = 256;
const SSDP_MAX_FETCH: usize = 4;

fn now_ms() -> i64 {
    let (s, n) = crate::util::now_wall();
    s * 1000 + (n / 1_000_000) as i64
}

struct Inner {
    cfg: DeviceIDConfig,
    by_ip: HashMap<String, (String, i64)>,
    by_mac: HashMap<String, String>,
    heard: HashMap<String, (String, i64)>,
    vendor: HashMap<String, String>,
    vendor_at: HashMap<String, i64>,
    pending: HashSet<String>,
    queue: VecDeque<(String, String)>,
    worker: bool,
    dirty: bool,
}

pub struct DevIdent {
    inner: Mutex<Inner>,
    ssdp_busy: AtomicUsize,
}

/// MAC «aa:bb:…» → байты.
pub fn mac_bytes(mac: &str) -> Option<[u8; 6]> {
    let h: String = mac.chars().filter(|c| *c != ':' && *c != '-').collect();
    if h.len() != 12 {
        return None;
    }
    let mut b = [0u8; 6];
    for i in 0..6 {
        b[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(b)
}

const CATEGORIES: &[(&str, &str)] = &[
    ("espressif|tuya|beken|bouffalo|shelly|sonoff|itead|broadlink|yeelink|aqara|lumi united|realtek semiconductor|hi-flying|winner micro|wiznet|silicon labs", "smart home"),
    ("hikvision|dahua|ezviz|uniview|reolink|imou|axis comm|tp-link systems camera", "камера"),
    ("apple", "Apple"),
    ("samsung|xiaomi|huawei|honor|oppo|vivo|oneplus|realme|motorola|nokia|google|tecno|infinix|itel", "телефон/планшет"),
    ("lg electronics|tcl|hisense|skyworth|sony|philips|amlogic|rockchip|allwinner|mediatek", "ТВ/приставка"),
    ("intel|liteon|azurewave|hon hai|foxconn|asustek|micro-star|giga-byte|dell|hewlett|lenovo|acer|realtek pci", "компьютер"),
    ("tp-link|mikrotik|ubiquiti|zyxel|d-link|tenda|netgear|keenetic|mercusys|cudy|gl technologies", "сетевое"),
    ("amazon|sonos|harman", "колонка"),
    ("nintendo|playstation|sony interactive|microsoft", "приставка/ПК"),
];

pub fn vendor_category(v: &str) -> &'static str {
    let l = v.to_lowercase();
    for (keys, cat) in CATEGORIES {
        if keys.split('|').any(|k| l.contains(k)) {
            return if *cat == "Apple" { "" } else { cat };
        }
    }
    ""
}

/// «Espressif Inc.» → «Espressif».
pub fn short_vendor(v: &str) -> String {
    let mut v = v.to_string();
    for suf in [",", " Co.", " Co ", " Inc", " Ltd", " LLC", " GmbH", " Corporation", " Corp", " Technology", " Technologies", " Electronics Co"] {
        if let Some(i) = v.find(suf) {
            if i > 0 {
                v.truncate(i);
            }
        }
    }
    v.trim().to_string()
}

/// Имя хоста: без «.local»/«.lan» и домена; адрес и мусор — пусто.
pub fn clean_hostname(s: &str) -> String {
    let s = s.trim().trim_end_matches('.');
    if s.parse::<IpAddr>().is_ok() {
        return String::new();
    }
    let s = s.strip_suffix(".local").unwrap_or(s);
    let s = s.strip_suffix(".lan").unwrap_or(s);
    let s = match s.find('.') {
        Some(i) if i > 0 => &s[..i],
        _ => s,
    };
    if s.is_empty() || s.parse::<IpAddr>().is_ok() || s.len() > 63 || s.chars().any(|r| (r as u32) < 0x20 || "\"\\<>".contains(r)) {
        return String::new();
    }
    s.to_string()
}

/// Обратный DNS у местного dnsmasq (аренды, /etc/hosts).
fn probe_ptr(ip: &IpAddr) -> String {
    udp_ptr("127.0.0.1:53".parse().unwrap(), ip, 1500)
}

fn udp_ptr(srv: SocketAddr, ip: &IpAddr, ms: u64) -> String {
    let Ok(s) = UdpSocket::bind(if srv.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) else { return String::new() };
    if s.connect(srv).is_err() || s.set_read_timeout(Some(Duration::from_millis(ms))).is_err() {
        return String::new();
    }
    let id = 0x4d44;
    if s.send(&dns::build_query(id, &dns::reverse_name(ip), dns::TYPE_PTR)).is_err() {
        return String::new();
    }
    let mut buf = [0u8; 1500];
    let Ok(n) = s.recv(&mut buf) else { return String::new() };
    dns::parse(&buf[..n]).and_then(|(_, a)| a.names.into_iter().next()).unwrap_or_default()
}

/// mDNS: unicast-запрос PTR на ip:5353.
fn probe_mdns(ip: &IpAddr) -> String {
    udp_ptr(SocketAddr::new(*ip, 5353), ip, 800)
}

/// NBSTAT «*» на udp/137: имя компьютера Windows/Samba.
fn probe_netbios(ip: &IpAddr) -> String {
    if !ip.is_ipv4() {
        return String::new();
    }
    let Ok(s) = UdpSocket::bind("0.0.0.0:0") else { return String::new() };
    if s.connect(SocketAddr::new(*ip, 137)).is_err() || s.set_read_timeout(Some(Duration::from_millis(800))).is_err() {
        return String::new();
    }
    let mut q = vec![0x4e, 0x42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
    let mut name = [0u8; 16];
    name[0] = b'*';
    for ch in name {
        q.push(b'A' + (ch >> 4));
        q.push(b'A' + (ch & 0x0f));
    }
    q.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    if s.send(&q).is_err() {
        return String::new();
    }
    let mut buf = [0u8; 1500];
    let Ok(n) = s.recv(&mut buf) else { return String::new() };
    if n < 57 {
        return String::new();
    }
    for i in 0..buf[56] as usize {
        let o = 57 + i * 18;
        if o + 18 > n {
            break;
        }
        let (suffix, flags) = (buf[o + 15], u16::from_be_bytes([buf[o + 16], buf[o + 17]]));
        if suffix == 0 && flags & 0x8000 == 0 {
            return crate::dgtarget::sanitize_label(&String::from_utf8_lossy(&buf[o..o + 15]));
        }
    }
    String::new()
}

/// Производитель по OUI (uclient-fetch / wget / curl); None — сеть недоступна.
fn lookup_vendor(url: &str) -> Option<String> {
    for args in [vec!["uclient-fetch", "-q", "-T", "5", "-O", "-", url], vec!["wget", "-q", "-T", "5", "-O", "-", url], vec!["curl", "-s", "-m", "5", url]] {
        if !crate::util::have_bin(args[0]) {
            continue;
        }
        let o = crate::flowwatch::output_timeout(args[0], &args[1..], 8000);
        let v = o.clone().unwrap_or_default().trim().to_string();
        if o.is_none() && v.is_empty() {
            return None; // отказ сети — не кешируем как «нет»
        }
        if v.starts_with('{') || v.len() > 80 {
            return Some(String::new());
        }
        return Some(short_vendor(&v));
    }
    None
}

/// friendlyName из описания UPnP (GET только с самого объявившего устройства).
fn upnp_friendly(loc: &str, src: &IpAddr) -> String {
    let rest = loc.trim_start_matches("http://");
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr: SocketAddr = match hp.parse() {
        Ok(a) => a,
        Err(_) => match hp.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, 80),
            Err(_) => return String::new(),
        },
    };
    if addr.ip() != *src {
        return String::new();
    }
    let Ok(mut c) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else { return String::new() };
    let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = c.set_write_timeout(Some(Duration::from_secs(3)));
    if write!(c, "GET {path} HTTP/1.0\r\nHost: {hp}\r\nConnection: close\r\n\r\n").is_err() {
        return String::new();
    }
    let mut buf = Vec::with_capacity(8192);
    let _ = c.take(32 * 1024).read_to_end(&mut buf);
    let body = String::from_utf8_lossy(&buf);
    let Some(i) = body.find("<friendlyName>") else { return String::new() };
    let b = &body[i + 14..];
    let Some(j) = b.find("</friendlyName>") else { return String::new() };
    b[..j].replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")
}

impl DevIdent {
    pub fn new(cfg: &DeviceIDConfig) -> Arc<DevIdent> {
        let mut i = Inner { cfg: cfg.clone(), by_ip: HashMap::new(), by_mac: HashMap::new(), heard: HashMap::new(), vendor: HashMap::new(), vendor_at: HashMap::new(), pending: HashSet::new(), queue: VecDeque::new(), worker: false, dirty: false };
        if let Some(v) = std::fs::read_to_string(crate::storage::path(&cfg.vendor_cache)).ok().and_then(|t| parse_json(&t).ok()) {
            if let Some(Value::Map(m)) = v.get("vendor") {
                i.vendor = m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect();
            }
            if let Some(Value::Map(m)) = v.get("at") {
                i.vendor_at = m.iter().map(|(k, x)| (k.clone(), x.as_f64().unwrap_or(0.0) as i64)).collect();
            }
        }
        Arc::new(DevIdent { inner: Mutex::new(i), ssdp_busy: AtomicUsize::new(0) })
    }

    /// Пробы/производитель со страницы (адрес и кеш — прежние).
    pub fn set_config(&self, c: &DeviceIDConfig) {
        let mut i = self.inner.lock().unwrap();
        i.cfg.probe = c.probe;
        i.cfg.vendor_lookup = c.vendor_lookup;
    }

    fn enqueue(self: &Arc<Self>, i: &mut Inner, key: String, mac: String) {
        if i.pending.contains(&key) || i.queue.len() >= MAX_QUEUE {
            return;
        }
        i.pending.insert(key.clone());
        i.queue.push_back((key, mac));
        if !i.worker {
            i.worker = true;
            let me = self.clone();
            let r = std::thread::Builder::new().name("cgmon-devid".into()).stack_size(128 << 10).spawn(move || me.work());
            if r.is_err() {
                i.worker = false;
            }
        }
    }

    /// Рабочий поток: разобрать очередь и завершиться.
    fn work(self: Arc<Self>) {
        loop {
            let (job, url) = {
                let mut i = self.inner.lock().unwrap();
                match i.queue.pop_front() {
                    Some(j) => (j, i.cfg.vendor_url.clone()),
                    None => {
                        i.worker = false;
                        return;
                    }
                }
            };
            let (key, mac) = job;
            if let Some(oui) = key.strip_prefix("oui:") {
                let v = lookup_vendor(&format!("{url}{oui}"));
                let mut i = self.inner.lock().unwrap();
                if let Some(v) = v {
                    i.vendor.insert(oui.to_string(), v);
                    i.vendor_at.insert(oui.to_string(), now_ms() / 1000);
                    i.dirty = true;
                }
                i.pending.remove(&key);
                drop(i);
                std::thread::sleep(Duration::from_millis(1500)); // бесплатный API: не чаще раза в секунду
                continue;
            }
            let mut name = String::new();
            if let Ok(ip) = key.parse::<IpAddr>() {
                for f in [probe_ptr, probe_mdns, probe_netbios] {
                    name = clean_hostname(&f(&ip));
                    if !name.is_empty() {
                        break;
                    }
                }
            }
            let mut i = self.inner.lock().unwrap();
            if !name.is_empty() {
                crate::log_debug!("devid: {} ({}) = {}", key, mac, name);
                if !mac.is_empty() {
                    i.by_mac.insert(mac, name.clone());
                }
            }
            i.by_ip.insert(key.clone(), (name, now_ms()));
            i.pending.remove(&key);
        }
    }

    /// Имя по пробам или производителю; если пора — пробы в очередь.
    pub fn name(self: &Arc<Self>, ip: &str, mac: &str) -> String {
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        let i = &mut *g;
        let p = i.by_ip.get(ip).cloned();
        let stale = match &p {
            None => true,
            Some((n, at)) => (!n.is_empty() && now - at > PROBE_OK) || (n.is_empty() && now - at > PROBE_FAIL),
        };
        if stale && i.cfg.probe {
            self.enqueue(i, ip.to_string(), mac.to_string());
        }
        let (mut name, pat) = p.unwrap_or_default();
        if let Some((h, at)) = i.heard.get(ip) {
            if !h.is_empty() && (name.is_empty() || *at > pat) {
                name = h.clone();
            }
        }
        if !name.is_empty() && !mac.is_empty() {
            i.by_mac.insert(mac.to_string(), name.clone());
        }
        if name.is_empty() && !mac.is_empty() {
            name = i.by_mac.get(mac).cloned().unwrap_or_default(); // то же устройство под другим адресом
        }
        if name.is_empty() && !mac.is_empty() {
            name = self.vendor_name(i, mac, now / 1000);
        }
        name
    }

    /// Имя без проб: объявленное устройством или производитель.
    pub fn known(self: &Arc<Self>, ip: &str, mac: &str) -> String {
        let mut g = self.inner.lock().unwrap();
        if let Some((h, _)) = g.heard.get(ip) {
            if !h.is_empty() {
                return h.clone();
            }
        }
        self.vendor_name(&mut g, mac, now_ms() / 1000)
    }

    fn vendor_name(self: &Arc<Self>, i: &mut Inner, mac: &str, now: i64) -> String {
        let Some(b) = mac_bytes(mac) else { return String::new() };
        if b[0] & 0x02 != 0 {
            return "*Телефон/планшет (частный MAC)".into(); // случайный MAC — почти только телефоны
        }
        let oui = format!("{:02x}{:02x}{:02x}", b[0], b[1], b[2]);
        let v = i.vendor.get(&oui).cloned();
        let retry = v.as_deref() == Some("") && now - i.vendor_at.get(&oui).copied().unwrap_or(0) > VENDOR_RETRY;
        if (v.is_none() || retry) && i.cfg.vendor_lookup {
            self.enqueue(i, format!("oui:{oui}"), String::new());
        }
        let v = v.unwrap_or_default();
        if v.is_empty() {
            return String::new();
        }
        match vendor_category(&v) {
            "" => format!("*{v}"),
            c => format!("*{v} ({c})"),
        }
    }

    /// Раз в 10 мин: кеш производителей на диск, старые пробы — вон.
    pub fn maintain(&self, path: &str) {
        let now = now_ms();
        let mut i = self.inner.lock().unwrap();
        i.by_ip.retain(|_, p| now - p.1 <= 48 * 3600 * 1000);
        i.heard.retain(|_, p| now - p.1 <= 48 * 3600 * 1000);
        if !i.dirty {
            return;
        }
        i.dirty = false;
        let mut j = J::new();
        j.obj().key("vendor").obj();
        let mut keys: Vec<&String> = i.vendor.keys().collect();
        keys.sort();
        for k in keys {
            j.key(k).str(&i.vendor[k]);
        }
        j.end_obj().key("at").obj();
        let mut keys: Vec<&String> = i.vendor_at.keys().collect();
        keys.sort();
        for k in keys {
            j.key(k).int(i.vendor_at[k]);
        }
        j.end_obj().end_obj();
        drop(i);
        if !crate::util::readonly() {
            let _ = crate::util::write_atomic(&crate::storage::path(path), j.b.as_bytes(), 0o644);
        }
    }

    fn set_heard(&self, ip: &IpAddr, name: &str) {
        let name = crate::dgtarget::sanitize_label(name);
        if name.is_empty() {
            return;
        }
        let mut i = self.inner.lock().unwrap();
        if i.heard.len() >= MAX_HEARD {
            i.heard.clear(); // поток анонсов с поддельных адресов — начать заново
        }
        i.heard.insert(ip.to_string(), (name, now_ms()));
    }

    /// mDNS-ответ/анонс: имя хоста по A/AAAA с адресом отправителя, fn= из TXT.
    pub fn on_mdns(&self, src: &IpAddr, msg: &[u8]) {
        if msg.len() < 12 || msg[2] & 0x80 == 0 {
            return;
        }
        let be = |o: usize| u16::from_be_bytes([msg[o], msg[o + 1]]) as usize;
        let qd = be(4);
        let rr = be(6) + be(8) + be(10);
        let mut off = 12usize;
        for _ in 0..qd {
            let Some((_, o)) = crate::dnswatch::dns_name(msg, off) else { return };
            off = o + 4;
        }
        let (mut host, mut friendly) = (String::new(), String::new());
        for _ in 0..rr {
            let Some((name, o)) = crate::dnswatch::dns_name(msg, off) else { break };
            off = o;
            if off + 10 > msg.len() {
                break;
            }
            let typ = be(off);
            let rdlen = be(off + 8);
            let rd = off + 10;
            if rd + rdlen > msg.len() {
                break;
            }
            let data = &msg[rd..rd + rdlen];
            match typ {
                1 | 28 => {
                    let ip = match data.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(data).unwrap())),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(data).unwrap())),
                        _ => None,
                    };
                    if ip.as_ref() == Some(src) && host.is_empty() {
                        host = clean_hostname(&name);
                    }
                }
                16 => {
                    let mut j = 0;
                    while j < data.len() {
                        let l = data[j] as usize;
                        if j + 1 + l > data.len() {
                            break;
                        }
                        let kv = String::from_utf8_lossy(&data[j + 1..j + 1 + l]);
                        if let Some(f) = kv.strip_prefix("fn=") {
                            if friendly.is_empty() {
                                friendly = f.to_string();
                            }
                        }
                        j += 1 + l;
                    }
                }
                _ => {}
            }
            off = rd + rdlen;
        }
        if !friendly.is_empty() {
            self.set_heard(src, &friendly);
        } else if !host.is_empty() {
            self.set_heard(src, &host);
        }
    }

    /// SSDP NOTIFY/ответ с LOCATION: friendlyName (раз в сутки на адрес, ≤ 4 сразу).
    pub fn on_ssdp(self: &Arc<Self>, src: IpAddr, msg: &[u8]) {
        let text = String::from_utf8_lossy(msg);
        let mut loc = String::new();
        for line in text.split("\r\n") {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("location") {
                    loc = v.trim().to_string();
                }
            }
        }
        if !loc.starts_with("http://") {
            return;
        }
        let key = format!("ssdp:{src}");
        {
            let mut i = self.inner.lock().unwrap();
            let fresh = i.heard.get(&src.to_string()).map_or(false, |h| now_ms() - h.1 < PROBE_OK);
            if fresh || i.pending.contains(&key) || self.ssdp_busy.load(Ordering::Relaxed) >= SSDP_MAX_FETCH {
                return;
            }
            i.pending.insert(key.clone());
        }
        self.ssdp_busy.fetch_add(1, Ordering::Relaxed);
        let me = self.clone();
        let r = std::thread::Builder::new().name("cgmon-upnp".into()).stack_size(128 << 10).spawn(move || {
            let n = upnp_friendly(&loc, &src);
            if !n.is_empty() {
                me.set_heard(&src, &n);
            }
            me.inner.lock().unwrap().pending.remove(&key);
            me.ssdp_busy.fetch_sub(1, Ordering::Relaxed);
        });
        if r.is_err() {
            self.ssdp_busy.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Сокет multicast-группы (порт с SO_REUSEADDR), вступление на интерфейсах.
pub fn mcast_socket(group: Ipv4Addr, port: u16, ifaces: &[String]) -> Option<i32> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return None;
        }
        let one: i32 = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const i32 as *const libc::c_void, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &one as *const i32 as *const libc::c_void, 4);
        let (sa, l) = crate::netx::sockaddr_of(&IpAddr::V4(group), port);
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, l) < 0 {
            libc::close(fd);
            return None;
        }
        let mut joined = 0;
        for name in ifaces {
            let Ok(c) = std::ffi::CString::new(name.as_str()) else { continue };
            let idx = libc::if_nametoindex(c.as_ptr());
            if idx == 0 {
                continue;
            }
            let m = libc::ip_mreqn { imr_multiaddr: libc::in_addr { s_addr: u32::from_ne_bytes(group.octets()) }, imr_address: libc::in_addr { s_addr: 0 }, imr_ifindex: idx as i32 };
            if libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &m as *const _ as *const libc::c_void, std::mem::size_of::<libc::ip_mreqn>() as u32) == 0 {
                joined += 1;
            }
        }
        if joined == 0 {
            libc::close(fd);
            return None;
        }
        Some(fd)
    }
}

/// Прочитать датаграммы: (отправитель, данные).
pub fn recv_all(fd: i32, mut f: impl FnMut(IpAddr, &[u8])) {
    let mut buf = [0u8; 9000];
    loop {
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut l = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let n = unsafe { libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0, &mut ss as *mut _ as *mut libc::sockaddr, &mut l) };
        if n <= 0 {
            return;
        }
        if let Some(ip) = crate::netx::ip_of_sockaddr(&ss) {
            f(ip, &buf[..n as usize]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_vendors() {
        assert_eq!(clean_hostname("iPhone-Ann.local."), "iPhone-Ann");
        assert_eq!(clean_hostname("192.0.2.1"), "");
        assert_eq!(clean_hostname("nas.lan"), "nas");
        assert_eq!(short_vendor("Espressif Inc."), "Espressif");
        assert_eq!(vendor_category("Espressif"), "smart home");
        assert_eq!(vendor_category("Apple, Inc."), "");
        let mut c = crate::config::defaults().devices;
        c.vendor_cache = String::new();
        c.vendor_lookup = false;
        c.probe = false;
        let d = DevIdent::new(&c);
        assert_eq!(d.name("192.0.2.5", "da:00:00:00:00:01"), "*Телефон/планшет (частный MAC)");
        // mDNS-анонс: A с адресом отправителя
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        for l in ["tv", "local"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 7]);
        d.on_mdns(&"192.0.2.7".parse().unwrap(), &m);
        assert_eq!(d.known("192.0.2.7", ""), "tv");
    }
}
