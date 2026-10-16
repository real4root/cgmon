//! Имена адресов для down detector и адресного режима (перенос dnswatch.go):
//! AF_PACKET на всех интерфейсах, BPF пропускает UDP sport 53; берём только
//! исходящие (ответы dnsmasq клиентам LAN и самому роутеру через lo):
//! адрес → какое имя спросили и кто спрашивал. Имена — общие (Rc), без копий.

use crate::synrtt::{packet_socket, recv_packet};
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;

const KEEP_MS: u64 = 2 * 3600 * 1000;
pub const MAX_IPS: usize = 20000;
const CLIENTS: usize = 4;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// UDP с sport 53: IPv4 без фрагментов, IPv6 без доп. заголовков.
const DNS_FILTER: [SockFilter; 17] = [
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x00 },
    SockFilter { code: 0x54, jt: 0, jf: 0, k: 0xf0 },
    SockFilter { code: 0x15, jt: 0, jf: 7, k: 0x40 },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x09 },
    SockFilter { code: 0x15, jt: 0, jf: 11, k: 0x11 },
    SockFilter { code: 0x28, jt: 0, jf: 0, k: 0x06 },
    SockFilter { code: 0x45, jt: 9, jf: 0, k: 0x1fff },
    SockFilter { code: 0xb1, jt: 0, jf: 0, k: 0x00 },
    SockFilter { code: 0x48, jt: 0, jf: 0, k: 0x00 },
    SockFilter { code: 0x15, jt: 5, jf: 6, k: 0x35 },
    SockFilter { code: 0x15, jt: 0, jf: 5, k: 0x60 },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x06 },
    SockFilter { code: 0x15, jt: 0, jf: 3, k: 0x11 },
    SockFilter { code: 0x28, jt: 0, jf: 0, k: 0x28 },
    SockFilter { code: 0x15, jt: 0, jf: 1, k: 0x35 },
    SockFilter { code: 0x06, jt: 0, jf: 0, k: 1500 },
    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x00 },
];

/// Имя DNS (со сжатием) с позиции off → (имя, позиция после), None — битое.
pub fn dns_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumped = 0;
    while off < msg.len() && jumped < 16 {
        let l = msg[off] as usize;
        if l == 0 {
            return Some((parts.join("."), end.unwrap_or(off + 1)));
        } else if l & 0xc0 == 0xc0 {
            if off + 1 >= msg.len() {
                return None;
            }
            end.get_or_insert(off + 2);
            off = (u16::from_be_bytes([msg[off], msg[off + 1]]) & 0x3fff) as usize;
            jumped += 1;
        } else {
            if off + 1 + l > msg.len() {
                return None;
            }
            parts.push(String::from_utf8_lossy(&msg[off + 1..off + 1 + l]).into_owned());
            off += 1 + l;
        }
    }
    None
}

/// Ответ DNS → (спрошенное имя в нижнем регистре, адреса A/AAAA).
pub fn parse_answer(m: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if m.len() < 12 || m[2] & 0x80 == 0 || m[3] & 0x0f != 0 {
        return None; // не ответ или ошибка
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    if qd != 1 || an == 0 {
        return None;
    }
    let (name, mut off) = dns_name(m, 12)?;
    if name.is_empty() || off + 4 > m.len() {
        return None;
    }
    off += 4;
    let mut ips = Vec::new();
    for _ in 0..an {
        if off >= m.len() {
            break;
        }
        let Some((_, o)) = dns_name(m, off) else { break };
        off = o;
        if off + 10 > m.len() {
            break;
        }
        let typ = u16::from_be_bytes([m[off], m[off + 1]]);
        let rdl = u16::from_be_bytes([m[off + 8], m[off + 9]]) as usize;
        off += 10;
        if off + rdl > m.len() {
            break;
        }
        if typ == 1 && rdl == 4 {
            ips.push(IpAddr::from([m[off], m[off + 1], m[off + 2], m[off + 3]]));
        } else if typ == 28 && rdl == 16 {
            let a: [u8; 16] = m[off..off + 16].try_into().unwrap();
            ips.push(IpAddr::from(a));
        }
        off += rdl;
    }
    if ips.is_empty() {
        return None;
    }
    Some((name.to_lowercase(), ips))
}

struct Entry {
    name: Rc<str>,
    /// спросившие (последние CLIENTS); loopback — сам роутер
    clients: Vec<IpAddr>,
    at: u64,
}

#[derive(Default)]
pub struct DnsWatch {
    pub on: bool,
    pub fd: Option<i32>,
    ips: HashMap<IpAddr, Entry>,
    names: HashMap<Rc<str>, ()>,
    last_sweep: u64,
    /// новые адреса (или сменившие имя) с прошлого забора — обход их ждёт сразу
    pub fresh: Vec<(IpAddr, Rc<str>)>,
}

impl DnsWatch {
    /// Открыть/закрыть сокет по флагу on. Возвращает (закрытый, новый) fd.
    pub fn ensure(&mut self) -> (Option<i32>, Option<i32>) {
        if self.on == self.fd.is_some() {
            return (None, None);
        }
        if !self.on {
            let fd = self.fd.take();
            if let Some(f) = fd {
                unsafe { libc::close(f) };
            }
            self.ips.clear();
            self.names.clear();
            return (fd, None);
        }
        match packet_socket(DNS_FILTER.as_ptr() as *const u8, DNS_FILTER.len(), 0) {
            Ok(fd) => {
                self.fd = Some(fd);
                crate::log_info!("dnswatch: watching DNS answers to LAN");
                (None, Some(fd))
            }
            Err(e) => {
                crate::log_err!("dnswatch: {}", e);
                (None, None)
            }
        }
    }

    pub fn on_readable(&mut self, now: u64) {
        let Some(fd) = self.fd else { return };
        // чистка — до приёма: fresh этой порции заберёт демон сразу после
        if now - self.last_sweep >= 60_000 {
            self.sweep(now);
        }
        let mut buf = vec![0u8; 1500];
        for _ in 0..4096 {
            let Some((n, out)) = recv_packet(fd, &mut buf) else { break };
            // только отправленные роутером (на lo каждый пакет виден дважды)
            if out && n >= 28 {
                self.on_packet(now, &buf[..n]);
            }
        }
    }

    fn intern(&mut self, name: &str) -> Rc<str> {
        if let Some((k, _)) = self.names.get_key_value(name) {
            return k.clone();
        }
        let r: Rc<str> = Rc::from(name);
        self.names.insert(r.clone(), ());
        r
    }

    pub fn on_packet(&mut self, now: u64, p: &[u8]) {
        let (client, udp) = match p[0] >> 4 {
            4 => {
                let hl = (p[0] & 0x0f) as usize * 4;
                if p.len() < hl + 8 {
                    return;
                }
                (IpAddr::from([p[16], p[17], p[18], p[19]]), &p[hl..])
            }
            6 => {
                if p.len() < 48 {
                    return;
                }
                let a: [u8; 16] = p[24..40].try_into().unwrap();
                (IpAddr::from(a), &p[40..])
            }
            _ => return,
        };
        let Some((name, ips)) = parse_answer(&udp[8..]) else { return };
        if self.ips.len() >= MAX_IPS {
            self.ips.clear(); // перебор — начать заново, чем раздуваться
            self.names.clear();
        }
        let nm = self.intern(&name);
        for ip in ips {
            let mut new = false;
            let e = self.ips.entry(ip).or_insert_with(|| {
                new = true;
                Entry { name: nm.clone(), clients: Vec::new(), at: now }
            });
            if *e.name != *nm {
                *e = Entry { name: nm.clone(), clients: Vec::new(), at: now };
                new = true;
            }
            if new && self.fresh.len() < 512 {
                self.fresh.push((ip, nm.clone()));
            }
            e.at = now;
            if !e.clients.contains(&client) {
                e.clients.push(client);
                if e.clients.len() > CLIENTS {
                    e.clients.remove(0);
                }
            }
        }
    }

    pub fn sweep(&mut self, now: u64) {
        self.last_sweep = now;
        self.fresh.clear(); // никто не забрал (обхода нет) — не держать имена
        self.ips.retain(|_, e| now - e.at <= KEEP_MS);
        // имена без адресов — забыть
        self.names.retain(|k, _| Rc::strong_count(k) > 1);
    }

    fn client_str(c: &IpAddr) -> String {
        if c.is_loopback() {
            "router".into()
        } else {
            c.to_string()
        }
    }

    /// Имя, под которым клиенты получили этот адрес, и кто спрашивал.
    pub fn lookup(&self, ip: &IpAddr) -> Option<(&str, Vec<String>)> {
        self.ips.get(ip).map(|e| (&*e.name, e.clients.iter().map(Self::client_str).collect()))
    }

    pub fn name_of(&self, ip: &IpAddr) -> Option<&str> {
        self.ips.get(ip).map(|e| &*e.name)
    }

    /// Адрес → имя (адресный режим DNS-страховки).
    pub fn pairs(&self) -> impl Iterator<Item = (&IpAddr, &str)> {
        self.ips.iter().map(|(ip, e)| (ip, &*e.name))
    }

    /// Самые частые имена с момента since (по числу адресов × спросивших).
    pub fn recent_names(&self, since: u64, n: usize) -> Vec<String> {
        let mut hits: HashMap<&str, usize> = HashMap::new();
        for e in self.ips.values().filter(|e| e.at >= since) {
            *hits.entry(&*e.name).or_insert(0) += e.clients.len() + 1;
        }
        let mut v: Vec<(&str, usize)> = hits.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        v.into_iter().take(n).map(|(k, _)| k.to_string()).collect()
    }

    pub fn len(&self) -> usize {
        self.ips.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer() -> Vec<u8> {
        // ответ на example.com A: 2 записи (A и AAAA), имя сжато указателем
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(&[7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        m.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        m.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        m
    }

    #[test]
    fn parse_and_track() {
        let (n, ips) = parse_answer(&answer()).unwrap();
        assert_eq!(n, "example.com");
        assert_eq!(ips, vec!["192.0.2.7".parse::<IpAddr>().unwrap(), "2001:db8::1".parse().unwrap()]);
        assert!(parse_answer(&answer()[..20]).is_none());
        // пакет: IPv4 (роутер → клиент 10.0.0.5) + UDP + DNS
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = 17;
        p[16..20].copy_from_slice(&[10, 0, 0, 5]);
        p.extend_from_slice(&answer());
        let mut w = DnsWatch::default();
        w.on_packet(1000, &p);
        let (name, cl) = w.lookup(&"192.0.2.7".parse().unwrap()).unwrap();
        assert_eq!((name, cl), ("example.com", vec!["10.0.0.5".to_string()]));
        assert_eq!(w.recent_names(0, 5), vec!["example.com"]);
        w.sweep(1000 + KEEP_MS + 1);
        assert_eq!(w.len(), 0);
        assert!(w.names.is_empty());
    }
}
