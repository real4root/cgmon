//! Неблокирующий DNS-клиент в общем epoll: запрос — UDP-сокет к серверу,
//! ответ — событием. Метка (tag) говорит, чей запрос (владельцы адресов,
//! свидетели, адресный режим, отчёт). Без потоков и без резолвера libc.

use crate::evloop::Poller;
use crate::netx;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Answer {
    pub rcode: u8,
    pub ips: Vec<IpAddr>,
    pub names: Vec<String>, // PTR/CNAME
    pub txt: Vec<String>,
}

struct Pending {
    fd: i32,
    id: u16,
    tag: u64,
    deadline: u64,
}

pub struct Client {
    tok_base: u64,
    next: u64,
    pending: HashMap<u64, Pending>,
    /// готовые: (метка, ответ; None — таймаут/ошибка)
    pub done: Vec<(u64, Option<Answer>)>,
    rng: u64,
}

/// DNS-запрос (RD=1).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + name.len());
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.trim_end_matches('.').split('.') {
        if l.is_empty() || l.len() > 63 {
            continue;
        }
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m
}

/// Разбор ответа: адреса A/AAAA, имена PTR/CNAME, строки TXT.
pub fn parse(m: &[u8]) -> Option<(u16, Answer)> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let id = u16::from_be_bytes([m[0], m[1]]);
    let mut a = Answer { rcode: m[3] & 0x0f, ..Default::default() };
    let qd = u16::from_be_bytes([m[4], m[5]]) as usize;
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let mut off = 12;
    for _ in 0..qd {
        let (_, o) = crate::dnswatch::dns_name(m, off)?;
        off = o + 4;
    }
    for _ in 0..an {
        if off >= m.len() {
            break;
        }
        let (_, o) = crate::dnswatch::dns_name(m, off)?;
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
        let rd = &m[off..off + rdl];
        match typ {
            TYPE_A if rdl == 4 => a.ips.push(IpAddr::from([rd[0], rd[1], rd[2], rd[3]])),
            TYPE_AAAA if rdl == 16 => {
                let b: [u8; 16] = rd.try_into().unwrap();
                a.ips.push(IpAddr::from(b));
            }
            TYPE_PTR | 5 => {
                if let Some((n, _)) = crate::dnswatch::dns_name(m, off) {
                    a.names.push(n);
                }
            }
            TYPE_TXT => {
                // строки <длина><текст>… — склеиваем как Go LookupTXT
                let mut s = String::new();
                let mut i = 0;
                while i < rd.len() {
                    let l = rd[i] as usize;
                    if i + 1 + l > rd.len() {
                        break;
                    }
                    s.push_str(&String::from_utf8_lossy(&rd[i + 1..i + 1 + l]));
                    i += 1 + l;
                }
                a.txt.push(s);
            }
            _ => {}
        }
        off += rdl;
    }
    Some((id, a))
}

/// Имя для PTR-запроса (in-addr.arpa / ip6.arpa).
pub fn reverse_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(72);
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0x0f, b >> 4));
            }
            s + "ip6.arpa"
        }
    }
}

impl Client {
    pub fn new(tok_base: u64) -> Client {
        Client { tok_base, next: 0, pending: HashMap::new(), done: Vec::new(), rng: crate::evloop::now_ms() | 1 }
    }

    pub fn owns(&self, tok: u64) -> bool {
        tok & !0xffff_ffff == self.tok_base
    }

    fn rid(&mut self) -> u16 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng as u16
    }

    /// Отправить запрос; результат придёт в done с этой меткой.
    pub fn query(&mut self, poller: &Poller, server: SocketAddr, name: &str, qtype: u16, tag: u64, timeout_ms: u64, now: u64) {
        let fam = if server.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let fd = unsafe { libc::socket(fam, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            self.done.push((tag, None));
            return;
        }
        let (sa, l) = netx::sockaddr_of(&server.ip(), server.port());
        let id = self.rid();
        let q = build_query(id, name, qtype);
        let ok = unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, l) } == 0 && {
            crate::probe::mark_service(fd, 17, server); // запросы cgmon к резолверам — служебные
            let sent = unsafe { libc::send(fd, q.as_ptr() as *const libc::c_void, q.len(), 0) };
            sent == q.len() as isize
        };
        self.next += 1;
        let tok = self.tok_base | (self.next & 0xffff_ffff);
        if !ok || poller.add(fd, (libc::EPOLLIN | libc::EPOLLERR) as u32, tok).is_err() {
            unsafe { libc::close(fd) };
            self.done.push((tag, None));
            return;
        }
        self.pending.insert(tok, Pending { fd, id, tag, deadline: now + timeout_ms });
    }

    pub fn on_event(&mut self, tok: u64, poller: &Poller) {
        let Some(p) = self.pending.get(&tok) else { return };
        let mut buf = [0u8; 1500];
        let n = unsafe { libc::recv(p.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT) };
        let res = if n > 0 { parse(&buf[..n as usize]).filter(|(id, _)| *id == p.id).map(|x| x.1) } else { None };
        if n > 0 && res.is_none() {
            return; // чужой/битый ответ — ждём дальше (до таймаута)
        }
        let p = self.pending.remove(&tok).unwrap();
        poller.del(p.fd);
        unsafe { libc::close(p.fd) };
        self.done.push((p.tag, res));
    }

    /// Таймауты; ближайший срок — для ожидания epoll.
    pub fn sweep(&mut self, poller: &Poller, now: u64) -> u64 {
        let late: Vec<u64> = self.pending.iter().filter(|(_, p)| now >= p.deadline).map(|(t, _)| *t).collect();
        for t in late {
            let p = self.pending.remove(&t).unwrap();
            poller.del(p.fd);
            unsafe { libc::close(p.fd) };
            self.done.push((p.tag, None));
        }
        self.pending.values().map(|p| p.deadline.saturating_sub(now)).min().unwrap_or(u64::MAX)
    }

    /// Забрать готовые ответы с метками из диапазона [lo, hi].
    pub fn take(&mut self, lo: u64, hi: u64) -> Vec<(u64, Option<Answer>)> {
        let mut out = Vec::new();
        self.done.retain(|(t, a)| {
            if *t >= lo && *t <= hi {
                out.push((*t, a.clone()));
                false
            } else {
                true
            }
        });
        out
    }

    pub fn in_flight(&self, lo: u64, hi: u64) -> usize {
        self.pending.values().filter(|p| p.tag >= lo && p.tag <= hi).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_parse() {
        let q = build_query(0x1234, "AS13238.asn.cymru.com.", TYPE_TXT);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        // ответ: тот же вопрос + TXT «13238 | RU | ripencc | 2003-08-20 | YANDEX, RU»
        let mut a = q.clone();
        a[2] |= 0x80;
        a[7] = 1;
        let txt = b"13238 | RU | ripencc | 2003-08-20 | YANDEX, RU";
        a.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, (txt.len() + 1) as u8, txt.len() as u8]);
        a.extend_from_slice(txt);
        let (id, ans) = parse(&a).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(ans.txt, vec![String::from_utf8_lossy(txt).to_string()]);
        assert_eq!(reverse_name(&"192.0.2.7".parse().unwrap()), "7.2.0.192.in-addr.arpa");
        assert!(reverse_name(&"2001:db8::1".parse().unwrap()).starts_with("1.0.0.0.0.0.0.0."));
    }
}
