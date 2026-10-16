//! Одна проба: неблокирующий сокет, готовность — через epoll.
//! TCP: connect, итог — SO_ERROR после EPOLLOUT. UDP: connect + DNS-запрос
//! example.com A, успех — любой ответ (EPOLLIN).

use crate::netx;
use std::io;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Tcp,
    Udp,
}

pub struct Probe {
    pub fd: i32,
    pub kind: Kind,
    pub addr: SocketAddr,
    pub started: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Outcome {
    Ok,
    Refused,
    Unreachable,
    Fail(i32),
    Timeout,
}

/// DNS-запрос example.com A (как dnsQueryBytes в Go).
pub const DNS_QUERY: [u8; 29] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01];

fn errno_outcome(e: i32) -> Outcome {
    match e {
        0 => Outcome::Ok,
        libc::ECONNREFUSED => Outcome::Refused,
        libc::ENETUNREACH | libc::EHOSTUNREACH => Outcome::Unreachable,
        libc::ETIMEDOUT => Outcome::Timeout,
        e => Outcome::Fail(e),
    }
}

impl Probe {
    /// Начать пробу; src — привязка источника (IPv6 WAN, см. prober).
    pub fn start(kind: Kind, addr: SocketAddr, src: Option<IpAddr>, now: u64) -> Result<Probe, Outcome> {
        Self::start_dev(kind, addr, src, "", now)
    }

    /// То же, с привязкой к устройству (SO_BINDTODEVICE; пусто — без привязки).
    pub fn start_dev(kind: Kind, addr: SocketAddr, src: Option<IpAddr>, dev: &str, now: u64) -> Result<Probe, Outcome> {
        let fam = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let ty = if kind == Kind::Tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
        let fd = unsafe { libc::socket(fam, ty | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(errno_outcome(io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        let p = Probe { fd, kind, addr, started: now };
        if !dev.is_empty() && unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr() as *const libc::c_void, dev.len() as u32) } < 0 {
            return Err(errno_outcome(io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        if let Some(s) = src {
            let (sa, l) = netx::sockaddr_of(&s, 0);
            if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
                return Err(errno_outcome(io::Error::last_os_error().raw_os_error().unwrap_or(0)));
            }
        }
        let (sa, l) = netx::sockaddr_of(&addr.ip(), addr.port());
        if unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
            let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e != libc::EINPROGRESS {
                return Err(errno_outcome(e));
            }
        }
        mark_service(fd, if kind == Kind::Tcp { 6 } else { 17 }, addr);
        if kind == Kind::Udp && unsafe { libc::send(fd, DNS_QUERY.as_ptr() as *const libc::c_void, DNS_QUERY.len(), 0) } < 0 {
            return Err(errno_outcome(io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        Ok(p)
    }

    /// События epoll, которые ждёт проба.
    pub fn events(&self) -> u32 {
        (match self.kind {
            Kind::Tcp => libc::EPOLLOUT,
            Kind::Udp => libc::EPOLLIN,
        } | libc::EPOLLERR
            | libc::EPOLLHUP) as u32
    }

    /// Итог после события.
    pub fn finish(&self) -> Outcome {
        match self.kind {
            Kind::Tcp => {
                let mut err: i32 = 0;
                let mut l = std::mem::size_of::<i32>() as u32;
                unsafe { libc::getsockopt(self.fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut libc::c_void, &mut l) };
                errno_outcome(err)
            }
            Kind::Udp => {
                let mut buf = [0u8; 512];
                let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n > 0 {
                    Outcome::Ok
                } else if n == 0 {
                    Outcome::Fail(0)
                } else {
                    errno_outcome(io::Error::last_os_error().raw_os_error().unwrap_or(0))
                }
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ---------- служебные соединения cgmon (пробы, свидетели, трассировка, проверки) ----------
// Счётчик «Соединения» на странице — без них: пользователю важны полезные соединения
// (клиенты, службы роутера, Tailscale/ZeroTier), а лимит провайдера (CGNAT) считает
// все — оба числа идут в статус и в текст инцидента. Сокет после connect метится
// по (протокол, адрес и порт назначения, свой порт); conntrack сверяет с этим.

use std::collections::HashMap;
use std::sync::Mutex;

/// Метка живёт дольше записи conntrack пробы (TIME_WAIT / несостоявшийся SYN — 120 с).
const SVC_KEEP_MS: u64 = 180_000;
const SVC_MAX: usize = 20_000;

static SVC: Mutex<Option<HashMap<(u8, IpAddr, u16, u16), u64>>> = Mutex::new(None);

/// Пометить сокет fd (после connect) служебным; proto — 6 TCP, 17 UDP.
pub fn mark_service(fd: i32, proto: u8, dst: SocketAddr) {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut sl = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    if unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) } < 0 {
        return;
    }
    let sport = match ss.ss_family as i32 {
        libc::AF_INET => u16::from_be(unsafe { (*(&ss as *const _ as *const libc::sockaddr_in)).sin_port }),
        libc::AF_INET6 => u16::from_be(unsafe { (*(&ss as *const _ as *const libc::sockaddr_in6)).sin6_port }),
        _ => return,
    };
    if sport == 0 {
        return;
    }
    let now = crate::evloop::now_ms();
    let Ok(mut g) = SVC.lock() else { return };
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= SVC_MAX / 2 {
        m.retain(|_, t| now.saturating_sub(*t) <= SVC_KEEP_MS);
        if m.len() >= SVC_MAX {
            m.clear(); // поток проб невиданный — начать заново, память не копить
        }
    }
    m.insert((proto, dst.ip(), dst.port(), sport), now);
}

/// Соединение роутера — служебное cgmon (по исходному порту и адресату).
pub fn is_service(proto: &str, dst: &IpAddr, dport: u16, sport: u16) -> bool {
    let p = match proto {
        "tcp" => 6,
        "udp" => 17,
        _ => return false,
    };
    let now = crate::evloop::now_ms();
    SVC.lock().ok().and_then(|g| g.as_ref().and_then(|m| m.get(&(p, *dst, dport, sport)).copied())).map_or(false, |t| now.saturating_sub(t) <= SVC_KEEP_MS)
}

#[cfg(test)]
mod svc_tests {
    use super::*;

    #[test]
    fn marks() {
        // UDP-сокет: connect назначает порт — метка находится по нему
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (sa, l) = crate::netx::sockaddr_of(&dst.ip(), dst.port());
        assert_eq!(unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, l) }, 0);
        mark_service(fd, 17, dst);
        let mut ss: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut sl = std::mem::size_of::<libc::sockaddr_in>() as u32;
        unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) };
        let sport = u16::from_be(ss.sin_port);
        unsafe { libc::close(fd) };
        assert!(is_service("udp", &dst.ip(), 9, sport));
        assert!(!is_service("tcp", &dst.ip(), 9, sport));
        assert!(!is_service("udp", &dst.ip(), 9, sport.wrapping_add(1)));
    }
}
