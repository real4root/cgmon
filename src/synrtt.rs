//! Пассивный контроль WAN по рукопожатиям TCP/443 (перенос synrtt.go):
//! AF_PACKET на устройстве маршрута по умолчанию, BPF в ядре пропускает только
//! TCP с SYN или RST. SYN наружу → ждём SYN-ACK/RST: RTT рукопожатия, провал
//! (нет ответа 3 с), потери (повторный SYN). Сокет — в общем epoll.
//! Память: ключи — (адрес, порт), адрес не строкой; лимиты как в Go.

use std::collections::HashMap;
use std::net::IpAddr;

const FAIL_AFTER_MS: u64 = 3000;
const KEEP_MS: u64 = 10 * 60 * 1000;
const MIN_COUNT: usize = 5;
pub const RESET_WIN_MS: u64 = 4000; // RST в пределах 4 с после SYN-ACK — похоже на сброс DPI
const MAX_PEND: usize = 20000;
pub const MAX_OUT: usize = 20000;
pub const ETH_P_ALL: u16 = 0x0003;

#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// TCP с SYN или RST (IPv4 без фрагментов, IPv6 без доп. заголовков).
const SYN_FILTER: [SockFilter; 18] = [
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x00 },
    SockFilter { code: 0x54, jt: 0, jf: 0, k: 0xf0 },
    SockFilter { code: 0x15, jt: 0, jf: 8, k: 0x40 },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x09 },
    SockFilter { code: 0x15, jt: 0, jf: 12, k: 0x06 },
    SockFilter { code: 0x28, jt: 0, jf: 0, k: 0x06 },
    SockFilter { code: 0x45, jt: 10, jf: 0, k: 0x1fff },
    SockFilter { code: 0xb1, jt: 0, jf: 0, k: 0x00 },
    SockFilter { code: 0x50, jt: 0, jf: 0, k: 0x0d },
    SockFilter { code: 0x45, jt: 6, jf: 7, k: 0x06 },
    SockFilter { code: 0x05, jt: 0, jf: 0, k: 0x06 },
    SockFilter { code: 0x15, jt: 0, jf: 5, k: 0x60 },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x06 },
    SockFilter { code: 0x15, jt: 0, jf: 3, k: 0x06 },
    SockFilter { code: 0x30, jt: 0, jf: 0, k: 0x35 },
    SockFilter { code: 0x45, jt: 0, jf: 1, k: 0x06 },
    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x80 },
    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x00 },
];

/// Открыть AF_PACKET (SOCK_DGRAM: данные с IP-заголовка) с BPF и привязкой
/// к устройству (ifindex 0 — все). Неблокирующий.
pub fn packet_socket(filter_ptr: *const u8, filter_len: usize, ifindex: i32) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, (ETH_P_ALL).to_be() as i32) };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    let prog = SockFprog { len: filter_len as u16, filter: filter_ptr as *const SockFilter };
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &prog as *const _ as *const libc::c_void, std::mem::size_of::<SockFprog>() as u32) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("attach filter: {e}"));
    }
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETH_P_ALL.to_be();
    sll.sll_ifindex = ifindex;
    if unsafe { libc::bind(fd, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("bind: {e}"));
    }
    Ok(fd)
}

/// Прочитать пакет (неблокирующе): (длина, исходящий?) или None.
pub fn recv_packet(fd: i32, buf: &mut [u8]) -> Option<(usize, bool)> {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    let mut l = std::mem::size_of::<libc::sockaddr_ll>() as u32;
    let n = unsafe { libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT, &mut sll as *mut _ as *mut libc::sockaddr, &mut l) };
    if n < 0 {
        return None;
    }
    Some((n as usize, sll.sll_pkttype == libc::PACKET_OUTGOING as u8))
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    t0: u64,
    v6: bool,
    retrans: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Outcome {
    pub at: u64,
    pub ok: bool,
    pub rtt: f32,
    pub retrans: u32,
    pub ip: IpAddr,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SynStats {
    pub count: i64,
    pub success_rate: f64,
    pub loss_pct: f64,
    pub median_ms: f64,
    pub p90_ms: f64,
}

#[derive(Default)]
pub struct SynRtt {
    pub on: bool,
    pub fd: Option<i32>,
    pub dev: String,
    ifindex: i32,
    pending: HashMap<(IpAddr, u16), Pending>,
    out4: Vec<Outcome>,
    out6: Vec<Outcome>,
    pub syns: u64,
    skip: Vec<IpAddr>,
    skip_w: Vec<IpAddr>,
    last_sweep: u64,
    /// соединения с полученным SYN-ACK (установились) — чтобы заметить RST сразу после
    est: HashMap<(IpAddr, u16), u64>,
    /// адреса, которым RST пришёл вскоре после рукопожатия (сигнатура сброса DPI по имени)
    resets: Vec<(IpAddr, u64)>,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

impl SynRtt {
    pub fn set_skip(&mut self, ips: &[IpAddr]) {
        self.skip = ips.to_vec();
    }

    pub fn set_skip_witness(&mut self, ips: &[IpAddr]) {
        self.skip_w = ips.to_vec();
    }

    /// Открыть/переоткрыть сокет на устройстве dev (смена WAN, PPPoE-переподключение).
    /// Возвращает (закрытый fd, новый fd) для перерегистрации в epoll.
    pub fn ensure(&mut self, dev: &str) -> (Option<i32>, Option<i32>) {
        let want = if self.on && !dev.is_empty() { unsafe { libc::if_nametoindex(std::ffi::CString::new(dev).unwrap_or_default().as_ptr()) as i32 } } else { 0 };
        if self.fd.is_some() && want == self.ifindex && dev == self.dev {
            return (None, None);
        }
        let old = self.fd.take();
        if let Some(fd) = old {
            unsafe { libc::close(fd) };
        }
        self.ifindex = 0;
        if want == 0 {
            return (old, None);
        }
        match packet_socket(SYN_FILTER.as_ptr() as *const u8, SYN_FILTER.len(), want) {
            Ok(fd) => {
                self.fd = Some(fd);
                self.ifindex = want;
                self.dev = dev.to_string();
                crate::log_info!("synrtt: watching TCP handshakes on {}", dev);
                (old, Some(fd))
            }
            Err(e) => {
                crate::log_err!("synrtt: {}", e);
                (old, None)
            }
        }
    }

    /// Сокет готов: прочитать всё накопившееся.
    pub fn on_readable(&mut self, now: u64) {
        let Some(fd) = self.fd else { return };
        let mut buf = [0u8; 128];
        for _ in 0..4096 {
            let Some((n, out)) = recv_packet(fd, &mut buf) else { break };
            if n >= 20 {
                self.on_packet(now, &buf[..n], out);
            }
        }
        if now - self.last_sweep >= 500 {
            self.sweep(now);
        }
    }

    /// Разбор пакета (IP-заголовок + TCP).
    pub fn on_packet(&mut self, now: u64, p: &[u8], out: bool) {
        let (v6, src, dst, tcp) = match p[0] >> 4 {
            4 => {
                let hl = (p[0] & 0x0f) as usize * 4;
                if p.len() < hl + 14 {
                    return;
                }
                (false, IpAddr::from([p[12], p[13], p[14], p[15]]), IpAddr::from([p[16], p[17], p[18], p[19]]), &p[hl..])
            }
            6 => {
                if p.len() < 54 {
                    return;
                }
                let a: [u8; 16] = p[8..24].try_into().unwrap();
                let b: [u8; 16] = p[24..40].try_into().unwrap();
                (true, IpAddr::from(a), IpAddr::from(b), &p[40..])
            }
            _ => return,
        };
        let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
        let fl = tcp[13];
        let (syn, ack, rst) = (fl & 0x02 != 0, fl & 0x10 != 0, fl & 0x04 != 0);
        if out && syn && !ack && dport == 443 && !self.skip.contains(&dst) && !self.skip_w.contains(&dst) {
            self.syns += 1;
            if let Some(pd) = self.pending.get_mut(&(dst, sport)) {
                pd.retrans += 1; // тот же SYN ещё раз — потеря
                return;
            }
            if self.pending.len() >= MAX_PEND {
                return;
            }
            self.pending.insert((dst, sport), Pending { t0: now, v6, retrans: 0 });
        } else if !out && sport == 443 && ((syn && ack) || rst) {
            // SYN-ACK или RST — сервер ответил, путь жив
            if let Some(pd) = self.pending.remove(&(src, dport)) {
                let o = Outcome { at: now, ok: true, rtt: (now - pd.t0) as f32, retrans: pd.retrans, ip: src };
                if pd.v6 { self.out6.push(o) } else { self.out4.push(o) }
            }
            if syn && ack {
                if self.est.len() < MAX_PEND {
                    self.est.insert((src, dport), now);
                }
            } else if rst {
                // RST вскоре после установки соединения — вероятный сброс DPI по имени сайта
                if let Some(t) = self.est.remove(&(src, dport)) {
                    if now - t <= RESET_WIN_MS && self.resets.len() < 256 {
                        self.resets.push((src, now));
                    }
                }
            }
        }
    }

    /// Адреса со сбросом после рукопожатия (кандидаты на блокировку по имени), один раз.
    pub fn drain_resets(&mut self, now: u64) -> Vec<IpAddr> {
        self.resets.retain(|(_, t)| now - *t <= 60_000);
        let mut v: Vec<IpAddr> = std::mem::take(&mut self.resets).into_iter().map(|(ip, _)| ip).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Счётчики успешных рукопожатий по адресам за окно `window_ms` (клиент активно
    /// долбится — перезагрузки, ретраи приложения). Демон складывает их ПО ИМЕНИ сайта
    /// (CDN размазан по многим адресам) → кандидаты на «тихую» блокировку: провайдер
    /// пропускает TCP (SYN-ACK есть), а ClientHello молча глотает без RST — ни drain_resets
    /// (нет RST), ни неотвеченные SYN (SYN отвечен) такое не ловят. Отсев рабочих сайтов —
    /// на подтверждающей пробе (unblock::check).
    pub fn succ_counts(&self, now: u64, window_ms: u64) -> Vec<(IpAddr, u32)> {
        let mut cnt: HashMap<IpAddr, u32> = HashMap::new();
        for o in self.out4.iter().chain(self.out6.iter()) {
            if o.ok && now.saturating_sub(o.at) <= window_ms {
                *cnt.entry(o.ip).or_insert(0) += 1;
            }
        }
        let mut v: Vec<(IpAddr, u32)> = cnt.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(256);
        v
    }

    pub fn sweep(&mut self, now: u64) {
        self.last_sweep = now;
        self.est.retain(|_, t| now - *t <= RESET_WIN_MS * 2);
        let mut failed = Vec::new();
        self.pending.retain(|(ip, _), pd| {
            if now - pd.t0 >= FAIL_AFTER_MS {
                failed.push((pd.v6, Outcome { at: now, ok: false, rtt: 0.0, retrans: pd.retrans, ip: *ip }));
                false
            } else {
                true
            }
        });
        for (v6, o) in failed {
            if v6 { self.out6.push(o) } else { self.out4.push(o) }
        }
        for o in [&mut self.out4, &mut self.out6] {
            let mut i = o.iter().position(|x| now - x.at <= KEEP_MS).unwrap_or(o.len());
            if o.len() - i > MAX_OUT {
                i = o.len() - MAX_OUT;
            }
            o.drain(..i);
        }
    }

    pub fn stats(&self, family: &str, window_ms: u64, now: u64) -> SynStats {
        let src = if family == "ipv6" { &self.out6 } else { &self.out4 };
        let mut rtts: Vec<f32> = Vec::new();
        let (mut ok, mut n, mut retr) = (0usize, 0usize, 0u64);
        for o in src.iter().filter(|o| now - o.at <= window_ms) {
            n += 1;
            retr += o.retrans as u64;
            if o.ok {
                ok += 1;
                rtts.push(o.rtt);
            }
        }
        if n < MIN_COUNT {
            return SynStats::default();
        }
        let mut st = SynStats { count: n as i64, success_rate: round1(ok as f64 * 100.0 / n as f64), loss_pct: round1(retr as f64 * 100.0 / (n as f64 + retr as f64)), ..Default::default() };
        if !rtts.is_empty() {
            rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            st.median_ms = round1(rtts[rtts.len() / 2] as f64);
            st.p90_ms = round1(rtts[rtts.len() * 9 / 10] as f64);
        }
        st
    }

    /// Исходы обоих семейств с момента t (новые первыми — как Go Since).
    pub fn since(&self, t: u64) -> impl Iterator<Item = &Outcome> {
        self.out4.iter().rev().take_while(move |o| o.at >= t).chain(self.out6.iter().rev().take_while(move |o| o.at >= t))
    }

    pub fn close(&mut self) -> Option<i32> {
        let fd = self.fd.take();
        if let Some(f) = fd {
            unsafe { libc::close(f) };
        }
        self.ifindex = 0;
        fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4syn(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[33] = flags;
        p
    }

    #[test]
    fn succ_counts_tracks_retries() {
        // клиент долбится в srv (6 успешных рукопожатий), в dead — одно.
        let mut s = SynRtt::default();
        let (me, srv, dead) = ([192, 0, 2, 2], [198, 51, 100, 1], [198, 51, 100, 9]);
        for i in 0..6u16 {
            s.on_packet(1000 + i as u64, &v4syn(me, srv, 40000 + i, 443, 0x02), true);
            s.on_packet(1040 + i as u64, &v4syn(srv, me, 443, 40000 + i, 0x12), false);
        }
        s.on_packet(1000, &v4syn(me, dead, 50000, 443, 0x02), true);
        s.on_packet(1040, &v4syn(dead, me, 443, 50000, 0x12), false);
        let c = s.succ_counts(1100, 120_000);
        assert_eq!(c.iter().find(|(ip, _)| *ip == IpAddr::from(srv)).map(|(_, n)| *n), Some(6));
        assert_eq!(c.iter().find(|(ip, _)| *ip == IpAddr::from(dead)).map(|(_, n)| *n), Some(1));
        assert_eq!(c.first().map(|(ip, _)| *ip), Some(IpAddr::from(srv))); // по убыванию
        // вне окна — ничего
        assert!(s.succ_counts(1100 + 200_000, 120_000).is_empty());
    }

    #[test]
    fn handshakes() {
        let mut s = SynRtt::default();
        let (me, srv, dead) = ([192, 0, 2, 2], [198, 51, 100, 1], [198, 51, 100, 9]);
        for i in 0..6u16 {
            s.on_packet(1000 + i as u64, &v4syn(me, srv, 40000 + i, 443, 0x02), true);
            s.on_packet(1040 + i as u64, &v4syn(srv, me, 443, 40000 + i, 0x12), false);
        }
        s.on_packet(2000, &v4syn(me, dead, 50000, 443, 0x02), true);
        s.on_packet(2500, &v4syn(me, dead, 50000, 443, 0x02), true); // повтор SYN
        s.sweep(5100);
        let st = s.stats("ipv4", 60_000, 5100);
        assert_eq!(st.count, 7);
        assert_eq!(st.success_rate, round1(600.0 / 7.0));
        assert_eq!(st.median_ms, 40.0);
        assert!(st.loss_pct > 0.0);
        assert_eq!(s.since(0).filter(|o| !o.ok).count(), 1);
        // пробы cgmon не считаются
        s.set_skip(&[IpAddr::from([203, 0, 113, 1])]);
        s.on_packet(6000, &v4syn(me, [203, 0, 113, 1], 1, 443, 0x02), true);
        assert!(s.pending.is_empty());
    }
}
