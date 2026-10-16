//! Чтение счётчиков nftables из ядра (netlink, NFNL_SUBSYS_NFTABLES) без
//! запуска nft и без JSON — перенос nfnl.go. Буфер приёма передаётся снаружи
//! и переиспользуется между вызовами.

use std::io;

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_GETSETELEM: u16 = 13;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
const NLA_F_NESTED: u16 = 0x8000;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_CREATE: u16 = 0x400;
const NFT_MSG_GETOBJ: u16 = 19;
pub const NFPROTO_INET: u8 = 1;

const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_EXPR: u16 = 7;
const NFTA_SET_ELEM_EXPRESSIONS: u16 = 10;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_COUNTER_BYTES: u16 = 1;
const NFTA_OBJ_TABLE: u16 = 1;
const NFTA_OBJ_NAME: u16 = 2;
const NFTA_OBJ_TYPE: u16 = 3;
const NFTA_OBJ_DATA: u16 = 4;
const NFT_OBJECT_COUNTER: u32 = 1;

const NLA_TYPE_MASK: u16 = 0x3fff;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;

/// Итератор атрибутов netlink: (тип, данные).
pub struct Attrs<'a>(&'a [u8]);

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let b = self.0;
        if b.len() < 4 {
            return None;
        }
        let l = u16::from_ne_bytes([b[0], b[1]]) as usize;
        if l < 4 || l > b.len() {
            self.0 = &[];
            return None;
        }
        let typ = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
        let data = &b[4..l];
        let al = (l + 3) & !3;
        self.0 = if al >= b.len() { &[] } else { &b[al..] };
        Some((typ, data))
    }
}

pub fn attrs(b: &[u8]) -> Attrs<'_> {
    Attrs(b)
}

fn put_attr(buf: &mut Vec<u8>, typ: u16, data: &[u8]) {
    let l = 4 + data.len();
    buf.extend_from_slice(&(l as u16).to_ne_bytes());
    buf.extend_from_slice(&typ.to_ne_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn put_cstr(buf: &mut Vec<u8>, typ: u16, s: &str) {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    put_attr(buf, typ, &v);
}

fn trim_nul(b: &[u8]) -> &[u8] {
    let mut e = b.len();
    while e > 0 && b[e - 1] == 0 {
        e -= 1;
    }
    &b[..e]
}

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Запрос-дамп nftables: каждая полезная нагрузка ответа (после nfgenmsg) → f.
pub fn dump(msg_type: u16, family: u8, attrs_in: &[u8], buf: &mut Vec<u8>, mut f: impl FnMut(&[u8])) -> io::Result<()> {
    dump_subsys(NFNL_SUBSYS_NFTABLES, msg_type, family, attrs_in, buf, |_, m| f(m))
}

/// Запрос-дамп любой подсистемы nfnetlink: (семейство из nfgenmsg, нагрузка) → f.
pub fn dump_subsys(subsys: u16, msg_type: u16, family: u8, attrs_in: &[u8], buf: &mut Vec<u8>, mut f: impl FnMut(u8, &[u8])) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = Fd(fd);
    let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd.0, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
    }
    let mut msg: Vec<u8> = Vec::with_capacity(20 + attrs_in.len());
    msg.extend_from_slice(&[0u8; 16]);
    msg.extend_from_slice(&[family, 0, 0, 0]);
    msg.extend_from_slice(attrs_in);
    let len = msg.len() as u32;
    msg[0..4].copy_from_slice(&len.to_ne_bytes());
    msg[4..6].copy_from_slice(&((subsys << 8) | msg_type).to_ne_bytes());
    msg[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    msg[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    let r = unsafe {
        libc::sendto(fd.0, msg.as_ptr() as *const libc::c_void, msg.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if buf.len() < 64 * 1024 {
        buf.resize(64 * 1024, 0);
    }
    loop {
        let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut b = &buf[..n as usize];
        while b.len() >= 16 {
            let l = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
            if l < 16 || l > b.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "netlink: bad message length"));
            }
            let typ = u16::from_ne_bytes([b[4], b[5]]);
            let m = &b[16..l];
            match typ {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => {
                    if m.len() >= 4 {
                        let e = i32::from_ne_bytes([m[0], m[1], m[2], m[3]]);
                        if e != 0 {
                            return Err(io::Error::from_raw_os_error(-e));
                        }
                    }
                }
                _ => {
                    if m.len() >= 4 {
                        f(m[0], &m[4..]);
                    }
                }
            }
            let al = (l + 3) & !3;
            if al >= b.len() {
                break;
            }
            b = &b[al..];
        }
    }
}

fn counter_bytes(expr: &[u8]) -> Option<u64> {
    let mut name: &[u8] = &[];
    let mut data: &[u8] = &[];
    for (t, d) in attrs(expr) {
        match t {
            NFTA_EXPR_NAME => name = trim_nul(d),
            NFTA_EXPR_DATA => data = d,
            _ => {}
        }
    }
    if name != b"counter" {
        return None;
    }
    attrs(data).find(|(t, d)| *t == NFTA_COUNTER_BYTES && d.len() == 8).map(|(_, d)| u64::from_be_bytes(d.try_into().unwrap()))
}

/// Разбор одного NEWSETELEM: ключ (4 или 16 байт адреса) и байты счётчика → f.
pub fn parse_set_elems(payload: &[u8], f: &mut impl FnMut(&[u8], u64)) {
    for (t, d) in attrs(payload) {
        if t != NFTA_SET_ELEM_LIST_ELEMENTS {
            continue;
        }
        for (et, ed) in attrs(d) {
            if et != NFTA_LIST_ELEM {
                continue;
            }
            let mut key: &[u8] = &[];
            let mut bytes = None;
            for (ft, fd) in attrs(ed) {
                match ft {
                    NFTA_SET_ELEM_KEY => {
                        for (vt, vd) in attrs(fd) {
                            if vt == NFTA_DATA_VALUE && (vd.len() == 4 || vd.len() == 16) {
                                key = vd;
                            }
                        }
                    }
                    NFTA_SET_ELEM_EXPR => bytes = counter_bytes(fd),
                    NFTA_SET_ELEM_EXPRESSIONS => {
                        for (xt, xd) in attrs(fd) {
                            if xt == NFTA_LIST_ELEM {
                                if let Some(b) = counter_bytes(xd) {
                                    bytes = Some(b);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let (false, Some(b)) = (key.is_empty(), bytes) {
                f(key, b);
            }
        }
    }
}

fn nl_msg(buf: &mut Vec<u8>, typ: u16, flags: u16, seq: u32, family: u8, res_id: u16, attrs: &[u8]) {
    let len = 16 + 4 + attrs.len();
    buf.extend_from_slice(&(len as u32).to_ne_bytes());
    buf.extend_from_slice(&typ.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&[family, 0]);
    buf.extend_from_slice(&res_id.to_be_bytes());
    buf.extend_from_slice(attrs);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Сообщение-пакет «добавить элементы в набор» (как `nft add element … timeout`).
pub fn set_add_batch(table: &str, set: &str, keys: &[&[u8]], timeout_ms: u64) -> Vec<u8> {
    let mut elems = Vec::new();
    for k in keys {
        let mut key = Vec::new();
        put_attr(&mut key, NFTA_DATA_VALUE, k);
        let mut e = Vec::new();
        put_attr(&mut e, NFTA_SET_ELEM_KEY | NLA_F_NESTED, &key);
        if timeout_ms > 0 {
            put_attr(&mut e, NFTA_SET_ELEM_TIMEOUT, &timeout_ms.to_be_bytes());
        }
        put_attr(&mut elems, NFTA_LIST_ELEM | NLA_F_NESTED, &e);
    }
    let mut a = Vec::new();
    put_cstr(&mut a, NFTA_SET_ELEM_LIST_TABLE, table);
    put_cstr(&mut a, NFTA_SET_ELEM_LIST_SET, set);
    put_attr(&mut a, NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED, &elems);
    let mut m = Vec::with_capacity(64 + a.len());
    nl_msg(&mut m, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 1, 0, NFNL_SUBSYS_NFTABLES, &[]);
    nl_msg(&mut m, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 2, NFPROTO_INET, 0, &a);
    nl_msg(&mut m, NFNL_MSG_BATCH_END, NLM_F_REQUEST, 3, 0, NFNL_SUBSYS_NFTABLES, &[]);
    m
}

/// Добавить элементы (адреса) в набор inet-таблицы без запуска nft: одна
/// посылка netlink (~доли мс). Уже существующий элемент — не ошибка.
pub fn set_add(table: &str, set: &str, keys: &[&[u8]], timeout_ms: u64) -> io::Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = Fd(fd);
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd.0, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
    }
    let msg = set_add_batch(table, set, keys, timeout_ms);
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    let r = unsafe { libc::sendto(fd.0, msg.as_ptr() as *const libc::c_void, msg.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // ответ — подтверждение (NLMSG_ERROR с кодом 0) или ошибка
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut b = &buf[..n as usize];
    while b.len() >= 20 {
        let l = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if l < 16 || l > b.len() {
            break;
        }
        if u16::from_ne_bytes([b[4], b[5]]) == NLMSG_ERROR {
            let e = i32::from_ne_bytes([b[16], b[17], b[18], b[19]]);
            if e != 0 && e != -libc::EEXIST {
                return Err(io::Error::from_raw_os_error(-e));
            }
        }
        let al = (l + 3) & !3;
        if al >= b.len() {
            break;
        }
        b = &b[al..];
    }
    Ok(())
}

/// Элементы набора (адреса) и их счётчики байт.
pub fn set_counters(table: &str, set: &str, buf: &mut Vec<u8>, mut f: impl FnMut(&[u8], u64)) -> io::Result<()> {
    let mut a = Vec::with_capacity(64);
    put_cstr(&mut a, NFTA_SET_ELEM_LIST_TABLE, table);
    put_cstr(&mut a, NFTA_SET_ELEM_LIST_SET, set);
    dump(NFT_MSG_GETSETELEM, NFPROTO_INET, &a, buf, |p| parse_set_elems(p, &mut f))
}

/// Именованные счётчики таблицы: имя → байты.
pub fn named_counters(table: &str, buf: &mut Vec<u8>, mut f: impl FnMut(&str, u64)) -> io::Result<()> {
    let mut a = Vec::with_capacity(64);
    put_cstr(&mut a, NFTA_OBJ_TABLE, table);
    put_attr(&mut a, NFTA_OBJ_TYPE, &NFT_OBJECT_COUNTER.to_be_bytes());
    dump(NFT_MSG_GETOBJ, NFPROTO_INET, &a, buf, |p| {
        let mut name: &[u8] = &[];
        let mut data: &[u8] = &[];
        for (t, d) in attrs(p) {
            match t {
                NFTA_OBJ_NAME => name = trim_nul(d),
                NFTA_OBJ_DATA => data = d,
                _ => {}
            }
        }
        if let Ok(n) = std::str::from_utf8(name) {
            if let Some((_, d)) = attrs(data).find(|(t, d)| *t == NFTA_COUNTER_BYTES && d.len() == 8) {
                if !n.is_empty() {
                    f(n, u64::from_be_bytes(d.try_into().unwrap()));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nest(typ: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        put_attr(&mut v, typ, inner);
        v
    }

    #[test]
    fn set_elem_with_counter() {
        // ключ 192.0.2.7 + выражение counter (bytes = 1234)
        let key = nest(NFTA_SET_ELEM_KEY, &nest(NFTA_DATA_VALUE, &[192, 0, 2, 7]));
        let mut cdata = Vec::new();
        put_attr(&mut cdata, NFTA_COUNTER_BYTES, &1234u64.to_be_bytes());
        let mut expr = Vec::new();
        put_cstr(&mut expr, NFTA_EXPR_NAME, "counter");
        put_attr(&mut expr, NFTA_EXPR_DATA, &cdata);
        let mut el = key.clone();
        put_attr(&mut el, NFTA_SET_ELEM_EXPR, &expr);
        let list = nest(NFTA_SET_ELEM_LIST_ELEMENTS, &nest(NFTA_LIST_ELEM, &el));
        let mut got = Vec::new();
        parse_set_elems(&list, &mut |k: &[u8], b| got.push((k.to_vec(), b)));
        assert_eq!(got, vec![(vec![192, 0, 2, 7], 1234)]);
    }

    #[test]
    fn garbage_is_safe() {
        let mut n = 0;
        parse_set_elems(&[0xff, 0xff, 3, 0, 1, 2, 3], &mut |_: &[u8], _| n += 1);
        parse_set_elems(&[8, 0, 3, 0, 4, 0], &mut |_: &[u8], _| n += 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn set_add_message() {
        let m = set_add_batch("cgmon_route", "p1_ip", &[&[192, 0, 2, 7]], 3_600_000);
        // три сообщения: начало пакета, NEWSETELEM, конец пакета
        let l1 = u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize;
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), NFNL_MSG_BATCH_BEGIN);
        let b = &m[l1..];
        let l2 = u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize;
        assert_eq!(u16::from_ne_bytes([b[4], b[5]]), (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM);
        let p = &b[20..l2];
        let names: Vec<u16> = attrs(p).map(|(t, _)| t).collect();
        assert_eq!(names, vec![NFTA_SET_ELEM_LIST_TABLE, NFTA_SET_ELEM_LIST_SET, NFTA_SET_ELEM_LIST_ELEMENTS]);
        let (_, el) = attrs(p).nth(2).unwrap();
        let (_, e) = attrs(el).next().unwrap();
        let f: Vec<(u16, usize)> = attrs(e).map(|(t, d)| (t, d.len())).collect();
        assert_eq!(f, vec![(NFTA_SET_ELEM_KEY, 8), (NFTA_SET_ELEM_TIMEOUT, 8)]);
        let e3 = &b[((l2 + 3) & !3)..];
        assert_eq!(u16::from_ne_bytes([e3[4], e3[5]]), NFNL_MSG_BATCH_END);
    }
}
