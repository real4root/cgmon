//! Центр сбора (перенос hub.go + minihttp.go): принимает зашифрованные отчёты
//! роутеров (POST /api/v1/report), хранит их состояние и общий журнал,
//! сопоставляет (каждые 10 с) и шлёт в Telegram:
//!   🔴 общий сбой внешнего канала — деградация у ≥ min_isps провайдеров;
//!   🟠 сбой у провайдера — ≥ 2 роутера одного провайдера;
//!   🟡 сервис не отвечает или медленный у ≥ 2 роутеров;
//!   ⚫/🟢 роутер не на связи / снова на связи; (по желанию) сбой одного роутера.
//! Сервер — неблокирующие сокеты в общем epoll: ≤ 64 соединения, ≤ 8 с адреса,
//! 10 с на запрос, строка ≤ 4 КБ, тело ≤ 64 КБ, 120 запросов/мин с адреса,
//! ≤ 500 роутеров, единый 403. Telegram — curl (токен через stdin) в потоке.

use crate::config::HubConfig;
use crate::dnsguard::{time_json, time_parse, vstr};
use crate::evloop::Poller;
use crate::json::J;
use crate::report::Report;
use crate::value::{parse_json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};

const MAX_BODY: usize = 64 << 10;
const MAX_CONNS: usize = 64;
const MAX_PER_IP: usize = 8;
const MAX_ROUTERS: usize = 500;
const MAX_EVENTS: usize = 200;
const RATE_PER_MIN: i64 = 120;
const MAX_SKEW: i64 = 5 * 60;
const NONCE_MAX: usize = 50000;

fn now_ms() -> i64 {
    let (s, n) = crate::util::now_wall();
    s * 1000 + (n / 1_000_000) as i64
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;").replace('\'', "&#39;")
}

/// Длительность как в Go hubDur: «2 ч 5 мин», «3 мин 10 с», «40 с».
pub fn dur(ms: i64) -> String {
    let s = ms / 1000;
    if s >= 3600 {
        format!("{} ч {} мин", s / 3600, s % 3600 / 60)
    } else if s >= 60 {
        format!("{} мин {} с", s / 60, s % 60)
    } else {
        format!("{s} с")
    }
}

fn hhmm(ms: i64) -> String {
    crate::dnsguard::hhmm(ms)
}

#[derive(Clone, Debug, Default)]
struct Router {
    last: Report,
    seen: i64,
    offline: bool,
    off_at: i64,
    noticed: BTreeMap<String, i64>,
    known: Option<HashSet<i64>>,
    /// адрес, с которого пришёл последний отчёт (ссылка на страницу роутера, обычно ZeroTier)
    from: String,
}

#[derive(Clone, Debug, Default)]
struct Alert {
    kind: String,
    key: String,
    since: i64,
    last_bad: i64,
    routers: BTreeSet<String>,
    isps: BTreeSet<String>,
    min_v4: f64,
    detail: String,
}

struct SvcView {
    name: String,
    detail: String,
    routers: Vec<String>,
    isps: Vec<String>,
    since: i64,
}

struct Conn {
    fd: i32,
    ip: String,
    buf: Vec<u8>,
    deadline: i64,
}

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Итог отправки в Telegram: получатель, отправлено, ошибка.
type TgDone = Vec<((String, String), usize, Option<String>)>;

/// Роутер не на связи дольше — центр его забывает (переустановлен, выключен навсегда).
const FORGET_AFTER: i64 = 30 * 24 * 3600 * 1000;

pub struct Hub {
    pub cfg: HubConfig,
    listen_fd: Option<i32>,
    tok_base: u64,
    next_tok: u64,
    conns: HashMap<u64, Conn>,
    per_ip: HashMap<String, usize>,
    routers: BTreeMap<String, Router>,
    alerts: BTreeMap<String, Alert>,
    events: Vec<(i64, String)>,
    queues: HashMap<(String, String), Vec<String>>,
    tg_err: HashMap<(String, String), String>,
    sent_n: i64,
    last_tg: String,
    svc_now: Vec<SvcView>,
    nonces: HashMap<[u8; 12], i64>,
    limiter: HashMap<String, (i64, i64)>,
    bad_n: i64,
    bad_log_at: i64,
    pub next_eval: u64,
    saved_at: i64,
    tg_busy: bool,
    tx: Sender<TgDone>,
    rx: Receiver<TgDone>,
}

fn degraded(r: &Report) -> bool {
    if !r.wan_up {
        return true;
    }
    matches!(r.state.as_str(), "WARNING" | "CRITICAL") && (r.diagnosis == "IPV4_EXTERNAL_DEGRADATION" || r.diagnosis == "UNKNOWN")
}

fn isp_of(r: &Report, name: &str) -> String {
    if !r.isp.name.is_empty() {
        r.isp.name.clone()
    } else if !r.isp.asn.is_empty() {
        format!("AS{}", r.isp.asn)
    } else {
        format!("провайдер {name}")
    }
}

fn set_list(s: &BTreeSet<String>) -> String {
    esc(&s.iter().cloned().collect::<Vec<_>>().join(", "))
}

/// Длина строк отчёта (сбойный или угнанный роутер не раздувает память).
fn sane(r: &mut Report) -> bool {
    let short = |l: usize, ss: &[&str]| ss.iter().all(|s| s.len() <= l);
    if !short(128, &[&r.version, &r.state, &r.diagnosis, &r.link, &r.isp.name, &r.isp.asn, &r.isp.ip]) {
        return false;
    }
    if !r.services.iter().all(|s| s.len() <= 253) || !r.svc.iter().all(|s| s.name.len() <= 253 && s.state.len() <= 16 && s.fam.len() <= 16) {
        return false;
    }
    if r.issues.len() > 30 || !r.issues.iter().all(|i| i.level.len() <= 8 && i.kind.len() <= 64 && i.text.len() <= 600) {
        return false;
    }
    for i in r.incidents.iter_mut() {
        if i.typ.len() > 64 {
            return false;
        }
        if i.text.len() > 2000 {
            let mut n = 2000;
            while !i.text.is_char_boundary(n) {
                n -= 1;
            }
            i.text.truncate(n);
            i.text.push('…'); // длинный текст — обрезать, а не терять отчёт
        }
    }
    true
}

/// Сообщение в Telegram одному получателю: curl, URL и данные — через stdin (-K -).
pub fn send_telegram(bot: &str, chat: &str, text: &str) -> Result<(), String> {
    let (bin, kind) = crate::report::https_tool();
    let url = format!("https://api.telegram.org/bot{bot}/sendMessage");
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t"));
    let res = match kind {
        "" => Err("нет curl, uclient-fetch или wget".to_string()),
        "curl" => {
            let mut conf = format!("url = {}\n", q(&url));
            for (k, v) in [("chat_id", chat), ("text", text), ("parse_mode", "HTML"), ("disable_web_page_preview", "true")] {
                conf.push_str(&format!("data-urlencode = {}\n", q(&format!("{k}={v}"))));
            }
            run_stdin(bin, &["-s", "-f", "-m", "15", "-o", "/dev/null", "-K", "-"], &conf).map_err(|e| format!("curl: {e}"))
        }
        _ => {
            let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
            let data = format!("chat_id={}&disable_web_page_preview=true&parse_mode=HTML&text={}", enc(chat), enc(text));
            let pd = format!("--post-data={data}");
            if kind == "gnu" {
                run_stdin(bin, &["-q", "-T", "15", "-O", "/dev/null", &pd, "-t", "1", "-i", "-"], &format!("{url}\n")).map_err(|e| format!("{kind}: {e}"))
            } else {
                run_stdin(bin, &["-q", "-T", "15", "-O", "/dev/null", &pd, &url], "").map_err(|_| format!("{kind}: exit status 1"))
            }
        }
    };
    res.map_err(|e| e.replace(bot, "***"))
}

fn run_stdin(bin: &str, args: &[&str], input: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut ch = std::process::Command::new(bin).args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    if let Some(mut si) = ch.stdin.take() {
        let _ = si.write_all(input.as_bytes());
    }
    let o = ch.wait_with_output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("exit status {} {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).trim()));
    }
    Ok(())
}

fn tg_label(bot: &str, chat: &str) -> String {
    format!("бот {} → {chat}", bot.split(':').next().unwrap_or(""))
}

/// Слушающий сокет (IPv6 с приёмом IPv4, иначе IPv4).
fn listen(addr: &str) -> Result<i32, String> {
    let (host, port) = addr.rsplit_once(':').ok_or_else(|| format!("{addr}: нужен адрес:порт"))?;
    let port: u16 = port.parse().map_err(|_| format!("{addr}: порт"))?;
    let host = host.trim_matches(['[', ']']);
    let ip: IpAddr = if host.is_empty() { "::".parse().unwrap() } else { host.parse().map_err(|_| format!("{addr}: адрес"))? };
    unsafe {
        let fam = if ip.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let fd = libc::socket(fam, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let one: i32 = 1;
        let zero: i32 = 0;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const i32 as *const libc::c_void, 4);
        if fam == libc::AF_INET6 {
            libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &zero as *const i32 as *const libc::c_void, 4);
        }
        let (sa, l) = crate::netx::sockaddr_of(&ip, port);
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, l) < 0 || libc::listen(fd, 64) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("listen tcp {addr}: {e}"));
        }
        Ok(fd)
    }
}

fn write_all(fd: i32, b: &[u8]) {
    let mut b = b;
    let t0 = std::time::Instant::now();
    while !b.is_empty() && t0.elapsed().as_millis() < 2000 {
        let n = unsafe { libc::write(fd, b.as_ptr() as *const libc::c_void, b.len()) };
        if n > 0 {
            b = &b[n as usize..];
        } else {
            let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            unsafe { libc::poll(&mut p, 1, 200) };
        }
    }
}

/// Разбор запроса: Some((метод, путь, тело)) — готов; None — ждать ещё; Err — плохой.
fn parse_req(b: &[u8]) -> Result<Option<(String, String, Vec<u8>)>, ()> {
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).or_else(|| b.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)) else {
        if b.len() > 64 * 4096 || b.split(|c| *c == b'\n').any(|l| l.len() > 4096) {
            return Err(());
        }
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&b[..end]);
    let mut lines = head.lines();
    let first = lines.next().ok_or(())?;
    if first.len() > 2048 {
        return Err(());
    }
    let f: Vec<&str> = first.split_whitespace().collect();
    if f.len() < 2 {
        return Err(());
    }
    let mut n: usize = 0;
    for (i, h) in lines.enumerate() {
        if i >= 64 || h.len() > 4096 {
            return Err(());
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                n = v.trim().parse().map_err(|_| ())?;
            }
        }
    }
    if n > MAX_BODY {
        return Err(());
    }
    if b.len() < end + n {
        return Ok(None);
    }
    Ok(Some((f[0].to_string(), f[1].to_string(), b[end..end + n].to_vec())))
}

impl Hub {
    pub fn new(cfg: HubConfig, tok_base: u64) -> Hub {
        let (tx, rx) = channel();
        let mut h = Hub { cfg, listen_fd: None, tok_base, next_tok: 0, conns: HashMap::new(), per_ip: HashMap::new(), routers: BTreeMap::new(), alerts: BTreeMap::new(), events: Vec::new(), queues: HashMap::new(), tg_err: HashMap::new(), sent_n: 0, last_tg: String::new(), svc_now: Vec::new(), nonces: HashMap::new(), limiter: HashMap::new(), bad_n: 0, bad_log_at: 0, next_eval: 0, saved_at: now_ms(), tg_busy: false, tx, rx };
        h.load();
        h
    }

    pub fn owns(&self, tok: u64) -> bool {
        tok >> 48 == self.tok_base >> 48
    }

    pub fn start(&mut self, poller: &Poller) {
        match listen(&self.cfg.listen) {
            Ok(fd) => {
                if poller.add(fd, libc::EPOLLIN as u32, self.tok_base).is_ok() {
                    crate::log_info!("hub: listening on {}", self.cfg.listen);
                    self.listen_fd = Some(fd);
                } else {
                    unsafe { libc::close(fd) };
                }
            }
            Err(e) => crate::log_err!("hub: {}", e),
        }
    }

    pub fn stop(&mut self, poller: &Poller) {
        if let Some(fd) = self.listen_fd.take() {
            poller.del(fd);
            unsafe { libc::close(fd) };
        }
        for (_, c) in self.conns.drain() {
            poller.del(c.fd);
        }
        self.save();
    }

    fn load(&mut self) {
        let Some(v) = std::fs::read_to_string(crate::storage::path(&self.cfg.state_file)).ok().and_then(|t| parse_json(&t).ok()) else { return };
        if let Some(Value::Map(m)) = v.get("routers") {
            for (name, r) in m {
                let noticed = match r.get("noticed") {
                    Some(Value::Map(n)) => n.iter().map(|(k, t)| (k.clone(), time_parse(Some(t)))).collect(),
                    _ => BTreeMap::new(),
                };
                let last = r.get("last").map(Report::from).unwrap_or_default();
                self.routers.insert(name.clone(), Router { last, seen: time_parse(r.get("seen")), offline: r.get("offline").and_then(|x| x.as_bool()).unwrap_or(false), off_at: time_parse(r.get("off_at")), noticed, known: None, from: r.get("from").and_then(|x| x.as_str()).unwrap_or("").to_string() });
            }
        }
        if let Some(Value::Map(m)) = v.get("alerts") {
            for (id, a) in m {
                let set = |k: &str| -> BTreeSet<String> {
                    match a.get(k) {
                        Some(Value::Map(x)) => x.iter().map(|(n, _)| n.clone()).collect(),
                        _ => BTreeSet::new(),
                    }
                };
                self.alerts.insert(id.clone(), Alert { kind: vstr(a, "kind"), key: vstr(a, "key"), since: time_parse(a.get("since")), last_bad: time_parse(a.get("last_bad")), routers: set("routers"), isps: set("isps"), min_v4: a.get("min_v4").and_then(|x| x.as_f64()).unwrap_or(100.0), detail: vstr(a, "detail") });
            }
        }
        if let Some(Value::List(l)) = v.get("events") {
            for e in l {
                self.events.push((time_parse(e.get("time")), vstr(e, "text")));
            }
        }
    }

    fn save(&self) {
        if self.cfg.state_file.is_empty() || crate::util::readonly() {
            return;
        }
        let mut j = J::new();
        j.obj().key("alerts").obj();
        for (id, a) in &self.alerts {
            j.key(id).obj().key("kind").str(&a.kind).key("key").str(&a.key).key("since").str(&time_json(a.since)).key("last_bad").str(&time_json(a.last_bad));
            for (k, s) in [("routers", &a.routers), ("isps", &a.isps)] {
                j.key(k).obj();
                for n in s {
                    j.key(n).bool(true);
                }
                j.end_obj();
            }
            j.key("min_v4").raw(&crate::config::go_float(a.min_v4));
            if !a.detail.is_empty() {
                j.key("detail").str(&a.detail);
            }
            j.end_obj();
        }
        j.end_obj().key("events").arr();
        for (t, text) in &self.events {
            j.obj().key("time").str(&time_json(*t)).key("kind").str("").key("text").str(text).end_obj();
        }
        j.end_arr().key("routers").obj();
        for (name, r) in &self.routers {
            j.key(name).obj().key("last");
            r.last.json(&mut j);
            j.key("seen").str(&time_json(r.seen));
            if !r.from.is_empty() {
                j.key("from").str(&r.from);
            }
            if r.offline {
                j.key("offline").bool(true);
            }
            if r.off_at != 0 {
                j.key("off_at").str(&time_json(r.off_at));
            }
            if !r.noticed.is_empty() {
                j.key("noticed").obj();
                for (k, t) in &r.noticed {
                    j.key(k).str(&time_json(*t));
                }
                j.end_obj();
            }
            j.end_obj();
        }
        j.end_obj().end_obj();
        if let Err(e) = crate::util::write_atomic(&crate::storage::path(&self.cfg.state_file), j.b.as_bytes(), 0o600) {
            crate::log_err!("hub: {}: {}", self.cfg.state_file, e);
        }
    }

    /// Запись общего журнала (JSONL, ключи по алфавиту — как Go map).
    fn journal(&self, kv: &[(&str, String)]) {
        let mut kv: Vec<&(&str, String)> = kv.iter().collect();
        kv.sort_by_key(|x| x.0);
        let mut s = String::from("{");
        for (i, (k, v)) in kv.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            crate::value::json_str(&mut s, k);
            s.push(':');
            s.push_str(v);
        }
        s.push('}');
        crate::incidents::append_jsonl(&self.cfg.journal_file, &s, 2 << 20);
    }

    fn q(s: &str) -> String {
        let mut o = String::new();
        crate::value::json_str(&mut o, s);
        o
    }

    // ---- сервер ----

    pub fn on_event(&mut self, tok: u64, poller: &Poller) {
        if tok == self.tok_base {
            self.accept(poller);
            return;
        }
        let Some(c) = self.conns.get_mut(&tok) else { return };
        let mut tmp = [0u8; 4096];
        let mut eof = false;
        loop {
            let n = unsafe { libc::read(c.fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
            if n > 0 {
                c.buf.extend_from_slice(&tmp[..n as usize]);
                if c.buf.len() > MAX_BODY + 64 * 4096 {
                    break;
                }
                continue;
            }
            eof = n == 0;
            break;
        }
        let parsed = parse_req(&c.buf);
        let (fd, ip) = (c.fd, c.ip.clone());
        let reply = match parsed {
            Ok(None) if !eof => return,
            Ok(Some((m, p, body))) => self.handle(&m, &p, &body, &ip),
            _ => (400, "{\"error\":\"bad request\"}".to_string()),
        };
        let text = match reply.0 {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Bad Request",
        };
        let head = format!("HTTP/1.1 {} {text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.0, reply.1.len());
        write_all(fd, head.as_bytes());
        write_all(fd, reply.1.as_bytes());
        poller.del(fd);
        self.drop_conn(tok);
    }

    fn drop_conn(&mut self, tok: u64) {
        if let Some(c) = self.conns.remove(&tok) {
            if let Some(n) = self.per_ip.get_mut(&c.ip) {
                *n -= 1;
                if *n == 0 {
                    self.per_ip.remove(&c.ip);
                }
            }
        }
    }

    fn accept(&mut self, poller: &Poller) {
        let Some(lfd) = self.listen_fd else { return };
        loop {
            let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut l = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            let fd = unsafe { libc::accept4(lfd, &mut ss as *mut _ as *mut libc::sockaddr, &mut l, libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if fd < 0 {
                return;
            }
            let ip = match crate::netx::ip_of_sockaddr(&ss) {
                Some(IpAddr::V6(a)) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
                Some(a) => a,
                None => {
                    unsafe { libc::close(fd) };
                    continue;
                }
            }
            .to_string();
            // перегрузка (или атака) — не копим соединения
            if self.conns.len() >= MAX_CONNS || self.per_ip.get(&ip).copied().unwrap_or(0) >= MAX_PER_IP {
                unsafe { libc::close(fd) };
                continue;
            }
            self.next_tok += 1;
            let tok = self.tok_base | 1 << 32 | (self.next_tok & 0xffff_ffff);
            if poller.add(fd, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32, tok).is_err() {
                unsafe { libc::close(fd) };
                continue;
            }
            *self.per_ip.entry(ip.clone()).or_insert(0) += 1;
            self.conns.insert(tok, Conn { fd, ip, buf: Vec::new(), deadline: now_ms() + 10_000 });
        }
    }

    /// Медленные соединения — закрыть (весь запрос — за 10 с).
    pub fn sweep(&mut self, poller: &Poller) {
        let now = now_ms();
        let late: Vec<u64> = self.conns.iter().filter(|(_, c)| c.deadline <= now).map(|(k, _)| *k).collect();
        for k in late {
            if let Some(c) = self.conns.get(&k) {
                poller.del(c.fd);
            }
            self.drop_conn(k);
        }
    }

    fn allow(&mut self, ip: &str, now: i64) -> bool {
        if self.limiter.len() > 10000 {
            self.limiter.clear(); // наплыв адресов — начать заново
        }
        let b = self.limiter.entry(ip.to_string()).or_insert((0, now + 60_000));
        if now > b.1 {
            *b = (0, now + 60_000);
        }
        b.0 += 1;
        b.0 <= RATE_PER_MIN
    }

    fn note_bad(&mut self, ip: &str, why: &str, now: i64) {
        self.bad_n += 1;
        if now - self.bad_log_at >= 60_000 {
            crate::log_info!("hub: rejected {} request(s), last from {}: {}", self.bad_n, ip, why);
            self.bad_n = 0;
            self.bad_log_at = now;
        }
    }

    /// Расшифровать и проверить отчёт: время ±5 мин, повторы nonce.
    fn open(&mut self, b: &[u8], now: i64) -> Result<Report, &'static str> {
        if self.cfg.token.is_empty() {
            return Err("no token");
        }
        if b.len() < 1 + 12 + 16 || b[0] != crate::hubcrypt::PROTO_V1 {
            return Err("bad format");
        }
        let nonce: [u8; 12] = b[1..13].try_into().unwrap();
        if self.nonces.contains_key(&nonce) {
            return Err("replay");
        }
        let plain = crate::hubcrypt::open(&self.cfg.token, b).ok_or("auth")?;
        let v = parse_json(&String::from_utf8_lossy(&plain)).map_err(|_| "bad report")?;
        let rep = v.get("report").map(Report::from).ok_or("bad report")?;
        if rep.router.is_empty() {
            return Err("bad report");
        }
        let ts = v.get("ts").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
        if (ts - now / 1000).abs() > MAX_SKEW {
            return Err("clock skew");
        }
        if self.nonces.len() >= NONCE_MAX {
            self.nonces.retain(|_, t| now - *t <= 2 * MAX_SKEW * 1000);
            if self.nonces.len() >= NONCE_MAX {
                return Err("busy");
            }
        }
        self.nonces.insert(nonce, now);
        Ok(rep)
    }

    fn handle(&mut self, method: &str, path: &str, body: &[u8], ip: &str) -> (u16, String) {
        let now = now_ms();
        let forbidden = (403, "{\"error\":\"forbidden\"}".to_string());
        if !self.allow(ip, now) {
            self.note_bad(ip, "rate limit", now);
            return forbidden;
        }
        if method == "POST" && path == "/api/v1/report" {
            return match self.open(body, now) {
                Err(e) => {
                    self.note_bad(ip, e, now);
                    forbidden
                }
                Ok(rep) => {
                    let name = rep.router.clone();
                    if self.accept_report(rep, now) {
                        if let Some(r) = self.routers.get_mut(&name) {
                            r.from = ip.to_string();
                        }
                        (200, "{\"ok\":true}".into())
                    } else {
                        forbidden
                    }
                }
            };
        }
        if method == "GET" && path == "/api/state" && (ip == "127.0.0.1" || ip == "::1") {
            let mut j = J::new();
            j.obj().key("routers").arr();
            for name in self.routers.keys() {
                j.str(name);
            }
            j.end_arr().key("open_alerts").int(self.alerts.len() as i64).key("telegram_sent").int(self.sent_n).key("telegram_last_error").str(&self.last_tg).end_obj();
            return (200, j.b);
        }
        forbidden
    }

    /// Отчёт роутера: состояние, новые инциденты — в общий журнал, напоминания — в Telegram.
    fn accept_report(&mut self, mut rep: Report, now: i64) -> bool {
        if rep.router.len() > 64 || rep.incidents.len() > 50 || rep.services.len() > 50 || rep.svc.len() > 50 || rep.notices.len() > 10 || !sane(&mut rep) {
            return false;
        }
        if !self.routers.contains_key(&rep.router) {
            if self.routers.len() >= MAX_ROUTERS {
                return false;
            }
            crate::log_info!("hub: new router {} ({})", rep.router, rep.isp.name);
            self.routers.insert(rep.router.clone(), Router::default());
        }
        let name = rep.router.clone();
        let rt = self.routers.get_mut(&name).unwrap();
        let known = rt.known.get_or_insert_with(|| rt.last.incidents.iter().filter(|i| !i.open).map(|i| i.id).collect());
        if known.len() > 2000 {
            known.clear(); // сбойный роутер с бесконечными новыми номерами — не копить
        }
        let mut journal: Vec<Vec<(&str, String)>> = Vec::new();
        let t = Self::q(&time_json(now));
        for i in &rep.incidents {
            if known.contains(&i.id) && i.open {
                continue;
            }
            if !i.open {
                if known.contains(&i.id) {
                    continue;
                }
                known.insert(i.id);
            }
            let mut ij = J::new();
            ij.obj().key("id").int(i.id).key("type").str(&i.typ).key("open").bool(i.open).key("start").str(&i.start).key("end").str(&i.end);
            if i.dur != 0 {
                ij.key("dur").int(i.dur);
            }
            if !i.text.is_empty() {
                ij.key("text").str(&i.text);
            }
            ij.end_obj();
            journal.push(vec![("time", t.clone()), ("router", Self::q(&name)), ("isp", Self::q(&rep.isp.name)), ("incident", ij.b)]);
        }
        let mut notify = Vec::new();
        for n in &rep.notices {
            if n.key.len() > 64 || n.text.len() > 500 || rt.noticed.contains_key(&n.key) || rt.noticed.len() >= 500 {
                continue;
            }
            rt.noticed.insert(n.key.clone(), now);
            notify.push(format!("<b>{}</b>: {}", esc(&name), esc(&n.text)));
            let mut nj = J::new();
            nj.obj().key("key").str(&n.key).key("text").str(&n.text).end_obj();
            journal.push(vec![("time", t.clone()), ("router", Self::q(&name)), ("notice", nj.b)]);
        }
        rt.noticed.retain(|_, t| now - *t <= 90 * 24 * 3600 * 1000);
        // проблемы роутера: новая критичная — в Telegram, остальное — в журнал центра
        let mut ev_only = Vec::new();
        if rt.seen != 0 {
            for i in rep.issues.iter().filter(|i| !rt.last.issues.iter().any(|o| o.kind == i.kind && o.level == i.level)) {
                let m = format!("{} <b>{}</b>: {}", if i.level == "crit" { "🔴" } else { "🟡" }, esc(&name), esc(&i.text));
                if i.level == "crit" { notify.push(m) } else { ev_only.push(m) }
            }
            for o in rt.last.issues.iter().filter(|o| !rep.issues.iter().any(|i| i.kind == o.kind)) {
                ev_only.push(format!("✅ <b>{}</b>: прошло — {}", esc(&name), esc(&o.text)));
            }
        }
        if rep.isp.asn.is_empty() && !rt.last.isp.asn.is_empty() {
            rep.isp = rt.last.isp.clone(); // центр помнит провайдера, пока роутер его выясняет
        }
        rt.last = rep;
        rt.seen = now;
        for j in journal {
            self.journal(&j);
        }
        for m in ev_only {
            self.event(&m, now);
        }
        let had = !notify.is_empty();
        for n in notify {
            self.notify(&n, now);
        }
        if had {
            self.save(); // не повторить после перезапуска центра
        }
        true
    }

    // ---- сопоставление ----

    /// Запись в журнал центра без Telegram.
    fn event(&mut self, text: &str, now: i64) {
        crate::log_info!("hub: {}", text.replace('\n', " | "));
        self.events.push((now, text.to_string()));
        if self.events.len() > MAX_EVENTS {
            let n = self.events.len() - MAX_EVENTS;
            self.events.drain(..n);
        }
    }

    /// Убрать роутер с центра (переустановка, продан, выключен навсегда): его
    /// отчёты, место в сбоях и напоминания. Снова пришлёт отчёт — появится заново.
    pub fn forget(&mut self, name: &str, now: i64, why: &str) -> bool {
        if self.routers.remove(name).is_none() {
            return false;
        }
        for a in self.alerts.values_mut() {
            a.routers.remove(name);
        }
        self.alerts.retain(|_, a| !a.routers.is_empty());
        self.event(&format!("🗑 <b>{}</b> убран с центра ({})", esc(name), esc(why)), now);
        self.journal(&[("time", Self::q(&time_json(now))), ("router", Self::q(name)), ("event", Self::q("removed"))]);
        self.save();
        true
    }

    fn notify(&mut self, text: &str, now: i64) {
        self.event(text, now);
        for d in crate::livecfg::telegram_dests(&self.cfg) {
            let q = self.queues.entry(d).or_default();
            if q.len() < 100 {
                q.push(text.to_string());
            }
        }
    }

    /// Каждые 10 с: сопоставление, сохранение, Telegram, итоги отправки.
    pub fn tick(&mut self, now_mono: u64, poller: &Poller) {
        self.sweep(poller);
        self.collect_tg();
        if now_mono < self.next_eval {
            return;
        }
        self.next_eval = now_mono + 10_000;
        let now = now_ms();
        self.evaluate(now);
        self.nonces.retain(|_, t| now - *t <= 2 * MAX_SKEW * 1000);
        self.flush_tg();
        if now - self.saved_at >= 60_000 {
            self.saved_at = now;
            self.save();
        }
    }

    fn evaluate(&mut self, now: i64) {
        let cfg = self.cfg.clone();
        let stale = cfg.stale_sec * 1000;
        let mut fresh: BTreeMap<String, Report> = BTreeMap::new();
        let mut msgs = Vec::new();
        let mut jl: Vec<Vec<(&str, String)>> = Vec::new();
        let t = Self::q(&time_json(now));
        for (name, rt) in self.routers.iter_mut() {
            if now - rt.seen <= stale {
                fresh.insert(name.clone(), rt.last.clone());
                if rt.offline {
                    rt.offline = false;
                    if cfg.notify_offline {
                        msgs.push(format!("🟢 <b>{}</b> снова на связи (не было {})", esc(name), dur(now - rt.off_at)));
                    }
                    jl.push(vec![("time", t.clone()), ("router", Self::q(name)), ("event", Self::q("online"))]);
                }
            } else if !rt.offline && rt.seen != 0 {
                rt.offline = true;
                rt.off_at = rt.seen;
                if cfg.notify_offline {
                    msgs.push(format!("⚫ <b>{}</b> не на связи с {} (последнее состояние: {}, провайдер {})", esc(name), hhmm(rt.seen), esc(&rt.last.state), esc(&isp_of(&rt.last, name))));
                }
                jl.push(vec![("time", t.clone()), ("router", Self::q(name)), ("event", Self::q("offline"))]);
            }
        }
        for m in msgs {
            self.notify(&m, now);
        }
        for j in jl {
            self.journal(&j);
        }
        let gone: Vec<String> = self.routers.iter().filter(|(_, r)| r.offline && r.seen != 0 && now - r.seen > FORGET_AFTER).map(|(n, _)| n.clone()).collect();
        for n in gone {
            self.forget(&n, now, "не на связи 30 дней");
        }
        let mut isp_bad: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut bad: Vec<String> = Vec::new();
        for (name, r) in &fresh {
            if degraded(r) {
                bad.push(name.clone());
                isp_bad.entry(isp_of(r, name)).or_default().push(name.clone());
            }
        }
        let mut want: BTreeMap<String, Alert> = BTreeMap::new();
        let mk = |kind: &str, key: &str, routers: &[String], want: &mut BTreeMap<String, Alert>| {
            let mut a = Alert { kind: kind.into(), key: key.into(), min_v4: 100.0, ..Default::default() };
            for n in routers {
                let r = &fresh[n];
                a.routers.insert(n.clone());
                a.isps.insert(isp_of(r, n));
                if r.v4.n > 0 && r.v4.ok < a.min_v4 {
                    a.min_v4 = r.v4.ok;
                }
            }
            want.insert(format!("{kind}:{key}"), a);
        };
        if isp_bad.len() as i64 >= cfg.min_isps {
            mk("external", "all", &bad, &mut want);
        } else {
            for (isp, names) in &isp_bad {
                if names.len() >= 2 {
                    mk("isp", isp, names, &mut want);
                } else if cfg.notify_single {
                    mk("single", &names[0], names, &mut want);
                }
            }
        }
        // сервис не отвечает или медленный у ≥ 2 роутеров (любых провайдеров)
        let mut svc: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
        for (name, r) in &fresh {
            if !r.svc.is_empty() {
                for s in &r.svc {
                    svc.entry(s.name.clone()).or_default().push((name.clone(), s.state.clone(), s.fam.clone()));
                }
                continue;
            }
            for s in &r.services {
                svc.entry(s.clone()).or_default().push((name.clone(), "down".into(), String::new()));
            }
        }
        let mut views = Vec::new();
        for (s, hits) in &svc {
            if hits.len() < 2 {
                continue;
            }
            let mut names: Vec<String> = hits.iter().map(|x| x.0.clone()).collect();
            names.sort();
            let states: BTreeSet<&str> = hits.iter().map(|x| x.1.as_str()).collect();
            let fams: BTreeSet<&str> = hits.iter().map(|x| x.2.as_str()).collect();
            let mut detail = if states.contains("down") && states.contains("slow") {
                "не отвечает или отвечает медленно"
            } else if states.contains("slow") {
                "отвечает медленно"
            } else {
                "не отвечает"
            }
            .to_string();
            if fams.len() == 1 && !fams.contains("") {
                detail.push_str(&format!(" по {}", fams.iter().next().unwrap()));
            }
            mk("service", s, &names, &mut want);
            let w = want.get_mut(&format!("service:{s}")).unwrap();
            w.detail = detail.clone();
            let since = self.alerts.get(&format!("service:{s}")).map_or(now, |a| a.since);
            views.push(SvcView { name: s.clone(), detail, routers: names, isps: w.isps.iter().cloned().collect(), since });
        }
        self.svc_now = views;
        let clear = cfg.clear_sec * 1000;
        let total = fresh.len();
        for (id, mut w) in want.clone() {
            match self.alerts.get_mut(&id) {
                None => {
                    w.since = now;
                    w.last_bad = now;
                    let text = Self::open_text(&w, &fresh, total);
                    let mut rj = J::new();
                    rj.obj();
                    for n in &w.routers {
                        rj.key(n).bool(true);
                    }
                    rj.end_obj();
                    self.journal(&[("time", t.clone()), ("alert", Self::q("open")), ("kind", Self::q(&w.kind)), ("key", Self::q(&w.key)), ("routers", rj.b)]);
                    self.alerts.insert(id, w);
                    self.notify(&text, now);
                }
                Some(a) => {
                    a.last_bad = now;
                    a.routers.extend(w.routers);
                    a.isps.extend(w.isps);
                    a.min_v4 = a.min_v4.min(w.min_v4);
                }
            }
        }
        let external = self.alerts.contains_key("external:all");
        let gone: Vec<String> = self.alerts.iter().filter(|(id, a)| !want.contains_key(*id) && now - a.last_bad >= clear).map(|(id, _)| id.clone()).collect();
        for id in gone {
            let a = self.alerts.remove(&id).unwrap();
            // сбой провайдера, перешедший в общий, — без отдельного «восстановился»
            if external && (a.kind == "isp" || a.kind == "single") {
                continue;
            }
            let text = Self::close_text(&a);
            self.journal(&[("time", t.clone()), ("alert", Self::q("close")), ("kind", Self::q(&a.kind)), ("key", Self::q(&a.key)), ("dur_sec", ((a.last_bad - a.since) / 1000).to_string())]);
            self.notify(&text, now);
        }
    }

    fn open_text(a: &Alert, fresh: &BTreeMap<String, Report>, total: usize) -> String {
        let mut b = String::new();
        match a.kind.as_str() {
            "external" => b.push_str(&format!("🔴 <b>Общий сбой внешнего канала</b>\nНовые соединения не проходят у {} из {total} роутеров, провайдеры: {}.\nПохоже на сбой магистрали/внешнего канала, а не у отдельных роутеров.\n", a.routers.len(), set_list(&a.isps))),
            "isp" => b.push_str(&format!("🟠 <b>Сбой у провайдера {}</b>\nДеградация у {} роутеров этого провайдера, у остальных провайдеров всё в порядке.\n", esc(&a.key), a.routers.len())),
            "service" => {
                let d = if a.detail.is_empty() { "не отвечает" } else { &a.detail };
                b.push_str(&format!("🟡 <b>{} {}</b> у {} из {total} роутеров: {}; их WAN в норме.\n", esc(&a.key), esc(d), a.routers.len(), set_list(&a.routers)));
                if a.isps.len() >= 2 {
                    b.push_str(&format!("Провайдеры разные ({}) — похоже, сбой самого сервиса.", set_list(&a.isps)));
                } else {
                    b.push_str(&format!("Все у одного провайдера ({}) — похоже, проблема провайдера с этим сервисом.", set_list(&a.isps)));
                }
                return b;
            }
            "single" => b.push_str(&format!("🟠 <b>Сбой на роутере {}</b>\n", esc(&a.key))),
            _ => {}
        }
        for n in &a.routers {
            let Some(r) = fresh.get(n) else { continue };
            let mut line = format!("• <b>{}</b> ({}): ", esc(n), esc(&isp_of(r, n)));
            if !r.wan_up {
                line.push_str("WAN не работает");
            } else {
                line.push_str(&format!("пробы IPv4 {:.0}%", r.v4.ok));
                if r.v6.avail && r.v6.n > 0 {
                    line.push_str(&format!(", IPv6 {:.0}%", r.v6.ok));
                }
            }
            b.push_str(&line);
            b.push('\n');
        }
        b
    }

    fn close_text(a: &Alert) -> String {
        let d = dur(a.last_bad - a.since + 10_000);
        let span = format!("{}–{}", hhmm(a.since), hhmm(a.last_bad));
        match a.kind.as_str() {
            "external" => format!("🟢 <b>Внешний канал восстановлен</b>\nСбой длился {d} ({span}), затронуто роутеров: {}, провайдеров: {} ({}). Худшие пробы IPv4: {:.0}%.", a.routers.len(), a.isps.len(), set_list(&a.isps), a.min_v4),
            "isp" => format!("🟢 <b>Провайдер {} восстановился</b> — сбой {d} ({span}), роутеров: {}.", esc(&a.key), a.routers.len()),
            "service" => format!("🟢 <b>{}</b> снова отвечает — сбой {d} ({span}).", esc(&a.key)),
            _ => format!("🟢 <b>{}</b>: восстановилось — сбой {d} ({span}).", esc(&a.key)),
        }
    }

    // ---- Telegram ----

    fn flush_tg(&mut self) {
        let dests = crate::livecfg::telegram_dests(&self.cfg);
        self.queues.retain(|d, _| dests.contains(d)); // получателя убрали — его очередь не нужна
        self.tg_err.retain(|d, _| dests.contains(d));
        if self.tg_busy || crate::util::readonly() {
            return;
        }
        let work: Vec<((String, String), Vec<String>)> = self.queues.iter().filter(|(_, q)| !q.is_empty()).map(|(d, q)| (d.clone(), q.clone())).collect();
        if work.is_empty() {
            return;
        }
        self.tg_busy = true;
        let tx = self.tx.clone();
        let r = std::thread::Builder::new().name("cgmon-tg".into()).stack_size(256 << 10).spawn(move || {
            let mut out = Vec::new();
            for (d, q) in work {
                let mut sent = 0;
                let mut err = None;
                for text in q {
                    if let Err(e) = send_telegram(&d.0, &d.1, &text) {
                        err = Some(e);
                        break;
                    }
                    sent += 1;
                }
                out.push((d, sent, err));
            }
            let _ = tx.send(out);
        });
        if r.is_err() {
            self.tg_busy = false;
        }
    }

    fn collect_tg(&mut self) {
        while let Ok(res) = self.rx.try_recv() {
            self.tg_busy = false;
            for (d, sent, err) in res {
                if let Some(q) = self.queues.get_mut(&d) {
                    q.drain(..sent.min(q.len()));
                }
                self.sent_n += sent as i64;
                match err {
                    Some(e) => {
                        let msg = format!("{}: {e}", tg_label(&d.0, &d.1));
                        if self.tg_err.get(&d) != Some(&msg) {
                            crate::log_err!("hub: telegram {}", msg);
                        }
                        self.tg_err.insert(d, msg.clone());
                        self.last_tg = msg;
                    }
                    None if sent > 0 => {
                        self.tg_err.remove(&d);
                        if self.tg_err.is_empty() {
                            self.last_tg.clear();
                        }
                    }
                    None => {}
                }
            }
        }
    }

    /// Для страницы: роутеры, открытые сбои, журнал.
    pub fn status_json(&self, j: &mut J) {
        let g = crate::config::go_float;
        let n_tg = crate::livecfg::telegram_dests(&self.cfg).len();
        j.obj().key("listen").str(&self.cfg.listen).key("routers").arr();
        for (name, r) in &self.routers {
            let l = &r.last;
            j.obj().key("name").str(name).key("isp").str(&isp_of(l, name)).key("state").str(&l.state).key("diagnosis").str(&l.diagnosis).key("wan_up").bool(l.wan_up);
            j.key("v4").raw(&g(l.v4.ok)).key("v6").raw(&g(l.v6.ok)).key("has_v6").bool(l.v6.avail && l.v6.n > 0).key("seen").str(&time_json(r.seen)).key("offline").bool(r.offline).key("version").str(&l.version);
            let link = crate::dgtarget::sanitize_label(&l.link);
            if !link.is_empty() {
                j.key("link").str(&link);
            }
            if l.backup {
                j.key("backup").bool(true);
            }
            // для окна «о роутере»: адрес отчёта (ссылка на его страницу), внешний IP и AS
            if !r.from.is_empty() {
                j.key("from").str(&r.from);
            }
            if !l.isp.ip.is_empty() {
                j.key("isp_ip").str(&l.isp.ip);
            }
            if !l.isp.asn.is_empty() {
                j.key("asn").str(&l.isp.asn);
            }
            // уровень роутера (ok/warn/crit) и описания проблем — окно по нажатию на статус
            j.key("level").str(if r.offline { "crit" } else { l.level() });
            if !l.issues.is_empty() {
                j.key("issues").arr();
                for i in &l.issues {
                    j.obj().key("level").str(&i.level).key("text").str(&i.text).end_obj();
                }
                j.end_arr();
            }
            j.end_obj();
        }
        j.end_arr().key("open_alerts").int(self.alerts.len() as i64).key("events").arr();
        for (t, text) in self.events.iter().rev().take(50) {
            j.obj().key("time").str(&time_json(*t)).key("kind").str("").key("text").str(text).end_obj();
        }
        j.end_arr().key("telegram").bool(n_tg > 0).key("telegram_targets").int(n_tg as i64).key("telegram_sent").int(self.sent_n);
        if !self.last_tg.is_empty() {
            j.key("telegram_error").str(&self.last_tg);
        }
        if !self.svc_now.is_empty() {
            j.key("services").arr();
            for s in &self.svc_now {
                j.obj().key("name").str(&s.name).key("detail").str(&s.detail).key("routers").arr();
                for r in &s.routers {
                    j.str(r);
                }
                j.end_arr().key("isps").arr();
                for r in &s.isps {
                    j.str(r);
                }
                j.end_arr().key("since").str(&time_json(s.since)).end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Probe, Svc};

    fn rep(name: &str, isp: &str, state: &str, diag: &str) -> Report {
        Report { router: name.into(), state: state.into(), diagnosis: diag.into(), wan_up: true, isp: crate::report::Isp { name: isp.into(), ..Default::default() }, v4: Probe { ok: 40.0, n: 10, ..Default::default() }, ..Default::default() }
    }

    fn hub() -> Hub {
        let mut c = crate::config::defaults().hub;
        c.state_file = String::new();
        c.journal_file = String::new();
        c.token = "0123456789abcdef-token".into();
        Hub::new(c, 11 << 48)
    }

    #[test]
    fn external_and_service() {
        let mut h = hub();
        let t = 1_700_000_000_000;
        h.accept_report(rep("a", "ISP1", "WARNING", "IPV4_EXTERNAL_DEGRADATION"), t);
        h.accept_report(rep("b", "ISP2", "CRITICAL", "IPV4_EXTERNAL_DEGRADATION"), t);
        let mut c = rep("c", "ISP2", "NORMAL", "HEALTHY");
        c.svc = vec![Svc { name: "example.com".into(), state: "down".into(), fam: "IPv6".into() }];
        let mut d = rep("d", "ISP1", "NORMAL", "HEALTHY");
        d.svc = c.svc.clone();
        h.accept_report(c, t);
        h.accept_report(d, t);
        h.evaluate(t);
        let texts: Vec<&String> = h.events.iter().map(|e| &e.1).collect();
        assert!(texts.iter().any(|x| x.starts_with("🔴 <b>Общий сбой внешнего канала</b>\nНовые соединения не проходят у 2 из 4 роутеров, провайдеры: ISP1, ISP2.")), "{texts:?}");
        assert!(texts.iter().any(|x| x.starts_with("🟡 <b>example.com не отвечает по IPv6</b> у 2 из 4 роутеров: c, d")), "{texts:?}");
        // всё прошло — закрытие через clear_sec
        h.accept_report(rep("a", "ISP1", "NORMAL", "HEALTHY"), t + 10_000);
        h.accept_report(rep("b", "ISP2", "NORMAL", "HEALTHY"), t + 10_000);
        h.accept_report(rep("c", "ISP2", "NORMAL", "HEALTHY"), t + 10_000);
        h.accept_report(rep("d", "ISP1", "NORMAL", "HEALTHY"), t + 10_000);
        h.evaluate(t + 10_000 + h.cfg.clear_sec * 1000);
        assert!(h.events.iter().any(|e| e.1.starts_with("🟢 <b>Внешний канал восстановлен</b>")), "{:?}", h.events);
        assert!(h.alerts.is_empty());
    }

    #[test]
    fn issues_levels_and_forget() {
        use crate::report::Issue;
        let mut h = hub();
        let t = 1_700_000_000_000;
        h.accept_report(rep("g", "ISP1", "NORMAL", "HEALTHY"), t);
        let mut r = rep("g", "ISP1", "NORMAL", "HEALTHY");
        r.issues = vec![
            Issue { level: "warn".into(), kind: "phy_slow:eth0".into(), text: "Порт eth0: ошибки CRC".into() },
            Issue { level: "crit".into(), kind: "phy_drop:eth0".into(), text: "Порт eth0: 3 обрыв(ов) линка за час".into() },
        ];
        assert_eq!(r.level(), "crit");
        h.accept_report(r.clone(), t + 1000);
        // критичное — в очередь Telegram, предупреждение — только в журнал
        let tg: usize = h.queues.values().map(|q| q.len()).sum();
        assert!(h.events.iter().any(|e| e.1.starts_with("🔴 <b>g</b>: Порт eth0: 3 обрыв")), "{:?}", h.events);
        assert!(h.events.iter().any(|e| e.1.starts_with("🟡 <b>g</b>: Порт eth0: ошибки CRC")));
        assert_eq!(tg, crate::livecfg::telegram_dests(&h.cfg).len());
        // тот же отчёт ещё раз — ничего нового
        let n = h.events.len();
        h.accept_report(r, t + 2000);
        assert_eq!(h.events.len(), n);
        // прошло
        h.accept_report(rep("g", "ISP1", "NORMAL", "HEALTHY"), t + 3000);
        assert!(h.events.iter().filter(|e| e.1.starts_with("✅ <b>g</b>: прошло")).count() == 2, "{:?}", h.events);
        let mut j = crate::json::J::new();
        h.status_json(&mut j);
        assert!(j.b.contains("\"level\":\"ok\""), "{}", j.b);
        // убрать со страницы и автозабывание
        assert!(h.forget("g", t + 4000, "тест") && !h.routers.contains_key("g"));
        assert!(!h.forget("g", t + 4000, "тест"));
        h.accept_report(rep("old", "ISP1", "NORMAL", "HEALTHY"), t);
        h.evaluate(t + h.cfg.stale_sec * 1000 + 1000);
        h.evaluate(t + FORGET_AFTER + 1000);
        assert!(!h.routers.contains_key("old"));
    }

    #[test]
    fn sealed_report_accepted_once() {
        let mut h = hub();
        let r = rep("a", "ISP1", "NORMAL", "HEALTHY");
        let mut j = J::new();
        j.obj().key("ts").int(now_ms() / 1000).key("report");
        r.json(&mut j);
        j.end_obj();
        let b = crate::hubcrypt::seal(&h.cfg.token.clone(), j.b.as_bytes()).unwrap();
        assert_eq!(h.handle("POST", "/api/v1/report", &b, "192.0.2.1").0, 200);
        assert_eq!(h.handle("POST", "/api/v1/report", &b, "192.0.2.1").0, 403, "повтор");
        assert_eq!(h.handle("GET", "/api/state", &[], "192.0.2.1").0, 403);
        let req = b"POST /api/v1/report HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse_req(req).unwrap().unwrap().2, b"abc");
        assert!(parse_req(b"POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").is_err());
        assert!(parse_req(b"POST / HTTP/1.1\r\nContent-Le").unwrap().is_none());
    }
}
