//! DNS-страховка: действия с системой (перенос блокирующих частей dnsguard.go,
//! dgtarget.go, dgroute.go, dgv6.go). Всё за трейтом `Sys`: настоящий —
//! команды, файлы, DNS, пробы; в тестах — подделка. Долгое (перезапуск
//! SmartDNS, проверки владельцев, загрузка через путь) вызывается из рабочих
//! потоков страховки, быстрое (uci, nft, ip) — прямо в такте, как и в Go.
//! CGMON_READONLY: изменяющие действия не выполняются (считаются удачными).

use crate::dns;
use std::collections::{BTreeMap, HashMap};
use std::io::Read as _;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Публичные DNS по IPv4 (witResolvers): мимо местного DNS, где адреса могут быть запрещены.
pub const RESOLVERS: [&str; 3] = ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"];
const LOCAL_DNS: &str = "127.0.0.1:53";

/// Альтернатива для проверки владельца (dgrAlt): снимок пути.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Alt {
    pub id: String,
    pub label: String,
    pub dev: String,
    pub relay: bool,
    pub idx: u32,
    pub mark: u32,
    pub up: bool,
    pub why: String,
}

/// uid проверок через ретранслятор (uid+N → таблица пути N).
pub const UID_BASE: u32 = 61000;

pub trait Sys: Send + Sync {
    /// Команда, меняющая систему (uci set, restart, ip rule add…).
    fn run(&self, args: &[&str]) -> Result<String, String>;
    /// Команда только для чтения (uci get/show, ip … show, pidof).
    fn query(&self, args: &[&str]) -> Result<String, String>;
    fn read_file(&self, path: &str) -> Option<String>;
    fn write_file(&self, path: &str, data: &str, mode: u32) -> Result<(), String>;
    fn remove_file(&self, path: &str);
    fn nft(&self, script: &str) -> Result<(), String>;
    /// Добавить IPv4-адреса в набор inet-таблицы с таймаутом (обход: адреса из DNS-ответов).
    fn set_add4(&self, table: &str, set: &str, ips: &[std::net::Ipv4Addr], timeout_s: u64) -> Result<(), String> {
        let l: Vec<String> = ips.iter().map(|ip| format!("{ip} timeout {timeout_s}s")).collect();
        self.nft(&format!("add element inet {table} {set} {{ {} }}\n", l.join(", ")))
    }
    /// Именованные счётчики таблицы nft (байты).
    fn counters(&self, table: &str) -> HashMap<String, u64>;
    /// n подключений tcp/443 по кругу к адресам (метка — путь обхода): ответивших и медиана, мс.
    fn probe(&self, ips: &[IpAddr], n: usize, mark: u32, v6src: Option<IpAddr>) -> (usize, f64);
    /// Адреса имени нужного протокола через публичные DNS.
    fn resolve(&self, name: &str, fam: &str) -> Vec<IpAddr>;
    /// Загрузка через путь (dgrBulk): годен ли и сколько КБ прочитано (-1 — не проверялся).
    fn bulk(&self, name: &str, ip: &IpAddr, a: &Alt) -> (bool, i64);
    /// Как местный DNS отвечает на деле (dgLiveState): dns64 | no_aaaa | normal | "".
    fn live_state(&self) -> String;
    /// Местный DNS всё ещё отдаёт запрещённый тип записи домена (dgtLeaks).
    fn leaks(&self, domain: &str, fam: &str) -> bool;
    fn sleep(&self, ms: u64);
}

pub struct RealSys;

fn exec(args: &[&str]) -> Result<String, String> {
    let o = Command::new(args[0]).args(&args[1..]).stdin(Stdio::null()).output().map_err(|e| format!("{}: {} ", args.join(" "), e))?;
    let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&o.stderr));
    if !o.status.success() {
        let st = match o.status.code() {
            Some(c) => format!("exit status {c}"),
            None => "signal".to_string(),
        };
        return Err(format!("{}: {} {}", args.join(" "), st, out.trim()));
    }
    Ok(out.trim().to_string())
}

/// Итог одного DNS-запроса: адреса, «нет такого» (NXDOMAIN / пустой ответ) или сбой.
pub enum Res {
    Ips(Vec<IpAddr>),
    NotFound,
    Fail,
}

/// Блокирующий DNS-запрос (рабочий поток страховки).
pub fn dns_query(server: &str, name: &str, qtype: u16, timeout_ms: u64) -> Res {
    let Ok(srv) = server.parse::<SocketAddr>() else { return Res::Fail };
    let bind = if srv.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(s) = UdpSocket::bind(bind) else { return Res::Fail };
    if s.connect(srv).is_err() {
        return Res::Fail;
    }
    let mut seed = [0u8; 2];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut seed);
    }
    let id = u16::from_be_bytes(seed);
    if s.send(&dns::build_query(id, name, qtype)).is_err() {
        return Res::Fail;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            return Res::Fail;
        }
        let Ok(n) = s.recv(&mut buf) else { return Res::Fail };
        let Some((rid, a)) = dns::parse(&buf[..n]) else { continue };
        if rid != id {
            continue;
        }
        let want6 = qtype == dns::TYPE_AAAA;
        let ips: Vec<IpAddr> = a.ips.into_iter().filter(|ip| ip.is_ipv6() == want6).collect();
        return match a.rcode {
            0 if !ips.is_empty() => Res::Ips(ips),
            0 | 3 => Res::NotFound,
            _ => Res::Fail,
        };
    }
}

/// Адреса имени через публичные DNS: первый ответивший; «нет такого» — другие не спрашиваем.
pub fn resolve_public(name: &str, fam: &str) -> Vec<IpAddr> {
    let qt = if fam == "ipv6" { dns::TYPE_AAAA } else { dns::TYPE_A };
    for srv in RESOLVERS {
        match dns_query(srv, name, qt, 3000) {
            Res::Ips(v) => return v,
            Res::NotFound => return Vec::new(),
            Res::Fail => {}
        }
    }
    Vec::new()
}

/// Сокет tcp/443 к адресу (неблокирующий connect).
fn dial(ip: &IpAddr, mark: u32, src: Option<IpAddr>) -> Option<i32> {
    let fam = if ip.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(fam, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let fail = |fd: i32| {
        unsafe { libc::close(fd) };
        None
    };
    if mark != 0 {
        let m = mark as i32;
        if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &m as *const i32 as *const libc::c_void, 4) } < 0 {
            return fail(fd);
        }
    }
    if let Some(s) = src.filter(|s| s.is_ipv6() == ip.is_ipv6()) {
        let (sa, l) = crate::netx::sockaddr_of(&s, 0);
        if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
            return fail(fd);
        }
    }
    let (sa, l) = crate::netx::sockaddr_of(ip, 443);
    if unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, l) } < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e != libc::EINPROGRESS {
            return fail(fd);
        }
    }
    crate::probe::mark_service(fd, 6, std::net::SocketAddr::new(*ip, 443));
    Some(fd)
}

/// n подключений сразу, ждать до timeout: ответившие (и RST — путь жив) и медиана.
pub fn probe_many(ips: &[IpAddr], n: usize, mark: u32, v6src: Option<IpAddr>, timeout_ms: u64) -> (usize, f64) {
    if ips.is_empty() || n == 0 {
        return (0, 0.0);
    }
    let t0 = Instant::now();
    let mut socks: Vec<i32> = Vec::new();
    for i in 0..n {
        if let Some(fd) = dial(&ips[i % ips.len()], mark, v6src) {
            socks.push(fd);
        }
    }
    let mut ms: Vec<f64> = Vec::new();
    let mut open = socks.clone();
    while !open.is_empty() {
        let left = Duration::from_millis(timeout_ms).saturating_sub(t0.elapsed());
        if left.is_zero() {
            break;
        }
        let mut pf: Vec<libc::pollfd> = open.iter().map(|&fd| libc::pollfd { fd, events: libc::POLLOUT, revents: 0 }).collect();
        let r = unsafe { libc::poll(pf.as_mut_ptr(), pf.len() as libc::nfds_t, left.as_millis().max(1) as i32) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let at = t0.elapsed().as_micros() as f64 / 1000.0;
        for p in &pf {
            if p.revents == 0 {
                continue;
            }
            let mut err: i32 = 0;
            let mut l = 4u32;
            unsafe { libc::getsockopt(p.fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut i32 as *mut libc::c_void, &mut l) };
            if err == 0 || err == libc::ECONNREFUSED {
                ms.push(at);
            }
            open.retain(|&x| x != p.fd);
        }
    }
    for fd in socks {
        unsafe { libc::close(fd) };
    }
    (ms.len(), median(&ms))
}

/// Медиана как в Go: s[len/2] отсортированного.
pub fn median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s[s.len() / 2]
}

/// Сколько скачать через путь, чтобы счесть его годным, КБ.
pub const BULK_KB: usize = 64;

/// Загрузка через путь (curl --interface или от uid пути для ретранслятора).
fn bulk(name: &str, ip: &IpAddr, a: &Alt) -> (bool, i64) {
    let dev = if a.dev.is_empty() { &a.id } else { &a.dev };
    if !crate::livecfg::domain_ok(name) || !crate::livecfg::path_id_ok(dev) {
        return (true, -1);
    }
    if !crate::variant::EXT || !std::path::Path::new(&format!("/sys/class/net/{dev}")).exists() || !crate::util::have_bin("curl") {
        return (true, -1);
    }
    let host = if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() };
    let mut cmd = Command::new("curl");
    if !a.relay {
        cmd.args(["--interface", dev]);
    }
    cmd.args(["-s", "-k", "--resolve", &format!("{name}:443:{host}"), "--connect-timeout", "4", "-m", "10", "-o", "-", &format!("https://{name}/")]);
    if a.relay {
        use std::os::unix::process::CommandExt;
        cmd.uid(UID_BASE + a.idx).gid(65534);
    }
    let Ok(mut ch) = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else { return (true, -1) };
    let mut out = ch.stdout.take().unwrap();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut n = 0usize;
    let mut buf = [0u8; 8192];
    let mut timed_out = false;
    while n < BULK_KB * 1024 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            timed_out = true;
            break;
        }
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let r = unsafe { libc::poll(&mut p, 1, left.as_millis().max(1) as i32) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if r <= 0 {
            timed_out = r == 0;
            break;
        }
        match out.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    if n >= BULK_KB * 1024 || timed_out {
        let _ = ch.kill();
        let _ = ch.wait();
        return (n >= BULK_KB * 1024, (n / 1024) as i64);
    }
    drop(out);
    let ok = ch.wait().map(|s| s.success()).unwrap_or(false);
    (ok, (n / 1024) as i64)
}

impl Sys for RealSys {
    fn run(&self, args: &[&str]) -> Result<String, String> {
        if crate::util::readonly() {
            crate::log_debug!("readonly: {}", args.join(" "));
            return Ok(String::new());
        }
        exec(args)
    }
    fn query(&self, args: &[&str]) -> Result<String, String> {
        exec(args)
    }
    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read(path).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
    }
    fn write_file(&self, path: &str, data: &str, mode: u32) -> Result<(), String> {
        if crate::util::readonly() {
            return Ok(());
        }
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path).map_err(|e| format!("open {path}: {e}"))?;
        f.write_all(data.as_bytes()).map_err(|e| format!("write {path}: {e}"))
    }
    fn remove_file(&self, path: &str) {
        if !crate::util::readonly() {
            let _ = std::fs::remove_file(path);
        }
    }
    fn nft(&self, script: &str) -> Result<(), String> {
        crate::acct::nft_script(script).map_err(|e| format!("nft: {e}"))
    }
    fn set_add4(&self, table: &str, set: &str, ips: &[std::net::Ipv4Addr], timeout_s: u64) -> Result<(), String> {
        if crate::util::readonly() || ips.is_empty() {
            return Ok(());
        }
        // netlink — без запуска nft (адрес должен успеть в набор до первого SYN клиента)
        let keys: Vec<[u8; 4]> = ips.iter().map(|ip| ip.octets()).collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| &k[..]).collect();
        crate::nfnl::set_add(table, set, &refs, timeout_s * 1000).map_err(|e| format!("netlink {set}: {e}"))
    }
    fn counters(&self, table: &str) -> HashMap<String, u64> {
        let mut m = HashMap::new();
        let mut buf = Vec::new();
        let _ = crate::nfnl::named_counters(table, &mut buf, |n, b| {
            m.insert(n.to_string(), b);
        });
        m
    }
    fn probe(&self, ips: &[IpAddr], n: usize, mark: u32, v6src: Option<IpAddr>) -> (usize, f64) {
        probe_many(ips, n, mark, v6src, 3000)
    }
    fn resolve(&self, name: &str, fam: &str) -> Vec<IpAddr> {
        resolve_public(name, fam)
    }
    fn bulk(&self, name: &str, ip: &IpAddr, a: &Alt) -> (bool, i64) {
        bulk(name, ip, a)
    }
    fn live_state(&self) -> String {
        if let Res::Ips(_) = dns_query(LOCAL_DNS, "ipv4only.arpa", dns::TYPE_AAAA, 2000) {
            return "dns64".into();
        }
        match dns_query(LOCAL_DNS, "dns.google", dns::TYPE_A, 2000) {
            Res::Ips(_) => {}
            _ => return String::new(),
        }
        match dns_query(LOCAL_DNS, "dns.google", dns::TYPE_AAAA, 2000) {
            Res::Ips(_) => "normal".into(),
            _ => "no_aaaa".into(),
        }
    }
    fn leaks(&self, domain: &str, fam: &str) -> bool {
        let qt = if fam == "ipv4" { dns::TYPE_A } else { dns::TYPE_AAAA };
        for _ in 0..5 {
            match dns_query(LOCAL_DNS, domain, qt, 3000) {
                Res::Ips(_) => return true,
                Res::NotFound => return false,
                Res::Fail => std::thread::sleep(Duration::from_secs(1)), // SmartDNS ещё стартует
            }
        }
        false
    }
    fn sleep(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Какие файлы включены в конфиг SmartDNS (строки conf-file).
pub fn includes(sys: &dyn Sys) -> Vec<String> {
    let mut l = Vec::new();
    for f in ["/etc/smartdns/custom.conf", "/var/etc/smartdns/smartdns.conf"] {
        for ln in sys.read_file(f).unwrap_or_default().lines() {
            let mut w = ln.split_whitespace();
            if w.next() == Some("conf-file") {
                if let Some(p) = w.next() {
                    l.push(p.trim_matches(['\'', '"']).to_string());
                }
            }
        }
    }
    l
}

/// ra_lifetime секций dhcp с ra=server из «uci -q show dhcp».
pub fn ra_parse(out: &str) -> BTreeMap<String, String> {
    let mut server: Vec<(String, bool)> = Vec::new();
    let mut life: HashMap<String, String> = HashMap::new();
    for ln in out.lines() {
        let Some(rest) = ln.strip_prefix("dhcp.") else { continue };
        let Some((sec, rest)) = rest.split_once('.') else { continue };
        if sec.is_empty() || !sec.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            continue;
        }
        let Some((opt, val)) = rest.split_once('=') else { continue };
        if opt != "ra" && opt != "ra_lifetime" {
            continue;
        }
        let Some(v) = val.strip_prefix('\'').and_then(|v| v.split_once('\'')).map(|x| x.0) else { continue };
        if opt == "ra" {
            server.retain(|(s, _)| s != sec);
            server.push((sec.to_string(), v == "server"));
        } else {
            life.insert(sec.to_string(), v.to_string());
        }
    }
    let mut res = BTreeMap::new();
    for (sec, on) in server {
        if on {
            let l = life.get(&sec).cloned().unwrap_or_default();
            res.insert(sec, l);
        }
    }
    res
}

pub fn ra_read(sys: &dyn Sys) -> BTreeMap<String, String> {
    sys.query(&["uci", "-q", "show", "dhcp"]).map(|o| ra_parse(&o)).unwrap_or_default()
}
