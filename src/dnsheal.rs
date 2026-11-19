//! Самолечение DNS роутера: зависший SmartDNS / AdGuard Home / dnsmasq перезапускается.
//!
//! Раз в минуту — запрос к dnsmasq (127.0.0.1:53) случайного несуществующего имени: ответ
//! «нет такого» не берётся из кеша, значит, цепочка до вышестоящих серверов жива. Сбой
//! (таймаут, SERVFAIL, REFUSED) — проверки чаще; три подряд при живом интернете (публичные
//! DNS отвечают напрямую) — виновник ищется так: локальные вышестоящие dnsmasq
//! (`server=127.0.0.1#5399` — SmartDNS, AdGuard Home…) спрашиваются напрямую, служба на
//! порту — по сокету в /proc. Не отвечает служба — перезапуск её init-скрипта; служба
//! отвечает, а dnsmasq нет — перезапуск dnsmasq. Нет интернета — ничего не делается.
//! Не чаще раза в 15 минут и не больше 4 перезапусков за сутки; дальше — только журнал.

use crate::dns;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

const LOCAL: &str = "127.0.0.1:53";
const EVERY_MS: u64 = 60_000;
const RETRY_MS: u64 = 20_000;
const FAILS: u32 = 3;
const GAP_MS: u64 = 15 * 60_000;
const DAY_MAX: usize = 4;
/// после загрузки роутера DNS поднимается не сразу
const BOOT_SEC: f64 = 300.0;

#[derive(Clone, Debug, PartialEq)]
pub enum R {
    Ok,
    Timeout,
    Rcode(u8),
}

impl R {
    fn ok(&self) -> bool {
        *self == R::Ok
    }
    fn text(&self) -> String {
        match self {
            R::Ok => "ok".into(),
            R::Timeout => tr!("нет ответа").to_string(),
            R::Rcode(2) => "SERVFAIL".into(),
            R::Rcode(5) => "REFUSED".into(),
            R::Rcode(c) => format!("rcode {c}"),
        }
    }
}

/// Один запрос: ответил ли сервер по существу (адреса или «нет такого»).
pub fn ask(server: &str, name: &str, timeout_ms: u64) -> R {
    let Ok(srv) = server.parse::<SocketAddr>() else { return R::Timeout };
    let Ok(s) = UdpSocket::bind(if srv.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) else { return R::Timeout };
    if s.connect(srv).is_err() {
        return R::Timeout;
    }
    let id = (rand() & 0xffff) as u16;
    if s.send(&dns::build_query(id, name, dns::TYPE_A)).is_err() {
        return R::Timeout;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            return R::Timeout;
        }
        let Ok(n) = s.recv(&mut buf) else { return R::Timeout };
        let Some((rid, a)) = dns::parse(&buf[..n]) else { continue };
        if rid != id {
            continue;
        }
        return if matches!(a.rcode, 0 | 3) { R::Ok } else { R::Rcode(a.rcode) };
    }
}

fn rand() -> u64 {
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    u64::from_le_bytes(b)
}

/// Имя, которого нет и не может быть в кеше.
fn probe_name() -> String {
    format!("cgmon-{:012x}.example.com", rand() & 0xffff_ffff_ffff)
}

/// Локальные вышестоящие dnsmasq: `127.0.0.1#5399`, `::1#5300` (без /домен/).
pub fn local_upstreams(servers: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for s in servers {
        let s = s.trim();
        if s.starts_with('/') {
            continue;
        }
        let Some((ip, port)) = s.split_once('#') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        let addr = match ip {
            "127.0.0.1" => format!("127.0.0.1:{port}"),
            "::1" => format!("[::1]:{port}"),
            _ => continue,
        };
        if port != 53 && !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Процесс, слушающий UDP-порт: имя из /proc/PID/comm.
fn listener(port: u16) -> Option<String> {
    let want = format!(":{port:04X}");
    let mut inodes = Vec::new();
    for f in ["/proc/net/udp", "/proc/net/udp6"] {
        let t = std::fs::read_to_string(f).unwrap_or_default();
        for l in t.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() > 9 && c[1].ends_with(&want) && c[9] != "0" {
                inodes.push(format!("socket:[{}]", c[9]));
            }
        }
    }
    if inodes.is_empty() {
        return None;
    }
    for p in std::fs::read_dir("/proc").ok()?.flatten() {
        let pid = p.file_name().to_string_lossy().to_string();
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if let Ok(l) = std::fs::read_link(fd.path()) {
                if inodes.iter().any(|i| l.to_string_lossy() == *i) {
                    return std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string());
                }
            }
        }
    }
    None
}

/// init-скрипт службы по имени процесса (AdGuardHome → adguardhome).
pub fn init_script(comm: &str, scripts: &[String]) -> Option<String> {
    let c = comm.to_ascii_lowercase();
    scripts.iter().find(|s| s.to_ascii_lowercase() == c).or_else(|| scripts.iter().find(|s| s.len() >= 5 && c.starts_with(&s.to_ascii_lowercase()))).cloned()
}

fn scripts() -> Vec<String> {
    std::fs::read_dir("/etc/init.d").map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default()
}

fn uci_servers() -> Vec<String> {
    crate::flowwatch::output_timeout("uci", &["-q", "get", "dhcp.@dnsmasq[0].server"], 3000).map(|t| t.split_whitespace().map(String::from).collect()).unwrap_or_default()
}

fn boot_age() -> f64 {
    std::fs::read_to_string("/proc/uptime").ok().and_then(|t| t.split_whitespace().next().and_then(|x| x.parse().ok())).unwrap_or(0.0)
}

/// Что делать по итогам проверки.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// перезапустить: (что не отвечает, почему, init-скрипт)
    Restart(String, String, String),
    /// вышестоящий DNS не отвечает, а перезапускать нечего
    Nothing(String, String),
}

/// Решение (чистая функция для тестов): ответ dnsmasq, ответы локальных вышестоящих
/// (адрес, ответ, служба), есть ли dnsmasq-скрипт.
pub fn decide(local: &R, ups: &[(String, R, Option<String>)], has_dnsmasq: bool) -> Option<Verdict> {
    if local.ok() {
        return None;
    }
    if let Some((addr, r, svc)) = ups.iter().find(|(_, r, _)| !r.ok()) {
        let what = format!("{} {addr}", svc.clone().unwrap_or_else(|| "DNS".into()));
        return Some(match svc {
            Some(s) => Verdict::Restart(what, r.text(), s.clone()),
            None => Verdict::Nothing(what, r.text()),
        });
    }
    // вышестоящие (свои) живы или их нет: виноват dnsmasq — если молчит совсем
    // или если отвечают свои вышестоящие; SERVFAIL без своих — сервер провайдера
    if has_dnsmasq && (*local == R::Timeout || !ups.is_empty()) {
        return Some(Verdict::Restart(format!("dnsmasq {LOCAL}"), local.text(), "dnsmasq".into()));
    }
    Some(Verdict::Nothing(format!("dnsmasq {LOCAL}"), local.text()))
}

struct Probe {
    local: R,
    ups: Vec<(String, R, Option<String>)>,
    net: bool,
}

fn probe(deep: bool) -> Probe {
    let local = ask(LOCAL, &probe_name(), 4000);
    if !deep {
        return Probe { local, ups: Vec::new(), net: true };
    }
    let sc = scripts();
    let ups = local_upstreams(&uci_servers())
        .into_iter()
        .map(|a| {
            let r = ask(&a, &probe_name(), 4000);
            let port = a.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
            let svc = listener(port).and_then(|c| init_script(&c, &sc));
            (a, r, svc)
        })
        .collect();
    let net = crate::dgsys::RESOLVERS.iter().any(|s| ask(s, &probe_name(), 3000).ok());
    Probe { local, ups, net }
}

/// `cgmon dns-check`: полная проверка и решение, без перезапуска.
pub fn report() -> String {
    let p = probe(true);
    let mut o = format!("dnsmasq {LOCAL}: {}\n", p.local.text());
    for (a, r, svc) in &p.ups {
        o.push_str(&format!("{a}: {} ({})\n", r.text(), svc.as_deref().unwrap_or("?")));
    }
    o.push_str(&format!("public DNS: {}\n", if p.net { "ok" } else { "-" }));
    let v = if p.local.ok() || !p.net { None } else { decide(&p.local, &p.ups, std::path::Path::new("/etc/init.d/dnsmasq").exists()) };
    o.push_str(&match v {
        None => "verdict: ok\n".to_string(),
        Some(Verdict::Restart(w, why, svc)) => format!("verdict: {w} ({why}) -> restart {svc}\n"),
        Some(Verdict::Nothing(w, why)) => format!("verdict: {w} ({why}), nothing to restart\n"),
    });
    o
}

#[derive(Default)]
pub struct DnsHeal {
    busy: Option<Receiver<Probe>>,
    restarting: Option<Receiver<(String, Result<(), String>)>>,
    next: u64,
    fails: u32,
    /// перезапуски (мс) за последние сутки
    done: Vec<u64>,
    /// перезапускали и ждём, что заработает
    healed: Option<String>,
    /// уже сказали «не помогло / нечего перезапускать» — до выздоровления молчим
    told: bool,
}

impl DnsHeal {
    /// mode: off | observe | active.
    pub fn tick(&mut self, now: u64, mode: &str) -> Vec<String> {
        let mut msgs = Vec::new();
        if mode == "off" || crate::util::readonly() {
            return msgs;
        }
        if let Some(rx) = &self.restarting {
            match rx.try_recv() {
                Ok((svc, r)) => {
                    self.restarting = None;
                    if let Err(e) = r {
                        msgs.push(tr!("DNS: не удалось перезапустить {}: {}", svc, e));
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return msgs,
                Err(_) => self.restarting = None,
            }
        }
        if let Some(rx) = &self.busy {
            match rx.try_recv() {
                Ok(p) => {
                    self.busy = None;
                    self.judge(now, mode, p, &mut msgs);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(_) => self.busy = None,
            }
            return msgs;
        }
        if now < self.next || boot_age() < BOOT_SEC {
            return msgs;
        }
        // подробно (вышестоящие, интернет) — только на третьей неудаче подряд
        let deep = self.fails + 1 >= FAILS;
        let (tx, rx) = std::sync::mpsc::channel();
        if std::thread::Builder::new()
            .name("dnsheal".into())
            .spawn(move || {
                let _ = tx.send(probe(deep));
            })
            .is_ok()
        {
            self.busy = Some(rx);
        }
        self.next = now + EVERY_MS;
        msgs
    }

    fn judge(&mut self, now: u64, mode: &str, p: Probe, msgs: &mut Vec<String>) {
        if p.local.ok() {
            if let Some(svc) = self.healed.take() {
                msgs.push(tr!("DNS: после перезапуска {} снова работает", svc));
            }
            self.fails = 0;
            self.told = false;
            return;
        }
        self.fails += 1;
        self.next = now + RETRY_MS;
        if self.fails < FAILS {
            return;
        }
        if !p.net {
            // нет интернета — DNS тут ни при чём
            self.fails = FAILS - 1;
            self.next = now + EVERY_MS;
            return;
        }
        let has_dnsmasq = std::path::Path::new("/etc/init.d/dnsmasq").exists();
        let Some(v) = decide(&p.local, &p.ups, has_dnsmasq) else { return };
        self.done.retain(|t| now.saturating_sub(*t) < 86_400_000);
        match v {
            Verdict::Restart(what, why, svc) => {
                let last = self.done.last().copied().unwrap_or(0);
                if mode != "active" {
                    if !self.told {
                        msgs.push(tr!("DNS: {} не отвечает ({}), интернет есть — нужен перезапуск {} (режим наблюдения)", what, why, svc));
                        self.told = true;
                    }
                } else if self.done.len() >= DAY_MAX {
                    if !self.told {
                        msgs.push(tr!("DNS: {} не отвечает ({}), перезапуски за сутки исчерпаны — только журнал", what, why));
                        self.told = true;
                    }
                } else if last == 0 || now.saturating_sub(last) >= GAP_MS {
                    msgs.push(tr!("DNS: {} не отвечает ({}), интернет есть — перезапускаю {}", what, why, svc));
                    self.done.push(now);
                    self.healed = Some(svc.clone());
                    self.fails = 0;
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.restarting = Some(rx);
                    let _ = std::thread::Builder::new().name("dnsheal-restart".into()).spawn(move || {
                        let r = crate::flowwatch::output_timeout(&format!("/etc/init.d/{svc}"), &["restart"], 60_000).map(|_| ()).ok_or_else(|| tr!("ошибка или таймаут").to_string());
                        let _ = tx.send((svc, r));
                    });
                    // проверить вскоре после перезапуска
                    self.next = now + RETRY_MS;
                }
            }
            Verdict::Nothing(what, why) => {
                if !self.told {
                    msgs.push(tr!("DNS: {} не отвечает ({}), а интернет есть; своей службы для перезапуска нет", what, why));
                    self.told = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_and_scripts() {
        let s: Vec<String> = ["/zzz/100.100.100.100", "/zt/10.147.17.5", "127.0.0.1#5399", "::1#5300", "8.8.8.8", "127.0.0.1#53"].iter().map(|x| x.to_string()).collect();
        assert_eq!(local_upstreams(&s), vec!["127.0.0.1:5399".to_string(), "[::1]:5300".to_string()]);
        let sc: Vec<String> = ["adguardhome", "smartdns", "dnsmasq", "https-dns-proxy"].iter().map(|x| x.to_string()).collect();
        assert_eq!(init_script("AdGuardHome", &sc).as_deref(), Some("adguardhome"));
        assert_eq!(init_script("smartdns", &sc).as_deref(), Some("smartdns"));
        assert_eq!(init_script("https-dns-prox", &sc), None);
        assert_eq!(init_script("dockerd", &sc), None);
    }

    #[test]
    fn verdicts() {
        let up = |r: R, s: Option<&str>| vec![("127.0.0.1:5399".to_string(), r, s.map(String::from))];
        assert_eq!(decide(&R::Ok, &[], true), None);
        // SmartDNS отдаёт SERVFAIL — перезапуск smartdns
        assert!(matches!(decide(&R::Rcode(2), &up(R::Rcode(2), Some("smartdns")), true), Some(Verdict::Restart(_, _, s)) if s == "smartdns"));
        // SmartDNS жив, dnsmasq нет — dnsmasq
        assert!(matches!(decide(&R::Timeout, &up(R::Ok, Some("smartdns")), true), Some(Verdict::Restart(_, _, s)) if s == "dnsmasq"));
        // служба в контейнере (нет init-скрипта) — только журнал
        assert!(matches!(decide(&R::Rcode(2), &up(R::Timeout, None), true), Some(Verdict::Nothing(..))));
        // без своих вышестоящих: SERVFAIL — сервер провайдера, молчание — dnsmasq
        assert!(matches!(decide(&R::Rcode(2), &[], true), Some(Verdict::Nothing(..))));
        assert!(matches!(decide(&R::Timeout, &[], true), Some(Verdict::Restart(_, _, s)) if s == "dnsmasq"));
    }
}
