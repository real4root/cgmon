//! Отчёты на центр сбора (перенос report.go): состояние WAN, пробы, открытые
//! инциденты, сбои down detector, свой провайдер (AS внешнего IP), канал
//! (переключатель шлюзов), напоминания. Раз в interval_sec и сразу при смене
//! ключа «что изменилось». Отправка — в рабочем потоке (медленный центр не
//! тормозит демон); формат шифрования — hubcrypt.rs (как в Go).

use crate::config::ReportConfig;
use crate::json::J;
use crate::value::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct Probe {
    pub ok: f64,
    pub ms: f64,
    pub n: i64,
    pub avail: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Isp {
    pub ip: String,
    pub asn: String,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct Svc {
    pub name: String,
    pub state: String,
    pub fam: String,
}

#[derive(Clone, Debug, Default)]
pub struct Inc {
    pub id: i64,
    pub typ: String,
    pub open: bool,
    pub start: String,
    pub end: String,
    pub dur: i64,
    pub text: String,
}

/// Проблема роутера для центра: уровень (warn | crit), вид (ключ), текст для людей.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Issue {
    pub level: String,
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub router: String,
    pub version: String,
    pub time: String,
    pub isp: Isp,
    pub state: String,
    pub diagnosis: String,
    pub wan_up: bool,
    pub v4: Probe,
    pub v6: Probe,
    pub services: Vec<String>,
    pub svc: Vec<Svc>,
    pub incidents: Vec<Inc>,
    pub notices: Vec<crate::payment::Notice>,
    pub link: String,
    pub backup: bool,
    /// текущие проблемы (порты, канал, DNS-страховка, нагрузка…) — статус на центре
    pub issues: Vec<Issue>,
}

fn vs(v: &Value, k: &str) -> String {
    crate::dnsguard::vstr(v, k)
}

fn vf(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn vb(v: &Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn list<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    match v.get(k) {
        Some(Value::List(l)) => l,
        _ => &[],
    }
}

impl Probe {
    fn json(&self, j: &mut J) {
        let g = crate::config::go_float;
        j.obj().key("ok").raw(&g(self.ok)).key("ms").raw(&g(self.ms)).key("n").int(self.n).key("avail").bool(self.avail).end_obj();
    }
    fn from(v: Option<&Value>) -> Probe {
        let Some(v) = v else { return Probe::default() };
        Probe { ok: vf(v, "ok"), ms: vf(v, "ms"), n: vf(v, "n") as i64, avail: vb(v, "avail") }
    }
}

impl Report {
    pub fn json(&self, j: &mut J) {
        j.obj().key("router").str(&self.router).key("version").str(&self.version).key("time").str(&self.time);
        j.key("isp").obj();
        for (k, v) in [("ip", &self.isp.ip), ("asn", &self.isp.asn), ("name", &self.isp.name)] {
            if !v.is_empty() {
                j.key(k).str(v);
            }
        }
        j.end_obj();
        j.key("state").str(&self.state).key("diagnosis").str(&self.diagnosis).key("wan_up").bool(self.wan_up);
        j.key("v4");
        self.v4.json(j);
        j.key("v6");
        self.v6.json(j);
        if !self.services.is_empty() {
            j.key("services").arr();
            for s in &self.services {
                j.str(s);
            }
            j.end_arr();
        }
        if !self.svc.is_empty() {
            j.key("svc").arr();
            for s in &self.svc {
                j.obj().key("name").str(&s.name).key("state").str(&s.state);
                if !s.fam.is_empty() {
                    j.key("fam").str(&s.fam);
                }
                j.end_obj();
            }
            j.end_arr();
        }
        if !self.incidents.is_empty() {
            j.key("incidents").arr();
            for i in &self.incidents {
                j.obj().key("id").int(i.id).key("type").str(&i.typ).key("open").bool(i.open).key("start").str(&i.start).key("end").str(&i.end);
                if i.dur != 0 {
                    j.key("dur").int(i.dur);
                }
                if !i.text.is_empty() {
                    j.key("text").str(&i.text);
                }
                j.end_obj();
            }
            j.end_arr();
        }
        if !self.notices.is_empty() {
            j.key("notices").arr();
            for n in &self.notices {
                j.obj().key("key").str(&n.key).key("text").str(&n.text).end_obj();
            }
            j.end_arr();
        }
        if !self.link.is_empty() {
            j.key("link").str(&self.link);
        }
        if self.backup {
            j.key("backup").bool(true);
        }
        if !self.issues.is_empty() {
            j.key("issues").arr();
            for i in &self.issues {
                j.obj().key("level").str(&i.level).key("kind").str(&i.kind).key("text").str(&i.text).end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
    }

    /// Уровень роутера: crit | warn | ok — худший из фазы WAN и проблем.
    pub fn level(&self) -> &'static str {
        if !self.wan_up || self.state == "CRITICAL" || self.issues.iter().any(|i| i.level == "crit") {
            "crit"
        } else if self.state == "WARNING" || !self.issues.is_empty() {
            "warn"
        } else {
            "ok"
        }
    }

    pub fn from(v: &Value) -> Report {
        let isp = v.get("isp").map(|i| Isp { ip: vs(i, "ip"), asn: vs(i, "asn"), name: vs(i, "name") }).unwrap_or_default();
        Report {
            router: vs(v, "router"),
            version: vs(v, "version"),
            time: vs(v, "time"),
            isp,
            state: vs(v, "state"),
            diagnosis: vs(v, "diagnosis"),
            wan_up: vb(v, "wan_up"),
            v4: Probe::from(v.get("v4")),
            v6: Probe::from(v.get("v6")),
            services: crate::dnsguard::str_list(v.get("services")),
            svc: list(v, "svc").iter().map(|s| Svc { name: vs(s, "name"), state: vs(s, "state"), fam: vs(s, "fam") }).collect(),
            incidents: list(v, "incidents").iter().map(|i| Inc { id: vf(i, "id") as i64, typ: vs(i, "type"), open: vb(i, "open"), start: vs(i, "start"), end: vs(i, "end"), dur: vf(i, "dur") as i64, text: vs(i, "text") }).collect(),
            notices: list(v, "notices").iter().map(|n| crate::payment::Notice { key: vs(n, "key"), text: vs(n, "text") }).collect(),
            link: vs(v, "link"),
            backup: vb(v, "backup"),
            issues: list(v, "issues").iter().map(|i| Issue { level: vs(i, "level"), kind: vs(i, "kind"), text: vs(i, "text") }).collect(),
        }
    }

    /// Ключ «что изменилось»: состояние, открытые инциденты, сбои сервисов, напоминания, канал.
    pub fn change_key(&self) -> String {
        let mut k = format!("{}{}", self.state, self.diagnosis);
        if !self.wan_up {
            k.push_str("down");
        }
        for i in self.incidents.iter().filter(|i| i.open) {
            k.push_str(&format!("|{}", i.id));
        }
        if let Some(i) = self.incidents.first() {
            k.push_str(&format!("#{}", i.id));
        }
        for s in &self.svc {
            k.push_str(&format!("|{}:{}", s.name, s.state));
        }
        for n in &self.notices {
            k.push_str(&format!("|{}", n.key));
        }
        if self.backup {
            k.push_str(&format!("|link:{}", self.link));
        }
        for i in &self.issues {
            k.push_str(&format!("|{}:{}", i.kind, i.level));
        }
        k
    }
}

/// Все центры (url + urls, без повторов).
pub fn urls(c: &ReportConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in std::iter::once(&c.url).chain(&c.urls) {
        let u = u.trim();
        if !u.is_empty() && !out.iter().any(|x| x == u) {
            out.push(u.to_string());
        }
    }
    out
}

/// POST на http://host:port/path; код ответа.
pub fn http_post(url: &str, ctype: &str, body: &[u8], timeout: Duration) -> Result<u16, String> {
    let rest = url.strip_prefix("http://").ok_or("bad url (only http://host:port/path)")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if host.is_empty() {
        return Err("bad url (only http://host:port/path)".into());
    }
    let hp = if host.rsplit_once(':').map_or(false, |(_, p)| p.parse::<u16>().is_ok()) && !host.ends_with(']') { host.to_string() } else { format!("{host}:80") };
    let addr: SocketAddr = hp.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?;
    let mut c = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("dial tcp {hp}: {e}"))?;
    let _ = c.set_read_timeout(Some(timeout));
    let _ = c.set_write_timeout(Some(timeout));
    write!(c, "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(|e| e.to_string())?;
    c.write_all(body).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(c.take(4096)).read_line(&mut line).map_err(|e| e.to_string())?;
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 2 {
        return Err("bad response".into());
    }
    Ok(f[1].parse().unwrap_or(0))
}

/// Глобальный адрес (не частный, не CGNAT 100.64/10).
pub fn public_ip(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_multicast() || a.is_broadcast() || (o[0] == 100 && o[1] & 0xc0 == 64))
        }
        Ok(IpAddr::V6(a)) => crate::netx::is_public_ipv6(&IpAddr::V6(a)),
        Err(_) => false,
    }
}

/// Чем ходить по HTTPS: curl | uclient | gnu | busybox ("" — нечем).
pub fn https_tool() -> (&'static str, &'static str) {
    if crate::util::have_bin("curl") {
        return ("curl", "curl");
    }
    if crate::util::have_bin("uclient-fetch") {
        return ("uclient-fetch", "uclient");
    }
    if crate::util::have_bin("wget") {
        let gnu = std::process::Command::new("wget").arg("--version").output().map_or(false, |o| String::from_utf8_lossy(&o.stdout).contains("GNU Wget"));
        return ("wget", if gnu { "gnu" } else { "busybox" });
    }
    ("", "")
}

/// Короткий ответ по HTTPS.
pub fn https_get(url: &str) -> String {
    let (bin, kind) = https_tool();
    let out = match kind {
        "curl" => crate::flowwatch::output_timeout(bin, &["-s", "-f", "-m", "5", url], 7000),
        "" => None,
        _ => crate::flowwatch::output_timeout(bin, &["-q", "-T", "5", "-O", "-", url], 7000),
    };
    match out {
        Some(s) if s.len() <= 4096 => s.trim().to_string(),
        _ => String::new(),
    }
}

/// Внешний IP: DNS myip.opendns.com у OpenDNS, иначе (перехват DNS) — по HTTPS.
fn my_ip() -> String {
    if let crate::dgsys::Res::Ips(v) = crate::dgsys::dns_query("208.67.222.222:53", "myip.opendns.com", crate::dns::TYPE_A, 3000) {
        if let Some(ip) = v.iter().map(|x| x.to_string()).find(|x| public_ip(x)) {
            return ip;
        }
    }
    let ip = https_get("https://api.ipify.org");
    if public_ip(&ip) {
        ip
    } else {
        String::new()
    }
}

#[derive(Clone, Debug, Default)]
struct HubSend {
    sent: i64,
    failed: i64,
    last_ok: i64,
    last_err: String,
}

struct Done {
    ip: Option<String>,
    res: Vec<(String, Result<(), String>)>,
}

pub struct Reporter {
    pending: Option<Report>,
    last_key: String,
    last_at: u64,
    busy: bool,
    pub isp: Isp,
    isp_at: u64,
    hubs: BTreeMap<String, HubSend>,
    tx: Sender<Done>,
    rx: Receiver<Done>,
}

fn wall() -> (i64, u32) {
    crate::util::now_wall()
}

impl Reporter {
    pub fn new() -> Reporter {
        let (tx, rx) = channel();
        Reporter { pending: None, last_key: String::new(), last_at: 0, busy: false, isp: Isp::default(), isp_at: 0, hubs: BTreeMap::new(), tx, rx }
    }

    /// Свежий отчёт; отправка — когда пора или что-то изменилось.
    pub fn offer(&mut self, cfg: &ReportConfig, rep: Report, now: u64, owner: &mut crate::ipowner::IpOwner) {
        self.collect(owner, now);
        if !cfg.enabled || urls(cfg).is_empty() {
            return;
        }
        let key = rep.change_key();
        if key != self.last_key || now - self.last_at >= cfg.interval_sec.max(1) as u64 * 1000 {
            self.last_key = key;
            self.last_at = now;
            self.pending = Some(rep);
        }
        self.send(cfg, now);
    }

    fn send(&mut self, cfg: &ReportConfig, now: u64) {
        if self.busy {
            return;
        }
        let Some(mut rep) = self.pending.take() else { return };
        let need_ip = self.isp_at == 0 || now - self.isp_at >= 3600 * 1000;
        rep.isp = self.isp.clone();
        let (token, list, tx) = (cfg.token.clone(), urls(cfg), self.tx.clone());
        self.busy = true;
        let r = std::thread::Builder::new().name("cgmon-report".into()).stack_size(256 << 10).spawn(move || {
            let mut ip = None;
            if need_ip {
                let x = my_ip();
                if !x.is_empty() {
                    if x != rep.isp.ip {
                        rep.isp = Isp { ip: x.clone(), ..Default::default() };
                    }
                    ip = Some(x);
                }
            }
            let mut res = Vec::new();
            for u in list {
                let mut j = J::new();
                j.obj().key("ts").int(wall().0).key("report");
                rep.json(&mut j);
                j.end_obj();
                let r = if token.is_empty() {
                    Err("report.token is empty".to_string())
                } else {
                    match crate::hubcrypt::seal(&token, j.b.as_bytes()) {
                        None => Err("seal failed".into()),
                        Some(body) => match http_post(&u, "application/octet-stream", &body, Duration::from_secs(10)) {
                            Ok(200) => Ok(()),
                            Ok(c) => Err(format!("hub answered {c}")),
                            Err(e) => Err(e),
                        },
                    }
                };
                res.push((u, r));
            }
            let _ = tx.send(Done { ip, res });
        });
        if r.is_err() {
            self.busy = false;
        }
    }

    /// Итоги отправки; провайдер — по кешу владельцев адресов.
    fn collect(&mut self, owner: &mut crate::ipowner::IpOwner, now: u64) {
        while let Ok(d) = self.rx.try_recv() {
            self.busy = false;
            if let Some(ip) = d.ip {
                if ip != self.isp.ip {
                    self.isp = Isp { ip, ..Default::default() };
                    self.isp_at = 0;
                }
            }
            let mut all_ok = true;
            for (u, r) in d.res {
                let h = self.hubs.entry(u.clone()).or_default();
                match r {
                    Ok(()) => {
                        h.sent += 1;
                        h.last_ok = wall().0;
                        h.last_err.clear();
                    }
                    Err(e) => {
                        h.failed += 1;
                        if h.last_err != e {
                            crate::log_err!("report: {}: {}", u, e);
                        }
                        h.last_err = e;
                        all_ok = false;
                    }
                }
            }
            if !all_ok {
                self.last_key.clear(); // центр недоступен: изменения не потерять
            }
        }
        if let Ok(ip) = self.isp.ip.parse::<IpAddr>() {
            match owner.get(&ip, now) {
                Some(i) if !i.asn.is_empty() => {
                    if self.isp.asn.is_empty() {
                        self.isp.asn = i.asn.clone();
                        self.isp.name = if i.brand.is_empty() { i.as_name.clone() } else { i.brand.clone() };
                        self.isp_at = now.max(1); // запоминаем только определённого провайдера
                    }
                }
                Some(_) => {}
                None => owner.want(ip, now),
            }
        }
    }

    pub fn status_json(&self, cfg: &ReportConfig, j: &mut J) {
        j.obj().key("enabled").bool(true);
        if !self.isp.name.is_empty() {
            j.key("isp").str(&self.isp.name);
        }
        j.key("hubs").obj();
        for u in urls(cfg) {
            let h = self.hubs.get(&u).cloned().unwrap_or_default();
            j.key(&u).obj().key("sent").int(h.sent).key("failed").int(h.failed);
            j.key("last_ok").str(&if h.last_ok == 0 { "0001-01-01T00:00:00Z".to_string() } else { crate::util::rfc3339(h.last_ok, 0) });
            if !h.last_err.is_empty() {
                j.key("last_err").str(&h.last_err);
            }
            j.end_obj();
        }
        j.end_obj().end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_key() {
        let r = Report { router: "r1".into(), version: "2.0".into(), time: "2026-10-14T10:00:00+05:00".into(), state: "NORMAL".into(), diagnosis: "HEALTHY".into(), wan_up: true, svc: vec![Svc { name: "example.com".into(), state: "down".into(), fam: "IPv6".into() }], incidents: vec![Inc { id: 7, typ: "wan_down".into(), open: true, start: "x".into(), end: "y".into(), ..Default::default() }], ..Default::default() };
        let mut j = J::new();
        r.json(&mut j);
        let back = Report::from(&crate::value::parse_json(&j.b).unwrap());
        assert!(back.router == "r1" && back.svc[0].fam == "IPv6" && back.incidents[0].id == 7 && back.incidents[0].open);
        assert_eq!(r.change_key(), "NORMALHEALTHY|7#7|example.com:down");
        assert!(public_ip("203.0.113.5") && !public_ip("100.64.1.2") && !public_ip("10.0.0.1"));
    }
}
