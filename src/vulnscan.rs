//! Сканер уязвимостей: пакеты и ядро против баз уязвимостей, настройки роутера,
//! опасные службы устройств LAN. Всё — в одном фоновом потоке, по кнопке со
//! страницы или раз в неделю (и после смены пакетов).
//!
//! Пакеты и ядро:
//!   * опись — `apk list -I` / opkg status: исходный пакет (origin) и версия upstream;
//!   * OSV.dev querybatch — экосистема Debian:13 (записи DEBIAN-CVE-* несут оценку
//!     Debian: urgency, и вектор CVSS: AV:N — по сети, AV:L — нужен доступ к роутеру),
//!     Go — для tailscale, AdGuard Home, docker;
//!   * подробности — только для найденного; версия сравнивается по upstream (эпоха и
//!     ревизия Debian отбрасываются), «исправлено патчем Debian в той же версии» —
//!     отдельный статус «возможно»;
//!   * ядро: у Debian на ядро сотни открытых записей — сначала только номера, затем
//!     CISA KEV (уже атакуемые) и FIRST EPSS (вероятность атаки), подробности — для
//!     отобранных, остальное — счётчиком.
//! Настройки: что открыто в интернет, пароль root, SSH, Wi-Fi, WPS, UPnP, проброс
//! портов, политика firewall. LAN: только безопасные пробы — открытые порты и
//! приветствия служб (без попыток входа).
//!
//! Находки — коды и параметры, текст пишет страница на своём языке.

use crate::json::J;
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

const WEEK_MS: i64 = 7 * 86400_000;
const DEBIAN: &str = "Debian:13";
const MAX_DETAILS: usize = 400;
/// уточнений по данным апстрима (записи CVE / проекта в OSV) за проверку
const MAX_UPSTREAM: usize = 250;
const KERNEL_DETAILS: usize = 40;
const EPSS_SHORTLIST: f64 = 0.05;

/// Одна находка.
#[derive(Clone, Debug, Default)]
pub struct Finding {
    /// crit | high | med | low | info
    pub sev: String,
    /// pkg | kernel | cfg | lan
    pub area: String,
    /// код находки (страница переводит): cve, open_wan, root_nopass, …
    pub code: String,
    /// где: пакет, порт, устройство, интерфейс Wi-Fi
    pub target: String,
    /// параметры для текста
    pub args: Vec<String>,
    pub cve: String,
    pub osv: String,
    pub version: String,
    pub fixed: String,
    pub cvss: f64,
    /// N (сеть) | A (соседняя сеть) | L (локально) | P (физически) | "" (неизвестно)
    pub av: String,
    pub urgency: String,
    pub epss: f64,
    pub kev: bool,
    /// fixed | maybe (исправлено патчем Debian той же версии) | open (исправления нет)
    pub state: String,
    pub summary: String,
    /// доступная новая версия (из индекса пакетов или релиза cgmon)
    pub upgrade: String,
    /// что делает кнопка: pkg (apk/opkg upgrade пакетов pkgs) | self (обновить cgmon) | sysupgrade (только подсказка)
    pub action: String,
    pub pkgs: Vec<String>,
    /// ссылка на запись (GitHub advisory и т. п.)
    pub url: String,
    /// служба доступна из интернета (порт открыт для wan или проброшен) — только тогда «критично»
    pub exposed: bool,
    /// какие порты видны из интернета
    pub ports: String,
    /// MAC устройства LAN (для изоляции от интернета)
    pub mac: String,
    /// камера/регистратор ходит в интернет (облако производителя): yes | no | "" — не камера
    pub cloud: String,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub at: i64,
    pub took_ms: i64,
    pub packages: usize,
    pub kernel: String,
    /// уязвимостей ядра всего / в том числе малозначимых и локальных (не показаны поштучно)
    pub kernel_total: usize,
    pub kernel_hidden: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
    pub pkg_sig: String,
}

pub struct VulnScan {
    pub report: Option<Report>,
    rx: Option<Receiver<Msg>>,
    tx: Sender<Msg>,
    busy: bool,
    pub phase: String,
    loaded: bool,
    last_try: i64,
    /// действие со страницы: идёт / итог (ok, текст)
    act_busy: bool,
    act_result: Option<(bool, String)>,
    /// изоляция от интернета: применённый скрипт nft и когда проверяли
    iso_written: String,
    iso_at: u64,
    iso_macs: Vec<String>,
    /// после обновления пакета — полная перепроверка, как только поток свободен
    recheck_due: bool,
}

enum Msg {
    Phase(String),
    Done(Report),
    Act(bool, String, Vec<(String, String)>),
}

impl Default for VulnScan {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        VulnScan { report: None, rx: Some(rx), tx, busy: false, phase: String::new(), loaded: false, last_try: 0, act_busy: false, act_result: None, iso_written: String::new(), iso_at: 0, iso_macs: Vec::new(), recheck_due: false }
    }
}

/// Данные для потока (из конфига и демона).
#[derive(Clone)]
pub struct Input {
    pub lan: bool,
    /// адрес, имя, MAC, байт в интернет за сутки (учёт трафика)
    pub lan_devices: Vec<(IpAddr, String, String, u64)>,
    pub own: Vec<IpAddr>,
}

impl VulnScan {
    /// Такт: результаты потока, плановый запуск. Возвращает сообщения для журнала.
    pub fn tick(&mut self, now: i64, mode: &str, billed: bool, state_file: &str, input: impl FnOnce() -> Input) -> Vec<String> {
        let mut msgs = Vec::new();
        if !self.loaded {
            self.loaded = true;
            self.report = load(state_file);
            // отчёт прежней версии — по нынешним правилам, не дожидаясь перепроверки
            if let Some(r) = self.report.as_mut() {
                if normalize(r) {
                    save(state_file, r);
                }
            }
        }
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                match m {
                    Msg::Phase(p) => self.phase = p,
                    Msg::Act(ok, t, vers) => {
                        self.act_busy = false;
                        msgs.push(if ok { tr!("Сканер уязвимостей: обновлено — {}", t) } else { tr!("Сканер уязвимостей: обновить не удалось — {}", t) });
                        self.act_result = Some((ok, t));
                        // сразу пересчитать находки обновлённых пакетов по новой версии,
                        // затем — полная перепроверка в фоне
                        if ok {
                            if let Some(r) = self.report.as_mut() {
                                recheck_upgraded(r, &vers);
                                normalize(r);
                                save(state_file, r);
                                r.pkg_sig.clear();
                                self.recheck_due = true;
                            }
                        }
                    }
                    Msg::Done(r) => {
                        self.busy = false;
                        self.phase.clear();
                        let (c, h) = (r.findings.iter().filter(|f| f.sev == "crit").count(), r.findings.iter().filter(|f| f.sev == "high").count());
                        msgs.push(tr!("Сканер уязвимостей: проверка завершена — критических {}, серьёзных {}, всего находок {}", c, h, r.findings.len()));
                        save(state_file, &r);
                        self.report = Some(r);
                    }
                }
            }
        }
        if self.recheck_due && !self.busy && mode != "off" {
            self.recheck_due = false;
            self.start(now, input());
            return msgs;
        }
        if self.busy || mode == "off" || mode == "manual" || billed {
            return msgs;
        }
        // раз в неделю или после смены пакетов (не чаще раза в час)
        let due = match &self.report {
            None => true,
            Some(r) => now - r.at >= WEEK_MS || (r.pkg_sig != pkg_sig() && now - r.at >= 3600_000),
        };
        if due && now - self.last_try >= 3600_000 {
            self.start(now, input());
        }
        msgs
    }

    /// Запустить проверку (кнопка на странице); false — уже идёт.
    pub fn start(&mut self, now: i64, input: Input) -> bool {
        if self.busy {
            return false;
        }
        self.busy = true;
        self.last_try = now;
        self.phase = "start".into();
        let tx = self.tx.clone();
        let _ = std::thread::Builder::new().name("vulnscan".into()).spawn(move || {
            let r = run(now, &input, &tx);
            let _ = tx.send(Msg::Done(r));
        });
        true
    }


    /// Кнопка находки: pkg — обновить пакеты, self — обновить cgmon.
    pub fn action(&mut self, kind: &str, pkgs: Vec<String>) -> Result<(), String> {
        if self.act_busy {
            return Err(tr!("обновление уже идёт").to_string());
        }
        if kind != "pkg" && kind != "self" {
            return Err("bad action".into());
        }
        self.act_busy = true;
        self.act_result = None;
        let tx = self.tx.clone();
        let kind = kind.to_string();
        let _ = std::thread::Builder::new().name("vulnact".into()).spawn(move || {
            let r = if kind == "self" { self_update().map(|v| format!("cgmon {v}")) } else { upgrade_pkgs(&pkgs) };
            // новые версии установленных пакетов — для быстрого пересчёта
            let vers: Vec<(String, String)> = if r.is_ok() && kind == "pkg" { inventory().into_iter().filter(|p| pkgs.contains(&p.name)).map(|p| (p.name, p.version)).collect() } else { Vec::new() };
            let _ = tx.send(match r {
                Ok(t) => Msg::Act(true, t, vers),
                Err(e) => Msg::Act(false, e, Vec::new()),
            });
        });
        Ok(())
    }

    /// Кратко — в статус (счётчики; находки — по запросу vuln_get).
    /// Изоляция устройств от интернета (MAC из vuln_scan.isolate): своя таблица nft,
    /// только LAN и сам роутер. Работает при любом режиме сканера.
    pub fn isolate_tick(&mut self, macs: &[String], now_ms: u64) -> Vec<String> {
        let mut list: Vec<String> = macs.iter().filter_map(|m| norm_mac(m)).collect();
        list.sort();
        list.dedup();
        let script = iso_script(&list);
        if script == self.iso_written && now_ms.saturating_sub(self.iso_at) < 60_000 {
            return Vec::new();
        }
        self.iso_at = now_ms;
        let changed = script != self.iso_written;
        if crate::util::readonly() {
            return Vec::new();
        }
        match crate::acct::nft_script(&script) {
            Ok(_) => {
                self.iso_written = script;
                let was = std::mem::replace(&mut self.iso_macs, list.clone());
                if changed {
                    let added: Vec<&String> = list.iter().filter(|m| !was.contains(m)).collect();
                    let removed: Vec<&String> = was.iter().filter(|m| !list.contains(m)).collect();
                    let mut msgs = Vec::new();
                    for m in added {
                        msgs.push(tr!("Изоляция: {} отрезано от интернета — только локальная сеть", m));
                    }
                    for m in removed {
                        msgs.push(tr!("Изоляция снята: {} снова выходит в интернет", m));
                    }
                    return msgs;
                }
                Vec::new()
            }
            Err(e) => vec![tr!("Изоляция: не удалось применить правила nft: {}", e)],
        }
    }

    pub fn status_json(&self, j: &mut J, mode: &str) {
        if mode == "off" && self.report.is_none() && self.iso_macs.is_empty() {
            return;
        }
        j.obj().key("mode").str(mode).key("busy").bool(self.busy);
        if self.busy {
            j.key("phase").str(&self.phase);
        }
        j.key("act_busy").bool(self.act_busy);
        j.key("isolated").arr();
        for m in &self.iso_macs {
            j.str(m);
        }
        j.end_arr();
        if let Some((ok, t)) = &self.act_result {
            j.key("act_ok").bool(*ok).key("act_text").str(t);
        }
        if let Some(r) = &self.report {
            let n = |s: &str| r.findings.iter().filter(|f| f.sev == s).count() as i64;
            j.key("at").int(r.at).key("crit").int(n("crit")).key("high").int(n("high")).key("med").int(n("med")).key("low").int(n("low")).key("info").int(n("info"));
            j.key("kev").int(r.findings.iter().filter(|f| f.kev).count() as i64);
        }
        j.end_obj();
    }

    pub fn report_json(&self) -> String {
        let mut j = J::new();
        match &self.report {
            Some(r) => report_json(&mut j, r, self.busy, &self.phase),
            None => {
                j.obj().key("busy").bool(self.busy).key("phase").str(&self.phase).end_obj();
            }
        }
        j.b
    }
}

/// Проверка сразу, в этом потоке (команда `cgmon vuln-scan`): отчёт JSON.
pub fn scan_now(input: Input) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    let now = { let w = crate::util::now_wall(); w.0 * 1000 + (w.1 / 1_000_000) as i64 };
    let r = run(now, &input, &tx);
    while let Ok(Msg::Phase(p)) = rx.try_recv() {
        eprintln!("· {p}");
    }
    let mut j = J::new();
    report_json(&mut j, &r, false, "");
    j.b
}

fn report_json(j: &mut J, r: &Report, busy: bool, phase: &str) {
    j.obj().key("at").int(r.at).key("took_ms").int(r.took_ms).key("packages").int(r.packages as i64).key("kernel").str(&r.kernel);
    j.key("kernel_total").int(r.kernel_total as i64).key("kernel_hidden").int(r.kernel_hidden as i64).key("pkg_sig").str(&r.pkg_sig);
    j.key("busy").bool(busy).key("phase").str(phase);
    j.key("errors").arr();
    for e in &r.errors {
        j.str(e);
    }
    j.end_arr().key("findings").arr();
    for f in &r.findings {
        j.obj().key("sev").str(&f.sev).key("area").str(&f.area).key("code").str(&f.code).key("target").str(&f.target);
        j.key("args").arr();
        for a in &f.args {
            j.str(a);
        }
        j.end_arr();
        if !f.pkgs.is_empty() {
            j.key("pkgs").arr();
            for p in &f.pkgs {
                j.str(p);
            }
            j.end_arr();
        }
        for (k, v) in [("cve", &f.cve), ("osv", &f.osv), ("version", &f.version), ("fixed", &f.fixed), ("av", &f.av), ("urgency", &f.urgency), ("state", &f.state), ("summary", &f.summary), ("upgrade", &f.upgrade), ("action", &f.action), ("url", &f.url), ("ports", &f.ports), ("mac", &f.mac), ("cloud", &f.cloud)] {
            if !v.is_empty() {
                j.key(k).str(v);
            }
        }
        if f.cvss > 0.0 {
            j.key("cvss").num(f.cvss, 1);
        }
        if f.epss > 0.0 {
            j.key("epss").num(f.epss, 4);
        }
        if f.kev {
            j.key("kev").bool(true);
        }
        if f.exposed {
            j.key("exposed").bool(true);
        }
        j.end_obj();
    }
    j.end_arr().end_obj();
}

fn save(path: &str, r: &Report) {
    if crate::util::readonly() {
        return;
    }
    let mut j = J::new();
    report_json(&mut j, r, false, "");
    let _ = crate::util::write_atomic(&crate::storage::path(path), j.b.as_bytes(), 0o600);
}

fn load(path: &str) -> Option<Report> {
    let t = std::fs::read_to_string(crate::storage::path(path)).ok()?;
    let v = crate::value::parse_json(&t).ok()?;
    let s = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let f = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
    let mut r = Report { at: f(&v, "at") as i64, took_ms: f(&v, "took_ms") as i64, packages: f(&v, "packages") as usize, kernel: s(&v, "kernel"), kernel_total: f(&v, "kernel_total") as usize, kernel_hidden: f(&v, "kernel_hidden") as usize, pkg_sig: s(&v, "pkg_sig"), ..Default::default() };
    if let Some(Value::List(l)) = v.get("errors") {
        r.errors = l.iter().filter_map(|x| x.as_str().map(String::from)).collect();
    }
    if let Some(Value::List(l)) = v.get("findings") {
        for x in l {
            let list = |k: &str| match x.get(k) {
                Some(Value::List(a)) => a.iter().filter_map(|y| y.as_str().map(String::from)).collect(),
                _ => Vec::new(),
            };
            r.findings.push(Finding { sev: s(x, "sev"), area: s(x, "area"), code: s(x, "code"), target: s(x, "target"), args: list("args"), cve: s(x, "cve"), osv: s(x, "osv"), version: s(x, "version"), fixed: s(x, "fixed"), cvss: f(x, "cvss"), av: s(x, "av"), urgency: s(x, "urgency"), epss: f(x, "epss"), kev: x.get("kev").and_then(|y| y.as_bool()).unwrap_or(false), state: s(x, "state"), summary: s(x, "summary"), upgrade: s(x, "upgrade"), action: s(x, "action"), pkgs: list("pkgs"), url: s(x, "url"), exposed: x.get("exposed").and_then(|y| y.as_bool()).unwrap_or(false), ports: s(x, "ports"), mac: s(x, "mac"), cloud: s(x, "cloud") });
        }
    }
    Some(r)
}

// ======================= опись пакетов =======================

/// Пакет: имя бинарного пакета, исходник (origin), версия upstream (без -rN).
#[derive(Clone, Debug, PartialEq)]
pub struct Pkg {
    pub name: String,
    pub origin: String,
    pub version: String,
}

/// Подпись списка пакетов (смена — повод перепроверить).
pub fn pkg_sig() -> String {
    for p in ["/lib/apk/db/installed", "/usr/lib/opkg/status"] {
        if let Ok(m) = std::fs::metadata(p) {
            use std::os::unix::fs::MetadataExt;
            return format!("{}:{}", m.len(), m.mtime());
        }
    }
    String::new()
}

/// `2.93-r1` → `2.93`; `1.37.0-r6` → `1.37.0`.
fn strip_rel(v: &str) -> String {
    match v.rfind("-r") {
        Some(i) if v[i + 2..].bytes().all(|c| c.is_ascii_digit()) && i + 2 < v.len() => v[..i].to_string(),
        _ => v.to_string(),
    }
}

/// Строки `apk list -I`: «name-ver-rN arch {origin/path} (lic) [installed]».
pub fn parse_apk(text: &str) -> Vec<Pkg> {
    let mut out = Vec::new();
    for line in text.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        // имя-версия: версия начинается с последнего «-цифра», за которым идёт -rN
        let Some(rpos) = first.rfind("-r") else { continue };
        let head = &first[..rpos];
        let Some(vpos) = head.rfind('-') else { continue };
        let (name, ver) = (&first[..vpos], &first[vpos + 1..]);
        let origin = line.split('{').nth(1).and_then(|x| x.split('}').next()).map(|p| p.rsplit('/').next().unwrap_or(p).to_string()).unwrap_or_else(|| name.to_string());
        out.push(Pkg { name: name.to_string(), origin, version: strip_rel(ver) });
    }
    out
}

/// /usr/lib/opkg/status: Package / Version / (Source) — исходник по последнему элементу Source.
pub fn parse_opkg_status(text: &str) -> Vec<Pkg> {
    let mut out = Vec::new();
    for blk in text.split("\n\n") {
        let (mut name, mut ver, mut src) = (String::new(), String::new(), String::new());
        for l in blk.lines() {
            if let Some(x) = l.strip_prefix("Package: ") {
                name = x.trim().into();
            } else if let Some(x) = l.strip_prefix("Version: ") {
                ver = x.trim().into();
            } else if let Some(x) = l.strip_prefix("Source: ") {
                src = x.trim().rsplit('/').next().unwrap_or("").to_string();
            }
        }
        if !name.is_empty() && !ver.is_empty() {
            let origin = if src.is_empty() { name.clone() } else { src };
            out.push(Pkg { name, origin, version: strip_rel(&ver) });
        }
    }
    out
}

fn inventory() -> Vec<Pkg> {
    if let Some(t) = crate::flowwatch::output_timeout("apk", &["list", "-I"], 20_000).filter(|t| !t.is_empty()) {
        return parse_apk(&t);
    }
    std::fs::read_to_string("/usr/lib/opkg/status").map(|t| parse_opkg_status(&t)).unwrap_or_default()
}

/// Исходник OpenWrt → (экосистема OSV, имя, версия для запроса); None — данных нет.
fn osv_target(origin: &str, ver: &str) -> Option<(&'static str, String, String)> {
    if ver.contains('~') || ver.is_empty() {
        return None; // снимок git OpenWrt (uhttpd, odhcpd…) — в базах их нет
    }
    // программы на Go — экосистема Go, модуль и версия v…
    let go = match origin {
        "tailscale" => Some("tailscale.com"),
        "adguardhome" => Some("github.com/AdguardTeam/AdGuardHome"),
        "docker" | "dockerd" => Some("github.com/docker/docker"),
        "containerd" => Some("github.com/containerd/containerd"),
        "runc" => Some("github.com/opencontainers/runc"),
        "frp" => Some("github.com/fatedier/frp"),
        _ => None,
    };
    if let Some(m) = go {
        let v = if origin.starts_with("docker") { format!("v{ver}+incompatible") } else { format!("v{ver}") };
        return Some(("Go", m.to_string(), v));
    }
    // только OpenWrt — сверять не с чем
    const OWN: &[&str] = &["base-files", "procd", "netifd", "ubus", "ubox", "uci", "libubox", "uhttpd", "odhcpd", "odhcp6c", "rpcd", "fstools", "fwtool", "mtd", "opkg", "apk", "firewall4", "ucode", "usign", "jsonfilter", "ustream-ssl", "libnl-tiny", "iwinfo", "urngd", "cgmon", "luci", "musl", "toolchain", "linux", "openwrt-keyring", "ca-certificates", "uboot-envtools", "wireless-regdb", "kmod", "logd"];
    if OWN.contains(&origin) || origin.starts_with("luci") || origin.starts_with("kmod-") {
        return None;
    }
    // имена исходников Debian, где отличаются, и эпохи Debian
    let deb = match origin {
        "hostapd" => "wpa",
        "sqlite3" | "sqlite" => "sqlite3",
        "glib2" => "glib2.0",
        "samba4" => "samba",
        "xz" => "xz-utils",
        "zstd" => "libzstd",
        "lua" => "lua5.1",
        "libnl" => "libnl3",
        "gnutls" => "gnutls28",
        "bind" => "bind9",
        "zerotier" => "zerotier-one",
        "openvpn" => "openvpn",
        "lighttpd" => "lighttpd",
        o => o,
    };
    let epoch = match deb {
        "busybox" | "openssh" | "nftables" | "bind9" | "zlib" | "ntp" | "iputils" => "1:",
        "wpa" | "samba" => "2:",
        _ => "",
    };
    Some(("Debian", deb.to_string(), format!("{epoch}{ver}-0")))
}

// ======================= сравнение версий =======================

/// Debian/Go/OpenWrt → upstream: без эпохи, ревизии, +dfsg, ~, v.
pub fn upstream(v: &str) -> String {
    let v = v.trim().trim_start_matches('v');
    let v = v.split_once(':').map(|(e, r)| if e.bytes().all(|c| c.is_ascii_digit()) { r } else { v }).unwrap_or(v);
    let v = match v.rfind('-') {
        Some(i) => &v[..i],
        None => v,
    };
    let v = v.split(['+', '~']).next().unwrap_or(v);
    v.to_string()
}

fn prerelease(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    ["rc", "alpha", "beta", "pre", "dev", "snapshot"].iter().any(|p| s.starts_with(p))
}

/// Сравнение версий по сегментам (числа — как числа, буквы — как строки).
pub fn vcmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let seg = |s: &str| -> Vec<(bool, String)> {
        let mut v: Vec<(bool, String)> = Vec::new();
        for c in s.chars() {
            let d = c.is_ascii_digit();
            if !c.is_ascii_alphanumeric() {
                v.push((false, String::new()));
                continue;
            }
            match v.last_mut() {
                Some((dd, cur)) if *dd == d && !cur.is_empty() => cur.push(c),
                _ => v.push((d, c.to_string())),
            }
        }
        v.into_iter().filter(|x| !x.1.is_empty()).collect()
    };
    let (x, y) = (seg(a), seg(b));
    for i in 0..x.len().max(y.len()) {
        match (x.get(i), y.get(i)) {
            (Some(p), Some(q)) => {
                let o = if p.0 && q.0 {
                    let (pn, qn) = (p.1.trim_start_matches('0'), q.1.trim_start_matches('0'));
                    pn.len().cmp(&qn.len()).then(pn.cmp(qn))
                } else if p.0 != q.0 {
                    if p.0 { Greater } else { Less }
                } else {
                    p.1.cmp(&q.1)
                };
                if o != Equal {
                    return o;
                }
            }
            // лишний хвост: число — новее; буквы — новее (10.6p1, 1.0.2k), кроме предрелизов (rc, beta…)
            (Some(p), None) => return if p.0 || !prerelease(&p.1) { Greater } else { Less },
            (None, Some(q)) => return if q.0 || !prerelease(&q.1) { Less } else { Greater },
            (None, None) => break,
        }
    }
    Equal
}

// ======================= сеть =======================

fn tmpf(name: &str) -> String {
    let _ = std::fs::create_dir_all(crate::util::RUN_DIR);
    format!("{}/vs_{name}", crate::util::RUN_DIR)
}

/// GET в файл → текст (большие ответы — только через файл).
fn http_get(url: &str, name: &str, timeout_s: u64) -> Result<String, String> {
    let (bin, kind) = crate::report::https_tool();
    if kind.is_empty() {
        return Err(tr!("нет curl, uclient-fetch или wget").to_string());
    }
    let out = tmpf(name);
    let _ = std::fs::remove_file(&out);
    let t = timeout_s.to_string();
    let code = match kind {
        "curl" => crate::flowwatch::output_timeout(bin, &["-s", "-m", &t, "-o", &out, "-w", "%{http_code}", url], timeout_s * 1000 + 5000),
        _ => crate::flowwatch::output_timeout(bin, &["-q", "-T", &t, "-O", &out, url], timeout_s * 1000 + 5000),
    }
    .unwrap_or_default();
    let body = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    if body.is_empty() || (!code.is_empty() && !code.starts_with('2')) {
        return Err(format!("{url}: HTTP {}", if code.is_empty() { "—".into() } else { code }));
    }
    Ok(body)
}

/// POST JSON в файл → текст.
fn http_post(url: &str, body: &str, name: &str, timeout_s: u64) -> Result<String, String> {
    let (bin, kind) = crate::report::https_tool();
    let req = tmpf(&format!("{name}.req"));
    crate::util::write_atomic(&req, body.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    let out = tmpf(name);
    let _ = std::fs::remove_file(&out);
    let t = timeout_s.to_string();
    let data = format!("@{req}");
    let pf = format!("--post-file={req}");
    let code = match kind {
        "" => return Err(tr!("нет curl, uclient-fetch или wget").to_string()),
        "curl" => crate::flowwatch::output_timeout(bin, &["-s", "-m", &t, "-H", "Content-Type: application/json", "--data-binary", &data, "-o", &out, "-w", "%{http_code}", url], timeout_s * 1000 + 5000),
        _ => crate::flowwatch::output_timeout(bin, &["-q", "-T", &t, &pf, "-O", &out, url], timeout_s * 1000 + 5000),
    }
    .unwrap_or_default();
    let _ = std::fs::remove_file(&req);
    let resp = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    if resp.is_empty() || (!code.is_empty() && !code.starts_with('2')) {
        return Err(format!("{url}: HTTP {}", if code.is_empty() { "—".into() } else { code }));
    }
    Ok(resp)
}

fn js(s: &str) -> String {
    let mut o = String::new();
    crate::value::json_str(&mut o, s);
    o
}

/// OSV querybatch: для каждого запроса — список id (со страницами).
fn osv_ids(queries: &[(String, String, String)]) -> Result<Vec<Vec<String>>, String> {
    let mut res: Vec<Vec<String>> = vec![Vec::new(); queries.len()];
    let mut pending: Vec<(usize, String)> = (0..queries.len()).map(|i| (i, String::new())).collect();
    let mut rounds = 0;
    while !pending.is_empty() && rounds < 12 {
        rounds += 1;
        for chunk in pending.clone().chunks(200) {
            let mut b = String::from("{\"queries\":[");
            for (n, (i, tok)) in chunk.iter().enumerate() {
                let (eco, name, ver) = &queries[*i];
                if n > 0 {
                    b.push(',');
                }
                b.push_str(&format!("{{\"package\":{{\"name\":{},\"ecosystem\":{}}},\"version\":{}", js(name), js(eco), js(ver)));
                if !tok.is_empty() {
                    b.push_str(&format!(",\"page_token\":{}", js(tok)));
                }
                b.push('}');
            }
            b.push_str("]}");
            let resp = http_post("https://api.osv.dev/v1/querybatch", &b, "osvq", 120)?;
            let v = crate::value::parse_json(&resp).map_err(|e| format!("OSV: {e}"))?;
            let Some(Value::List(results)) = v.get("results") else { return Err("OSV: results".into()) };
            for ((i, _), r) in chunk.iter().zip(results.iter()) {
                if let Some(Value::List(vs)) = r.get("vulns") {
                    for x in vs {
                        if let Some(id) = x.get("id").and_then(|y| y.as_str()) {
                            res[*i].push(id.to_string());
                        }
                    }
                }
                let tok = r.get("next_page_token").and_then(|y| y.as_str()).unwrap_or("");
                pending.retain(|(k, _)| k != i);
                if !tok.is_empty() && res[*i].len() < 5000 {
                    pending.push((*i, tok.to_string()));
                }
            }
        }
    }
    Ok(res)
}

/// Подробности одной записи OSV.
fn osv_vuln(id: &str) -> Result<Value, String> {
    let t = http_get(&format!("https://api.osv.dev/v1/vulns/{id}"), "osvv", 40)?;
    crate::value::parse_json(&t).map_err(|e| format!("OSV {id}: {e}"))
}

/// Затронута ли наша версия по диапазонам одного набора событий OSV
/// (introduced / fixed / last_affected). Some((затронута, версия исправления)).
fn in_ranges(events: &[Value], ours: &str) -> Option<(bool, Option<String>)> {
    use std::cmp::Ordering::*;
    let mut start: Option<String> = None;
    let mut any = false;
    for e in events {
        let g = |k: &str| e.get(k).and_then(|x| x.as_str()).map(String::from);
        if let Some(i) = g("introduced") {
            start = Some(i);
            any = true;
        } else if let Some(f) = g("fixed") {
            if let Some(st) = start.take() {
                if (st == "0" || vcmp(ours, &st) != Less) && vcmp(ours, &f) == Less {
                    return Some((true, Some(f)));
                }
            }
        } else if let Some(la) = g("last_affected") {
            if let Some(st) = start.take() {
                if (st == "0" || vcmp(ours, &st) != Less) && vcmp(ours, &la) != Greater {
                    return Some((true, None));
                }
            }
        }
    }
    if let Some(st) = start {
        if st == "0" || vcmp(ours, &st) != Less {
            return Some((true, None)); // открытый диапазон — не исправлено
        }
    }
    any.then_some((false, None))
}

/// Все наборы событий с версиями (SEMVER/ECOSYSTEM; у записей CVE — диапазоны из CPE).
fn version_ranges(v: &Value) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    for a in v.get("affected").and_then(|x| x.as_array()).into_iter().flatten() {
        for r in a.get("ranges").and_then(|x| x.as_array()).into_iter().flatten() {
            let t = r.get("type").and_then(|x| x.as_str()).unwrap_or("");
            if t == "SEMVER" || t == "ECOSYSTEM" {
                if let Some(ev) = r.get("events").and_then(|x| x.as_array()) {
                    out.push(ev.to_vec());
                }
            }
            for x in r.get("database_specific").and_then(|d| d.get("extracted_events")).and_then(|x| x.as_array()).into_iter().flatten() {
                if let Some(ev) = x.get("range").and_then(|x| x.as_array()) {
                    out.push(ev.to_vec());
                }
            }
        }
    }
    out
}

/// Debian исправления не дал — смотрим апстрим: запись CVE в OSV и запись самого
/// проекта (CURL-CVE-…, у curl точные диапазоны по веткам). None — данных нет.
fn upstream_verdict(cve: &str, ours: &str, pkg: &str) -> Option<(bool, Option<String>)> {
    // проекты со своей базой в OSV: запись «ПРЕФИКС-CVE-…» есть, даже когда у записи CVE
    // ещё нет ни ссылок, ни диапазонов
    let own = match pkg {
        "curl" | "libcurl" | "libcurl4" => Some("CURL-"),
        _ => None,
    };
    if let Some(pre) = own {
        if let Ok(p) = osv_vuln(&format!("{pre}{cve}")) {
            let v: Vec<(bool, Option<String>)> = version_ranges(&p).iter().filter_map(|ev| in_ranges(ev, ours)).collect();
            if !v.is_empty() {
                return v.iter().find(|(a, _)| *a).cloned().or(Some((false, None)));
            }
        }
    }
    let v = osv_vuln(cve).ok()?;
    let mut sets: Vec<Vec<Value>> = Vec::new();
    // запись проекта точнее — первой
    for a in v.get("aliases").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|x| x.as_str()) {
        if a.starts_with("CVE-") || a.starts_with("GHSA-") {
            continue;
        }
        if let Ok(p) = osv_vuln(a) {
            sets.extend(version_ranges(&p));
        }
        break;
    }
    let project_sets = sets.len();
    sets.extend(version_ranges(&v));
    let verdicts: Vec<(bool, Option<String>)> = sets.iter().enumerate().filter_map(|(i, ev)| in_ranges(ev, ours).map(|r| (i, r))).filter(|(i, _)| project_sets == 0 || *i < project_sets).map(|(_, r)| r).collect();
    if verdicts.is_empty() {
        return None;
    }
    verdicts.iter().find(|(a, _)| *a).cloned().or(Some((false, None)))
}

/// Из записи OSV: CVE, CVSS (балл, вектор доступа), оценка Debian и исправленная версия
/// для нужного пакета/экосистемы.
struct VulnInfo {
    cve: String,
    cvss: f64,
    av: String,
    urgency: String,
    fixed: Option<String>,
    summary: String,
}

fn vuln_info(v: &Value, eco: &str, name: &str) -> VulnInfo {
    let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
    let mut cve = if id.starts_with("CVE-") { id.to_string() } else { String::new() };
    for k in ["upstream", "aliases"] {
        if let Some(Value::List(l)) = v.get(k) {
            if let Some(c) = l.iter().filter_map(|x| x.as_str()).find(|x| x.starts_with("CVE-")) {
                if cve.is_empty() {
                    cve = c.to_string();
                }
            }
        }
    }
    let (mut cvss, mut av) = (0.0, String::new());
    if let Some(Value::List(l)) = v.get("severity") {
        for s in l {
            if let Some(vec) = s.get("score").and_then(|x| x.as_str()) {
                if let Some(a) = vec.split('/').find_map(|p| p.strip_prefix("AV:")) {
                    av = a.chars().next().map(String::from).unwrap_or_default();
                }
                if let Some(sc) = cvss_score(vec) {
                    cvss = f64::max(cvss, sc);
                }
            }
        }
    }
    let mut urgency = String::new();
    let mut fixed: Option<String> = None;
    if let Some(Value::List(aff)) = v.get("affected") {
        for a in aff {
            let p = a.get("package");
            let pe = p.and_then(|x| x.get("ecosystem")).and_then(|x| x.as_str()).unwrap_or("");
            let pn = p.and_then(|x| x.get("name")).and_then(|x| x.as_str()).unwrap_or("");
            if pn != name || !(pe == eco || (eco == "Debian" && pe == DEBIAN)) {
                continue;
            }
            if eco == "Debian" && pe != DEBIAN {
                continue;
            }
            if let Some(u) = a.get("ecosystem_specific").and_then(|x| x.get("urgency")).and_then(|x| x.as_str()) {
                urgency = u.to_string();
            }
            if let Some(Value::List(rs)) = a.get("ranges") {
                for r in rs {
                    if let Some(Value::List(evs)) = r.get("events") {
                        for e in evs {
                            if let Some(f) = e.get("fixed").and_then(|x| x.as_str()) {
                                fixed = Some(f.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    let summary = v.get("summary").and_then(|x| x.as_str()).or_else(|| v.get("details").and_then(|x| x.as_str())).unwrap_or("");
    let summary: String = summary.chars().take(240).collect();
    // Debian исправления ещё не указал — берём upstream-версию из описания
    // («OpenSSH before 10.4», «prior to version 2.11»)
    let fixed = fixed.or_else(|| {
        let full = format!("{} {}", v.get("summary").and_then(|x| x.as_str()).unwrap_or(""), v.get("details").and_then(|x| x.as_str()).unwrap_or(""));
        fixed_from_text(&full)
    });
    VulnInfo { cve, cvss, av, urgency, fixed, summary }
}

/// «… through 8.3p1», «4.6 and earlier», «up to 2.1» → последняя уязвимая версия.
pub fn last_affected_from_text(t: &str) -> Option<String> {
    let w: Vec<&str> = t.split_whitespace().collect();
    let ver = |x: &str| -> Option<String> {
        let x = x.trim_start_matches(['v', 'V']).trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        (x.chars().next().map_or(false, |c| c.is_ascii_digit()) && x.contains('.')).then(|| x.to_string())
    };
    // «In OpenSSH 7.9, due to …» — речь об одной версии
    if w.len() > 3 && w[0].eq_ignore_ascii_case("in") && w[2].ends_with(',') {
        if let Some(v) = ver(w[2]) {
            return Some(v);
        }
    }
    for i in 0..w.len() {
        let l = w[i].to_ascii_lowercase();
        if l == "through" || (l == "up" && w.get(i + 1).map_or(false, |x| x.eq_ignore_ascii_case("to"))) {
            let j = if l == "up" { i + 2 } else { i + 1 };
            if let Some(v) = w.get(j).and_then(|x| ver(x)) {
                return Some(v);
            }
        }
        if w.get(i + 1).map_or(false, |x| x.eq_ignore_ascii_case("and")) && w.get(i + 2).map_or(false, |x| x.to_ascii_lowercase().starts_with("earlier")) {
            if let Some(v) = ver(w[i]) {
                return Some(v);
            }
        }
    }
    None
}

/// Запись не про нашу версию: в описании последняя уязвимая версия старше нашей.
fn past_last_affected(ours: &str, text: &str) -> bool {
    last_affected_from_text(text).map_or(false, |la| vcmp(ours, &la) == std::cmp::Ordering::Greater)
}

/// «… before 10.4 …», «prior to version 2.11.1» → версия, где исправлено.
pub fn fixed_from_text(t: &str) -> Option<String> {
    let w: Vec<&str> = t.split_whitespace().collect();
    for i in 0..w.len() {
        let after = match (w[i].to_ascii_lowercase().as_str(), w.get(i + 1).map(|x| x.to_ascii_lowercase())) {
            ("before", _) => i + 1,
            ("prior", Some(n)) if n == "to" => i + 2,
            _ => continue,
        };
        let mut j = after;
        if w.get(j).map_or(false, |x| x.eq_ignore_ascii_case("version") || x.eq_ignore_ascii_case("versions")) {
            j += 1;
        }
        let Some(tok) = w.get(j) else { continue };
        let tok = tok.trim_start_matches(['v', 'V']).trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        if tok.chars().next().map_or(false, |c| c.is_ascii_digit()) && tok.contains('.') {
            return Some(tok.to_string());
        }
    }
    None
}

/// Базовый балл CVSS 3.x по вектору (без временных метрик).
pub fn cvss_score(vec: &str) -> Option<f64> {
    if !vec.starts_with("CVSS:3") {
        return None;
    }
    let m: HashMap<&str, &str> = vec.split('/').skip(1).filter_map(|p| p.split_once(':')).collect();
    let av: f64 = match *m.get("AV")? { "N" => 0.85, "A" => 0.62, "L" => 0.55, _ => 0.2 };
    let ac = match *m.get("AC")? { "L" => 0.77, _ => 0.44 };
    let changed = *m.get("S")? == "C";
    let pr = match (*m.get("PR")?, changed) { ("N", _) => 0.85, ("L", false) => 0.62, ("L", true) => 0.68, ("H", false) => 0.27, _ => 0.5 };
    let ui = match *m.get("UI")? { "N" => 0.85, _ => 0.62 };
    let cia = |k: &str| -> f64 { match m.get(k).copied() { Some("H") => 0.56, Some("L") => 0.22, _ => 0.0 } };
    let iss: f64 = 1.0 - (1.0 - cia("C")) * (1.0 - cia("I")) * (1.0 - cia("A"));
    let impact: f64 = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let expl: f64 = 8.22 * av * ac * pr * ui;
    let base = if changed { (1.08 * (impact + expl)).min(10.0) } else { (impact + expl).min(10.0) };
    Some((base * 10.0).ceil() / 10.0)
}

/// CVE из KEV (кеш на неделю в /tmp/cgmon).
fn kev_set() -> Result<BTreeSet<String>, String> {
    let cache = format!("{}/kev.json", crate::util::RUN_DIR);
    let fresh = std::fs::metadata(&cache).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).map_or(false, |d| d.as_secs() < 7 * 86400);
    let text = if fresh {
        std::fs::read_to_string(&cache).unwrap_or_default()
    } else {
        let t = http_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev", 60)
            .or_else(|_| http_get("https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json", "kev", 60))?;
        let _ = crate::util::write_atomic(&cache, t.as_bytes(), 0o644);
        t
    };
    // без разбора всего JSON: только значения "cveID"
    let mut set = BTreeSet::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find("\"cveID\"") {
        rest = &rest[i + 7..];
        if let Some(s) = rest.find("CVE-") {
            let c: String = rest[s..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
            set.insert(c);
        }
    }
    Ok(set)
}

/// EPSS по списку CVE (пачками по 100).
fn epss(cves: &[String]) -> HashMap<String, f64> {
    let mut m = HashMap::new();
    for ch in cves.chunks(100) {
        let url = format!("https://api.first.org/data/v1/epss?cve={}", ch.join(","));
        if let Ok(t) = http_get(&url, "epss", 40) {
            if let Ok(v) = crate::value::parse_json(&t) {
                if let Some(Value::List(l)) = v.get("data") {
                    for x in l {
                        let c = x.get("cve").and_then(|y| y.as_str()).unwrap_or("");
                        let e = x.get("epss").and_then(|y| y.as_str().and_then(|s| s.parse::<f64>().ok()).or(y.as_f64())).unwrap_or(0.0);
                        m.insert(c.to_string(), e);
                    }
                }
            }
        }
    }
    m
}

/// Важность находки по CVE. «Критично» — только служба, доступная из интернета, с
/// уязвимостью, эксплуатируемой по сети, и при этом уже атакуемая (KEV), вероятная
/// (EPSS ≥ 10 %) или с CVSS ≥ 9. Всё, что атакуется лишь из LAN или с самого роутера
/// (клиентские библиотеки, локальные службы), — не выше «серьёзно».
/// «maybe» (Debian исправил патчем в той же версии) — не выше «средне».
pub fn cve_sev(kev: bool, epss: f64, cvss: f64, av: &str, urgency: &str, state: &str, exposed: bool) -> &'static str {
    if urgency == "unimportant" && !kev {
        return "low";
    }
    let remote = av == "N" || av.is_empty();
    let outside = exposed && remote;
    let sev = if outside && (kev || epss >= 0.1 || cvss >= 9.0) {
        "crit"
    } else if kev || epss >= 0.1 || (outside && cvss >= 7.0) || (remote && cvss >= 9.0) || epss >= 0.02 {
        "high"
    } else if (remote && cvss >= 7.0) || epss >= 0.005 {
        "med"
    } else {
        "low"
    };
    let cap = |s: &'static str, max: &'static str| -> &'static str {
        let r = |x: &str| match x { "crit" => 0, "high" => 1, "med" => 2, _ => 3 };
        if r(s) < r(max) { max } else { s }
    };
    let sev = if urgency == "low" { cap(sev, "high") } else { sev };
    if state == "maybe" { cap(sev, "med") } else { sev }
}

/// Не выше «серьёзно», если не видно из интернета.
fn cap_unexposed(sev: &str, exposed: bool) -> String {
    if sev == "crit" && !exposed { "high".into() } else { sev.into() }
}

// ======================= что видно из интернета =======================

#[derive(Default, Debug)]
pub struct Exposure {
    /// зона wan принимает всё входящее
    pub all: bool,
    /// порты роутера, открытые правилами для wan
    pub ports: BTreeSet<u16>,
    /// проброс из интернета: адрес LAN, порт
    pub forwards: Vec<(IpAddr, u16)>,
    /// пакет → его порты, на которых он слушает и которые видны из интернета
    pub pkgs: BTreeMap<String, BTreeSet<u16>>,
}

fn port_list(spec: &str) -> Vec<u16> {
    let mut v = Vec::new();
    for p in spec.split([' ', ',']).filter(|x| !x.is_empty()) {
        match p.split_once(['-', ':']) {
            Some((a, b)) => {
                let (a, b): (u16, u16) = (a.parse().unwrap_or(0), b.parse().unwrap_or(0));
                if a > 0 && b >= a && b - a <= 1024 {
                    v.extend(a..=b);
                }
            }
            None => {
                if let Ok(n) = p.parse() {
                    v.push(n);
                }
            }
        }
    }
    v
}

/// Слушающие сокеты не на loopback: (порт, inode).
fn listeners() -> Vec<(u16, u64)> {
    let mut v = Vec::new();
    for (file, tcp) in [("/proc/net/tcp", true), ("/proc/net/tcp6", true), ("/proc/net/udp", false), ("/proc/net/udp6", false)] {
        for l in std::fs::read_to_string(file).unwrap_or_default().lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() < 10 || (tcp && c[3] != "0A") {
                continue;
            }
            let Some((addr, port)) = c[1].split_once(':') else { continue };
            // 127.0.0.1 и ::1 — не наружу
            if addr == "0100007F" || addr == "00000000000000000000000001000000" {
                continue;
            }
            v.push((u16::from_str_radix(port, 16).unwrap_or(0), c[9].parse().unwrap_or(0)));
        }
    }
    v
}

pub fn exposure() -> Exposure {
    let mut e = Exposure::default();
    let fw = uci_sections("firewall");
    e.all = fw.iter().any(|s| s.1 == "zone" && s.2.get("name").map_or(false, |n| n == "wan") && s.2.get("input").map_or(false, |x| x == "ACCEPT"));
    for s in fw.iter() {
        let o = &s.2;
        if o.get("src").map_or(true, |x| x != "wan") || o.get("enabled").map_or(false, |x| x == "0") {
            continue;
        }
        if s.1 == "rule" && !o.contains_key("dest") && o.get("target").map_or(false, |x| x == "ACCEPT") {
            for p in port_list(o.get("dest_port").map(|x| x.as_str()).unwrap_or("")) {
                if p != 68 && p != 546 {
                    e.ports.insert(p);
                }
            }
        }
        if s.1 == "redirect" && o.get("target").map_or(true, |x| x == "DNAT") {
            if let Some(ip) = o.get("dest_ip").and_then(|x| x.parse::<IpAddr>().ok()) {
                for p in port_list(o.get("dest_port").or(o.get("src_dport")).map(|x| x.as_str()).unwrap_or("")) {
                    e.forwards.push((ip, p));
                }
            }
        }
    }
    // слушающие сокеты, видимые из интернета → процесс → пакет
    let open: Vec<(u16, u64)> = listeners().into_iter().filter(|(p, _)| e.all || e.ports.contains(p)).collect();
    if open.is_empty() {
        return e;
    }
    let want: HashMap<u64, u16> = open.iter().map(|(p, i)| (*i, *p)).collect();
    let owners = file_owners();
    for d in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(fds) = std::fs::read_dir(d.path().join("fd")) else { continue };
        let mut ports: Vec<u16> = Vec::new();
        for fd in fds.flatten() {
            if let Ok(l) = std::fs::read_link(fd.path()) {
                let l = l.to_string_lossy();
                if let Some(n) = l.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')).and_then(|x| x.parse::<u64>().ok()) {
                    if let Some(p) = want.get(&n) {
                        ports.push(*p);
                    }
                }
            }
        }
        if ports.is_empty() {
            continue;
        }
        let exe = std::fs::read_link(d.path().join("exe")).map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string()).unwrap_or_default();
        let pkg = owners.get(&exe).cloned().unwrap_or_else(|| exe.clone());
        e.pkgs.entry(pkg).or_default().extend(ports);
    }
    e
}

// ======================= проверка =======================

fn run(now: i64, input: &Input, tx: &Sender<Msg>) -> Report {
    let t0 = std::time::Instant::now();
    let phase = |p: &str| {
        let _ = tx.send(Msg::Phase(p.to_string()));
    };
    let mut r = Report { at: now, pkg_sig: pkg_sig(), ..Default::default() };
    phase("config");
    let exp = exposure();
    r.findings.extend(check_config(&exp));
    phase("packages");
    let pkgs = inventory();
    r.packages = pkgs.len();
    r.kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
    // исходник → версия (один раз на исходник)
    let mut srcs: BTreeMap<String, String> = BTreeMap::new();
    for p in &pkgs {
        srcs.entry(p.origin.clone()).or_insert_with(|| p.version.clone());
    }
    let mut queries: Vec<(String, String, String)> = Vec::new();
    let mut qsrc: Vec<String> = Vec::new();
    for (o, v) in &srcs {
        if let Some((eco, name, ver)) = osv_target(o, v) {
            queries.push((if eco == "Debian" { DEBIAN.to_string() } else { eco.to_string() }, name, ver));
            qsrc.push(o.clone());
        }
    }
    // программы, запущенные не из пакетов (известные — тоже в OSV)
    phase("binaries");
    for (path, eco, module, ver) in unpackaged() {
        match (eco, module, ver) {
            (Some(e), Some(m), Some(v)) => {
                queries.push((e.to_string(), m.to_string(), v));
                qsrc.push(path);
            }
            _ => r.findings.push(Finding { sev: "info".into(), area: "pkg".into(), code: "unpackaged".into(), target: path, ..Default::default() }),
        }
    }
    let kver = upstream(&r.kernel);
    let kidx = queries.len();
    if !kver.is_empty() {
        queries.push((DEBIAN.to_string(), "linux".into(), format!("{kver}-0")));
        qsrc.push("kernel".into());
    }
    // собственные пакеты OpenWrt и LuCI — их трекер безопасности (GitHub advisories)
    phase("openwrt");
    match openwrt_advisories(&pkgs) {
        Ok(v) => r.findings.extend(v),
        Err(e) => r.errors.push(e),
    }
    // свежий cgmon
    if let Some(f) = cgmon_update_finding() {
        r.findings.push(f);
    }
    phase("osv");
    let ids = match osv_ids(&queries) {
        Ok(x) => x,
        Err(e) => {
            r.errors.push(e);
            r.took_ms = t0.elapsed().as_millis() as i64;
            if input.lan {
                phase("lan");
                r.findings.extend(check_lan(input, &exp));
            }
            return r;
        }
    };
    phase("kev");
    let kev = kev_set().unwrap_or_else(|e| {
        r.errors.push(format!("KEV: {e}"));
        BTreeSet::new()
    });
    // пакеты (не ядро): подробности по каждой записи
    phase("details");
    let mut details = 0;
    let mut upstream_n = 0;
    let mut pkg_found: Vec<Finding> = Vec::new();
    for (i, list) in ids.iter().enumerate() {
        if i == kidx {
            continue;
        }
        let (eco, name, qver) = &queries[i];
        let ours = upstream(qver);
        for id in list {
            if details >= MAX_DETAILS {
                break;
            }
            details += 1;
            let Ok(v) = osv_vuln(id) else { continue };
            let eco_short = if eco.starts_with("Debian") { "Debian" } else { eco.as_str() };
            let mut info = vuln_info(&v, eco_short, name);
            if info.fixed.is_none() && info.cve.starts_with("CVE-") && upstream_n < MAX_UPSTREAM {
                upstream_n += 1;
                match upstream_verdict(&info.cve, &ours, name) {
                    Some((false, _)) => continue, // по данным апстрима наша версия не затронута
                    Some((true, Some(f))) => info.fixed = Some(f),
                    _ => {}
                }
            }
            if info.fixed.is_none() && past_last_affected(&ours, &format!("{} {}", info.summary, v.get("details").and_then(|x| x.as_str()).unwrap_or(""))) {
                continue;
            }
            let state = match &info.fixed {
                Some(f) => match vcmp(&ours, &upstream(f)) {
                    std::cmp::Ordering::Less => "fixed",
                    std::cmp::Ordering::Equal => "maybe",
                    std::cmp::Ordering::Greater => continue, // наша версия новее исправления
                },
                None => "open",
            };
            pkg_found.push(Finding { area: "pkg".into(), code: "cve".into(), target: qsrc[i].clone(), cve: info.cve, osv: id.clone(), version: qver.trim_start_matches('v').split(':').last().unwrap_or("").trim_end_matches("-0").trim_end_matches("+incompatible").to_string(), fixed: info.fixed.map(|f| upstream(&f)).unwrap_or_default(), cvss: info.cvss, av: info.av, urgency: info.urgency, state: state.into(), summary: info.summary, ..Default::default() });
        }
    }
    // ядро: номера → KEV/EPSS → подробности для отобранных
    let mut kernel_found: Vec<Finding> = Vec::new();
    if let Some(klist) = ids.get(kidx).filter(|_| kidx < ids.len()) {
        r.kernel_total = klist.len();
        let kcves: Vec<String> = klist.iter().map(|x| x.trim_start_matches("DEBIAN-").to_string()).filter(|x| x.starts_with("CVE-")).collect();
        phase("epss");
        let ke = epss(&kcves);
        let mut short: Vec<(String, f64, bool)> = kcves.iter().map(|c| (c.clone(), ke.get(c).copied().unwrap_or(0.0), kev.contains(c))).filter(|(_, e, k)| *k || *e >= EPSS_SHORTLIST).collect();
        short.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)));
        short.truncate(KERNEL_DETAILS);
        phase("kernel");
        for (c, e, k) in &short {
            let id = format!("DEBIAN-{c}");
            let Ok(v) = osv_vuln(&id) else { continue };
            let info = vuln_info(&v, "Debian", "linux");
            let state = match &info.fixed {
                Some(f) => match vcmp(&kver, &upstream(f)) {
                    std::cmp::Ordering::Less => "fixed",
                    std::cmp::Ordering::Equal => "maybe",
                    std::cmp::Ordering::Greater => continue,
                },
                None => "open",
            };
            kernel_found.push(Finding { area: "kernel".into(), code: "cve".into(), target: "linux".into(), cve: c.clone(), osv: id, version: kver.clone(), fixed: info.fixed.map(|f| upstream(&f)).unwrap_or_default(), cvss: info.cvss, av: info.av, urgency: info.urgency, epss: *e, kev: *k, state: state.into(), summary: info.summary, ..Default::default() });
        }
        r.kernel_hidden = r.kernel_total.saturating_sub(kernel_found.len());
    }
    // EPSS для пакетов, KEV — для всех
    phase("epss");
    let pc: Vec<String> = pkg_found.iter().filter(|f| !f.cve.is_empty()).map(|f| f.cve.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let pe = epss(&pc);
    for f in pkg_found.iter_mut().chain(kernel_found.iter_mut()) {
        if let Some(e) = pe.get(&f.cve) {
            f.epss = *e;
        }
        f.kev = kev.contains(&f.cve);
        mark_exposed(f, &pkgs, &exp);
        f.sev = cve_sev(f.kev, f.epss, f.cvss, &f.av, &f.urgency, &f.state, f.exposed).into();
    }
    // кнопки: обновление пакета (если в индексе есть новее), ядро — прошивкой
    phase("updates");
    let upg = upgradable();
    for f in pkg_found.iter_mut() {
        attach_upgrade(f, &pkgs, &upg);
    }
    for f in r.findings.iter_mut().filter(|f| f.area == "openwrt") {
        attach_upgrade(f, &pkgs, &upg);
        mark_exposed(f, &pkgs, &exp);
        f.sev = cap_unexposed(&f.sev, f.exposed && (f.av == "N" || f.av.is_empty()));
    }
    for f in kernel_found.iter_mut() {
        f.action = "sysupgrade".into();
    }
    let mut merged: Vec<Finding> = Vec::new();
    for f in pkg_found {
        match merged.iter_mut().find(|m| !f.cve.is_empty() && m.cve == f.cve && m.version == f.version) {
            Some(m) => {
                if !m.target.split(", ").any(|t| t == f.target) {
                    m.target = format!("{}, {}", m.target, f.target);
                }
                for p in f.pkgs {
                    if !m.pkgs.contains(&p) {
                        m.pkgs.push(p);
                    }
                }
            }
            None => merged.push(f),
        }
    }
    r.findings.extend(merged);
    r.findings.extend(kernel_found);
    if input.lan {
        phase("lan");
        r.findings.extend(check_lan(input, &exp));
    }
    let rank = |s: &str| match s { "crit" => 0, "high" => 1, "med" => 2, "low" => 3, _ => 4 };
    r.findings.sort_by(|a, b| rank(&a.sev).cmp(&rank(&b.sev)).then(b.kev.cmp(&a.kev)).then(b.epss.partial_cmp(&a.epss).unwrap_or(std::cmp::Ordering::Equal)).then(b.cvss.partial_cmp(&a.cvss).unwrap_or(std::cmp::Ordering::Equal)));
    r.took_ms = t0.elapsed().as_millis() as i64;
    r
}

/// Видна ли служба пакета из интернета: его процесс слушает открытый для wan порт.
/// Ядро обрабатывает всё, что приходит с WAN, — его сетевые уязвимости видны снаружи.
fn mark_exposed(f: &mut Finding, pkgs: &[Pkg], exp: &Exposure) {
    if f.area == "kernel" {
        f.exposed = f.av == "N" || f.av.is_empty();
        return;
    }
    let names: Vec<String> = pkgs.iter().filter(|p| f.target.split(", ").any(|t| t == p.origin) || f.pkgs.contains(&p.name)).map(|p| p.name.clone()).collect();
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for n in names.iter().chain(f.target.split(", ").map(|t| t.to_string()).collect::<Vec<_>>().iter()) {
        if let Some(p) = exp.pkgs.get(n) {
            ports.extend(p.iter().copied());
        }
    }
    f.exposed = !ports.is_empty();
    f.ports = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
}

// ======================= настройки роутера =======================

fn uci_show(cfg: &str) -> Vec<(String, String)> {
    let t = crate::flowwatch::output_timeout("uci", &["-q", "show", cfg], 5000).unwrap_or_default();
    t.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.trim_matches('\'').to_string())).collect()
}

/// Секции uci: имя секции → (тип, опции).
fn uci_sections(cfg: &str) -> Vec<(String, String, HashMap<String, String>)> {
    let mut secs: Vec<(String, String, HashMap<String, String>)> = Vec::new();
    for (k, v) in uci_show(cfg) {
        let parts: Vec<&str> = k.splitn(3, '.').collect();
        match parts.len() {
            2 => secs.push((parts[1].to_string(), v, HashMap::new())),
            3 => {
                if let Some(s) = secs.iter_mut().rev().find(|s| s.0 == parts[1]) {
                    s.2.insert(parts[2].to_string(), v);
                }
            }
            _ => {}
        }
    }
    secs
}

fn f(sev: &str, code: &str, target: &str, args: &[&str]) -> Finding {
    Finding { sev: sev.into(), area: "cfg".into(), code: code.into(), target: target.into(), args: args.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

/// Порты, на которых что-то слушает (TCP: LISTEN; UDP: любое), с адресом привязки.
fn listening() -> Vec<(String, u16, bool)> {
    let mut v = Vec::new();
    for (file, tcp) in [("/proc/net/tcp", true), ("/proc/net/tcp6", true), ("/proc/net/udp", false), ("/proc/net/udp6", false)] {
        for l in std::fs::read_to_string(file).unwrap_or_default().lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() < 4 || (tcp && c[3] != "0A") {
                continue;
            }
            let Some((addr, port)) = c[1].split_once(':') else { continue };
            let port = u16::from_str_radix(port, 16).unwrap_or(0);
            let any = addr.bytes().all(|b| b == b'0');
            v.push((addr.to_string(), port, any && tcp));
        }
    }
    v
}

pub fn check_config(exp: &Exposure) -> Vec<Finding> {
    let mut out = Vec::new();
    // пароль root
    if let Ok(sh) = std::fs::read_to_string("/etc/shadow") {
        if let Some(l) = sh.lines().find(|l| l.starts_with("root:")) {
            let h = l.split(':').nth(1).unwrap_or("");
            if h.is_empty() {
                // без пароля root — критично, только если SSH или LuCI открыты из интернета
                let outside = exp.all || exp.ports.iter().any(|p| matches!(p, 22 | 80 | 443));
                let mut x = f(if outside { "crit" } else { "high" }, "root_nopass", "root", &[]);
                x.exposed = outside;
                out.push(x);
            }
        }
    }
    let fw = uci_sections("firewall");
    // зона WAN: входящие и пересылка
    let wan_zones: Vec<&(String, String, HashMap<String, String>)> = fw.iter().filter(|s| s.1 == "zone" && s.2.get("name").map_or(false, |n| n == "wan")).collect();
    for z in &wan_zones {
        for (opt, code) in [("input", "wan_input_accept"), ("forward", "wan_forward_accept")] {
            if z.2.get(opt).map_or(false, |x| x == "ACCEPT") {
                let mut x = f("crit", code, "wan", &[]);
                x.exposed = true;
                out.push(x);
            }
        }
    }
    // правила, открывающие порты роутера из интернета
    let mut open_wan: BTreeSet<String> = BTreeSet::new();
    for s in fw.iter().filter(|s| s.1 == "rule") {
        let o = &s.2;
        if o.get("src").map_or(true, |x| x != "wan") || o.contains_key("dest") || o.get("target").map_or(true, |x| x != "ACCEPT") || o.get("enabled").map_or(false, |x| x == "0") {
            continue;
        }
        if let Some(p) = o.get("dest_port") {
            for port in p.split([' ', ',']).filter(|x| !x.is_empty()) {
                open_wan.insert(port.to_string());
            }
        }
    }
    let listen: Vec<u16> = listening().iter().map(|x| x.1).collect();
    for p in &open_wan {
        let n: u16 = p.split('-').next().unwrap_or("").parse().unwrap_or(0);
        // штатные правила OpenWrt: DHCP/DHCPv6-клиент
        if n == 0 || n == 68 || n == 546 || !listen.contains(&n) {
            continue;
        }
        let (sev, svc) = match n {
            23 => ("crit", "telnet"),
            22 => ("high", "ssh"),
            80 | 443 | 8080 => ("high", "web"),
            53 => ("high", "dns"),
            21 => ("high", "ftp"),
            445 | 139 => ("crit", "smb"),
            1900 | 5000 => ("high", "upnp"),
            _ => ("med", "other"),
        };
        let mut x = f(sev, "open_wan", p, &[svc]);
        x.exposed = true;
        x.ports = p.clone();
        out.push(x);
    }
    // проброс портов из интернета в LAN
    for s in fw.iter().filter(|s| s.1 == "redirect") {
        let o = &s.2;
        if o.get("src").map_or(true, |x| x != "wan") || o.get("enabled").map_or(false, |x| x == "0") || o.get("target").map_or(false, |x| x != "DNAT") {
            continue;
        }
        let ext = o.get("src_dport").cloned().unwrap_or_default();
        let to = format!("{}:{}", o.get("dest_ip").cloned().unwrap_or_default(), o.get("dest_port").cloned().unwrap_or_else(|| ext.clone()));
        let n: u16 = o.get("dest_port").or(o.get("src_dport")).and_then(|x| x.split('-').next()).and_then(|x| x.parse().ok()).unwrap_or(0);
        let sev = match n { 23 | 445 | 139 | 3389 | 5900 | 21 => "high", _ => "med" };
        let mut x = f(sev, "port_forward", &ext, &[&to, o.get("name").map(|s| s.as_str()).unwrap_or("")]);
        x.exposed = true;
        x.ports = ext.clone();
        out.push(x);
    }
    // SSH (dropbear): вход по паролю, на каких интерфейсах
    for s in uci_sections("dropbear").iter().filter(|s| s.1 == "dropbear") {
        let o = &s.2;
        if o.get("enable").map_or(false, |x| x == "0") {
            continue;
        }
        let pass = o.get("PasswordAuth").map_or(true, |x| x == "on" || x == "1");
        let root_pass = o.get("RootPasswordAuth").map_or(true, |x| x == "on" || x == "1");
        let iface = o.get("Interface").cloned().unwrap_or_default();
        let port = o.get("Port").cloned().unwrap_or_else(|| "22".into());
        if pass && root_pass {
            let wan = open_wan.contains(&port) || iface == "wan";
            out.push(f(if wan { "high" } else { "low" }, "ssh_password", &port, &[if iface.is_empty() { "*" } else { &iface }]));
        }
    }
    // telnet работает
    if listen.contains(&23) {
        out.push(f("high", "telnet_on", "23", &[]));
    }
    // LuCI только по http
    let uh = uci_sections("uhttpd");
    if !uh.is_empty() && !uh.iter().any(|s| s.2.contains_key("listen_https")) {
        out.push(f("low", "luci_http", "uhttpd", &[]));
    }
    // Wi-Fi
    let wl = uci_sections("wireless");
    for s in wl.iter().filter(|s| s.1 == "wifi-iface") {
        let o = &s.2;
        if o.get("disabled").map_or(false, |x| x == "1") || o.get("mode").map_or(false, |x| x != "ap") {
            continue;
        }
        let ssid = o.get("ssid").cloned().unwrap_or_default();
        let enc = o.get("encryption").cloned().unwrap_or_else(|| "none".into());
        let e = enc.as_str();
        if e == "none" || e.is_empty() {
            out.push(f("high", "wifi_open", &ssid, &[]));
        } else if e.starts_with("wep") {
            out.push(f("crit", "wifi_wep", &ssid, &[e]));
        } else if e == "psk" || e.starts_with("psk+") || e.contains("tkip") || e.starts_with("psk-mixed") {
            out.push(f("med", "wifi_weak", &ssid, &[e]));
        }
        if o.get("wps_pushbutton").map_or(false, |x| x == "1") || o.get("wps_label").map_or(false, |x| x == "1") {
            out.push(f("med", "wifi_wps", &ssid, &[]));
        }
        if (e.starts_with("psk") || e.starts_with("sae")) && o.get("key").map_or(false, |k| k.chars().count() < 12) {
            out.push(f("med", "wifi_short_key", &ssid, &[]));
        }
    }
    // UPnP
    if uci_sections("upnpd").iter().any(|s| s.1 == "upnpd" && s.2.get("enabled").map_or(false, |x| x == "1")) || listen.contains(&5351) {
        out.push(f("med", "upnp_on", "miniupnpd", &[]));
    }
    out
}

/// MAC в виде aa:bb:cc:dd:ee:ff; None — не MAC.
pub fn norm_mac(m: &str) -> Option<String> {
    let h: String = m.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_lowercase();
    if h.len() != 12 || m.chars().any(|c| !(c.is_ascii_hexdigit() || c == ':' || c == '-' || c == '.')) {
        return None;
    }
    Some((0..6).map(|i| &h[i * 2..i * 2 + 2]).collect::<Vec<_>>().join(":"))
}

/// nft: устройствам из списка — только частные сети (LAN, роутер), остальное отбрасывается
/// ещё до маршрутизации (prerouting, по MAC источника — смена IP не помогает).
pub fn iso_script(macs: &[String]) -> String {
    let mut b = String::from("add table inet cgmon_iso\ndelete table inet cgmon_iso\n");
    if macs.is_empty() {
        return b;
    }
    b.push_str("table inet cgmon_iso {\n");
    b.push_str(&format!("\tset mac {{ type ether_addr; elements = {{ {} }} }}\n", macs.join(", ")));
    b.push_str("\tset lan4 { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } }\n");
    b.push_str("\tset lan6 { type ipv6_addr; flags interval; elements = { fc00::/7, fe80::/10, ff00::/8 } }\n");
    b.push_str("\tchain pre {\n\t\ttype filter hook prerouting priority mangle - 5; policy accept;\n");
    b.push_str("\t\tether saddr @mac ip daddr != @lan4 counter drop\n");
    b.push_str("\t\tether saddr @mac ip6 daddr != @lan6 counter drop\n");
    b.push_str("\t}\n}\n");
    b
}

// ======================= устройства LAN =======================

const LAN_PORTS: &[u16] = &[21, 23, 80, 139, 445, 554, 3389, 5900, 8000, 8080, 34567, 37777];

fn connect(ip: IpAddr, port: u16) -> Option<TcpStream> {
    let s = TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(600)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(1200)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(1200)));
    Some(s)
}

fn read_some(s: &mut TcpStream, max: usize) -> String {
    use std::io::Read;
    let mut b = vec![0u8; max];
    let n = s.read(&mut b).unwrap_or(0);
    String::from_utf8_lossy(&b[..n]).into_owned()
}

fn lan_one(ip: IpAddr, name: &str, mac: &str, day_bytes: u64, forwarded: &[u16], clouds: &HashMap<IpAddr, Vec<String>>) -> Vec<Finding> {
    use std::io::Write;
    let mut out = Vec::new();
    let who = if name.is_empty() { ip.to_string() } else { format!("{name} ({ip})") };
    // порт проброшен из интернета — служба видна снаружи: опасное становится критичным
    let g = |_sev: &str, code: &str, port: u16, extra: &str| {
        let outside = forwarded.contains(&port);
        let sev = lan_sev(code, outside, "");
        Finding { sev: sev.into(), area: "lan".into(), code: code.into(), target: who.clone(), args: vec![port.to_string(), extra.to_string()], exposed: outside, ports: if outside { port.to_string() } else { String::new() }, mac: mac.to_string(), ..Default::default() }
    };
    let mut open_ports: Vec<u16> = Vec::new();
    for &p in LAN_PORTS {
        let Some(mut s) = connect(ip, p) else { continue };
        open_ports.push(p);
        match p {
            23 => out.push(g("med", "lan_telnet", p, "")),
            21 => {
                let b = read_some(&mut s, 200);
                out.push(g("low", "lan_ftp", p, b.lines().next().unwrap_or("").trim()));
            }
            139 | 445 => out.push(g("low", "lan_smb", p, "")),
            3389 => out.push(g("low", "lan_rdp", p, "")),
            5900 => {
                let b = read_some(&mut s, 32);
                out.push(g("low", "lan_vnc", p, b.trim()));
            }
            554 => {
                // RTSP: DESCRIBE без пароля — 200 значит, что видео открыто всем в сети
                let _ = s.write_all(format!("DESCRIBE rtsp://{ip}:554/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n").as_bytes());
                let b = read_some(&mut s, 300);
                if b.starts_with("RTSP/1.0 200") {
                    out.push(g("med", "lan_rtsp_open", p, ""));
                }
            }
            34567 => out.push(g("med", "lan_xmeye", p, "")),
            37777 => out.push(g("low", "lan_dahua", p, "")),
            8000 => out.push(g("low", "lan_hik_sdk", p, "")),
            80 | 8080 => {
                let _ = s.write_all(format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: cgmon\r\n\r\n").as_bytes());
                let b = read_some(&mut s, 1500);
                let status = b.lines().next().unwrap_or("").to_string();
                let server = b.lines().find_map(|l| l.strip_prefix("Server:").or_else(|| l.strip_prefix("server:"))).unwrap_or("").trim().to_string();
                // вход в веб-интерфейс по http — пароль идёт открытым текстом
                if status.contains(" 200") || status.contains(" 401") || status.contains(" 302") {
                    out.push(g("info", "lan_http", p, &server));
                }
            }
            _ => {}
        }
    }
    // камера/видеорегистратор: RTSP, XMEye, Dahua, Hikvision SDK — или производитель камер по MAC
    let cam_ports = open_ports.iter().any(|p| matches!(p, 554 | 34567 | 37777 | 8000));
    let cam_vendor = name.contains(crate::i18n::tr("камера"));
    if cam_ports || cam_vendor {
        let kind = if open_ports.iter().any(|p| matches!(p, 34567 | 37777)) { "dvr" } else { "camera" };
        // ходит ли в интернет: отвеченные соединения сейчас (conntrack) или трафик за сутки
        let dests = clouds.get(&ip).cloned().unwrap_or_default();
        let cloud = if !dests.is_empty() || day_bytes > 1_000_000 { "yes" } else { "no" };
        for f in out.iter_mut() {
            f.cloud = cloud.into();
            f.sev = lan_sev(&f.code, f.exposed, cloud).into();
        }
        let mut cam = Finding { area: "lan".into(), code: "lan_camera".into(), target: who.clone(), args: vec![kind.into(), open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "), dests.join(", "), (day_bytes / 1_000_000).to_string()], mac: mac.to_string(), action: "isolate".into(), cloud: cloud.into(), ..Default::default() };
        cam.sev = lan_sev("lan_camera", false, cloud).into();
        out.push(cam);
    }
    out
}

/// Куда устройства сейчас ходят в интернет (только соединения, на которые ответили):
/// до 5 адресов «ip:порт» на устройство. Таблица conntrack читается построчно и один раз
/// на всю проверку — на загруженном роутере в ней десятки мегабайт.
fn cloud_dests(ips: &BTreeSet<IpAddr>) -> HashMap<IpAddr, Vec<String>> {
    use std::io::BufRead;
    let mut m: HashMap<IpAddr, Vec<String>> = HashMap::new();
    if ips.is_empty() {
        return m;
    }
    let Ok(f) = std::fs::File::open("/proc/net/nf_conntrack") else { return m };
    for l in std::io::BufReader::new(f).lines().map_while(Result::ok) {
        if l.contains("[UNREPLIED]") {
            continue;
        }
        let field = |k: &str| l.split_whitespace().find_map(|w| w.strip_prefix(k));
        // первая пара — от устройства
        let (Some(src), Some(dst)) = (field("src=").and_then(|x| x.parse::<IpAddr>().ok()), field("dst=").and_then(|x| x.parse::<IpAddr>().ok())) else { continue };
        if !ips.contains(&src) || !crate::witness::public(&dst) {
            continue;
        }
        let v = m.entry(src).or_default();
        if v.len() >= 5 {
            continue;
        }
        let port = field("dport=").unwrap_or("");
        let e = if dst.is_ipv6() { format!("[{dst}]:{port}") } else { format!("{dst}:{port}") };
        if !v.contains(&e) {
            v.push(e);
        }
    }
    m
}

pub fn check_lan(input: &Input, exp: &Exposure) -> Vec<Finding> {
    let mut out = Vec::new();
    let ips: BTreeSet<IpAddr> = input.lan_devices.iter().take(96).map(|d| d.0).collect();
    let clouds = cloud_dests(&ips);
    for (ip, name, mac, day) in input.lan_devices.iter().take(96) {
        if input.own.contains(ip) || ip.is_loopback() {
            continue;
        }
        let fwd: Vec<u16> = exp.forwards.iter().filter(|(a, _)| a == ip).map(|(_, p)| *p).collect();
        out.extend(lan_one(*ip, name, mac, *day, &fwd, &clouds));
    }
    out
}

/// Важность находки устройства LAN по коду: из своей сети — не выше «средне»,
/// проброшено из интернета — на две ступени выше.
fn lan_sev(code: &str, exposed: bool, cloud: &str) -> &'static str {
    let mut base = match code {
        "lan_telnet" | "lan_xmeye" | "lan_rtsp_open" => "med",
        "lan_ftp" | "lan_smb" | "lan_rdp" | "lan_vnc" | "lan_dahua" | "lan_hik_sdk" => "low",
        "lan_camera" if cloud == "yes" => "med",
        _ => "info",
    };
    // камера/регистратор: сидит в облаке производителя — достать можно и снаружи (P2P,
    // облачный ID), на ступень выше; в интернет не ходит — только из своей сети, «низко»
    if code != "lan_camera" {
        match cloud {
            "yes" => base = match base { "med" => "high", "low" => "med", b => b },
            "no" => base = match base { "med" => "low", b => b },
            _ => {}
        }
    }
    match (exposed, base) {
        (true, "med") => "crit",
        (true, "low") => "high",
        (true, "info") => "med",
        (_, b) => b,
    }
}

/// Сохранённый отчёт — по нынешним правилам: версия исправления из описания (если
/// Debian её не дал) и шкала устройств LAN. true — что-то поменялось.
fn normalize(r: &mut Report) -> bool {
    let before = r.findings.len();
    let mut changed = false;
    r.findings.retain_mut(|f| {
        if f.code == "cve" && !f.fixed.is_empty() && !f.version.is_empty() && vcmp(&f.version, &f.fixed) != std::cmp::Ordering::Less {
            return false;
        }
        if f.area == "lan" {
            let s = lan_sev(&f.code, f.exposed, &f.cloud);
            if f.sev != s {
                f.sev = s.into();
                changed = true;
            }
        }
        if f.code == "cve" && f.fixed.is_empty() && !f.version.is_empty() && past_last_affected(&f.version, &f.summary) {
            return false;
        }
        if f.code == "cve" && f.fixed.is_empty() {
            if let Some(fx) = fixed_from_text(&f.summary) {
                f.fixed = fx;
                changed = true;
                if !f.version.is_empty() && vcmp(&f.version, &f.fixed) != std::cmp::Ordering::Less {
                    return false; // наша версия уже не старше исправления
                }
                f.state = "fixed".into();
            }
        }
        true
    });
    changed || r.findings.len() != before
}

/// Находки обновлённых пакетов — по новой версии: исправленное убрать, кнопку
/// «Обновить» снять, если новее уже не предлагается.
fn recheck_upgraded(r: &mut Report, vers: &[(String, String)]) {
    if vers.is_empty() {
        return;
    }
    let ver_of = |f: &Finding| -> Option<String> { vers.iter().find(|(n, _)| f.pkgs.contains(n)).map(|(_, v)| v.clone()) };
    r.findings.retain_mut(|f| {
        let Some(nv) = ver_of(f) else { return true };
        f.version = nv.clone();
        if !f.upgrade.is_empty() && vcmp(&nv, &f.upgrade) != std::cmp::Ordering::Less {
            f.upgrade.clear();
            if f.action == "pkg" {
                f.action.clear();
            }
        }
        // исправлено в этой или более ранней версии — находки больше нет
        !(!f.fixed.is_empty() && vcmp(&nv, &f.fixed) != std::cmp::Ordering::Less)
    });
}

// ======================= трекер OpenWrt =======================

fn openwrt_release() -> (String, String) {
    let t = std::fs::read_to_string("/etc/openwrt_release").unwrap_or_default();
    let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim_start_matches('=').trim_matches(['\'', '"']).to_string()).unwrap_or_default();
    (get("DISTRIB_RELEASE"), get("DISTRIB_ID"))
}

/// Дата сборки собственного пакета OpenWrt из версии: `2026.06.16~hash` → 20260616;
/// LuCI `25.346.37412~hash` → год+день года. 0 — не дата.
pub fn pkg_date(v: &str) -> u32 {
    let head = v.split('~').next().unwrap_or("");
    let p: Vec<u32> = head.split('.').filter_map(|x| x.parse().ok()).collect();
    match p.as_slice() {
        [y, m, d, ..] if *y >= 2000 && *m <= 12 && *d <= 31 => y * 10000 + m * 100 + d,
        [yy, doy, ..] if *yy >= 15 && *yy < 100 && *doy >= 1 && *doy <= 366 => {
            let y = 2000 + yy;
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let mut left = *doy;
            let mut m = 1;
            for days in [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] {
                if left <= days {
                    break;
                }
                left -= days;
                m += 1;
            }
            y * 10000 + m * 100 + left
        }
        _ => 0,
    }
}

/// Компонент из заголовка/имени пакета advisory → установленные пакеты.
fn component_pkgs(text: &str, pkgs: &[Pkg]) -> Vec<Pkg> {
    let alias = |w: &str| -> String {
        match w {
            "jsonpath" => "jsonfilter".into(),
            "mdnsd" => "umdns".into(),
            "ubusd" => "ubus".into(),
            "uhttpd" => "uhttpd".into(),
            x => x.into(),
        }
    };
    let words: Vec<String> = text.to_lowercase().split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')).filter(|w| w.len() >= 3).map(alias).collect();
    let mut out: Vec<Pkg> = Vec::new();
    for w in &words {
        if matches!(w.as_str(), "openwrt" | "luci" | "via" | "and" | "the" | "for" | "stack" | "buffer" | "heap" | "overflow" | "memory" | "leak" | "command" | "execution" | "bypass" | "local" | "root") {
            continue;
        }
        for p in pkgs.iter().filter(|p| p.origin == *w || p.name == *w) {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
    }
    out
}

/// GitHub Security Advisories репозиториев openwrt/openwrt и openwrt/luci.
fn openwrt_advisories(pkgs: &[Pkg]) -> Result<Vec<Finding>, String> {
    let (rel, _) = openwrt_release();
    let mut out = Vec::new();
    for repo in ["openwrt/openwrt", "openwrt/luci"] {
        let t = http_get(&format!("https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published"), "ghsa", 40)?;
        let Ok(Value::List(list)) = crate::value::parse_json(&t) else { continue };
        for a in &list {
            let s = |k: &str| a.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let summary = s("summary");
            let published = s("published_at");
            let pdate: u32 = published.get(0..10).map(|d| d.replace('-', "")).and_then(|d| d.parse().ok()).unwrap_or(0);
            let comp_text = summary.split(':').next().unwrap_or("").to_string();
            let vulns: Vec<&Value> = match a.get("vulnerabilities") { Some(Value::List(v)) => v.iter().collect(), _ => Vec::new() };
            let names = vulns.iter().filter_map(|v| v.get("package").and_then(|p| p.get("name")).and_then(|x| x.as_str())).collect::<Vec<_>>().join(" ");
            let comp = component_pkgs(&format!("{comp_text} {names}"), pkgs);
            // бюллетень про приложение LuCI (luci-app-…), которого на роутере нет, — не наш
            let luci_apps: Vec<String> = format!("{summary} {names}").to_lowercase().split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).filter(|w| w.starts_with("luci-app-") || w.starts_with("luci-mod-")).map(String::from).collect();
            if !luci_apps.is_empty() && !luci_apps.iter().any(|a| pkgs.iter().any(|p| p.name == *a || a.starts_with(&p.name))) {
                continue;
            }
            // ветка релиза: «< X» / «<= X» для той же ветки major.minor
            let branch = |v: &str| v.split('.').take(2).collect::<Vec<_>>().join(".");
            let mut by_release: Option<(bool, String)> = None; // (уязвим, исправлено в)
            if !rel.is_empty() && rel != "SNAPSHOT" {
                for v in &vulns {
                    let range = v.get("vulnerable_version_range").and_then(|x| x.as_str()).unwrap_or("");
                    let patched = v.get("patched_versions").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let (op, ver) = if let Some(x) = range.trim().strip_prefix("<=") { ("<=", x.trim()) } else if let Some(x) = range.trim().strip_prefix('<') { ("<", x.trim()) } else if let Some(x) = range.trim().strip_prefix('≤') { ("<=", x.trim()) } else { continue };
                    let ver = ver.split_whitespace().next().unwrap_or("");
                    if !ver.chars().next().map_or(false, |c| c.is_ascii_digit()) || branch(ver) != branch(&rel) {
                        continue;
                    }
                    let c = vcmp(&rel, ver);
                    let hit = if op == "<" { c == std::cmp::Ordering::Less } else { c != std::cmp::Ordering::Greater };
                    // «<= X»: исправленная версия неизвестна (X ещё уязвима)
                    by_release = Some((hit, if !patched.is_empty() { patched } else if op == "<" { ver.to_string() } else { String::new() }));
                }
            }
            let mentioned_release = vulns.iter().any(|v| v.get("vulnerable_version_range").and_then(|x| x.as_str()).map_or(false, |r| r.chars().any(|c| c.is_ascii_digit()) && r.contains('.') && !r.contains("commit")));
            let (state, fixed) = match &by_release {
                Some((true, fx)) => ("fixed", fx.clone()),
                Some((false, _)) => continue,
                None if mentioned_release => continue, // диапазоны только для других веток — наша новее
                None => {
                    // по коммиту/«main»: дата сборки пакета компонента против даты публикации
                    if comp.is_empty() {
                        continue;
                    }
                    let d = comp.iter().map(|p| pkg_date(&p.version)).max().unwrap_or(0);
                    if d != 0 && d >= pdate {
                        continue;
                    }
                    ("maybe", String::new())
                }
            };
            // компонент назван, но не установлен — не наш случай
            let comp_named = !comp_text.is_empty() && !comp_text.to_lowercase().contains("openwrt") && comp_text.split_whitespace().count() <= 3;
            if comp.is_empty() && comp_named && !matches!(comp_text.to_lowercase().as_str(), "luci" | "openwrt") {
                continue;
            }
            let sevmap = |x: &str| match x { "critical" => "crit", "high" => "high", "medium" | "moderate" => "med", _ => "low" };
            let mut sev = sevmap(&s("severity")).to_string();
            if state == "maybe" {
                sev = match sev.as_str() { "crit" => "high", "high" => "med", _ => "low" }.into();
            }
            let target = comp.first().map(|p| p.origin.clone()).unwrap_or_else(|| "openwrt".into());
            let cvss = a.get("cvss").and_then(|c| c.get("score")).and_then(|x| x.as_f64()).unwrap_or(0.0);
            let vec = a.get("cvss").and_then(|c| c.get("vector_string")).and_then(|x| x.as_str()).unwrap_or("");
            let av = vec.split('/').find_map(|p| p.strip_prefix("AV:")).unwrap_or("").chars().next().map(String::from).unwrap_or_default();
            out.push(Finding {
                sev,
                area: "openwrt".into(),
                code: "advisory".into(),
                target,
                cve: s("cve_id"),
                osv: s("ghsa_id"),
                version: if comp.is_empty() { rel.clone() } else { comp[0].version.clone() },
                fixed,
                cvss,
                av,
                state: state.into(),
                summary: summary.chars().take(240).collect(),
                url: s("html_url"),
                pkgs: comp.iter().map(|p| p.name.clone()).collect(),
                ..Default::default()
            });
        }
    }
    Ok(out)
}

// ======================= обновления =======================

/// Пакеты, для которых в индексе есть новее: имя → новая версия (обновляет индекс).
fn upgradable() -> HashMap<String, String> {
    let mut m = HashMap::new();
    if crate::util::have_bin("apk") {
        let _ = crate::flowwatch::output_timeout("apk", &["update", "-q"], 120_000);
        // «name-newver arch {origin} (lic) [upgradable from: name-oldver]»
        for p in parse_apk(&crate::flowwatch::output_timeout("apk", &["list", "-u"], 30_000).unwrap_or_default()) {
            m.insert(p.name, p.version);
        }
    } else if crate::util::have_bin("opkg") {
        let _ = crate::flowwatch::output_timeout("opkg", &["update"], 120_000);
        for l in crate::flowwatch::output_timeout("opkg", &["list-upgradable"], 30_000).unwrap_or_default().lines() {
            let c: Vec<&str> = l.split(" - ").collect();
            if c.len() == 3 {
                m.insert(c[0].trim().to_string(), strip_rel(c[2].trim()));
            }
        }
    }
    m
}

fn attach_upgrade(f: &mut Finding, pkgs: &[Pkg], upg: &HashMap<String, String>) {
    let names: Vec<String> = if f.pkgs.is_empty() { pkgs.iter().filter(|p| p.origin == f.target).map(|p| p.name.clone()).collect() } else { f.pkgs.clone() };
    let up: Vec<String> = names.iter().filter(|n| upg.contains_key(*n)).cloned().collect();
    if let Some(v) = up.first().and_then(|n| upg.get(n)) {
        f.upgrade = v.clone();
        f.action = "pkg".into();
        f.pkgs = up;
    } else {
        f.pkgs = names;
    }
}

/// Архитектура для файлов релиза cgmon.
fn release_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "x86" => "i686",
        "aarch64" => "aarch64",
        "arm" => if cfg!(target_feature = "v7") { "armv7" } else { "armv5te" },
        "mips" => "mips",
        _ => if cfg!(target_endian = "little") { "mipsel" } else { "mips" },
    }
}

const REPO: &str = "real4root/cgmon";

fn latest_release() -> Result<String, String> {
    let t = http_get(&format!("https://api.github.com/repos/{REPO}/releases/latest"), "rel", 30)?;
    let v = crate::value::parse_json(&t).map_err(|e| e.to_string())?;
    v.get("tag_name").and_then(|x| x.as_str()).map(|x| x.trim_start_matches('v').to_string()).ok_or_else(|| "tag_name".into())
}

fn cgmon_update_finding() -> Option<Finding> {
    let latest = latest_release().ok()?;
    if vcmp(&latest, crate::VERSION) != std::cmp::Ordering::Greater {
        return None;
    }
    Some(Finding { sev: "low".into(), area: "pkg".into(), code: "cgmon_update".into(), target: "cgmon".into(), version: crate::VERSION.into(), upgrade: latest, action: "self".into(), ..Default::default() })
}

/// Как установлен cgmon: apk | opkg | binary.
fn cgmon_install_kind() -> &'static str {
    if crate::util::have_bin("apk") && crate::flowwatch::output_timeout("apk", &["info", "-e", "cgmon", "cgmon-lite", "cgmon-nano"], 10_000).map_or(false, |o| !o.trim().is_empty()) {
        return "apk";
    }
    if std::path::Path::new("/usr/lib/opkg/info/cgmon.control").exists() || std::path::Path::new("/usr/lib/opkg/info/cgmon-lite.control").exists() || std::path::Path::new("/usr/lib/opkg/info/cgmon-nano.control").exists() {
        return "opkg";
    }
    "binary"
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn download(url: &str, to: &str) -> Result<(), String> {
    let (bin, kind) = crate::report::https_tool();
    let _ = std::fs::remove_file(to);
    match kind {
        "curl" => crate::flowwatch::output_timeout(bin, &["-s", "-f", "-L", "-m", "300", "-o", to, url], 310_000),
        "" => return Err(tr!("нет curl, uclient-fetch или wget").to_string()),
        _ => crate::flowwatch::output_timeout(bin, &["-q", "-T", "300", "-O", to, url], 310_000),
    };
    match std::fs::metadata(to) {
        Ok(m) if m.len() > 0 => Ok(()),
        _ => Err(format!("{url}: download failed")),
    }
}

/// Обновить cgmon из последнего релиза (в потоке): пакетом, если стоит пакетом, иначе
/// бинарником с проверкой SHA256; затем перезапуск службы.
pub fn self_update() -> Result<String, String> {
    let ver = latest_release()?;
    if vcmp(&ver, crate::VERSION) != std::cmp::Ordering::Greater {
        return Err(tr!("cgmon {} — уже последняя версия", crate::VERSION).to_string());
    }
    let arch = release_arch();
    let variant = crate::variant::name();
    let kind = cgmon_install_kind();
    let base = format!("https://github.com/{REPO}/releases/download/v{ver}");
    let pkgname = if variant == "full" { "cgmon".to_string() } else { format!("cgmon-{variant}") };
    let (asset, sums) = match kind {
        "apk" => (format!("{pkgname}-{ver}-r1-{arch}.apk"), "SHA256SUMS-APK+IPK"),
        "opkg" => (format!("{pkgname}_{ver}-1_{arch}.ipk"), "SHA256SUMS-APK+IPK"),
        _ => (format!("cgmon-{variant}-linux-{arch}"), "SHA256SUMS"),
    };
    let dir = crate::util::RUN_DIR;
    let _ = std::fs::create_dir_all(dir);
    let file = format!("{dir}/{asset}");
    download(&format!("{base}/{asset}"), &file)?;
    let sums_text = http_get(&format!("{base}/{sums}"), "sums", 30).or_else(|_| http_get(&format!("{base}/SHA256SUMS"), "sums", 30))?;
    let want = sums_text.lines().find(|l| l.split_whitespace().last().map_or(false, |n| n.trim_start_matches('*') == asset)).and_then(|l| l.split_whitespace().next()).map(|s| s.to_lowercase()).ok_or_else(|| tr!("в SHA256SUMS нет {}", asset).to_string())?;
    let got = sha256_hex(&std::fs::read(&file).map_err(|e| e.to_string())?);
    if got != want {
        let _ = std::fs::remove_file(&file);
        return Err(tr!("{}: контрольная сумма не совпала", asset).to_string());
    }
    match kind {
        "apk" => {
            let o = std::process::Command::new("apk").args(["add", "--allow-untrusted", &file]).output().map_err(|e| e.to_string())?;
            if !o.status.success() {
                return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
            }
        }
        "opkg" => {
            let o = std::process::Command::new("opkg").args(["install", "--force-reinstall", &file]).output().map_err(|e| e.to_string())?;
            if !o.status.success() {
                return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
            }
        }
        _ => {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755));
            let o = std::process::Command::new(&file).arg("--version").output().map_err(|e| e.to_string())?;
            if !String::from_utf8_lossy(&o.stdout).contains(&ver) {
                return Err(tr!("новый бинарник не запускается на этом роутере").to_string());
            }
            let me = std::env::current_exe().map_err(|e| e.to_string())?;
            let me = me.to_string_lossy().trim_end_matches(" (deleted)").to_string();
            let _ = std::fs::copy(&me, format!("{me}.{}.bak", crate::VERSION));
            let tmp = format!("{me}.new");
            std::fs::copy(&file, &tmp).map_err(|e| format!("{tmp}: {e}"))?;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
            std::fs::rename(&tmp, &me).map_err(|e| format!("{me}: {e}"))?;
        }
    }
    let _ = std::fs::remove_file(&file);
    // перезапуск службы — отдельным процессом, после ответа странице
    let _ = std::process::Command::new("/bin/sh").args(["-c", "sleep 3; /etc/init.d/cgmon restart"]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
    Ok(ver)
}

/// Обновить пакеты (apk/opkg upgrade); имена — только из установленных.
pub fn upgrade_pkgs(names: &[String]) -> Result<String, String> {
    let installed: BTreeSet<String> = inventory().into_iter().map(|p| p.name).collect();
    let names: Vec<&String> = names.iter().filter(|n| installed.contains(*n) && n.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.+".contains(&c))).collect();
    if names.is_empty() {
        return Err(tr!("нечего обновлять").to_string());
    }
    let apk = crate::util::have_bin("apk");
    space_check(&names, apk)?;
    let (bin, args): (&str, Vec<&str>) = if apk { ("apk", vec!["upgrade"]) } else { ("opkg", vec!["upgrade"]) };
    let mut cmd = std::process::Command::new(bin);
    cmd.args(&args);
    for n in &names {
        cmd.arg(n.as_str());
    }
    let o = cmd.output().map_err(|e| e.to_string())?;
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    if !o.status.success() {
        return Err(text.lines().last().unwrap_or("").trim().to_string());
    }
    Ok(names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
}

/// Свободное место (байт) на разделе, куда ставятся пакеты: overlay или корень.
fn free_bytes(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.f_bavail as u64 * st.f_frsize as u64)
}

fn pkg_root() -> &'static str {
    let m = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    if m.lines().any(|l| l.split_whitespace().nth(1) == Some("/overlay")) { "/overlay" } else { "/" }
}

/// Сколько места нужно: новые версии целиком, минус то, что освободят старые — но только
/// если старые лежат в overlay (пакет из прошивки /rom место не освобождает, его новая
/// версия ложится в overlay полностью). Плюс запас 10 % и не меньше 1 МБ.
pub fn space_need(new: &[(String, u64)], old_overlay: &HashMap<String, u64>) -> u64 {
    let total: u64 = new.iter().map(|(_, n)| *n).sum();
    let freed: u64 = new.iter().map(|(name, n)| old_overlay.get(name).copied().unwrap_or(0).min(*n)).sum();
    let net = total.saturating_sub(freed);
    // при замене файл пишется рядом и потом подменяет старый — на время нужен самый крупный пакет целиком
    let peak = new.iter().map(|(_, n)| *n).max().unwrap_or(0);
    let need = net.max(peak);
    need + (need / 10).max(1 << 20)
}

/// Хватит ли места на обновление: что именно поставится (с зависимостями), их размер,
/// свободное место. Не хватает — ошибка с цифрами, ничего не трогаем.
fn space_check(names: &[&String], apk: bool) -> Result<(), String> {
    let new: Vec<(String, u64)>;
    let mut old: HashMap<String, u64> = HashMap::new();
    let rom: BTreeSet<String>;
    if apk {
        // что поставится вместе с зависимостями
        let mut sim = vec!["add", "--simulate", "-u"];
        sim.extend(names.iter().map(|s| s.as_str()));
        let st = crate::flowwatch::output_timeout("apk", &sim, 60_000).unwrap_or_default();
        let mut todo: Vec<String> = Vec::new();
        for l in st.lines() {
            let w: Vec<&str> = l.split_whitespace().collect();
            if let Some(i) = w.iter().position(|x| *x == "Upgrading" || *x == "Installing") {
                if let Some(n) = w.get(i + 1) {
                    todo.push(n.to_string());
                }
            }
        }
        if todo.is_empty() {
            todo = names.iter().map(|s| s.to_string()).collect();
        }
        let mut q = vec!["query", "--from", "repositories", "--fields", "name,installed-size"];
        q.extend(todo.iter().map(|s| s.as_str()));
        let qt = crate::flowwatch::output_timeout("apk", &q, 60_000).unwrap_or_default();
        let mut sizes: HashMap<String, u64> = HashMap::new();
        let mut cur = String::new();
        for l in qt.lines() {
            if let Some(n) = l.strip_prefix("Name: ") {
                cur = n.trim().to_string();
            } else if let Some(v) = l.strip_prefix("Installed-Size: ") {
                let v: u64 = v.trim().parse().unwrap_or(0);
                let e = sizes.entry(cur.clone()).or_insert(0);
                *e = (*e).max(v);
            }
        }
        new = todo.iter().map(|n| (n.clone(), sizes.get(n).copied().unwrap_or(0))).collect();
        let db = |path: &str| -> HashMap<String, u64> {
            let mut m = HashMap::new();
            let mut p = String::new();
            for l in std::fs::read_to_string(path).unwrap_or_default().lines() {
                if let Some(x) = l.strip_prefix("P:") {
                    p = x.to_string();
                } else if let Some(x) = l.strip_prefix("I:") {
                    m.insert(p.clone(), x.parse().unwrap_or(0));
                }
            }
            m
        };
        old = db("/lib/apk/db/installed");
        rom = db("/rom/lib/apk/db/installed").into_keys().collect();
    } else {
        // opkg: размеры из списков репозиториев
        let mut sizes: HashMap<String, u64> = HashMap::new();
        for e in std::fs::read_dir("/var/opkg-lists").into_iter().flatten().flatten() {
            let mut p = String::new();
            for l in std::fs::read_to_string(e.path()).unwrap_or_default().lines() {
                if let Some(x) = l.strip_prefix("Package: ") {
                    p = x.trim().to_string();
                } else if let Some(x) = l.strip_prefix("Installed-Size: ").or_else(|| l.strip_prefix("Size: ")) {
                    let v: u64 = x.trim().parse().unwrap_or(0);
                    let e = sizes.entry(p.clone()).or_insert(0);
                    *e = (*e).max(v);
                }
            }
        }
        new = names.iter().map(|n| (n.to_string(), sizes.get(n.as_str()).copied().unwrap_or(0))).collect();
        rom = std::fs::read_to_string("/rom/usr/lib/opkg/status").unwrap_or_default().lines().filter_map(|l| l.strip_prefix("Package: ").map(|x| x.trim().to_string())).collect();
    }
    let old_overlay: HashMap<String, u64> = old.into_iter().filter(|(n, _)| !rom.contains(n)).collect();
    let need = space_need(&new, &old_overlay);
    let root = pkg_root();
    let Some(free) = free_bytes(root) else { return Ok(()) };
    if free < need {
        let mb = |b: u64| format!("{:.1}", b as f64 / 1048576.0);
        return Err(tr!("не хватает места на {}: нужно ≈ {} МБ, свободно {} МБ — ничего не обновлено", root, mb(need), mb(free)).to_string());
    }
    Ok(())
}

// ======================= программы вне пакетов =======================

/// Файлы, принадлежащие пакетам (apk db или opkg *.list).
/// Файл → пакет-владелец (apk db: P: — пакет, F: — каталог, R: — файл; opkg: *.list).
fn file_owners() -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(t) = std::fs::read_to_string("/lib/apk/db/installed") {
        let (mut pkg, mut dir) = (String::new(), String::new());
        for l in t.lines() {
            if let Some(p) = l.strip_prefix("P:") {
                pkg = p.to_string();
            } else if let Some(d) = l.strip_prefix("F:") {
                dir = d.to_string();
            } else if let Some(f) = l.strip_prefix("R:") {
                m.insert(format!("/{dir}/{f}"), pkg.clone());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir("/usr/lib/opkg/info") {
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().map_or(false, |x| x == "list") {
                let pkg = path.file_stem().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
                for l in std::fs::read_to_string(&path).unwrap_or_default().lines() {
                    m.insert(l.trim().to_string(), pkg.clone());
                }
            }
        }
    }
    m
}

fn packaged_files() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Ok(t) = std::fs::read_to_string("/lib/apk/db/installed") {
        let mut dir = String::new();
        for l in t.lines() {
            if let Some(d) = l.strip_prefix("F:") {
                dir = d.to_string();
            } else if let Some(f) = l.strip_prefix("R:") {
                set.insert(format!("/{dir}/{f}"));
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir("/usr/lib/opkg/info") {
        for e in rd.flatten() {
            if e.path().extension().map_or(false, |x| x == "list") {
                for l in std::fs::read_to_string(e.path()).unwrap_or_default().lines() {
                    set.insert(l.trim().to_string());
                }
            }
        }
    }
    set
}

/// Запущенные программы не из пакетов: (путь, экосистема, модуль, версия) — для
/// известных Go-программ версия берётся из самой программы.
fn unpackaged() -> Vec<(String, Option<&'static str>, Option<&'static str>, Option<String>)> {
    let pk = packaged_files();
    if pk.is_empty() {
        return Vec::new();
    }
    let me = std::env::current_exe().ok().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(exe) = std::fs::read_link(e.path().join("exe")) else { continue };
        // процесс в контейнере (своё пространство монтирования) — не программа роутера
        if std::fs::read_link(e.path().join("ns/mnt")).ok() != std::fs::read_link("/proc/self/ns/mnt").ok() {
            continue;
        }
        let path = exe.to_string_lossy().trim_end_matches(" (deleted)").to_string();
        let is_cgmon = path.rsplit('/').next().map_or(false, |b| b.starts_with("cgmon"));
        if path.is_empty() || path == me || is_cgmon || pk.contains(&path) || !seen.insert(path.clone()) {
            continue;
        }
        // интерпретаторы и docker-контейнеры (свои слои) пропускаем
        if path.starts_with("/var/lib/docker") || path.starts_with("/overlay") || path.contains("/docker/") {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or("").to_string();
        let ver_of = |args: &[&str]| crate::flowwatch::output_timeout(&path, args, 5000).unwrap_or_default();
        let (eco, module, ver): (Option<&'static str>, Option<&'static str>, Option<String>) = match base.as_str() {
            "AdGuardHome" => {
                let t = ver_of(&["--version"]);
                let v = t.split_whitespace().find(|w| w.starts_with('v') && w.contains('.')).map(String::from);
                (Some("Go"), Some("github.com/AdguardTeam/AdGuardHome"), v)
            }
            "tailscaled" | "tailscale" => {
                let t = ver_of(&["--version"]);
                let v = t.lines().next().map(|l| format!("v{}", l.trim().split('-').next().unwrap_or("")));
                (Some("Go"), Some("tailscale.com"), v)
            }
            _ => (None, None, None),
        };
        out.push((path, eco, module, ver.filter(|v| v.len() > 2)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apk_lines() {
        let p = parse_apk("libcurl4-8.19.0-r2 x86_64 {feeds/packages/feeds/packages/net/curl} (MIT) [installed]\ndnsmasq-full-2.93-r1 x86_64 {feeds/base/network/services/dnsmasq} (GPL-2.0) [installed]\nuhttpd-2026.06.16~7b1bec45-r1 x86_64 {feeds/base/network/services/uhttpd} (ISC) [installed]\n");
        assert_eq!(p[0], Pkg { name: "libcurl4".into(), origin: "curl".into(), version: "8.19.0".into() });
        assert_eq!(p[1].origin, "dnsmasq");
        assert_eq!(p[1].version, "2.93");
        assert!(osv_target(&p[2].origin, &p[2].version).is_none());
    }

    #[test]
    fn opkg_status() {
        let p = parse_opkg_status("Package: libopenssl3\nVersion: 3.0.13-1\nSource: package/libs/openssl\n\nPackage: dropbear\nVersion: 2022.82-6\n");
        assert_eq!(p[0], Pkg { name: "libopenssl3".into(), origin: "openssl".into(), version: "3.0.13-1".into() });
        assert_eq!(p[1].origin, "dropbear");
    }

    #[test]
    fn versions() {
        use std::cmp::Ordering::*;
        assert_eq!(upstream("1:1.37.0-6+deb13u1"), "1.37.0");
        assert_eq!(upstream("2.90-4~bpo12+1"), "2.90");
        assert_eq!(upstream("v1.98.3"), "1.98.3");
        assert_eq!(vcmp("2.93", "2.90"), Greater);
        assert_eq!(vcmp("6.12.103", "6.12.43"), Greater);
        assert_eq!(vcmp("3.5.7", "3.5.7"), Equal);
        assert_eq!(vcmp("2025.89", "2025.88"), Greater);
        assert_eq!(vcmp("1.0.2k", "1.0.2m"), Less);
        assert_eq!(vcmp("10.6_p1", "10.6"), Greater);
        assert_eq!(vcmp("2.0rc1", "2.0"), Less);
        assert_eq!(last_affected_from_text("scp in OpenSSH through 8.3p1 allows").as_deref(), Some("8.3p1"));
        assert_eq!(last_affected_from_text("OpenSSH 4.6 and earlier, when").as_deref(), Some("4.6"));
        assert!(past_last_affected("10.6_p1", "OpenSSH through 8.7 allows"));
        assert!(past_last_affected("10.6_p1", "In OpenSSH 7.9, due to accepting and displaying"));
        assert!(!past_last_affected("10.6_p1", "In OpenSSH 7.9 and later, due to"));
        assert!(!past_last_affected("8.7", "OpenSSH through 8.7 allows"));
        assert_eq!(osv_target("busybox", "1.37.0").unwrap().2, "1:1.37.0-0");
        assert_eq!(osv_target("hostapd", "2.11").unwrap().1, "wpa");
        assert_eq!(osv_target("tailscale", "1.98.3").unwrap(), ("Go", "tailscale.com".to_string(), "v1.98.3".to_string()));
    }

    #[test]
    fn cvss() {
        assert_eq!(cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(cvss_score("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H"), Some(4.4));
    }

    #[test]
    fn severity() {
        // уже атакуют, но служба не видна из интернета (клиентская библиотека) — не критично
        assert_eq!(cve_sev(true, 0.0, 9.8, "N", "", "open", false), "high");
        // открыта наружу, по сети, атакуют — критично
        assert_eq!(cve_sev(true, 0.0, 7.0, "N", "", "open", true), "crit");
        assert_eq!(cve_sev(false, 0.0, 9.8, "N", "", "open", true), "crit");
        // только локально — никогда не критично
        assert_eq!(cve_sev(true, 0.5, 9.8, "L", "", "open", true), "high");
        assert_eq!(cve_sev(false, 0.0, 9.8, "N", "unimportant", "fixed", true), "low");
        assert_eq!(cve_sev(false, 0.0, 4.4, "L", "not yet assigned", "open", false), "low");
        assert_eq!(cve_sev(false, 0.0, 7.5, "N", "", "fixed", false), "med");
        assert_eq!(cve_sev(false, 0.03, 9.8, "N", "", "maybe", true), "med");
        assert_eq!(port_list("22 8000-8002,443"), vec![22, 8000, 8001, 8002, 443]);
    }

    #[test]
    fn fixed_in_text() {
        assert_eq!(fixed_from_text("ssh in OpenSSH before 10.4 can have a use-after-free").as_deref(), Some("10.4"));
        assert_eq!(fixed_from_text("affects curl prior to version 8.20.0.").as_deref(), Some("8.20.0"));
        assert_eq!(fixed_from_text("before the handshake"), None);
        let mut r = Report { findings: vec![Finding { pkgs: vec!["openssh-sftp-server".into()], fixed: "10.4".into(), upgrade: "10.6_p1".into(), action: "pkg".into(), ..Default::default() }, Finding { pkgs: vec!["openssh-sftp-server".into()], fixed: "10.7".into(), ..Default::default() }], ..Default::default() };
        recheck_upgraded(&mut r, &[("openssh-sftp-server".into(), "10.6_p1".into())]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].version, "10.6_p1");
    }

    #[test]
    fn upstream_ranges() {
        let ev: Vec<Value> = crate::value::parse_json(r#"[{"introduced":"8.8.0"},{"fixed":"8.14.2"},{"introduced":"8.17.0"},{"fixed":"8.20.1"},{"introduced":"8.21.0"},{"fixed":"8.21.0"}]"#).unwrap().as_array().unwrap().to_vec();
        assert_eq!(in_ranges(&ev, "8.22.0"), Some((false, None)));
        assert_eq!(in_ranges(&ev, "8.19.0"), Some((true, Some("8.20.1".into()))));
        let ev2: Vec<Value> = crate::value::parse_json(r#"[{"introduced":"8.21.0"},{"fixed":"8.23.0"}]"#).unwrap().as_array().unwrap().to_vec();
        assert_eq!(in_ranges(&ev2, "8.22.0"), Some((true, Some("8.23.0".into()))));
        let ev3: Vec<Value> = crate::value::parse_json(r#"[{"introduced":"0"},{"last_affected":"7.9"}]"#).unwrap().as_array().unwrap().to_vec();
        assert_eq!(in_ranges(&ev3, "10.6_p1"), Some((false, None)));
    }

    #[test]
    fn space_estimate() {
        let mb = 1u64 << 20;
        // пакет в overlay: нужна разница (но не меньше самого крупного пакета) + запас
        let mut old = HashMap::new();
        old.insert("curl".to_string(), 3 * mb);
        assert_eq!(space_need(&[("curl".into(), 4 * mb)], &old), 4 * mb + mb);
        // пакет из прошивки: новая версия целиком
        assert_eq!(space_need(&[("curl".into(), 4 * mb), ("lib".into(), 20 * mb)], &HashMap::new()), 24 * mb + 24 * mb / 10);
    }

    #[test]
    fn normalize_old_report() {
        let mut r = Report { findings: vec![
            Finding { code: "cve".into(), area: "pkg".into(), version: "10.6_p1".into(), summary: "ssh in OpenSSH before 10.4 can have a use-after-free".into(), state: "open".into(), ..Default::default() },
            Finding { code: "lan_xmeye".into(), area: "lan".into(), sev: "high".into(), ..Default::default() },
        ], ..Default::default() };
        assert!(normalize(&mut r));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].sev, "med");
        assert_eq!(lan_sev("lan_xmeye", false, "yes"), "high");
        assert_eq!(lan_sev("lan_xmeye", false, "no"), "low");
        assert_eq!(lan_sev("lan_camera", false, "yes"), "med");
        assert_eq!(lan_sev("lan_xmeye", true, ""), "crit");
    }

    #[test]
    fn isolation() {
        assert_eq!(norm_mac("AA-BB-CC-00-11-22").as_deref(), Some("aa:bb:cc:00:11:22"));
        assert_eq!(norm_mac("zz"), None);
        let s = iso_script(&["aa:bb:cc:00:11:22".into()]);
        assert!(s.contains("ether saddr @mac ip daddr != @lan4 counter drop"), "{s}");
        assert!(s.contains("elements = { aa:bb:cc:00:11:22 }"), "{s}");
        assert!(!iso_script(&[]).contains("chain"));
    }

    #[test]
    fn osv_record() {
        let v = crate::value::parse_json(r#"{"id":"DEBIAN-CVE-2026-13002","upstream":["CVE-2026-13002"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H"}],"summary":"loop","affected":[{"package":{"name":"dnsmasq","ecosystem":"Debian:12"},"ecosystem_specific":{"urgency":"low"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.89-1+deb12u1"}]}]},{"package":{"name":"dnsmasq","ecosystem":"Debian:13"},"ecosystem_specific":{"urgency":"not yet assigned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#).unwrap();
        let i = vuln_info(&v, "Debian", "dnsmasq");
        assert_eq!(i.cve, "CVE-2026-13002");
        assert_eq!(i.av, "L");
        assert_eq!(i.urgency, "not yet assigned");
        assert_eq!(i.fixed, None, "Debian:12 fix must not leak into Debian:13");
        assert_eq!(i.cvss, 4.4);
    }
}