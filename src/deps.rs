//! Зависимости от пакетов OpenWrt (перенос deps.go): модули ядра и программы
//! для включённых функций. Демон раз в минуту проверяет и кладёт в статус
//! (`deps_missing`, `needs` — страница показывает недоступное серым);
//! `cgmon deps` — проверка, `cgmon deps --install` — установка (apk / opkg).

use crate::config::Config;
use crate::json::J;
use std::io::Write;

#[derive(Clone, Debug, PartialEq)]
pub struct Dep {
    pub kind: &'static str,
    pub name: String,
    pub pkg: &'static str,
    pub feature: String,
    /// Функция, которую нельзя запускать без этой зависимости (qos, shaper, hard, gate, route, …).
    pub tag: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Missing {
    pub dep: Dep,
    pub hint: &'static str,
}

/// В alternatives есть путь, кроме proto (устройство или узел).
pub fn dg_uses_route(c: &Config) -> bool {
    c.dns_guard.alternatives.iter().any(|a| a != crate::livecfg::DGR_PROTO) || !c.dns_guard.relays.is_empty()
}

/// Модули ядра для tc при данном конфиге: (модуль, пакет, приём?).
fn tc_kmods(c: &Config, shaper: bool) -> Vec<(&'static str, &'static str, bool)> {
    let mut m = Vec::new();
    if c.qos.flow_cap_up_kbit > 0 || shaper {
        for k in ["sch_htb", "cls_flow", "sch_fq_codel"] {
            m.push((k, "kmod-sched-core", false));
        }
    } else {
        m.push(("sch_cake", "kmod-sched-cake", false));
    }
    if c.qos.enabled && c.qos.download_kbit > 0 {
        for k in ["sch_ingress", "act_mirred"] {
            m.push((k, "kmod-sched-core", true));
        }
        m.push(("ifb", "kmod-ifb", true));
        if c.qos.flow_cap_down_kbit > 0 {
            m.push(("sch_htb", "kmod-sched-core", true));
            m.push(("cls_flow", "kmod-sched-core", true));
        } else {
            m.push(("sch_cake", "kmod-sched-cake", true));
        }
    }
    m
}

/// Что нужно при данном конфиге (без повторов — первая причина).
pub fn deps_for(c: &Config) -> Vec<Dep> {
    let mut d: Vec<Dep> = Vec::new();
    let mut add = |kind: &'static str, name: &str, pkg: &'static str, feature: &str, tag: &'static str| {
        if !d.iter().any(|x| x.kind == kind && x.name == name && x.tag == tag) {
            d.push(Dep { kind, name: name.into(), pkg, feature: feature.into(), tag });
        }
    };
    add("file", "/proc/net/nf_conntrack", "", "соединения (conntrack)", "conntrack");
    add("bin", "nft", "nftables-json", "правила nftables", "nft");
    if c.hard_limit.enabled {
        add("kmod", "nft_connlimit", "kmod-nft-connlimit", "жёсткие лимиты соединений (hard_limit)", "hard");
    }
    for (on, tag, f) in [(c.qos.enabled, "qos", "SQM (qos)"), (c.upload_shaper.enabled, "shaper", "шейпер отдачи (upload_shaper)")] {
        if !on {
            continue;
        }
        add("bin", "tc", "tc-tiny", f, tag);
        for (k, pkg, rx) in tc_kmods(c, tag == "shaper" || c.upload_shaper.enabled) {
            if tag == "shaper" && rx {
                continue; // шейперу приём не нужен
            }
            let fr = if rx { format!("{f}: приём") } else { f.to_string() };
            add("kmod", k, pkg, &fr, tag);
        }
    }
    if c.gate_selector.enabled && !c.gate_selector.dry_run {
        // основная таблица: хватает и ip из busybox
        add("bin", "ip", "ip-full", "выбор шлюза (gate_selector)", "gate");
    }
    if c.dns_guard.mode == "targeted" {
        if crate::variant::SMARTDNS {
            add("bin", "smartdns", "smartdns", "адресная DNS-страховка (dns_guard.mode: targeted)", "smartdns");
        }
        if dg_uses_route(c) {
            add("ipfull", "ip", "ip-full", "обход маршрутом (dns_guard.alternatives)", "route");
            add("bin", "curl", "curl", "проверка загрузки через путь обхода", "bulk");
        }
        if !c.dns_guard.relays.is_empty() {
            add("bin", "zerotier-one", "zerotier", "обход через свои роутеры (dns_guard.relays)", "relay");
        }
    }
    let mut https = Vec::new();
    if c.hub.enabled && !crate::livecfg::telegram_dests(&c.hub).is_empty() {
        https.push("Telegram");
    }
    if c.report.enabled {
        https.push("провайдер для отчётов");
    }
    if c.billing.enabled && c.billing.tasix_url.starts_with("https://") {
        https.push("список TAS-IX");
    }
    if c.devices.vendor_lookup && c.devices.vendor_url.starts_with("https://") {
        https.push("производители по MAC");
    }
    if !https.is_empty() {
        add("https", "curl", "curl", &format!("HTTPS: {}", https.join(", ")), "https");
    }
    d
}

/// Последняя проверка ip_full() (карты шлюзов выбирают по ней номера таблиц).
pub static IPFULL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Настоящий ip (ip-full / ip-tiny), не busybox: таблицы > 255, fwmark с маской, uidrange.
pub fn ip_full() -> bool {
    for c in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let p = std::path::Path::new(c);
        if !p.exists() {
            continue;
        }
        let real = std::fs::canonicalize(p).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default();
        if !real.contains("busybox") {
            return true;
        }
    }
    false
}

/// tc и модули для qos/шейпера при данном конфиге (для пометки на странице — как если бы включили).
fn tc_ready(c: &Config, shaper: bool) -> bool {
    crate::util::have_bin("tc") && tc_kmods(c, shaper).iter().all(|(k, _, rx)| (shaper && *rx) || kmod_available(k))
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string()
}

/// Модуль загружен, лежит в /lib/modules или встроен в ядро.
pub fn kmod_available(name: &str) -> bool {
    if std::path::Path::new(&format!("/sys/module/{name}")).exists() {
        return true;
    }
    let dir = format!("/lib/modules/{}", kernel_release());
    let has = |d: &str| {
        std::fs::read_dir(d).map_or(false, |rd| rd.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(&format!("{name}.ko"))
        }))
    };
    if has(&dir) {
        return true;
    }
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path().is_dir() && has(&e.path().to_string_lossy()) {
                return true;
            }
        }
    }
    std::fs::read_to_string(format!("{dir}/modules.builtin")).map_or(false, |t| {
        t.lines().any(|l| l.rsplit('/').next().unwrap_or("").trim_end_matches(".ko").replace('-', "_") == name)
    })
}

/// Есть ли чем ходить по HTTPS: curl, wget или uclient-fetch с SSL.
pub fn https_client() -> bool {
    match crate::report::https_tool().1 {
        "curl" | "gnu" | "busybox" => true,
        "uclient" => ["/lib/libustream-ssl.so", "/usr/lib/libustream-ssl.so"].iter().any(|p| std::path::Path::new(p).exists()),
        _ => false,
    }
}

/// Чего не хватает включённым функциям.
pub fn check(c: &Config) -> Vec<Missing> {
    let mut miss = Vec::new();
    for d in deps_for(c) {
        let (ok, hint) = match d.kind {
            "kmod" => (kmod_available(&d.name), ""),
            "bin" => (crate::util::have_bin(&d.name), ""),
            "ipfull" => (ip_full(), "ip из busybox не умеет таблицы > 255 и fwmark с маской"),
            "https" => (https_client(), "или wget, или uclient-fetch + libustream-*ssl"),
            _ => (std::path::Path::new(&d.name).exists(), "ядро без conntrack/procfs: нужна другая сборка прошивки (kmod-nf-conntrack, CONFIG_NF_CONNTRACK_PROCFS)"),
        };
        if !ok {
            miss.push(Missing { dep: d, hint });
        }
    }
    miss
}

/// Пакеты для установки (без повторов, по алфавиту).
pub fn missing_pkgs(miss: &[Missing]) -> Vec<&'static str> {
    let mut p: Vec<&'static str> = miss.iter().map(|m| m.dep.pkg).filter(|p| !p.is_empty()).collect();
    p.sort();
    p.dedup();
    p
}

/// apk (OpenWrt 25+) или opkg.
pub fn pkg_manager() -> Option<(&'static str, [&'static str; 2], [&'static str; 2])> {
    if crate::util::have_bin("apk") {
        return Some(("apk", ["apk", "update"], ["apk", "add"]));
    }
    if crate::util::have_bin("opkg") {
        return Some(("opkg", ["opkg", "update"], ["opkg", "install"]));
    }
    None
}

/// Отчёт о зависимостях; true — всё есть.
pub fn print(w: &mut dyn Write, c: &Config) -> bool {
    let need = deps_for(c);
    let miss = check(c);
    if miss.is_empty() {
        let _ = writeln!(w, "Зависимости: всё на месте ({} проверено для включённых функций).", need.len());
        return true;
    }
    let _ = writeln!(w, "Не хватает ({} из {}):", miss.len(), need.len());
    for m in &miss {
        let pkg = if m.dep.pkg.is_empty() { "—" } else { m.dep.pkg };
        let _ = writeln!(w, "  {:<5} {:<24} пакет {:<20} → {}", m.dep.kind, m.dep.name, pkg, m.dep.feature);
        if !m.hint.is_empty() {
            let _ = writeln!(w, "        {}", m.hint);
        }
    }
    let p = missing_pkgs(&miss);
    if !p.is_empty() {
        match pkg_manager() {
            Some((pm, _, inst)) => {
                let _ = writeln!(w, "Установить: {pm} update && {} {}   (или: cgmon deps --install)", inst.join(" "), p.join(" "));
            }
            None => {
                let _ = writeln!(w, "Пакеты: {} (менеджер пакетов не найден)", p.join(" "));
            }
        }
    }
    false
}

/// Поставить недостающие пакеты.
pub fn install(w: &mut dyn Write, c: &Config) -> Result<(), String> {
    let p = missing_pkgs(&check(c));
    if p.is_empty() {
        let _ = writeln!(w, "Устанавливать нечего.");
        return Ok(());
    }
    let list: Vec<String> = p.iter().map(|x| x.to_string()).collect();
    install_list(w, &list)?;
    let miss = check(c);
    if !miss.is_empty() {
        print(w, c);
        return Err(format!("после установки всё ещё не хватает {}", miss.len()));
    }
    let _ = writeln!(w, "Готово: все зависимости на месте.");
    Ok(())
}

/// Каких программ нет функциям (включены они или нет): настройка → пакеты через пробел
/// (или «build» — нет в этой сборке). Страница делает строку серой и даёт кнопку установки.
pub fn feature_needs(c: &Config) -> Vec<(&'static str, String)> {
    let mut m: Vec<(&'static str, String)> = Vec::new();
    let have = crate::util::have_bin;
    if crate::variant::TC {
        for (key, shaper) in [("qos_on", false), ("shaper_on", true)] {
            if tc_ready(c, shaper) {
                continue;
            }
            let mut p = vec!["tc-tiny"];
            for (k, pkg, rx) in tc_kmods(c, shaper) {
                if !(shaper && rx) && !kmod_available(k) && !p.contains(&pkg) {
                    p.push(pkg);
                }
            }
            if have("tc") {
                p.retain(|x| *x != "tc-tiny");
            }
            m.push((key, p.join(" ")));
        }
    }
    if crate::variant::CONNLIMIT && !kmod_available("nft_connlimit") {
        m.push(("hard_limit.enabled", "kmod-nft-connlimit".into()));
    }
    let mut alt = Vec::new();
    // обход маршрутом (адресный режим): таблицы 2100+, uidrange — нужен настоящий ip
    if crate::variant::SMARTDNS && !ip_full() {
        alt.push("ip-full");
    }
    if crate::variant::EXT && !have("curl") {
        alt.push("curl");
    }
    if !alt.is_empty() {
        m.push(("dns_guard.alternatives", alt.join(" ")));
    }
    if crate::variant::EXT && !have("zerotier-one") {
        m.push(("dns_guard.relays", "zerotier".into()));
        m.push(("dns_guard.relay_mbit", "zerotier".into()));
    }
    if crate::variant::SMARTDNS && !have("smartdns") {
        m.push(("dns_guard.mode=targeted", "smartdns".into()));
    }
    if !https_client() {
        let p = if installable().contains(&"curl") { "curl" } else { "libustream-openssl" };
        m.push(("hub.enabled", p.into()));
        m.push(("payment.enabled", p.into()));
    }
    // нет в этой сборке (lite, nano) — вместо «требуется пакет»
    for (k, v) in crate::variant::absent() {
        m.retain(|x| x.0 != k);
        m.push((k, v.into()));
    }
    m.sort();
    m
}

/// Пакеты, которые можно поставить со страницы в этой сборке: (имя, ≈КБ с зависимостями
/// на mips_24kc, чего нет в стандартном образе). nano — ничего: в ней только штатное.
const PKGS: &[(&str, u32, &str)] = &[
    ("tc-tiny", 150, "tc"),
    ("kmod-sched-core", 70, "tc"),
    ("kmod-sched-cake", 20, "tc"),
    ("kmod-ifb", 5, "tc"),
    ("kmod-nft-connlimit", 10, "connlimit"),
    ("ip-full", 400, "smartdns"),
    ("curl", 400, "ext"),
    ("zerotier", 1150, "ext"),
    ("smartdns", 200, "smartdns"),
];

pub fn installable() -> Vec<&'static str> {
    let on = |f: &str| match f {
        "tc" => crate::variant::TC,
        "connlimit" => crate::variant::CONNLIMIT,
        "ext" => crate::variant::EXT,
        "smartdns" => crate::variant::SMARTDNS,
        _ => false,
    };
    PKGS.iter().filter(|p| on(p.2)).map(|p| p.0).collect()
}

/// Свободно на разделе с /usr (overlay), КБ.
fn free_kb() -> u64 {
    let path = if std::path::Path::new("/overlay").exists() { "/overlay\0" } else { "/\0" };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr() as *const libc::c_char, &mut st) } != 0 {
        return u64::MAX;
    }
    st.f_bavail as u64 * st.f_frsize as u64 / 1024
}

/// Установка со страницы: в фоне (apk/opkg долгие), итог — в статус.
#[derive(Default, Clone)]
pub struct InstallState {
    pub running: bool,
    pub pkgs: Vec<String>,
    pub ok: bool,
    pub msg: String,
    pub at: i64,
}

#[derive(Default)]
pub struct Installer {
    pub st: std::sync::Arc<std::sync::Mutex<InstallState>>,
}

impl Installer {
    /// Проверить список и запустить. Пустой список — недостающее для включённых функций.
    pub fn start(&self, want: &[String], c: &Config) -> Result<Vec<String>, String> {
        let ok = installable();
        if ok.is_empty() {
            return Err(format!("в сборке cgmon {} пакеты не ставятся: только то, что есть в прошивке", crate::variant::name()));
        }
        let mut pkgs: Vec<String> = if want.is_empty() {
            missing_pkgs(&check(c)).into_iter().map(String::from).collect()
        } else {
            want.to_vec()
        };
        pkgs.sort();
        pkgs.dedup();
        if let Some(bad) = pkgs.iter().find(|p| !ok.contains(&p.as_str())) {
            return Err(format!("пакет {bad} не ставится со страницы"));
        }
        if pkgs.is_empty() {
            return Err("устанавливать нечего".into());
        }
        if pkg_manager().is_none() {
            return Err("нет ни apk, ни opkg".into());
        }
        let need: u64 = pkgs.iter().map(|p| PKGS.iter().find(|x| x.0 == p).map_or(100, |x| x.1) as u64).sum();
        let free = free_kb();
        if free < need * 3 / 2 + 512 {
            return Err(format!("мало места: свободно {free} КБ, нужно ≈{} КБ", need * 3 / 2 + 512));
        }
        {
            let mut s = self.st.lock().unwrap();
            if s.running {
                return Err("установка уже идёт".into());
            }
            *s = InstallState { running: true, pkgs: pkgs.clone(), ok: false, msg: String::new(), at: crate::util::now_wall().0 };
        }
        let st = self.st.clone();
        let list = pkgs.clone();
        let local_domain = c.dns_guard.clone();
        std::thread::spawn(move || {
            let mut log: Vec<u8> = Vec::new();
            let res = install_list(&mut log, &list).and_then(|_| {
                let mut notes = Vec::new();
                if list.iter().any(|p| p == "zerotier") {
                    notes.push(crate::pkgsetup::zerotier());
                }
                if list.iter().any(|p| p == "smartdns") {
                    notes.push(crate::pkgsetup::smartdns(&local_domain));
                }
                Ok(notes.into_iter().filter(|n| !n.is_empty()).collect::<Vec<_>>().join("; "))
            });
            let mut s = st.lock().unwrap();
            s.running = false;
            s.at = crate::util::now_wall().0;
            match res {
                Ok(n) => {
                    s.ok = true;
                    s.msg = n;
                    crate::log_info!("deps: установлено {}{}", list.join(" "), if s.msg.is_empty() { String::new() } else { format!(" ({})", s.msg) });
                }
                Err(e) => {
                    let tail: String = String::from_utf8_lossy(&log).lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" / ");
                    s.msg = format!("{e}: {tail}").chars().take(400).collect();
                    crate::log_err!("deps: установка {} не удалась: {}", list.join(" "), s.msg);
                }
            }
        });
        Ok(pkgs)
    }

    pub fn json(&self, j: &mut J) {
        let s = self.st.lock().unwrap().clone();
        if s.at == 0 {
            return;
        }
        j.key("pkg_install").obj().key("running").bool(s.running).key("ok").bool(s.ok).key("at").int(s.at).key("msg").str(&s.msg).key("pkgs").arr();
        for p in &s.pkgs {
            j.str(p);
        }
        j.end_arr().end_obj();
    }
}

/// apk/opkg update + add.
fn install_list(w: &mut dyn Write, p: &[String]) -> Result<(), String> {
    let Some((pm, upd, inst)) = pkg_manager() else { return Err("нет ни apk, ни opkg".into()) };
    let run = |w: &mut dyn Write, args: &[&str]| -> Result<(), String> {
        let _ = writeln!(w, "# {}", args.join(" "));
        let o = std::process::Command::new(args[0]).args(&args[1..]).output().map_err(|e| e.to_string())?;
        let _ = w.write_all(&o.stdout);
        let _ = w.write_all(&o.stderr);
        if o.status.success() {
            Ok(())
        } else {
            Err(format!("exit status {}", o.status.code().unwrap_or(-1)))
        }
    };
    run(w, &upd).map_err(|e| format!("{pm} update: {e}"))?;
    let mut args: Vec<&str> = inst.to_vec();
    args.extend(p.iter().map(|s| s.as_str()));
    run(w, &args).map_err(|e| format!("установка: {e} (модули ядра есть только под ядро вашей сборки — на snapshot их может не быть)"))
}

/// Проверка раз в минуту в демоне: изменения — в журнал, итог — в статус.
#[derive(Default)]
pub struct Watch {
    at: u64,
    key: String,
    pub miss: Vec<Missing>,
    pub needs: Vec<(&'static str, String)>,
    /// Настоящий ip есть (таблицы > 255, fwmark с маской).
    pub ipfull: bool,
    pub inst: Installer,
    /// Было «идёт установка» — по окончании проверить сразу.
    was_running: bool,
}

impl Watch {
    /// true — набор доступного изменился (демону пересчитать, что запускать).
    pub fn tick(&mut self, c: &Config, now: u64) -> bool {
        let running = self.inst.st.lock().map_or(false, |s| s.running);
        let done = std::mem::replace(&mut self.was_running, running) && !running;
        if !done && self.at != 0 && now - self.at < 60_000 {
            return false;
        }
        self.at = now.max(1);
        let ipf = ip_full();
        IPFULL.store(ipf, std::sync::atomic::Ordering::Relaxed);
        let ipf_changed = ipf != self.ipfull;
        self.ipfull = ipf;
        self.miss = check(c);
        self.needs = feature_needs(c);
        let key: String = self.miss.iter().map(|m| format!("{}:{};", m.dep.kind, m.dep.name)).collect();
        if key == self.key {
            return ipf_changed;
        }
        self.key = key;
        for m in &self.miss {
            let pkg = if m.dep.pkg.is_empty() { m.hint } else { m.dep.pkg };
            crate::log_err!("deps: нет {} {} ({}) — нужно для: {}", m.dep.kind, m.dep.name, pkg, m.dep.feature);
        }
        let p = missing_pkgs(&self.miss);
        if !p.is_empty() {
            crate::log_err!("deps: установить: cgmon deps --install  (пакеты: {})", p.join(" "));
        } else if self.miss.is_empty() {
            crate::log_info!("deps: все зависимости на месте");
        }
        true
    }

    /// Функции (qos, shaper, hard, gate, route, …) не хватает пакета — не запускать.
    pub fn blocked(&self, tag: &str) -> bool {
        self.miss.iter().any(|m| m.dep.tag == tag)
    }

    pub fn json(&self, j: &mut J) {
        if !self.miss.is_empty() {
            j.key("deps_missing").arr();
            for m in &self.miss {
                j.obj().key("kind").str(m.dep.kind).key("name").str(&m.dep.name).key("pkg").str(m.dep.pkg).key("feature").str(&m.dep.feature);
                if !m.hint.is_empty() {
                    j.key("hint").str(m.hint);
                }
                j.end_obj();
            }
            j.end_arr();
        }
        if !self.needs.is_empty() {
            j.key("needs").obj();
            for (k, v) in &self.needs {
                j.key(k).str(v);
            }
            j.end_obj();
        }
        let inst = installable();
        if !inst.is_empty() {
            j.key("pkg_can").arr();
            for p in inst {
                j.str(p);
            }
            j.end_arr();
        }
        self.inst.json(j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deps_for_features() {
        let mut c = crate::config::defaults();
        c.qos.enabled = true;
        c.qos.download_kbit = 1000;
        c.upload_shaper.enabled = true;
        c.dns_guard.mode = "targeted".into();
        c.dns_guard.alternatives = vec!["proto".into(), "eth3".into()];
        let d = deps_for(&c);
        let names: Vec<&str> = d.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"sch_htb") && names.contains(&"ifb") && names.contains(&"ip"), "{names:?}");
        // приём и отдача qos — один модуль на функцию; шейперу приём не нужен
        assert_eq!(d.iter().filter(|x| x.name == "sch_htb" && x.tag == "qos").count(), 1);
        assert!(!d.iter().any(|x| x.tag == "shaper" && x.name == "ifb"));
        assert!(d.iter().any(|x| x.kind == "ipfull" && x.tag == "route"));
        // переключение шлюза — хватает busybox ip; в dry_run не нужно ничего
        c.gate_selector.dry_run = true;
        assert!(!deps_for(&c).iter().any(|x| x.tag == "gate"));
    }

    #[test]
    fn install_whitelist() {
        let inst = installable();
        assert_eq!(inst.contains(&"tc-tiny"), crate::variant::TC);
        assert_eq!(inst.contains(&"smartdns"), crate::variant::SMARTDNS);
        assert_eq!(inst.contains(&"zerotier"), crate::variant::EXT);
        let i = Installer::default();
        let c = crate::config::defaults();
        assert!(i.start(&["dropbear".into()], &c).is_err());
        assert!(i.start(&["tc-tiny; rm".into()], &c).is_err());
    }
}
