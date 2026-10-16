//! Все настройки cgmon.yaml со страницы без перезапуска (перенос livecfg.go):
//! поля по путям «секция.ключ», слой "config" в runtime.json поверх
//! cgmon.yaml (сам файл не трогаем), проверка собранного конфига.

use crate::config::{Config, Field, FieldMut};
use crate::netx;
use crate::value::{parse_json, Value};

/// Пути (или префиксы с точкой на конце), которых нет на странице.
pub const HIDDEN: &[&str] = &[
    "paths.", "simulation.", "web.", "nft.table", "hard_limit.table", "hard_limit.uci_import",
    "wan_monitor.incidents_file",
    "gate_selector.interfaces", "gate_selector.switching.on_switch", "gate_selector.enabled",
    "billing.tasix_file", "billing.state_file", "witness.state_file", "payment.state_file",
    // файлы, в которые cgmon пишет, — только в cgmon.yaml
    "dns_guard.upstream_file", "dns_guard.guard_file", "dns_guard.targets_file", "dns_guard.cache_file", "dns_guard.state_file", "flow_watch.learn_file", "devices.vendor_cache", "devices.vendor_url",
    "qos.device", "qos.ifb", "upload_shaper.device", "upload_shaper.class_id", "upload_shaper.stages",
    "accounting.enabled", "peers.list", "special_hosts", "dns.static",
    "report.token", "report.url", "hub.", // секреты и параметры центра
    // основные настройки страницы (runtime)
    "dry_run", "wan_check", "qos.enabled", "qos.upload_kbit", "qos.download_kbit",
    "qos.flow_cap_up_kbit", "qos.flow_cap_down_kbit", "upload_shaper.enabled", "upload_shaper.sustained_kbit",
    "flow_watch.enabled", "billing.enabled", "billing.daily_limit_mb", "billing.monthly_limit_mb",
];

/// Поля конфига в основных настройках страницы (меняются тем же механизмом).
pub const MAIN: &[&str] = &[
    "probe_interval_sec", "probes.ipv4", "probes.ipv6", "down_detector.enabled",
    "lan_zones", "lan_interfaces", "isolated_zones",
    "billing.tasix_url",
    "report.enabled", "report.urls", "hub.enabled",
    "dns_guard.mode", "dns_guard.withdraw_ra", "dns_guard.v6_enter_sec",
    "dns_guard.v4_enter_sec", "dns_guard.recover_sec", "dns_guard.dns64_servers",
    "dns_guard.target_base_min", "dns_guard.target_max_hours",
    "dns_guard.alternatives", "dns_guard.metered", "dns_guard.metered_day_mb", "dns_guard.relays", "dns_guard.relay_mbit",
    "gate_selector.from_alternatives", "gate_selector.backups", "dns_guard.check_domains",
    "dns_guard.check_via", "dns_guard.reject_all_v6_score", "dns_guard.reject_all_v6_sec",
    "witness.mode", "witness.per_family", "witness.interval_sec",
    "payment.enabled", "payment.mode", "payment.day", "payment.interval_days", "payment.start_date",
    "payment.amount", "payment.note", "payment.remind_days", "payment.remind_hour",
    "flow_watch.learn_mode", "flow_watch.learn_min_kbit", "flow_watch.loss_only_percent",
    "client_retention_sec",
    "devices.l2_watch", "devices.l2_probe", "path_trace.enabled", "storage",
];

/// Свободный текст (только показывается): буквы любых алфавитов.
const TEXT_PATHS: &[&str] = &["payment.amount", "payment.note"];

pub fn is_main(path: &str) -> bool {
    MAIN.contains(&path)
}

pub fn is_hidden(path: &str) -> bool {
    if is_main(path) {
        return true;
    }
    HIDDEN.iter().any(|h| path == *h || (h.ends_with('.') && path.starts_with(h)) || (path.starts_with(h) && path.as_bytes().get(h.len()) == Some(&b'.')))
}

/// Строки уходят в tc/nft/exec аргументами: без переводов строк, кавычек и
/// спецсимволов shell.
pub fn allowed_string(s: &str) -> bool {
    s.len() <= 300 && s.chars().all(|r| r.is_ascii_alphanumeric() || " ._:/?=&%~+-,@[]".contains(r))
}

/// Свободный текст: буквы и цифры любых алфавитов + простая пунктуация, ≤ 80.
pub fn allowed_text(s: &str) -> bool {
    s.chars().count() <= 80 && s.chars().all(|r| r.is_alphanumeric() || " .,:;-+()№/#%".contains(r))
}

/// Значение по пути с проверкой типа (со страницы: скрытые — нельзя).
pub fn set(c: &mut Config, path: &str, raw: &Value) -> Result<(), String> {
    if is_hidden(path) && !is_main(path) {
        return Err("not editable".into());
    }
    set_any(c, path, raw)
}

/// Без ограничения скрытых путей (мастер установки, локально).
pub fn set_any(c: &mut Config, path: &str, raw: &Value) -> Result<(), String> {
    let text = TEXT_PATHS.contains(&path);
    let Some(f) = c.field_mut(path) else { return Err("unknown setting".into()) };
    let num = |raw: &Value| -> Result<f64, String> {
        match raw.as_f64() {
            Some(n) if (0.0..=1e9).contains(&n) => Ok(n),
            _ => Err("must be a number ≥ 0".into()),
        }
    };
    match f {
        FieldMut::Bool(b) => *b = raw.as_bool().ok_or("must be true/false")?,
        FieldMut::Int(v) => {
            let n = num(raw)?;
            if n.fract() != 0.0 {
                return Err("must be an integer".into());
            }
            *v = n as i64;
        }
        FieldMut::Float(v) => *v = num(raw)?,
        FieldMut::Str(s) => {
            let x = raw.as_str().ok_or("invalid characters")?;
            if !(allowed_string(x) || (text && allowed_text(x))) {
                return Err("invalid characters".into());
            }
            *s = x.trim().to_string();
        }
        FieldMut::StrList(l) => *l = clean_list(raw)?,
        FieldMut::IntList(l) => {
            let mut ints = Vec::new();
            for s in clean_list(raw)? {
                match s.parse::<i64>() {
                    Ok(n) if (0..=65535).contains(&n) => ints.push(n),
                    _ => return Err("must be numbers".into()),
                }
            }
            *l = ints;
        }
    }
    Ok(())
}

fn clean_list(raw: &Value) -> Result<Vec<String>, String> {
    let Value::List(l) = raw else { return Err("must be a list".into()) };
    if l.len() > 64 {
        return Err("must be a list".into());
    }
    let mut out = Vec::new();
    for x in l {
        let Some(s) = x.as_str() else { return Err("must be a list".into()) };
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        if !allowed_string(s) || s.contains(' ') {
            return Err("invalid characters".into());
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// Значение поля по пути (JSON) — для сравнения и статуса.
pub fn field_json(c: &Config, path: &str) -> Option<String> {
    let mut out = None;
    c.walk("", &mut |p, f| {
        if p == path && !matches!(f, Field::Complex) {
            let mut s = String::new();
            crate::config::field_json(f, &mut s);
            out = Some(s);
        }
    });
    out
}

/// Значение после разбора совпадает с cgmon.yaml (слой не нужен).
pub fn same_as_base(base: &Config, path: &str, raw: &Value) -> bool {
    let mut c = base.clone();
    if set(&mut c, path, raw).is_err() {
        return false;
    }
    field_json(&c, path) == field_json(base, path)
}

/// Исходный конфиг + слой со страницы (ключи по алфавиту, как в Go).
pub fn build_live(base: &Config, overlay: &[(String, Value)]) -> Result<Config, String> {
    let mut c = base.clone();
    let mut keys: Vec<&(String, Value)> = overlay.iter().collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in keys {
        set(&mut c, k, v).map_err(|e| format!("{k}: {e}"))?;
    }
    c.normalize();
    validate(&c)?;
    Ok(c)
}

/// Слой "config" из runtime.json (до создания компонентов).
pub fn read_overlay(path: &str) -> Vec<(String, Value)> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    match parse_json(&text) {
        Ok(v) => match v.get("config") {
            Some(Value::Map(m)) => m.clone(),
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

// ---- проверки (перенос cfgValidate и его помощников) ----

pub const DGR_PROTO: &str = "proto";
pub const DGR_MAX_PATHS: usize = 8;

/// Имя пути обхода: ^[A-Za-z0-9_.@-]{1,15}$.
pub fn path_id_ok(s: &str) -> bool {
    (1..=15).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.@-".contains(&c))
}

/// Имя DNS-сервиса (не свидетель): .arpa, one.one.one.one, метки с dns/doh/dot.
pub fn wit_dns_name(n: &str) -> bool {
    let n = n.trim_end_matches('.').to_ascii_lowercase();
    if n.ends_with(".arpa") || n == "one.one.one.one" {
        return true;
    }
    n.split('.').any(|l| l.contains("dns") || l == "doh" || l == "dot")
}

/// Домен для правил SmartDNS (чужие данные): ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.…)+$.
pub fn domain_ok(d: &str) -> bool {
    if d.len() > 253 || wit_dns_name(d) {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            !b.is_empty() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') && b[0] != b'-' && b[b.len() - 1] != b'-'
        })
}

/// Ретранслятор «имя@адрес»: имя ^[A-Za-z0-9_-]{1,14}$, адрес — частный IPv4 или CGNAT.
pub fn parse_relay(s: &str) -> Option<(String, String)> {
    let (name, ip) = s.trim().split_once('@')?;
    if !(1..=14).contains(&name.len()) || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
        return None;
    }
    if !(7..=15).contains(&ip.len()) || !ip.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    let a = netx::to4(&netx::parse_ip(ip)?)?;
    if !netx::is_private4(a) && !(a[0] == 100 && a[1] & 0xc0 == 64) {
        return None;
    }
    Some((name.to_string(), std::net::Ipv4Addr::from(a).to_string()))
}

/// Получатели Telegram (бот, чат) без повторов.
pub fn telegram_dests(c: &crate::config::HubConfig) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut add = |bot: &str, chat: &str| {
        let d = (bot.trim().to_string(), chat.trim().to_string());
        if !d.0.is_empty() && !d.1.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    };
    add(&c.telegram_bot_token, &c.telegram_chat_id);
    for t in &c.telegram {
        for ch in &t.chat_ids {
            add(&t.bot_token, ch);
        }
    }
    out
}

fn tg_bot_ok(s: &str) -> bool {
    let Some((id, key)) = s.split_once(':') else { return false };
    id.len() >= 5 && id.bytes().all(|c| c.is_ascii_digit()) && key.len() >= 20 && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn tg_chat_ok(s: &str) -> bool {
    if let Some(n) = s.strip_prefix('@') {
        return n.len() >= 4 && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    }
    let d = s.strip_prefix('-').unwrap_or(s);
    d.len() >= 3 && d.bytes().all(|c| c.is_ascii_digit())
}

/// Дата ГГГГ-ММ-ДД (как time.Parse("2006-01-02")).
pub fn date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (s[..4].parse::<i32>(), s[5..7].parse::<u32>(), s[8..].parse::<u32>()) else { return false };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    (1..=12).contains(&m) && d >= 1 && d <= dim[(m - 1) as usize]
}

pub const BILLING_FILE_SRC: &str = "file";

/// Смысловые проверки после normalize.
pub fn validate(c: &Config) -> Result<(), String> {
    if !crate::storage::valid(&c.storage) {
        return Err(format!("storage: {:?} — flash, tmp или свой каталог (/mnt/usb/cgmon)", c.storage));
    }
    let dg = &c.dns_guard;
    for s in &dg.dns64_servers {
        let h = netx::split_host_port(s).map(|x| x.0).unwrap_or(s);
        if netx::parse_ip(h.trim_matches(['[', ']'])).is_none() {
            return Err(format!("dns_guard.dns64_servers: {s:?} — нужен IP-адрес"));
        }
    }
    for id in dg.alternatives.iter().chain(&dg.metered).chain(&c.gate_selector.backups) {
        if !path_id_ok(id) {
            return Err(format!("dns_guard: путь {id:?} — нужно имя устройства (eth3, tailscale0) или proto"));
        }
    }
    for d in &dg.check_domains {
        if !domain_ok(&d.to_lowercase()) {
            return Err(format!("dns_guard.check_domains: {d:?} — нужен домен (ipleak.net)"));
        }
    }
    let v = &dg.check_via;
    if !v.is_empty() && v != "direct" && v != DGR_PROTO && !path_id_ok(v) {
        return Err(format!("dns_guard.check_via: {v:?} — пусто, direct, proto или устройство"));
    }
    for r in &dg.relays {
        if parse_relay(r).is_none() {
            return Err(format!("dns_guard.relays: {r:?} — нужно имя@адрес узла (node1@10.147.17.5, частный IPv4)"));
        }
    }
    if dg.relays.len() > DGR_MAX_PATHS {
        return Err(format!("dns_guard.relays: не больше {DGR_MAX_PATHS} узлов"));
    }
    if dg.relay_mbit < 0 || dg.relay_mbit > 10000 {
        return Err("dns_guard.relay_mbit: 0..10000".into());
    }
    if dg.check_domains.len() > 10 {
        return Err("dns_guard.check_domains: не больше 10 сайтов".into());
    }
    if dg.alternatives.len() > DGR_MAX_PATHS + 1 {
        return Err(format!("dns_guard.alternatives: не больше {DGR_MAX_PATHS} путей"));
    }
    let p = &c.payment;
    if p.mode != "monthly" && p.mode != "interval" {
        return Err("payment.mode: monthly или interval".into());
    }
    if p.day < 1 || p.day > 31 {
        return Err("payment.day: 1..31".into());
    }
    if p.interval_days < 1 || p.interval_days > 366 {
        return Err("payment.interval_days: 1..366".into());
    }
    if p.enabled && p.mode == "interval" && !date_ok(&p.start_date) {
        return Err("payment.start_date: нужна дата ГГГГ-ММ-ДД".into());
    }
    if !allowed_text(&p.amount) || !allowed_text(&p.note) {
        return Err("payment.amount/note: недопустимые символы".into());
    }
    for ep in c.probes.ipv4.iter().chain(&c.probes.ipv6) {
        match netx::split_host_port(ep) {
            Some((h, port)) if netx::parse_ip(h).is_some() && !port.is_empty() => {}
            _ => return Err(format!("цель пробы {ep:?}: нужен адрес:порт (IPv6 — [адрес]:порт)")),
        }
    }
    for ep in &c.probes.ipv4 {
        let h = netx::split_host_port(ep).map(|x| x.0).unwrap_or("");
        if netx::parse_ip(h).as_ref().and_then(netx::to4).is_none() {
            return Err(format!("цель пробы IPv4 {ep:?} — не IPv4"));
        }
    }
    for ep in &c.probes.ipv6 {
        let h = netx::split_host_port(ep).map(|x| x.0).unwrap_or("");
        if netx::parse_ip(h).as_ref().and_then(netx::to4).is_some() {
            return Err(format!("цель пробы IPv6 {ep:?} — не IPv6"));
        }
    }
    if c.probes.ipv4.is_empty() {
        return Err("нужна хотя бы одна цель пробы IPv4".into());
    }
    if c.probe_interval_sec < 1 || c.probe_interval_sec > 3600 {
        return Err("probe_interval_sec: 1..3600".into());
    }
    if c.interval_sec < 1 || c.interval_sec > 60 {
        return Err("interval_sec: 1..60".into());
    }
    if c.stat_window_sec < 5 {
        return Err("stat_window_sec: ≥ 5".into());
    }
    for (bot, chat) in telegram_dests(&c.hub) {
        if !tg_bot_ok(&bot) {
            return Err("telegram: неверный токен бота (нужен вид 123456:ABC…)".into());
        }
        if !tg_chat_ok(&chat) {
            return Err(format!("telegram: неверный chat id {chat:?} (число, -100… или @канал)"));
        }
    }
    if c.hub.enabled && c.hub.token.len() < 16 {
        return Err("центр сбора: задайте hub.token в cgmon.yaml (не короче 16 символов)".into());
    }
    if c.report.enabled {
        if c.report.token.len() < 16 {
            return Err("отправка на центр: задайте report.token в cgmon.yaml (не короче 16 символов)".into());
        }
        if c.report.urls.is_empty() && c.report.url.trim().is_empty() {
            return Err("отправка на центр: нет адреса центра".into());
        }
        for u in c.report.urls.iter().chain(std::iter::once(&c.report.url).filter(|u| !u.trim().is_empty())) {
            match netx::url_scheme_host(u.trim()) {
                Some(("http", h)) if !h.is_empty() => {}
                _ => return Err(format!("адрес центра {u:?}: нужен http://адрес:порт/api/v1/report (данные шифруются сами)")),
            }
        }
    }
    let u = &c.billing.tasix_url;
    if u != BILLING_FILE_SRC {
        match netx::url_scheme_host(u) {
            Some(("http" | "https", h)) if !h.is_empty() => {}
            _ => return Err("список бесплатных сетей: нужна ссылка http(s)://… или file (загруженный файл)".into()),
        }
    }
    if !matches!(c.log_level.to_lowercase().as_str(), "error" | "err" | "info" | "debug") {
        return Err("log_level: error | info | debug".into());
    }
    for n in c.lan_networks.iter().chain(&c.tunnel_networks).chain(&c.exclude_networks) {
        if netx::parse_cidr(n).is_none() && netx::parse_ip(n).is_none() {
            return Err(format!("сеть {n:?}: нужен CIDR"));
        }
    }
    Ok(())
}

// ---- подсказки: комментарии ключей в cgmon.yaml ----

/// Комментарий над ключом и в его строке → «путь → текст» (≤ 400 байт).
/// Закомментированные примеры «ключ: значение» — не пояснение.
pub fn hints(text: &str) -> Vec<(String, String)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    let is_key_example = |l: &str| {
        let l = l.trim_start_matches('-').trim_start();
        let k = l.split(':').next().unwrap_or("");
        l.contains(':') && !k.is_empty() && k.bytes().next().map_or(false, |c| c.is_ascii_lowercase() || c == b'_') && k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') && {
            let rest = &l[k.len() + 1..];
            rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')
        }
    };
    let clean = |l: &str| -> Option<String> {
        let l = l.trim().trim_start_matches('#').trim();
        if l.trim_matches(['-', '=', '*', '#', ' ']).is_empty() || is_key_example(l) {
            None
        } else {
            Some(l.to_string())
        }
    };
    for raw in text.lines() {
        let t = raw.trim();
        if t.is_empty() {
            pending.clear();
            continue;
        }
        if t.starts_with('#') {
            if let Some(c) = clean(t) {
                pending.push(c);
            }
            continue;
        }
        let ind = raw.len() - raw.trim_start().len();
        if t.starts_with('-') {
            pending.clear();
            continue;
        }
        let Some(colon) = t.find(':').filter(|&i| t[..i].bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')) else {
            pending.clear();
            continue;
        };
        while stack.last().map_or(false, |(i, _)| *i >= ind) {
            stack.pop();
        }
        let key = &t[..colon];
        let path = match stack.last() {
            Some((_, p)) => format!("{p}.{key}"),
            None => key.to_string(),
        };
        let mut parts = std::mem::take(&mut pending);
        if let Some(h) = t.find(" #") {
            if let Some(c) = clean(&t[h + 2..]) {
                parts.push(c);
            }
        }
        if !parts.is_empty() {
            let mut h = parts.join(" ");
            if h.len() > 400 {
                let mut n = 400;
                while !h.is_char_boundary(n) {
                    n -= 1;
                }
                h.truncate(n);
                h.push('…');
            }
            out.push((path.clone(), h));
        }
        stack.push((ind, path));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::defaults;

    #[test]
    fn set_and_hidden() {
        let mut c = defaults();
        c.normalize();
        assert!(set(&mut c, "dns_guard.relay_mbit", &Value::Num("30".into())).is_ok());
        assert_eq!(c.dns_guard.relay_mbit, 30);
        assert_eq!(set(&mut c, "web.password", &Value::Str("x".into())), Err("not editable".into()));
        assert_eq!(set(&mut c, "hub.token", &Value::Str("x".into())), Err("not editable".into()));
        assert!(set(&mut c, "hub.enabled", &Value::Bool(true)).is_ok()); // основная настройка
        assert!(set(&mut c, "log_level", &Value::Str("a;rm -rf".into())).is_err());
        assert!(set(&mut c, "payment.note", &Value::Str("Оплата №5".into())).is_ok());
        assert!(set(&mut c, "probes.ipv4", &parse_json(r#"["192.0.2.1:443", " "]"#).unwrap()).is_ok());
        assert_eq!(c.probes.ipv4, vec!["192.0.2.1:443"]);
        assert!(set(&mut c, "interval_sec", &Value::Num("1.5".into())).is_err());
        assert!(set(&mut c, "no.such", &Value::Bool(true)).is_err());
    }

    #[test]
    fn live_build_and_validate() {
        let mut base = defaults();
        base.normalize();
        assert!(validate(&base).is_ok(), "{:?}", validate(&base));
        let ov = vec![("dns_guard.relays".to_string(), parse_json(r#"["node1@10.147.17.5"]"#).unwrap())];
        assert!(build_live(&base, &ov).is_ok());
        let bad = vec![("dns_guard.relays".to_string(), parse_json(r#"["node1@8.8.8.8"]"#).unwrap())];
        // в lite/nano ретрансляторов нет (variant::limit очищает) — проверять нечего
        if crate::variant::EXT {
            assert!(build_live(&base, &bad).is_err());
        }
        assert!(same_as_base(&base, "interval_sec", &Value::Num(base.interval_sec.to_string())));
        assert!(!same_as_base(&base, "interval_sec", &Value::Num("9".into())));
    }

    #[test]
    fn helpers() {
        assert!(domain_ok("ipleak.net") && !domain_ok("dns.google") && !domain_ok("-a.com") && !domain_ok("localhost"));
        assert!(date_ok("2024-02-29") && !date_ok("2023-02-29") && !date_ok("2024-13-01"));
        assert!(tg_bot_ok("123456:ABCDEFGHIJKLMNOPQRSTU") && !tg_bot_ok("12:x"));
        assert!(tg_chat_ok("-1001234") && tg_chat_ok("@chan") && !tg_chat_ok("ab"));
    }

    #[test]
    fn hints_from_comments() {
        let y = "# Уровень журнала\nlog_level: info\n\nprobes:\n  # Цели IPv4\n  # interval: 5\n  ipv4: [] # и ещё\n";
        let h = hints(y);
        assert_eq!(h, vec![("log_level".to_string(), "Уровень журнала".to_string()), ("probes.ipv4".to_string(), "Цели IPv4 и ещё".to_string())]);
    }
}
