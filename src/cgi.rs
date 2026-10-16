//! CGI для страницы: `cgmon cgi-set` (/cgi-bin/api_set — 2 строки sh с exec).
//! Весь разбор здесь: только POST, тело ≤ 16 КБ (≤ 1 МБ — только список
//! бесплатных сетей), JSON-объект с белым списком ключей, квартирантам — 403.

use crate::config;
use crate::daemon;
use crate::netx;
use crate::runtime::{KEYS, MAX_BODY, MAX_UPLOAD};
use crate::value::{json_str, parse_json, Value};
use std::io::Read;

pub const ISOLATION_FILE: &str = "/tmp/cgmon/isolated.json";

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn reply(code: u16, body: &str) -> i32 {
    print!("Status: {} {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n{}\n", code, status_text(code), body);
    0
}

fn fail(code: u16, msg: &str) -> i32 {
    let mut s = String::from("{\"error\":");
    json_str(&mut s, msg);
    s.push('}');
    reply(code, &s)
}

/// Сети группы квартирантов, в которую входит адрес (None — полный доступ).
pub fn iso_group_for(remote: &str) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(ISOLATION_FILE).ok()?;
    let Ok(Value::List(gs)) = parse_json(&text) else { return None };
    let ip = netx::parse_ip(remote.trim_matches(['[', ']']))?;
    for g in gs {
        let Some(Value::List(nets)) = g.get("nets") else { continue };
        let nets: Vec<String> = nets.iter().filter_map(|n| n.as_str().map(String::from)).collect();
        if nets.iter().any(|n| cidr_contains(n, &ip)) {
            return Some(nets);
        }
    }
    None
}

pub fn cidr_contains(cidr: &str, ip: &std::net::IpAddr) -> bool {
    let Some((net, bits)) = netx::parse_cidr(cidr) else { return false };
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(a)) => {
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(n) & m == u32::from(*a) & m
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(a)) => {
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(n) & m == u128::from(*a) & m
        }
        _ => false,
    }
}

pub fn is_tenant() -> bool {
    iso_group_for(&std::env::var("REMOTE_ADDR").unwrap_or_default()).is_some()
}

pub fn set(config_path: &str) -> i32 {
    if is_tenant() {
        return fail(403, "forbidden");
    }
    if std::env::var("REQUEST_METHOD").as_deref() != Ok("POST") {
        return fail(405, "POST only");
    }
    let n: usize = match std::env::var("CONTENT_LENGTH").ok().and_then(|s| s.parse().ok()) {
        Some(n) if n > 0 && n <= MAX_UPLOAD => n,
        _ => return fail(413, "bad length"),
    };
    let mut body = vec![0u8; n];
    if std::io::stdin().read_exact(&mut body).is_err() {
        return fail(400, "bad body");
    }
    let Ok(text) = String::from_utf8(body) else { return fail(400, "bad request") };
    let v = match parse_json(&text) {
        Ok(v @ Value::Map(_)) => v,
        _ => return fail(400, "bad request"),
    };
    let map_len = |k: &str| match v.get(k) {
        Some(Value::Map(m)) => m.len(),
        _ => 0,
    };
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    let (password, free, l2o, l2c) = (s("password"), s("free_nets"), s("l2_open"), s("l2_close"));
    let get_config = v.get("get_config").and_then(|x| x.as_bool()).unwrap_or(false);
    let l2_scan = v.get("l2_scan").and_then(|x| x.as_bool()).unwrap_or(false);
    let extras = v.get("extras").and_then(|x| x.as_bool()).unwrap_or(false);
    let l2_on = v.get("l2_on").and_then(|x| x.as_bool()).unwrap_or(false);
    let forget = s("hub_forget");
    // установка пакетов: true — недостающее для включённых функций, строка — имена через пробел
    let install = match v.get("install") {
        Some(Value::Bool(true)) => Some(String::new()),
        Some(Value::Str(x)) if x.len() <= 200 && x.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == ' ') => Some(x.trim().to_string()),
        Some(_) => return fail(400, "bad request"),
        None => None,
    };
    let (nset, ncfg) = (map_len("set"), map_len("config"));
    if (nset == 0 && ncfg == 0 && !get_config && free.is_empty() && l2o.is_empty() && l2c.is_empty() && !l2_scan && !extras && !l2_on && forget.is_empty() && install.is_none()) || password.len() > 128 || ncfg > 300 {
        return fail(400, "bad request");
    }
    // большое тело — только загрузка списка, без других настроек
    if n > MAX_BODY && (free.is_empty() || nset > 0 || ncfg > 0 || get_config) {
        return fail(413, "bad length");
    }
    if let Some(Value::Map(m)) = v.get("set") {
        if m.iter().any(|(k, _)| !KEYS.contains(&k.as_str())) {
            return fail(400, "unknown setting");
        }
    }
    let mut req = String::new();
    let pw = |r: &mut String| {
        r.push_str(",\"password\":");
        json_str(r, password);
    };
    if get_config {
        req.push_str("{\"cmd\":\"config_get\"}"); // чтение — без пароля (секретов там нет)
    } else if !forget.is_empty() {
        req.push_str("{\"cmd\":\"hub_forget\",\"text\":");
        json_str(&mut req, forget);
        pw(&mut req);
        req.push('}');
    } else if let Some(p) = &install {
        req.push_str("{\"cmd\":\"pkg_install\",\"text\":");
        json_str(&mut req, p);
        pw(&mut req);
        req.push('}');
    } else if l2_on {
        req.push_str("{\"cmd\":\"l2_on\"}"); // ловец устройств на 30 минут — только слушает
    } else if extras {
        req.push_str("{\"cmd\":\"extras\"}"); // показать порты и TOP на 5 минут — ничего не меняет
    } else if !free.is_empty() {
        req.push_str("{\"cmd\":\"free_nets\",\"text\":");
        json_str(&mut req, free);
        pw(&mut req);
        req.push('}');
    } else if !l2o.is_empty() || !l2c.is_empty() {
        req.push_str(if !l2o.is_empty() { "{\"cmd\":\"l2_open\",\"text\":" } else { "{\"cmd\":\"l2_close\",\"text\":" });
        json_str(&mut req, if !l2o.is_empty() { l2o } else { l2c });
        pw(&mut req);
        req.push('}');
    } else if l2_scan {
        req.push_str("{\"cmd\":\"l2_scan\"");
        pw(&mut req);
        req.push('}');
    } else {
        req.push_str("{\"cmd\":\"set\"");
        for k in ["set", "config"] {
            if let Some(x) = v.get(k) {
                req.push_str(",\"");
                req.push_str(k);
                req.push_str("\":");
                x.to_json(&mut req);
            }
        }
        pw(&mut req);
        req.push('}');
    }
    let cfg = match config::load(config_path) {
        Ok(c) => c,
        Err(_) => return fail(500, "config"),
    };
    match daemon::request(&cfg.paths.socket, &req, 5000) {
        Ok(resp) => {
            let bad = parse_json(&resp).ok().map_or(true, |r| r.get("error").is_some());
            reply(if bad { 400 } else { 200 }, &resp)
        }
        Err(_) => fail(503, "cgmon is not running"),
    }
}

/// История графика (CGI api_hist, GET ?sec=N): выделенным подсетям — 403
/// (в истории имена устройств).
pub fn hist(config_path: &str) -> i32 {
    if is_tenant() {
        return fail(403, "forbidden");
    }
    let q = std::env::var("QUERY_STRING").unwrap_or_default();
    let sec: i64 = q.split('&').find_map(|kv| kv.strip_prefix("sec=")).and_then(|v| v.parse().ok()).unwrap_or(600).clamp(60, 86_400);
    let cfg = match config::load(config_path) {
        Ok(c) => c,
        Err(_) => return fail(500, "config"),
    };
    match daemon::request(&cfg.paths.socket, &format!("{{\"cmd\":\"hist\",\"sec\":{sec}}}"), 5000) {
        Ok(resp) => reply(200, &resp),
        Err(_) => fail(503, "cgmon is not running"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let ip: std::net::IpAddr = "192.168.7.20".parse().unwrap();
        assert!(cidr_contains("192.168.7.0/24", &ip));
        assert!(!cidr_contains("192.168.8.0/24", &ip));
        let v6: std::net::IpAddr = "2001:db8::5".parse().unwrap();
        assert!(cidr_contains("2001:db8::/32", &v6) && !cidr_contains("192.168.7.0/24", &v6));
    }
}
