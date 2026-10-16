//! Выделенные подсети — квартиранты (перенос isolation.go): каждый VLAN
//! (устройство) зоны из isolated_zones — группа; зашедший на страницу из неё
//! видит только свои устройства, без настроек и чужих имён. Фильтрует сам
//! роутер: демон пишет группы в /tmp/cgmon_isolated.json, CGI урезают ответ
//! по REMOTE_ADDR. Нет групп — нет файла, CGI остаются простым cat.

use crate::cgi::{cidr_contains, iso_group_for, ISOLATION_FILE};
use crate::config::Config;
use crate::json::J;
use crate::topo::{self, Netifd};
use crate::value::{parse_json, Value};
use std::io::{Read, Write};

/// Группы: (зона/устройство, сети).
pub fn groups(cfg: &Config, netifd: &mut Netifd, now: u64) -> Vec<(String, Vec<String>)> {
    if cfg.isolated_zones.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for c in topo::lan_choices(cfg, netifd, now) {
        if !c.on || c.fixed || !cfg.isolated_zones.contains(&c.name) {
            continue;
        }
        for d in &c.devices {
            let nets = topo::dev_cidrs(d);
            if !nets.is_empty() {
                out.push((format!("{}/{}", c.name, d), nets));
            }
        }
    }
    out
}

/// Файл групп для CGI (нет групп — файла нет).
pub fn write(cfg: &Config, netifd: &mut Netifd, now: u64) {
    if crate::util::readonly() {
        return;
    }
    let g = groups(cfg, netifd, now);
    if g.is_empty() {
        let _ = std::fs::remove_file(ISOLATION_FILE);
        return;
    }
    let mut j = J::new();
    j.arr();
    for (n, nets) in &g {
        j.obj().key("name").str(n).key("nets").arr();
        for x in nets {
            j.str(x);
        }
        j.end_arr().end_obj();
    }
    j.end_arr();
    let _ = crate::util::write_atomic(ISOLATION_FILE, j.b.as_bytes(), 0o644);
}

const TENANT_KEYS: &[&str] = &["time", "version", "uptime", "state", "diagnosis", "router_name", "ipv4", "ipv6", "ipv6_available", "udp4", "udp6", "udp6_available", "wan", "conntrack", "local", "sys_extra", "wan_link", "gate", "incidents", "down_detector", "top", "clients_all"];

fn in_nets(ip: &str, nets: &[String]) -> bool {
    ip.parse::<std::net::IpAddr>().map_or(false, |a| nets.iter().any(|n| cidr_contains(n, &a)))
}

/// Текст события без упоминаний устройств.
pub fn tenant_text(s: &str) -> String {
    let mut s = s.to_string();
    for cut in ["; больше всех соединений", "; клиенты:"] {
        if let Some(i) = s.find(cut) {
            s.truncate(i);
        }
    }
    s
}

/// Статус для выделенной подсети.
pub fn tenant_status(st: &Value, nets: &[String]) -> Value {
    let mut out: Vec<(String, Value)> = vec![("tenant".into(), Value::Bool(true))];
    let Value::Map(m) = st else { return Value::Map(out) };
    for (k, v) in m {
        if !TENANT_KEYS.contains(&k.as_str()) {
            continue;
        }
        let v = match (k.as_str(), v) {
            ("top" | "clients_all", Value::List(l)) => {
                // как Go: пустой список — null (nil-срез)
                let keep: Vec<Value> = l.iter().filter(|c| c.get("ip").and_then(|x| x.as_str()).map_or(false, |ip| in_nets(ip, nets))).cloned().collect();
                if keep.is_empty() {
                    Value::Null
                } else {
                    Value::List(keep)
                }
            }
            ("wan", Value::Map(w)) => Value::Map(w.iter().filter(|(k, _)| !k.starts_with("top_client")).cloned().collect()),
            ("incidents", Value::List(l)) => Value::List(
                l.iter()
                    .map(|x| {
                        let mut c: Vec<(String, Value)> = ["id", "type", "open", "start", "end", "duration_sec", "result"].iter().filter_map(|k| x.get(k).map(|v| (k.to_string(), v.clone()))).collect();
                        c.push(("text".into(), Value::Str(tenant_text(x.get("text").and_then(|t| t.as_str()).unwrap_or("")))));
                        Value::Map(c)
                    })
                    .collect(),
            ),
            ("down_detector", Value::Map(dd)) => Value::Map(
                dd.iter()
                    .map(|(k, v)| match (k.as_str(), v) {
                        ("services", Value::List(l)) => (k.clone(), Value::List(l.iter().map(|s| if let Value::Map(sm) = s { Value::Map(sm.iter().filter(|(k, _)| k != "clients").cloned().collect()) } else { s.clone() }).collect())),
                        _ => (k.clone(), v.clone()),
                    })
                    .collect(),
            ),
            _ => v.clone(),
        };
        out.push((k.clone(), v));
    }
    Value::Map(out)
}

/// /cgi-bin/api_status при выделенных подсетях.
pub fn cgi_status(status_path: &str) -> i32 {
    let _ = std::fs::write(crate::util::WEB_HB, b"");
    print!("Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n");
    let Ok(b) = std::fs::read_to_string(status_path) else {
        println!("{{}}");
        return 0;
    };
    let Some(nets) = iso_group_for(&std::env::var("REMOTE_ADDR").unwrap_or_default()) else {
        let _ = std::io::stdout().write_all(b.as_bytes());
        return 0;
    };
    match parse_json(&b) {
        Ok(st) => {
            let mut s = String::new();
            tenant_status(&st, &nets).to_json(&mut s);
            let _ = std::io::stdout().write_all(s.as_bytes());
        }
        Err(_) => println!("{{}}"),
    }
    0
}

/// Фильтр JSON api_router (stdin → stdout): квартиранту — имена и MAC только своих.
pub fn cgi_filter() -> i32 {
    let mut b = String::new();
    let _ = std::io::stdin().take(4 << 20).read_to_string(&mut b);
    let Some(nets) = iso_group_for(&std::env::var("REMOTE_ADDR").unwrap_or_default()) else {
        let _ = std::io::stdout().write_all(b.as_bytes());
        return 0;
    };
    let Ok(Value::Map(mut m)) = parse_json(&b) else {
        let _ = std::io::stdout().write_all(b.as_bytes());
        return 0;
    };
    for (k, v) in m.iter_mut() {
        if k == "names" || k == "macs" {
            if let Value::Map(mm) = v {
                mm.retain(|(ip, _)| in_nets(ip, &nets));
            }
        }
    }
    m.retain(|(k, _)| k != "tenant");
    m.push(("tenant".into(), Value::Bool(true)));
    let mut s = String::new();
    Value::Map(m).to_json(&mut s);
    let _ = std::io::stdout().write_all(s.as_bytes());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_view() {
        let st = parse_json(r#"{"time":"t","runtime":{"x":1},"top":[{"ip":"192.168.7.5"},{"ip":"192.168.1.5"}],"wan":{"total":3,"top_client":"192.168.1.5"},"incidents":[{"id":1,"type":"degradation","text":"Новые соединения IPv4 не проходят; больше всех соединений у PC (192.168.1.5) — 40","context":"c"}],"down_detector":{"services":[{"name":"x","clients":["a"]}]}}"#).unwrap();
        let t = tenant_status(&st, &["192.168.7.0/24".to_string()]);
        let mut s = String::new();
        t.to_json(&mut s);
        assert_eq!(s, r#"{"tenant":true,"time":"t","top":[{"ip":"192.168.7.5"}],"wan":{"total":3},"incidents":[{"id":1,"type":"degradation","text":"Новые соединения IPv4 не проходят"}],"down_detector":{"services":[{"name":"x"}]}}"#);
    }
}
