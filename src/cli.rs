//! Команды CLI (перенос handleCLI/printStatus/printTop из main.go): вывод
//! состояния таблицами с цветом (NO_COLOR, не терминал — без цвета), команды
//! демону через сокет, проверка пакетов, пробное сообщение в Telegram.

use crate::config::Config;
use crate::value::{parse_json, Value};
use std::io::IsTerminal;

const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";

fn color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn paint(s: &str, c: &str) -> String {
    if color() {
        format!("{c}{s}{RESET}")
    } else {
        s.to_string()
    }
}

fn good(s: &str) -> String {
    paint(s, GREEN)
}
fn warn(s: &str) -> String {
    paint(s, YELLOW)
}
fn bad(s: &str) -> String {
    paint(s, RED)
}
fn info(s: &str) -> String {
    paint(s, CYAN)
}
fn blue(s: &str) -> String {
    paint(s, BLUE)
}

fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if !esc && c == '\x1b' {
            esc = true;
            continue;
        }
        if esc {
            if c == 'm' {
                esc = false;
            }
            continue;
        }
        n += 1;
    }
    n
}

fn pad_right(s: &str, w: usize) -> String {
    let l = visible_len(s);
    if l >= w {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(w - l))
    }
}

fn pad_left(s: &str, w: usize) -> String {
    let l = visible_len(s);
    if l >= w {
        s.to_string()
    } else {
        format!("{}{s}", " ".repeat(w - l))
    }
}

fn trunc_right(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        return s.to_string();
    }
    if w <= 3 {
        return s.chars().take(w).collect();
    }
    format!("{}...", s.chars().take(w - 3).collect::<String>())
}

fn trunc_left(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        return s.to_string();
    }
    if w <= 3 {
        return s.chars().skip(n - w).collect();
    }
    format!("...{}", s.chars().skip(n - (w - 3)).collect::<String>())
}

fn short_ip(s: &str) -> String {
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.to_string(),
        Ok(a) => {
            let s = a.to_string();
            if s.len() <= 20 {
                return s;
            }
            let p: Vec<&str> = s.split(':').collect();
            let short = format!("{}:...{}", p[0], p[p.len() - 1]);
            if short.len() <= 20 {
                short
            } else {
                trunc_left(&short, 20)
            }
        }
        Err(_) => trunc_left(s, 20),
    }
}

fn color_state(s: &str) -> String {
    match s {
        "HEALTHY" | "NORMAL" => good(s),
        "WARNING" | "LOCAL_PRESSURE" => warn(s),
        "CRITICAL" | "UNKNOWN" => bad(s),
        _ => info(s),
    }
}

fn color_diag(s: &str) -> String {
    match s {
        "HEALTHY" => good(s),
        "MONITORING_ONLY" => info(s),
        "LOCAL_PRESSURE" | "IPV6_DEGRADATION" | "UNKNOWN" => warn(s),
        "IPV4_EXTERNAL_DEGRADATION" => bad(s),
        _ => s.to_string(),
    }
}

fn color_rate(v: f64, count: i64, hi_good: bool) -> String {
    if count == 0 {
        return warn("no data");
    }
    let s = format!("{v:.1}%");
    let (g, w) = if hi_good { (v >= 98.0, v >= 95.0) } else { (v <= 2.0, v <= 5.0) };
    if g {
        good(&s)
    } else if w {
        warn(&s)
    } else {
        bad(&s)
    }
}

fn color_high(v: f64, w: f64, b: f64) -> String {
    let s = format!("{v:.1}%");
    if v >= b {
        bad(&s)
    } else if v >= w {
        warn(&s)
    } else {
        good(&s)
    }
}

/// Значение по пути «a.b.c».
fn at<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for k in path.split('.') {
        cur = cur.get(k)?;
    }
    Some(cur)
}

fn s(v: &Value, p: &str) -> String {
    at(v, p).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn n(v: &Value, p: &str) -> f64 {
    at(v, p).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn i(v: &Value, p: &str) -> i64 {
    n(v, p) as i64
}

fn b(v: &Value, p: &str) -> bool {
    at(v, p).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn list<'a>(v: &'a Value, p: &str) -> &'a [Value] {
    match at(v, p) {
        Some(Value::List(l)) => l,
        _ => &[],
    }
}

fn table(headers: &[&str], widths: &[usize], right: &[bool], rows: &[Vec<String>]) {
    let mut line = String::new();
    for (k, h) in headers.iter().enumerate() {
        let c = info(h);
        line.push_str(&if k > 0 && right[k] { pad_left(&c, widths[k]) } else { pad_right(&c, widths[k]) });
        if k + 1 < headers.len() {
            line.push_str("  ");
        }
    }
    println!("{line}");
    for r in rows {
        let mut line = String::new();
        for k in 0..headers.len() {
            let c = r.get(k).cloned().unwrap_or_default();
            line.push_str(&if right[k] { pad_left(&c, widths[k]) } else { pad_right(&c, widths[k]) });
            if k + 1 < headers.len() {
                line.push_str("  ");
            }
        }
        println!("{line}");
    }
    println!();
}

/// Время RFC 3339 → «ГГГГ-ММ-ДД ЧЧ:ММ:СС» местное (short — без года).
fn fmt_time(t: &str, short: bool) -> String {
    match crate::util::parse_rfc3339(t) {
        Some((sec, _)) if sec > 0 => {
            let m = crate::util::local(sec);
            if short {
                format!("{:02}-{:02} {:02}:{:02}:{:02}", m.mon, m.day, m.hour, m.min, m.sec)
            } else {
                format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", m.year, m.mon, m.day, m.hour, m.min, m.sec)
            }
        }
        _ => "-".into(),
    }
}

fn probe_lines(p: &Value) -> Vec<String> {
    if !b(p, "available") {
        return vec!["unavailable".into()];
    }
    if i(p, "count") == 0 {
        return vec!["no data".into()];
    }
    vec![
        format!("window:  {}s", i(p, "window_sec")),
        format!("count:   {}", i(p, "count")),
        format!("success: {}", color_rate(n(p, "success_rate"), i(p, "count"), true)),
        format!("timeout: {}", color_rate(n(p, "timeout_rate"), i(p, "count"), false)),
        format!("latency: {:.1} ms", n(p, "avg_latency_ms")),
    ]
}

/// cgmon status — таблицами (как Go printStatus).
pub fn print_status(raw: &str) {
    let Ok(st) = parse_json(raw) else {
        println!("{raw}");
        return;
    };
    println!("CGMON STATUS\n------------\n");
    let cores = i(&st, "local.num_cpu");
    let load = n(&st, "local.load1");
    let load_s = format!("{load:.2}");
    let load_c = if cores <= 0 {
        load_s
    } else if load / cores as f64 >= 0.9 {
        bad(&load_s)
    } else if load / cores as f64 >= 0.7 {
        warn(&load_s)
    } else {
        good(&load_s)
    };
    let mem = i(&st, "local.mem_available_mb");
    let mem_s = format!("{mem} MB");
    let mem_c = if mem <= 32 { bad(&mem_s) } else if mem <= 64 { warn(&mem_s) } else { good(&mem_s) };
    let left = [format!("State: {}", color_state(&s(&st, "state"))), format!("Diagnosis: {}", color_diag(&s(&st, "diagnosis")))];
    let right = [
        format!("Local: cpu={} load={} mem={} cores={}", color_high(n(&st, "local.cpu_percent"), 75.0, 90.0), load_c, mem_c, cores),
        format!("Uptime: {}  Dry-run: {}  Limiter: {}  Grace: {}", s(&st, "uptime"), b(&st, "dry_run"), b(&st, "enable_limiter"), b(&st, "grace")),
    ];
    for k in 0..2 {
        println!("{}{}", pad_right(&left[k], 50), right[k]);
    }
    println!();
    let w = |k: &str| i(&st, &format!("wan.{k}"));
    let v4 = w("lan_to_wan_ipv4") + w("router_own_ipv4") + w("incoming_ipv4");
    let v6 = w("lan_to_wan_ipv6") + w("router_own_ipv6") + w("incoming_ipv6");
    let mut worst = 100.0;
    if i(&st, "ipv4.count") > 0 {
        worst = n(&st, "ipv4.success_rate");
    }
    if b(&st, "ipv6_available") && i(&st, "ipv6.count") > 0 && n(&st, "ipv6.success_rate") < worst {
        worst = n(&st, "ipv6.success_rate");
    }
    let nc = if worst < 80.0 { RED } else if worst < 95.0 { YELLOW } else { GREEN };
    let l = format!("{} {}", info("TOTAL WAN IPV4 CONNECTIONS:"), paint(&v4.to_string(), nc));
    println!("{}{} {}\n", pad_right(&l, 50), info("TOTAL WAN IPV6 CONNECTIONS:"), paint(&v6.to_string(), nc));
    // трафик провайдера
    let lan_other = (w("lan_to_wan") - w("lan_to_wan_tcp") - w("lan_to_wan_udp")).max(0);
    let r = |k: &str| (w(&format!("router_own{k}")) - w(&format!("router_own_tunnel{k}")) - w(&format!("router_own_probe{k}"))).max(0);
    let (rt, rtcp, rudp) = (r(""), r("_tcp"), r("_udp"));
    let mut rows = vec![
        vec![info("incoming"), w("incoming").to_string(), format!("{:.1}", n(&st, "wan.new_incoming_rate")), "-".into(), "-".into(), "-".into(), w("incoming_ipv4").to_string(), w("incoming_ipv6").to_string()],
        vec!["lan clients".into(), w("lan_to_wan").to_string(), format!("{:.1}", n(&st, "wan.new_lan_rate")), w("lan_to_wan_tcp").to_string(), w("lan_to_wan_udp").to_string(), lan_other.to_string(), w("lan_to_wan_ipv4").to_string(), w("lan_to_wan_ipv6").to_string()],
        vec![good("router"), rt.to_string(), format!("{:.1}", n(&st, "wan.new_router_rate")), rtcp.to_string(), rudp.to_string(), (rt - rtcp - rudp).max(0).to_string(), r("_ipv4").to_string(), r("_ipv6").to_string()],
    ];
    for (sub, label) in [("_tunnel", blue("+ tunnel")), ("_probe", info("+ probes (cgmon)"))] {
        if w(&format!("router_own{sub}")) > 0 {
            let g = |k: &str| w(&format!("router_own{sub}{k}")).to_string();
            rows.push(vec![format!("  {label}"), g(""), "-".into(), g("_tcp"), g("_udp"), "-".into(), g("_ipv4"), g("_ipv6")]);
        }
    }
    println!("WAN provider traffic");
    table(&["category", "total", "new/s", "tcp", "udp", "other", "ipv4", "ipv6"], &[22, 8, 8, 7, 7, 7, 8, 8], &[false, true, true, true, true, true, true, true], &rows);
    // самые активные
    let top = list(&st, "top");
    if top.is_empty() {
        println!("Top clients: none\n");
    } else {
        let rows: Vec<Vec<String>> = top.iter().map(|c| vec![name_of(c), i(c, "wan").to_string(), i(c, "incoming").to_string(), i(c, "total").to_string(), format!("{:.1}", n(c, "new_rate"))]).collect();
        println!("Top {} clients", top.len());
        table(&["host/ip", "wan", "inc", "total", "new/s"], &[22, 8, 7, 8, 8], &[false, true, true, true, true], &rows);
    }
    let segs = list(&st, "lan_segments");
    if !segs.is_empty() {
        let rows: Vec<Vec<String>> = segs.iter().map(|x| vec![trunc_right(&s(x, "network"), 28), i(x, "clients").to_string(), i(x, "wan").to_string(), i(x, "incoming").to_string(), short_ip(&s(x, "leader")), i(x, "leader_wan").to_string()]).collect();
        println!("LAN segments");
        table(&["network", "clients", "wan", "inc", "leader", "leader_wan"], &[28, 8, 8, 7, 22, 10], &[false, true, true, true, false, true], &rows);
    }
    let mut rows = Vec::new();
    for (k, label, at_k) in [("total_wan", "total wan", "total_wan_at"), ("lan_to_wan", "lan_to_wan", "lan_to_wan_at"), ("router_own", "router_own", "router_own_at")] {
        let v = i(&st, &format!("peaks.{k}"));
        if v > 0 {
            rows.push(vec![label.into(), v.to_string(), fmt_time(&s(&st, &format!("peaks.{at_k}")), false)]);
        }
    }
    let tw = i(&st, "peaks.top_client_wan");
    if tw > 0 {
        rows.push(vec!["top client".into(), format!("{tw} by {}", short_ip(&s(&st, "peaks.top_client_ip"))), fmt_time(&s(&st, "peaks.top_client_at"), false)]);
    }
    if !rows.is_empty() {
        println!("Peaks since start");
        table(&["metric", "value", "at"], &[16, 34, 19], &[false, false, false], &rows);
    }
    // пробы колонками
    let titles = ["IPv4 TCP probes", "IPv6 TCP probes", "IPv4 UDP probes", "IPv6 UDP probes"];
    let cols: Vec<Vec<String>> = ["ipv4", "ipv6", "udp4", "udp6"].iter().map(|k| at(&st, k).map(probe_lines).unwrap_or_default()).collect();
    println!("{}", titles.iter().map(|t| pad_right(&info(t), 24)).collect::<Vec<_>>().join(" "));
    for row in 0..5 {
        println!("{}", cols.iter().map(|c| pad_right(c.get(row).map(|x| x.as_str()).unwrap_or(""), 24)).collect::<Vec<_>>().join(" "));
    }
    println!();
    if b(&st, "dynamic_limits.active") {
        println!("Dynamic limits:     {} host={} limit={} blocked={}", good("active"), s(&st, "dynamic_limits.ip"), i(&st, "dynamic_limits.limit"), b(&st, "dynamic_limits.blocked"));
    } else {
        println!("Dynamic limits:     active=no");
    }
    if b(&st, "dry_run_action.active") {
        println!("Dry-run action:     {} host={} wan={} inc={} limit={}", warn("would limit"), s(&st, "dry_run_action.ip"), i(&st, "dry_run_action.current_wan"), i(&st, "dry_run_action.current_incoming"), i(&st, "dry_run_action.calculated_limit"));
    } else {
        println!("Dry-run action:     none");
    }
    println!();
    if let Some(us) = st.get("upload_shaper") {
        let mb = |k: &str| format!("[{}]", list(us, k).iter().map(|x| crate::config::go_float(x.as_f64().unwrap_or(0.0))).collect::<Vec<_>>().join(" "));
        println!("Upload shaper\n  {}: stage {}, {} kbit, tx {:.1} Mbit/s, buckets MB {} of {}", s(us, "device"), i(us, "stage") + 1, i(us, "rate_kbit"), n(us, "tx_mbps"), mb("bucket_mb"), mb("cap_mb"));
        if i(us, "cooldown_sec") > 0 {
            println!("  ISP penalty cooldown: no bursts for {}s", i(us, "cooldown_sec"));
        }
        if n(us, "debt_mb") > 0.0 {
            println!("  debt over sustained: {:.1} MB", n(us, "debt_mb"));
        }
        if !s(us, "error").is_empty() {
            println!("  error: {}", s(us, "error"));
        }
        println!();
    }
    if let Some(fw) = st.get("flow_watch") {
        let targets = list(fw, "targets");
        if s(fw, "state") != "ok" || !targets.is_empty() {
            let mut l = format!("Flow watch: {}", s(fw, "state"));
            if !s(fw, "since").is_empty() {
                l.push_str(&format!(" since {}", &fmt_time(&s(fw, "since"), true)[6..]));
            }
            if !s(fw, "suspect").is_empty() {
                l.push_str(&format!(" ({})", s(fw, "suspect")));
            }
            println!("{l}");
            for t in targets {
                let mode = if i(t, "hop") > 0 { format!("hop {}", i(t, "hop")) } else { s(t, "mode") };
                println!("  {:<16} {:<6} probes {:2}, loss {:3.0}%, median {:.0} ms, base {:.0} ms", s(t, "ip"), mode, i(t, "count"), n(t, "loss_pct"), n(t, "median_ms"), n(t, "base_ms"));
            }
            println!();
        }
    }
    let peers = list(&st, "peers");
    if !peers.is_empty() {
        let rows: Vec<Vec<String>> = peers.iter().map(|p| {
            let state = s(p, "state");
            let sc = match state.as_str() {
                "ok" => good(&state),
                "degraded" => bad(&state),
                _ => warn(&state),
            };
            vec![s(p, "name"), s(p, "probe"), sc, format!("{:.0}%", n(p, "success_rate")), i(p, "count").to_string(), format!("{:.0} ms", n(p, "avg_latency_ms")), trunc_right(&s(p, "suspect"), 60)]
        }).collect();
        println!("Peers (overlay paths)");
        table(&["peer", "probe", "state", "success", "count", "latency", "suspect"], &[12, 21, 9, 8, 6, 9, 60], &[false, false, false, true, true, true, false], &rows);
    }
    let flows = list(&st, "wan_flows");
    if !flows.is_empty() {
        let rows: Vec<Vec<String>> = flows.iter().map(|f| vec![s(f, "proto"), trunc_left(&s(f, "local"), 27), trunc_left(&s(f, "remote"), 27), format!("{:.2}", n(f, "tx_mbps")), format!("{:.2}", n(f, "rx_mbps")), format!("{:.1}", n(f, "peak_tx_mbps")), format!("{:.1}", n(f, "peak_rx_mbps"))]).collect();
        println!("Top WAN flows");
        table(&["proto", "local", "remote", "tx Mbit", "rx Mbit", "peak tx", "peak rx"], &[5, 27, 27, 8, 8, 8, 8], &[false, false, false, true, true, true, true], &rows);
    }
    let evs: Vec<&Value> = list(&st, "events").iter().filter(|e| !(s(e, "type") == "state" && s(e, "message").contains("MONITORING_ONLY"))).take(8).collect();
    if !evs.is_empty() {
        println!("Recent events");
        for e in evs {
            let t = s(e, "type");
            let tc = match t.as_str() {
                "peak" => blue(&t),
                "limit" | "block" | "peer" => bad(&t),
                "relax" | "unblock" => good(&t),
                "state" => warn(&t),
                _ => t.clone(),
            };
            println!("  {}  {} {}", fmt_time(&s(e, "time"), true), pad_right(&tc, 10), s(e, "message"));
        }
        println!();
    }
    let tr = list(&st, "tracked_interfaces");
    if !tr.is_empty() {
        println!("Tracked interfaces:");
        for t in tr {
            let ips: Vec<String> = list(t, "ips").iter().filter_map(|x| x.as_str().map(String::from)).collect();
            println!("  {:<14} {:<5} {}", s(t, "name"), s(t, "zone"), ips.join(", "));
        }
        println!();
    }
    let classified = w("lan_to_wan") + w("router_own") + w("incoming") + i(&st, "conntrack.lan_to_router") + i(&st, "conntrack.lan_to_local");
    println!("Local conntrack");
    let c = |k: &str| i(&st, &format!("conntrack.{k}")).to_string();
    table(
        &["current", "maximum", "usage", "classified", "ignored", "unclass", "lan_rtr", "lan_loc"],
        &[9, 9, 9, 18, 9, 9, 9, 9],
        &[true; 8],
        &[vec![c("current"), c("max"), color_high(n(&st, "conntrack.usage_pct"), 75.0, 90.0), format!("{} ({classified}/{})", color_high(n(&st, "wan.classified_pct"), 60.0, 40.0), c("current")), w("ignored").to_string(), w("unclassified").to_string(), c("lan_to_router"), c("lan_to_local")]],
    );
    table(&["tcp", "udp", "icmp", "established", "syn_sent", "syn_recv", "time_wait"], &[9, 9, 9, 18, 9, 9, 10], &[true; 7], &[vec![c("tcp"), c("udp"), c("icmp"), c("established"), c("syn_sent"), c("syn_recv"), c("time_wait")]]);
}

fn name_of(c: &Value) -> String {
    let h = s(c, "hostname");
    if h.is_empty() {
        short_ip(&s(c, "ip"))
    } else {
        trunc_right(&h, 22)
    }
}

/// cgmon top — самые активные устройства.
pub fn print_top(raw: &str) {
    let Ok(v) = parse_json(raw) else {
        println!("{raw}");
        return;
    };
    let top: &[Value] = match &v {
        Value::List(l) => l,
        _ => list(&v, "top"),
    };
    let rows: Vec<Vec<String>> = top.iter().map(|c| vec![name_of(c), i(c, "wan").to_string(), i(c, "incoming").to_string(), i(c, "total").to_string(), i(c, "tcp").to_string(), i(c, "udp").to_string(), format!("{:.1}", n(c, "new_rate"))]).collect();
    table(&["host/ip", "wan", "inc", "total", "tcp", "udp", "new/s"], &[22, 8, 7, 8, 8, 8, 8], &[false, true, true, true, true, true, true], &rows);
}

/// cgmon sites — направления tcp/443 за 5 мин.
pub fn print_sites(raw: &str) {
    let Ok(Value::List(rows)) = parse_json(raw) else {
        println!("{raw}");
        return;
    };
    println!("{:<34} {:>5} {:>5} {:>7}  {:<32} CLIENTS", "SERVICE", "OK", "FAIL", "MED,ms", "IPS");
    for r in &rows {
        let j = |k: &str| list(r, k).iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>();
        println!("{:<34} {:>5} {:>5} {:>7.0}  {:<32} {}", s(r, "name"), i(r, "ok"), i(r, "fail"), n(r, "median_ms"), j("ips").join(","), j("clients").join(", "));
    }
}

/// Запрос демону; без сокета — Err.
pub fn ask(cfg: &Config, cmd: &str) -> Result<String, String> {
    crate::daemon::request(&cfg.paths.socket, &format!("{{\"cmd\":\"{cmd}\"}}"), 5000)
}

/// cgmon nft-status — все таблицы cgmon кратко; отсутствие — с причиной.
pub fn nft_status(cfg: &Config) -> i32 {
    let tables = [
        (cfg.nft.table.as_str(), "создаётся, когда лимитер впервые ограничивает клиента (в dry-run — никогда)"),
        ("cgmon_acct", "учёт трафика выключен (accounting.enabled)"),
        (cfg.hard_limit.table.as_str(), "жёсткие лимиты выключены (hard_limit.enabled)"),
        ("cgmon_route", "обход маршрутом не используется (dns_guard.alternatives)"),
        ("cgmon_v6", "отказ в IPv6 не действует"),
        ("cgmon_l2", "доступ к пойманным устройствам не открыт"),
    ];
    for (t, why) in tables {
        let o = std::process::Command::new(crate::acct::nft_bin()).args(["-t", "list", "table", "inet", t]).output();
        let o = match o {
            Ok(o) if o.status.success() => Some(o),
            _ => std::process::Command::new(crate::acct::nft_bin()).args(["-t", "list", "table", "ip", t]).output().ok().filter(|o| o.status.success()),
        };
        match o {
            Some(o) => println!("# таблица {t}\n{}\n", String::from_utf8_lossy(&o.stdout).trim()),
            None => println!("# таблица {t}: нет — {why}\n"),
        }
    }
    0
}

/// cgmon disable — через демон; без демона — убрать таблицу лимитера.
pub fn disable(cfg: &Config) -> i32 {
    if let Ok(r) = ask(cfg, "disable") {
        println!("{r}");
        return 0;
    }
    match crate::limiter::nft_clear(&cfg.nft.table) {
        Ok(()) => {
            println!("cgmon disabled: cgmon nft table removed if present");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// cgmon telegram-test — пробное сообщение всем получателям центра.
pub fn telegram_test(cfg: &Config) -> i32 {
    let dests = crate::livecfg::telegram_dests(&cfg.hub);
    if dests.is_empty() {
        eprintln!("в hub.telegram нет получателей");
        return 1;
    }
    let text = format!("✅ <b>cgmon {}</b>: проверка уведомлений с {} — сообщения центра сбора будут приходить сюда.", crate::VERSION, crate::status::hostname());
    let mut code = 0;
    for (bot, chat) in dests {
        let label = format!("бот {} → {chat}", bot.split(':').next().unwrap_or(""));
        match crate::hub::send_telegram(&bot, &chat, &text) {
            Ok(()) => println!("{label}: отправлено"),
            Err(e) => {
                println!("{label}: ошибка: {e}");
                code = 1;
            }
        }
    }
    code
}

/// cgmon deps [--install] [-y].
pub fn deps(cfg: &Config, args: &[String]) -> i32 {
    let install = args.iter().any(|a| a == "--install" || a == "install");
    let yes = args.iter().any(|a| a == "-y" || a == "--yes");
    let mut out = std::io::stdout();
    if crate::deps::print(&mut out, cfg) {
        return 0;
    }
    if !install {
        return 1;
    }
    let p = crate::deps::missing_pkgs(&crate::deps::check(cfg));
    if p.is_empty() {
        println!("Недостающее пакетами не ставится (см. пояснения выше).");
        return 1;
    }
    if !yes && !crate::wizard::yes_no(&format!("Установить {}? Будут скачаны списки пакетов и сами пакеты. [y/N]: ", p.join(" "))) {
        println!("Отменено.");
        return 1;
    }
    match crate::deps::install(&mut out, cfg) {
        Ok(()) => {
            println!("Перезапуск не обязателен: cgmon подхватит пакеты в течение минуты (QoS — при следующей сверке).");
            0
        }
        Err(e) => {
            eprintln!("Ошибка: {e}");
            1
        }
    }
}

/// Память процесса (VmRSS и др. из /proc) — для cgmon heap.
pub fn mem_json() -> String {
    let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut j = crate::json::J::new();
    j.obj();
    for k in ["VmRSS", "RssAnon", "RssFile", "VmHWM", "VmData", "Threads"] {
        if let Some(l) = st.lines().find(|l| l.starts_with(&format!("{k}:"))) {
            let v: i64 = l.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
            j.key(&k.to_lowercase()).int(v);
        }
    }
    j.key("unit").str("kB (threads — штук)").end_obj();
    j.b
}
