//! Конфиг: справочник по умолчанию (config.reference.yaml, встроен) →
//! cgmon.yaml → normalize (перенос Config.normalize из Go) → проверки.
//! Структуры и обход полей — config_gen.rs (tools/gencfg.py из Go-структур).

pub use crate::config_gen::*;
use crate::value::{parse_yaml, Value};

/// Справочник всех ключей со значениями по умолчанию (как Go DefaultConfig;
/// совпадение проверяет Go TestReferenceConfigComplete).
pub static REFERENCE: &str = include_str!("../config.reference.yaml");

/// Пути поиска конфига (как в Go: -config → $CGMON_CONFIG → эти).
pub const SEARCH: &[&str] = &["/etc/cgmon/cgmon.yaml", "/etc/cgmon.yaml", "/opt/cgmon/cgmon.yaml", "/etc/config/cgmon.yaml"];

/// Поле на чтение (обход для страницы «Все настройки», сравнение с базой).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field<'a> {
    Bool(&'a bool),
    Int(&'a i64),
    Float(&'a f64),
    Str(&'a String),
    StrList(&'a Vec<String>),
    IntList(&'a Vec<i64>),
    /// Сложные списки/словари — только в cgmon.yaml.
    Complex,
}

/// Поле на запись по пути (живые настройки).
pub enum FieldMut<'a> {
    Bool(&'a mut bool),
    Int(&'a mut i64),
    Float(&'a mut f64),
    Str(&'a mut String),
    StrList(&'a mut Vec<String>),
    IntList(&'a mut Vec<i64>),
}

pub fn join(p: &str, k: &str) -> String {
    if p.is_empty() {
        k.to_string()
    } else {
        format!("{p}.{k}")
    }
}

// Декодеры — как yaml.v3: null → нулевое значение, строковое поле принимает
// любой скаляр, bool — также yes/no/on/off (YAML 1.1 при цели bool).

pub fn dec_bool(v: &Value, p: &str) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::Null => Ok(false),
        Value::Str(s) => match s.to_ascii_lowercase().as_str() {
            "yes" | "on" | "y" => Ok(true),
            "no" | "off" | "n" => Ok(false),
            _ => Err(format!("{p}: ожидается true/false, а не {s:?}")),
        },
        _ => Err(format!("{p}: ожидается true/false")),
    }
}

pub fn dec_int(v: &Value, p: &str) -> Result<i64, String> {
    match v {
        Value::Num(n) => n.parse::<i64>().or_else(|_| {
            // 1e3, 10.0 — целое по значению
            n.parse::<f64>().ok().filter(|f| f.fract() == 0.0 && f.abs() < 9e15).map(|f| f as i64).ok_or(format!("{p}: ожидается целое, а не {n}"))
        }),
        Value::Null => Ok(0),
        Value::Str(s) => Err(format!("{p}: ожидается число, а не {s:?}")),
        _ => Err(format!("{p}: ожидается число")),
    }
}

pub fn dec_float(v: &Value, p: &str) -> Result<f64, String> {
    match v {
        Value::Num(n) => n.parse::<f64>().map_err(|_| format!("{p}: ожидается число, а не {n}")),
        Value::Null => Ok(0.0),
        Value::Str(s) => Err(format!("{p}: ожидается число, а не {s:?}")),
        _ => Err(format!("{p}: ожидается число")),
    }
}

pub fn dec_str(v: &Value, p: &str) -> Result<String, String> {
    match v {
        Value::Str(s) => Ok(s.clone()),
        Value::Num(n) => Ok(n.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(format!("{p}: ожидается строка")),
    }
}

pub fn dec_str_list(v: &Value, p: &str) -> Result<Vec<String>, String> {
    match v {
        Value::List(l) => l.iter().enumerate().map(|(i, x)| dec_str(x, &format!("{p}[{i}]"))).collect(),
        Value::Null => Ok(Vec::new()),
        _ => Err(format!("{p}: ожидается список")),
    }
}

pub fn dec_int_list(v: &Value, p: &str) -> Result<Vec<i64>, String> {
    match v {
        Value::List(l) => l.iter().enumerate().map(|(i, x)| dec_int(x, &format!("{p}[{i}]"))).collect(),
        Value::Null => Ok(Vec::new()),
        _ => Err(format!("{p}: ожидается список")),
    }
}

/// Словарь строк: как yaml.v3 — ключи добавляются к имеющимся.
pub fn dec_str_map(m: &mut Vec<(String, String)>, v: &Value, p: &str) -> Result<(), String> {
    match v {
        Value::Map(src) => {
            for (k, x) in src {
                let s = dec_str(x, &join(p, k))?;
                match m.iter_mut().find(|(a, _)| a == k) {
                    Some(e) => e.1 = s,
                    None => m.push((k.clone(), s)),
                }
            }
            Ok(())
        }
        Value::Null => {
            m.clear();
            Ok(())
        }
        _ => Err(format!("{p}: ожидается словарь")),
    }
}

/// Значения по умолчанию — из встроенного справочника.
pub fn defaults() -> Config {
    let mut c = Config::default();
    let v = parse_yaml(REFERENCE).expect("config.reference.yaml: встроенный справочник не разбирается");
    c.apply(&v, "").expect("config.reference.yaml: встроенный справочник не применяется");
    c
}

/// Загрузить конфиг: справочник → файл (если есть) → normalize → проверки.
pub fn load(path: &str) -> Result<Config, String> {
    let mut c = defaults();
    if path.is_empty() {
        c.normalize();
        return Ok(c);
    }
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let v = parse_yaml(&text).map_err(|e| format!("parse {path}: {e}"))?;
            c.apply(&v, "").map_err(|e| format!("parse {path}: {e}"))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            c.normalize();
            return Ok(c);
        }
        Err(e) => return Err(format!("{path}: {e}")),
    }
    c.normalize();
    c.source = path.to_string();
    let us = &c.upload_shaper;
    if us.enabled {
        if us.device.is_empty() {
            return Err("upload_shaper.device is required".into());
        }
        valid_stages(us).map_err(|e| format!("upload_shaper: {e}"))?;
    }
    Ok(c)
}

/// Найти конфиг: явный путь → $CGMON_CONFIG → стандартные места.
pub fn find(explicit: Option<&str>) -> String {
    if let Some(p) = explicit.filter(|p| !p.is_empty()) {
        return p.to_string();
    }
    if let Ok(p) = std::env::var("CGMON_CONFIG") {
        if !p.is_empty() {
            return p;
        }
    }
    SEARCH.iter().find(|p| std::path::Path::new(p).exists()).unwrap_or(&SEARCH[0]).to_string()
}

pub fn valid_stages(c: &UploadShaperConfig) -> Result<(), String> {
    if c.sustained_kbit <= 0 {
        return Err("sustained_kbit must be > 0".into());
    }
    if c.payback_kbit >= c.sustained_kbit {
        return Err("payback_kbit must be lower than sustained_kbit".into());
    }
    let mut prev = 0;
    for (i, st) in c.stages.iter().enumerate() {
        if st.kbit <= c.sustained_kbit || st.mb <= 0.0 {
            return Err(format!("stage {}: kbit must be > sustained_kbit and mb > 0", i + 1));
        }
        if i > 0 && st.kbit >= prev {
            return Err(format!("stage {}: kbit must be lower than previous stage", i + 1));
        }
        prev = st.kbit;
    }
    Ok(())
}

fn or_s(s: &mut String, d: &str) {
    if s.is_empty() {
        *s = d.to_string();
    }
}

fn or_list(l: &mut Vec<String>, d: &[&str]) {
    if l.is_empty() {
        *l = d.iter().map(|s| s.to_string()).collect();
    }
}

fn pos_i(v: &mut i64, d: i64) {
    if *v <= 0 {
        *v = d;
    }
}

fn pos_f(v: &mut f64, d: f64) {
    if *v <= 0.0 {
        *v = d;
    }
}

fn pct(v: &mut f64, d: f64) {
    if *v <= 0.0 || *v > 100.0 {
        *v = d;
    }
}

fn non_neg_i(v: &mut i64) {
    if *v < 0 {
        *v = 0;
    }
}

fn non_neg_f(v: &mut f64) {
    if *v < 0.0 {
        *v = 0.0;
    }
}

impl Config {
    /// Перенос Go Config.normalize: нули и недопустимые значения → по умолчанию.
    /// Проверки «== nil» из Go здесь не нужны: умолчания уже из справочника.
    /// Файлы промежуточных данных (переезжают вместе с `storage`).
    pub fn storage_files(&self) -> Vec<String> {
        vec![crate::acct::PERSISTENT_FILE.into(), crate::phywatch::STATE.into(), self.billing.state_file.clone(), self.devices.vendor_cache.clone(), self.hub.state_file.clone(), self.flow_watch.learn_file.clone(), self.witness.state_file.clone(), self.payment.state_file.clone()]
    }

    pub fn normalize(&mut self) {
        or_s(&mut self.storage, "flash");
        // старые пути в /tmp (до 2.4.8) из своего cgmon.yaml — в /tmp/cgmon
        for p in [&mut self.wan_monitor.incidents_file, &mut self.paths.metrics_file, &mut self.hub.journal_file] {
            if let Some(n) = crate::util::tmp_legacy(p) {
                *p = n;
            }
        }
        let r = &mut self.report;
        if !r.url.is_empty() {
            r.urls.insert(0, std::mem::take(&mut r.url));
        }
        let mut urls: Vec<String> = Vec::new();
        for u in r.urls.iter() {
            let u = u.trim().replacen("/api/report", "/api/v1/report", 1);
            if !u.is_empty() && !urls.contains(&u) {
                urls.push(u);
            }
        }
        r.urls = urls;
        pos_i(&mut r.interval_sec, 60);
        let h = &mut self.hub;
        or_s(&mut h.listen, ":7788");
        pos_i(&mut h.stale_sec, 180);
        pos_i(&mut h.min_isps, 2);
        pos_i(&mut h.clear_sec, 60);
        or_s(&mut h.state_file, "/etc/cgmon/hub_state.json");
        or_s(&mut h.journal_file, "/tmp/cgmon/hub.jsonl");
        or_s(&mut self.log_level, "info");

        pos_i(&mut self.interval_sec, 5);
        pos_i(&mut self.probe_interval_sec, 5);
        pos_i(&mut self.udp_probe_interval_sec, 15);
        pos_i(&mut self.probe_timeout_sec, 3);
        pos_i(&mut self.stat_window_sec, 60);
        pos_i(&mut self.stat_long_window_sec, 300);
        non_neg_i(&mut self.startup_grace_sec);
        pos_i(&mut self.status_top_clients, 10);
        or_list(&mut self.lan_zones, &["lan"]);

        let p = &mut self.probes;
        or_list(&mut p.ipv4, &["1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"]);
        or_list(&mut p.ipv6, &["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]);
        or_list(&mut p.udp_v4, &["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]);
        or_list(&mut p.udp_v6, &["[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"]);

        let t = &mut self.thresholds;
        pct(&mut t.warning_enter_success, 95.0);
        pct(&mut t.critical_enter_success, 80.0);
        pct(&mut t.recovery_success, 98.0);
        pct(&mut t.ipv6_healthy_success, 98.0);
        pos_i(&mut t.enter_duration_sec, 30);
        pos_i(&mut t.recovery_duration_sec, 300);

        let l = &mut self.limits;
        or_s(&mut l.mode, "adaptive");
        non_neg_i(&mut l.min);
        pos_i(&mut l.max, 100000);
        if l.min > l.max {
            l.min = l.max;
        }
        if l.warning_factor <= 0.0 || l.warning_factor > 1.0 {
            l.warning_factor = 0.8;
        }
        if l.critical_factor <= 0.0 || l.critical_factor > 1.0 {
            l.critical_factor = 0.6;
        }
        pos_i(&mut l.recovery_step_percent, 10);
        pos_i(&mut l.min_change_interval_sec, 60);
        non_neg_i(&mut l.min_offender_connections);
        if l.block_hysteresis_percent <= 0 || l.block_hysteresis_percent > 100 {
            l.block_hysteresis_percent = 90;
        }

        let lc = &mut self.local;
        non_neg_f(&mut lc.cpu_threshold_percent);
        non_neg_f(&mut lc.conntrack_threshold_percent);
        non_neg_f(&mut lc.load_per_core);
        non_neg_f(&mut lc.core_threshold_percent);
        non_neg_i(&mut lc.pressure_duration_sec);
        non_neg_i(&mut lc.min_memory_mb);

        or_s(&mut self.nft.table, "cgmon");
        pos_i(&mut self.nft.set_timeout_sec, 60);
        pos_i(&mut self.nft.refresh_sec, 30);

        let pa = &mut self.paths;
        or_s(&mut pa.socket, "/var/run/cgmon.sock");
        or_s(&mut pa.status_file, "/var/run/cgmon.status.json");
        or_s(&mut pa.runtime, "/etc/cgmon/runtime.json");
        or_s(&mut pa.metrics_file, "/tmp/cgmon/metrics.jsonl");

        if !matches!(self.counting.mode.as_str(), "all" | "lan_only" | "lan_to_wan") {
            self.counting.mode = "lan_to_wan".into();
        }
        pos_i(&mut self.dns.timeout_ms, 500);
        pos_i(&mut self.dns.cache_ttl_sec, 600);

        let hl = &mut self.hard_limit;
        or_s(&mut hl.table, "torrent_limit");
        or_list(&mut hl.interfaces, &["lan"]);
        pos_i(&mut hl.connlimit, 25);
        pos_i(&mut hl.connlimit_host, 50);

        let wm = &mut self.wan_monitor;
        pos_i(&mut wm.down_debounce_sec, 15);
        non_neg_i(&mut wm.post_up_grace_sec);
        or_s(&mut wm.incidents_file, "/tmp/cgmon/incidents.jsonl");

        let g = &mut self.gate_selector;
        pos_i(&mut g.evaluation_interval_sec, 1);
        pos_i(&mut g.probes.interval_sec, 5);
        pos_i(&mut g.probes.decision_window_sec, 30);
        or_list(&mut g.probes.ipv4, &["1.1.1.1:443", "8.8.8.8:443"]);
        let gt = &mut g.thresholds;
        pos_f(&mut gt.ok_score, 60.0);
        pos_f(&mut gt.bad_score, 40.0);
        pos_f(&mut gt.margin, 25.0);
        pos_i(&mut gt.fail_hold_sec, 20);
        pos_f(&mut gt.failback_score, 80.0);
        pos_i(&mut gt.failback_hold_sec, 120);
        let gs = &mut g.switching;
        pos_i(&mut gs.cooldown_sec, 300);
        pos_i(&mut gs.inactive_metric, 98);
        pos_i(&mut gs.post_switch_grace_sec, 120);
        let gr = &mut g.repair;
        or_s(&mut gr.method, "ubus");
        pos_i(&mut gr.setup_stuck_sec, 45);
        pos_i(&mut gr.no_ip_stuck_sec, 30);
        pos_i(&mut gr.post_repair_grace_sec, 60);
        pos_i(&mut gr.cooldown_sec, 300);
        pos_i(&mut gr.max_per_window, 4);
        pos_i(&mut gr.window_sec, 1800);
        pos_i(&mut gr.backoff_initial_sec, 30);
        pos_i(&mut gr.backoff_max_sec, 300);
        pos_i(&mut gr.auth_fail_pause_sec, 60);

        let pe = &mut self.peers;
        pos_i(&mut pe.window_sec, 30);
        pos_f(&mut pe.min_success, 70.0);
        non_neg_i(&mut pe.degrade_sec);
        pos_f(&mut pe.recover_success, 90.0);
        if pe.recover_success < pe.min_success {
            pe.recover_success = pe.min_success;
        }
        non_neg_i(&mut pe.recover_sec);
        pos_f(&mut pe.penalty_mbps, 45.0);
        pos_i(&mut pe.peak_window_sec, 300);
        pos_i(&mut pe.wan_flows_top, 10);

        let us = &mut self.upload_shaper;
        if !us.class_id.contains(':') {
            us.class_id = "1:1".into();
        }
        if us.refill_factor < 1.0 {
            us.refill_factor = 2.0;
        }
        pct(&mut us.resume_percent, 20.0);
        pos_i(&mut us.penalty_cooldown_sec, 600);
        if !matches!(self.wan_check.as_str(), "active" | "passive" | "hybrid") {
            self.wan_check = "active".into();
        }
        or_s(&mut self.devices.vendor_url, "https://api.macvendors.com/");
        or_s(&mut self.devices.vendor_cache, "/etc/cgmon/oui_cache.json");

        let q = &mut self.qos;
        or_s(&mut q.device, "auto");
        or_s(&mut self.upload_shaper.device, "auto");
        or_s(&mut q.flow_keys_up, "src,dst,proto,proto-src,proto-dst");
        or_s(&mut q.flow_keys_down, "src,dst,proto,proto-src,proto-dst");
        q.need_htb = self.upload_shaper.enabled;
        if q.flow_buckets <= 0 || q.flow_buckets > 1024 {
            q.flow_buckets = 128;
        }
        or_s(&mut q.cake_opts, "besteffort nat raw");
        or_s(&mut q.ingress_cake_opts, "besteffort nat wash raw");

        let b = &mut self.billing;
        or_s(&mut b.tasix_url, "https://tasix.dc.uz/subnets.txt");
        or_s(&mut b.tasix_file, "/etc/cgmon/tasix.txt");
        pos_i(&mut b.refresh_hours, 24);
        if b.month_start_day < 1 || b.month_start_day > 28 {
            b.month_start_day = 1;
        }
        or_s(&mut b.state_file, "/etc/cgmon/billing.json");

        let fw = &mut self.flow_watch;
        pos_f(&mut fw.heavy_mbps, 5.0);
        if fw.stall_percent <= 0.0 || fw.stall_percent >= 100.0 {
            fw.stall_percent = 10.0;
        }
        pos_i(&mut fw.stall_sec, 8);
        if fw.probe_interval_ms < 200 {
            fw.probe_interval_ms = 1000;
        }
        pos_i(&mut fw.probe_window_sec, 10);
        pct(&mut fw.loss_percent, 50.0);
        if fw.latency_factor < 1.0 {
            fw.latency_factor = 3.0;
        }
        pos_f(&mut fw.latency_add_ms, 100.0);
        pos_i(&mut fw.hold_sec, 60);
        pos_i(&mut fw.recover_sec, 20);
        pos_i(&mut fw.max_targets, 4);
        pct(&mut fw.loss_only_percent, 80.0);
        if fw.learn_mode != "off" {
            fw.learn_mode = "observe".into();
        }
        pos_i(&mut fw.learn_min_kbit, 3000);
        or_s(&mut fw.learn_file, "/etc/cgmon/uplearn.json");

        let dg = &mut self.dns_guard;
        if !matches!(dg.mode.as_str(), "observe" | "active" | "targeted") {
            dg.mode = "off".into();
        }
        if !matches!(dg.backend.as_str(), "smartdns" | "dnsmasq") {
            dg.backend = "auto".into();
        }
        or_s(&mut dg.state_file, "/etc/cgmon/dnsguard.json");
        pos_i(&mut dg.v6_enter_sec, 300);
        pos_i(&mut dg.v4_enter_sec, 60);
        pos_i(&mut dg.recover_sec, 600);
        or_s(&mut dg.targets_file, "/etc/smartdns/cgmon-dnsguard-targets.conf");
        pos_i(&mut dg.target_base_min, 60);
        pos_i(&mut dg.target_max_hours, 24);
        if dg.target_max_hours > 168 {
            dg.target_max_hours = 168;
        }
        pos_i(&mut dg.metered_day_mb, 5000);
        pos_i(&mut dg.overlay_fail_sec, 12); // overlay: быстрый перевод на физику при падении туннеля
        if dg.reject_all_v6_score < 0 || dg.reject_all_v6_score > 100 {
            dg.reject_all_v6_score = 0;
        }
        pos_i(&mut dg.reject_all_v6_sec, 300);
        or_list(&mut dg.dns64_servers, &["2001:67c:2960::64", "2001:67c:2960::6464"]);
        or_s(&mut dg.upstream_file, "/etc/smartdns/upstream.conf");
        or_s(&mut dg.guard_file, "/etc/smartdns/cgmon-dnsguard.conf");
        or_s(&mut dg.cache_file, "/etc/smartdns/smartdns.cache");

        let w = &mut self.witness;
        if w.mode != "observe" {
            w.mode = "off".into();
        }
        pos_i(&mut w.per_family, 12);
        if w.per_family > 32 {
            w.per_family = 32;
        }
        if w.interval_sec < 10 {
            w.interval_sec = 60;
        }
        or_s(&mut w.state_file, "/etc/cgmon/witness.json");

        let pc = &mut self.payment;
        if pc.mode != "interval" {
            pc.mode = "monthly".into();
        }
        pos_i(&mut pc.day, 1);
        pos_i(&mut pc.interval_days, 30);
        pos_i(&mut pc.remind_days, 3);
        if pc.remind_hour <= 0 || pc.remind_hour > 23 {
            pc.remind_hour = 10;
        }
        or_s(&mut pc.state_file, "/etc/cgmon/payment.json");
        if self.upload_shaper.interval_ms < 20 {
            self.upload_shaper.interval_ms = 100;
        }
        // вариант сборки (lite, nano): выключить то, чего в нём нет
        crate::variant::limit(self);
    }

    /// Все поля «путь → JSON-значение» в порядке обхода (для сравнения с Go и
    /// для страницы «Все настройки»).
    pub fn dump_json(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        self.walk("", &mut |path, f| {
            if matches!(f, Field::Complex) {
                return;
            }
            if !first {
                out.push(',');
            }
            first = false;
            crate::value::json_str(out, path);
            out.push(':');
            field_json(f, out);
        });
        out.push('}');
    }
}

/// JSON значения поля (числа — как Go encoding/json).
pub fn field_json(f: Field, out: &mut String) {
    use std::fmt::Write as _;
    match f {
        Field::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Field::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Field::Float(x) => out.push_str(&go_float(*x)),
        Field::Str(s) => crate::value::json_str(out, s),
        Field::StrList(l) => {
            out.push('[');
            for (i, s) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                crate::value::json_str(out, s);
            }
            out.push(']');
        }
        Field::IntList(l) => {
            out.push('[');
            for (i, v) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "{v}");
            }
            out.push(']');
        }
        Field::Complex => out.push_str("null"),
    }
}

/// float64 как в Go encoding/json для обычных величин: 95, 0.8, 1.5e+21.
pub fn go_float(x: f64) -> String {
    if !x.is_finite() {
        return "0".into();
    }
    if x.fract() == 0.0 && x.abs() < 1e21 {
        return format!("{}", x as i64);
    }
    format!("{x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_parses_and_is_normal() {
        let d = defaults();
        let mut n = d.clone();
        n.normalize();
        // справочник = значения по умолчанию: normalize ничего не меняет,
        // кроме вычисляемого need_htb
        assert_eq!(d.probes.ipv4, n.probes.ipv4);
        let (mut a, mut b) = (String::new(), String::new());
        d.dump_json(&mut a);
        n.dump_json(&mut b);
        assert_eq!(a, b);
        assert_eq!(n.paths.socket, "/var/run/cgmon.sock");
        assert!(n.down_detector.enabled);
    }

    #[test]
    fn overlay_and_errors() {
        let mut c = defaults();
        let v = parse_yaml("interval_sec: 7\nprobes:\n  ipv4: [\"192.0.2.1:443\"]\nreport:\n  url: http://192.0.2.9:7788/api/report\n  urls: [\"http://192.0.2.9:7788/api/v1/report\"]\nthresholds:\n  warning_enter_success: 150\n").unwrap();
        c.apply(&v, "").unwrap();
        c.normalize();
        assert_eq!(c.interval_sec, 7);
        assert_eq!(c.probes.ipv4, vec!["192.0.2.1:443"]);
        assert_eq!(c.report.urls, vec!["http://192.0.2.9:7788/api/v1/report"]);
        assert_eq!(c.thresholds.warning_enter_success, 95.0);
        assert!(c.apply(&parse_yaml("interval_sec: abc\n").unwrap(), "").is_err());
        assert!(c.apply(&parse_yaml("probes: 5\n").unwrap(), "").is_err());
    }

    #[test]
    fn field_mut_by_path() {
        let mut c = defaults();
        match c.field_mut("dns_guard.relay_mbit") {
            Some(FieldMut::Int(v)) => *v = 77,
            _ => panic!("dns_guard.relay_mbit"),
        }
        assert_eq!(c.dns_guard.relay_mbit, 77);
        assert!(c.field_mut("dns_guard.nope").is_none());
        assert!(c.field_mut("gate_selector.interfaces").is_none());
    }
}
