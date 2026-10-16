//! Ограничитель (перенос nft.go, hardlimit.go и лимитера из engine.go):
//! - таблица inet cgmon (nft.table): набор cgmon_blocked_new — у «жадного»
//!   клиента режутся только НОВЫЕ соединения (ESTABLISHED не трогаем);
//! - таблица torrent_limit (hard_limit): статические ct count на хост
//!   (forward — клиенты, output — сам роутер), как torrent_limit.sh;
//! - расчёт лимита по фазе и снижение connlimit_host роутера, когда
//!   деградацию создаёт его собственный трафик.

use crate::acct::nft_script;
use crate::config::{Config, HardLimitConfig};
use crate::conntrack::{ClientStats, Snapshot};
use crate::topo::read_uci;

fn nft_out(args: &[&str]) -> Result<String, String> {
    let o = std::process::Command::new(crate::acct::nft_bin()).args(args).output().map_err(|e| e.to_string())?;
    let t = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)).trim().to_string();
    if o.status.success() {
        Ok(t)
    } else {
        Err(t)
    }
}

/// Таблица динамического ограничителя.
pub fn nft_ensure(table: &str) -> Result<(), String> {
    if crate::util::readonly() {
        return Ok(());
    }
    let out = match nft_out(&["list", "table", "inet", table]) {
        Ok(o) => o,
        Err(_) => {
            return nft_script(&format!(
                "add table inet {t}\nadd chain inet {t} cgmon_forward {{ type filter hook forward priority 0; policy accept; }}\nadd set inet {t} cgmon_limited_hosts {{ type ipv4_addr; flags timeout; }}\nadd set inet {t} cgmon_blocked_new {{ type ipv4_addr; flags timeout; }}\nadd rule inet {t} cgmon_forward ip saddr @cgmon_blocked_new ct state new counter drop comment \"cgmon_block_new\"\n",
                t = table
            ))
        }
    };
    let mut s = String::new();
    if !out.contains("cgmon_forward") {
        s += &format!("add chain inet {table} cgmon_forward {{ type filter hook forward priority 0; policy accept; }}\n");
    }
    if !out.contains("cgmon_limited_hosts") {
        s += &format!("add set inet {table} cgmon_limited_hosts {{ type ipv4_addr; flags timeout; }}\n");
    }
    if !out.contains("cgmon_blocked_new") {
        s += &format!("add set inet {table} cgmon_blocked_new {{ type ipv4_addr; flags timeout; }}\n");
    }
    if !out.contains("cgmon_block_new") {
        s += &format!("add rule inet {table} cgmon_forward ip saddr @cgmon_blocked_new ct state new counter drop comment \"cgmon_block_new\"\n");
    }
    if s.is_empty() {
        Ok(())
    } else {
        nft_script(&s)
    }
}

pub fn nft_apply_blocked(table: &str, hosts: &[String], timeout_sec: i64) -> Result<(), String> {
    nft_ensure(table)?;
    let mut s = format!("flush set inet {table} cgmon_blocked_new\n");
    for h in hosts {
        s += &format!("add element inet {table} cgmon_blocked_new {{ {h} timeout {timeout_sec}s }}\n");
    }
    nft_script(&s)
}

/// Удалить таблицу (команда disable).
pub fn nft_clear(table: &str) -> Result<(), String> {
    if crate::util::readonly() {
        return Ok(());
    }
    match nft_out(&["delete", "table", "inet", table]) {
        Ok(_) => Ok(()),
        Err(o) if o.contains("No such file") || o.contains("does not exist") => Ok(()),
        Err(o) => Err(o),
    }
}

// ---------------- жёсткие лимиты ----------------

/// hard_limit с учётом импорта старого UCI-блока /etc/config/bash-tools.
pub fn hard_effective(cfg: &Config) -> (HardLimitConfig, &'static str) {
    let mut hl = cfg.hard_limit.clone();
    if !hl.uci_import {
        return (hl, "yaml");
    }
    let secs = read_uci("/etc/config/bash-tools");
    let Some(sec) = secs.iter().find(|s| s.name == "torrent_limit" || s.typ == "torrent_limit") else { return (hl, "yaml") };
    let b = |k: &str, d: &mut bool| {
        let v = sec.opt(k).trim().to_lowercase();
        if sec.options.iter().any(|(x, _)| x == k) {
            *d = matches!(v.as_str(), "1" | "true" | "on" | "yes");
        }
    };
    let n = |k: &str, d: &mut i64| {
        if let Ok(v) = sec.opt(k).trim().parse() {
            *d = v;
        }
    };
    b("enabled_ipv4_tcp", &mut hl.forward_ipv4_tcp);
    b("enabled_ipv4_udp", &mut hl.forward_ipv4_udp);
    b("enabled_ipv6_tcp", &mut hl.forward_ipv6_tcp);
    b("enabled_ipv6_udp", &mut hl.forward_ipv6_udp);
    n("connlimit", &mut hl.connlimit);
    b("enabled_host_ipv4_tcp", &mut hl.host_ipv4_tcp);
    b("enabled_host_ipv4_udp", &mut hl.host_ipv4_udp);
    b("enabled_host_ipv6_tcp", &mut hl.host_ipv6_tcp);
    b("enabled_host_ipv6_udp", &mut hl.host_ipv6_udp);
    n("connlimit_host", &mut hl.connlimit_host);
    let ports = |k: &str| -> Vec<i64> { sec.list(k).iter().filter_map(|s| s.trim().parse().ok()).collect() };
    let t = ports("except_ports_tcp");
    if !t.is_empty() {
        hl.except_ports_tcp = t;
    }
    let u = ports("except_ports_udp");
    if !u.is_empty() {
        hl.except_ports_udp = u;
    }
    if !sec.list("limit_interfaces").is_empty() {
        hl.interfaces = sec.list("limit_interfaces").to_vec();
    }
    (hl, "uci")
}

/// Сети UCI → устройства (ifname может перечислять несколько).
fn resolve_devices(names: &[String]) -> Vec<String> {
    let nw = read_uci("/etc/config/network");
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let n = n.trim();
        let dev = nw
            .iter()
            .find(|s| s.typ == "interface" && (if s.name.is_empty() { s.opt("name") } else { s.name.as_str() }) == n)
            .map(|s| if !s.opt("device").trim().is_empty() { s.opt("device").trim().to_string() } else if !s.opt("ifname").trim().is_empty() { s.opt("ifname").trim().to_string() } else { n.to_string() })
            .unwrap_or_else(|| n.to_string());
        for p in dev.split_whitespace() {
            if !out.iter().any(|x| x == p) {
                out.push(p.to_string());
            }
        }
    }
    if out.is_empty() {
        out.push("br-lan".into());
    }
    out
}

pub fn hard_script(hl: &HardLimitConfig, devices: &[String], conn: i64, host: i64) -> String {
    let t = if hl.table.is_empty() { "torrent_limit" } else { &hl.table };
    let ifl = devices.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(", ");
    let ports = |l: &[i64]| l.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
    let (te, ue) = (ports(&hl.except_ports_tcp), ports(&hl.except_ports_udp));
    let mut b = format!("flush table inet {t}\n\n");
    for (n, ty) in [("tcp_hosts", "ipv4_addr"), ("udp_hosts", "ipv4_addr"), ("output_tcp_hosts", "ipv4_addr"), ("output_udp_hosts", "ipv4_addr"), ("tcp6_hosts", "ipv6_addr"), ("udp6_hosts", "ipv6_addr"), ("output_tcp6_hosts", "ipv6_addr"), ("output_udp6_hosts", "ipv6_addr")] {
        b += &format!("add set inet {t} {n} {{\n    type {ty}\n    size 65535\n    flags dynamic\n}}\n\n");
    }
    if hl.forward_ipv4_tcp {
        b += &format!("add rule inet {t} forward ct state new iifname {{ {ifl} }} ip protocol tcp tcp dport != {{ {te} }} add @tcp_hosts {{ ip saddr ct count over {conn} }} counter reject with tcp reset\n");
    }
    if hl.forward_ipv4_udp {
        b += &format!("add rule inet {t} forward ct state new iifname {{ {ifl} }} ip protocol udp udp dport != {{ {ue} }} add @udp_hosts {{ ip saddr ct count over {conn} }} counter drop\n");
    }
    if hl.forward_ipv6_tcp {
        b += &format!("add rule inet {t} forward ct state new iifname {{ {ifl} }} ip6 nexthdr tcp tcp dport != {{ {te} }} add @tcp6_hosts {{ ip6 saddr ct count over {conn} }} counter reject with tcp reset\n");
    }
    if hl.forward_ipv6_udp {
        b += &format!("add rule inet {t} forward ct state new iifname {{ {ifl} }} ip6 nexthdr udp udp dport != {{ {ue} }} add @udp6_hosts {{ ip6 saddr ct count over {conn} }} counter drop\n");
    }
    if hl.host_ipv4_tcp {
        b += &format!("add rule inet {t} output ct state new oifname != \"lo\" ip protocol tcp tcp dport != {{ {te} }} add @output_tcp_hosts {{ ip saddr ct count over {host} }} counter reject with tcp reset\n");
    }
    if hl.host_ipv4_udp {
        b += &format!("add rule inet {t} output ct state new oifname != \"lo\" ip protocol udp udp dport != {{ {ue} }} add @output_udp_hosts {{ ip saddr ct count over {host} }} counter drop\n");
    }
    if hl.host_ipv6_tcp {
        b += &format!("add rule inet {t} output ct state new oifname != \"lo\" ip6 nexthdr tcp tcp dport != {{ {te} }} add @output_tcp6_hosts {{ ip6 saddr ct count over {host} }} counter reject with tcp reset\n");
    }
    if hl.host_ipv6_udp {
        b += &format!("add rule inet {t} output ct state new oifname != \"lo\" ip6 nexthdr udp udp dport != {{ {ue} }} add @output_udp6_hosts {{ ip6 saddr ct count over {host} }} counter drop\n");
    }
    b
}

/// Пересобрать и применить жёсткие лимиты (host_override > 0 — connlimit_host роутера).
pub fn hard_apply(cfg: &Config, host_override: i64) -> Result<(), String> {
    let (hl, source) = hard_effective(cfg);
    if !hl.enabled {
        return Ok(());
    }
    let devices = resolve_devices(&hl.interfaces);
    let host = if host_override > 0 { host_override } else { hl.connlimit_host };
    let script = hard_script(&hl, &devices, hl.connlimit, host);
    if hl.dry_run || cfg.dry_run || crate::util::readonly() {
        crate::log_info!("hard-limit DRY-RUN (source={}) script:\n{}", source, script);
        return Ok(());
    }
    let t = if hl.table.is_empty() { "torrent_limit" } else { &hl.table };
    if nft_out(&["list", "table", "inet", t]).is_err() {
        nft_out(&["add", "table", "inet", t]).map_err(|e| format!("cannot create table: {e}"))?;
    }
    for (name, hook) in [("forward", "forward"), ("output", "output")] {
        if nft_out(&["list", "chain", "inet", t, name]).is_err() {
            let spec = format!("{{ type filter hook {hook} priority -5; policy accept; }}");
            nft_out(&["add", "chain", "inet", t, name, &spec]).map_err(|e| format!("cannot create chain {name}: {e}"))?;
        }
    }
    let tmp = "/tmp/cgmon/hardlimit.nft";
    std::fs::write(tmp, &script).map_err(|e| e.to_string())?;
    let r = nft_out(&["-c", "-f", tmp]).map_err(|e| format!("hard-limit syntax error: {e}")).and_then(|_| nft_out(&["-f", tmp]).map_err(|e| format!("hard-limit apply failed: {e}")));
    let _ = std::fs::remove_file(tmp);
    r?;
    crate::log_info!("hard-limit applied (source={}): interfaces={:?} connlimit={} connlimit_host={}", source, devices, hl.connlimit, host);
    Ok(())
}

// ---------------- динамический ограничитель ----------------

#[derive(Default)]
pub struct Limiter {
    pub ip: String,
    pub limit: i64,
    pub since: i64,
    pub blocked: bool,
    last_change: i64,
    last_blocked_key: String,
    last_set_refresh: i64,
    pub router_host_limit: i64,
    router_limit_since: i64,
    pub last_ensure: i64,
    pub last_hard: i64,
    pub disabled: bool,
}

pub fn relaxed_limit(cur: i64, step_pct: i64, max: i64) -> i64 {
    if cur <= 0 {
        return 0;
    }
    (cur + (cur * step_pct / 100).max(1)).min(max)
}

/// Состояние движка, нужное ограничителю.
pub struct View<'a> {
    pub cfg: &'a Config,
    pub phase: &'a str,
    pub diagnosis: &'a str,
    pub grace: bool,
    pub v4_success: f64,
    pub v4_count: i64,
    pub v6_healthy: bool,
    /// шторм переподключений после фейловера / подъёма WAN — не душим
    pub post_switch: bool,
}

pub fn calculate_limit(cfg: &Config, phase: &str, top: &ClientStats, v4_success: f64) -> i64 {
    let top_v = top.wan;
    if top_v <= 0 {
        return 0;
    }
    let l = &cfg.limits;
    let mut limit = if l.mode.eq_ignore_ascii_case("static") {
        let x = if phase == "CRITICAL" { l.critical } else { l.warning };
        if x <= 0 {
            return 0;
        }
        x
    } else {
        let mut f = if phase == "CRITICAL" || v4_success <= cfg.thresholds.critical_enter_success { l.critical_factor } else { l.warning_factor };
        if f <= 0.0 || f > 1.0 {
            f = 0.6;
        }
        (top_v as f64 * f) as i64
    };
    limit = limit.max(l.min).min(l.max);
    if limit >= top_v {
        limit = (top_v as f64 * 0.9) as i64;
    }
    limit.max(0)
}

impl Limiter {
    fn can_change(&self, cfg: &Config, now: i64) -> bool {
        self.last_change == 0 || now - self.last_change >= cfg.limits.min_change_interval_sec
    }

    /// Новый лимит; сообщения (тип события, текст) — наружу.
    fn set(&mut self, cfg: &Config, ip: &str, limit: i64, now: i64, action: &str, out: &mut Vec<(String, String)>) {
        let limit = limit.max(0);
        let ip_eff = if limit == 0 { "" } else { ip };
        if self.ip == ip_eff && self.limit == limit {
            return;
        }
        let log_ip = if ip.is_empty() { self.ip.clone() } else { ip.to_string() };
        self.ip = ip_eff.to_string();
        self.limit = limit;
        self.since = now;
        self.blocked = false;
        self.last_change = now;
        let typ = if limit == 0 { "relax" } else if cfg.dry_run { "dry_run_limit" } else { "limit" };
        out.push((typ.into(), format!("action={action} host={log_ip} limit={limit}")));
        if limit == 0 {
            crate::log_info!("action=RELAX host={} limit=unlimited dry_run={}", log_ip, cfg.dry_run);
        } else if cfg.dry_run {
            crate::log_info!("DRY-RUN: Would limit host={} limit={} action={}", ip, limit, action);
        } else {
            crate::log_info!("action={} host={} limit={}", action, ip, limit);
        }
    }

    /// Такт: лимит самому жадному при внешней деградации IPv4, ослабление при
    /// восстановлении. Возвращает (события, journal-заметки, сбросить RECOVERY → NORMAL).
    pub fn apply(&mut self, v: &View, s: &Snapshot, top: Option<&ClientStats>, now: i64) -> (Vec<(String, String)>, bool) {
        let cfg = v.cfg;
        let mut ev = Vec::new();
        if self.disabled || v.post_switch {
            self.update_blocked(v, s, now, &mut ev);
            return (ev, false);
        }
        if self.limit > 0 && !self.ip.is_empty() && !s.clients.contains_key(&self.ip) && self.can_change(cfg, now) {
            self.set(cfg, "", 0, now, "CLEAR", &mut ev);
        }
        let recovering = (v.phase == "RECOVERY" || v.diagnosis == "HEALTHY") && v.v4_count > 0 && v.v4_success >= cfg.thresholds.recovery_success && v.v6_healthy;
        if self.limit > 0 && recovering && self.can_change(cfg, now) {
            let cur = s.clients.get(&self.ip);
            let cur_v = cur.map(|c| c.wan).unwrap_or(0);
            let nl = relaxed_limit(self.limit, cfg.limits.recovery_step_percent, cfg.limits.max);
            let ip = self.ip.clone();
            if cur.is_none() || nl >= cur_v || nl >= cfg.limits.max {
                self.set(cfg, &ip, 0, now, "RELAX", &mut ev);
            } else if nl > self.limit {
                self.set(cfg, &ip, nl, now, "RELAX", &mut ev);
            }
        }
        if (v.phase == "WARNING" || v.phase == "CRITICAL") && v.diagnosis == "IPV4_EXTERNAL_DEGRADATION" {
            if let Some(top) = top {
                let desired = calculate_limit(cfg, v.phase, top, v.v4_success);
                if desired > 0 {
                    if self.limit == 0 || self.ip.is_empty() {
                        if self.can_change(cfg, now) {
                            self.set(cfg, &top.ip, desired, now, "LIMIT", &mut ev);
                        }
                    } else if self.ip == top.ip {
                        if desired < self.limit && self.can_change(cfg, now) {
                            self.set(cfg, &top.ip, desired, now, "LIMIT", &mut ev);
                        }
                    } else {
                        let old = s.clients.get(&self.ip);
                        if (old.is_none() || top.wan > old.map(|c| c.wan).unwrap_or(0)) && self.can_change(cfg, now) {
                            self.set(cfg, &top.ip, desired, now, "LIMIT", &mut ev);
                        }
                    }
                }
            }
        }
        let reset = v.phase == "RECOVERY" && self.limit == 0;
        self.update_blocked(v, s, now, &mut ev);
        (ev, reset)
    }

    fn update_blocked(&mut self, v: &View, s: &Snapshot, now: i64, ev: &mut Vec<(String, String)>) {
        let cfg = v.cfg;
        let mut hosts = Vec::new();
        if self.limit > 0 && !self.ip.is_empty() && !v.grace && cfg.enable_limiter && !self.disabled {
            match s.clients.get(&self.ip) {
                Some(c) => {
                    let unblock = (self.limit as f64 * cfg.limits.block_hysteresis_percent as f64 / 100.0) as i64;
                    if self.blocked {
                        if c.wan > unblock {
                            hosts.push(self.ip.clone());
                        } else {
                            self.blocked = false;
                        }
                    } else if c.wan > self.limit {
                        self.blocked = true;
                        hosts.push(self.ip.clone());
                    }
                }
                None => self.blocked = false,
            }
        }
        let key = hosts.join(",");
        if cfg.dry_run || self.disabled || !cfg.enable_limiter {
            if cfg.dry_run && !self.disabled && key != self.last_blocked_key && !key.is_empty() {
                crate::log_info!("DRY-RUN: Would block new connections for {} (limit {})", key, self.limit);
            }
            self.last_blocked_key = key;
            return;
        }
        let changed = key != self.last_blocked_key;
        let refresh = !hosts.is_empty() && now - self.last_set_refresh >= cfg.nft.refresh_sec;
        if changed || refresh {
            match nft_apply_blocked(&cfg.nft.table, &hosts, cfg.nft.set_timeout_sec) {
                Err(e) => crate::log_err!("nft apply blocked hosts failed: {}", e),
                Ok(()) => {
                    self.last_set_refresh = now;
                    if changed {
                        ev.push(if key.is_empty() { ("unblock".into(), "unblocked new connections".into()) } else { ("block".into(), format!("blocked new connections for {key}")) });
                    }
                    self.last_blocked_key = key;
                }
            }
        }
    }

    /// connlimit_host роутера: вниз (×0,7 до base/4, ≥ 10), когда деградацию
    /// создаёт его собственный трафик; потом плавно назад.
    pub fn router_limit(&mut self, v: &View, s: &Snapshot, now: i64) -> Vec<(String, String)> {
        let cfg = v.cfg;
        let mut ev = Vec::new();
        if !cfg.hard_limit.enabled {
            return ev;
        }
        let min_change = cfg.limits.min_change_interval_sec;
        let degrading = (v.phase == "WARNING" || v.phase == "CRITICAL") && v.diagnosis == "IPV4_EXTERNAL_DEGRADATION";
        let base = hard_effective(cfg).0.connlimit_host;
        if base <= 0 {
            return ev;
        }
        if degrading && s.router_own > s.lan_to_wan {
            let floor = (base / 4).max(10);
            let cur = if self.router_host_limit == 0 { base } else { self.router_host_limit };
            let next = (cur * 7 / 10).max(floor);
            if next != cur && now - self.router_limit_since >= min_change {
                self.router_host_limit = next;
                self.router_limit_since = now;
                ev.push(("router_limit".into(), format!("router connlimit_host reduced to {} (router_own={} lan_to_wan={})", next, s.router_own, s.lan_to_wan)));
                if let Err(e) = hard_apply(cfg, next) {
                    crate::log_err!("hard-limit router modulation failed: {}", e);
                }
            }
            return ev;
        }
        if self.router_host_limit > 0 {
            let cur = self.router_host_limit;
            let mut next = cur + cur * cfg.limits.recovery_step_percent / 100;
            let restored = next >= base;
            if restored {
                next = 0;
            }
            if next != cur && now - self.router_limit_since >= min_change {
                self.router_host_limit = next;
                self.router_limit_since = now;
                ev.push(("router_limit".into(), if restored { format!("router connlimit_host restored to base {base}") } else { format!("router connlimit_host raised to {next}") }));
                if let Err(e) = hard_apply(cfg, next) {
                    crate::log_err!("hard-limit router modulation failed: {}", e);
                }
            }
        }
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = crate::config::defaults();
        c.normalize();
        c.startup_grace_sec = 0;
        c.limits.min_change_interval_sec = 60;
        c
    }

    #[test]
    fn relax_and_calc() {
        // TestRelaxedLimit и расчёт как в Go
        assert_eq!(relaxed_limit(100, 10, 1000), 110);
        assert_eq!(relaxed_limit(5, 10, 1000), 6);
        assert_eq!(relaxed_limit(995, 10, 1000), 1000);
        assert_eq!(relaxed_limit(0, 10, 1000), 0);
        let c = cfg();
        let top = ClientStats { wan: 200, ..Default::default() };
        assert_eq!(calculate_limit(&c, "WARNING", &top, 90.0), (200.0 * c.limits.warning_factor) as i64);
        assert_eq!(calculate_limit(&c, "CRITICAL", &top, 50.0), (200.0 * c.limits.critical_factor) as i64);
    }

    #[test]
    fn oscillation_protection() {
        // TestOscillationProtection: смена лимита не чаще min_change_interval_sec
        let c = cfg();
        let mut l = Limiter::default();
        let mut s = Snapshot::default();
        s.clients.insert("192.0.2.5".into(), ClientStats { ip: "192.0.2.5".into(), wan: 300, ..Default::default() });
        s.clients.insert("192.0.2.6".into(), ClientStats { ip: "192.0.2.6".into(), wan: 900, ..Default::default() });
        let v = View { cfg: &c, phase: "WARNING", diagnosis: "IPV4_EXTERNAL_DEGRADATION", grace: false, v4_success: 90.0, v4_count: 10, v6_healthy: true, post_switch: false };
        let a = s.clients["192.0.2.5"].clone();
        let (ev, _) = l.apply(&v, &s, Some(&a), 1000);
        assert_eq!(l.ip, "192.0.2.5");
        assert!(ev.iter().any(|(t, _)| t == "dry_run_limit" || t == "limit"));
        let b = s.clients["192.0.2.6"].clone();
        l.apply(&v, &s, Some(&b), 1010);
        assert_eq!(l.ip, "192.0.2.5", "смена раньше min_change_interval_sec");
        l.apply(&v, &s, Some(&b), 1070);
        assert_eq!(l.ip, "192.0.2.6");
    }

    #[test]
    fn hard_script_shape() {
        let c = cfg();
        let mut hl = c.hard_limit.clone();
        hl.forward_ipv4_tcp = true;
        hl.host_ipv6_udp = true;
        let s = hard_script(&hl, &["br-lan".into(), "vlan2".into()], 25, 50);
        assert!(s.starts_with("flush table inet torrent_limit\n"));
        assert!(s.contains("iifname { \"br-lan\", \"vlan2\" } ip protocol tcp tcp dport != { 53, 80, 443 } add @tcp_hosts { ip saddr ct count over 25 } counter reject with tcp reset"));
        assert!(s.contains("ip6 nexthdr udp udp dport != { 53, 123, 443 } add @output_udp6_hosts { ip6 saddr ct count over 50 } counter drop"));
    }
}
