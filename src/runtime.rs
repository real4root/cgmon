//! Настройки на лету со страницы (перенос runtime.go): белый список ключей с
//! границами, runtime.json поверх cgmon.yaml (сам файл не трогаем), слой
//! "config" (livecfg), пароль с паузой после 5 неверных, ≤ 10 изменений за 10 с.

use crate::config::Config;
use crate::livecfg;
use crate::util;
use crate::value::{parse_json, Value};

pub const KEYS: &[&str] = &[
    "extended", "extended_minutes", "shaper_on", "sustained_kbit", "burst_mb", "burst_kbit",
    "flow_watch_on", "dry_run", "billing_on", "qos_on", "qos_upload_kbit", "qos_download_kbit",
    "qos_flow_cap_kbit", "qos_flow_cap_down_kbit", "billing_daily_mb", "billing_monthly_mb", "wan_check",
    "gate_maps",
];

const MAX_FAILS: usize = 5;
const FAIL_WINDOW: i64 = 300;
pub const MAX_BODY: usize = 16384;
pub const MAX_UPLOAD: usize = 1 << 20;
const RATE_LIMIT: usize = 10;
const RATE_WINDOW: i64 = 10;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    pub extended: bool,
    pub extended_minutes: i64,
    pub shaper_on: bool,
    pub sustained_kbit: i64,
    pub burst_mb: f64,
    pub burst_kbit: i64,
    pub flow_watch_on: bool,
    pub dry_run: bool,
    pub billing_on: bool,
    pub qos_on: bool,
    pub qos_upload_kbit: i64,
    pub qos_download_kbit: i64,
    pub qos_flow_cap_kbit: i64,
    pub qos_flow_cap_down_kbit: i64,
    pub billing_daily_mb: f64,
    pub billing_monthly_mb: f64,
    pub wan_check: String,
    /// карты шлюзов (gatemap.rs): кому из LAN каким выходом ходить
    pub gate_maps: Vec<crate::gatemap::GateMap>,
}

pub fn defaults(c: &Config) -> Settings {
    let mut s = Settings {
        extended_minutes: 60,
        shaper_on: c.upload_shaper.enabled,
        sustained_kbit: c.upload_shaper.sustained_kbit,
        flow_watch_on: c.flow_watch.enabled,
        dry_run: c.dry_run,
        billing_on: c.billing.enabled,
        qos_on: c.qos.enabled,
        qos_upload_kbit: c.qos.upload_kbit,
        qos_download_kbit: c.qos.download_kbit,
        qos_flow_cap_kbit: c.qos.flow_cap_up_kbit,
        qos_flow_cap_down_kbit: c.qos.flow_cap_down_kbit,
        billing_daily_mb: c.billing.daily_limit_mb,
        billing_monthly_mb: c.billing.monthly_limit_mb,
        wan_check: c.wan_check.clone(),
        ..Default::default()
    };
    if let Some(st) = c.upload_shaper.stages.first() {
        s.burst_mb = st.mb;
        s.burst_kbit = st.kbit;
    }
    s
}

/// Один ключ с проверкой границ (ext_at — когда включили расширенный).
pub fn apply_key(cur: &mut Settings, ext_at: &mut i64, now: i64, k: &str, v: &Value) -> Result<(), String> {
    if *v == Value::Null {
        return Err("value required".into());
    }
    if k == "gate_maps" {
        cur.gate_maps = crate::gatemap::parse_maps(v)?;
        return Ok(());
    }
    if k == "wan_check" {
        match v.as_str() {
            Some(m @ ("active" | "passive" | "hybrid")) => {
                cur.wan_check = m.to_string();
                return Ok(());
            }
            _ => return Err("active, passive or hybrid".into()),
        }
    }
    let (b, n) = match k {
        "extended" | "shaper_on" | "flow_watch_on" | "dry_run" | "billing_on" | "qos_on" => (v.as_bool().ok_or("must be true/false")?, 0.0),
        _ => (false, v.as_f64().ok_or("must be a number")?),
    };
    match k {
        "extended" => {
            if b && !cur.extended {
                *ext_at = now;
            }
            cur.extended = b;
        }
        "extended_minutes" => {
            if !(0.0..=10080.0).contains(&n) {
                return Err("0..10080".into());
            }
            cur.extended_minutes = n as i64;
        }
        "shaper_on" => cur.shaper_on = b,
        "sustained_kbit" => {
            if !(1000.0..=1000000.0).contains(&n) {
                return Err("1000..1000000 kbit".into());
            }
            cur.sustained_kbit = n as i64;
        }
        "burst_kbit" => {
            if n != 0.0 && !(1000.0..=10000000.0).contains(&n) {
                return Err("0 or 1000..10000000 kbit".into());
            }
            cur.burst_kbit = n as i64;
        }
        "billing_daily_mb" | "billing_monthly_mb" => {
            if !(0.0..=10000000.0).contains(&n) {
                return Err("0..10000000 MB".into());
            }
            if k == "billing_daily_mb" {
                cur.billing_daily_mb = n;
            } else {
                cur.billing_monthly_mb = n;
            }
        }
        "burst_mb" => {
            if !(0.0..=1000.0).contains(&n) {
                return Err("0..1000 MB".into());
            }
            cur.burst_mb = n;
        }
        "flow_watch_on" => cur.flow_watch_on = b,
        "dry_run" => cur.dry_run = b,
        "billing_on" => cur.billing_on = b,
        "qos_on" => cur.qos_on = b,
        "qos_upload_kbit" | "qos_download_kbit" | "qos_flow_cap_kbit" | "qos_flow_cap_down_kbit" => {
            // 0 — это направление не шейпить (для flow cap — cake вместо HTB)
            if n.fract() != 0.0 || n < 0.0 || (n > 0.0 && n < 1000.0) || n > 10000000.0 {
                return Err("0 or 1000..10000000 kbit".into());
            }
            let n = n as i64;
            match k {
                "qos_upload_kbit" => cur.qos_upload_kbit = n,
                "qos_download_kbit" => cur.qos_download_kbit = n,
                "qos_flow_cap_down_kbit" => cur.qos_flow_cap_down_kbit = n,
                _ => cur.qos_flow_cap_kbit = n,
            }
        }
        _ => {}
    }
    Ok(())
}

/// Пароль страницы не задан — изменения со страницы запрещены.
pub const NO_PASSWORD: &str = "пароль страницы не задан — настройки только для просмотра; задайте пароль: LuCI → Службы → cgmon (или web.password в cgmon.yaml)";

pub struct Runtime {
    pub path: String,
    pub cur: Settings,
    saved: Vec<(String, Value)>,
    ext_at: i64,
    sets: Vec<i64>,
    fails: Vec<i64>,
    pub changed: bool,
    /// cgmon.yaml как есть (без слоя) и слой "config" со страницы.
    pub base: Config,
    overlay: Vec<(String, Value)>,
    pending: Option<Config>,
}

fn recent(ts: &mut Vec<i64>, now: i64, window: i64) {
    ts.retain(|t| now - t <= window);
}

impl Runtime {
    pub fn new(cfg: &Config, base: Config, overlay: Vec<(String, Value)>, now: i64) -> Runtime {
        let mut r = Runtime {
            path: cfg.paths.runtime.clone(),
            cur: defaults(cfg),
            saved: Vec::new(),
            ext_at: 0,
            sets: Vec::new(),
            fails: Vec::new(),
            changed: true,
            base,
            overlay,
            pending: None,
        };
        if let Ok(text) = std::fs::read_to_string(&r.path) {
            match parse_json(&text) {
                Ok(Value::Map(m)) => {
                    for (k, v) in m {
                        if !KEYS.contains(&k.as_str()) {
                            continue;
                        }
                        if let Err(e) = apply_key(&mut r.cur, &mut r.ext_at, now, &k, &v) {
                            crate::log_err!("runtime: {}: {}: {} (ignored)", r.path, k, e);
                            continue;
                        }
                        r.saved.push((k, v));
                    }
                }
                Ok(_) => crate::log_err!("runtime: {}: не объект (ignored)", r.path),
                Err(e) => crate::log_err!("runtime: {}: {} (ignored)", r.path, e),
            }
        }
        if r.cur.extended {
            r.ext_at = now; // после перезапуска отсчёт автоотключения — заново
        }
        r
    }

    fn pass_ok(&mut self, cfg: &Config, password: &str, now: i64) -> Result<(), String> {
        // без пароля страница только показывает: менять нечем и некому
        if cfg.web.password.is_empty() {
            return Err(NO_PASSWORD.into());
        }
        {
            recent(&mut self.fails, now, FAIL_WINDOW);
            if self.fails.len() >= MAX_FAILS {
                return Err("too many wrong passwords, try later".into());
            }
            if !util::ct_eq(password.as_bytes(), cfg.web.password.as_bytes()) {
                self.fails.push(now);
                return Err("wrong password".into());
            }
            self.fails.clear();
        }
        Ok(())
    }

    fn rate(&mut self, now: i64) -> Result<(), String> {
        recent(&mut self.sets, now, RATE_WINDOW);
        if self.sets.len() >= RATE_LIMIT {
            return Err("too many changes, try later".into());
        }
        self.sets.push(now);
        Ok(())
    }

    /// Пароль и предел частоты — для действий помимо настроек (загрузки, доступ).
    pub fn check_password(&mut self, cfg: &Config, password: &str, now: i64) -> Result<(), String> {
        self.pass_ok(cfg, password, now)?;
        self.rate(now)
    }

    /// Изменение со страницы: сначала всё проверяется на копии, потом применяется.
    pub fn set(&mut self, cfg: &Config, m: &[(String, Value)], cm: &[(String, Value)], password: &str, now: i64) -> Result<(), String> {
        self.pass_ok(cfg, password, now)?;
        self.rate(now)?;
        if m.iter().any(|(k, _)| !KEYS.contains(&k.as_str())) {
            return Err("unknown setting".into());
        }
        let has = |k: &str| m.iter().any(|(x, _)| x == k);
        let (mut cur, mut ext_at) = (self.cur.clone(), self.ext_at);
        for (k, v) in m {
            apply_key(&mut cur, &mut ext_at, now, k, v).map_err(|e| format!("{k}: {e}"))?;
        }
        let us = &cfg.upload_shaper;
        if (has("shaper_on") || has("sustained_kbit") || has("burst_mb") || has("burst_kbit")) && !us.enabled {
            return Err("upload_shaper is not configured".into());
        }
        if us.enabled && cur.burst_mb > 0.0 && cur.burst_kbit > 0 && cur.burst_kbit <= cur.sustained_kbit {
            return Err("скорость после триггера должна быть ниже начальной".into());
        }
        if cfg.qos.enabled {
            let (up, down) = (cur.qos_upload_kbit, cur.qos_download_kbit);
            if us.enabled && up > 0 && cur.burst_kbit > up {
                return Err("лимит начальной скорости выше Upload канала".into());
            } else if us.enabled && up > 0 && cur.sustained_kbit >= up {
                return Err("скорость после триггера должна быть ниже Upload канала".into());
            } else if up > 0 && cur.qos_flow_cap_kbit > up {
                return Err("лимит отдачи на соединение выше Upload канала".into());
            } else if down > 0 && cur.qos_flow_cap_down_kbit > down {
                return Err("лимит загрузки на соединение выше Download канала".into());
            }
        }
        if ["qos_on", "qos_upload_kbit", "qos_download_kbit", "qos_flow_cap_kbit", "qos_flow_cap_down_kbit"].iter().any(|k| has(k)) && !cfg.qos.enabled {
            return Err("qos is not configured".into());
        }
        if (has("billing_on") || has("billing_daily_mb") || has("billing_monthly_mb")) && !cfg.accounting.enabled {
            return Err("billing is not configured".into());
        }
        if has("flow_watch_on") && !cfg.flow_watch.enabled {
            return Err("flow_watch is disabled in config".into());
        }
        // настройки конфига: собрать новый конфиг целиком и проверить
        let mut nc = None;
        let mut ov = self.overlay.clone();
        if !cm.is_empty() {
            for (k, v) in cm {
                let mut probe = self.base.clone();
                livecfg::set(&mut probe, k, v).map_err(|e| format!("{k}: {e}"))?;
                ov.retain(|(x, _)| x != k);
                if !livecfg::same_as_base(&self.base, k, v) {
                    ov.push((k.clone(), v.clone()));
                }
            }
            nc = Some(livecfg::build_live(&self.base, &ov)?);
        }
        self.cur = cur;
        self.ext_at = ext_at;
        for (k, v) in m {
            self.saved.retain(|(x, _)| x != k);
            self.saved.push((k.clone(), v.clone()));
        }
        if nc.is_some() {
            self.overlay = ov;
            self.pending = nc;
        }
        self.changed = true;
        self.save().map_err(|e| e.to_string())
    }

    /// Собранный со страницы конфиг для такта (один раз).
    pub fn take_config(&mut self) -> Option<Config> {
        self.pending.take()
    }

    pub fn overlay(&self) -> &[(String, Value)] {
        &self.overlay
    }

    fn save(&self) -> std::io::Result<()> {
        let mut keys: Vec<&(String, Value)> = self.saved.iter().collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let mut s = String::from("{");
        let mut first = true;
        let mut put = |s: &mut String, k: &str, v: &Value| {
            s.push_str(if first { "\n  " } else { ",\n  " });
            first = false;
            crate::value::json_str(s, k);
            s.push_str(": ");
            v.to_json(s);
        };
        let ov = Value::Map(self.overlay.clone());
        let mut all: Vec<(&str, &Value)> = keys.iter().map(|(k, v)| (k.as_str(), v)).collect();
        if !self.overlay.is_empty() {
            all.push(("config", &ov));
            all.sort_by(|a, b| a.0.cmp(b.0));
        }
        for (k, v) in all {
            put(&mut s, k, v);
        }
        s.push_str("\n}");
        util::write_atomic(&self.path, s.as_bytes(), 0o644)
    }

    /// Текущие настройки для такта; changed — их надо применить. Здесь же
    /// автоотключение расширенного режима.
    pub fn take(&mut self, now: i64) -> (Settings, bool) {
        if self.cur.extended && self.cur.extended_minutes > 0 && now - self.ext_at >= self.cur.extended_minutes * 60 {
            self.cur.extended = false;
            self.saved.retain(|(x, _)| x != "extended");
            self.saved.push(("extended".into(), Value::Bool(false)));
            let _ = self.save();
            self.changed = true;
        }
        let ch = self.changed;
        self.changed = false;
        (self.cur.clone(), ch)
    }

    pub fn locked(&self, cfg: &Config, now: i64) -> bool {
        !cfg.web.password.is_empty() && self.fails.iter().filter(|t| now - **t <= FAIL_WINDOW).count() >= MAX_FAILS
    }

    /// Статус для страницы (RuntimeStatus в Go).
    pub fn status_json(&self, cfg: &Config, now: i64, j: &mut crate::json::J) {
        let c = &self.cur;
        j.obj();
        j.key("extended").bool(c.extended).key("extended_minutes").int(c.extended_minutes);
        j.key("shaper_on").bool(c.shaper_on).key("sustained_kbit").int(c.sustained_kbit);
        j.key("burst_mb").raw(&crate::config::go_float(c.burst_mb)).key("burst_kbit").int(c.burst_kbit);
        j.key("flow_watch_on").bool(c.flow_watch_on).key("dry_run").bool(c.dry_run).key("billing_on").bool(c.billing_on);
        j.key("qos_on").bool(c.qos_on).key("qos_upload_kbit").int(c.qos_upload_kbit).key("qos_download_kbit").int(c.qos_download_kbit);
        j.key("qos_flow_cap_kbit").int(c.qos_flow_cap_kbit).key("qos_flow_cap_down_kbit").int(c.qos_flow_cap_down_kbit);
        j.key("billing_daily_mb").raw(&crate::config::go_float(c.billing_daily_mb)).key("billing_monthly_mb").raw(&crate::config::go_float(c.billing_monthly_mb));
        j.key("wan_check").str(&c.wan_check);
        j.key("gate_maps");
        crate::gatemap::maps_json(&c.gate_maps, j);
        if c.extended && c.extended_minutes > 0 {
            j.key("extended_until").str(&util::rfc3339(self.ext_at + c.extended_minutes * 60, 0));
        }
        j.key("has_shaper").bool(cfg.upload_shaper.enabled).key("has_flow_watch").bool(cfg.flow_watch.enabled);
        j.key("has_billing").bool(cfg.accounting.enabled).key("has_qos").bool(cfg.qos.enabled);
        j.key("password_required").bool(!cfg.web.password.is_empty());
        if cfg.web.password.is_empty() {
            j.key("password_missing").bool(true); // страница — только просмотр
        }
        if self.locked(cfg, now) {
            j.key("locked").bool(true);
        }
        j.key("config").obj();
        cfg.walk("", &mut |p, f| {
            if livecfg::is_main(p) && !matches!(f, crate::config::Field::Complex) {
                let mut s = String::new();
                crate::config::field_json(f, &mut s);
                j.key(p).raw(&s);
            }
        });
        j.end_obj();
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::defaults as cfg_defaults;

    fn cfg() -> Config {
        let mut c = cfg_defaults();
        c.normalize();
        c.web.password = "secret".into();
        c
    }

    #[test]
    fn password_rate_and_save() {
        let dir = std::env::temp_dir().join(format!("cgmon-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = cfg();
        c.paths.runtime = dir.join("runtime.json").to_string_lossy().into_owned();
        let mut r = Runtime::new(&c, c.clone(), Vec::new(), 1000);
        let m = vec![("extended".to_string(), Value::Bool(true))];
        assert_eq!(r.set(&c, &m, &[], "bad", 1000), Err("wrong password".into()));
        for i in 0..4 {
            let _ = r.set(&c, &m, &[], "bad", 1001 + i);
        }
        assert!(r.locked(&c, 1010));
        assert_eq!(r.set(&c, &m, &[], "secret", 1010), Err("too many wrong passwords, try later".into()));
        // через 5 минут пароль снова принимается
        assert!(r.set(&c, &m, &[], "secret", 1400).is_ok());
        assert!(r.cur.extended);
        let cm = vec![("dns_guard.relay_mbit".to_string(), Value::Num("30".into()))];
        assert!(r.set(&c, &[], &cm, "secret", 1401).is_ok());
        assert_eq!(r.take_config().unwrap().dns_guard.relay_mbit, 30);
        // перечитать с диска
        let r2 = Runtime::new(&c, c.clone(), crate::livecfg::read_overlay(&c.paths.runtime), 2000);
        assert!(r2.cur.extended);
        assert_eq!(r2.overlay().len(), 1);
        // автоотключение через extended_minutes
        let mut r3 = r2;
        let (s, _) = r3.take(2000 + 61 * 60);
        assert!(!s.extended);
        // без пароля страницы — только просмотр: менять нельзя ничего
        let mut nc = c.clone();
        nc.web.password.clear();
        let mut r4 = Runtime::new(&nc, nc.clone(), Vec::new(), 3000);
        assert_eq!(r4.set(&nc, &m, &[], "", 3000), Err(NO_PASSWORD.into()));
        assert_eq!(r4.check_password(&nc, "", 3000), Err(NO_PASSWORD.into()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounds() {
        let c = cfg();
        let mut s = defaults(&c);
        let mut e = 0;
        assert!(apply_key(&mut s, &mut e, 0, "qos_upload_kbit", &Value::Num("500".into())).is_err());
        assert!(apply_key(&mut s, &mut e, 0, "qos_upload_kbit", &Value::Num("0".into())).is_ok());
        assert!(apply_key(&mut s, &mut e, 0, "wan_check", &Value::Str("x".into())).is_err());
        assert!(apply_key(&mut s, &mut e, 0, "extended", &Value::Null).is_err());
    }
}
