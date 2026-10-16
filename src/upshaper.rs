//! Шейпер отдачи (перенос upshaper.go): ступени скорости всего аплоада с
//! медленным восполнением запаса — потолок класса HTB 1:1 (qos.rs).
//!
//!   stages[0].kbit, пока не отдано stages[0].mb → stages[1].kbit … → sustained_kbit
//!
//! Корзина j копит превышение над порогом T_j (скорость следующей ступени):
//! отдали больше T_j·dt — тратится на разницу, меньше — пополняется на
//! разницу / refill_factor. Возврат долга (payback_kbit): долг = отдано сверх
//! sustained·t; после ступеней — payback, пока долг не погашен. Корзины после
//! старта пусты (перезапуск не даёт разгона). Такт — interval_ms при отдаче,
//! раз в секунду в простое (таймер в общем цикле).

use crate::config::{UploadShaperConfig, UploadStage};
use crate::json::J;

/// С остатком меньше этого ступень кончилась.
const STAGE_MIN_BYTES: f64 = 512.0 * 1024.0;
/// В возврат долга — только при заметном долге.
const PAYBACK_ENTER_BYTES: f64 = 2.0 * 1048576.0;
const MB: f64 = 1048576.0;

#[derive(Default)]
pub struct Status {
    device: String,
    rate_kbit: i64,
    stage: usize,
    debt_mb: f64,
    cooldown_sec: i64,
    off: bool,
    sustained_kbit: i64,
    tx_mbps: f64,
    bucket_mb: Vec<f64>,
    cap_mb: Vec<f64>,
    error: String,
}

pub struct UploadShaper {
    pub cfg: UploadShaperConfig,
    rates: Vec<i64>,
    thresh: Vec<f64>,
    caps: Vec<f64>,
    tokens: Vec<f64>,
    debt: f64,
    penalty: bool,
    cool_until: u64,
    busy_at: u64,
    reconf: Option<UploadShaperConfig>,
    off: bool,
    top_kbit: i64,
    orig: UploadShaperConfig,
    force: bool,
    st: Status,
    applied: i64,
    applied_at: u64,
    err_logged: bool,
    prev_dev: String,
    prev_tx: u64,
    prev_at: u64,
    stage: usize,
    /// следующий такт (монотонные мс)
    pub next_at: u64,
}

fn r2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn mb_list(v: &[f64]) -> Vec<f64> {
    v.iter().map(|x| r2(x / MB)).collect()
}

/// Ступени строго убывают и выше устойчивой.
#[allow(dead_code)]
pub fn valid_stages(c: &UploadShaperConfig) -> Result<(), String> {
    if c.sustained_kbit <= 0 {
        return Err("sustained_kbit must be > 0".into());
    }
    if c.payback_kbit >= c.sustained_kbit {
        return Err("payback_kbit must be lower than sustained_kbit".into());
    }
    let mut prev = 0;
    for (i, s) in c.stages.iter().enumerate() {
        if s.kbit <= c.sustained_kbit || s.mb <= 0.0 {
            return Err(format!("stage {}: kbit must be > sustained_kbit and mb > 0", i + 1));
        }
        if i > 0 && s.kbit >= prev {
            return Err(format!("stage {}: kbit must be lower than previous stage", i + 1));
        }
        prev = s.kbit;
    }
    Ok(())
}

impl UploadShaper {
    pub fn new(cfg: UploadShaperConfig) -> UploadShaper {
        let top = cfg.stages.first().map_or(cfg.sustained_kbit, |s| s.kbit);
        let mut s = UploadShaper {
            cfg: cfg.clone(),
            rates: Vec::new(),
            thresh: Vec::new(),
            caps: Vec::new(),
            tokens: Vec::new(),
            debt: 0.0,
            penalty: false,
            cool_until: 0,
            busy_at: 0,
            reconf: None,
            off: false,
            top_kbit: top,
            orig: cfg.clone(),
            force: false,
            st: Status::default(),
            applied: 0,
            applied_at: 0,
            err_logged: false,
            prev_dev: String::new(),
            prev_tx: 0,
            prev_at: 0,
            stage: 0,
            next_at: 0,
        };
        s.build(cfg);
        s
    }

    /// Ступени и корзины заново; запас сохраняется в пределах новых ёмкостей.
    fn build(&mut self, cfg: UploadShaperConfig) {
        let old = std::mem::take(&mut self.tokens);
        self.rates = cfg.stages.iter().map(|s| s.kbit).collect();
        self.rates.push(cfg.sustained_kbit);
        if cfg.payback_kbit > 0 {
            self.rates.push(cfg.payback_kbit);
        }
        self.thresh.clear();
        self.caps.clear();
        for j in 0..cfg.stages.len() {
            let t = self.rates[j + 1] as f64 * 1000.0 / 8.0;
            let c: f64 = cfg.stages[..=j].iter().map(|k| {
                let r = k.kbit as f64 * 1000.0 / 8.0;
                k.mb * MB * (r - t) / r
            }).sum();
            self.thresh.push(t);
            self.caps.push(c);
            self.tokens.push(old.get(j).map_or(0.0, |x| x.min(c)));
        }
        self.cfg = cfg;
    }

    /// Со страницы: вкл/выкл, sustained, объём (и скорость) первой ступени.
    pub fn reconfigure(&mut self, on: bool, sustained: i64, burst_mb: f64, burst_kbit: i64) {
        let mut cfg = self.orig.clone();
        cfg.sustained_kbit = sustained;
        if let Some(s) = cfg.stages.first_mut() {
            s.mb = burst_mb;
            if burst_kbit > 0 {
                s.kbit = burst_kbit;
            }
        }
        cfg.stages.retain(|x: &UploadStage| x.kbit > sustained && x.mb > 0.0);
        if cfg.payback_kbit >= sustained {
            cfg.payback_kbit = sustained * 6 / 10;
        }
        if self.off == !on && self.reconf.is_none() && cfg == self.cfg {
            return;
        }
        self.reconf = Some(cfg);
        self.off = !on;
    }

    /// Новые настройки из конфига; ступени и устройство — прежние.
    pub fn set_base(&mut self, mut c: UploadShaperConfig) {
        c.device = self.orig.device.clone();
        c.class_id = self.orig.class_id.clone();
        c.stages = self.orig.stages.clone();
        self.orig = c;
    }

    fn thresh0(&self) -> f64 {
        self.cfg.sustained_kbit as f64 * 1000.0 / 8.0
    }

    /// Учесть sent байт за dt с; номер ступени.
    pub fn step(&mut self, sent: f64, dt: f64, cur: usize) -> usize {
        for j in 0..self.tokens.len() {
            let d = sent - self.thresh[j] * dt;
            if d > 0.0 {
                self.tokens[j] -= d;
            } else {
                self.tokens[j] += -d / self.cfg.refill_factor;
            }
            self.tokens[j] = self.tokens[j].clamp(0.0, self.caps[j]);
        }
        let n = self.tokens.len();
        let payback = self.cfg.payback_kbit > 0;
        if payback {
            self.debt = (self.debt + sent - self.thresh0() * dt).max(0.0);
        }
        let mut stage = n;
        for i in (0..n).rev() {
            let mut need = STAGE_MIN_BYTES;
            if i < cur {
                need = self.caps[i] * self.cfg.resume_percent / 100.0;
                if payback && self.debt > 0.0 {
                    break; // вернуться на ступень — только с погашенным долгом
                }
            }
            if self.tokens[i] < need {
                break;
            }
            stage = i;
        }
        if payback && stage == n {
            let enter = cur < n || self.debt > PAYBACK_ENTER_BYTES;
            if (cur == n + 1 && self.debt > 0.0) || (cur != n + 1 && enter && self.debt > 0.0) {
                stage = n + 1;
            }
        }
        stage
    }

    fn device(&self, qos_dev: &str) -> String {
        let d = &self.cfg.device;
        if !d.is_empty() && d != "auto" {
            return d.clone();
        }
        if !qos_dev.is_empty() {
            return qos_dev.to_string();
        }
        crate::netx::default_route_interface()
    }

    /// Дерево qdisc перестроено — поставить потолок сразу.
    pub fn reapply(&mut self) {
        self.force = true;
        self.next_at = 0;
    }

    /// Провайдер наказал путь: запас обнулить, без разгона penalty_cooldown_sec.
    pub fn penalize(&mut self) {
        self.penalty = true;
    }

    /// Отдача была выше половины sustained за последние within мс.
    pub fn busy(&self, now: u64, within: u64) -> bool {
        self.busy_at != 0 && now - self.busy_at <= within
    }

    /// Такт по таймеру (qos_dev — устройство очереди qos при device: auto).
    pub fn tick(&mut self, now: u64, qos_dev: &str) {
        let iv = (self.cfg.interval_ms.max(50)) as u64;
        self.next_at = now + iv;
        let dev = self.device(qos_dev);
        if dev != self.prev_dev {
            // WAN сменился — счётчики другого устройства
            self.prev_dev = dev.clone();
            self.prev_tx = 0;
            self.prev_at = 0;
        }
        let tx = match std::fs::read_to_string(format!("/sys/class/net/{dev}/statistics/tx_bytes")).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
            Some(v) => v,
            None => {
                self.st.error = format!("read {dev} tx_bytes: no such device");
                self.prev_at = 0;
                return;
            }
        };
        if self.prev_at == 0 || tx < self.prev_tx {
            self.prev_tx = tx;
            self.prev_at = now;
            return;
        }
        let dt = (now - self.prev_at) as f64 / 1000.0;
        if dt <= 0.0 {
            return;
        }
        let sent = (tx - self.prev_tx) as f64;
        self.prev_tx = tx;
        self.prev_at = now;
        // в простое — раз в секунду (корзины и долг от dt не зависят)
        if sent * 8.0 / dt <= 1e6 {
            self.next_at = now + 1000;
        }
        if let Some(c) = self.reconf.take() {
            self.build(c);
            self.stage = self.stage.min(self.rates.len() - 1);
            crate::log_info!("upload shaper: reconfigured: sustained {} kbit, stages {}, off={}", self.cfg.sustained_kbit, stages_text(&self.cfg.stages), self.off);
        }
        let force = std::mem::take(&mut self.force);
        if sent * 8.0 / dt >= self.cfg.sustained_kbit as f64 * 1000.0 / 2.0 {
            self.busy_at = now;
        }
        if std::mem::take(&mut self.penalty) {
            // провайдер наказал путь: его запас исчерпан — наш тоже
            self.tokens.iter_mut().for_each(|t| *t = 0.0);
            self.cool_until = now + self.cfg.penalty_cooldown_sec.max(0) as u64 * 1000;
            crate::log_info!("upload shaper: ISP penalty detected, no bursts for {}s", self.cfg.penalty_cooldown_sec);
        }
        let mut stage = self.step(sent, dt, self.stage);
        if now < self.cool_until {
            self.tokens.iter_mut().for_each(|t| *t = 0.0);
            stage = stage.max(self.caps.len());
        }
        self.stage = stage;
        let rate = if self.off { self.top_kbit } else { self.rates[stage] };
        // и без изменений раз в 5 с: дерево могли пересоздать
        let mut apply_err = String::new();
        if force || rate != self.applied || now - self.applied_at > 5000 {
            match self.apply(&dev, rate) {
                Err(e) => {
                    if !self.err_logged {
                        crate::log_err!("upload shaper: {}", e);
                        self.err_logged = true;
                    }
                    apply_err = e;
                }
                Ok(()) => {
                    if rate != self.applied {
                        crate::log_info!("upload shaper: stage {}, {} kbit (debt {:.1} MB, buckets MB {})", stage + 1, rate, self.debt / MB, list_text(&mb_list(&self.tokens)));
                    }
                    self.applied = rate;
                    self.applied_at = now;
                    self.err_logged = false;
                }
            }
        }
        let cool = if now < self.cool_until { ((self.cool_until - now) / 1000) as i64 } else { 0 };
        self.st = Status {
            device: dev,
            rate_kbit: rate,
            stage,
            debt_mb: r2(self.debt / MB),
            cooldown_sec: cool,
            off: self.off,
            sustained_kbit: self.cfg.sustained_kbit,
            tx_mbps: r2(sent * 8.0 / dt / 1e6),
            bucket_mb: mb_list(&self.tokens),
            cap_mb: mb_list(&self.caps),
            error: apply_err,
        };
    }

    fn apply(&self, dev: &str, kbit: i64) -> Result<(), String> {
        if crate::util::readonly() {
            return Ok(());
        }
        let cls = &self.cfg.class_id;
        let parent = &cls[..cls.find(':').map_or(0, |i| i + 1)];
        let r = format!("{kbit}kbit");
        // burst как у sqm (1 мс на скорости класса)
        let bs = format!("{}b", (kbit * 1000 / 8 / 1000).max(1600));
        let o = std::process::Command::new("tc").args(["class", "change", "dev", dev, "parent", parent, "classid", cls, "htb", "rate", &r, "ceil", &r, "burst", &bs, "cburst", &bs]).output().map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err(format!("tc class change {cls} {r}: exit status {}: {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stderr).trim()));
        }
        Ok(())
    }

    pub fn status_json(&self, j: &mut J) {
        let s = &self.st;
        let g = crate::config::go_float;
        j.obj().key("device").str(&s.device).key("rate_kbit").int(s.rate_kbit).key("stage").int(s.stage as i64).key("debt_mb").raw(&g(s.debt_mb));
        if s.cooldown_sec > 0 {
            j.key("cooldown_sec").int(s.cooldown_sec);
        }
        if s.off {
            j.key("off").bool(true);
        }
        j.key("sustained_kbit").int(s.sustained_kbit).key("tx_mbps").raw(&g(s.tx_mbps));
        for (k, l) in [("bucket_mb", &s.bucket_mb), ("cap_mb", &s.cap_mb)] {
            j.key(k);
            if l.is_empty() {
                j.raw("[]");
            } else {
                j.arr();
                for x in l.iter() {
                    j.raw(&g(*x));
                }
                j.end_arr();
            }
        }
        if !s.error.is_empty() {
            j.key("error").str(&s.error);
        }
        j.end_obj();
    }
}

fn list_text(v: &[f64]) -> String {
    format!("[{}]", v.iter().map(|x| crate::config::go_float(*x)).collect::<Vec<_>>().join(" "))
}

fn stages_text(v: &[UploadStage]) -> String {
    format!("[{}]", v.iter().map(|s| format!("{{{} {}}}", s.kbit, crate::config::go_float(s.mb))).collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> UploadShaperConfig {
        let mut c = crate::config::defaults().upload_shaper;
        c.sustained_kbit = 24000;
        c.stages = vec![UploadStage { kbit: 90000, mb: 200.0 }];
        c.refill_factor = 2.0;
        c.resume_percent = 50.0;
        c.payback_kbit = 0;
        c
    }

    #[test]
    fn stages_and_refill() {
        let mut s = UploadShaper::new(cfg());
        // после старта запас пуст — сразу устойчивая
        assert_eq!(s.step(90e6 / 8.0, 1.0, 0), 1); // после старта запас пуст — сразу устойчивая
        // простой копит запас медленнее (refill_factor 2): 3000000 Б/с / 2 за с
        for _ in 0..200 {
            s.step(0.0, 1.0, 1);
        }
        let cap = s.caps[0];
        assert!((s.tokens[0] - cap).abs() < 1.0, "{} {}", s.tokens[0], cap);
        // ёмкость ступени ≈ 200 МБ·(90−24)/90, на полную ступень — всё ещё 0
        assert!((cap / MB - 146.67).abs() < 0.1, "{}", cap / MB);
        // запас вернулся выше resume_percent — ступень 0
        assert_eq!(s.step(0.0, 1.0, 1), 0);
        // гоним 90 Мбит/с — запас (146,7 МБ) тратится по 66 Мбит/с: ~18 с
        let mut st = 0;
        let mut t = 0;
        while st == 0 && t < 100 {
            st = s.step(90e6 / 8.0, 1.0, st);
            t += 1;
        }
        assert!(st == 1 && (17..=19).contains(&t), "{st} {t}");
        assert!(valid_stages(&cfg()).is_ok());
        let mut bad = cfg();
        bad.stages[0].kbit = 1000;
        assert!(valid_stages(&bad).is_err());
    }
}
