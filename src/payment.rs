//! Напоминание об оплате интернета (перенос payment.go): срок по числу месяца
//! (monthly; в коротком месяце — последний день) или каждые interval_days от
//! start_date. За remind_days до срока и в сам день, с remind_hour — notice в
//! отчёт центру (тот шлёт каждое один раз), локально — журнал payment.

use crate::config::PaymentConfig;
use crate::json::J;

/// Напоминание: ключ (центр шлёт каждое один раз) и текст.
#[derive(Clone, Debug, PartialEq)]
pub struct Notice {
    pub key: String,
    pub text: String,
}

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub due: String,
    pub days_left: i64,
    pub amount: String,
    pub note: String,
    pub remind: bool,
    pub notices: Vec<Notice>,
}

/// (год, месяц, день) по номеру дня от 1970-01-01 (обратный к days_from_civil).
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days(y: i64, m: u32, d: u32) -> i64 {
    crate::util::days_from_civil(y, m, d)
}

/// День месяца, не дальше последнего.
fn month_day(y: i64, m: u32, day: i64) -> i64 {
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let last = days(ny, nm, 1) - days(y, m, 1);
    days(y, m, 1) + day.min(last).max(1) - 1
}

fn parse_date(s: &str) -> Option<i64> {
    let f: Vec<&str> = s.split('-').collect();
    if f.len() != 3 || f[0].len() != 4 || f[1].len() != 2 || f[2].len() != 2 {
        return None;
    }
    let (y, m, d) = (f[0].parse().ok()?, f[1].parse::<u32>().ok()?, f[2].parse::<u32>().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days(y, m, d))
}

/// Ближайший срок (номер дня), не раньше сегодняшнего.
pub fn due(c: &PaymentConfig, today: i64) -> Option<i64> {
    if c.mode == "interval" {
        let start = parse_date(&c.start_date)?;
        if c.interval_days <= 0 {
            return None;
        }
        if start >= today {
            return Some(start);
        }
        let k = (today - start + c.interval_days - 1) / c.interval_days;
        return Some(start + k * c.interval_days);
    }
    if c.day < 1 {
        return None;
    }
    let (y, m, _) = civil(today);
    let mut d = month_day(y, m, c.day);
    if d < today {
        let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
        d = month_day(ny, nm, c.day);
    }
    Some(d)
}

/// Состояние на местное время unix (None — выключено или срок не задать).
pub fn status(c: &PaymentConfig, unix: i64) -> Option<Status> {
    if !c.enabled {
        return None;
    }
    let t = crate::util::local(unix);
    let today = days(t.year as i64, t.mon as u32, t.day as u32);
    let d = due(c, today)?;
    let (y, m, dd) = civil(d);
    let left = d - today;
    let mut st = Status { due: format!("{y:04}-{m:02}-{dd:02}"), days_left: left, amount: c.amount.clone(), note: c.note.clone(), remind: left <= c.remind_days, notices: Vec::new() };
    if !st.remind || (t.hour as i64) < c.remind_hour {
        return Some(st);
    }
    let mut extra = String::new();
    if !c.amount.is_empty() {
        extra.push_str(&format!(", сумма: {}", c.amount));
    }
    if !c.note.is_empty() {
        extra.push_str(&format!(" ({})", c.note));
    }
    st.notices.push(if left == 0 {
        Notice { key: format!("pay:{}:due", st.due), text: format!("💳 Сегодня день оплаты интернета{extra}") }
    } else {
        Notice { key: format!("pay:{}:before", st.due), text: format!("💳 Оплата интернета через {left} дн. — до {dd:02}.{m:02}.{y:04}{extra}") }
    });
    Some(st)
}

impl Status {
    pub fn json(&self, j: &mut J) {
        j.obj().key("due").str(&self.due).key("days_left").int(self.days_left);
        if !self.amount.is_empty() {
            j.key("amount").str(&self.amount);
        }
        if !self.note.is_empty() {
            j.key("note").str(&self.note);
        }
        if self.remind {
            j.key("remind").bool(true);
        }
        if !self.notices.is_empty() {
            j.key("notices").arr();
            for n in &self.notices {
                j.obj().key("key").str(&n.key).key("text").str(&n.text).end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
    }
}

/// Какие напоминания уже в журнале (payment.state_file).
#[derive(Default)]
pub struct Journaled {
    done: Option<Vec<String>>,
}

impl Journaled {
    /// Новые напоминания (их — в журнал); ключи сохраняются.
    pub fn fresh(&mut self, st: &Status, file: &str, year: i64) -> Vec<Notice> {
        if st.notices.is_empty() {
            return Vec::new();
        }
        let done = self.done.get_or_insert_with(|| {
            std::fs::read_to_string(crate::storage::path(file)).ok().and_then(|t| crate::value::parse_json(&t).ok()).map(|v| crate::dnsguard::str_list(Some(&v))).unwrap_or_default()
        });
        let mut out = Vec::new();
        for n in &st.notices {
            if done.contains(&n.key) {
                continue;
            }
            done.push(n.key.clone());
            out.push(n.clone());
        }
        if !out.is_empty() {
            let y = year.to_string();
            let keep: Vec<&String> = done.iter().filter(|k| done.len() < 50 || k.contains(&y)).collect();
            let mut j = J::new();
            j.arr();
            for k in keep {
                j.str(k);
            }
            j.end_arr();
            if !file.is_empty() && !crate::util::readonly() {
                let _ = crate::util::write_atomic(&crate::storage::path(file), j.b.as_bytes(), 0o600);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_dates() {
        let mut c = crate::config::defaults().payment;
        c.enabled = true;
        c.mode = "monthly".into();
        c.day = 31;
        assert_eq!(civil(days(2026, 2, 28)), (2026, 2, 28));
        // в феврале — последний день
        assert_eq!(due(&c, days(2026, 2, 10)), Some(days(2026, 2, 28)));
        // прошёл — следующий месяц
        c.day = 5;
        assert_eq!(due(&c, days(2026, 12, 6)), Some(days(2027, 1, 5)));
        c.mode = "interval".into();
        c.interval_days = 30;
        c.start_date = "2026-10-01".into();
        assert_eq!(due(&c, days(2026, 10, 14)), Some(days(2026, 10, 31)));
        assert_eq!(due(&c, days(2026, 10, 31)), Some(days(2026, 10, 31)));
    }
}
