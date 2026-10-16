//! Платный трафик (перенос billing.go): всё, кроме бесплатных сетей
//! провайдера (TAS-IX и т.п., имена tasix_*). Список — tasix_url (раз в
//! refresh_hours) или file (загружен со страницы) → наборы tasix_v4/v6
//! таблицы cgmon_acct; свои цепочки bill_* с именованными счётчиками, читаем
//! через netlink; суммы за сутки и расчётный месяц в state_file.
//! Память: сам список в памяти не держим — читаем файл при заливке в nft.

use crate::acct::nft_script;
use crate::config::BillingConfig;
use crate::json::J;
use crate::nfnl;
use crate::util;
use crate::value::{parse_json, Value};
use std::collections::HashMap;

pub const COUNTERS: [&str; 6] = ["bill4_dl", "bill4_ul", "bill6_dl", "bill6_ul", "tasix_dl", "tasix_ul"];
pub const FILE_SRC: &str = "file";
pub const MAX_NETS: usize = 50000;
const TMP_STATE: &str = "/tmp/cgmon/billing.json";

type Totals = HashMap<String, u64>;

#[derive(Default, Clone)]
struct State {
    day: String,
    today: Totals,
    month_start: String,
    month: Totals,
    days: Vec<(String, Totals)>,
    last: Totals,
    warned: String,
}

pub struct Billing {
    pub cfg: BillingConfig,
    pub on: bool,
    applied: bool,
    st: State,
    last: Totals,
    rates: HashMap<String, f64>,
    last_at: u64,
    saved_tmp: i64,
    saved_disk: i64,
    nets: usize,
    tasix_at: i64,
    pub tasix_err: String,
    fetch: Option<(std::process::Child, String, String)>, // процесс, источник, временный файл
    next_fetch: i64,
    dirty: bool,
    nlbuf: Vec<u8>,
}

/// Сети из текста: CIDR или адрес на строку (текст после сети — комментарий),
/// IPv4 и IPv6, без /0 и дублей, по порядку строк.
pub fn parse_list(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tok = line.split_whitespace().next().unwrap_or("");
        let net = if let Some((ip, bits)) = crate::netx::parse_cidr(tok) {
            crate::netx::IpNet::new(ip, bits)
        } else if let Some(ip) = crate::netx::parse_ip(tok) {
            let ip = crate::netx::to4(&ip).map(std::net::IpAddr::from).unwrap_or(ip);
            crate::netx::IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })
        } else {
            continue;
        };
        if net.bits == 0 {
            continue; // весь интернет бесплатным не бывает
        }
        let s = net.to_string();
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out.sort();
    out
}

/// Список не битый: есть сети, не больше предела, не меньше половины прежнего.
pub fn list_ok(nets: usize, old: usize) -> Result<(), String> {
    if nets == 0 {
        Err("no networks in the list".into())
    } else if nets > MAX_NETS {
        Err(format!("too many networks: {nets}"))
    } else if nets * 2 < old {
        Err(format!("only {nets} networks in the list (was {old})"))
    } else {
        Ok(())
    }
}

fn totals_json(j: &mut J, t: &Totals) {
    j.obj();
    let mut keys: Vec<&String> = t.keys().collect();
    keys.sort();
    for k in keys {
        j.key(k).uint(t[k]);
    }
    j.end_obj();
}

fn totals(v: Option<&Value>) -> Totals {
    let mut m = Totals::new();
    if let Some(Value::Map(l)) = v {
        for (k, x) in l {
            if let Value::Num(n) = x {
                if let Ok(u) = n.parse() {
                    m.insert(k.clone(), u);
                }
            }
        }
    }
    m
}

fn mtime(p: &str) -> i64 {
    std::fs::metadata(p).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64)
}

impl Billing {
    pub fn new(cfg: &BillingConfig) -> Billing {
        let mut b = Billing { cfg: cfg.clone(), on: false, applied: false, st: State::default(), last: Totals::new(), rates: HashMap::new(), last_at: 0, saved_tmp: 0, saved_disk: 0, nets: 0, tasix_at: 0, tasix_err: String::new(), fetch: None, next_fetch: 0, dirty: false, nlbuf: Vec::new() };
        b.load();
        // список с диска: только число сетей и время
        if let Ok(t) = std::fs::read_to_string(&b.cfg.tasix_file) {
            let n = parse_list(&t).len();
            if n > 0 && n <= MAX_NETS {
                b.nets = n;
                b.dirty = true;
                b.tasix_at = mtime(&b.cfg.tasix_file);
                b.next_fetch = b.tasix_at + b.cfg.refresh_hours * 3600;
            }
        }
        b
    }

    fn load(&mut self) {
        let mut best: Option<(i64, Value)> = None;
        for p in [TMP_STATE.to_string(), crate::storage::path(&self.cfg.state_file)] {
            let Ok(t) = std::fs::read_to_string(&p) else { continue };
            let Ok(v @ Value::Map(_)) = parse_json(&t) else { continue };
            let m = mtime(&p);
            if best.as_ref().map_or(true, |(bm, _)| m > *bm) {
                best = Some((m, v));
            }
        }
        if let Some((_, v)) = best {
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            self.st.day = s("day");
            self.st.month_start = s("month_start");
            self.st.warned = s("warned");
            self.st.today = totals(v.get("today"));
            self.st.month = totals(v.get("month"));
            self.st.last = totals(v.get("last"));
            if let Some(Value::List(l)) = v.get("days") {
                for d in l {
                    self.st.days.push((d.get("date").and_then(|x| x.as_str()).unwrap_or("").into(), totals(d.get("bytes"))));
                }
            }
        }
        // last годится, только если счётчики ядра живы (проверит tick)
        self.last = self.st.last.clone();
    }

    fn state_json(&self) -> String {
        let mut j = J::new();
        j.obj().key("day").str(&self.st.day).key("today");
        totals_json(&mut j, &self.st.today);
        j.key("month_start").str(&self.st.month_start).key("month");
        totals_json(&mut j, &self.st.month);
        j.key("days").arr();
        for (d, t) in &self.st.days {
            j.obj().key("date").str(d).key("bytes");
            totals_json(&mut j, t);
            j.end_obj();
        }
        j.end_arr().key("last");
        totals_json(&mut j, &self.last);
        if !self.st.warned.is_empty() {
            j.key("warned").str(&self.st.warned);
        }
        j.end_obj();
        j.b
    }

    fn save(&mut self, now: i64, disk: bool) {
        if util::readonly() {
            return;
        }
        let data = self.state_json();
        let _ = util::write_atomic(TMP_STATE, data.as_bytes(), 0o644);
        if disk {
            let _ = util::write_atomic(&crate::storage::path(&self.cfg.state_file), data.as_bytes(), 0o644);
            self.saved_disk = now;
        }
        self.saved_tmp = now;
    }

    /// Начало расчётного месяца, в который попадает now (ГГГГ-ММ-ДД).
    pub fn month_start(day: i64, t: &util::Tm) -> String {
        let (mut y, mut m) = (t.year, t.mon);
        if (t.day as i64) < day {
            if m == 1 {
                y -= 1;
                m = 12;
            } else {
                m -= 1;
            }
        }
        format!("{y:04}-{m:02}-{day:02}")
    }

    /// Список со страницы: проверить, записать в tasix_file и включить.
    pub fn upload(&mut self, text: &str, now: i64) -> Result<usize, String> {
        let nets = parse_list(text);
        list_ok(nets.len(), 0)?;
        let data = format!("# cgmon: бесплатные сети, загружено со страницы\n{}\n", nets.join("\n"));
        let tmp = format!("{}.up", self.cfg.tasix_file);
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        if let Err(e) = std::fs::rename(&tmp, &self.cfg.tasix_file) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        self.cfg.tasix_url = FILE_SRC.into();
        self.nets = nets.len();
        self.tasix_at = now;
        self.tasix_err.clear();
        self.dirty = true;
        crate::log_info!("billing: free networks uploaded: {}", nets.len());
        Ok(nets.len())
    }

    fn start_fetch(&mut self) {
        let src = self.cfg.tasix_url.clone();
        let tmp = format!("{}.dl", self.cfg.tasix_file);
        let cands: [(&str, [&str; 4]); 3] = [("uclient-fetch", ["-q", "-T", "30", "-O"]), ("wget", ["-q", "-T", "30", "-O"]), ("curl", ["-s", "-m", "30", "-o"])];
        for (bin, args) in cands {
            if !util::have_bin(bin) {
                continue;
            }
            let spawned = std::process::Command::new(bin).args(args).arg(&tmp).arg(&src).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
            if let Ok(ch) = spawned {
                self.fetch = Some((ch, src, tmp));
                return;
            }
        }
        self.tasix_err = "нет uclient-fetch, wget или curl".into();
        self.next_fetch = util::now_wall().0 + 3600;
    }

    fn poll_fetch(&mut self, now: i64) {
        let Some((ch, _, _)) = self.fetch.as_mut() else { return };
        let ok = match ch.try_wait() {
            Ok(Some(st)) => st.success(),
            Ok(None) => return,
            Err(_) => false,
        };
        let (_, src, tmp) = self.fetch.take().unwrap();
        if self.cfg.tasix_url != src {
            let _ = std::fs::remove_file(&tmp); // пока качали, сменили источник
            return;
        }
        let res = if !ok {
            Err("download failed".to_string())
        } else {
            std::fs::read_to_string(&tmp).map_err(|e| e.to_string()).and_then(|t| {
                let n = parse_list(&t).len();
                list_ok(n, self.nets).map(|_| n)
            })
        };
        let res = res.and_then(|n| std::fs::rename(&tmp, &self.cfg.tasix_file).map(|_| n).map_err(|e| e.to_string()));
        let _ = std::fs::remove_file(&tmp);
        match res {
            Ok(n) => {
                self.nets = n;
                self.tasix_at = now;
                self.tasix_err.clear();
                self.dirty = true;
                self.next_fetch = now + self.cfg.refresh_hours * 3600;
                crate::log_info!("billing: free networks list updated: {} networks", n);
            }
            Err(e) => {
                self.tasix_err = e.clone();
                self.next_fetch = now + 3600;
                crate::log_err!("billing: free networks list {}: {}", src, e);
            }
        }
    }

    fn apply_rules(&self) -> Result<(), String> {
        let mut s = String::from("add set inet cgmon_acct tasix_v4 { type ipv4_addr; flags interval; auto-merge; }\nadd set inet cgmon_acct tasix_v6 { type ipv6_addr; flags interval; auto-merge; }\n");
        for c in COUNTERS {
            s += &format!("add counter inet cgmon_acct {c}\n");
        }
        s += "add chain inet cgmon_acct bill_fwd { type filter hook forward priority 1; policy accept; }
add chain inet cgmon_acct bill_in { type filter hook input priority 1; policy accept; }
add chain inet cgmon_acct bill_out { type filter hook output priority 1; policy accept; }
flush chain inet cgmon_acct bill_fwd
flush chain inet cgmon_acct bill_in
flush chain inet cgmon_acct bill_out
add rule inet cgmon_acct bill_in iifname \"lo\" accept
add rule inet cgmon_acct bill_out oifname \"lo\" accept
";
        // транзит через туннели — не трафик этого WAN
        for t in ["zt*", "tailscale*", "wg*"] {
            s += &format!("add rule inet cgmon_acct bill_fwd iifname \"{t}\" accept\nadd rule inet cgmon_acct bill_fwd oifname \"{t}\" accept\n");
        }
        let dl = ["ip saddr != @nw_v4 ip saddr @tasix_v4 counter name tasix_dl", "ip saddr != @nw_v4 ip saddr != @tasix_v4 counter name bill4_dl", "ip6 saddr != @nw_v6 ip6 saddr @tasix_v6 counter name tasix_dl", "ip6 saddr != @nw_v6 ip6 saddr != @tasix_v6 counter name bill6_dl"];
        let ul = ["ip daddr != @nw_v4 ip daddr @tasix_v4 counter name tasix_ul", "ip daddr != @nw_v4 ip daddr != @tasix_v4 counter name bill4_ul", "ip6 daddr != @nw_v6 ip6 daddr @tasix_v6 counter name tasix_ul", "ip6 daddr != @nw_v6 ip6 daddr != @tasix_v6 counter name bill6_ul"];
        for r in dl.iter().chain(ul.iter()) {
            s += &format!("add rule inet cgmon_acct bill_fwd {r}\n");
        }
        for r in dl {
            s += &format!("add rule inet cgmon_acct bill_in {r}\n");
        }
        for r in ul {
            s += &format!("add rule inet cgmon_acct bill_out {r}\n");
        }
        nft_script(&s)
    }

    fn apply_set(&self) -> Result<(), String> {
        let text = std::fs::read_to_string(&self.cfg.tasix_file).map_err(|e| e.to_string())?;
        let nets = parse_list(&text);
        let (v4, v6): (Vec<&String>, Vec<&String>) = nets.iter().partition(|n| !n.contains(':'));
        let mut s = String::new();
        for (set, l) in [("tasix_v4", v4), ("tasix_v6", v6)] {
            s += &format!("flush set inet cgmon_acct {set}\n");
            for ch in l.chunks(200) {
                s += &format!("add element inet cgmon_acct {set} {{ {} }}\n", ch.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(", "));
            }
        }
        nft_script(&s)
    }

    pub fn set_config(&mut self, c: &BillingConfig) {
        if c.tasix_url != self.cfg.tasix_url {
            self.next_fetch = 0;
        }
        self.cfg.tasix_url = c.tasix_url.clone();
        self.cfg.refresh_hours = c.refresh_hours;
        self.cfg.month_start_day = c.month_start_day;
    }

    pub fn set_limits(&mut self, daily: f64, monthly: f64) {
        self.cfg.daily_limit_mb = daily;
        self.cfg.monthly_limit_mb = monthly;
    }

    /// Такт (каждую секунду, после учёта). Возвращает сообщение о превышении лимита.
    pub fn tick(&mut self, now_ms: u64, now: i64) -> Option<String> {
        if !self.on {
            if self.applied {
                let _ = nft_script("delete chain inet cgmon_acct bill_fwd\ndelete chain inet cgmon_acct bill_in\ndelete chain inet cgmon_acct bill_out\n");
                self.applied = false;
                self.rates.clear();
                crate::log_info!("billing: off");
            }
            return None;
        }
        if !self.applied {
            if let Err(e) = self.apply_rules() {
                crate::log_err!("billing: rules: {}", e);
                return None;
            }
            self.applied = true;
            self.dirty = true;
            crate::log_info!("billing: on");
        }
        if self.dirty && self.nets > 0 {
            if let Err(e) = self.apply_set() {
                crate::log_err!("billing: TAS-IX set: {}", e);
            }
            self.dirty = false;
        }
        self.poll_fetch(now);
        if self.fetch.is_none() && now >= self.next_fetch && self.cfg.tasix_url != FILE_SRC {
            self.start_fetch();
        }
        let mut raw: HashMap<String, u64> = HashMap::new();
        let mut buf = std::mem::take(&mut self.nlbuf);
        let r = nfnl::named_counters("cgmon_acct", &mut buf, |n, b| {
            raw.insert(n.to_string(), b);
        });
        self.nlbuf = buf;
        if r.is_err() || raw.is_empty() {
            self.applied = false; // таблицу пересоздали — правила заново
            return None;
        }
        let tm = util::local(now);
        let day = format!("{:04}-{:02}-{:02}", tm.year, tm.mon, tm.day);
        if self.st.day != day {
            if !self.st.day.is_empty() {
                let prev = (std::mem::take(&mut self.st.day), std::mem::take(&mut self.st.today));
                self.st.days.insert(0, prev);
                self.st.days.truncate(62);
            }
            self.st.day = day;
            self.st.today.clear();
        }
        let ms = Self::month_start(self.cfg.month_start_day, &tm);
        if self.st.month_start != ms {
            self.st.month_start = ms;
            self.st.month.clear();
        }
        let dt = if self.last_at > 0 { (now_ms - self.last_at) as f64 / 1000.0 } else { 0.0 };
        for c in COUNTERS {
            let cur = raw.get(c).copied().unwrap_or(0);
            let prev = self.last.get(c).copied();
            let d = match prev {
                None => 0,
                Some(p) if cur >= p => cur - p,
                Some(_) => cur,
            };
            self.last.insert(c.into(), cur);
            *self.st.today.entry(c.into()).or_insert(0) += d;
            *self.st.month.entry(c.into()).or_insert(0) += d;
            if prev.is_some() && dt > 0.5 && dt < 10.0 {
                let r = self.rates.entry(c.into()).or_insert(0.0);
                *r = *r * 0.5 + d as f64 * 8.0 / dt / 1e6 * 0.5;
            }
        }
        self.last_at = now_ms;
        if now - self.saved_disk >= 600 {
            self.save(now, true);
        } else if now - self.saved_tmp >= 60 {
            self.save(now, false);
        }
        self.limit_msg()
    }

    fn billed(t: &Totals) -> u64 {
        ["bill4_dl", "bill4_ul", "bill6_dl", "bill6_ul"].iter().map(|k| t.get(*k).copied().unwrap_or(0)).sum()
    }

    fn limit_msg(&mut self) -> Option<String> {
        let mb = |v: u64| v as f64 / 1e6;
        let (m, d) = (mb(Self::billed(&self.st.month)), mb(Self::billed(&self.st.today)));
        let l = self.cfg.monthly_limit_mb;
        if l > 0.0 && m >= l && self.st.warned != format!("m{}", self.st.month_start) {
            self.st.warned = format!("m{}", self.st.month_start);
            return Some(format!("billed traffic this month {m:.0} MB >= limit {l:.0} MB"));
        }
        let l = self.cfg.daily_limit_mb;
        if l > 0.0 && d >= l && self.st.warned != format!("d{}", self.st.day) && self.st.warned != format!("m{}", self.st.month_start) {
            self.st.warned = format!("d{}", self.st.day);
            return Some(format!("billed traffic today {d:.0} MB >= limit {l:.0} MB"));
        }
        None
    }

    pub fn flush(&mut self) {
        self.save(util::now_wall().0, true);
    }

    pub fn status_json(&self, j: &mut J) {
        use crate::config::go_float;
        j.obj().key("on").bool(self.on).key("today");
        totals_json(j, &self.st.today);
        j.key("month");
        totals_json(j, &self.st.month);
        j.key("month_start").str(&self.st.month_start).key("rate_mbps").obj();
        let mut keys: Vec<&String> = self.rates.keys().collect();
        keys.sort();
        for k in keys {
            j.key(k).raw(&go_float(crate::clients::round2(self.rates[k])));
        }
        j.end_obj();
        if !self.st.days.is_empty() {
            j.key("days").arr();
            for (d, t) in self.st.days.iter().take(31) {
                j.obj().key("date").str(d).key("bytes");
                totals_json(j, t);
                j.end_obj();
            }
            j.end_arr();
        }
        j.key("tasix_nets").int(self.nets as i64);
        if self.tasix_at > 0 {
            j.key("tasix_at").str(&util::rfc3339(self.tasix_at, 0));
        }
        if !self.tasix_err.is_empty() {
            j.key("tasix_error").str(&self.tasix_err);
        }
        if self.cfg.daily_limit_mb != 0.0 {
            j.key("daily_limit_mb").raw(&go_float(self.cfg.daily_limit_mb));
        }
        if self.cfg.monthly_limit_mb != 0.0 {
            j.key("monthly_limit_mb").raw(&go_float(self.cfg.monthly_limit_mb));
        }
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_free_nets() {
        // TestParseTasix из Go: CIDR, адрес, комментарии, IPv6, /0 — нет
        let l = parse_list("# x\n192.0.2.0/24 TAS-IX\n198.51.100.7\n2a00::/16\n0.0.0.0/0\n192.0.2.0/24\nbad\n2001:db8::1\n");
        assert_eq!(l, vec!["192.0.2.0/24", "198.51.100.7/32", "2001:db8::1/128", "2a00::/16"]);
        assert!(list_ok(0, 0).is_err() && list_ok(10, 30).is_err() && list_ok(20, 30).is_ok() && list_ok(MAX_NETS + 1, 0).is_err());
    }

    #[test]
    fn month_start_day() {
        let t = |y, m, d| util::Tm { year: y, mon: m, day: d, hour: 0, min: 0, sec: 0, wday: 0, off: 0 };
        assert_eq!(Billing::month_start(10, &t(2026, 10, 14)), "2026-10-10");
        assert_eq!(Billing::month_start(10, &t(2026, 10, 3)), "2026-09-10");
        assert_eq!(Billing::month_start(10, &t(2026, 1, 3)), "2025-12-10");
        assert_eq!(Billing::month_start(1, &t(2026, 1, 1)), "2026-01-01");
    }
}
