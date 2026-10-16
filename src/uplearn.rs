//! Учитель отдачи (перенос uplearn.go): по доводам детектора наказаний
//! запоминает, на какой скорости отдача к сети проходит, а на какой
//! наказывается; observe — только журнал «ограничил бы до …».
//! Ключ — «AS<n> <proto>» (владелец через общий IpOwner), пока AS не
//! выяснилась дольше 2 мин — префикс /24 (/48); наказание сразу нескольких
//! адресов — «global» (лимит абонента).

use crate::config::FlowWatchConfig;
use crate::dnsguard::{time_json, time_parse, vstr};
use crate::ipowner::IpOwner;
use crate::json::J;
use crate::value::{parse_json, Value};
use std::collections::HashMap;
use std::net::IpAddr;

const BACKOFF: f64 = 0.8;
const RESOLVE_MAX: u64 = 2 * 60_000;
const SAVE_EVERY: u64 = 10 * 60_000;
const FORGET_MS: i64 = 90 * 24 * 3600 * 1000;
const MAX_ENTRIES: usize = 2000;
const MAX_PENDING: usize = 500;

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub key: String,
    pub brand: String,
    pub good_mbps: f64,
    pub bad_mbps: f64,
    pub goods: i64,
    pub bads: i64,
    /// мс unix
    pub last_bad: i64,
    pub seen: i64,
}

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

impl Entry {
    /// До скольких ограничить (0 — не нужно).
    pub fn safe(&self, min_mbps: f64) -> f64 {
        if self.bads == 0 || self.bad_mbps <= 0.0 {
            return 0.0;
        }
        let mut s = self.bad_mbps * BACKOFF;
        if self.good_mbps > s && self.good_mbps < self.bad_mbps {
            s = self.good_mbps;
        }
        r1(s.max(min_mbps))
    }

    fn json(&self, j: &mut J, safe: Option<f64>) {
        let g = crate::config::go_float;
        j.obj().key("key").str(&self.key);
        if !self.brand.is_empty() {
            j.key("brand").str(&self.brand);
        }
        j.key("good_mbps").raw(&g(self.good_mbps)).key("bad_mbps").raw(&g(self.bad_mbps)).key("goods").int(self.goods).key("bads").int(self.bads);
        if self.last_bad != 0 {
            j.key("last_bad").str(&time_json(self.last_bad));
        }
        j.key("seen").str(&time_json(self.seen));
        if let Some(s) = safe.filter(|s| *s != 0.0) {
            j.key("safe_mbps").raw(&g(s));
        }
        j.end_obj();
    }
}

struct Evidence {
    at: u64,
    wall: i64,
    ip: IpAddr,
    proto: String,
    mbps: f64,
    bad: bool,
    global: bool,
    total: f64,
    others: usize,
}

pub struct UploadLearner {
    pub mode: String,
    min_mbps: f64,
    file: String,
    entries: HashMap<String, Entry>,
    pending: Vec<Evidence>,
    dirty: bool,
    saved_at: u64,
}

/// tcp с известным портом (<1024) — «tcp/443»; прочее — «tcp»/«udp».
pub fn proto_key(proto: &str, remote: &str) -> String {
    if proto == "tcp" {
        if let Ok(sa) = remote.parse::<std::net::SocketAddr>() {
            if sa.port() > 0 && sa.port() < 1024 {
                return format!("tcp/{}", sa.port());
            }
        }
    }
    proto.to_string()
}

/// Сеть адреса, пока AS не известна: /24 или /48.
pub fn prefix(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            format!("{}/48", std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
    }
}

fn wall_ms() -> i64 {
    let (s, n) = crate::util::now_wall();
    s * 1000 + (n / 1_000_000) as i64
}

impl UploadLearner {
    pub fn new(c: &FlowWatchConfig) -> UploadLearner {
        let mut l = UploadLearner { mode: String::new(), min_mbps: 0.0, file: String::new(), entries: HashMap::new(), pending: Vec::new(), dirty: false, saved_at: 0 };
        l.set_config(c);
        l.load();
        l
    }

    pub fn set_config(&mut self, c: &FlowWatchConfig) {
        self.mode = c.learn_mode.clone();
        self.min_mbps = c.learn_min_kbit as f64 / 1000.0;
        self.file = c.learn_file.clone();
    }

    pub fn good(&mut self, now: u64, ip: IpAddr, proto: &str, remote: &str, mbps: f64) {
        self.add(Evidence { at: now, wall: wall_ms(), ip, proto: proto_key(proto, remote), mbps, bad: false, global: false, total: 0.0, others: 0 });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bad(&mut self, now: u64, ip: IpAddr, proto: &str, remote: &str, mbps: f64, scope: &str, total: f64, others: usize) {
        self.add(Evidence { at: now, wall: wall_ms(), ip, proto: proto_key(proto, remote), mbps, bad: true, global: scope == "global", total, others });
    }

    fn add(&mut self, ev: Evidence) {
        if self.mode == "off" || ev.mbps <= 0.0 {
            return;
        }
        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(ev);
    }

    /// Разобрать доводы (AS выяснилась или ждать больше нельзя), записать файл.
    pub fn tick(&mut self, now: u64, owner: &mut IpOwner) -> Vec<String> {
        let mut msgs = Vec::new();
        let mut keep = Vec::new();
        for ev in std::mem::take(&mut self.pending) {
            let (mut key, mut brand) = ("global".to_string(), String::new());
            if !(ev.bad && ev.global) {
                match owner.get(&ev.ip, now).filter(|i| !i.asn.is_empty()) {
                    Some(i) => {
                        key = format!("AS{} {}", i.asn, ev.proto);
                        brand = i.brand.clone();
                    }
                    None if now - ev.at < RESOLVE_MAX => {
                        owner.want(ev.ip, now);
                        keep.push(ev);
                        continue;
                    }
                    None => key = format!("{} {}", prefix(&ev.ip), ev.proto),
                }
            }
            let e = self.entries.entry(key.clone()).or_insert_with(|| Entry { key, ..Default::default() });
            if !brand.is_empty() {
                e.brand = brand;
            }
            e.seen = ev.wall;
            self.dirty = true;
            if !ev.bad {
                e.goods += 1;
                if ev.mbps > e.good_mbps {
                    e.good_mbps = r1(ev.mbps);
                }
                continue;
            }
            let rate = if ev.global { ev.total } else { ev.mbps };
            e.bads += 1;
            e.last_bad = ev.wall;
            if e.bad_mbps == 0.0 || rate < e.bad_mbps {
                e.bad_mbps = r1(rate);
            }
            let e = e.clone();
            msgs.push(self.describe(&e, &ev, rate));
        }
        self.pending = keep;
        if self.dirty && now - self.saved_at >= SAVE_EVERY {
            self.save(now);
        }
        msgs
    }

    fn describe(&self, e: &Entry, ev: &Evidence, rate: f64) -> String {
        let safe = e.safe(self.min_mbps);
        if ev.global {
            return format!("учитель отдачи: общее наказание — встали отдачи на {} адреса при общей отдаче {:.1} Мбит/с (раз: {}); подсказка шейперу: постоянная скорость не выше {:.1} Мбит/с", ev.others, rate, e.bads, safe);
        }
        let name = if e.brand.is_empty() { e.key.clone() } else { format!("{} ({})", e.brand, e.key) };
        let good = if e.good_mbps > 0.0 { format!("; без наказания бывало до {:.1} Мбит/с", e.good_mbps) } else { String::new() };
        format!("учитель отдачи: {name} — наказание на {rate:.1} Мбит/с (раз: {}{good}); в активном режиме ограничил бы до {safe:.1} Мбит/с", e.bads)
    }

    fn save(&mut self, now: u64) {
        let w = wall_ms();
        self.entries.retain(|_, e| w - e.seen <= FORGET_MS);
        let mut list: Vec<&Entry> = self.entries.values().collect();
        list.sort_by(|a, b| b.seen.cmp(&a.seen));
        list.truncate(MAX_ENTRIES);
        let keep: Vec<String> = list.iter().map(|e| e.key.clone()).collect();
        let mut j = J::new();
        j.arr();
        for e in &list {
            e.json(&mut j, None);
        }
        j.end_arr();
        self.entries.retain(|k, _| keep.contains(k));
        self.saved_at = now;
        self.dirty = false;
        if self.file.is_empty() || crate::util::readonly() {
            return;
        }
        if let Err(e) = crate::util::write_atomic(&crate::storage::path(&self.file), j.b.as_bytes(), 0o644) {
            crate::log_err!("upload learner: save {}: {}", self.file, e);
        }
    }

    fn load(&mut self) {
        let Some(Value::List(l)) = std::fs::read_to_string(crate::storage::path(&self.file)).ok().and_then(|t| parse_json(&t).ok()) else { return };
        for v in l {
            let key = vstr(&v, "key");
            if key.trim().is_empty() {
                continue;
            }
            let n = |k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
            let e = Entry { key: key.clone(), brand: vstr(&v, "brand"), good_mbps: n("good_mbps"), bad_mbps: n("bad_mbps"), goods: n("goods") as i64, bads: n("bads") as i64, last_bad: time_parse(v.get("last_bad")), seen: time_parse(v.get("seen")) };
            self.entries.insert(key, e);
        }
    }

    /// Выученное: сначала наказанные (чаще и недавно), затем прочие; ≤ 20.
    pub fn status_json(&self, j: &mut J) {
        j.obj().key("mode").str(&self.mode).key("min_mbps").raw(&crate::config::go_float(self.min_mbps)).key("count").int(self.entries.len() as i64);
        let mut l: Vec<&Entry> = self.entries.values().collect();
        l.sort_by(|a, b| b.bads.cmp(&a.bads).then(b.seen.cmp(&a.seen)));
        l.truncate(20);
        if !l.is_empty() {
            j.key("entries").arr();
            for e in l {
                e.json(j, Some(e.safe(self.min_mbps)));
            }
            j.end_arr();
        }
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_safe() {
        assert_eq!(proto_key("tcp", "198.51.100.1:443"), "tcp/443");
        assert_eq!(proto_key("tcp", "198.51.100.1:51413"), "tcp");
        assert_eq!(proto_key("udp", "198.51.100.1:443"), "udp");
        assert_eq!(prefix(&"198.51.100.77".parse().unwrap()), "198.51.100.0/24");
        let e = Entry { bad_mbps: 50.0, bads: 1, good_mbps: 45.0, ..Default::default() };
        assert_eq!(e.safe(3.0), 45.0);
        let e = Entry { bad_mbps: 50.0, bads: 1, good_mbps: 10.0, ..Default::default() };
        assert_eq!(e.safe(3.0), 40.0);
    }

    #[test]
    fn evidence_without_owner_goes_to_prefix() {
        let mut c = crate::config::defaults().flow_watch;
        c.learn_mode = "observe".into();
        c.learn_file = String::new();
        let mut l = UploadLearner::new(&c);
        let mut own = IpOwner::new(1 << 40);
        l.bad(1000, "198.51.100.7".parse().unwrap(), "tcp", "198.51.100.7:443", 60.0, "dest", 60.0, 1);
        assert!(l.tick(2000, &mut own).is_empty()); // ждёт AS
        let m = l.tick(1000 + RESOLVE_MAX + 1, &mut own);
        assert!(m.len() == 1 && m[0].contains("198.51.100.0/24 tcp/443 — наказание на 60.0 Мбит/с"), "{m:?}");
    }
}
