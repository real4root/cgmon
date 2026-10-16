//! Учёт трафика (перенос acct.go): ядро считает байты по IP в динамических
//! наборах nft (cdl/cul — клиенты LAN, rdl/rul — сам роутер), читаем через
//! netlink; накопление — по идентичности (MAC «m:<mac>», иначе IP; роутер —
//! одна корзина "router"), снимки раз в минуту за окно и часовые отметки за
//! 26 ч. Чекпоинты — в формате Go (/tmp/cgmon_acct_state.json, ежечасно
//! /etc/cgmon/acct_state.json): переход Go ↔ Rust не теряет историю.
//! Память: ключи снимков — индексы в общей таблице, а не строки.

use crate::json::J;
use crate::netx::IpNet;
use crate::nfnl;
use crate::value::{parse_json, Value};
use std::collections::HashMap;
use std::net::IpAddr;

pub const STATE_FILE: &str = "/tmp/cgmon/acct_state.json";
pub const PERSISTENT_FILE: &str = "/etc/cgmon/acct_state.json";
pub const ROUTER_ID: &str = "router";
const ELEM_TIMEOUT: &str = "1h";
/// last-счётчик адреса забываем позже, чем истекает элемент ядра
const FORGET_IP: i64 = 70 * 60;

/// (имя набора, клиент/роутер, загрузка/отдача, тип)
pub const SETS: &[(&str, bool, bool, &str)] = &[
    ("cdl4", true, true, "ipv4_addr"), ("cul4", true, false, "ipv4_addr"),
    ("cdl6", true, true, "ipv6_addr"), ("cul6", true, false, "ipv6_addr"),
    ("rdl4", false, true, "ipv4_addr"), ("rul4", false, false, "ipv4_addr"),
    ("rdl6", false, true, "ipv6_addr"), ("rul6", false, false, "ipv6_addr"),
];

/// Снимок/отметка: (индекс ключа «c:<id>» / «r:router», загрузка, отдача).
#[derive(Clone, Debug, Default)]
struct Mark {
    at: i64,
    v: Vec<(u32, u64, u64)>,
}

#[derive(Default)]
struct Keys {
    names: Vec<String>,
    idx: HashMap<String, u32>,
}

impl Keys {
    fn get(&mut self, k: &str) -> u32 {
        if let Some(i) = self.idx.get(k) {
            return *i;
        }
        let i = self.names.len() as u32;
        self.names.push(k.to_string());
        self.idx.insert(k.to_string(), i);
        i
    }
    fn find(&self, k: &str) -> Option<u32> {
        self.idx.get(k).copied()
    }
}

#[derive(Default)]
pub struct Acct {
    pub enabled: bool,
    ready: bool,
    pub refresh_ms: u64,
    pub window_s: i64,
    pub mac_of: HashMap<String, String>,
    last_seen_c: HashMap<String, i64>,
    last_dc: HashMap<String, u64>,
    last_uc: HashMap<String, u64>,
    cum_dc: HashMap<String, u64>,
    cum_uc: HashMap<String, u64>,
    id_last_seen: HashMap<String, i64>,
    last_seen_r: HashMap<String, i64>,
    last_dr: HashMap<String, u64>,
    last_ur: HashMap<String, u64>,
    cum_dr: u64,
    /// когда в последний раз прочитаны счётчики ядра (unix мс)
    read_ms: i64,
    /// устройство WAN и его байты в тот же момент (снимок для графика страницы)
    pub wan_dev: String,
    wan_rx: u64,
    wan_tx: u64,
    cum_ur: u64,
    prime_only: bool,
    nets: Option<(Vec<IpNet>, Vec<IpNet>, Vec<IpNet>)>,
    nw_sig: String,
    rate_dr: f64,
    rate_ur: f64,
    prev_dr: u64,
    prev_ur: u64,
    last_rate_t: u64,
    rate_c: HashMap<String, f64>,
    rate_cu: HashMap<String, f64>,
    prev_c: HashMap<String, u64>,
    prev_cu: HashMap<String, u64>,
    last_rate_ct: u64,
    keys: Keys,
    marks: Vec<Mark>,
    snaps: Vec<Mark>,
    last_roll: i64,
    last_tick: u64,
    /// история графика страницы (час по 2 с, сутки по минуте)
    pub chart: crate::chart::Chart,
    last_snap: i64,
    last_prune: i64,
    nlbuf: Vec<u8>,
}

/// Путь к nft (как nftBin в Go).
pub fn nft_bin() -> &'static str {
    for c in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"] {
        if std::path::Path::new(c).exists() {
            return c;
        }
    }
    "nft"
}

/// nft -f - со сценарием; Err — вывод nft.
pub fn nft_script(script: &str) -> Result<(), String> {
    use std::io::Write;
    if crate::util::readonly() {
        return Ok(());
    }
    use std::process::{Command, Stdio};
    let mut ch = Command::new(nft_bin()).args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    if let Some(mut si) = ch.stdin.take() {
        let _ = si.write_all(script.as_bytes());
    }
    let out = ch.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Сети без повторов и без вложенных в более широкую (nft interval не терпит пересечений).
pub fn collapse(input: &[IpNet]) -> Vec<IpNet> {
    let mut l: Vec<IpNet> = input.to_vec();
    l.sort_by_key(|n| n.bits);
    let mut out: Vec<IpNet> = Vec::new();
    for n in l {
        if !out.iter().any(|k| k.is_v4() == n.is_v4() && k.bits <= n.bits && k.contains(&n.ip)) {
            out.push(n);
        }
    }
    out
}

fn ip_key(b: &[u8]) -> String {
    match b.len() {
        4 => IpAddr::from([b[0], b[1], b[2], b[3]]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            IpAddr::from(a).to_string()
        }
        _ => String::new(),
    }
}

fn hour_floor(t: i64) -> i64 {
    t - t.rem_euclid(3600)
}

fn delta(last: &mut HashMap<String, u64>, ip: &str, raw: u64, prime: bool) -> u64 {
    let prev = last.insert(ip.to_string(), raw);
    match prev {
        None => {
            if prime {
                0
            } else {
                raw
            }
        }
        Some(p) if raw >= p => raw - p,
        Some(_) => raw,
    }
}

fn map_u64(v: Option<&Value>) -> HashMap<String, u64> {
    let mut m = HashMap::new();
    if let Some(Value::Map(l)) = v {
        for (k, x) in l {
            if let Value::Num(n) = x {
                if let Ok(u) = n.parse::<u64>() {
                    m.insert(k.clone(), u);
                }
            }
        }
    }
    m
}

impl Acct {
    pub fn new(cfg: &crate::config::Config) -> Acct {
        let mut a = Acct { enabled: cfg.accounting.enabled, refresh_ms: (cfg.accounting.refresh_sec.max(1) as u64) * 1000, window_s: if cfg.accounting.window_sec > 0 { cfg.accounting.window_sec } else { 3600 }, ..Default::default() };
        if a.enabled {
            crate::log_info!("acct: starting session sess_{}", crate::evloop::unix_now());
            if let Ok(t) = std::fs::read_to_string(crate::chart::FILE) {
                a.chart.load(&t);
            }
            a.refresh_macs();
            a.ensure();
            a.ready = true;
        }
        a
    }

    pub fn set_timing(&mut self, refresh_sec: i64, window_sec: i64) {
        if refresh_sec > 0 {
            self.refresh_ms = refresh_sec as u64 * 1000;
        }
        if window_sec > 0 {
            self.window_s = window_sec;
        }
    }

    fn refresh_macs(&mut self) {
        let Ok(o) = std::process::Command::new("ip").args(["-o", "neigh", "show"]).output() else { return };
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            if let Some(i) = f.iter().position(|x| *x == "lladdr") {
                if let Some(mac) = f.get(i + 1) {
                    if *mac != "failed" && *mac != "incomplete" {
                        self.mac_of.insert(f[0].to_string(), mac.to_string());
                    }
                }
            }
        }
    }

    fn identity(&self, ip: &str) -> String {
        match self.mac_of.get(ip) {
            Some(m) if !m.is_empty() => format!("m:{m}"),
            _ => ip.to_string(),
        }
    }

    pub fn mac_of(&self, ip: &str) -> String {
        if !self.enabled {
            return String::new();
        }
        self.mac_of.get(ip).cloned().unwrap_or_default()
    }

    // ---- чекпоинты (формат Go acctCheckpoint) ----

    fn map_json(j: &mut J, m: &HashMap<String, u64>) {
        j.obj();
        for (k, v) in m {
            j.key(k).uint(*v);
        }
        j.end_obj();
    }

    fn marks_json(&self, j: &mut J, l: &[Mark]) {
        j.arr();
        for m in l {
            j.obj().key("at").int(m.at).key("down").obj();
            for (i, d, _) in &m.v {
                j.key(&self.keys.names[*i as usize]).uint(*d);
            }
            j.end_obj().key("up").obj();
            for (i, _, u) in &m.v {
                j.key(&self.keys.names[*i as usize]).uint(*u);
            }
            j.end_obj().end_obj();
        }
        j.end_arr();
    }

    fn checkpoint_json(&self, with_snaps: bool) -> String {
        let mut j = J::new();
        j.obj();
        j.key("cum_dc");
        Self::map_json(&mut j, &self.cum_dc);
        j.key("cum_uc");
        Self::map_json(&mut j, &self.cum_uc);
        j.key("cum_dr").obj().key(ROUTER_ID).uint(self.cum_dr).end_obj();
        j.key("cum_ur").obj().key(ROUTER_ID).uint(self.cum_ur).end_obj();
        j.key("snaps");
        if with_snaps {
            self.marks_json(&mut j, &self.snaps);
        } else {
            j.raw("null");
        }
        j.key("marks");
        self.marks_json(&mut j, &self.marks);
        j.key("macs").obj();
        for (ip, m) in &self.mac_of {
            j.key(ip).str(m);
        }
        j.end_obj();
        for (k, m) in [("last_dc", &self.last_dc), ("last_uc", &self.last_uc), ("last_dr", &self.last_dr), ("last_ur", &self.last_ur)] {
            if !m.is_empty() {
                j.key(k);
                Self::map_json(&mut j, m);
            }
        }
        j.end_obj();
        j.b
    }

    fn save_checkpoint(&self) {
        if crate::util::readonly() {
            return;
        }
        let _ = crate::util::write_atomic(STATE_FILE, self.checkpoint_json(true).as_bytes(), 0o644);
    }

    fn save_persistent(&self) {
        if crate::util::readonly() {
            return;
        }
        let _ = crate::util::write_atomic(&crate::storage::path(PERSISTENT_FILE), self.checkpoint_json(false).as_bytes(), 0o644);
    }

    fn load_checkpoint() -> Option<Value> {
        for p in [STATE_FILE.to_string(), crate::storage::path(PERSISTENT_FILE)] {
            let Ok(t) = std::fs::read_to_string(&p) else { continue };
            if let Ok(v @ Value::Map(_)) = parse_json(&t) {
                if p != STATE_FILE {
                    crate::log_info!("acct: /tmp checkpoint missing (reboot?), loaded persistent {}", p);
                }
                return Some(v);
            }
        }
        None
    }

    fn parse_marks(&mut self, v: Option<&Value>, cutoff: i64) -> Vec<Mark> {
        let mut out = Vec::new();
        let Some(Value::List(l)) = v else { return out };
        for m in l {
            let at = m.get("at").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
            if at < cutoff {
                continue;
            }
            let (d, u) = (map_u64(m.get("down")), map_u64(m.get("up")));
            let mut mk = Mark { at, v: Vec::with_capacity(d.len()) };
            for (k, dv) in &d {
                let i = self.keys.get(k);
                mk.v.push((i, *dv, u.get(k).copied().unwrap_or(0)));
            }
            out.push(mk);
        }
        out
    }

    /// Таблица nft и чекпоинт (как ensure в Go).
    fn ensure(&mut self) {
        let existed = nfnl::set_counters("cgmon_acct", "cdl4", &mut self.nlbuf, |_, _| {}).is_ok();
        crate::log_info!("acct: ensure (counter sets alive={})", existed);
        let mut b = String::from("add table inet cgmon_acct\n");
        for s in ["nw_v4 { type ipv4_addr; flags interval; }", "nw_v6 { type ipv6_addr; flags interval; }", "lan_v4 { type ipv4_addr; flags interval; }", "lan_v6 { type ipv6_addr; flags interval; }"] {
            b += &format!("add set inet cgmon_acct {s}\n");
        }
        for (n, _, _, t) in SETS {
            b += &format!("add set inet cgmon_acct {n} {{ type {t}; size 65535; flags dynamic,timeout; timeout {ELEM_TIMEOUT}; counter; }}\n");
        }
        // роутер: трафик через lo (процессы роутера между собой) не считаем
        b += "add chain inet cgmon_acct acct { type filter hook forward priority 0; policy accept; }
add chain inet cgmon_acct acct_in { type filter hook input priority 0; policy accept; }
add chain inet cgmon_acct acct_out { type filter hook output priority 0; policy accept; }
flush chain inet cgmon_acct acct
flush chain inet cgmon_acct acct_in
flush chain inet cgmon_acct acct_out
add rule inet cgmon_acct acct ip daddr @lan_v4 ip saddr != @nw_v4 update @cdl4 { ip daddr }
add rule inet cgmon_acct acct ip saddr @lan_v4 ip daddr != @nw_v4 update @cul4 { ip saddr }
add rule inet cgmon_acct acct ip6 daddr @lan_v6 ip6 saddr != @nw_v6 update @cdl6 { ip6 daddr }
add rule inet cgmon_acct acct ip6 saddr @lan_v6 ip6 daddr != @nw_v6 update @cul6 { ip6 saddr }
add rule inet cgmon_acct acct_in iifname \"lo\" accept
add rule inet cgmon_acct acct_out oifname \"lo\" accept
add rule inet cgmon_acct acct_in ip saddr != @nw_v4 update @rdl4 { ip daddr }
add rule inet cgmon_acct acct_in ip6 saddr != @nw_v6 update @rdl6 { ip6 daddr }
add rule inet cgmon_acct acct_out ip daddr != @nw_v4 update @rul4 { ip saddr }
add rule inet cgmon_acct acct_out ip6 daddr != @nw_v6 update @rul6 { ip6 saddr }
";
        if let Err(e) = nft_script(&b) {
            crate::log_err!("acct: nft ensure failed: {}", e);
            self.enabled = false;
            return;
        }
        let now = crate::evloop::unix_now();
        let cp = Self::load_checkpoint();
        let mut have_last = false;
        if let Some(cp) = &cp {
            if let Some(Value::Map(m)) = cp.get("macs") {
                for (ip, mac) in m {
                    if let (false, Some(s)) = (self.mac_of.contains_key(ip), mac.as_str()) {
                        self.mac_of.insert(ip.clone(), s.into());
                    }
                }
            }
            self.cum_dc = map_u64(cp.get("cum_dc"));
            self.cum_uc = map_u64(cp.get("cum_uc"));
            self.cum_dr = map_u64(cp.get("cum_dr")).get(ROUTER_ID).copied().unwrap_or(0);
            self.cum_ur = map_u64(cp.get("cum_ur")).get(ROUTER_ID).copied().unwrap_or(0);
            for id in self.cum_dc.keys() {
                self.id_last_seen.insert(id.clone(), now);
            }
            self.snaps = self.parse_marks(cp.get("snaps"), now - self.window_s - 600);
            self.marks = self.parse_marks(cp.get("marks"), now - 26 * 3600);
            // самый старый снимок — тоже часовая отметка (если раньше всех)
            if let Some(o) = self.snaps.first().cloned() {
                if !self.marks.iter().any(|m| m.at <= o.at) {
                    self.marks.push(o);
                }
            }
            self.marks.sort_by_key(|m| m.at);
            if let Some(m) = self.marks.last() {
                self.last_roll = m.at;
            }
            have_last = matches!(cp.get("last_dc"), Some(Value::Map(_)));
        }
        self.last_dc.clear();
        self.last_uc.clear();
        self.last_dr.clear();
        self.last_ur.clear();
        self.prime_only = false;
        if existed && have_last {
            // счётчики ядра шли и без нас: дельта — от значений в чекпоинте
            let cp = cp.as_ref().unwrap();
            self.last_dc = map_u64(cp.get("last_dc"));
            self.last_uc = map_u64(cp.get("last_uc"));
            self.last_dr = map_u64(cp.get("last_dr"));
            self.last_ur = map_u64(cp.get("last_ur"));
            for ip in self.last_dc.keys() {
                self.last_seen_c.insert(ip.clone(), now);
            }
            for ip in self.last_dr.keys() {
                self.last_seen_r.insert(ip.clone(), now);
            }
        } else if existed {
            self.prime_only = true;
        }
        self.nw_sig.clear();
        self.apply_subnets();
        crate::log_info!("acct: ready (restored clients={})", self.last_dc.len());
    }

    /// Сети LAN, туннелей и исключений (наборы nw_* и lan_*).
    pub fn set_subnets(&mut self, lan: &[IpNet], tun: &[IpNet], excl: &[IpNet]) {
        if !self.enabled || !self.ready {
            return;
        }
        self.nets = Some((lan.to_vec(), tun.to_vec(), excl.to_vec()));
        self.apply_subnets();
    }

    fn apply_subnets(&mut self) {
        let Some((lan, tun, excl)) = &self.nets else { return };
        let split = |groups: &[&[IpNet]]| {
            let all: Vec<IpNet> = groups.iter().flat_map(|g| g.iter().copied()).collect();
            let (mut v4, mut v6): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
            for n in collapse(&all) {
                if n.is_v4() {
                    v4.push(n.to_string());
                } else {
                    v6.push(n.to_string());
                }
            }
            v4.sort();
            v6.sort();
            (v4, v6)
        };
        let (mut nw4, mut nw6) = split(&[lan, tun, excl]);
        nw4.extend(["0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"].map(String::from));
        nw6.extend(["::1/128", "fe80::/10", "ff00::/8"].map(String::from));
        let (lan4, lan6) = split(&[lan]);
        let sig = format!("{}|{}|{}|{}", nw4.join(","), nw6.join(","), lan4.join(","), lan6.join(","));
        if sig == self.nw_sig {
            return;
        }
        let mut b = String::new();
        for (set, list) in [("nw_v4", &nw4), ("nw_v6", &nw6), ("lan_v4", &lan4), ("lan_v6", &lan6)] {
            b += &format!("flush set inet cgmon_acct {set}\n");
            for e in list {
                b += &format!("add element inet cgmon_acct {set} {{ {e} }}\n");
            }
        }
        match nft_script(&b) {
            Ok(()) => {
                self.nw_sig = sig;
                crate::log_info!("acct: subnet sets updated: non-WAN v4={} v6={}, LAN v4={} v6={}", nw4.len(), nw6.len(), lan4.len(), lan6.len());
            }
            Err(e) => crate::log_err!("acct: subnet sets: {}", e),
        }
    }

    fn prune(&mut self, now: i64) {
        let cutoff = now - FORGET_IP;
        let old: Vec<String> = self.last_seen_c.iter().filter(|(_, t)| **t < cutoff).map(|(k, _)| k.clone()).collect();
        for ip in &old {
            self.last_seen_c.remove(ip);
            self.last_dc.remove(ip);
            self.last_uc.remove(ip);
            self.rate_c.remove(ip);
            self.rate_cu.remove(ip);
            self.prev_c.remove(ip);
            self.prev_cu.remove(ip);
        }
        let oldr: Vec<String> = self.last_seen_r.iter().filter(|(_, t)| **t < cutoff).map(|(k, _)| k.clone()).collect();
        for ip in oldr {
            self.last_seen_r.remove(&ip);
            self.last_dr.remove(&ip);
            self.last_ur.remove(&ip);
        }
        // идентичность и её MAC-память — после 26 ч тишины
        let gone: Vec<String> = self.id_last_seen.iter().filter(|(_, t)| now - **t > 26 * 3600).map(|(k, _)| k.clone()).collect();
        for id in gone {
            self.cum_dc.remove(&id);
            self.cum_uc.remove(&id);
            self.id_last_seen.remove(&id);
        }
        let ils = &self.id_last_seen;
        let lsc = &self.last_seen_c;
        self.mac_of.retain(|ip, mac| lsc.contains_key(ip) || ils.get(&format!("m:{mac}")).map_or(false, |t| now - t < 26 * 3600));
        // таблица ключей: перестроить по живым снимкам и отметкам
        let mut used = vec![false; self.keys.names.len()];
        for m in self.snaps.iter().chain(&self.marks) {
            for (i, _, _) in &m.v {
                used[*i as usize] = true;
            }
        }
        if used.iter().filter(|u| !**u).count() > 64 {
            let mut nk = Keys::default();
            let names = std::mem::take(&mut self.keys.names);
            for m in self.snaps.iter_mut().chain(self.marks.iter_mut()) {
                for e in m.v.iter_mut() {
                    e.0 = nk.get(&names[e.0 as usize]);
                }
            }
            self.keys = nk;
        }
    }

    fn current_mark(&mut self, at: i64) -> Mark {
        let mut m = Mark { at, v: Vec::with_capacity(self.cum_dc.len() + 1) };
        for (k, d) in &self.cum_dc {
            let i = self.keys.get(&format!("c:{k}"));
            m.v.push((i, *d, self.cum_uc.get(k).copied().unwrap_or(0)));
        }
        for (k, u) in &self.cum_uc {
            if !self.cum_dc.contains_key(k) {
                let i = self.keys.get(&format!("c:{k}"));
                m.v.push((i, 0, *u));
            }
        }
        let r = self.keys.get(&format!("r:{ROUTER_ID}"));
        m.v.push((r, self.cum_dr, self.cum_ur));
        m
    }

    fn roll_hour(&mut self, now: i64) {
        let b = hour_floor(now);
        if self.last_roll != 0 && b <= self.last_roll {
            return;
        }
        self.last_roll = b;
        let m = self.current_mark(b);
        self.marks.push(m);
        self.marks.retain(|m| m.at >= now - 26 * 3600);
        self.save_persistent();
    }

    /// Такт (по refresh_sec): счётчики ядра → накопления, скорости, снимки.
    pub fn tick(&mut self, now_ms: u64, now: i64) {
        if !self.enabled || !self.ready || now_ms.saturating_sub(self.last_tick) < self.refresh_ms {
            return;
        }
        self.last_tick = now_ms;
        let mut cs: Vec<(bool, bool, String, u64)> = Vec::with_capacity(64);
        let mut buf = std::mem::take(&mut self.nlbuf);
        let mut err = None;
        for (name, client, dl, _) in SETS {
            if let Err(e) = nfnl::set_counters("cgmon_acct", name, &mut buf, |k, b| cs.push((*client, *dl, ip_key(k), b))) {
                err = Some(e);
                break;
            }
        }
        self.nlbuf = buf;
        if err.is_none() {
            let w = crate::util::now_wall();
            self.read_ms = w.0 * 1000 + (w.1 / 1_000_000) as i64;
            // WAN — сразу за счётчиками устройств: один момент для всех
            if !self.wan_dev.is_empty() {
                let rd = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{}/statistics/{f}", self.wan_dev)).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
                (self.wan_rx, self.wan_tx) = (rd("rx_bytes"), rd("tx_bytes"));
            }
        }
        if let Some(e) = err {
            if e.raw_os_error() == Some(libc::ENOENT) && crate::util::readonly() {
                // только чтение: своих таблиц нет и не будет — учёт молчит
                crate::log_info!("acct: no counter sets (read-only mode) — accounting off");
                self.ready = false;
            } else if e.raw_os_error() == Some(libc::ENOENT) {
                crate::log_err!("acct: counter sets disappeared (fw4 reload?) — checkpoint + restore");
                self.save_checkpoint();
                self.ensure();
            } else {
                crate::log_debug!("acct: read counters: {}", e);
            }
            return;
        }
        let prime = self.prime_only;
        self.prime_only = false;
        for (client, dl, ip, raw) in cs {
            if client {
                let last = if dl { &mut self.last_dc } else { &mut self.last_uc };
                let seen = last.contains_key(&ip);
                let d = delta(last, &ip, raw, prime);
                if d > 0 || !seen {
                    self.last_seen_c.insert(ip.clone(), now);
                }
                if d > 0 {
                    let id = self.identity(&ip);
                    *(if dl { &mut self.cum_dc } else { &mut self.cum_uc }).entry(id.clone()).or_insert(0) += d;
                    self.id_last_seen.insert(id, now);
                }
            } else {
                let last = if dl { &mut self.last_dr } else { &mut self.last_ur };
                let seen = last.contains_key(&ip);
                let d = delta(last, &ip, raw, prime);
                if d > 0 || !seen {
                    self.last_seen_r.insert(ip.clone(), now);
                }
                if dl {
                    self.cum_dr += d;
                } else {
                    self.cum_ur += d;
                }
            }
        }
        // история графика: тот же момент, что и снимок страницы (устройства за последний час)
        {
            let mut ids: Vec<(&str, (u64, u64))> = Vec::with_capacity(self.id_last_seen.len() + 1);
            for (id, seen) in &self.id_last_seen {
                if now - *seen <= 3600 {
                    ids.push((id.as_str(), (self.cum_dc.get(id).copied().unwrap_or(0), self.cum_uc.get(id).copied().unwrap_or(0))));
                }
            }
            ids.push(("router", (self.cum_dr, self.cum_ur)));
            self.chart.step(self.read_ms, &self.wan_dev, (self.wan_rx, self.wan_tx), &ids);
        }
        // скорости клиентов (по IP), без сглаживания
        if self.last_rate_ct == 0 {
            self.prev_c = self.last_dc.clone();
            self.prev_cu = self.last_uc.clone();
            self.last_rate_ct = now_ms;
        } else {
            let dt = (now_ms - self.last_rate_ct) as f64 / 1000.0;
            if dt > 0.5 {
                for (last, prev, rate) in [(&self.last_dc, &mut self.prev_c, &mut self.rate_c), (&self.last_uc, &mut self.prev_cu, &mut self.rate_cu)] {
                    for (ip, cur) in last {
                        let p = prev.get(ip).copied().unwrap_or(*cur);
                        rate.insert(ip.clone(), if *cur >= p { (*cur - p) as f64 / dt } else { 0.0 });
                        prev.insert(ip.clone(), *cur);
                    }
                }
                self.last_rate_ct = now_ms;
            }
        }
        // скорость роутера — дельта единой корзины
        if self.last_rate_t == 0 {
            self.prev_dr = self.cum_dr;
            self.prev_ur = self.cum_ur;
            self.last_rate_t = now_ms;
        } else {
            let dt = (now_ms - self.last_rate_t) as f64 / 1000.0;
            if dt > 0.5 {
                if self.cum_dr >= self.prev_dr {
                    self.rate_dr = (self.cum_dr - self.prev_dr) as f64 / dt;
                }
                if self.cum_ur >= self.prev_ur {
                    self.rate_ur = (self.cum_ur - self.prev_ur) as f64 / dt;
                }
                self.prev_dr = self.cum_dr;
                self.prev_ur = self.cum_ur;
                self.last_rate_t = now_ms;
            }
        }
        if now - self.last_prune >= 600 {
            self.last_prune = now;
            self.prune(now);
        }
        if now - self.last_snap >= 60 {
            self.last_snap = now;
            self.refresh_macs();
            self.roll_hour(now);
            let m = self.current_mark(now);
            self.snaps.push(m);
            let cutoff = now - self.window_s - 600;
            self.snaps.retain(|s| s.at >= cutoff);
            self.save_checkpoint();
            if now / 60 % 5 == 0 {
                self.chart.save(); // копия истории графика — в /tmp раз в 5 мин
            }
        }
    }

    fn val(m: &Mark, key: Option<u32>) -> Option<(u64, u64)> {
        let k = key?;
        m.v.iter().find(|(i, _, _)| *i == k).map(|(_, d, u)| (*d, *u))
    }

    fn hour_for(&self, key: &str, cur: (u64, u64), now: i64) -> (u64, u64) {
        let k = self.keys.find(key);
        let target = now - self.window_s;
        let mut base = (0, 0);
        let mut found = false;
        if let Some(s) = self.snaps.iter().rev().find(|s| s.at <= target) {
            if let Some(v) = Self::val(s, k) {
                base = v;
                found = true;
            }
        }
        if !found {
            if let Some(v) = self.snaps.first().and_then(|s| Self::val(s, k)) {
                base = v;
            }
        }
        (cur.0 - base.0.min(cur.0), cur.1 - base.1.min(cur.1))
    }

    fn day_for(&self, key: &str, cur: (u64, u64), now: i64) -> (u64, u64) {
        let k = self.keys.find(key);
        let target = hour_floor(now) - 23 * 3600;
        let mut base = (0, 0);
        let mut found = false;
        if let Some(m) = self.marks.iter().rev().find(|m| m.at <= target) {
            if let Some(v) = Self::val(m, k) {
                base = v;
                found = true;
            }
        }
        if !found {
            if let Some(v) = self.marks.iter().find_map(|m| Self::val(m, k)) {
                base = v;
            }
        }
        (cur.0 - base.0.min(cur.0), cur.1 - base.1.min(cur.1))
    }

    /// Накопленные байты устройства (его MAC или адреса) и роутера и когда прочитаны
    /// счётчики (unix мс): страница считает скорость по разнице за свой интервал
    /// опроса — как WAN, без пропуска секундных всплесков между опросами.
    pub fn cum(&self, ip: &str) -> (u64, u64) {
        if !self.enabled {
            return (0, 0);
        }
        self.cum_of(&self.identity(ip))
    }

    /// Снимок для графика страницы: в один момент — байты WAN, роутера и всех
    /// устройств, что учёт видел за последний час (накопленные, по MAC, без MAC —
    /// по адресу). Скорости страница считает по разнице двух снимков: сумма
    /// «устройства + роутер» сходится с WAN, всплески и фронты не теряются.
    pub fn snapshot_json(&self, j: &mut J) {
        j.obj().key("ms").int(self.read_ms).key("dev").str(&self.wan_dev);
        j.key("wan").arr().uint(self.wan_rx).uint(self.wan_tx).end_arr();
        j.key("router").arr().uint(self.cum_dr).uint(self.cum_ur).end_arr();
        j.key("ids").obj();
        let mut seen: Vec<String> = Vec::new();
        for ip in self.last_dc.keys().chain(self.last_uc.keys()) {
            let id = self.identity(ip);
            if seen.contains(&id) {
                continue;
            }
            let (d, u) = self.cum_of(&id);
            j.key(&id).arr().uint(d).uint(u).end_arr();
            seen.push(id);
        }
        j.end_obj().end_obj();
    }

    pub fn router_cum(&self) -> (u64, u64, i64) {
        (self.cum_dr, self.cum_ur, self.read_ms)
    }

    fn cum_of(&self, id: &str) -> (u64, u64) {
        (self.cum_dc.get(id).copied().unwrap_or(0), self.cum_uc.get(id).copied().unwrap_or(0))
    }

    pub fn hour(&self, ip: &str, now: i64) -> (u64, u64) {
        if !self.enabled {
            return (0, 0);
        }
        let id = self.identity(ip);
        self.hour_for(&format!("c:{id}"), self.cum_of(&id), now)
    }

    pub fn day(&self, ip: &str, now: i64) -> (u64, u64) {
        if !self.enabled {
            return (0, 0);
        }
        let id = self.identity(ip);
        self.day_for(&format!("c:{id}"), self.cum_of(&id), now)
    }

    pub fn router_hour(&self, now: i64) -> (u64, u64) {
        if !self.enabled {
            return (0, 0);
        }
        self.hour_for(&format!("r:{ROUTER_ID}"), (self.cum_dr, self.cum_ur), now)
    }

    pub fn router_day(&self, now: i64) -> (u64, u64) {
        if !self.enabled {
            return (0, 0);
        }
        self.day_for(&format!("r:{ROUTER_ID}"), (self.cum_dr, self.cum_ur), now)
    }

    pub fn router_rate(&self) -> (f64, f64) {
        if !self.enabled {
            return (0.0, 0.0);
        }
        (self.rate_dr, self.rate_ur)
    }

    pub fn client_rate(&self, ip: &str) -> (f64, f64) {
        if !self.enabled {
            return (0.0, 0.0);
        }
        (self.rate_c.get(ip).copied().unwrap_or(0.0), self.rate_cu.get(ip).copied().unwrap_or(0.0))
    }

    /// Сохранить чекпоинт сейчас (при остановке).
    pub fn flush(&self) {
        if self.enabled && self.ready {
            self.save_checkpoint();
            self.chart.save();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_acct() -> Acct {
        Acct { enabled: true, ready: true, refresh_ms: 1000, window_s: 3600, ..Default::default() }
    }

    #[test]
    fn deltas_and_windows() {
        let mut a = test_acct();
        let mut last = HashMap::new();
        assert_eq!(delta(&mut last, "x", 100, false), 100);
        assert_eq!(delta(&mut last, "x", 150, false), 50);
        assert_eq!(delta(&mut last, "x", 20, false), 20); // элемент пересоздан
        assert_eq!(delta(&mut last, "y", 500, true), 0); // первый замер при живой таблице
        // часовой объём: снимок час назад
        a.mac_of.insert("192.0.2.5".into(), "aa:bb".into());
        a.cum_dc.insert("m:aa:bb".into(), 1000);
        a.cum_uc.insert("m:aa:bb".into(), 100);
        let m = a.current_mark(10_000);
        a.snaps.push(m);
        a.cum_dc.insert("m:aa:bb".into(), 4000);
        a.cum_uc.insert("m:aa:bb".into(), 400);
        assert_eq!(a.hour("192.0.2.5", 10_000 + 3600), (3000, 300));
        // суточный: самая ранняя отметка, если ровно сутки назад нет
        let m = a.current_mark(hour_floor(20_000));
        a.marks.push(m);
        a.cum_dc.insert("m:aa:bb".into(), 9000);
        assert_eq!(a.day("192.0.2.5", 21_000).0, 5000);
        assert_eq!(a.day("198.51.100.1", 21_000), (0, 0));
    }

    #[test]
    fn checkpoint_roundtrip_format() {
        let mut a = test_acct();
        a.cum_dc.insert("m:aa:bb".into(), 12345678901234);
        a.cum_dr = 77;
        a.mac_of.insert("192.0.2.5".into(), "aa:bb".into());
        let m = a.current_mark(1000);
        a.snaps.push(m);
        let j = a.checkpoint_json(true);
        let v = parse_json(&j).unwrap();
        assert_eq!(map_u64(v.get("cum_dc")).get("m:aa:bb"), Some(&12345678901234));
        assert_eq!(map_u64(v.get("cum_dr")).get("router"), Some(&77));
        let mut b = test_acct();
        let snaps = b.parse_marks(v.get("snaps"), 0);
        assert_eq!(snaps.len(), 1);
        assert_eq!(Acct::val(&snaps[0], b.keys.find("c:m:aa:bb")), Some((12345678901234, 0)));
        assert_eq!(Acct::val(&snaps[0], b.keys.find("r:router")), Some((77, 0)));
    }

    #[test]
    fn collapse_nested() {
        let n = |s: &str, b| IpNet::new(s.parse().unwrap(), b);
        let c = collapse(&[n("192.168.1.0", 24), n("192.168.0.0", 16), n("10.0.0.1", 32), n("192.168.0.0", 16)]);
        assert_eq!(c.iter().map(|x| x.to_string()).collect::<Vec<_>>(), vec!["192.168.0.0/16", "10.0.0.1/32"]);
    }
}
