//! Клиенты LAN поверх снимка conntrack (перенос updateClientDynamics,
//! updateClientKeep/withKeptClients, chooseTopOffender, buildLANSegments,
//! updatePeaks, sortedClients и JSON ClientStats).

use crate::conntrack::{ClientStats, Snapshot};
use crate::json::J;
use crate::netx::{self, IpNet};
use crate::util;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default, Clone)]
struct Meta {
    sum: i64,
    count: i64,
    max: i64,
    max_wan: i64,
    seen: i64,
}

pub fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

pub fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

pub fn client_score(c: &ClientStats) -> i64 {
    c.wan + c.incoming
}

pub fn limiter_score(c: &ClientStats) -> i64 {
    c.wan
}

#[derive(Default)]
pub struct Peaks {
    pub total_wan: i64,
    pub total_wan_at: (i64, u32),
    pub lan_to_wan: i64,
    pub lan_to_wan_at: (i64, u32),
    pub router_own: i64,
    pub router_own_at: (i64, u32),
    pub top_client_ip: String,
    pub top_client_wan: i64,
    pub top_client_at: (i64, u32),
    last_event: i64,
}

#[derive(Default)]
pub struct Clients {
    meta: HashMap<String, Meta>,
    meta_pruned: i64,
    /// прошлый снимок: (total, wan) по IP и итоги категорий
    prev: Option<(HashMap<String, (i64, i64)>, i64, i64, i64)>,
    prev_ms: u64,
    keep: HashMap<String, (ClientStats, (i64, u32))>,
    pub rates: (f64, f64, f64, f64), // total, lan, router, incoming (новые/с)
    pub peaks: Peaks,
    router_own_ewma: f64,
    last_router_alert: i64,
}

fn should_peak(old: i64, new: i64) -> bool {
    if old == 0 {
        return true;
    }
    let d = new - old;
    d > 0 && (d >= 100 || d as f64 / old as f64 >= 0.10)
}

impl Clients {
    /// После чтения conntrack: скорости, максимумы/средние, удержание.
    /// Возвращает событие-алерт (всплеск router_own), если есть.
    pub fn update(&mut self, s: &mut Snapshot, now_ms: u64, wall: (i64, u32), interval_sec: i64, long_window: i64, retention: i64) -> Option<String> {
        let now = wall.0;
        let mut interval = interval_sec as f64;
        if self.prev_ms != 0 && now_ms > self.prev_ms {
            interval = (now_ms - self.prev_ms) as f64 / 1000.0;
        }
        let rate = |d: i64| if interval > 0.0 { d.max(0) as f64 / interval } else { 0.0 };
        if let Some((_, lw, ro, inc)) = &self.prev {
            let (l, r, i) = (round2(rate(s.lan_to_wan - lw)), round2(rate(s.router_own - ro)), round2(rate(s.incoming_forwarded - inc)));
            self.rates = (round2(l + r + i), l, r, i);
        } else {
            self.rates = (0.0, 0.0, 0.0, 0.0);
        }
        // метаданные клиентов: забыть не виденных дольше часа (IPv6 privacy)
        if now - self.meta_pruned >= 600 {
            self.meta_pruned = now;
            self.meta.retain(|_, m| now - m.seen <= 3600);
        }
        let prev = self.prev.as_ref().map(|p| &p.0);
        for (ip, c) in s.clients.iter_mut() {
            let (pt, pw) = prev.and_then(|p| p.get(ip)).copied().unwrap_or((0, 0));
            c.new_rate = round2((c.total - pt).max(0) as f64 / interval);
            c.new_wan_rate = round2((c.wan - pw).max(0) as f64 / interval);
            let m = self.meta.entry(ip.clone()).or_default();
            m.seen = now;
            m.sum += c.total;
            m.count += 1;
            m.max = m.max.max(c.total);
            m.max_wan = m.max_wan.max(client_score(c));
            c.max = m.max;
            c.max_wan = m.max_wan;
            c.avg = round1(m.sum as f64 / m.count as f64);
            c.last_seen = wall;
        }
        self.prev = Some((s.clients.iter().map(|(k, c)| (k.clone(), (c.total, c.wan))).collect(), s.lan_to_wan, s.router_own, s.incoming_forwarded));
        self.prev_ms = now_ms;
        // удержание: клиенты ещё retention после исчезновения записей
        let ret = if retention > 0 { retention } else { 3600 };
        for (ip, c) in &s.clients {
            self.keep.insert(ip.clone(), (c.clone(), wall));
        }
        self.keep.retain(|ip, (_, t)| s.clients.contains_key(ip) || now - t.0 <= ret);
        // скользящая база router_own + алерт по всплеску
        if self.router_own_ewma == 0.0 {
            self.router_own_ewma = s.router_own as f64;
        } else {
            let mut a = interval / long_window.max(1) as f64;
            if a <= 0.0 || a > 1.0 {
                a = 0.1;
            }
            self.router_own_ewma += a * (s.router_own as f64 - self.router_own_ewma);
        }
        if s.router_own > 200 && s.router_own as f64 > 3.0 * self.router_own_ewma && now - self.last_router_alert >= 600 {
            self.last_router_alert = now;
            return Some(format!("router_own spike: {} (baseline {:.0})", s.router_own, self.router_own_ewma));
        }
        None
    }

    /// Недавние, но неактивные клиенты (сессии обнулены).
    pub fn kept(&self, s: &Snapshot, now: i64, retention: i64) -> Vec<ClientStats> {
        let ret = if retention > 0 { retention } else { 3600 };
        let mut out = Vec::new();
        for (ip, (c, t)) in &self.keep {
            if s.clients.contains_key(ip) || now - t.0 > ret {
                continue;
            }
            let mut st = c.clone();
            st.total = 0;
            st.wan = 0;
            st.incoming = 0;
            st.router = 0;
            st.local = 0;
            st.new_rate = 0.0;
            st.new_wan_rate = 0.0;
            st.watching_tv = false;
            st.last_seen = *t;
            out.push(st);
        }
        out
    }

    /// Пики WAN-соединений; событие — не чаще раза в 30 с.
    pub fn update_peaks(&mut self, s: &Snapshot, top: Option<&ClientStats>, wall: (i64, u32)) -> Option<String> {
        let total = s.lan_to_wan + s.router_own + s.incoming_forwarded;
        let (tip, tsc) = top.map(|t| (t.ip.clone(), limiter_score(t))).unwrap_or_default();
        let p = &mut self.peaks;
        let mut msgs = Vec::new();
        if total > p.total_wan {
            if should_peak(p.total_wan, total) {
                msgs.push(format!("new peak total_wan={} lan_to_wan={} router_own={} incoming={}", total, s.lan_to_wan, s.router_own, s.incoming_forwarded));
            }
            p.total_wan = total;
            p.total_wan_at = wall;
        }
        if s.lan_to_wan > p.lan_to_wan {
            if should_peak(p.lan_to_wan, s.lan_to_wan) {
                msgs.push(format!("new peak lan_to_wan={}", s.lan_to_wan));
            }
            p.lan_to_wan = s.lan_to_wan;
            p.lan_to_wan_at = wall;
        }
        if s.router_own > p.router_own {
            if should_peak(p.router_own, s.router_own) {
                msgs.push(format!("new peak router_own={}", s.router_own));
            }
            p.router_own = s.router_own;
            p.router_own_at = wall;
        }
        if tsc > p.top_client_wan {
            if should_peak(p.top_client_wan, tsc) {
                msgs.push(format!("new peak top_client={} top_wan={}", tip, tsc));
            }
            p.top_client_wan = tsc;
            p.top_client_ip = tip;
            p.top_client_at = wall;
        }
        if !msgs.is_empty() && wall.0 - p.last_event >= 30 {
            p.last_event = wall.0;
            return Some(msgs.join("; "));
        }
        None
    }
}

/// Самый «жадный» клиент для ограничителя (не из защищённых).
pub fn top_offender<'a>(s: &'a Snapshot, protected: &[IpNet], min_conn: i64) -> Option<&'a ClientStats> {
    let mut best: Option<&ClientStats> = None;
    for c in s.clients.values() {
        let sc = limiter_score(c);
        if sc < min_conn {
            continue;
        }
        let Ok(ip) = c.ip.parse::<IpAddr>() else { continue };
        if netx::in_nets(&ip, protected) {
            continue;
        }
        let bs = best.map(limiter_score).unwrap_or(0);
        if best.is_none() || sc > bs || (sc == bs && c.new_wan_rate > best.unwrap().new_wan_rate) {
            best = Some(c);
        }
    }
    best
}

/// Клиенты по убыванию WAN-соединений (n > 0 — первые n).
pub fn sorted(list: impl Iterator<Item = ClientStats>, n: usize) -> Vec<ClientStats> {
    let mut v: Vec<ClientStats> = list.collect();
    v.sort_by(|a, b| {
        limiter_score(b).cmp(&limiter_score(a)).then(b.new_wan_rate.partial_cmp(&a.new_wan_rate).unwrap_or(std::cmp::Ordering::Equal)).then(b.total.cmp(&a.total))
    });
    if n > 0 {
        v.truncate(n);
    }
    v
}

/// Сегменты LAN: клиенты, соединения, лидер.
pub fn segments_json(j: &mut J, s: &Snapshot, lan_nets: &[IpNet]) {
    struct Seg {
        net: String,
        clients: i64,
        wan: i64,
        incoming: i64,
        leader: Option<(String, i64, i64, f64)>,
    }
    let mut segs: Vec<Seg> = Vec::new();
    for n in lan_nets {
        let k = n.to_string();
        if !segs.iter().any(|x| x.net == k) {
            segs.push(Seg { net: k, clients: 0, wan: 0, incoming: 0, leader: None });
        }
    }
    for c in s.clients.values() {
        let Ok(ip) = c.ip.parse::<IpAddr>() else { continue };
        let Some(n) = lan_nets.iter().find(|n| n.contains(&ip)) else { continue };
        let k = n.to_string();
        let Some(st) = segs.iter_mut().find(|x| x.net == k) else { continue };
        st.clients += 1;
        st.wan += c.wan;
        st.incoming += c.incoming;
        let better = match &st.leader {
            None => true,
            Some((_, w, _, r)) => c.wan > *w || (c.wan == *w && c.new_wan_rate > *r),
        };
        if better {
            st.leader = Some((c.ip.clone(), c.wan, c.incoming, c.new_wan_rate));
        }
    }
    segs.retain(|s| !(s.clients == 0 && s.wan == 0 && s.incoming == 0));
    segs.sort_by(|a, b| b.wan.cmp(&a.wan).then(b.clients.cmp(&a.clients)).then(a.net.cmp(&b.net)));
    j.arr();
    for s in &segs {
        let (l, lw, li) = s.leader.as_ref().map(|x| (x.0.as_str(), x.1, x.2)).unwrap_or(("", 0, 0));
        j.obj().key("network").str(&s.net).key("clients").int(s.clients).key("wan").int(s.wan).key("incoming").int(s.incoming);
        j.key("leader").str(l).key("leader_wan").int(lw).key("leader_incoming").int(li).end_obj();
    }
    j.end_arr();
}

/// JSON ClientStats (ключи как в Go).
pub fn client_json(j: &mut J, c: &ClientStats) {
    use crate::config::go_float;
    j.obj();
    j.key("ip").str(&c.ip);
    if !c.hostname.is_empty() {
        j.key("hostname").str(&c.hostname);
    }
    j.key("mac").str(&c.mac);
    for (k, v) in [("total", c.total), ("wan", c.wan), ("incoming", c.incoming), ("router", c.router), ("local", c.local), ("tcp", c.tcp), ("udp", c.udp), ("icmp", c.icmp), ("established", c.established), ("syn_sent", c.syn_sent), ("syn_recv", c.syn_recv), ("time_wait", c.time_wait)] {
        j.key(k).int(v);
    }
    j.key("cum_down").uint(c.cum_down).key("cum_up").uint(c.cum_up);
    for (k, v) in [("new_rate", c.new_rate), ("new_wan_rate", c.new_wan_rate), ("rate_down_mbps", c.rate_down_mbps), ("rate_up_mbps", c.rate_up_mbps)] {
        j.key(k).raw(&go_float(v));
    }
    j.key("bytes_up").uint(c.bytes_up).key("bytes_down").uint(c.bytes_down).key("watching_tv").bool(c.watching_tv);
    j.key("hour_down").uint(c.hour_down).key("hour_up").uint(c.hour_up).key("day_down").uint(c.day_down).key("day_up").uint(c.day_up);
    j.key("max").int(c.max).key("max_wan").int(c.max_wan).key("avg").raw(&go_float(c.avg));
    j.key("last_seen").str(&if c.last_seen.0 == 0 { "0001-01-01T00:00:00Z".to_string() } else { util::rfc3339(c.last_seen.0, c.last_seen.1) });
    j.end_obj();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(ip: &str, wan: i64, total: i64) -> ClientStats {
        ClientStats { ip: ip.into(), wan, total, ..Default::default() }
    }

    #[test]
    fn dynamics_keep_top() {
        let mut c = Clients::default();
        let mut s = Snapshot::default();
        s.clients.insert("192.0.2.5".into(), cs("192.0.2.5", 10, 12));
        s.clients.insert("192.0.2.6".into(), cs("192.0.2.6", 30, 31));
        c.update(&mut s, 1000, (100, 0), 5, 300, 3600);
        let mut s2 = Snapshot::default();
        s2.clients.insert("192.0.2.5".into(), cs("192.0.2.5", 20, 22));
        c.update(&mut s2, 6000, (105, 0), 5, 300, 3600);
        let a = &s2.clients["192.0.2.5"];
        assert_eq!((a.new_rate, a.new_wan_rate, a.max, a.avg), (2.0, 2.0, 22, 17.0));
        let kept = c.kept(&s2, 105, 3600);
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].ip.as_str(), kept[0].wan), ("192.0.2.6", 0));
        let prot = vec![IpNet::new("192.0.2.6".parse().unwrap(), 32)];
        assert_eq!(top_offender(&s, &prot, 0).map(|c| c.ip.as_str()), Some("192.0.2.5"));
        assert_eq!(top_offender(&s, &[], 0).map(|c| c.ip.as_str()), Some("192.0.2.6"));
        let order: Vec<String> = sorted(s.clients.values().cloned(), 0).into_iter().map(|c| c.ip).collect();
        assert_eq!(order, vec!["192.0.2.6", "192.0.2.5"]);
    }
}
