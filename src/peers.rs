//! WAN-потоки и пути до пиров (перенос peers.go): скорость каждого потока из
//! conntrack между снимками, пики за peak_window_sec, топ в статус; пробы
//! пиров через overlay (семейство prober «peer:<имя>») — путь умер при живом
//! интернете → событие с потоком, разгонявшимся выше penalty_mbps.

use crate::config::PeersConfig;
use crate::conntrack::WanFlow;
use crate::flowwatch::Rate;
use crate::json::J;
use crate::prober::Prober;
use std::collections::HashMap;

/// Выше — артефакт счётчиков.
const MAX_PLAUSIBLE_MBPS: f64 = 10000.0;
/// Отдача выше половины sustained в этом окне до деградации пира — могло быть наказание за нашу отдачу.
pub const PEER_BUSY_MS: u64 = 60_000;

fn r2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

struct Peak {
    proto: &'static str,
    local: String,
    remote: String,
    tx: f64,
    rx: f64,
    at: u64,
}

pub struct FlowStatus {
    proto: &'static str,
    local: String,
    remote: String,
    tx: f64,
    rx: f64,
    peak_tx: f64,
    peak_rx: f64,
}

#[derive(Default)]
pub struct Flows {
    prev: HashMap<String, (u64, u64)>,
    prev_at: u64,
    have_prev: bool,
    peaks: HashMap<String, Peak>,
    pub list: Vec<FlowStatus>,
}

impl Flows {
    /// Скорости между снимками, пики; скорости отдачи — для flow watch (и нулевые).
    pub fn update(&mut self, flows: &HashMap<String, WanFlow>, now: u64, cfg: &PeersConfig) -> Option<HashMap<String, Rate>> {
        let window = cfg.peak_window_sec.max(1) as u64 * 1000;
        let dt = (now - self.prev_at) as f64 / 1000.0;
        let mut list = Vec::new();
        let mut rates = None;
        if self.have_prev && dt > 0.0 {
            let mut m = HashMap::new();
            for (k, c) in flows {
                let Some(&(ptx, prx)) = self.prev.get(k) else { continue };
                if c.tx < ptx || c.rx < prx {
                    continue;
                }
                let tx = (c.tx - ptx) as f64 * 8.0 / dt / 1e6;
                let rx = (c.rx - prx) as f64 * 8.0 / dt / 1e6;
                if tx > MAX_PLAUSIBLE_MBPS || rx > MAX_PLAUSIBLE_MBPS {
                    continue;
                }
                m.insert(k.clone(), Rate { proto: c.proto, local: c.local.clone(), remote: c.remote.clone(), tx });
                if tx < 0.01 && rx < 0.01 {
                    continue;
                }
                let fp = self.peaks.entry(k.clone()).or_insert_with(|| Peak { proto: c.proto, local: c.local.clone(), remote: c.remote.clone(), tx: 0.0, rx: 0.0, at: now });
                if now - fp.at > window {
                    *fp = Peak { proto: c.proto, local: c.local.clone(), remote: c.remote.clone(), tx: 0.0, rx: 0.0, at: now };
                }
                if tx > fp.tx || rx > fp.rx {
                    fp.tx = fp.tx.max(tx);
                    fp.rx = fp.rx.max(rx);
                    fp.at = now;
                }
                list.push(FlowStatus { proto: c.proto, local: c.local.clone(), remote: c.remote.clone(), tx: r2(tx), rx: r2(rx), peak_tx: r2(fp.tx), peak_rx: r2(fp.rx) });
            }
            rates = Some(m);
        }
        self.peaks.retain(|_, p| now - p.at <= window);
        list.sort_by(|a, b| (b.tx + b.rx).partial_cmp(&(a.tx + a.rx)).unwrap_or(std::cmp::Ordering::Equal));
        list.truncate(cfg.wan_flows_top.max(0) as usize);
        self.list = list;
        self.prev = flows.iter().map(|(k, c)| (k.clone(), (c.tx, c.rx))).collect();
        self.prev_at = now;
        self.have_prev = true;
        rates
    }

    /// Самый быстрый поток за окно пиков: выше penalty_mbps — вероятное наказание.
    fn penalty_suspect(&self, now: u64, penalty_mbps: f64) -> String {
        let mut all: Vec<(&Peak, f64)> = self.peaks.values().map(|p| (p, p.tx.max(p.rx))).collect();
        if all.is_empty() {
            return String::new();
        }
        all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let desc = |(p, r): &(&Peak, f64)| format!("{} {}>{} {:.1} Mbit/s {}s ago", p.proto, p.local, p.remote, r, (now - p.at) / 1000);
        let over: Vec<String> = all.iter().take_while(|c| c.1 >= penalty_mbps).take(3).map(desc).collect();
        if !over.is_empty() {
            return format!("likely ISP flow penalty (> {penalty_mbps:.0} Mbit/s): {}", over.join("; "));
        }
        format!("busiest flow: {}", desc(&all[0]))
    }

    pub fn json_list(&self, j: &mut J) {
        let g = crate::config::go_float;
        j.arr();
        for f in &self.list {
            j.obj().key("proto").str(f.proto).key("local").str(&f.local).key("remote").str(&f.remote);
            j.key("tx_mbps").raw(&g(f.tx)).key("rx_mbps").raw(&g(f.rx)).key("peak_tx_mbps").raw(&g(f.peak_tx)).key("peak_rx_mbps").raw(&g(f.peak_rx));
            j.end_obj();
        }
        j.end_arr();
    }
}

#[derive(Default)]
struct PState {
    degraded: bool,
    bad_since: u64,
    bad_wall: i64,
    good_since: u64,
    since: u64,
    since_wall: i64,
    suspect: String,
}

pub struct PeerView {
    name: String,
    probe: String,
    state: &'static str,
    success: f64,
    count: i64,
    latency: f64,
    since: i64,
    suspect: String,
}

#[derive(Default)]
pub struct Peers {
    states: HashMap<String, PState>,
    pub out: Vec<PeerView>,
}

/// Итог оценки: сообщения журнала и «наказать шейпер».
pub struct PeerEval {
    pub msgs: Vec<String>,
    pub penalize: bool,
}

impl Peers {
    /// Пути до пиров по TCP-пробам через overlay; busy — шейпер видел отдачу за минуту.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(&mut self, cfg: &PeersConfig, prober: &Prober, flows: &Flows, now: u64, wall: i64, internet_ok: bool, shaper_busy: bool) -> PeerEval {
        let mut ev = PeerEval { msgs: Vec::new(), penalize: false };
        if cfg.list.is_empty() {
            self.out.clear();
            return ev;
        }
        let mut out = Vec::new();
        for p in &cfg.list {
            let st = prober.stats(&format!("peer:{}", p.name), cfg.window_sec, now);
            let ps = self.states.entry(p.name.clone()).or_default();
            // наказание бывает не полной потерей, а частичной с огромной задержкой
            let slow = cfg.max_latency_ms > 0.0 && st.avg_latency_ms > cfg.max_latency_ms;
            let bad = st.count >= 3 && (st.success_rate < cfg.min_success || slow);
            let good = st.count >= 3 && st.success_rate >= cfg.recover_success && !slow;
            if bad {
                ps.good_since = 0;
                if ps.bad_since == 0 {
                    ps.bad_since = now;
                    ps.bad_wall = wall;
                }
                if !ps.degraded && now - ps.bad_since >= cfg.degrade_sec.max(0) as u64 * 1000 {
                    ps.degraded = true;
                    ps.since = ps.bad_since;
                    ps.since_wall = ps.bad_wall;
                    ps.suspect = if internet_ok { flows.penalty_suspect(now, cfg.penalty_mbps) } else { "general WAN problem, not a flow penalty".into() };
                    let mut msg = format!("peer {} path degraded: probe {:.0}%, {:.0} ms over {}s", p.name, st.success_rate, st.avg_latency_ms, cfg.window_sec);
                    if internet_ok {
                        msg.push_str(" while internet OK");
                        // задержку может поднять и чужая очередь: наказание — только если сами отдавали
                        if shaper_busy {
                            ev.penalize = true;
                            msg.push_str(" (upload busy: shaper penalized)");
                        }
                    } else {
                        msg.push_str(", internet degraded too");
                    }
                    if !ps.suspect.is_empty() {
                        msg.push_str(&format!("; {}", ps.suspect));
                    }
                    ev.msgs.push(msg);
                }
            } else if good {
                ps.bad_since = 0;
                if ps.good_since == 0 {
                    ps.good_since = now;
                }
                if ps.degraded && now - ps.good_since >= cfg.recover_sec.max(0) as u64 * 1000 {
                    ev.msgs.push(format!("peer {} path recovered after {}", p.name, crate::util::go_secs(now - ps.since)));
                    ps.degraded = false;
                    ps.suspect.clear();
                }
            } else {
                ps.bad_since = 0;
                ps.good_since = 0;
            }
            let state = if ps.degraded {
                "degraded"
            } else if st.count < 3 {
                "unknown"
            } else {
                "ok"
            };
            out.push(PeerView { name: p.name.clone(), probe: p.probe.clone(), state, success: r1(st.success_rate), count: st.count, latency: r1(st.avg_latency_ms), since: if ps.degraded { ps.since_wall } else { 0 }, suspect: ps.suspect.clone() });
        }
        self.states.retain(|k, _| cfg.list.iter().any(|p| p.name == *k));
        self.out = out;
        ev
    }

    pub fn json_list(&self, j: &mut J) {
        let g = crate::config::go_float;
        j.arr();
        for p in &self.out {
            j.obj().key("name").str(&p.name).key("probe").str(&p.probe).key("state").str(p.state).key("success_rate").raw(&g(p.success)).key("count").int(p.count).key("avg_latency_ms").raw(&g(p.latency));
            if p.since != 0 {
                j.key("since").str(&crate::util::rfc3339(p.since, 0));
            }
            if !p.suspect.is_empty() {
                j.key("suspect").str(&p.suspect);
            }
            j.end_obj();
        }
        j.end_arr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_peaks() {
        let cfg = crate::config::defaults().peers;
        let mut f = Flows::default();
        let k = "tcp 192.168.1.10:50000>198.51.100.9:443".to_string();
        let mut m = HashMap::new();
        m.insert(k.clone(), WanFlow { proto: "tcp", local: "192.168.1.10:50000".into(), remote: "198.51.100.9:443".into(), tx: 0, rx: 0 });
        assert!(f.update(&m, 1000, &cfg).is_none());
        m.get_mut(&k).unwrap().tx = 12_500_000; // 100 Мбит за 1 с
        let r = f.update(&m, 2000, &cfg).unwrap();
        assert!((r[&k].tx - 100.0).abs() < 1e-9);
        assert_eq!(f.list.len(), 1);
        assert!(f.penalty_suspect(2000, 50.0).starts_with("likely ISP flow penalty (> 50 Mbit/s): tcp 192.168.1.10:50000>198.51.100.9:443 100.0 Mbit/s 0s ago"));
    }
}
