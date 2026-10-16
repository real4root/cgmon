//! Статус для страницы и CLI (StatusResponse в Go). Пишется руками в
//! переиспользуемый буфер. Поля, которых ещё нет в 2.x, отдаются с нулевыми
//! значениями той же формы, чтобы status.html работала без ошибок; компоненты
//! заполняют свои блоки по мере переноса.

use crate::daemon::Daemon;
use crate::util;

use crate::clients::{self, round1, round2};
use crate::config::go_float;
use crate::conntrack::{ClientStats, Snapshot};
use crate::prober::{stats_json, ProbeStats};

/// Как Go roundedProbeStats: доли и задержка до десятых.
pub fn rounded(s: &ProbeStats) -> ProbeStats {
    ProbeStats { success_rate: round1(s.success_rate), timeout_rate: round1(s.timeout_rate), avg_latency_ms: round1(s.avg_latency_ms), ..s.clone() }
}

/// «1h2m3s» как Go time.Duration.String (до секунд).
pub fn go_duration(secs: i64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

fn time_or_zero(t: (i64, u32)) -> String {
    if t.0 == 0 {
        "0001-01-01T00:00:00Z".into()
    } else {
        util::rfc3339(t.0, t.1)
    }
}

/// Клиенты для статуса: учёт (часы, сутки, скорости, MAC) и имена.
fn fill(d: &Daemon, list: &mut [ClientStats], unix: i64) {
    for c in list.iter_mut() {
        (c.hour_down, c.hour_up) = d.acct.hour(&c.ip, unix);
        (c.day_down, c.day_up) = d.acct.day(&c.ip, unix);
        if c.mac.is_empty() {
            c.mac = d.acct.mac_of(&c.ip);
        }
        let (dl, ul) = d.acct.client_rate(&c.ip);
        c.rate_down_mbps = round2(dl * 8.0 / 1e6);
        c.rate_up_mbps = round2(ul * 8.0 / 1e6);
        (c.cum_down, c.cum_up) = d.acct.cum(&c.ip);
        if c.hostname.is_empty() {
            c.hostname = d.resolver.name_for(&c.ip, &c.mac);
        }
    }
}

/// Части статуса, которые пересобираются не на каждый запрос страницы.
#[derive(Default)]
pub struct Cache {
    at: u64,
    ext: bool,
    ev: String,
    inc: String,
    diag: String,
    ndiag: usize,
    ports_at: u64,
    ports: Option<String>,
}

impl Cache {
    /// Новое событие — показать сразу.
    pub fn touch(&mut self) {
        self.at = 0;
    }

    /// Порты пересобрать сразу (включили кнопкой).
    pub fn touch_ports(&mut self) {
        self.ports_at = 0;
    }
}

const CACHE_MS: u64 = 5000;

pub fn build(d: &mut Daemon, unix: i64) {
    let (sec, ns) = util::now_wall();
    let cfg = d.cfg.clone();
    let started = d.started;
    let grace = d.in_grace(unix);
    let (phase, diag) = (d.health.phase, d.health.diagnosis);
    let (v4, v6, u4, u6) = (rounded(&d.v4), rounded(&d.v6), rounded(&d.udp4), rounded(&d.udp6));
    let lm = d.local_m.clone();
    let pressure = if d.extended { d.local.pressure_reason.clone() } else { String::new() };
    let _sp = crate::prof::scope("st: события/инциденты");
    // события и инциденты меняются редко: JSON пересобирается раз в 5 с
    // (страница опрашивает раз в секунду) или сразу после нового события
    let now_ms = crate::evloop::now_ms();
    if d.st_cache.at == 0 || now_ms - d.st_cache.at >= CACHE_MS || d.st_cache.ext != d.extended {
        let mut evj = crate::json::J::new();
        evj.arr();
        for (t, typ, msg) in &d.events {
            evj.obj().key("time").str(&util::rfc3339(t.0, t.1)).key("type").str(typ).key("message").str(msg).end_obj();
        }
        evj.end_arr();
        // инциденты — только глобальные; служебные — diag в расширенном режиме
        let (mut incj, mut diagj) = (crate::json::J::new(), crate::json::J::new());
        incj.arr();
        diagj.arr();
        let mut ndiag = 0;
        for inc in d.journal.status_items(unix) {
            if crate::incidents::diag_type(&inc.typ) {
                if d.extended {
                    inc.to_json(&mut diagj);
                    ndiag += 1;
                }
            } else {
                inc.to_json(&mut incj);
            }
        }
        incj.end_arr();
        diagj.end_arr();
        d.st_cache = Cache { at: now_ms.max(1), ext: d.extended, ev: evj.b, inc: incj.b, diag: diagj.b, ndiag, ..std::mem::take(&mut d.st_cache) };
    }
    drop(_sp);
    let _sp = crate::prof::scope("st: клиенты (имена, JSON)");
    // клиенты
    let empty = Snapshot::default();
    let snap = d.snap.take();
    let s = snap.as_ref().unwrap_or(&empty);
    let top = clients::top_offender(s, &d.protected, cfg.limits.min_offender_connections).cloned();
    let mut top_list = clients::sorted(s.clients.values().cloned(), cfg.status_top_clients.max(0) as usize);
    let mut all = clients::sorted(s.clients.values().cloned(), 0);
    all.extend(d.clients.kept(s, unix, cfg.client_retention_sec));
    fill(d, &mut top_list, unix);
    fill(d, &mut all, unix);
    let mut cj = crate::json::J::new();
    cj.arr();
    for c in &top_list {
        clients::client_json(&mut cj, c);
    }
    cj.end_arr();
    let mut aj = crate::json::J::new();
    aj.arr();
    for c in &all {
        clients::client_json(&mut aj, c);
    }
    aj.end_arr();
    let mut segj = crate::json::J::new();
    clients::segments_json(&mut segj, s, &d.lan_nets);
    let (rh, rd, rr) = (d.acct.router_hour(unix), d.acct.router_day(unix), d.acct.router_rate());
    let rc = d.acct.router_cum();
    let mut accj = crate::json::J::new();
    d.acct.snapshot_json(&mut accj);
    let rates = d.clients.rates;
    let p = &d.clients.peaks;
    let mut pj = crate::json::J::new();
    pj.obj().key("total_wan").int(p.total_wan).key("total_wan_at").str(&time_or_zero(p.total_wan_at));
    pj.key("lan_to_wan").int(p.lan_to_wan).key("lan_to_wan_at").str(&time_or_zero(p.lan_to_wan_at));
    pj.key("router_own").int(p.router_own).key("router_own_at").str(&time_or_zero(p.router_own_at));
    pj.key("top_client_ip").str(&p.top_client_ip).key("top_client_wan").int(p.top_client_wan).key("top_client_at").str(&time_or_zero(p.top_client_at)).end_obj();
    drop(_sp);
    let _sp = crate::prof::scope("st: топология/прочее");
    let mut tj = crate::json::J::new();
    tj.arr();
    for t in &d.topo.tracked {
        tj.obj().key("name").str(&t.name).key("zone").str(&t.zone).key("ips").arr();
        for ip in &t.ips {
            tj.str(ip);
        }
        tj.end_arr().end_obj();
    }
    tj.end_arr();
    let router = hostname();
    drop(_sp);
    let _sp = crate::prof::scope("st: dns_guard");
    let mut dgj = crate::json::J::new();
    if let Some(g) = &d.dg {
        g.status_json(&mut dgj);
    }
    drop(_sp);
    let _sp = crate::prof::scope("st: witness");
    let mut witj = crate::json::J::new();
    if d.witness.cfg.mode != "off" {
        d.witness.status_json(&mut witj);
    }
    let mut ptj = crate::json::J::new();
    let has_pt = d.pathc.open_json(&mut ptj);
    drop(_sp);
    let _sp = crate::prof::scope("st: down_detector");
    let mut ddj = crate::json::J::new();
    if !d.downdet.off {
        d.downdet.status_json(&mut ddj, &d.syn, crate::evloop::now_ms());
    }
    let mut billj = crate::json::J::new();
    if d.extended {
        if let Some(b) = &d.billing {
            b.status_json(&mut billj);
        }
    }
    drop(_sp);
    let _sp = crate::prof::scope("st: runtime/настройки");
    let mut rtj = crate::json::J::new();
    d.rt.status_json(&cfg, unix, &mut rtj);
    let dry_run = d.effective_dry_run();
    let limiter_on = cfg.enable_limiter && !d.limiter.disabled;
    let lim = (d.limiter.limit > 0 && !dry_run, d.limiter.ip.clone(), d.limiter.limit, d.limiter.blocked);
    let dra = if dry_run && (phase == "WARNING" || phase == "CRITICAL") && diag == "IPV4_EXTERNAL_DEGRADATION" {
        top.as_ref().map(|t| (crate::limiter::calculate_limit(&cfg, phase, t, d.v4.success_rate), t.clone()))
    } else {
        None
    };
    // этап 6: шейпер, QoS; в расширенном режиме — пиры, потоки, flow watch, учитель
    let mut s6: Vec<(&str, crate::json::J)> = Vec::new();
    {
        let mut add = |k: &'static str, f: &dyn Fn(&mut crate::json::J)| {
            let mut x = crate::json::J::new();
            f(&mut x);
            s6.push((k, x));
        };
        if let Some(s) = &d.shaper {
            add("upload_shaper", &|x| s.status_json(x));
        }
        if let Some(q) = &d.qos {
            add("qos", &|x| q.status_json(x));
        }
        if d.extended {
            if !d.peers.out.is_empty() {
                add("peers", &|x| d.peers.json_list(x));
            }
            if !d.flows.list.is_empty() {
                add("wan_flows", &|x| d.flows.json_list(x));
            }
            if let Some(f) = &d.fw {
                let now = crate::evloop::now_ms();
                add("flow_watch", &|x| f.status_json(x, now));
                if let Some(l) = &f.learn {
                    add("upload_learn", &|x| l.status_json(x));
                }
            }
        }
    }
    drop(_sp);
    let _sp = crate::prof::scope("st: gate/report/hub");
    let gatej = d.gate.as_ref().map(|g| {
        let mut x = crate::json::J::new();
        x.obj();
        g.status_json(&mut x);
        x.end_obj();
        x
    });
    let payj = d.payment.as_ref().map(|p| {
        let mut x = crate::json::J::new();
        p.json(&mut x);
        x
    });
    let repj = if d.cfg.report.enabled {
        let mut x = crate::json::J::new();
        d.reporter.status_json(&d.cfg.report, &mut x);
        Some(x)
    } else {
        None
    };
    let hubj = d.hub.as_ref().map(|h| {
        let mut x = crate::json::J::new();
        h.status_json(&mut x);
        x
    });
    // канал основного шлюза, система, порты, плагины
    drop(_sp);
    let _sp = crate::prof::scope("st: wan_link (ubus)");
    let mut linkj = crate::json::J::new();
    let has_link = d.sys.wan_link_json(&mut linkj, now_ms, &crate::netx::default_route_interface());
    drop(_sp);
    let _sp = crate::prof::scope("st: sys_extra (/proc)");
    let mut sysj = crate::json::J::new();
    // порты и TOP CPU/RAM — только зрителям; на «слабом» роутере — по кнопке на 5 минут
    let viewed = Daemon::web_active();
    let extras_on = now_ms < d.extras_until;
    let extras = viewed && (!d.sys.weak || extras_on);
    let (weak, own_avg, extras_until) = (d.sys.weak, d.sys.own_avg, d.extras_until);
    d.sys.sys_extra_json(&mut sysj, now_ms, extras);
    drop(_sp);
    let _sp = crate::prof::scope("st: ports (sysfs)");
    // порты (sysfs, ~10 мс на x86) — раз в 5 с
    if !extras {
        d.st_cache.ports = None;
        d.st_cache.ports_at = 0;
    } else if d.st_cache.ports_at == 0 || now_ms - d.st_cache.ports_at >= CACHE_MS {
        let mut portj = crate::json::J::new();
        let nf = d.sys.netifd(now_ms);
        d.st_cache.ports = if crate::sysinfo::ports_json(&mut portj, &nf, &d.topo.wan_devs) { Some(portj.b) } else { None };
        d.st_cache.ports_at = now_ms.max(1);
    }
    drop(_sp);
    let _sp = crate::prof::scope("st: plugins/deps/l2");
    let mut plugj = crate::json::J::new();
    d.plugins.json(&mut plugj);
    let has_plug = !d.plugins.list.is_empty();
    let mut depj = crate::json::J::new();
    depj.obj();
    d.deps.json(&mut depj);
    depj.end_obj();
    let mut l2j = crate::json::J::new();
    if d.l2.on {
        let (resolver, acct) = (&d.resolver, &d.acct);
        // свои — как в таблице устройств; чужие — без проб (адрес ушёл бы в WAN)
        let name = |ip: &str, mac: &str, own: bool| -> String {
            if own {
                return resolver.name_for(ip, mac);
            }
            let _ = acct;
            resolver.dev.as_ref().map(|x| x.known(ip, mac)).unwrap_or_default()
        };
        d.l2.status_json(&mut l2j, &name);
    } else {
        l2j.obj().key("on").bool(false).end_obj(); // страница покажет кнопку «включить на 30 минут»
    }
    let l2_left = if !d.cfg.devices.l2_watch && now_ms < d.l2_until { (d.l2_until - now_ms) / 1000 } else { 0 };
    drop(_sp);
    let _sp = crate::prof::scope("st: запись JSON");
    let phyj = d.phy.on().then(|| {
        let mut x = crate::json::J::new();
        d.phy.status_json(&mut x);
        x
    });
    let gmj = d.gmaps.on().then(|| {
        let mut x = crate::json::J::new();
        d.gmaps.status_json(&mut x);
        x
    });
    let sc = std::mem::take(&mut d.st_cache);
    let j = d.out();
    j.obj();
    j.key("time").str(&util::rfc3339(sec, ns));
    j.key("uptime").str(&go_duration(unix - started));
    j.key("state").str(phase);
    j.key("diagnosis").str(diag);
    j.key("router_name").str(if router.is_empty() { "router" } else { &router });
    j.key("router_hour_down").uint(rh.0).key("router_hour_up").uint(rh.1);
    j.key("router_day_down").uint(rd.0).key("router_day_up").uint(rd.1);
    j.key("acct").raw(&accj.b);
    j.key("acct_ms").int(rc.2).key("router_cum_down").uint(rc.0).key("router_cum_up").uint(rc.1);
    j.key("router_dl_mbps").raw(&go_float(round2(rr.0 * 8.0 / 1e6))).key("router_ul_mbps").raw(&go_float(round2(rr.1 * 8.0 / 1e6)));
    j.key("dry_run").bool(dry_run);
    j.key("enable_limiter").bool(limiter_on);
    j.key("grace").bool(grace);
    // WAN-сводка
    let total = s.lan_to_wan + s.router_own + s.incoming_forwarded;
    let classified = total + s.lan_to_router + s.lan_to_local;
    let unclassified = (s.current - classified - s.ignored_total).max(0);
    let cpct = if s.current > 0 { round1(classified as f64 / s.current as f64 * 100.0) } else { 0.0 };
    let (tc, tsc, tw, ti, tr) = top.as_ref().map(|t| (t.ip.clone(), clients::client_score(t), t.wan, t.incoming, t.new_rate)).unwrap_or_default();
    j.key("wan").obj();
    for (k, v) in [("total", total), ("lan_to_wan", s.lan_to_wan), ("router_own", s.router_own), ("incoming", s.incoming_forwarded), ("ignored", s.ignored_total), ("unclassified", unclassified)] {
        j.key(k).int(v);
    }
    j.key("classified_pct").raw(&go_float(cpct));
    for (k, v) in [("new_total_rate", rates.0), ("new_lan_rate", rates.1), ("new_router_rate", rates.2), ("new_incoming_rate", rates.3)] {
        j.key(k).raw(&go_float(v));
    }
    for (k, v) in [
        ("lan_to_wan_tcp", s.lan_to_wan_tcp), ("lan_to_wan_udp", s.lan_to_wan_udp), ("lan_to_wan_ipv4", s.lan_to_wan_ipv4), ("lan_to_wan_ipv6", s.lan_to_wan_ipv6),
        ("router_own_tcp", s.router_own_tcp), ("router_own_udp", s.router_own_udp), ("router_own_ipv4", s.router_own_ipv4), ("router_own_ipv6", s.router_own_ipv6),
        ("incoming_ipv4", s.incoming_ipv4), ("incoming_ipv6", s.incoming_ipv6), ("router_own_tunnel", s.router_own_tunnel), ("router_own_probe", s.router_own_probe),
        ("router_own_tunnel_tcp", s.router_own_tunnel_tcp), ("router_own_tunnel_udp", s.router_own_tunnel_udp), ("router_own_tunnel_ipv4", s.router_own_tunnel_ipv4), ("router_own_tunnel_ipv6", s.router_own_tunnel_ipv6),
        ("router_own_probe_tcp", s.router_own_probe_tcp), ("router_own_probe_udp", s.router_own_probe_udp), ("router_own_probe_ipv4", s.router_own_probe_ipv4), ("router_own_probe_ipv6", s.router_own_probe_ipv6),
    ] {
        j.key(k).int(v);
    }
    j.key("top_client").str(&tc).key("top_client_score").int(tsc).key("top_client_wan").int(tw).key("top_client_incoming").int(ti).key("top_client_new_rate").raw(&go_float(tr));
    j.end_obj();
    j.key("peaks").raw(&pj.b);
    j.key("events").raw(&sc.ev);
    j.key("tracked_interfaces").raw(&tj.b);
    match &dra {
        Some((want, t)) => {
            j.key("dry_run_action").obj().key("active").bool(*want > 0).key("ip").str(&t.ip).key("current_score").int(clients::client_score(t)).key("current_wan").int(t.wan).key("current_incoming").int(t.incoming).key("calculated_limit").int(*want).end_obj();
        }
        None => {
            j.key("dry_run_action").obj().key("active").bool(false).key("ip").str("").key("current_score").int(0).key("current_wan").int(0).key("current_incoming").int(0).key("calculated_limit").int(0).end_obj();
        }
    }
    j.key("conntrack").obj();
    j.key("current").int(s.current).key("max").int(s.max).key("usage_pct").raw(&go_float(round1(s.usage_pct)));
    for (k, v) in [("tcp", s.tcp), ("udp", s.udp), ("icmp", s.icmp), ("established", s.established), ("syn_sent", s.syn_sent), ("syn_recv", s.syn_recv), ("time_wait", s.time_wait), ("lan_to_router", s.lan_to_router), ("lan_to_local", s.lan_to_local)] {
        j.key(k).int(v);
    }
    j.end_obj();
    j.key("lan").obj().key("clients").int(s.clients.len() as i64).key("top_client").str(&tc).key("top_connections").int(tw).end_obj();
    j.key("ipv4");
    stats_json(j, &v4);
    j.key("ipv6");
    stats_json(j, &v6);
    j.key("ipv6_available").bool(v6.available);
    j.key("udp4");
    stats_json(j, &u4);
    j.key("udp6");
    stats_json(j, &u6);
    j.key("udp6_available").bool(u6.available);
    j.key("dynamic_limits").obj().key("active").bool(lim.0).key("ip").str(&lim.1).key("limit").int(lim.2).key("blocked").bool(lim.3).end_obj();
    j.key("top").raw(&cj.b);
    j.key("clients_all").raw(&aj.b);
    j.key("lan_segments").raw(&segj.b);
    j.key("local").obj();
    j.key("cpu_percent").raw(&go_float(lm.cpu)).key("load1").raw(&go_float(lm.load1));
    j.key("mem_available_mb").int(lm.mem_available_mb).key("num_cpu").int(lm.num_cpu);
    j.key("max_core_percent").raw(&go_float(lm.max_core_cpu));
    if !lm.max_core.is_empty() {
        j.key("max_core").str(&lm.max_core);
    }
    j.key("max_core_softirq_percent").raw(&go_float(lm.max_core_softirq));
    j.end_obj();
    if !pressure.is_empty() {
        j.key("local_pressure_reason").str(&pressure);
    }
    j.key("version").str(crate::VERSION).key("build").str(crate::variant::name());
    j.key("runtime").raw(&rtj.b);
    if !ddj.b.is_empty() {
        j.key("down_detector").raw(&ddj.b);
    }
    if !dgj.b.is_empty() {
        j.key("dns_guard").raw(&dgj.b);
    }
    if !witj.b.is_empty() {
        j.key("witness").raw(&witj.b);
    }
    if has_pt {
        j.key("path_culprit").raw(&ptj.b);
    }
    if !billj.b.is_empty() {
        j.key("billing").raw(&billj.b);
    }
    if !l2j.b.is_empty() {
        j.key("l2").raw(&l2j.b);
    }
    if l2_left > 0 {
        j.key("l2_left_sec").int(l2_left as i64);
    }
    j.raw_kv(&depj.b);
    if has_link {
        j.key("wan_link").raw(&linkj.b);
    }
    j.key("sys_extra").raw(&sysj.b);
    // где промежуточные данные (storage) и ошибка своего каталога (флешка не смонтирована)
    j.key("storage").obj().key("dir").str(&crate::storage::dir());
    let se = crate::storage::error();
    if !se.is_empty() {
        j.key("error").str(&se);
    }
    j.end_obj();
    if viewed && weak {
        // заглушка на странице: «отключено для экономии CPU — запустить на 5 минут»
        j.key("extras").obj().key("weak").bool(true).key("cpu_avg").raw(&go_float(round2(own_avg)));
        if extras_on {
            j.key("left_sec").int(((extras_until - now_ms) / 1000) as i64);
        }
        j.end_obj();
    }
    if let Some(x) = &phyj {
        j.key("phy").raw(&x.b);
    }
    if let Some(x) = &gmj {
        j.key("gate_maps").raw(&x.b);
    }
    if let Some(p) = &sc.ports {
        j.key("ports").raw(p);
    }
    if has_plug {
        j.key("plugins").raw(&plugj.b);
    }
    if let Some(p) = &payj {
        j.key("payment").raw(&p.b);
    }
    if let Some(r) = &repj {
        j.key("report").raw(&r.b);
    }
    if let Some(h) = &hubj {
        j.key("hub").raw(&h.b);
    }
    for (k, v) in &s6 {
        j.key(k).raw(&v.b);
    }
    if sc.ndiag > 0 {
        j.key("diag").raw(&sc.diag);
    }
    match &gatej {
        Some(g) => {
            j.raw_kv(&g.b);
        }
        None => {
            j.key("gate").raw("null").key("gate_events").raw("null");
        }
    }
    j.key("incidents").raw(&sc.inc);
    j.end_obj();
    d.st_cache = sc;
    d.snap = snap;
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn duration() {
        assert_eq!(super::go_duration(3723), "1h2m3s");
        assert_eq!(super::go_duration(61), "1m1s");
        assert_eq!(super::go_duration(5), "5s");
    }
}
