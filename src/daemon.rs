//! Демон: один поток, epoll. Конфиг (cgmon.yaml + слой со страницы),
//! живые настройки, unix-сокет (JSON-запрос → JSON-ответ), запись статуса.
//! Компоненты (пробы, учёт, DNS-страховка …) подключаются следующими этапами.

use crate::config::{self, Config};
use crate::evloop::{self, Every, Poller};
use crate::json::J;
use crate::runtime::{Runtime, MAX_UPLOAD};
use crate::value::{parse_json, Value};
use crate::health::Health;
use crate::incidents::{Journal, Sample};
use crate::wanmon::WanMon;
use crate::local::{Local, LocalMetrics};
use crate::prober::{ProbeStats, Prober};
use crate::acct::Acct;
use crate::billing::Billing;
use crate::dns::Client as DnsClient;
use crate::dnswatch::DnsWatch;
use crate::downdet::DownDetector;
use crate::ipowner::IpOwner;
use crate::synrtt::SynRtt;
use crate::witness::Witness;
use crate::dnsguard::{self as dg, DnsGuard};
use crate::flowwatch::FlowWatch;
use crate::gatesel::GateSelector;
use crate::l2watch::L2Watch;
use crate::hub::Hub;
use crate::report::Reporter;
use crate::peers::{Flows, Peers};
use crate::qos::Qos;
use crate::upshaper::UploadShaper;
use crate::pathtrace::{PathCulprit, Run as PtRun};
use crate::clients::{self, Clients};
use crate::conntrack::{self, Snapshot};
use crate::netx::IpNet;
use crate::limiter::{self, Limiter};
use crate::resolver::Resolver;
use crate::topo::{self, Netifd, StatsDev, Topology};
use crate::{livecfg, status, util};
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

// токены epoll: сокет — 1, соединения — 1<<32.., компоненты — (номер)<<48 | n
const TOK_LISTEN: u64 = 1;
const TOK_CONN0: u64 = 1 << 32;
const TOK_PROBER: u64 = 1 << 48;
const TOK_SYN: u64 = 2 << 48;
const TOK_DNSW: u64 = 3 << 48;
const TOK_DNS: u64 = 4 << 48;
/// метки DNS-запросов компонентов (старшие биты метки)
pub const TAG_OWNER: u64 = 1 << 40;
pub const TAG_WIT: u64 = 2 << 40;
const TOK_WIT: u64 = 5 << 48;
const TOK_PT: u64 = 6 << 48;
const TOK_FW: u64 = 7 << 48;
const TOK_GATE: u64 = 8 << 48;
const TOK_MDNS: u64 = 9 << 48;
const TOK_SSDP: u64 = 9 << 48 | 1;
const TOK_L2: u64 = 10 << 48;
const TOK_HUB: u64 = 11 << 48;

struct Conn {
    fd: i32,
    buf: Vec<u8>,
    deadline: u64,
}

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

pub struct Daemon {
    pub cfg: Config,
    pub rt: Runtime,
    pub started: i64,
    poller: Poller,
    listen_fd: i32,
    conns: HashMap<u64, Conn>,
    next_conn: u64,
    out: J,
    t_tick: Every,
    t_tcp: Every,
    t_udp: Every,
    pub prober: Prober,
    pub health: Health,
    pub local: Local,
    pub local_m: LocalMetrics,
    pub v4: ProbeStats,
    pub v6: ProbeStats,
    pub udp4: ProbeStats,
    pub udp6: ProbeStats,
    pub journal: Journal,
    pub wan: WanMon,
    /// лента событий (новые первыми, ≤ 100): (время, тип, текст)
    pub events: Vec<((i64, u32), String, String)>,
    pub extended: bool,
    // топология (раз в 5 минут)
    pub topo: Topology,
    pub lan_nets: Vec<IpNet>,
    pub router_wan_ips: Vec<IpAddr>,
    pub router_local_ips: Vec<IpAddr>,
    tunnel_nets: Vec<IpNet>,
    probe_eps: Vec<(IpAddr, u16)>,
    exclude_nets: Vec<IpNet>,
    pub protected: Vec<IpNet>,
    last_topo: u64,
    netifd: Netifd,
    stats_dev: StatsDev,
    // клиенты и учёт
    pub acct: Acct,
    pub resolver: Resolver,
    pub clients: Clients,
    pub snap: Option<Snapshot>,
    last_heavy: u64,
    last_output: u64,
    pub limiter: Limiter,
    /// платный трафик — только при учёте трафика (галочка на странице)
    pub billing: Option<Billing>,
    // пассивное наблюдение
    pub syn: SynRtt,
    pub dnsw: DnsWatch,
    pub dns: DnsClient,
    pub owner: IpOwner,
    pub downdet: DownDetector,
    last_tap: u64,
    pub witness: Witness,
    pub pathc: PathCulprit,
    ptrun: Option<PtRun>,
    /// DNS-страховка (создаётся, когда включена)
    pub dg: Option<DnsGuard>,
    // QoS, шейпер отдачи, flow watch, потоки и пиры (этап 6)
    pub qos: Option<Qos>,
    pub shaper: Option<UploadShaper>,
    pub fw: Option<FlowWatch>,
    pub flows: Flows,
    pub peers: Peers,
    /// резервный канал (этап 7)
    pub gate: Option<GateSelector>,
    // имена устройств и ловец (этап 8)
    pub l2: L2Watch,
    mcast: Option<(Option<i32>, Option<i32>)>,
    dev_saved: u64,
    // отчёт, центр сбора, оплата (этап 9)
    pub reporter: Reporter,
    pub hub: Option<Hub>,
    pub payment: Option<crate::payment::Status>,
    pay_done: crate::payment::Journaled,
    // пакеты для включённых функций; история состояния для cgmon dump
    pub deps: crate::deps::Watch,
    /// страница: канал, система, порты; плагины рядом с бинарником
    pub sys: crate::sysinfo::SysInfo,
    pub st_cache: crate::status::Cache,
    /// порты и TOP CPU/RAM включены кнопкой на странице до этого момента (мс)
    pub extras_until: u64,
    /// ловец устройств включён кнопкой на странице до этого момента (мс)
    pub l2_until: u64,
    /// карты шлюзов (2.4): группы и устройства LAN → свои выходы в интернет
    pub gmaps: crate::gatemap::GateMaps,
    /// физический уровень портов (линк, скорость, ошибки кадров)
    pub phy: crate::phywatch::PhyWatch,
    pub plugins: crate::plugins::Plugins,
}

/// Защищённые от ограничителя: whitelist + protected_networks + свои адреса.
fn protected_nets(cfg: &Config) -> Vec<IpNet> {
    let mut l: Vec<String> = cfg.whitelist.clone();
    l.extend(cfg.protected_networks.iter().cloned());
    let mut out = crate::netx::parse_nets(&l).unwrap_or_default();
    for ip in ["127.0.0.1", "::1"] {
        out.push(IpNet::new(ip.parse().unwrap(), if ip.contains(':') { 128 } else { 32 }));
    }
    for (_, ip, _) in crate::netx::if_addrs() {
        out.push(IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }));
    }
    out
}

/// Блокировка единственного экземпляра: flock рядом с сокетом
/// (/var/run/cgmon.sock → /var/run/cgmon.lock, как в Go).
fn instance_lock(socket: &str) -> Result<i32, String> {
    let path = match socket.strip_suffix(".sock") {
        Some(p) => format!("{p}.lock"),
        None => format!("{socket}.lock"),
    };
    let c = std::ffi::CString::new(path.clone()).map_err(|e| e.to_string())?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC, 0o644) };
    if fd < 0 {
        return Err(format!("{path}: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let pid = std::fs::read_to_string(&path).unwrap_or_default();
        unsafe { libc::close(fd) };
        let pid = pid.trim();
        return Err(format!("another instance is already running (pid {})", if pid.is_empty() { "?" } else { pid }));
    }
    let s = format!("{}\n", std::process::id());
    unsafe {
        libc::ftruncate(fd, 0);
        libc::pwrite(fd, s.as_ptr() as *const libc::c_void, s.len(), 0);
    }
    Ok(fd)
}

fn listen_unix(path: &str) -> Result<i32, String> {
    let _ = std::fs::remove_file(path);
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as u16;
    let b = path.as_bytes();
    if b.len() >= sa.sun_path.len() {
        return Err(format!("{path}: путь сокета слишком длинный"));
    }
    for (i, c) in b.iter().enumerate() {
        sa.sun_path[i] = *c as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + b.len() + 1) as u32;
    if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len) } < 0 || unsafe { libc::listen(fd, 16) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("{path}: {e}"));
    }
    let c = std::ffi::CString::new(path).unwrap();
    unsafe { libc::chmod(c.as_ptr(), 0o600) };
    Ok(fd)
}

impl Daemon {
    pub fn new(path: &str) -> Result<Daemon, String> {
        crate::prof::main_thread();
        let _pc = crate::prof::scope("config (+слой страницы)");
        let base = config::load(path)?;
        let overlay = livecfg::read_overlay(&base.paths.runtime);
        // слой со страницы: при ошибке — cgmon.yaml как есть (страница покажет)
        let cfg = if overlay.is_empty() {
            livecfg::validate(&base).map(|_| base.clone()).unwrap_or_else(|e| {
                crate::log_err!("config: {e}");
                base.clone()
            })
        } else {
            livecfg::build_live(&base, &overlay).unwrap_or_else(|e| {
                crate::log_err!("config overlay ({}): {} — using cgmon.yaml", base.paths.runtime, e);
                base.clone()
            })
        };
        util::set_log_level(&cfg.log_level);
        // /tmp/cgmon и каталог данных — до того, как компоненты прочитают свои файлы
        util::migrate_tmp();
        // страница и CGI из бинарника — в /tmp/cgmon/www, в /www — ссылки
        if cfg.web.embedded {
            crate::webfiles::install(true);
        }
        crate::luci::install(); // «Службы → cgmon» в LuCI: пароль, центр сбора
        crate::storage::apply(&cfg.storage, &cfg.storage_files(), false);
        let now = evloop::unix_now();
        let rt = Runtime::new(&cfg, base, overlay, now);
        let _lock_fd = instance_lock(&cfg.paths.socket)?; // открыт до выхода процесса
        let listen_fd = listen_unix(&cfg.paths.socket)?;
        let poller = Poller::new().map_err(|e| e.to_string())?;
        poller.add(listen_fd, libc::EPOLLIN as u32, TOK_LISTEN).map_err(|e| e.to_string())?;
        let ms = evloop::now_ms();
        drop(_pc);
        let prober = { let _p = crate::prof::scope("prober"); Prober::new(&cfg, TOK_PROBER) };
        let acct = { let _p = crate::prof::scope("acct (учёт трафика)"); Acct::new(&cfg) };
        let cfg_witness = cfg.witness.clone();
        let resolver = { let _p = crate::prof::scope("resolver (имена)"); Resolver::new(&cfg.dns.r#static) };
        let _pi = crate::prof::scope("init (прочее)");
        let mut d = Daemon {
            t_tick: Every::new(cfg.interval_sec.max(1) as u64 * 1000, ms + 1000),
            t_tcp: Every::new(cfg.probe_interval_sec.max(1) as u64 * 1000, ms),
            t_udp: Every::new(cfg.udp_probe_interval_sec.max(1) as u64 * 1000, ms),
            journal: Journal::new(&cfg.wan_monitor.incidents_file),
            protected: protected_nets(&cfg),
            exclude_nets: crate::netx::parse_nets(&cfg.exclude_networks).unwrap_or_default(),
            cfg,
            rt,
            started: now,
            poller,
            listen_fd,
            conns: HashMap::new(),
            next_conn: TOK_CONN0,
            out: J::new(),
            prober,
            health: Health::default(),
            local: Local::default(),
            local_m: LocalMetrics::default(),
            v4: ProbeStats::default(),
            v6: ProbeStats::default(),
            udp4: ProbeStats::default(),
            udp6: ProbeStats::default(),
            wan: WanMon::default(),
            events: Vec::new(),
            extended: false,
            topo: Topology::default(),
            lan_nets: Vec::new(),
            router_wan_ips: Vec::new(),
            router_local_ips: Vec::new(),
            tunnel_nets: Vec::new(),
            probe_eps: Vec::new(),
            last_topo: 0,
            netifd: Netifd::new(),
            stats_dev: StatsDev::default(),
            acct,
            resolver,
            clients: Clients::default(),
            snap: None,
            last_heavy: 0,
            last_output: 0,
            limiter: Limiter::default(),
            billing: None,
            syn: SynRtt::default(),
            dnsw: DnsWatch::default(),
            dns: DnsClient::new(TOK_DNS),
            owner: IpOwner::new(TAG_OWNER),
            downdet: DownDetector::default(),
            last_tap: 0,
            witness: Witness::new(&cfg_witness, TOK_WIT, TAG_WIT),
            pathc: PathCulprit::default(),
            ptrun: None,
            dg: None,
            qos: None,
            shaper: None,
            fw: None,
            flows: Flows::default(),
            peers: Peers::default(),
            gate: None,
            l2: L2Watch::new(),
            mcast: None,
            dev_saved: 0,
            reporter: Reporter::new(),
            hub: None,
            payment: None,
            pay_done: Default::default(),
            deps: Default::default(),
            sys: Default::default(),
            st_cache: Default::default(),
            extras_until: 0,
            l2_until: 0,
            gmaps: Default::default(),
            phy: Default::default(),
            plugins: Default::default(),
        };
        d.prober.mode = d.rt.cur.wan_check.clone();
        d.resolver.dev = { let _p = crate::prof::scope("devid (mDNS/SSDP)"); Some(crate::devid::DevIdent::new(&d.cfg.devices)) };
        d.l2.set_config(d.cfg.devices.l2_watch, d.cfg.devices.l2_probe);
        L2Watch::cleanup();
        { let _p = crate::prof::scope("hub"); d.set_hub(); }
        if d.cfg.gate_selector.enabled {
            d.gate = Some(GateSelector::new(TOK_GATE));
        }
        if d.cfg.qos.enabled {
            d.qos = Some(Qos::new(d.cfg.qos.clone()));
        }
        if d.cfg.upload_shaper.enabled {
            d.shaper = Some(UploadShaper::new(d.cfg.upload_shaper.clone()));
        }
        if d.cfg.flow_watch.enabled {
            let _p = crate::prof::scope("flow_watch");
            let mut fw = FlowWatch::new(d.cfg.flow_watch.clone(), TOK_FW);
            fw.learn = Some(crate::uplearn::UploadLearner::new(&d.cfg.flow_watch));
            fw.prober.open(&d.poller);
            d.fw = Some(fw);
        }
        d.downdet.set_on(d.cfg.down_detector.enabled);
        { let _p = crate::prof::scope("taps (AF_PACKET)"); d.update_taps(ms); }
        if d.cfg.accounting.enabled {
            let _p = crate::prof::scope("billing");
            d.billing = Some(Billing::new(&d.cfg.billing));
        }
        { let _p = crate::prof::scope("topology"); d.refresh_topology(ms); }
        if !d.effective_dry_run() {
            match limiter::nft_ensure(&d.cfg.nft.table) {
                Ok(()) => d.limiter.last_ensure = now,
                Err(e) => crate::log_err!("initial nft ensure failed: {}", e),
            }
        }
        d.deps.tick(&d.cfg, evloop::now_ms()); // чего нет — то не запускать
        if !d.deps.blocked("hard") {
            if let Err(e) = limiter::hard_apply(&d.cfg, 0) {
                crate::log_err!("hard-limit apply failed: {}", e);
            }
        }
        d.limiter.last_hard = now;
        if d.router_wan_ips.is_empty() {
            crate::log_info!("warning: no WAN IPs detected, LAN->WAN classification may be incomplete");
        }
        Ok(d)
    }

    /// Топология: зоны, адреса роутера, сети LAN, туннели, наборы учёта.
    fn refresh_topology(&mut self, now: u64) {
        self.last_topo = now.max(1);
        crate::isolation::write(&self.cfg, &mut self.netifd, now); // группы квартирантов для CGI
        let topo = topo::detect(&self.cfg, &self.exclude_nets);
        self.probe_eps = topo::probe_endpoints(&self.cfg);
        // активные пробы cgmon — не трафик клиентов (SynRTT их не считает)
        let skip: Vec<IpAddr> = self.probe_eps.iter().map(|x| x.0).collect();
        self.syn.set_skip(&skip);
        self.witness.set_probes(&skip); // цели проб — не свидетели
        let (extra_nets, extra_ips) = topo::extra_zone_info(&self.cfg, &mut self.netifd, now);
        // не-WAN сети: tunnel_networks + всё, что маршрутизируется мимо WAN
        let mut tunnel = crate::netx::parse_nets(&self.cfg.tunnel_networks).unwrap_or_default();
        let (routed, routed_tun) = topo::routed_local_nets(&topo.wan_devs);
        let mut acct_nets = tunnel.clone();
        acct_nets.extend(routed.iter().copied());
        tunnel.extend(routed_tun);
        self.tunnel_nets = tunnel;
        self.router_wan_ips = if topo.wan_ips.is_empty() { topo::fallback_wan_ips(&self.cfg) } else { topo.wan_ips.clone() };
        let mut local: Vec<IpAddr> = topo.lan_ips.iter().chain(&topo.wan_ips).chain(&extra_ips).copied().collect();
        if local.is_empty() {
            local = topo::fallback_local_ips();
        }
        self.router_local_ips = local;
        let mut nets: Vec<IpNet> = Vec::new();
        let cfg_nets = crate::netx::parse_nets(&self.cfg.lan_networks).unwrap_or_default();
        for n in cfg_nets.iter().chain(&topo.lan_nets).chain(&extra_nets) {
            let n = topo::normalize_lan(n);
            if !nets.contains(&n) {
                nets.push(n);
            }
        }
        if nets.is_empty() {
            nets = topo::fallback_lan_networks();
        }
        self.lan_nets = nets;
        self.resolver.reload(&self.cfg.dns.r#static);
        let lan_ifs = topo::lan_interface_names(&self.lan_nets);
        self.l2.set_ifaces(&lan_ifs); // ловец устройств слушает эти интерфейсы
        if self.mcast.is_none() && !lan_ifs.is_empty() {
            // устройства сами объявляют имена: mDNS и SSDP на LAN
            let m = crate::devid::mcast_socket(std::net::Ipv4Addr::new(224, 0, 0, 251), 5353, &lan_ifs);
            let s = crate::devid::mcast_socket(std::net::Ipv4Addr::new(239, 255, 255, 250), 1900, &lan_ifs);
            for (fd, tok) in [(m, TOK_MDNS), (s, TOK_SSDP)] {
                if let Some(fd) = fd {
                    let _ = self.poller.add(fd, libc::EPOLLIN as u32, tok);
                }
            }
            self.mcast = Some((m, s));
        }
        let excl = self.exclude_nets.clone();
        self.acct.set_subnets(&self.lan_nets, &acct_nets, &excl);
        crate::log_debug!("topology refreshed: tracked={} ignored_ips={} wan_ips={} local_ips={} lan_nets={}", topo.tracked.len(), topo.ignored_ips.len(), self.router_wan_ips.len(), self.router_local_ips.len(), self.lan_nets.len());
        self.topo = topo;
    }

    /// Захват рукопожатий нужен down detector'у или контролю WAN по трафику;
    /// DNS-ответы — down detector'у. Сокеты на устройстве маршрута по умолчанию.
    fn update_taps(&mut self, now: u64) {
        self.last_tap = now.max(1);
        let targeted = self.cfg.dns_guard.mode == "targeted"; // адресный режим: рукопожатия и имена клиентов
        self.syn.on = self.cfg.down_detector.enabled || self.prober.mode != "active" || targeted;
        let dev = crate::netx::default_route_interface();
        let (old, new) = self.syn.ensure(&dev);
        if let Some(fd) = old {
            self.poller.del(fd);
        }
        if let Some(fd) = new {
            let _ = self.poller.add(fd, libc::EPOLLIN as u32, TOK_SYN);
        }
        let (old, new) = self.l2.ensure();
        if let Some(fd) = old {
            self.poller.del(fd);
        }
        if let Some(fd) = new {
            let _ = self.poller.add(fd, libc::EPOLLIN as u32, TOK_L2);
        }
        self.dnsw.on = self.cfg.down_detector.enabled || targeted;
        let (old, new) = self.dnsw.ensure();
        if let Some(fd) = old {
            self.poller.del(fd);
        }
        if let Some(fd) = new {
            let _ = self.poller.add(fd, libc::EPOLLIN as u32, TOK_DNSW);
        }
    }

    /// Шаг трассировки поиска виновника; конец прогона — разбор.
    fn step_trace(&mut self, now: u64) {
        let Some(r) = self.ptrun.as_mut() else { return };
        if !r.step(now, &mut self.owner) {
            return;
        }
        let r = self.ptrun.take().unwrap();
        let (fam, results) = (r.fam, r.results.clone());
        r.close(&self.poller);
        let wall = util::now_wall();
        let owner = &self.owner;
        let mut own = |ip: &str| ip.parse::<IpAddr>().ok().and_then(|a| owner.get(&a, now)).map(|i| (i.asn.clone(), i.brand.clone()));
        let msgs = self.pathc.finish(fam, &results, &mut own, wall.0);
        for m in msgs {
            self.add_event(wall, "path", &m);
            self.journal.record("path_culprit", &m, wall);
            crate::log_info!("{}", m);
        }
    }

    /// Поиск виновника: когда пробы протокола долго плохие — трассировка
    /// до целей проб и метрик по сайтам.
    fn tick_path(&mut self, now: u64, wall: (i64, u32), v4: &ProbeStats, v6: &ProbeStats) {
        if !self.cfg.path_trace.enabled {
            return;
        }
        for fam in ["ipv4", "ipv6"] {
            let st = if fam == "ipv6" { v6 } else { v4 };
            let rate = if st.count > 0 && (fam == "ipv4" || st.available) { st.success_rate } else { -1.0 };
            let mut targets: Vec<IpAddr> = Vec::new();
            for (ip, _) in &self.probe_eps {
                if ip.is_ipv6() == (fam == "ipv6") && !targets.contains(ip) {
                    targets.push(*ip);
                }
            }
            for ip in self.witness.ips_of(fam) {
                if !targets.contains(&ip) {
                    targets.push(ip);
                }
            }
            let (msgs, want) = self.pathc.tick(now, fam, rate, targets.len(), self.ptrun.is_some());
            for m in msgs {
                self.add_event(wall, "path", &m);
                self.journal.record("path_culprit", &m, wall);
                crate::log_info!("{}", m);
            }
            if want {
                let src = if fam == "ipv6" { self.prober.wan_ipv6_src(now) } else { None };
                self.ptrun = crate::pathtrace::Run::start(fam, &targets, src, &self.poller, TOK_PT);
            }
        }
    }

    /// Быстрые таймеры вне такта движка: шейпер отдачи (interval_ms), раунды проб flow watch.
    /// Возвращает, через сколько мс нужен следующий вызов.
    fn tick_fast(&mut self, now: u64) -> u64 {
        let mut next = 1000;
        if let Some(s) = self.shaper.as_mut().filter(|_| !self.deps.blocked("shaper")) {
            if now >= s.next_at {
                let _p = crate::prof::scope("upload_shaper");
                let dev = self.qos.as_ref().map(|q| q.current_device()).unwrap_or_default();
                s.tick(now, &dev);
            }
            next = next.min(s.next_at.saturating_sub(now));
        }
        if let Some(f) = self.fw.as_mut() {
            if now >= f.prober.next_round {
                let _p = crate::prof::scope("flow_watch");
                f.prober.round(now, &self.poller);
            }
            next = next.min(f.prober.next_round.saturating_sub(now));
        }
        if self.gate.is_some() {
            let _p = crate::prof::scope("gate_selector");
            next = next.min(self.tick_gate(now));
        }
        if let Some(h) = self.hub.as_mut() {
            let _p = crate::prof::scope("hub");
            h.tick(now, &self.poller);
            next = next.min(h.next_eval.saturating_sub(now).max(50));
        }
        next
    }

    /// Центр сбора: запустить, остановить или перезапустить по настройкам.
    fn set_hub(&mut self) {
        let want = self.cfg.hub.enabled;
        let same = self.hub.as_ref().map_or(false, |h| h.cfg == self.cfg.hub);
        if want && same {
            return;
        }
        if let Some(mut h) = self.hub.take() {
            h.stop(&self.poller);
        }
        if want {
            let mut h = Hub::new(self.cfg.hub.clone(), TOK_HUB);
            h.start(&self.poller);
            self.hub = Some(h);
        }
    }

    /// Оплата (журнал — один раз) и отчёт на центр сбора после сборки статуса.
    fn tick_report(&mut self, now: u64, unix: i64) {
        self.payment = crate::payment::status(&self.cfg.payment, unix);
        if let Some(p) = self.payment.clone() {
            let year = util::local(unix).year as i64;
            for n in self.pay_done.fresh(&p, &self.cfg.payment.state_file, year) {
                let wall = util::now_wall();
                self.journal.record("payment", &n.text, wall);
                crate::log_info!("{}", n.text);
            }
        }
        let rc = self.cfg.report.clone();
        if !rc.enabled {
            return;
        }
        let r1 = |v: f64| (v * 10.0).round() / 10.0;
        let probe = |s: &ProbeStats| crate::report::Probe { ok: r1(s.success_rate), ms: r1(s.avg_latency_ms), n: s.count, avail: s.available };
        let wall = util::now_wall();
        let mut rep = crate::report::Report {
            router: if rc.name.is_empty() { status::hostname() } else { rc.name.clone() },
            version: crate::variant::version(),
            time: util::rfc3339(wall.0, wall.1),
            state: self.health.phase.into(),
            diagnosis: self.health.diagnosis.into(),
            wan_up: self.wan.up || !self.cfg.wan_monitor.enabled,
            v4: probe(&self.v4),
            v6: probe(&self.v6),
            ..Default::default()
        };
        if rep.router.is_empty() {
            rep.router = "router".into();
        }
        for s in self.downdet.services() {
            if s.state == "down" {
                rep.services.push(s.name.clone());
            }
            if rep.svc.len() < 50 {
                rep.svc.push(crate::report::Svc { name: s.name.clone(), state: s.state.into(), fam: crate::downdet::family(&s.ips).into() });
            }
        }
        for inc in self.journal.status_items(unix) {
            if crate::incidents::diag_type(&inc.typ) || unix - inc.start.0 > 3 * 3600 || rep.incidents.len() >= 20 {
                continue;
            }
            let t = |x: (i64, u32)| if x.0 <= 0 { "0001-01-01T00:00:00Z".to_string() } else { util::rfc3339(x.0, x.1) };
            rep.incidents.push(crate::report::Inc { id: inc.id, typ: inc.typ.clone(), open: inc.open, start: t(inc.start), end: t(inc.end), dur: inc.dur_sec, text: inc.text.clone() });
        }
        if let Some(p) = &self.payment {
            rep.notices = p.notices.clone();
        }
        if let Some((link, backup)) = self.gate.as_ref().and_then(|g| g.link()) {
            rep.link = crate::dgtarget::sanitize_label(&link);
            rep.backup = backup;
        }
        rep.issues = self.issues();
        self.reporter.offer(&rc, rep, now, &mut self.owner);
    }

    /// Текущие проблемы роутера (для центра сбора): то, о чём хозяину нужно знать
    /// сейчас, — кроме фазы WAN, которая и так в отчёте.
    fn issues(&self) -> Vec<crate::report::Issue> {
        let mut v: Vec<crate::report::Issue> = Vec::new();
        let mut add = |level: &str, kind: String, text: String| v.push(crate::report::Issue { level: level.into(), kind, text });
        if self.cfg.wan_monitor.enabled && !self.wan.up {
            add("crit", "wan_down".into(), "WAN: нет связи с провайдером".into());
        } else if matches!(self.health.phase, "CRITICAL" | "WARNING") {
            add(if self.health.phase == "CRITICAL" { "crit" } else { "warn" }, "wan".into(), format!("WAN: {} — {}", self.health.phase, self.health.diagnosis));
        }
        for (l, k, t) in self.phy.issues() {
            add(l, k, t);
        }
        if let Some((link, true)) = self.gate.as_ref().and_then(|g| g.link()) {
            add("warn", "backup".into(), format!("Интернет через резервный канал {}", crate::dgtarget::sanitize_label(&link)));
        }
        if self.downdet.mass() {
            add("warn", "mass".into(), "Массовые сбои соединений к сайтам — вероятна беда маршрутов провайдера".into());
        }
        if let Some(g) = &self.dg {
            if g.saved.state != crate::dnsguard::NORMAL && g.acts() {
                add("warn", "dns_guard".into(), format!("DNS-страховка в общем режиме: {}", g.saved.state));
            }
            if g.v6_all != 0 {
                add("warn", "v6_all".into(), "IPv6 совсем плохой: клиентам отказ во всём IPv6, работают по IPv4".into());
            }
        }
        if let Some(o) = self.pathc.open_first() {
            add("warn", "culprit".into(), o);
        }
        if !self.local.pressure_reason.is_empty() {
            add("warn", "pressure".into(), format!("Роутер перегружен: {}", self.local.pressure_reason));
        }
        if self.local_m.mem_available_mb > 0 && self.local_m.mem_available_mb < 12 {
            add("warn", "mem".into(), format!("Мало памяти: {} МБ доступно", self.local_m.mem_available_mb));
        }
        let t = self.sys.temp_c;
        if t >= 85.0 {
            add("crit", "temp".into(), format!("Температура SoC {t:.0}°C — перегрев, возможен троттлинг"));
        } else if t >= 75.0 {
            add("warn", "temp".into(), format!("Температура SoC {t:.0}°C — горячо"));
        }
        let miss = crate::deps::missing_pkgs(&self.deps.miss);
        if !miss.is_empty() {
            add("warn", "deps".into(), format!("Не хватает пакетов для включённых функций: {}", miss.join(" ")));
        }
        v.truncate(30);
        v
    }

    /// Резервный канал: раунды проб через каждый шлюз, оценка, переключение.
    fn tick_gate(&mut self, now: u64) -> u64 {
        let win = self.cfg.gate_selector.probes.decision_window_sec;
        let g = self.gate.as_mut().unwrap();
        g.finish_round(now, &self.poller, &self.cfg);
        let mut msgs = Vec::new();
        if now >= g.next_eval {
            // статистика проб — только к оценке, не на каждом обороте цикла
            let (g4, g6) = (self.prober.stats("ipv4", win, now).success_rate, self.prober.stats("ipv6", win, now).success_rate);
            msgs = g.evaluate(&self.cfg, now, g4, g6);
        }
        if now >= g.next_probe {
            g.probe_round(&self.cfg, &self.poller, now);
        }
        let next = g.next_eval.min(g.next_probe).saturating_sub(now).max(50);
        let wall = util::now_wall();
        for m in msgs {
            if m.journal != "wan_degradation" {
                self.add_event(wall, "gate", &m.text);
            }
            if !m.journal.is_empty() {
                self.journal.record(m.journal, &m.text, wall);
            }
        }
        next.min(1000)
    }

    /// QoS (дерево qdisc), пути до пиров, наказания провайдера, учитель отдачи.
    fn tick_qos_flows(&mut self, now: u64, wall: (i64, u32), v4: &ProbeStats) {
        if let Some(q) = self.qos.as_mut().filter(|_| !self.deps.blocked("qos")) {
            q.tick(now, wall.0);
            if std::mem::take(&mut q.rebuilt) {
                if let Some(s) = self.shaper.as_mut() {
                    s.reapply();
                }
            }
        }
        let internet_ok = v4.count > 0 && v4.success_rate >= self.cfg.thresholds.warning_enter_success;
        let busy = self.shaper.as_ref().map_or(false, |s| s.busy(now, crate::peers::PEER_BUSY_MS));
        let pe = self.peers.evaluate(&self.cfg.peers, &self.prober, &self.flows, now, wall.0, internet_ok, busy);
        if pe.penalize {
            if let Some(s) = self.shaper.as_mut() {
                s.penalize();
            }
        }
        for m in pe.msgs {
            self.add_event(wall, "peer", &m);
            self.journal.record("peer_path", &m, wall);
            crate::log_info!("{}", m);
        }
        let Some(f) = self.fw.as_mut() else { return };
        let res = f.evaluate(now, wall.0, internet_ok);
        let lm = match f.learn.as_mut() {
            Some(l) => l.tick(now, &mut self.owner),
            None => Vec::new(),
        };
        for m in lm {
            self.add_event(wall, "learn", &m);
            self.journal.record("upload_learn", &m, wall);
            crate::log_info!("{}", m);
        }
        let Some((m, started)) = res else { return };
        if started {
            if let Some(s) = self.shaper.as_mut() {
                s.penalize();
            }
        }
        self.add_event(wall, "flow", &m);
        self.journal.record("flow_penalty", &m, wall);
        crate::log_info!("{}", m);
    }

    /// Настройки DNS-страховки с учётом установленного: без настоящего ip (таблицы
    /// 2100+, uidrange) обхода маршрутом нет — только «другой протокол».
    fn dg_cfg(&self, c: &crate::config::DNSGuardConfig) -> crate::config::DNSGuardConfig {
        let mut c = c.clone();
        if !self.deps.ipfull {
            c.alternatives.retain(|a| a == crate::livecfg::DGR_PROTO);
            if c.alternatives.is_empty() {
                c.alternatives.push(crate::livecfg::DGR_PROTO.into());
            }
            c.relays.clear();
        }
        c
    }

    /// DNS-страховка: по диагнозу уводит клиентов DNS на живой протокол.
    fn tick_dns_guard(&mut self, now: u64, wall: (i64, u32), v4: &ProbeStats, v6: &ProbeStats, v6src: Option<IpAddr>) {
        if self.dg.is_none() {
            if self.cfg.dns_guard.mode == "off" {
                return; // выключенная ничего не стоит
            }
            self.dg = Some(DnsGuard::new(self.dg_cfg(&self.cfg.dns_guard), std::sync::Arc::new(crate::dgsys::RealSys)));
        }
        let th = &self.cfg.thresholds;
        let h = dg::Health {
            v4_ok: v4.count > 0 && v4.success_rate >= th.warning_enter_success,
            v6_ok: v6.available && v6.count > 0 && v6.success_rate >= th.ipv6_healthy_success,
            outage: v4.count > 0 && v4.success_rate == 0.0 && (!v6.available || v6.count == 0 || v6.success_rate == 0.0),
            v6_avail: v6.available,
            wit_v4: self.witness.verdict("ipv4").into(),
            wit_v6: self.witness.verdict("ipv6").into(),
            v6_rate: if v6.available && v6.count > 0 { v6.success_rate } else { 100.0 },
            wit_v6_score: self.witness.score("ipv6"),
        };
        let (phase, diag) = (self.health.phase, self.health.diagnosis);
        let wall_ms = wall.0 * 1000 + (wall.1 / 1_000_000) as i64;
        let mut feed = DgFeed { syn: &self.syn, dnsw: &self.dnsw, owner: &mut self.owner, now };
        let g = self.dg.as_mut().unwrap();
        g.v6src = v6src;
        let msgs = g.tick(wall_ms, phase, diag, &h, &mut feed);
        for m in msgs {
            self.add_event(wall, "dns", &m);
            crate::log_info!("{}", m);
            if m.starts_with("Обход:") || m.starts_with("DNS-страховка (адресно)") {
                continue; // адресный режим: только лог и события — у штрафов свой блок на странице
            }
            let typ = if m.starts_with("DHCP:") { "dhcp_guard" } else { "dns_guard" };
            self.journal.record(typ, &m, wall);
        }
    }

    /// Имя клиента LAN по адресу (down detector).
    pub fn client_name(&self, ip: &str) -> String {
        self.resolver.name_for(ip, &self.acct.mac_of(ip))
    }

    /// dry_run || !enable_limiter || disabled.
    pub fn effective_dry_run(&self) -> bool {
        self.cfg.dry_run || !self.cfg.enable_limiter || self.limiter.disabled
    }

    /// Страницу смотрят (CGI трогает /tmp/cgmon_web_hb).
    pub fn web_active() -> bool {
        std::fs::metadata(crate::util::WEB_HB).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map_or(false, |e| e.as_secs() < 30)
    }

    pub fn run(&mut self) -> Result<(), String> {
        unsafe {
            let h = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::signal(libc::SIGTERM, h);
            libc::signal(libc::SIGINT, h);
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        crate::log_info!("cgmon {} started (config {})", crate::variant::version(), if self.cfg.source.is_empty() { "defaults" } else { &self.cfg.source });
        let mut ready: Vec<(u64, u32)> = Vec::with_capacity(64);
        crate::prof::main_thread();
        while !STOP.load(Ordering::Relaxed) {
            let now = evloop::now_ms();
            self.tick(now);
            let probe_due = { let _p = crate::prof::scope("prober"); self.prober.sweep(&self.cfg, &self.poller, now) };
            let dns_due = { let _p = crate::prof::scope("dns (резолвер)"); self.dns.sweep(&self.poller, now) };
            { let _p = crate::prof::scope("ipowner"); self.owner.tick(&mut self.dns, &self.poller, now); }
            { let _p = crate::prof::scope("path_trace"); self.step_trace(now); }
            let fast = self.tick_fast(now);
            let wait = [self.t_tick.left(now), self.t_tcp.left(now), self.t_udp.left(now), probe_due, dns_due, fast, 1000].into_iter().min().unwrap_or(1000) as i32;
            ready.clear();
            self.poller.wait(wait, |t, e| ready.push((t, e))).map_err(|e| e.to_string())?;
            let now = evloop::now_ms();
            for &(tok, _) in &ready {
                if tok == TOK_LISTEN {
                    let _p = crate::prof::scope("sock");
                    self.accept();
                } else if self.prober.owns(tok) {
                    let _p = crate::prof::scope("prober");
                    self.prober.on_event(tok, &self.poller, now);
                } else if tok == TOK_SYN {
                    let _p = crate::prof::scope("synrtt (AF_PACKET)");
                    self.syn.on_readable(now);
                } else if tok == TOK_DNSW {
                    let _p = crate::prof::scope("dnswatch (AF_PACKET)");
                    self.dnsw.on_readable(now);
                    // обход: адреса доменов — в наборы путей сразу, до первого SYN клиента
                    if !self.dnsw.fresh.is_empty() {
                        let fresh = std::mem::take(&mut self.dnsw.fresh);
                        if let Some(g) = self.dg.as_mut() {
                            let w = util::now_wall();
                            g.route_fresh(w.0 * 1000 + (w.1 / 1_000_000) as i64, &fresh); // часы dns_guard — настенные
                        }
                    }
                } else if tok == TOK_PT {
                    if let Some(r) = self.ptrun.as_mut() {
                        let _p = crate::prof::scope("path_trace");
                        r.on_icmp();
                    }
                } else if self.hub.as_ref().map_or(false, |h| h.owns(tok)) {
                    let poller = &self.poller;
                    let _p = crate::prof::scope("hub");
                    self.hub.as_mut().unwrap().on_event(tok, poller);
                } else if tok == TOK_L2 {
                    let _p = crate::prof::scope("l2watch (AF_PACKET)");
                    self.l2.on_readable(util::now_wall().0);
                } else if tok == TOK_MDNS || tok == TOK_SSDP {
                    let fd = self.mcast.and_then(|(m, s)| if tok == TOK_MDNS { m } else { s });
                    let _p = crate::prof::scope("devid (mDNS/SSDP)");
                    if let (Some(fd), Some(dev)) = (fd, self.resolver.dev.clone()) {
                        crate::devid::recv_all(fd, |src, msg| if tok == TOK_MDNS { dev.on_mdns(&src, msg) } else { dev.on_ssdp(src, msg) });
                    }
                } else if self.gate.as_ref().map_or(false, |g| g.owns(tok)) {
                    let (poller, cfg) = (&self.poller, &self.cfg);
                    let _p = crate::prof::scope("gate_selector");
                    self.gate.as_mut().unwrap().on_event(tok, poller, now, cfg);
                } else if self.fw.as_ref().map_or(false, |f| f.prober.owns(tok)) {
                    let poller = &self.poller;
                    let _p = crate::prof::scope("flow_watch");
                    self.fw.as_mut().unwrap().prober.on_event(tok, poller, now);
                } else if self.witness.owns(tok) {
                    let _p = crate::prof::scope("witness");
                    self.witness.on_event(tok, &self.poller, now);
                } else if self.dns.owns(tok) {
                    let _p = crate::prof::scope("dns (резолвер)");
                    self.dns.on_event(tok, &self.poller);
                } else {
                    let _p = crate::prof::scope("sock");
                    self.conn_ready(tok);
                }
            }
        }
        self.acct.flush();
        if let Some(b) = self.billing.as_mut() {
            b.flush();
        }
        self.phy.flush(evloop::now_ms() as i64);
        crate::log_info!("cgmon stopping (rules stay, the next start adopts them)");
        Ok(())
    }

    fn tick(&mut self, now: u64) {
        let unix = evloop::unix_now();
        let (rs, changed) = self.rt.take(unix);
        if rs.extended != self.extended {
            crate::log_info!("extended monitoring: {}", rs.extended);
        }
        self.extended = rs.extended;
        if changed {
            self.cfg.dry_run = rs.dry_run;
            self.prober.mode = rs.wan_check.clone();
            if let Some(s) = self.shaper.as_mut() {
                s.reconfigure(rs.shaper_on, rs.sustained_kbit, rs.burst_mb, rs.burst_kbit);
            }
            if let Some(f) = self.fw.as_mut() {
                f.set_off(!rs.flow_watch_on);
            }
            if let Some(q) = self.qos.as_mut() {
                q.reconfigure(rs.qos_on, rs.qos_upload_kbit, rs.qos_download_kbit, rs.qos_flow_cap_kbit, rs.qos_flow_cap_down_kbit);
            }
            self.gmaps.set_maps(rs.gate_maps.clone());
            if let Some(b) = self.billing.as_mut() {
                b.on = rs.billing_on;
                b.set_limits(rs.billing_daily_mb, rs.billing_monthly_mb);
            }
        }
        if let Some(nc) = self.rt.take_config() {
            let _p = crate::prof::scope("livecfg");
            self.apply_live_config(nc, now);
        }
        // интервалы могли смениться со страницы
        self.t_tick.every_ms = self.cfg.interval_sec.max(1) as u64 * 1000;
        self.t_tcp.every_ms = self.cfg.probe_interval_sec.max(1) as u64 * 1000;
        self.t_udp.every_ms = self.cfg.udp_probe_interval_sec.max(1) as u64 * 1000;
        if self.t_tcp.due(now) {
            let syn = if self.syn.fd.is_some() { Some(&self.syn) } else { None };
            let _p = crate::prof::scope("prober");
            let s4 = self.prober.skip(&self.cfg, "ipv4", now, syn);
            let s6 = self.prober.skip(&self.cfg, "ipv6", now, syn);
            self.prober.round_tcp(&self.cfg, &self.poller, now, s4, s6);
        }
        if now - self.last_tap >= 5000 {
            let _p = crate::prof::scope("taps (AF_PACKET)");
            self.update_taps(now);
        }
        if self.syn.fd.is_some() {
            let _p = crate::prof::scope("synrtt (AF_PACKET)");
            self.syn.sweep(now);
        }
        if self.t_udp.due(now) {
            let _p = crate::prof::scope("prober");
            self.prober.round_udp(&self.cfg, &self.poller, now);
        }
        if self.t_tick.due(now) {
            self.engine_tick(now, unix);
        }
        // соединения дольше 5 с — закрыть
        self.conns.retain(|_, c| c.deadline > now);
    }

    /// Новый конфиг со страницы: заменить и перенастроить то, что держит копии.
    fn apply_live_config(&mut self, nc: Config, now: u64) {
        util::set_log_level(&nc.log_level);
        let topo_changed = nc.probes != self.cfg.probes || nc.lan_interfaces != self.cfg.lan_interfaces || nc.lan_networks != self.cfg.lan_networks || nc.lan_zones != self.cfg.lan_zones || nc.isolated_zones != self.cfg.isolated_zones || nc.tunnel_networks != self.cfg.tunnel_networks || nc.exclude_networks != self.cfg.exclude_networks || nc.wan != self.cfg.wan;
        let prot_changed = nc.whitelist != self.cfg.whitelist || nc.protected_networks != self.cfg.protected_networks;
        self.acct.set_timing(nc.accounting.refresh_sec, nc.accounting.window_sec);
        self.witness.cfg = nc.witness.clone();
        let dc = self.dg_cfg(&nc.dns_guard);
        if let Some(g) = self.dg.as_mut() {
            g.set_config(dc);
        }
        if let Some(s) = self.shaper.as_mut() {
            s.set_base(nc.upload_shaper.clone());
        }
        if let Some(f) = self.fw.as_mut() {
            f.set_config(nc.flow_watch.clone());
        }
        if let Some(q) = self.qos.as_mut() {
            q.set_opts(nc.qos.clone());
        }
        if let Some(d) = &self.resolver.dev {
            d.set_config(&nc.devices);
        }
        self.l2.set_config(nc.devices.l2_watch || evloop::now_ms() < self.l2_until, nc.devices.l2_probe);
        let hub_changed = nc.hub != self.cfg.hub;
        if nc.storage != self.cfg.storage {
            crate::storage::apply(&nc.storage, &nc.storage_files(), true);
        }
        if let Some(b) = self.billing.as_mut() {
            b.set_config(&nc.billing);
        }
        self.cfg = nc;
        if hub_changed {
            self.set_hub();
        }
        if prot_changed {
            self.protected = protected_nets(&self.cfg);
        }
        self.exclude_nets = crate::netx::parse_nets(&self.cfg.exclude_networks).unwrap_or_default();
        if topo_changed {
            self.refresh_topology(now);
        }
    }

    /// Такт движка (interval_sec): тяжёлый блок (conntrack) — раз в 5 с или
    /// раз в 1 с в расширенном режиме при открытой странице; лёгкий — всегда;
    /// статус — после тяжёлого или раз в секунду, пока страницу смотрят.
    fn engine_tick(&mut self, now: u64, unix: i64) {
        if now - self.last_topo >= 300_000 {
            let _p = crate::prof::scope("topology");
            self.refresh_topology(now);
        }
        let viewed = Self::web_active();
        let heavy_every = if self.extended && viewed { 1000 } else { 5000 };
        let run_heavy = now - self.last_heavy >= heavy_every;
        if run_heavy {
            self.last_heavy = now;
        }
        let run_output = run_heavy || (viewed && now - self.last_output >= 1000);
        if run_output {
            self.last_output = now;
        }
        let wall = util::now_wall();
        if run_heavy {
            self.heavy(now, wall);
            self.sys.own_tick(now);
        }
        {
            let _p = crate::prof::scope("acct (учёт трафика)");
            if self.acct.wan_dev != self.stats_dev.dev {
                self.acct.wan_dev = self.stats_dev.dev.clone();
            }
            self.acct.tick(now, unix);
        }
        let _pb = crate::prof::scope("billing");
        if let Some(msg) = self.billing.as_mut().and_then(|b| b.tick(now, unix)) {
            self.add_event(wall, "billing", &msg);
            self.journal.record("billing_limit", &msg, wall);
            crate::log_info!("billing: {}", msg);
        }
        drop(_pb);
        { let _p = crate::prof::scope("resolver (имена)"); self.resolver.maybe_reload(now, &self.cfg.dns.r#static); }
        self.light_tick(now, unix);
        if run_output {
            let _p = crate::prof::scope("clients (пики)");
            if let Some(snap) = self.snap.take() {
                let top = clients::top_offender(&snap, &self.protected, self.cfg.limits.min_offender_connections).cloned();
                if let Some(m) = self.clients.update_peaks(&snap, top.as_ref(), wall) {
                    self.add_event(wall, "peak", &m);
                }
                self.snap = Some(snap);
            }
            drop(_p);
            { let _p = crate::prof::scope("stats_dev"); self.stats_dev.publish(now); }
            { let _p = crate::prof::scope("status (сборка JSON)"); self.write_status(unix); }
            { let _p = crate::prof::scope("report+payment"); self.tick_report(now, unix); }
        }
    }

    /// Тяжёлый блок: чтение conntrack и динамика клиентов.
    fn heavy(&mut self, now: u64, wall: (i64, u32)) {
        { let _p = crate::prof::scope("plugins"); self.plugins.scan(now); }
        let _pc = crate::prof::scope("conntrack (чтение)");
        let tv: Vec<u16> = self.plugins.watch_ports();
        let ctx = conntrack::Ctx {
            lan_nets: &self.lan_nets,
            wan_ips: &self.router_wan_ips,
            local_ips: &self.router_local_ips,
            ignored_ips: &self.topo.ignored_ips,
            tunnel_nets: &self.tunnel_nets,
            probes: &self.probe_eps,
            mode: &self.cfg.counting.mode,
            tv_ports: &tv,
            want_flows: self.extended || self.cfg.flow_watch.enabled || !self.cfg.peers.list.is_empty(),
        };
        let mut snap = match conntrack::read(&ctx) {
            Ok(s) => s,
            Err(e) => {
                crate::log_debug!("conntrack read error: {}", e);
                Snapshot::default()
            }
        };
        drop(_pc);
        let _pf = crate::prof::scope("peers/wan_flows");
        if let Some(rates) = self.flows.update(&snap.wan_flows, now, &self.cfg.peers) {
            if let Some(f) = self.fw.as_mut() {
                f.observe(now, &rates);
            }
        }
        snap.wan_flows.clear(); // счётчики потоков сохранены в flows — память не держим
        drop(_pf);
        let _p = crate::prof::scope("clients (динамика)");
        if let Some(m) = self.clients.update(&mut snap, now, wall, self.cfg.interval_sec, self.cfg.stat_long_window_sec, self.cfg.client_retention_sec) {
            self.add_event(wall, "alert", &m);
        }
        self.snap = Some(snap);
    }

    /// Лёгкий блок каждого такта: статистика проб, нагрузка, фаза WAN, журнал.
    fn light_tick(&mut self, now: u64, unix: i64) {
        let _pl = crate::prof::scope("light: пробы/нагрузка/wan");
        let w = self.cfg.stat_window_sec;
        let syn = if self.syn.fd.is_some() { Some(&self.syn) } else { None };
        let _ps = crate::prof::scope("light: stats_mode");
        self.v4 = self.prober.stats_mode(&self.cfg, "ipv4", w, now, syn);
        self.v6 = self.prober.stats_mode(&self.cfg, "ipv6", w, now, syn);
        self.udp4 = self.prober.stats_mode(&self.cfg, "udp4", w, now, syn);
        self.udp6 = self.prober.stats_mode(&self.cfg, "udp6", w, now, syn);
        drop(_ps);
        let _ps = crate::prof::scope("light: local");
        self.local_m = self.local.read();
        let ct = self.snap.as_ref().map(|s| (s.usage_pct, s.current, s.max)).unwrap_or((0.0, 0, 0));
        let pressure = self.local.update_pressure(&self.cfg.local, now as i64, &self.local_m, ct);
        drop(_ps);
        let _ps = crate::prof::scope("light: wan");
        let grace = self.in_grace(unix);
        let (v4, v6) = (self.v4.clone(), self.v6.clone());
        let wall = util::now_wall();
        let iface = crate::netx::default_route_interface();
        let ips: Vec<String> = self.router_wan_ips.iter().map(|ip| ip.to_string()).collect();
        let wm = self.cfg.wan_monitor.clone();
        for ev in self.wan.tick(wm.enabled, wm.down_debounce_sec, &wm.incidents_file, wall, &ips, &iface, &v4) {
            self.add_event(wall, "wan", &ev.msg);
            if ev.typ == "iface" {
                self.journal.record("route_change", &ev.msg, wall);
            }
        }
        { let _p = crate::prof::scope("qos+flow_watch"); self.tick_qos_flows(now, wall, &v4); }
        {
            let _p = crate::prof::scope("deps");
            if self.deps.tick(&self.cfg, now) {
                // поставили/сняли пакет: обходу маршрутом — что ему теперь можно
                let dc = self.dg_cfg(&self.cfg.dns_guard);
                if let Some(g) = self.dg.as_mut() {
                    g.set_config(dc);
                }
            }
        }
        if self.cfg.web.embedded {
            crate::webfiles::check(evloop::now_ms() as i64);
        }
        {
            let cfg = &self.cfg;
            crate::storage::recheck(&cfg.storage, evloop::now_ms() as i64, || cfg.storage_files());
        }
        {
            let _p = crate::prof::scope("phy (порты)");
            let up = std::fs::read_to_string("/proc/uptime").ok().and_then(|s| s.split('.').next().and_then(|x| x.parse::<i64>().ok())).unwrap_or(0);
            // настенное время: страница показывает «линк держится N» от up_ms
            for m in self.phy.tick(wall.0 * 1000 + (wall.1 / 1_000_000) as i64, up) {
                crate::log_info!("phy: {}", m);
                self.journal.record("phy", &m, wall);
            }
        }
        {
            let _p = crate::prof::scope("gate_maps");
            let wms = wall.0 * 1000 + (wall.1 / 1_000_000) as i64;
            // карты шлюзов: ip rule и таблицы (с busybox ip — таблицы ≤ 255)
            let maps = self.gmaps.tick(wms, &self.cfg.dns_guard.relays);
            for m in maps {
                crate::log_info!("{}", m);
                self.add_event(wall, "gate", &m);
            }
        }
        drop(_ps);
        {
            let _p = crate::prof::scope("l2watch (AF_PACKET)");
            // включён в настройках или кнопкой на 30 минут
            let want = self.cfg.devices.l2_watch || now < self.l2_until;
            if want != self.l2.on {
                self.l2.set_config(want, self.cfg.devices.l2_probe);
                self.last_tap = 0; // сокет открыть/закрыть сразу
                if !want {
                    crate::log_info!("l2watch: 30 minutes are over — off");
                }
            }
            self.l2.tick(wall.0);
            self.l2.expire(wall.0);
        }
        if now - self.dev_saved >= 600_000 {
            let _p = crate::prof::scope("devid (mDNS/SSDP)");
            self.dev_saved = now;
            if let Some(d) = &self.resolver.dev {
                d.maintain(&self.cfg.devices.vendor_cache);
            }
        }
        // down detector: сервисы, не отвечающие клиентам при живом WAN — только журнал
        let _pd = crate::prof::scope("down_detector");
        let msgs = {
            let (resolver, acct) = (&self.resolver, &self.acct);
            let cn = |ip: &str| resolver.name_for(ip, &acct.mac_of(ip));
            self.downdet.evaluate(now, wall, self.health.phase == "NORMAL", &self.syn, &self.dnsw, &mut self.owner, &cn)
        };
        for m in msgs {
            crate::log_info!("down detector: {}", m);
            let typ = if m.starts_with("Массовые сбои") { "mass_failure" } else { "service_down" };
            self.journal.record(typ, &m, wall);
        }
        drop(_pd);
        let _ps = crate::prof::scope("light: health");
        let (old_phase, old_diag) = (self.health.phase, self.health.diagnosis);
        self.health.evaluate(&self.cfg.thresholds, now as i64, grace, &v4, &v6, pressure);
        let (mut lan, mut rtr, mut inc, mut top_ip, mut top_wan, mut svc) = (0, 0, 0, "-".to_string(), 0, 0);
        if let Some(s) = &self.snap {
            lan = s.lan_to_wan;
            rtr = s.router_own;
            inc = s.incoming_forwarded;
            svc = s.router_own_probe;
            if let Some(t) = clients::top_offender(s, &self.protected, self.cfg.limits.min_offender_connections) {
                top_ip = t.ip.clone();
                top_wan = clients::limiter_score(t);
            }
        }
        drop(_ps);
        let v6src = { let _p = crate::prof::scope("light: wan_ipv6_src"); self.prober.wan_ipv6_src(now) };
        { let _p = crate::prof::scope("dns_guard (+обход)"); self.tick_dns_guard(now, wall, &v4, &v6, v6src); }
        let _pw = crate::prof::scope("witness");
        // метрики по сайтам (наблюдение): расхождение с диагнозом — в журнал
        let (wmsgs, wchanged) = self.witness.tick(now, wall.0, v6.available, self.health.diagnosis, &self.syn, &self.dnsw, &mut self.owner, &mut self.dns, &self.poller, v6src);
        if wchanged {
            self.syn.set_skip_witness(&self.witness.ips());
        }
        for m in wmsgs {
            self.journal.record("witness", &m, wall);
            crate::log_info!("{}", m);
        }
        drop(_pw);
        { let _p = crate::prof::scope("path_trace"); self.tick_path(now, wall, &v4, &v6); }
        let _pj = crate::prof::scope("journal+limiter");
        let sample = Sample {
            now: wall,
            state: self.health.phase.into(),
            diagnosis: self.health.diagnosis.into(),
            wan_total: lan + rtr + inc,
            lan_to_wan: lan,
            router_own: rtr,
            service: svc,
            top_ip: top_ip.clone(),
            top_wan,
            v4_success: v4.success_rate,
            v4_count: v4.count,
            v6_success: v6.success_rate,
            v6_count: v6.count,
            v6_available: v6.available,
            wan_up: self.wan.up || !wm.enabled,
            post_outage: self.wan.post_up_grace(wm.enabled, wm.post_up_grace_sec, wall.0),
            pressure: self.local.pressure_reason.clone(),
        };
        self.journal.tick(&sample);
        // ограничитель: самому жадному — лимит новых соединений
        if let Some(snap) = self.snap.take() {
            let top = clients::top_offender(&snap, &self.protected, self.cfg.limits.min_offender_connections).cloned();
            let wm2 = &self.cfg.wan_monitor;
            let view = limiter::View {
                cfg: &self.cfg,
                phase: self.health.phase,
                diagnosis: self.health.diagnosis,
                grace,
                v4_success: v4.success_rate,
                v4_count: v4.count,
                v6_healthy: crate::health::v6_healthy(&self.cfg.thresholds, &v6),
                post_switch: self.wan.post_up_grace(wm2.enabled, wm2.post_up_grace_sec, wall.0) || self.gate.as_ref().map_or(false, |g| g.post_switch_grace(&self.cfg, now)),
            };
            let (ev, reset) = self.limiter.apply(&view, &snap, top.as_ref(), unix);
            let rev = self.limiter.router_limit(&view, &snap, unix);
            if reset {
                self.health.set_normal();
            }
            for (t, m) in ev.iter().chain(rev.iter()) {
                self.add_event(wall, t, m);
                if matches!(t.as_str(), "limit" | "relax" | "dry_run_limit") {
                    self.journal.note_action(m);
                }
            }
            self.snap = Some(snap);
        }
        if !self.effective_dry_run() && unix - self.limiter.last_ensure > 60 {
            if let Err(e) = limiter::nft_ensure(&self.cfg.nft.table) {
                crate::log_err!("periodic nft ensure failed: {}", e);
            }
            self.limiter.last_ensure = unix;
        }
        if unix - self.limiter.last_hard >= 300 && !self.deps.blocked("hard") {
            if let Err(e) = limiter::hard_apply(&self.cfg, self.limiter.router_host_limit) {
                crate::log_err!("hard-limit refresh failed: {}", e);
            }
            self.limiter.last_hard = unix;
        }
        if old_phase != self.health.phase || old_diag != self.health.diagnosis {
            if self.health.diagnosis == "LOCAL_PRESSURE" && !self.local.pressure_reason.is_empty() {
                let m = format!("local pressure: {}", self.local.pressure_reason);
                self.add_event(wall, "alert", &m);
            }
            let m = format!("{}/{} wan={} lan={} rtr={} inc={} top={}({}) v4={:.1}%", self.health.phase, self.health.diagnosis, lan + rtr + inc, lan, rtr, inc, top_ip, top_wan, v4.success_rate);
            self.add_event(wall, "state", &m);
            let (cur, max) = self.snap.as_ref().map(|s| (s.current, s.max)).unwrap_or((0, 0));
            crate::log_info!("state={} diagnosis={} conntrack={}/{} wan_total={} lan_to_wan={} router_own={} incoming={} ipv4_probe={:.1}% ipv6_probe={:.1}% top_host={} top_wan={}", self.health.phase, self.health.diagnosis, cur, max, lan + rtr + inc, lan, rtr, inc, v4.success_rate, v6.success_rate, top_ip, top_wan);
        }
    }

    /// Событие в ленту статуса и в metrics JSONL.
    pub fn add_event(&mut self, t: (i64, u32), typ: &str, msg: &str) {
        self.events.insert(0, (t, typ.to_string(), msg.to_string()));
        self.st_cache.touch();
        self.events.truncate(100);
        let mut j = J::new();
        j.obj().key("event").str(typ).key("message").str(msg).key("time").str(&util::rfc3339_secs(t.0)).key("type").str("event").end_obj();
        crate::incidents::append_jsonl(&self.cfg.paths.metrics_file, &j.b, 5 * 1024 * 1024);
    }

    pub fn in_grace(&self, unix: i64) -> bool {
        unix - self.started < self.cfg.startup_grace_sec
    }

    fn write_status(&mut self, unix: i64) {
        self.out.clear();
        status::build(self, unix);
        if let Err(e) = util::write_atomic(&self.cfg.paths.status_file, self.out.b.as_bytes(), 0o644) {
            crate::log_err!("status: {}: {}", self.cfg.paths.status_file, e);
        }
    }

    pub fn out(&mut self) -> &mut J {
        &mut self.out
    }

    fn accept(&mut self) {
        loop {
            let fd = unsafe { libc::accept4(self.listen_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if fd < 0 {
                return;
            }
            if self.conns.len() >= 32 {
                unsafe { libc::close(fd) };
                continue;
            }
            let tok = self.next_conn;
            self.next_conn += 1;
            if self.poller.add(fd, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32, tok).is_err() {
                unsafe { libc::close(fd) };
                continue;
            }
            self.conns.insert(tok, Conn { fd, buf: Vec::new(), deadline: evloop::now_ms() + 5000 });
        }
    }

    fn conn_ready(&mut self, tok: u64) {
        let Some(c) = self.conns.get_mut(&tok) else { return };
        let mut eof = false;
        let mut tmp = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(c.fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
            if n > 0 {
                c.buf.extend_from_slice(&tmp[..n as usize]);
                if c.buf.len() > MAX_UPLOAD * 2 + 4096 {
                    self.conns.remove(&tok);
                    return;
                }
                continue;
            }
            if n == 0 {
                eof = true;
            }
            break;
        }
        // запрос — одна строка JSON (Go json.Encoder дописывает \n) или до EOF
        let Some(end) = c.buf.iter().position(|&b| b == b'\n').or(if eof { Some(c.buf.len()) } else { None }) else { return };
        let req = String::from_utf8_lossy(&c.buf[..end]).into_owned();
        let fd = c.fd;
        let reply = self.handle(&req);
        write_all(fd, reply.as_bytes());
        write_all(fd, b"\n");
        self.poller.del(fd);
        self.conns.remove(&tok);
    }

    /// Запрос сокета → ответ (команды как в Go api.go).
    pub fn handle(&mut self, req: &str) -> String {
        let v = match parse_json(req) {
            Ok(v) => v,
            Err(_) => return err_json("bad request"),
        };
        let cmd = v.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
        let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let map = |k: &str| match v.get(k) {
            Some(Value::Map(m)) => m.clone(),
            _ => Vec::new(),
        };
        let now = evloop::unix_now();
        match cmd {
            "status" => {
                self.write_status(now);
                self.out.b.clone()
            }
            "hist" => {
                // история графика страницы: до часа — точки по 2 с, дольше — по минуте
                let sec = v.get("sec").and_then(|x| x.as_f64()).unwrap_or(600.0) as i64;
                let w = util::now_wall();
                self.acct.chart.json(sec, w.0 * 1000 + (w.1 / 1_000_000) as i64)
            }
            "free_nets" => {
                // свой список бесплатных сетей со страницы: в tasix_file, источник — file
                let cfg = self.cfg.clone();
                if let Err(e) = self.rt.check_password(&cfg, &password, now) {
                    return err_json(&e);
                }
                let text = v.get("text").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let Some(b) = self.billing.as_mut() else { return err_json("billing is not configured") };
                let n = match b.upload(&text, now) {
                    Ok(n) => n,
                    Err(e) => return err_json(&e),
                };
                if cfg.billing.tasix_url != crate::billing::FILE_SRC {
                    let cm = vec![("billing.tasix_url".to_string(), Value::Str(crate::billing::FILE_SRC.into()))];
                    if let Err(e) = self.rt.set(&cfg, &[], &cm, &password, now) {
                        return err_json(&e);
                    }
                }
                format!("{{\"ok\":true,\"nets\":{n}}}")
            }
            "pkg_install" => {
                // кнопка «установить» на странице: apk/opkg в фоне, итог — status.pkg_install
                let cfg = self.cfg.clone();
                if let Err(e) = self.rt.check_password(&cfg, &password, now) {
                    return err_json(&e);
                }
                let want: Vec<String> = v.get("text").and_then(|x| x.as_str()).unwrap_or("").split_whitespace().map(String::from).collect();
                match self.deps.inst.start(&want, &cfg) {
                    Ok(p) => {
                        crate::log_info!("deps: установка со страницы: {}", p.join(" "));
                        let mut r = String::from("{\"ok\":true,\"pkgs\":");
                        crate::value::json_str(&mut r, &p.join(" "));
                        r.push('}');
                        r
                    }
                    Err(e) => err_json(&e),
                }
            }
            "l2_scan" | "l2_open" | "l2_close" => {
                // ловец устройств: скан типовых сетей и доступ к пойманному устройству
                let cfg = self.cfg.clone();
                if let Err(e) = self.rt.check_password(&cfg, &password, now) {
                    return err_json(&e);
                }
                let text = v.get("text").and_then(|x| x.as_str()).unwrap_or("").to_string();
                match cmd {
                    "l2_scan" => match self.l2.scan(now) {
                        Ok(n) => format!("{{\"ok\":true,\"nets\":{n}}}"),
                        Err(e) => err_json(&e),
                    },
                    "l2_close" => match self.l2.close(&text) {
                        Ok(()) => "{\"ok\":true}".to_string(),
                        Err(e) => err_json(&e),
                    },
                    _ => match self.l2.open(&text, now) {
                        Ok(a) => format!("{{\"ok\":true,\"access\":{}}}", L2Watch::access_json(&a)),
                        Err(e) => err_json(&e),
                    },
                }
            }
            "top" => {
                self.write_status(now);
                let v = parse_json(&self.out.b).unwrap_or(Value::Null);
                let mut s = String::new();
                match v.get("top") {
                    Some(t) => t.to_json(&mut s),
                    None => s.push_str("[]"),
                }
                s
            }
            "heap" => crate::cli::mem_json(),
            "hub_forget" => {
                // центр сбора: убрать роутер (с паролем) — переустановка, выключен навсегда
                let cfg = self.cfg.clone();
                if let Err(e) = self.rt.check_password(&cfg, &password, now) {
                    return err_json(&e);
                }
                let name = v.get("text").and_then(|x| x.as_str()).unwrap_or("").to_string();
                match self.hub.as_mut() {
                    None => err_json("this router is not a hub"),
                    Some(h) => {
                        if h.forget(&name, crate::util::now_wall().0 * 1000, "убран со страницы") {
                            "{\"ok\":true}".to_string()
                        } else {
                            err_json("no such router")
                        }
                    }
                }
            }
            "l2_on" => {
                // кнопка на странице: ловец устройств на 30 минут (только слушает и будит LAN — без пароля)
                self.l2_until = evloop::now_ms() + 30 * 60_000;
                "{\"ok\":true}".to_string()
            }
            "extras" => {
                // кнопка на странице: порты и TOP CPU/RAM на 5 минут (ничего не меняет — без пароля)
                self.extras_until = evloop::now_ms() + 300_000;
                self.st_cache.touch_ports();
                "{\"ok\":true}".to_string()
            }
            "prof" => crate::prof::report(),
            "disable" => {
                self.limiter.disabled = true;
                match limiter::nft_clear(&self.cfg.nft.table) {
                    Ok(()) => crate::log_info!("cgmon disabled: automatic limiter stopped, cgmon nft table removed"),
                    Err(e) => crate::log_err!("disable clear nft failed: {}", e),
                }
                "{\"ok\":\"disabled\"}".to_string()
            }
            "sites" => {
                let now_ms = evloop::now_ms();
                let mut j = J::new();
                let (resolver, acct) = (&self.resolver, &self.acct);
                let names = |ip: &str| resolver.name_for(ip, &acct.mac_of(ip));
                self.downdet.sites_json(&mut j, &self.syn, &self.dnsw, &mut self.owner, now_ms, &names);
                j.b
            }
            "probes" => {
                let mut j = J::new();
                j.obj();
                for (k, st) in [("ipv4", &self.v4), ("ipv6", &self.v6), ("udp4", &self.udp4), ("udp6", &self.udp6)] {
                    j.key(k);
                    crate::prober::stats_json(&mut j, &status::rounded(st));
                }
                j.key("recent").arr();
                for r in self.prober.recent(20) {
                    crate::prober::result_json(&mut j, r);
                }
                j.end_arr().end_obj();
                j.b
            }
            "config_get" => {
                // поля cgmon.yaml для страницы (без путей, паролей, команд)
                // пояснения: из своего cgmon.yaml, иначе из встроенного справочника
                let mut hints = std::fs::read_to_string(&self.cfg.source).map(|t| livecfg::hints(&t)).unwrap_or_default();
                for h in livecfg::hints(config::REFERENCE) {
                    if !hints.iter().any(|x| x.0 == h.0) {
                        hints.push(h);
                    }
                }
                let mut j = J::new();
                j.obj().key("fields").arr();
                self.cfg.walk("", &mut |p, f| {
                    if livecfg::is_main(p) || livecfg::is_hidden(p) {
                        return;
                    }
                    let kind = match f {
                        config::Field::Bool(_) => "bool",
                        config::Field::Int(_) => "int",
                        config::Field::Float(_) => "float",
                        config::Field::Str(_) => "string",
                        config::Field::StrList(_) => "list",
                        config::Field::IntList(_) => "intlist",
                        config::Field::Complex => return,
                    };
                    let mut s = String::new();
                    config::field_json(f, &mut s);
                    j.obj().key("path").str(p).key("kind").str(kind).key("value").raw(&s);
                    if let Some((_, h)) = hints.iter().find(|(k, _)| k == p) {
                        j.key("hint").str(h);
                    }
                    j.end_obj();
                });
                // пояснения к основным настройкам (окно по нажатию на название на странице)
                j.end_arr().key("hints").obj();
                for (p, h) in &hints {
                    if livecfg::is_main(p) || matches!(p.as_str(), "dry_run" | "wan_check" | "qos.enabled" | "upload_shaper.enabled" | "flow_watch.enabled" | "billing.enabled") {
                        j.key(p).str(h);
                    }
                }
                j.end_obj().key("lan");
                topo::lan_choices_json(&self.cfg, &mut self.netifd, evloop::now_ms(), &mut j);
                j.end_obj();
                j.b
            }
            "set" => {
                let cfg = self.cfg.clone();
                match self.rt.set(&cfg, &map("set"), &map("config"), &password, now) {
                    Ok(()) => {
                        let mut j = J::new();
                        j.obj().key("ok").bool(true).key("runtime");
                        self.rt.status_json(&cfg, now, &mut j);
                        j.end_obj();
                        j.b
                    }
                    Err(e) => err_json(&e),
                }
            }
            _ => err_json("unknown command"),
        }
    }
}

fn err_json(msg: &str) -> String {
    let mut s = String::from("{\"error\":");
    crate::value::json_str(&mut s, msg);
    s.push('}');
    s
}

fn write_all(fd: i32, mut b: &[u8]) {
    let deadline = evloop::now_ms() + 2000;
    while !b.is_empty() && evloop::now_ms() < deadline {
        let n = unsafe { libc::write(fd, b.as_ptr() as *const libc::c_void, b.len()) };
        if n > 0 {
            b = &b[n as usize..];
        } else {
            let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            unsafe { libc::poll(&mut p, 1, 200) };
        }
    }
}

/// Клиент сокета: запрос → ответ (CLI и CGI).
pub fn request(socket: &str, req: &str, timeout_ms: i32) -> Result<String, String> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as u16;
    for (i, c) in socket.as_bytes().iter().take(sa.sun_path.len() - 1).enumerate() {
        sa.sun_path[i] = *c as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + socket.len() + 1) as u32;
    if unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, len) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e.to_string());
    }
    let tv = libc::timeval { tv_sec: (timeout_ms / 1000) as _, tv_usec: ((timeout_ms % 1000) * 1000) as _ };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
    }
    write_all(fd, req.as_bytes());
    write_all(fd, b"\n");
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n as usize]);
        if out.last() == Some(&b'\n') {
            break;
        }
    }
    unsafe { libc::close(fd) };
    if out.is_empty() {
        return Err("нет ответа".into());
    }
    Ok(String::from_utf8_lossy(&out).trim_end().to_string())
}

/// Данные адресного режима: рукопожатия клиентов, имена из DNS, владельцы адресов.
struct DgFeed<'a> {
    syn: &'a SynRtt,
    dnsw: &'a DnsWatch,
    owner: &'a mut IpOwner,
    now: u64,
}

impl dg::Feed for DgFeed<'_> {
    fn handshakes(&self, window_ms: u64) -> Vec<(IpAddr, bool, f64)> {
        self.syn.since(self.now.saturating_sub(window_ms)).map(|o| (o.ip, o.ok, o.rtt as f64)).collect()
    }
    fn name_of(&self, ip: &IpAddr) -> Option<String> {
        self.dnsw.name_of(ip).map(String::from)
    }
    fn each_pair(&self, f: &mut dyn FnMut(&IpAddr, &str)) {
        for (ip, n) in self.dnsw.pairs() {
            f(ip, n);
        }
    }
    fn owner(&mut self, ip: &IpAddr) -> Option<(String, String)> {
        match self.owner.get(ip, self.now) {
            Some(i) => Some((i.asn.clone(), i.brand.clone())),
            None => {
                self.owner.want(*ip, self.now);
                None
            }
        }
    }
}
