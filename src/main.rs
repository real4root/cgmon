//! cgmon 2.x (Rust). План переноса — ROADMAP-2.md; контракты (cgmon.yaml,
//! JSON статуса, status.html, CGI, сокет, отчёт на центр) — как в Go 1.3.x.

mod acct;
mod variant;
mod luci;
mod webfiles;
mod chart;
mod storage;
mod billing;
mod cgi;
mod cli;
mod clients;
mod config;
mod config_gen;
mod conntrack;
mod daemon;
mod devid;
mod deps;
mod pkgsetup;
mod dgroute;
mod dgsys;
mod dgtarget;
mod dgv6;
mod dnsguard;
mod dns;
mod dnswatch;
mod downdet;
mod evloop;
mod flowwatch;
mod gatemap;
mod gatesel;
mod health;
mod help;
mod hub;
#[allow(dead_code)] // отчёт на центр — этап 9
mod hubcrypt;
mod incidents;
mod ipowner;
mod isolation;
mod l2watch;
mod json;
mod limiter;
mod livecfg;
mod local;
mod netx;
mod pathtrace;
mod phywatch;
mod plugins;
mod prof;
mod payment;
mod peers;
mod nfnl;
mod probe;
mod resolver;
mod prober;
mod qos;
mod report;
mod runtime;
mod status;
mod synrtt;
mod sysinfo;
mod topo;
mod uplearn;
mod upshaper;
mod util;
mod value;
mod wanmon;
mod witness;
mod wizard;
mod yamledit;

#[cfg(feature = "prof")]
#[global_allocator]
static ALLOC: prof::Alloc = prof::Alloc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() {
    print!("{}", help::short());
}

fn main() {
    // команды CLI — как обычные утилиты: вывод в закрытый канал (| head) — тихий выход,
    // а не паника записи; демон потом сам игнорирует SIGPIPE (daemon::run)
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    // часовой пояс OpenWrt: /etc/TZ (POSIX-строка); musl без TZ показывал UTC
    if std::env::var_os("TZ").is_none() {
        if let Ok(tz) = std::fs::read_to_string("/etc/TZ") {
            if !tz.trim().is_empty() {
                std::env::set_var("TZ", tz.trim());
            }
        }
    }
    util::init_readonly();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    match raw.first().map(|s| s.as_str()) {
        Some("-h" | "--help" | "help") => {
            usage();
            return;
        }
        Some("--help-advanced" | "help-advanced") => {
            print!("{}", help::advanced());
            return;
        }
        Some("-v" | "--version" | "version") => {
            println!("cgmon {}", variant::version());
            return;
        }
        Some("--uninstall") => {
            std::process::exit(webfiles::uninstall());
        }
        _ => {}
    }
    // -config/--config в любой позиции (как в Go)
    let mut explicit = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if (raw[i] == "-config" || raw[i] == "--config") && i + 1 < raw.len() {
            explicit = Some(raw[i + 1].clone());
            i += 2;
            continue;
        }
        rest.push(raw[i].clone());
        i += 1;
    }
    let cmd = rest.first().filter(|s| !s.starts_with('-')).cloned().unwrap_or_else(|| "daemon".into());
    let arg1 = rest.get(1).cloned();
    let file_arg = if matches!(cmd.as_str(), "config-test" | "config-dump") { arg1.clone() } else { None };
    let path = config::find(explicit.as_deref().or(file_arg.as_deref()));
    // мастер установки: флаг в любом месте
    let wiz = rest.iter().find_map(|a| match a.as_str() {
        "--install" => Some(None),
        "--install-min" => Some(Some(wizard::Mode::Min)),
        "--install-basic" => Some(Some(wizard::Mode::Basic)),
        "--advanced-install" | "--install-full" => Some(Some(wizard::Mode::Full)),
        _ => None,
    });
    if let Some(m) = wiz {
        let p = explicit.clone().unwrap_or_else(|| if path.is_empty() { "/etc/cgmon/cgmon.yaml".into() } else { path.clone() });
        std::process::exit(wizard::run(&p, m));
    }
    let load = || config::load(&path).map_err(|e| {
        eprintln!("{e}");
        1
    });
    let code = match cmd.as_str() {
        "status" | "top" => match load() {
            Ok(c) => {
                let raw = cli::ask(&c, "status").or_else(|_| std::fs::read_to_string(&c.paths.status_file).map_err(|e| e.to_string()));
                match raw {
                    Ok(r) if cmd == "status" => {
                        cli::print_status(&r);
                        0
                    }
                    Ok(r) => {
                        cli::print_top(&r);
                        0
                    }
                    Err(e) => {
                        eprintln!("cgmon {cmd}: {e}");
                        1
                    }
                }
            }
            Err(c) => c,
        },
        "probes" | "heap" | "sites" | "prof" => match load().and_then(|c| cli::ask(&c, &cmd).map_err(|e| {
            eprintln!("cgmon {cmd}: {e}");
            1
        })) {
            Ok(r) if cmd == "sites" => {
                cli::print_sites(&r);
                0
            }
            Ok(r) => {
                println!("{r}");
                0
            }
            Err(c) => c,
        },
        "ports" => {
            // порты: кабель, скорость, сеть (то же, что блок на странице)
            let mut j = json::J::new();
            let wan = load().map(|c| crate::topo::detect(&c, &[]).wan_devs).unwrap_or_default();
            if !sysinfo::ports_json(&mut j, &sysinfo::netifd_dump(), &wan) {
                j.raw("[]");
            }
            println!("{}", j.b);
            0
        }
        "nft-status" => load().map(|c| cli::nft_status(&c)).unwrap_or_else(|c| c),
        "disable" => load().map(|c| cli::disable(&c)).unwrap_or_else(|c| c),
        "telegram-test" => load().map(|c| cli::telegram_test(&c)).unwrap_or_else(|c| c),
        "deps" => load().map(|c| cli::deps(&c, &rest[1..])).unwrap_or_else(|c| c),
        "status-json" => match config::load(&path).and_then(|c| daemon::request(&c.paths.socket, "{\"cmd\":\"status\"}", 5000)) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("cgmon status: {e}");
                1
            }
        },
        "daemon" | "run" => match daemon::Daemon::new(&path).and_then(|mut d| d.run()) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("cgmon: {e}");
                1
            }
        },
        "cgi-set" => cgi::set(&path),
        "cgi-status" => {
            // путь к файлу статуса — последним аргументом (как в Go)
            let sp = rest.last().filter(|x| x.as_str() != "cgi-status").cloned().unwrap_or_else(|| config::load(&path).map(|c| c.paths.status_file).unwrap_or_else(|_| "/var/run/cgmon.status.json".into()));
            isolation::cgi_status(&sp)
        }
        "cgi-filter" => isolation::cgi_filter(),
        "cgi-hist" => cgi::hist(&path),
        // страница LuCI «Службы → cgmon» (через rpcd)
        "luci-get" => luci::get(&path),
        "luci-set" => luci::set(&path, arg1.as_deref().unwrap_or("")),
        "cgi-tenant" => {
            // для CGI-скриптов: код 0 — запрос из выделенной подсети
            if cgi::is_tenant() {
                0
            } else {
                1
            }
        }
        "config-test" => match config::load(&path).and_then(|c| livecfg::validate(&c).map(|_| c)) {
            Ok(c) => {
                println!("{path}: ok");
                deps::print(&mut std::io::stderr(), &c);
                0
            }
            Err(e) => {
                eprintln!("{path}: {e}");
                1
            }
        },
        "config-dump" => match config::load(&path) {
            Ok(c) => {
                let mut s = String::new();
                c.dump_json(&mut s);
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        "hints-dump" => {
            // подсказки из комментариев (сверка с Go cfgHintsBytes)
            let text = match &arg1 {
                Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
                None => config::REFERENCE.to_string(),
            };
            let mut s = String::from("{");
            for (i, (k, v)) in livecfg::hints(&text).iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                value::json_str(&mut s, k);
                s.push(':');
                value::json_str(&mut s, v);
            }
            s.push('}');
            println!("{s}");
            0
        }
        "trace" => trace_cli(&rest[1..]),
        "incidents-dump" => {
            // журнал для статуса (сверка с Go)
            let j = incidents::Journal::new(arg1.as_deref().unwrap_or(""));
            let mut out = json::J::new();
            out.arr();
            for inc in j.status_items(evloop::unix_now()) {
                inc.to_json(&mut out);
            }
            out.end_arr();
            println!("{}", out.b);
            0
        }
        _ => {
            usage();
            2
        }
    };
    std::process::exit(code);
}

/// cgmon trace <ip>…: трассировки, владельцы узлов и разбор (как в Go).
fn trace_cli(ips: &[String]) -> i32 {
    let targets: Vec<std::net::IpAddr> = ips.iter().filter_map(|s| s.parse().ok()).collect();
    if targets.is_empty() {
        eprintln!("cgmon trace <ip> [ip…]");
        return 2;
    }
    let fam: &'static str = if targets[0].is_ipv6() { "ipv6" } else { "ipv4" };
    let Ok(mut poller) = evloop::Poller::new() else { return 1 };
    let mut dnsc = dns::Client::new(4 << 48);
    let mut owner = ipowner::IpOwner::new(1 << 40);
    let mut pr = prober::Prober::new(&config::defaults(), 1 << 48);
    let src = if fam == "ipv6" { pr.wan_ipv6_src(evloop::now_ms()) } else { None };
    let Some(mut run) = pathtrace::Run::start(fam, &targets, src, &poller, 6 << 48) else { return 1 };
    loop {
        let now = evloop::now_ms();
        dnsc.sweep(&poller, now);
        owner.tick(&mut dnsc, &poller, now);
        if run.step(now, &mut owner) {
            break;
        }
        let mut ev = Vec::new();
        let _ = poller.wait(50, |t, _| ev.push(t));
        for t in ev {
            if t == 6 << 48 {
                run.on_icmp();
            } else if dnsc.owns(t) {
                dnsc.on_event(t, &poller);
            }
        }
    }
    let now = evloop::now_ms();
    let mut own = |ip: &str| ip.parse::<std::net::IpAddr>().ok().and_then(|a| owner.get(&a, now)).map(|i| (i.asn.clone(), i.brand.clone()));
    for r in &run.results {
        let st = if r.bad() { "ПЛОХО" } else if r.good() { "хорошо" } else { "?" };
        println!("== {} {} AS{}: дошло {}/{} — {}", r.ip, r.owner, r.asn, r.reached, r.sent, st);
        for (ttl, h) in &r.hops {
            let (asn, name) = own(h).unwrap_or_default();
            println!("  {:2}  {:<40} AS{:<7} {}", ttl, h, asn, name);
        }
    }
    match pathtrace::analyze(fam, &run.results, &mut own) {
        Some(v) => println!("\n{}", v.text),
        None => println!("\nобщего виновника нет (нужно ≥2 плохих цели разных владельцев и ≥1 хорошая)"),
    }
    let _ = &mut poller;
    run.close(&poller);
    0
}
