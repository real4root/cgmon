//! Доп. сведения для страницы (перенос sysinfo.go): канал основного шлюза
//! (`wan_link`: интерфейс netifd, адреса, время работы — ubus раз в 30 с) и
//! система (`sys_extra`: температура SoC, CPU и RSS самого cgmon, процессы,
//! больше всех нагружающие CPU и занимающие память — обход /proc раз в 5 с).

use crate::json::J;
use std::collections::HashMap;

const TOP_CPU: usize = 3;
const TOP_RAM: usize = 6;
const PROC_EVERY: u64 = 5000;

#[derive(Clone, Default)]
struct Link {
    iface: String,
    device: String,
    uptime: i64,
    ipv4: String,
    ipv6: String,
}

#[derive(Default)]
pub struct SysInfo {
    link: Option<Link>,
    link_at: u64,
    link_dev: String,
    cpu_ticks: u64,
    cpu_at: u64,
    cpu: f64,
    proc_ticks: HashMap<u32, u64>,
    proc_at: u64,
    top: Vec<(String, f64)>,
    top_ram: Vec<(String, f64)>,
    nf: Vec<NfIf>,
    nf_at: u64,
    /// средняя нагрузка самого cgmon, % одного ядра (≈10 мин) и с какого момента она есть
    pub own_avg: f64,
    own_since: u64,
    /// «слабый» роутер: cgmon в среднем грузит процессор больше WEAK_ON %
    pub weak: bool,
    /// последняя температура SoC, °C (0 — нет датчика)
    pub temp_c: f64,
}

/// Порог «слабого» роутера и возврата (разрыв — чтобы не переключаться туда-сюда).
const WEAK_ON: f64 = 10.0;
const WEAK_OFF: f64 = 7.0;
/// Окно средней нагрузки cgmon.
const OWN_WINDOW_MS: f64 = 600_000.0;

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// (имя, utime+stime, RSS в страницах) из /proc/<pid>/stat.
pub fn proc_stat(s: &str) -> Option<(String, u64, u64)> {
    let (i, j) = (s.find('(')?, s.rfind(')')?);
    if j < i {
        return None;
    }
    let f: Vec<&str> = s[j + 1..].split_whitespace().collect();
    if f.len() < 13 {
        return None;
    }
    let t = f[11].parse::<u64>().unwrap_or(0) + f[12].parse::<u64>().unwrap_or(0);
    let rss = f.get(21).and_then(|x| x.parse().ok()).unwrap_or(0);
    Some((s[i + 1..j].to_string(), t, rss))
}

/// Интерфейс netifd, поднятый на устройстве маршрута по умолчанию.
fn link_for(dev: &str) -> Option<Link> {
    let o = std::process::Command::new("ubus").args(["call", "network.interface", "dump"]).output().ok()?;
    let v = crate::value::parse_json(&String::from_utf8_lossy(&o.stdout)).ok()?;
    let crate::value::Value::List(l) = v.get("interface")? else { return None };
    let mut out: Option<Link> = None;
    for i in l {
        let up = i.get("up").and_then(|x| x.as_bool()).unwrap_or(false);
        if !up || crate::dnsguard::vstr(i, "l3_device") != dev {
            continue;
        }
        let name = crate::dnsguard::vstr(i, "interface");
        let uptime = i.get("uptime").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
        let v4 = match i.get("ipv4-address") {
            Some(crate::value::Value::List(a)) => a.first().map(|x| crate::dnsguard::vstr(x, "address")).unwrap_or_default(),
            _ => String::new(),
        };
        let l = out.get_or_insert_with(|| Link { iface: name.clone(), device: dev.to_string(), uptime, ..Default::default() });
        if l.ipv4.is_empty() && !v4.is_empty() {
            l.ipv4 = v4;
            l.iface = name; // имя и время — у v4-интерфейса
            l.uptime = uptime;
        }
    }
    if let Some(l) = out.as_mut() {
        l.ipv6 = crate::netx::addrs_of(dev).into_iter().map(|(a, _)| a).find(|a| crate::netx::is_public_ipv6(a)).map(|a| a.to_string()).unwrap_or_default();
    }
    out
}

impl SysInfo {
    /// Интерфейсы netifd (кеш 60 с; время работы — на момент `now`).
    pub fn netifd(&mut self, now: u64) -> Vec<NfIf> {
        if self.nf_at == 0 || now - self.nf_at >= 60_000 {
            self.nf = netifd_dump();
            self.nf_at = now.max(1);
        }
        let add = ((now - self.nf_at) / 1000) as i64;
        self.nf.iter().map(|i| NfIf { uptime: if i.up { i.uptime + add } else { 0 }, ..i.clone() }).collect()
    }

    /// wan_link (None — нет интерфейса на этом устройстве).
    pub fn wan_link_json(&mut self, j: &mut J, now: u64, dev: &str) -> bool {
        if dev != self.link_dev || self.link_at == 0 || now - self.link_at >= 30_000 {
            self.link = link_for(dev);
            self.link_at = now.max(1);
            self.link_dev = dev.to_string();
        }
        let Some(l) = &self.link else { return false };
        j.obj().key("iface").str(&l.iface).key("device").str(&l.device).key("uptime_sec").int(l.uptime + ((now - self.link_at) / 1000) as i64);
        if !l.ipv4.is_empty() {
            j.key("ipv4").str(&l.ipv4);
        }
        if !l.ipv6.is_empty() {
            j.key("ipv6").str(&l.ipv6);
        }
        j.end_obj();
        true
    }

    fn procs(&mut self, now: u64) {
        if self.proc_at != 0 && now - self.proc_at < PROC_EVERY {
            return;
        }
        let Ok(rd) = std::fs::read_dir("/proc") else { return };
        let mut cur = HashMap::with_capacity(self.proc_ticks.len() + 16);
        let mut cpu: HashMap<String, u64> = HashMap::new();
        let mut ram: HashMap<String, u64> = HashMap::new();
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
            let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
            let Some((name, t, rss)) = proc_stat(&s) else { continue };
            if let Some(prev) = self.proc_ticks.get(&pid) {
                if t > *prev {
                    *cpu.entry(name.clone()).or_insert(0) += t - prev; // одноимённые — вместе
                }
            }
            *ram.entry(name).or_insert(0) += rss;
            cur.insert(pid, t);
        }
        if self.proc_at != 0 {
            let sec = (now - self.proc_at) as f64 / 1000.0;
            let mut top: Vec<(String, f64)> = cpu.into_iter().map(|(n, d)| (n, r1(d as f64 / 100.0 / sec * 100.0))).collect();
            top.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            top.truncate(TOP_CPU);
            self.top = top;
        }
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64 / 1048576.0;
        let mut rt: Vec<(String, f64)> = ram.into_iter().filter(|x| x.1 > 0).map(|(n, p)| (n, r1(p as f64 * page))).collect();
        rt.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        rt.truncate(TOP_RAM);
        self.top_ram = rt;
        self.proc_ticks = cur;
        self.proc_at = now.max(1);
    }

    /// Нагрузка самого cgmon (раз в тяжёлый такт): текущая и средняя за ~10 мин;
    /// по средней — признак «слабого» роутера.
    pub fn own_tick(&mut self, now: u64) {
        let Some((_, t, _)) = std::fs::read_to_string("/proc/self/stat").ok().and_then(|s| proc_stat(&s)) else { return };
        if self.cpu_at != 0 && now > self.cpu_at {
            let dt = (now - self.cpu_at) as f64;
            let cur = t.saturating_sub(self.cpu_ticks) as f64 / 100.0 / (dt / 1000.0) * 100.0;
            self.cpu = r1(cur);
            if self.own_since == 0 {
                self.own_since = now;
                self.own_avg = cur;
            } else {
                let a = (dt / OWN_WINDOW_MS).min(1.0);
                self.own_avg += (cur - self.own_avg) * a;
            }
            // первые 10 минут после запуска (старт, разбор файлов) не в счёт
            if now - self.own_since >= OWN_WINDOW_MS as u64 {
                if !self.weak && self.own_avg > WEAK_ON {
                    self.weak = true;
                    crate::log_info!("cgmon CPU {:.1}% on average (>{WEAK_ON}%): ports and TOP CPU/RAM on the page only on request", self.own_avg);
                } else if self.weak && self.own_avg < WEAK_OFF {
                    self.weak = false;
                    crate::log_info!("cgmon CPU {:.1}% on average: ports and TOP CPU/RAM back on the page", self.own_avg);
                }
            }
        }
        self.cpu_ticks = t;
        self.cpu_at = now;
    }

    /// sys_extra: температура, CPU и RSS cgmon, топ процессов (`top` — только
    /// когда страницу смотрят и процессор позволяет: обход /proc не бесплатный).
    pub fn sys_extra_json(&mut self, j: &mut J, now: u64, top: bool) {
        let rss = std::fs::read_to_string("/proc/self/statm").ok().and_then(|s| s.split_whitespace().nth(1).and_then(|x| x.parse::<f64>().ok())).unwrap_or(0.0);
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64;
        let mut temp = 0.0f64;
        if let Ok(rd) = std::fs::read_dir("/sys/class/thermal") {
            for e in rd.flatten() {
                if !e.file_name().to_string_lossy().starts_with("thermal_zone") {
                    continue;
                }
                if let Some(v) = std::fs::read_to_string(e.path().join("temp")).ok().and_then(|s| s.trim().parse::<f64>().ok()) {
                    temp = temp.max(r1(v / 1000.0));
                }
            }
        }
        if top {
            self.procs(now);
        } else {
            // без зрителей не обходим /proc; при возврате — CPU с нового замера
            self.proc_at = 0;
            self.proc_ticks.clear();
            self.top.clear();
            self.top_ram.clear();
        }
        let g = crate::config::go_float;
        j.obj();
        self.temp_c = temp;
        if temp != 0.0 {
            j.key("temp_c").raw(&g(temp));
        }
        j.key("cgmon_cpu").raw(&g(self.cpu)).key("cgmon_rss_mb").raw(&g(r1(rss * page / 1048576.0)));
        for (k, l, cpu) in [("top", &self.top, true), ("top_ram", &self.top_ram, false)] {
            if l.is_empty() {
                continue;
            }
            j.key(k).arr();
            for (n, v) in l.iter() {
                j.obj().key("name").str(n);
                if *v != 0.0 {
                    j.key(if cpu { "cpu" } else { "mb" }).raw(&g(*v));
                }
                j.end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
    }
}

fn sysf(dev: &str, f: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/{f}")).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Устройства «выше» порта: VLAN, мосты (upper_* в sysfs, рекурсивно).
fn uppers(dev: &str, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(format!("/sys/class/net/{dev}")) else { return };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if let Some(u) = n.strip_prefix("upper_") {
            if !out.iter().any(|x| x == u) && out.len() < 32 {
                out.push(u.to_string());
                uppers(u, out);
            }
        }
    }
}

/// Интерфейс netifd: имя, устройства, поднят ли, время работы, первый IPv4.
#[derive(Clone, Default)]
pub struct NfIf {
    pub name: String,
    pub l3: String,
    pub dev: String,
    pub up: bool,
    pub uptime: i64,
    pub ipv4: String,
}

pub fn netifd_dump() -> Vec<NfIf> {
    let Ok(o) = std::process::Command::new("ubus").args(["call", "network.interface", "dump"]).output() else { return Vec::new() };
    let Ok(v) = crate::value::parse_json(&String::from_utf8_lossy(&o.stdout)) else { return Vec::new() };
    let Some(crate::value::Value::List(l)) = v.get("interface") else { return Vec::new() };
    let s = |i: &crate::value::Value, k: &str| crate::dnsguard::vstr(i, k);
    l.iter()
        .map(|i| NfIf {
            name: s(i, "interface"),
            l3: s(i, "l3_device"),
            dev: s(i, "device"),
            up: i.get("up").and_then(|x| x.as_bool()).unwrap_or(false),
            uptime: i.get("uptime").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64,
            ipv4: match i.get("ipv4-address") {
                Some(crate::value::Value::List(a)) => a.first().map(|x| s(x, "address")).unwrap_or_default(),
                _ => String::new(),
            },
        })
        .filter(|x| !x.name.is_empty())
        .collect()
}

/// Физические порты (одинаково на всех OpenWrt с DSA и на x86): устройства
/// с `device` или DSA-портом (`phys_port_name`), без Wi-Fi и без внутреннего
/// CPU-порта DSA. Кабель — carrier, скорость/дуплекс — из sysfs; сеть —
/// интерфейсы netifd на самом порту, его VLAN или мосту (upper_*); у
/// интерфейсов зоны wan (`wan_devs` топологии) — время работы и адреса,
/// у порта с ними — `wan:true`.
pub fn ports_json(j: &mut J, netifd: &[NfIf], wan_devs: &[String]) -> bool {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else { return false };
    let mut ports: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|d| {
        let base = format!("/sys/class/net/{d}");
        let phys = std::path::Path::new(&format!("{base}/device")).exists() || !sysf(d, "phys_port_name").is_empty();
        let wifi = std::path::Path::new(&format!("{base}/wireless")).exists() || std::path::Path::new(&format!("{base}/phy80211")).exists();
        let conduit = std::path::Path::new(&format!("{base}/dsa")).exists();
        phys && !wifi && !conduit
    }).collect();
    if ports.is_empty() {
        return false;
    }
    ports.sort_by(|a, b| {
        let key = |x: &str| (x.trim_end_matches(|c: char| c.is_ascii_digit()).to_string(), x.trim_start_matches(|c: char| !c.is_ascii_digit()).parse::<u32>().unwrap_or(0));
        key(a).cmp(&key(b))
    });
    j.arr();
    for d in &ports {
        let carrier = sysf(d, "carrier");
        let disabled = carrier.is_empty(); // интерфейс выключен (ip link down) — carrier не читается
        let up = carrier == "1";
        let speed: i64 = if up { sysf(d, "speed").parse().unwrap_or(0).max(0) } else { 0 };
        let mut stack = vec![d.clone()];
        uppers(d, &mut stack);
        let bridge = stack.iter().skip(1).find(|x| std::path::Path::new(&format!("/sys/class/net/{x}/bridge")).exists()).cloned().unwrap_or_default();
        let mut nets: Vec<&NfIf> = Vec::new();
        for i in netifd {
            if (stack.contains(&i.l3) || stack.contains(&i.dev)) && !nets.iter().any(|x| x.name == i.name) && !i.name.ends_with("_6") && i.name != "loopback" {
                nets.push(i);
            }
        }
        let is_wan = |i: &NfIf| wan_devs.iter().any(|w| *w == i.name || (!i.l3.is_empty() && *w == i.l3));
        j.obj().key("name").str(d).key("up").bool(up).key("speed").int(speed);
        if up {
            j.key("duplex").str(&sysf(d, "duplex"));
        }
        if disabled {
            j.key("disabled").bool(true);
        }
        if !bridge.is_empty() {
            j.key("bridge").str(&bridge);
        }
        if nets.iter().any(|i| is_wan(i)) {
            j.key("wan").bool(true);
        }
        if !nets.is_empty() {
            j.key("nets").arr();
            for i in &nets {
                j.obj().key("n").str(&i.name);
                if is_wan(i) {
                    j.key("wan").bool(true).key("up").bool(i.up);
                    if i.up {
                        j.key("uptime").int(i.uptime);
                    }
                    if !i.ipv4.is_empty() {
                        j.key("ipv4").str(&i.ipv4);
                    }
                    let v6 = crate::netx::addrs_of(if i.l3.is_empty() { &i.dev } else { &i.l3 }).into_iter().map(|(a, _)| a).find(|a| crate::netx::is_public_ipv6(a));
                    if let Some(a) = v6 {
                        j.key("ipv6").str(&a.to_string());
                    }
                }
                j.end_obj();
            }
            j.end_arr();
        }
        j.end_obj();
    }
    j.end_arr();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat() {
        let s = "1234 (dnsmasq (x)) S 1 1 1 0 -1 4194560 100 0 0 0 250 150 0 0 20 0 1 0 50 12345678 900 18446744073709551615";
        let (n, t, rss) = proc_stat(s).unwrap();
        assert_eq!((n.as_str(), t, rss), ("dnsmasq (x)", 400, 900));
    }
}
