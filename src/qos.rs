//! QoS (перенос qos.go): дерево qdisc одним `tc -force -batch -`, проверка,
//! что оно на месте (переподключение PPPoE пересоздаёт интерфейс).
//!
//! Отдача — HTB (если flow_cap_up_kbit > 0 или включён шейпер отдачи): класс
//! 1:1 = upload_kbit (его потолок двигает шейпер), flow_buckets классов на
//! соединения с потолком flow_cap_up_kbit, листья fq_codel, фильтр flow hash;
//! иначе cake. Приём: ingress → ifb, на ifb cake или то же дерево HTB.
//! device: auto — устройство маршрута по умолчанию (PPPoE, DHCP, резервный).

use crate::config::QoSConfig;
use crate::json::J;
use std::io::Write as _;
use std::process::{Command, Stdio};

const VERIFY_EVERY: u64 = 60_000;

pub struct Qos {
    pub cfg: QoSConfig,
    pub on: bool,
    dirty: bool,
    ifindex: i64,
    built_at: i64,
    check_at: u64,
    builds: i64,
    err: String,
    /// фактические устройства
    pub dev: String,
    ifb: String,
    /// дерево перестроено — шейпер отдачи ставит потолок сразу
    pub rebuilt: bool,
}

/// ifb4<устройство>, не длиннее 15 символов (IFNAMSIZ).
pub fn ifb_name(dev: &str) -> String {
    let mut n = format!("ifb4{dev}");
    n.truncate(15);
    n
}

fn ifindex(dev: &str) -> Option<i64> {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex")).ok()?.trim().parse().ok()
}

fn first_line(s: &str) -> String {
    s.trim().lines().next().unwrap_or("").to_string()
}

fn tc_batch(script: &str) -> Result<(), String> {
    if crate::util::readonly() {
        return Ok(());
    }
    let mut ch = Command::new("tc").args(["-force", "-batch", "-"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    if let Some(mut si) = ch.stdin.take() {
        let _ = si.write_all(script.as_bytes());
    }
    let o = ch.wait_with_output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&o.stderr));
        return Err(format!("exit status {}: {}", o.status.code().unwrap_or(-1), first_line(&t)));
    }
    Ok(())
}

/// Байт за 1 мс на скорости класса (как sqm), не меньше 1600.
pub fn quantum(kbit: i64) -> i64 {
    (kbit * 1000 / 8 / 1000).max(1600)
}

fn htb_egress(c: &QoSConfig) -> bool {
    c.flow_cap_up_kbit > 0 || c.need_htb
}

/// Дерево отдачи (строки tc -batch).
pub fn egress_script(c: &QoSConfig, dev: &str) -> Vec<String> {
    let mut l = vec![format!("qdisc del dev {dev} root")];
    if c.upload_kbit <= 0 {
        return l;
    }
    if !htb_egress(c) {
        l.push(format!("qdisc add dev {dev} root cake bandwidth {}kbit {}", c.upload_kbit, c.cake_opts));
        return l;
    }
    l.extend(htb_tree(dev, "root", c.upload_kbit, c.flow_cap_up_kbit, &c.flow_keys_up, c.flow_buckets));
    l
}

/// htb 1: — класс 1:1 (всё), n классов на соединения с потолком capk, листья fq_codel, flow hash.
pub fn htb_tree(dev: &str, parent: &str, total: i64, capk: i64, keys: &str, n: i64) -> Vec<String> {
    let capk = if capk <= 0 || capk > total { total } else { capk };
    let n = n.max(1);
    let minrate = (total / n).max(16);
    let qt = quantum(total);
    let fq = "fq_codel limit 10240 target 5ms interval 100ms memory_limit 4Mb ecn";
    let mut l = vec![
        format!("qdisc add dev {dev} {parent} handle 1: htb default 2"),
        format!("class add dev {dev} parent 1: classid 1:1 htb quantum {qt} rate {total}kbit ceil {total}kbit burst {qt}b cburst {qt}b"),
        format!("class add dev {dev} parent 1:1 classid 1:2 htb quantum {qt} rate {minrate}kbit ceil {capk}kbit"),
        format!("qdisc add dev {dev} parent 1:2 handle 2: {fq}"),
    ];
    for i in 0..n {
        let cls = format!("1:{:x}", 0x100 + i);
        l.push(format!("class add dev {dev} parent 1:1 classid {cls} htb quantum {qt} rate {minrate}kbit ceil {capk}kbit"));
        l.push(format!("qdisc add dev {dev} parent {cls} {fq}"));
    }
    l.push(format!("filter add dev {dev} parent 1: protocol ip prio 1 handle 1 flow hash keys {keys} divisor {n} baseclass 1:100"));
    l.push(format!("filter add dev {dev} parent 1: protocol ipv6 prio 2 handle 2 flow hash keys {keys} divisor {n} baseclass 1:100"));
    l
}

pub fn ingress_script(c: &QoSConfig, dev: &str, ifb: &str) -> Vec<String> {
    let mut l = vec![format!("qdisc del dev {dev} ingress"), format!("qdisc del dev {ifb} root")];
    if c.download_kbit <= 0 {
        return l;
    }
    l.push(format!("qdisc add dev {dev} handle ffff: ingress"));
    if c.flow_cap_down_kbit > 0 {
        l.extend(htb_tree(ifb, "root", c.download_kbit, c.flow_cap_down_kbit, &c.flow_keys_down, c.flow_buckets));
    } else {
        l.push(format!("qdisc add dev {ifb} root cake bandwidth {}kbit {}", c.download_kbit, c.ingress_cake_opts));
    }
    l.push(format!("filter add dev {dev} parent ffff: protocol all prio 10 u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev {ifb}"));
    l
}

impl Qos {
    pub fn new(cfg: QoSConfig) -> Qos {
        Qos { cfg, on: true, dirty: true, ifindex: 0, built_at: 0, check_at: 0, builds: 0, err: String::new(), dev: String::new(), ifb: String::new(), rebuilt: false }
    }

    fn resolve(&self) -> (String, String) {
        let mut dev = self.cfg.device.clone();
        if dev.is_empty() || dev == "auto" {
            dev = crate::netx::default_route_interface();
        }
        let mut ifb = self.cfg.ifb.clone();
        if ifb.is_empty() && !dev.is_empty() {
            ifb = ifb_name(&dev);
        }
        (dev, ifb)
    }

    /// Устройство, на котором построена (строится) очередь.
    pub fn current_device(&self) -> String {
        if self.dev.is_empty() {
            return self.resolve().0;
        }
        self.dev.clone()
    }

    /// Со страницы: вкл/выкл и скорости.
    pub fn reconfigure(&mut self, on: bool, up: i64, down: i64, cap: i64, cap_down: i64) {
        if on == self.on && up == self.cfg.upload_kbit && down == self.cfg.download_kbit && cap == self.cfg.flow_cap_up_kbit && cap_down == self.cfg.flow_cap_down_kbit {
            return;
        }
        self.on = on;
        self.cfg.upload_kbit = up;
        self.cfg.download_kbit = down;
        self.cfg.flow_cap_up_kbit = cap;
        self.cfg.flow_cap_down_kbit = cap_down;
        self.dirty = true;
    }

    /// Прочие настройки из конфига; скорости и вкл. — от reconfigure.
    pub fn set_opts(&mut self, mut c: QoSConfig) {
        c.device = self.cfg.device.clone();
        c.ifb = self.cfg.ifb.clone();
        c.need_htb = self.cfg.need_htb;
        c.upload_kbit = self.cfg.upload_kbit;
        c.download_kbit = self.cfg.download_kbit;
        c.flow_cap_up_kbit = self.cfg.flow_cap_up_kbit;
        c.flow_cap_down_kbit = self.cfg.flow_cap_down_kbit;
        if c != self.cfg {
            self.cfg = c;
            self.dirty = true;
        }
    }

    /// Каждый такт (лёгкий блок).
    pub fn tick(&mut self, now: u64, unix: i64) {
        let (dev, ifb) = self.resolve();
        if dev.is_empty() {
            return; // маршрута по умолчанию нет — дерево (если было) не трогаем
        }
        if dev != self.dev || ifb != self.ifb {
            if !self.dev.is_empty() && self.ifindex != 0 {
                self.teardown();
                crate::log_info!("qos: WAN device {} -> {}", self.dev, dev);
            }
            self.dev = dev;
            self.ifb = ifb;
            self.ifindex = 0;
            self.dirty = true;
        }
        let Some(idx) = ifindex(&self.dev) else {
            self.ifindex = 0; // PPPoE ещё не поднялся
            return;
        };
        if !self.on {
            if self.ifindex != 0 || self.dirty {
                self.teardown();
                self.ifindex = 0;
                self.dirty = false;
                crate::log_info!("qos: off, qdiscs removed from {}", self.dev);
            }
            return;
        }
        let mut need = self.dirty || idx != self.ifindex;
        if !need && now - self.check_at >= VERIFY_EVERY {
            self.check_at = now;
            need = !self.present();
        }
        if !need {
            return;
        }
        if let Err(e) = self.build() {
            crate::log_err!("qos: build on {}: {}", self.dev, e);
            self.err = e;
            self.dirty = true;
            return;
        }
        self.err.clear();
        self.ifindex = idx;
        self.dirty = false;
        self.built_at = unix;
        self.check_at = now;
        self.builds += 1;
        self.rebuilt = true;
        crate::log_info!("qos: built on {}: up {} kbit (flow cap {}), down {} kbit (flow cap {})", self.dev, self.cfg.upload_kbit, self.cfg.flow_cap_up_kbit, self.cfg.download_kbit, self.cfg.flow_cap_down_kbit);
    }

    /// На устройстве наше корневое дерево и (если нужно) ingress.
    fn present(&self) -> bool {
        let Ok(o) = Command::new("tc").args(["qdisc", "show", "dev", &self.dev]).output() else { return false };
        if !o.status.success() {
            return false;
        }
        let s = String::from_utf8_lossy(&o.stdout);
        if self.cfg.upload_kbit > 0 && !s.contains(if htb_egress(&self.cfg) { "qdisc htb 1: root" } else { "qdisc cake " }) {
            return false;
        }
        !(self.cfg.download_kbit > 0 && !s.contains("ingress ffff:"))
    }

    fn teardown(&self) {
        let _ = tc_batch(&format!("qdisc del dev {d} root\nqdisc del dev {d} ingress\nqdisc del dev {} root\n", self.ifb, d = self.dev));
    }

    fn build(&self) -> Result<(), String> {
        if crate::util::readonly() {
            return Ok(());
        }
        if self.cfg.download_kbit > 0 {
            if ifindex(&self.ifb).is_none() {
                let o = Command::new("ip").args(["link", "add", "name", &self.ifb, "type", "ifb"]).output().map_err(|e| e.to_string())?;
                if !o.status.success() {
                    return Err(format!("ifb {}: {}", self.ifb, first_line(&String::from_utf8_lossy(&o.stderr))));
                }
            }
            let o = Command::new("ip").args(["link", "set", "dev", &self.ifb, "up"]).output().map_err(|e| e.to_string())?;
            if !o.status.success() {
                return Err(format!("ifb {} up: {}", self.ifb, first_line(&String::from_utf8_lossy(&o.stderr))));
            }
        }
        let mut l = egress_script(&self.cfg, &self.dev);
        l.extend(ingress_script(&self.cfg, &self.dev, &self.ifb));
        // -force: удаление несуществующего — не ошибка; ошибку добавления увидит present()
        let _ = tc_batch(&(l.join("\n") + "\n"));
        if !self.present() {
            return Err("tree not present after tc batch".into());
        }
        Ok(())
    }

    pub fn status_json(&self, j: &mut J) {
        let dev = if self.dev.is_empty() { &self.cfg.device } else { &self.dev };
        j.obj().key("on").bool(self.on).key("device").str(dev).key("upload_kbit").int(self.cfg.upload_kbit).key("download_kbit").int(self.cfg.download_kbit);
        j.key("flow_cap_up_kbit").int(self.cfg.flow_cap_up_kbit).key("flow_cap_down_kbit").int(self.cfg.flow_cap_down_kbit);
        if self.built_at != 0 {
            j.key("built_at").str(&crate::util::rfc3339(self.built_at, 0));
        }
        j.key("builds").int(self.builds);
        if !self.err.is_empty() {
            j.key("error").str(&self.err);
        }
        j.end_obj();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts() {
        let mut c = crate::config::defaults().qos;
        c.upload_kbit = 23000;
        c.download_kbit = 90000;
        c.flow_cap_up_kbit = 0;
        c.need_htb = true;
        c.flow_buckets = 4;
        let e = egress_script(&c, "pppoe-wan");
        assert_eq!(e[1], "qdisc add dev pppoe-wan root handle 1: htb default 2");
        assert_eq!(e[2], "class add dev pppoe-wan parent 1: classid 1:1 htb quantum 2875 rate 23000kbit ceil 23000kbit burst 2875b cburst 2875b");
        assert!(e.iter().any(|x| x == "class add dev pppoe-wan parent 1:1 classid 1:103 htb quantum 2875 rate 5750kbit ceil 23000kbit"));
        let i = ingress_script(&c, "pppoe-wan", &ifb_name("pppoe-wan"));
        assert!(i[3].starts_with("qdisc add dev ifb4pppoe-wan root cake bandwidth 90000kbit"), "{}", i[3]);
        assert_eq!(ifb_name("pppoe-uplink1"), "ifb4pppoe-uplin");
        c.need_htb = false;
        assert!(egress_script(&c, "eth0")[1].starts_with("qdisc add dev eth0 root cake bandwidth 23000kbit"));
    }
}
