//! Имена клиентов из быстрых источников (перенос resolver.go): аренды DHCP
//! dnsmasq (IPv4) и odhcpd (IPv6), статические хосты /etc/config/dhcp,
//! /etc/ethers, dns.static; имя аренды по MAC — и для IPv6-адресов устройства.
//! Источники перечитываются при смене mtime (не чаще раза в 10 с).
//! Пробы (PTR/mDNS/NetBIOS) и производитель по MAC — devid (позже).

use std::collections::HashMap;
use std::net::IpAddr;

const FILES: &[&str] = &["/tmp/dhcp.leases", "/tmp/hosts/odhcpd", "/etc/config/dhcp", "/etc/ethers"];

/// MAC в каноническом виде aa:bb:cc:dd:ee:ff (как Go net.ParseMAC + String).
pub fn norm_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = if s.contains(':') { s.split(':').collect() } else if s.contains('-') { s.split('-').collect() } else { return None };
    if parts.len() != 6 {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 && p.len() != 1 {
            return None;
        }
        let b = u8::from_str_radix(p, 16).ok()?;
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02x}"));
    }
    Some(out)
}

#[derive(Default)]
pub struct Resolver {
    static_: HashMap<String, String>,
    v4: HashMap<String, String>,
    v6: HashMap<String, String>,
    by_mac: HashMap<String, String>,
    uci_ip: HashMap<String, String>,
    sig: String,
    sig_at: u64,
    /// пробы и производитель (devid)
    pub dev: Option<std::sync::Arc<crate::devid::DevIdent>>,
}

fn read_ethers(text: &str, m: &mut HashMap<String, String>) {
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 2 || f[0].starts_with('#') || f[1].parse::<IpAddr>().is_ok() {
            continue;
        }
        if let Some(mac) = norm_mac(f[0]) {
            m.entry(mac).or_insert_with(|| f[1].to_string());
        }
    }
}

/// Статические хосты /etc/config/dhcp: mac → имя, ip → имя.
fn read_uci_hosts(text: &str) -> (HashMap<String, String>, HashMap<String, String>) {
    let (mut by_mac, mut by_ip) = (HashMap::new(), HashMap::new());
    let (mut in_host, mut name, mut ip, mut macs) = (false, String::new(), String::new(), Vec::<String>::new());
    let mut flush = |in_host: bool, name: &mut String, ip: &mut String, macs: &mut Vec<String>| {
        if in_host && !name.is_empty() {
            for m in macs.iter() {
                if let Some(mac) = norm_mac(m) {
                    by_mac.insert(mac, name.clone());
                }
            }
            if !ip.is_empty() {
                by_ip.insert(ip.clone(), name.clone());
            }
        }
        name.clear();
        ip.clear();
        macs.clear();
    };
    for l in text.lines() {
        let l = l.replace('\'', "");
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f[0] == "config" {
            flush(in_host, &mut name, &mut ip, &mut macs);
            in_host = f.len() > 1 && f[1] == "host";
        } else if in_host && f.len() >= 3 {
            match f[1] {
                "name" => name = f[2].to_string(),
                "ip" => ip = f[2].to_string(),
                "mac" => macs.extend(f[2..].iter().map(|s| s.to_string())),
                _ => {}
            }
        }
    }
    flush(in_host, &mut name, &mut ip, &mut macs);
    (by_mac, by_ip)
}

impl Resolver {
    pub fn new(static_: &[(String, String)]) -> Resolver {
        let mut r = Resolver::default();
        r.reload(static_);
        r
    }

    /// Перечитать, если файлы-источники поменялись.
    pub fn maybe_reload(&mut self, now: u64, static_: &[(String, String)]) {
        if self.sig_at != 0 && now - self.sig_at < 10_000 {
            return;
        }
        self.sig_at = now.max(1);
        let mut sig = String::new();
        for f in FILES {
            if let Ok(m) = std::fs::metadata(f) {
                if let Ok(t) = m.modified() {
                    sig.push_str(&format!("{:?}", t));
                }
            }
            sig.push('|');
        }
        if sig != self.sig {
            self.sig = sig;
            self.reload(static_);
        }
    }

    pub fn reload(&mut self, static_: &[(String, String)]) {
        let (mut by_mac, uci_ip) = read_uci_hosts(&std::fs::read_to_string("/etc/config/dhcp").unwrap_or_default());
        read_ethers(&std::fs::read_to_string("/etc/ethers").unwrap_or_default(), &mut by_mac);
        let mut v4 = HashMap::new();
        // dnsmasq: expiry mac ip hostname [clientid]
        for l in std::fs::read_to_string("/tmp/dhcp.leases").unwrap_or_default().lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || f[3] == "*" || f[3].is_empty() {
                continue;
            }
            if f[2].parse::<IpAddr>().is_ok() {
                v4.insert(f[2].to_string(), f[3].to_string());
            }
            if let Some(mac) = norm_mac(f[1]) {
                by_mac.entry(mac).or_insert_with(|| f[3].to_string());
            }
        }
        // odhcpd (IPv6): первый IPv6-адрес и первое «имя» в строке
        let mut v6 = HashMap::new();
        for l in std::fs::read_to_string("/tmp/hosts/odhcpd").unwrap_or_default().lines() {
            let (mut ip, mut name) = (String::new(), String::new());
            for tok in l.split_whitespace() {
                let clean = tok.trim_end_matches('#');
                if let Ok(a @ IpAddr::V6(_)) = clean.parse::<IpAddr>() {
                    if ip.is_empty() && !a.is_loopback() {
                        ip = a.to_string();
                    }
                    continue;
                }
                if name.is_empty() && tok.chars().any(|c| c.is_ascii_alphabetic()) && !["#", "br-", "eth", "vlan", "pppoe"].iter().any(|p| tok.starts_with(p)) {
                    name = tok.to_string();
                }
            }
            if !ip.is_empty() && !name.is_empty() {
                if let Some(i) = name.find('.').filter(|i| *i > 0) {
                    name.truncate(i);
                }
                v6.insert(ip, name);
            }
        }
        self.static_ = static_.iter().cloned().collect();
        self.v4 = v4;
        self.v6 = v6;
        self.by_mac = by_mac;
        self.uci_ip = uci_ip;
    }

    pub fn name(&self, ip: &str) -> String {
        let Ok(a) = ip.parse::<IpAddr>() else { return String::new() };
        if let Some(n) = self.static_.get(ip) {
            return n.clone();
        }
        if a.is_ipv4() {
            return self.v4.get(ip).cloned().unwrap_or_default();
        }
        self.v6.get(&a.to_string()).or_else(|| self.v6.get(ip)).cloned().unwrap_or_default()
    }

    /// Имя по IP и MAC: DHCP/static/ethers (пробы и производитель — devid).
    pub fn name_for(&self, ip: &str, mac: &str) -> String {
        let n = self.name(ip);
        if !n.is_empty() {
            return n;
        }
        if let Some(n) = self.uci_ip.get(ip) {
            return n.clone();
        }
        let mac = norm_mac(mac).unwrap_or_default();
        if let Some(n) = self.by_mac.get(&mac) {
            return n.clone();
        }
        match &self.dev {
            Some(d) => d.name(ip, &mac),
            None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        assert_eq!(norm_mac("AA-bb-0C-dd-ee-ff").as_deref(), Some("aa:bb:0c:dd:ee:ff"));
        assert!(norm_mac("zz:bb").is_none());
        let (m, i) = read_uci_hosts("config host\n\toption name 'cam'\n\toption mac 'AA:BB:CC:DD:EE:01'\n\toption ip '192.0.2.9'\nconfig dnsmasq\n\toption name 'x'\n");
        assert_eq!(m.get("aa:bb:cc:dd:ee:01").map(|s| s.as_str()), Some("cam"));
        assert_eq!(i.get("192.0.2.9").map(|s| s.as_str()), Some("cam"));
        let mut e = HashMap::new();
        read_ethers("aa:bb:cc:dd:ee:02 printer\n# x y\naa:bb:cc:dd:ee:03 192.0.2.1\n", &mut e);
        assert_eq!(e.len(), 1);
    }
}
