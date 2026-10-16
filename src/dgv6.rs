//! Отказ по протоколу: плохой протокол не отказывает, а зависает; отказ
//! (TCP RST, ICMP admin-prohibited) — и клиент сразу уходит на другой.
//!  1. адресный режим: сетям /48 владельцев со штрафом за IPv6 и сетям /24
//!     владельцев со штрафом за IPv4 (вместо запретов AAAA/A в SmartDNS —
//!     DNS не трогается, работает и с DoH клиента, и с адресами в приложениях);
//!  2. reject_all_v6_score: пробы IPv6 (и метрики по сайтам) ниже порога
//!     дольше reject_all_v6_sec — всем новым IPv6-соединениям в интернет через
//!     WAN-устройства IPv6 (туннели и локальные адреса не трогаются); снимается,
//!     когда оба выше порога+20 5 минут. При полном обрыве не включается.
//! Только пересылаемый трафик (hook forward); своя таблица inet cgmon_v6.

use crate::dnsguard::{DnsGuard, Health};
use std::net::IpAddr;

pub const TABLE: &str = "cgmon_v6";
pub const MAX_NETS: usize = 64;
const OFF_AFTER: i64 = 5 * 60_000;

/// Сеть /48 публичного IPv6-адреса.
pub fn net6(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(a)) if crate::witness::public(&IpAddr::V6(a)) => {
            let s = a.segments();
            format!("{}/48", std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
        _ => String::new(),
    }
}

/// Добавить сети /48 адресов (или готовые сети /48).
pub fn nets6_add(mut nets: Vec<String>, ips: &[String]) -> Vec<String> {
    for ip in ips {
        let n = if ip.ends_with("/48") { ip.clone() } else { net6(ip) };
        if !n.is_empty() && !nets.contains(&n) && nets.len() < MAX_NETS {
            nets.push(n);
        }
    }
    nets.sort();
    nets
}

/// Устройства IPv6-маршрутов по умолчанию (без туннелей).
pub fn parse_devs(out: &str) -> Vec<String> {
    let mut devs: Vec<String> = Vec::new();
    for ln in out.lines() {
        let f: Vec<&str> = ln.split_whitespace().collect();
        if f.len() < 3 || f[0] != "default" {
            continue;
        }
        for i in 1..f.len() - 1 {
            let d = f[i + 1];
            if f[i] == "dev" && !crate::netx::is_tunnel_dev(d) && crate::livecfg::path_id_ok(d) && !devs.iter().any(|x| x == d) {
                devs.push(d.into());
            }
        }
    }
    devs.sort();
    devs
}

pub fn script(bad: &[String], bad4: &[String], devs: &[String]) -> String {
    let mut b = format!("add table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    b.push_str("\tset bad6 { type ipv6_addr; flags interval; ");
    if !bad.is_empty() {
        b.push_str(&format!("elements = {{ {} }}; ", bad.join(", ")));
    }
    b.push_str("}\n\tset bad4 { type ipv4_addr; flags interval; ");
    if !bad4.is_empty() {
        b.push_str(&format!("elements = {{ {} }}; ", bad4.join(", ")));
    }
    b.push_str("}\n\tchain v6_fwd {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n");
    b.push_str("\t\tct state new ip6 daddr @bad6 meta l4proto tcp counter reject with tcp reset\n");
    b.push_str("\t\tct state new ip6 daddr @bad6 counter reject with icmpv6 type admin-prohibited\n");
    b.push_str("\t\tct state new ip daddr @bad4 meta l4proto tcp counter reject with tcp reset\n");
    b.push_str("\t\tct state new ip daddr @bad4 counter reject with icmp type admin-prohibited\n");
    if !devs.is_empty() {
        let o = devs.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(", ");
        b.push_str(&format!("\t\tct state new meta nfproto ipv6 oifname {{ {o} }} ip6 daddr != {{ fc00::/7, fe80::/10, ff00::/8 }} meta l4proto tcp counter reject with tcp reset\n"));
        b.push_str(&format!("\t\tct state new meta nfproto ipv6 oifname {{ {o} }} ip6 daddr != {{ fc00::/7, fe80::/10, ff00::/8 }} counter reject with icmpv6 type admin-prohibited\n"));
    }
    b.push_str("\t}\n}\n");
    b
}

fn wit_text(s: f64) -> String {
    if s < 0.0 {
        String::new()
    } else {
        format!(", метрики по сайтам {s:.0}")
    }
}

impl DnsGuard {
    /// У владельца отказ по обоим протоколам — значит, он недоступен целиком: такого
    /// не должно быть (новый штраф снимает другой), а если всё же есть — не отказывать вовсе.
    fn both_refused(&self, as_: &str) -> bool {
        let on = |f: &str| self.targets.get(&crate::dgtarget::key(as_, f)).map_or(false, |t| t.active && !t.via_path());
        on("ipv4") && on("ipv6")
    }

    /// Сети /48 под адресным отказом в IPv6.
    pub fn v6_bad(&self) -> Vec<String> {
        if self.cfg.mode != "targeted" {
            return Vec::new();
        }
        let mut l: Vec<String> = Vec::new();
        for t in self.targets.values().filter(|t| t.active && t.fam == "ipv6" && !self.both_refused(&t.as_)) {
            for n in &t.nets6 {
                if !l.contains(n) {
                    l.push(n.clone());
                }
            }
        }
        l.sort();
        l
    }

    /// Сети /24 под адресным отказом в IPv4 (перевод на IPv6; обход — не здесь).
    pub fn v4_bad(&self) -> Vec<String> {
        if self.cfg.mode != "targeted" {
            return Vec::new();
        }
        let mut l: Vec<String> = Vec::new();
        for t in self.targets.values().filter(|t| t.active && t.fam == "ipv4" && !t.via_path() && !self.both_refused(&t.as_)) {
            for n in &t.nets {
                if !l.contains(n) {
                    l.push(n.clone());
                }
            }
        }
        l.sort();
        l
    }

    /// Раз в такт: общий отказ по пробам и метрикам, таблица.
    pub fn v6_tick(&mut self, now: i64, h: &Health) -> Vec<String> {
        let mut msgs = Vec::new();
        let thr = self.cfg.reject_all_v6_score as f64;
        let on = self.acts() && thr > 0.0;
        let bad = on && h.v6_avail && !h.v6_ok && !h.outage && h.v6_rate < thr && (h.wit_v6_score < 0.0 || h.wit_v6_score < thr);
        let good = !on || !h.v6_avail || (h.v6_rate >= thr + 20.0 && (h.wit_v6_score < 0.0 || h.wit_v6_score >= thr + 20.0));
        if self.v6_all == 0 && bad {
            if self.v6_bad_from == 0 {
                self.v6_bad_from = now;
            }
            if now - self.v6_bad_from >= self.cfg.reject_all_v6_sec * 1000 {
                self.v6_all = now;
                self.v6_good_from = 0;
                msgs.push(format!(
                    "IPv6: клиентам отказ во всех новых IPv6-соединениях в интернет — пробы IPv6 {:.0}%{} (порог {thr:.0}) дольше {}; клиенты сразу уходят на IPv4",
                    h.v6_rate, wit_text(h.wit_v6_score), crate::dgtarget::dur_text(self.cfg.reject_all_v6_sec * 1000)
                ));
            }
        } else if self.v6_all == 0 {
            self.v6_bad_from = 0;
        } else if good {
            if self.v6_good_from == 0 {
                self.v6_good_from = now;
            }
            if now - self.v6_good_from >= OFF_AFTER || !on {
                msgs.push(format!("IPv6: отказ во всех IPv6-соединениях снят — пробы IPv6 {:.0}%{} (действовал {})", h.v6_rate, wit_text(h.wit_v6_score), crate::dgtarget::dur_text(now - self.v6_all)));
                self.v6_all = 0;
                self.v6_bad_from = 0;
                self.v6_good_from = 0;
            }
        } else {
            self.v6_good_from = 0;
        }
        self.v6_apply(now);
        msgs
    }

    /// Таблица inet cgmon_v6 по нужному состоянию (пересоздаётся атомарно при изменении).
    pub fn v6_apply(&mut self, now: i64) {
        let (bad, bad4) = (self.v6_bad(), self.v4_bad());
        let mut devs: Vec<String> = Vec::new();
        if self.v6_all != 0 {
            if now - self.v6_devs_at >= 60_000 || self.v6_devs.is_none() {
                self.v6_devs_at = now;
                self.v6_devs = Some(parse_devs(&self.sys.query(&["ip", "-6", "route", "show", "table", "all"]).unwrap_or_default()));
            }
            devs = self.v6_devs.clone().unwrap_or_default();
        }
        let want = if bad.is_empty() && bad4.is_empty() && devs.is_empty() { String::new() } else { script(&bad, &bad4, &devs) };
        if want == self.v6_written {
            return;
        }
        let s = if want.is_empty() { format!("add table inet {TABLE}\ndelete table inet {TABLE}\n") } else { want.clone() };
        if let Err(e) = self.sys.nft(&s) {
            crate::log_err!("ipv6 reject: {}", e);
            return;
        }
        self.v6_written = want;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsguard::tests::{fake, guard, tmp};
    use crate::dnsguard::NoFeed;

    #[test]
    fn helpers() {
        assert_eq!(net6("2a00:1450:4001:80b::200e"), "2a00:1450:4001::/48");
        assert_eq!(net6("fd00::1"), "");
        assert_eq!(nets6_add(vec![], &["2a00:1450:4001::/48".into(), "2a00:1450:4001::1".into()]), vec!["2a00:1450:4001::/48".to_string()]);
        assert_eq!(parse_devs("default from 2001:db8::/56 via fe80::1 dev pppoe-wan metric 512\ndefault dev tailscale0 table 52\ndefault via fe80::2 dev eth3 metric 1024\n"), vec!["eth3".to_string(), "pppoe-wan".to_string()]);
    }

    #[test]
    fn reject_all_v6() {
        let (mut g, sys) = guard("active", fake("fake"), &tmp("v6"));
        g.cfg.reject_all_v6_score = 20;
        g.cfg.reject_all_v6_sec = 300;
        sys.queries.lock().unwrap().insert("ip -6 route show table all".into(), "default via fe80::1 dev pppoe-wan metric 512\n".into());
        let bad = Health { v4_ok: true, v6_avail: true, v6_rate: 5.0, wit_v6_score: -1.0, ..Default::default() };
        let mut now = 1_700_000_000_000i64;
        let mut all = Vec::new();
        for _ in 0..32 {
            all.extend(g.tick(now, "NORMAL", "IPV6_DEGRADATION", &bad, &mut NoFeed));
            now += 10_000;
        }
        assert!(g.v6_all != 0 && all.iter().any(|m| m.starts_with("IPv6: клиентам отказ")), "{all:?}");
        assert!(sys.nfts.lock().unwrap().last().unwrap().contains("oifname { \"pppoe-wan\" }"));
        // полный обрыв — не включать; IPv6 вернулся на 5 мин — снять
        let good = Health { v4_ok: true, v6_ok: true, v6_avail: true, v6_rate: 100.0, wit_v6_score: 90.0, ..Default::default() };
        all.clear();
        for _ in 0..31 {
            all.extend(g.tick(now, "NORMAL", "HEALTHY", &good, &mut NoFeed));
            now += 10_000;
        }
        assert!(g.v6_all == 0 && all.iter().any(|m| m.contains("отказ во всех IPv6-соединениях снят")), "{all:?}");
        assert!(sys.nfts.lock().unwrap().last().unwrap().starts_with("add table inet cgmon_v6\ndelete table inet cgmon_v6\n"));
    }
}
