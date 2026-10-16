//! Настройка пакетов, поставленных со страницы (deps.rs, кнопка «установить»).
//! Безопасно: только если пакет ещё не настраивали (свой конфиг не трогаем), без
//! личного (сети ZeroTier, списки рекламы), с проверкой и откатом DNS.
//! Возвращает строку для страницы (пусто — делать нечего).

use crate::config::DNSGuardConfig;
use std::process::{Command, Stdio};

fn sh(args: &[&str]) -> Result<String, String> {
    let o = Command::new(args[0]).args(&args[1..]).stdin(Stdio::null()).output().map_err(|e| format!("{}: {e}", args[0]))?;
    if !o.status.success() {
        return Err(format!("{}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn uci_get(k: &str) -> String {
    sh(&["uci", "-q", "get", k]).unwrap_or_default()
}

/// Публичная сеть ZeroTier «Earth» — никогда не подключать сам.
const ZT_EARTH: &str = "8056c2e21c000001";

/// ZeroTier: включить службу. В сеть не вступаем — её номер у каждого свой.
pub fn zerotier() -> String {
    if !std::path::Path::new("/etc/config/zerotier").exists() {
        return String::new();
    }
    // примеры из пакета с публичной сетью — убрать (иначе роутер окажется в чужой сети)
    let show = sh(&["uci", "-q", "show", "zerotier"]).unwrap_or_default();
    for l in show.lines() {
        if let Some((k, v)) = l.split_once('=') {
            if v.trim_matches('\'') == ZT_EARTH && k.ends_with(".id") {
                let sec = k.trim_end_matches(".id");
                let _ = sh(&["uci", "delete", sec]);
            } else if v.contains(ZT_EARTH) && k.ends_with(".join") {
                let _ = sh(&["uci", "del_list", &format!("{k}={ZT_EARTH}")]);
            }
        }
    }
    let was = uci_get("zerotier.global.enabled") == "1";
    if !was {
        let _ = sh(&["uci", "set", "zerotier.global.enabled=1"]);
    }
    let _ = sh(&["uci", "commit", "zerotier"]);
    let _ = sh(&["/etc/init.d/zerotier", "enable"]);
    let _ = sh(&["/etc/init.d/zerotier", "restart"]);
    "ZeroTier запущен; свою сеть подключите: zerotier-cli join <номер сети> (или LuCI → VPN → ZeroTier)".into()
}

const SD_PORT: &str = "5399";

/// Вышестоящие серверы: шифрованный DNS (DoH/DoT), адреса для начального разрешения — Quad9.
const SD_UPSTREAM: &str = "# cgmon: вышестоящие серверы SmartDNS (DNS-страховка меняет этот файл в аварии)
server 9.9.9.10 -bootstrap-dns -exclude-default-group
server 149.112.112.10 -bootstrap-dns -exclude-default-group
server-https https://cloudflare-dns.com/dns-query
server-https https://dns.google/dns-query
server-tls common.dot.dns.yandex.net
";

fn sd_custom(dg: &DNSGuardConfig) -> String {
    format!(
        "# cgmon: настройки SmartDNS (как на рабочем роутере, без личного)
speed-check-mode none
dualstack-ip-selection no
prefetch-domain yes
serve-expired no
cache-size 4096
cache-persist no
conf-file {}
conf-file {}
conf-file {}
",
        dg.upstream_file, dg.guard_file, dg.targets_file
    )
}

/// В файле только комментарии и пустые строки.
fn pristine(path: &str) -> bool {
    std::fs::read_to_string(path).map_or(true, |t| t.lines().all(|l| l.trim().is_empty() || l.trim_start().starts_with('#')))
}

fn answers(server: &str) -> bool {
    for _ in 0..10 {
        if matches!(crate::dgsys::dns_query(server, "dns.google", crate::dns::TYPE_A, 2000), crate::dgsys::Res::Ips(_)) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

/// SmartDNS: свой порт, DoH; dnsmasq пересылает ему — только если SmartDNS отвечает,
/// и откат, если после переключения DNS роутера не работает.
pub fn smartdns(dg: &DNSGuardConfig) -> String {
    let custom = "/etc/smartdns/custom.conf";
    if uci_get("smartdns.@smartdns[0].enabled") == "1" || !pristine(custom) {
        return "SmartDNS уже настроен — его настройки не трогаю".into();
    }
    if !pristine(&dg.upstream_file) {
        return format!("SmartDNS: {} уже есть — настройки не трогаю", dg.upstream_file);
    }
    let _ = std::fs::write(&dg.upstream_file, SD_UPSTREAM);
    for f in [&dg.guard_file, &dg.targets_file] {
        if !std::path::Path::new(f).exists() {
            let _ = std::fs::write(f, "");
        }
    }
    let _ = std::fs::copy(custom, format!("{custom}.bak-cgmon"));
    let _ = std::fs::write(custom, sd_custom(dg));
    for kv in ["enabled=1", "port=5399", "tcp_server=1", "ipv6_server=0", "auto_set_dnsmasq=0", "seconddns_enabled=0"] {
        let _ = sh(&["uci", "set", &format!("smartdns.@smartdns[0].{kv}")]);
    }
    let _ = sh(&["uci", "commit", "smartdns"]);
    let _ = sh(&["/etc/init.d/smartdns", "enable"]);
    let _ = sh(&["/etc/init.d/smartdns", "restart"]);
    let sd = format!("127.0.0.1:{SD_PORT}");
    if !answers(&sd) {
        return "SmartDNS поставлен, но не отвечает — DNS роутера не переключал".into();
    }
    // dnsmasq → SmartDNS: серверы для отдельных доменов (/zt/…) остаются
    let before = uci_get("dhcp.@dnsmasq[0].server");
    let noresolv = uci_get("dhcp.@dnsmasq[0].noresolv");
    let keep: Vec<&str> = before.split_whitespace().map(|s| s.trim_matches('\'')).filter(|s| s.starts_with('/')).collect();
    let _ = std::fs::write("/etc/cgmon/dnsmasq-before-smartdns.txt", format!("server: {before}\nnoresolv: {noresolv}\n"));
    let set = |servers: &[String], nr: &str| {
        let _ = sh(&["uci", "-q", "delete", "dhcp.@dnsmasq[0].server"]);
        for s in servers {
            let _ = sh(&["uci", "add_list", &format!("dhcp.@dnsmasq[0].server={s}")]);
        }
        if nr.is_empty() {
            let _ = sh(&["uci", "-q", "delete", "dhcp.@dnsmasq[0].noresolv"]);
        } else {
            let _ = sh(&["uci", "set", &format!("dhcp.@dnsmasq[0].noresolv={nr}")]);
        }
        let _ = sh(&["uci", "commit", "dhcp"]);
        let _ = sh(&["/etc/init.d/dnsmasq", "restart"]);
    };
    let mut new: Vec<String> = keep.iter().map(|s| s.to_string()).collect();
    new.push(format!("127.0.0.1#{SD_PORT}"));
    set(&new, "1");
    if answers("127.0.0.1:53") {
        return format!("SmartDNS: шифрованный DNS (Cloudflare, Google, Яндекс), dnsmasq → 127.0.0.1#{SD_PORT}; прежние серверы — /etc/cgmon/dnsmasq-before-smartdns.txt");
    }
    let old: Vec<String> = before.split_whitespace().map(|s| s.trim_matches('\'').to_string()).collect();
    set(&old, &noresolv);
    "SmartDNS: через него DNS роутера не заработал — вернул как было".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_conf_includes_guard_files() {
        let dg = crate::config::defaults().dns_guard;
        let c = sd_custom(&dg);
        for f in [&dg.upstream_file, &dg.guard_file, &dg.targets_file] {
            assert!(c.contains(&format!("conf-file {f}\n")), "{c}");
        }
        assert!(!c.contains("audit") && !c.contains("domain-set"));
    }
}
