//! Варианты сборки из одного кода (признаки Cargo):
//!   full  — всё;
//!   lite  — без SmartDNS (адресная DNS-страховка и обход маршрутом); curl, ZeroTier,
//!           tc и kmod-nft-connlimit — по желанию, ставятся кнопкой со страницы;
//!   nano  — рассчитана на штатный образ ImmortalWrt для слабых роутеров
//!           (TL-WR1043N/ND v4, 25.12: nftables, dnsmasq-full, busybox ip, swconfig,
//!           uclient-fetch + libustream-openssl): без жёстких лимитов, curl и ZeroTier.
//!           Переключение шлюза и карты шлюзов работают и на busybox ip; SQM (cake) —
//!           код есть, пакеты (tc-tiny + kmod-sched-cake, ≈240 КБ) ставятся со страницы.
//! Отключённое не просто серое на странице: конфиг его выключает (`limit`), до кода
//! дело не доходит, и компоновщик (LTO) выбрасывает его из бинарника. Чего нет на
//! роутере во время работы (пакет не стоит) — не запускается, пока не поставят (deps.rs).

use crate::config::Config;

/// SmartDNS — бэкенд DNS-страховки (иначе — dnsmasq).
pub const SMARTDNS: bool = cfg!(feature = "smartdns");
/// curl и ZeroTier: проверка загрузки через путь обхода, свои роутеры как пути.
pub const EXT: bool = cfg!(feature = "ext");
/// tc: SQM и шейпер отдачи.
pub const TC: bool = cfg!(feature = "tc");
/// kmod-nft-connlimit: жёсткие лимиты соединений.
pub const CONNLIMIT: bool = cfg!(feature = "connlimit");

/// Имя варианта: full / lite / nano.
pub fn name() -> &'static str {
    if SMARTDNS {
        "full"
    } else if EXT {
        "lite"
    } else {
        "nano"
    }
}

/// «2.4.22» или «2.4.22 lite» — для журнала, центра сбора, --version.
pub fn version() -> String {
    match name() {
        "full" => crate::VERSION.to_string(),
        n => format!("{} {n}", crate::VERSION),
    }
}

/// Выключить в конфиге то, чего нет в этой сборке (после загрузки и после
/// изменений со страницы — настройка не включит отсутствующее).
pub fn limit(c: &mut Config) {
    if !TC {
        c.qos.enabled = false;
        c.upload_shaper.enabled = false;
    }
    if !CONNLIMIT {
        c.hard_limit.enabled = false;
    }
    if !SMARTDNS {
        // адресный режим и обход маршрутом держатся на SmartDNS (address/nftset по доменам)
        if c.dns_guard.mode == "targeted" {
            c.dns_guard.mode = "active".into();
        }
        c.dns_guard.alternatives.retain(|a| a == "proto");
        c.dns_guard.metered.clear();
        if c.dns_guard.backend == "smartdns" {
            c.dns_guard.backend = "dnsmasq".into(); // auto в такой сборке и так выбирает dnsmasq
        }
    }
    if !EXT {
        c.dns_guard.relays.clear();
    }
}

/// Настройки, которых нет в сборке: путь → пометка «нет в сборке» на странице.
pub fn absent() -> Vec<(&'static str, &'static str)> {
    let mut m = Vec::new();
    if !EXT {
        m.push(("dns_guard.relays", "build"));
        m.push(("dns_guard.relay_mbit", "build"));
    }
    if !SMARTDNS {
        m.push(("dns_guard.mode=targeted", "build"));
        m.push(("dns_guard.metered_day_mb", "build"));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits() {
        let mut c = crate::config::defaults();
        c.qos.enabled = true;
        c.dns_guard.mode = "targeted".into();
        c.dns_guard.alternatives = vec!["proto".into(), "eth3".into()];
        c.dns_guard.relays = vec!["n1@10.147.17.5".into()];
        limit(&mut c);
        assert_eq!(c.qos.enabled, TC);
        assert_eq!(c.dns_guard.alternatives.len(), if SMARTDNS { 2 } else { 1 });
        assert_eq!(c.dns_guard.mode == "targeted", SMARTDNS);
        assert_eq!(c.dns_guard.relays.is_empty(), !EXT);
        assert!(!name().is_empty() && version().starts_with(crate::VERSION));
    }
}
