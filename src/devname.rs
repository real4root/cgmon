//! Имя устройства со страницы: статическая привязка DHCP (`config host`: имя, MAC, IP) и
//! «Имя хоста» (`config domain`: имя → IP) в /etc/config/dhcp, затем dnsmasq перечитывает
//! настройки. Пустое имя — убрать обе записи. Так имя видно и в cgmon, и в LuCI, и по DNS
//! (`имя.lan`), даже если устройство берёт адрес не по DHCP и само имени не сообщает.

use std::net::Ipv4Addr;

/// Имя для DHCP/DNS: буквы, цифры, «-» (не в начале и не в конце), до 63.
pub fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 63 && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') && !n.starts_with('-') && !n.ends_with('-')
}

/// Разбор `uci show dhcp`: секции типа `typ` → (id, опции).
pub fn sections(t: &str, typ: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for l in t.lines() {
        let Some(rest) = l.strip_prefix("dhcp.") else { continue };
        let Some((key, val)) = rest.split_once('=') else { continue };
        let val = val.trim().trim_matches('\'').to_string();
        match key.split_once('.') {
            None => {
                if val == typ {
                    out.push((key.to_string(), Vec::new()));
                }
            }
            Some((sec, opt)) => {
                if let Some(s) = out.iter_mut().find(|s| s.0 == sec) {
                    s.1.push((opt.to_string(), val));
                }
            }
        }
    }
    out
}

fn opt<'a>(s: &'a [(String, String)], k: &str) -> &'a str {
    s.iter().find(|x| x.0 == k).map(|x| x.1.as_str()).unwrap_or("")
}

/// Команды uci для имени `name` устройства (mac, ip); пустое имя — убрать.
pub fn uci_cmds(show: &str, mac: &str, ip: Ipv4Addr, name: &str) -> Vec<Vec<String>> {
    let s = |x: &str| x.to_string();
    let mut cmds: Vec<Vec<String>> = Vec::new();
    let ip_s = ip.to_string();
    let hosts = sections(show, "host");
    let host = hosts.iter().find(|h| opt(&h.1, "mac").split_whitespace().any(|m| m.eq_ignore_ascii_case(mac)));
    let domains = sections(show, "domain");
    let doms: Vec<&(String, Vec<(String, String)>)> = domains.iter().filter(|d| opt(&d.1, "ip") == ip_s).collect();
    if name.is_empty() {
        if let Some((id, o)) = host {
            // только наши поля — секцию целиком, иначе (свои теги, время аренды) — лишь имя
            if o.iter().all(|x| matches!(x.0.as_str(), "name" | "mac" | "ip" | "dns")) {
                cmds.push(vec![s("delete"), format!("dhcp.{id}")]);
            } else {
                cmds.push(vec![s("delete"), format!("dhcp.{id}.name")]);
            }
        }
        for (id, _) in doms {
            cmds.push(vec![s("delete"), format!("dhcp.{id}")]);
        }
        return cmds;
    }
    match host {
        Some((id, o)) => {
            cmds.push(vec![s("set"), format!("dhcp.{id}.name={name}")]);
            if opt(o, "ip").is_empty() {
                cmds.push(vec![s("set"), format!("dhcp.{id}.ip={ip_s}")]);
            }
        }
        None => {
            cmds.push(vec![s("set"), s("dhcp.cgmon_new=host")]);
            cmds.push(vec![s("set"), format!("dhcp.cgmon_new.name={name}")]);
            cmds.push(vec![s("set"), format!("dhcp.cgmon_new.mac={mac}")]);
            cmds.push(vec![s("set"), format!("dhcp.cgmon_new.ip={ip_s}")]);
            cmds.push(vec![s("set"), s("dhcp.cgmon_new.dns=1")]);
        }
    }
    match doms.first() {
        Some((id, _)) => cmds.push(vec![s("set"), format!("dhcp.{id}.name={name}")]),
        None => {
            cmds.push(vec![s("set"), s("dhcp.cgmon_dom=domain")]);
            cmds.push(vec![s("set"), format!("dhcp.cgmon_dom.name={name}")]);
            cmds.push(vec![s("set"), format!("dhcp.cgmon_dom.ip={ip_s}")]);
        }
    }
    cmds
}

fn uci(args: &[String]) -> Result<String, String> {
    let o = std::process::Command::new("uci").args(args).output().map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

/// Записать имя (или убрать) и перечитать dnsmasq. Именованные секции «cgmon_new/cgmon_dom»
/// сразу переименовываются в анонимные — следующее имя не столкнётся с ними.
pub fn apply(mac: &str, ip: Ipv4Addr, name: &str) -> Result<(), String> {
    if crate::util::readonly() {
        return Err("read-only".into());
    }
    let show = uci(&["-q".into(), "show".into(), "dhcp".into()]).unwrap_or_default();
    let mut cmds = uci_cmds(&show, mac, ip, name);
    if cmds.is_empty() {
        return Ok(());
    }
    // анонимные секции: add вместо set …=host
    for (named, typ) in [("cgmon_new", "host"), ("cgmon_dom", "domain")] {
        if cmds.iter().any(|c| c.get(1).map_or(false, |x| x == &format!("dhcp.{named}={typ}"))) {
            let id = uci(&["add".into(), "dhcp".into(), typ.into()])?.trim().to_string();
            cmds.retain(|c| c.get(1).map_or(true, |x| x != &format!("dhcp.{named}={typ}")));
            for c in cmds.iter_mut() {
                if let Some(x) = c.get_mut(1) {
                    *x = x.replace(&format!("dhcp.{named}."), &format!("dhcp.{id}."));
                }
            }
        }
    }
    for c in &cmds {
        uci(c)?;
    }
    uci(&["commit".into(), "dhcp".into()])?;
    let _ = std::process::Command::new("/etc/init.d/dnsmasq").arg("reload").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOW: &str = "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].domain='lan'\ndhcp.cfg01=host\ndhcp.cfg01.name='cam'\ndhcp.cfg01.mac='AA:BB:CC:DD:EE:01'\ndhcp.cfg01.ip='192.168.1.9'\ndhcp.cfg02=host\ndhcp.cfg02.mac='aa:bb:cc:dd:ee:02 aa:bb:cc:dd:ee:03'\ndhcp.cfg02.tag='x'\ndhcp.cfg03=domain\ndhcp.cfg03.name='cam'\ndhcp.cfg03.ip='192.168.1.9'\n";

    #[test]
    fn names_and_cmds() {
        assert!(name_ok("HOME-PC") && name_ok("tv2") && !name_ok("-x") && !name_ok("a b") && !name_ok("") && !name_ok("ТВ"));
        let ip: Ipv4Addr = "192.168.1.9".parse().unwrap();
        // есть host и domain — переименовать оба
        let c = uci_cmds(SHOW, "aa:bb:cc:dd:ee:01", ip, "camera1");
        assert_eq!(c, vec![vec!["set".to_string(), "dhcp.cfg01.name=camera1".into()], vec!["set".into(), "dhcp.cfg03.name=camera1".into()]]);
        // host без ip (несколько MAC, свой тег) — имя и ip; domain — новый
        let c = uci_cmds(SHOW, "AA:BB:CC:DD:EE:03", "192.168.1.20".parse().unwrap(), "pc");
        assert!(c.contains(&vec!["set".to_string(), "dhcp.cfg02.name=pc".into()]) && c.contains(&vec!["set".to_string(), "dhcp.cfg02.ip=192.168.1.20".into()]) && c.contains(&vec!["set".to_string(), "dhcp.cgmon_dom=domain".into()]));
        // нового — host и domain
        let c = uci_cmds(SHOW, "00:e0:1e:ca:a1:13", "192.168.1.254".parse().unwrap(), "HOME-PC");
        assert!(c.contains(&vec!["set".to_string(), "dhcp.cgmon_new.mac=00:e0:1e:ca:a1:13".into()]) && c.contains(&vec!["set".to_string(), "dhcp.cgmon_dom.name=HOME-PC".into()]));
        // убрать: host только с нашими полями — целиком, domain — целиком; с тегом — лишь имя
        assert_eq!(uci_cmds(SHOW, "aa:bb:cc:dd:ee:01", ip, ""), vec![vec!["delete".to_string(), "dhcp.cfg01".into()], vec!["delete".into(), "dhcp.cfg03".into()]]);
        assert_eq!(uci_cmds(SHOW, "aa:bb:cc:dd:ee:02", "10.0.0.1".parse().unwrap(), ""), vec![vec!["delete".to_string(), "dhcp.cfg02.name".into()]]);
    }
}
