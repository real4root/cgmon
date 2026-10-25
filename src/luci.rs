//! Страница LuCI «Службы → cgmon»: пароль страницы мониторинга и то, без чего cgmon
//! не работает и чего нельзя задать со страницы мониторинга (центр сбора, его токен,
//! Telegram). Страница (luci/cgmon.js) вызывает через rpcd сам cgmon:
//!   cgmon luci-get        — JSON для формы (секреты — только «задан / не задан»);
//!   cgmon luci-set JSON   — проверить, вписать в cgmon.yaml (комментарии целы,
//!                           прежний файл — в .bak-luci) и перезапустить службу.
//! Файлы LuCI ставит сам cgmon при запуске (install), если на роутере JS-LuCI.

use crate::config::{self, Config};
use crate::json::J;
use crate::value::{json_str, parse_json, Value};

const VIEW: &str = include_str!("../luci/cgmon.js");
const MENU: &str = include_str!("../luci/menu.json");
const ACL: &str = include_str!("../luci/acl.json");

const VIEW_PATH: &str = "/www/luci-static/resources/view/cgmon.js";
const MENU_PATH: &str = "/usr/share/luci/menu.d/luci-app-cgmon.json";
const ACL_PATH: &str = "/usr/share/rpcd/acl.d/luci-app-cgmon.json";

/// Ключи, которые меняет LuCI (остальное — на странице мониторинга).
const KEYS: &[&str] = &["web.password", "report.enabled", "report.urls", "report.token", "report.name", "hub.enabled", "hub.token", "hub.telegram_bot_token", "hub.telegram_chat_id"];

fn exe() -> String {
    std::env::current_exe().ok().and_then(|p| p.canonicalize().ok()).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "/opt/cgmon/cgmon".into())
}

/// Поставить/обновить файлы LuCI (если LuCI есть и они изменились); rpcd — перечитать права.
pub fn install() {
    if crate::util::readonly() || !std::path::Path::new("/usr/share/luci/menu.d").is_dir() || !std::path::Path::new("/www/luci-static/resources/view").is_dir() {
        return;
    }
    let bin = exe();
    let mut changed = false;
    for (path, text) in [(VIEW_PATH, VIEW.replace("__CGMON_BIN__", &bin)), (MENU_PATH, MENU.to_string()), (ACL_PATH, ACL.replace("__CGMON_BIN__", &bin))] {
        if std::fs::read_to_string(path).ok().as_deref() == Some(text.as_str()) {
            continue;
        }
        match crate::util::write_atomic(path, text.as_bytes(), 0o644) {
            Ok(()) => changed = true,
            Err(e) => crate::log_err!("luci: {path}: {e}"),
        }
    }
    if changed {
        // новые права и пункт меню: rpcd перечитать, кэш меню LuCI сбросить
        let _ = std::process::Command::new("/etc/init.d/rpcd").arg("reload").output();
        if let Ok(rd) = std::fs::read_dir("/tmp") {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("luci-indexcache") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let _ = std::fs::remove_dir_all("/tmp/luci-modulecache");
        crate::log_info!("luci: \"Services \u{2192} cgmon\" installed");
    }
}

/// Убрать файлы LuCI (cgmon --uninstall).
pub fn uninstall() {
    for p in [VIEW_PATH, MENU_PATH, ACL_PATH] {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::process::Command::new("/etc/init.d/rpcd").arg("reload").output();
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}

/// cgmon luci-get: состояние для формы.
pub fn get(path: &str) -> i32 {
    let c = match config::load(path) {
        Ok(c) => c,
        Err(e) => {
            println!("{{\"error\":{}}}", qs(&e));
            return 1;
        }
    };
    let mut j = J::new();
    j.obj().key("version").str(&crate::variant::version()).key("config").str(path).key("running").bool(std::path::Path::new(&c.paths.socket).exists());
    j.key("web").obj().key("password_set").bool(!c.web.password.is_empty()).end_obj();
    j.key("report").obj().key("enabled").bool(c.report.enabled).key("urls").arr();
    for u in &c.report.urls {
        j.str(u);
    }
    j.end_arr().key("token_set").bool(!c.report.token.is_empty()).key("name").str(&c.report.name).key("hostname").str(&hostname()).end_obj();
    let tg_list = c.hub.telegram.iter().filter(|t| !t.bot_token.is_empty()).count();
    j.key("hub").obj().key("enabled").bool(c.hub.enabled).key("listen").str(&c.hub.listen).key("token_set").bool(!c.hub.token.is_empty());
    j.key("tg_bot_set").bool(!c.hub.telegram_bot_token.is_empty() || tg_list > 0).key("tg_chat").str(&c.hub.telegram_chat_id).key("tg_list").int(tg_list as i64);
    j.end_obj().end_obj();
    println!("{}", j.b);
    0
}

fn qs(s: &str) -> String {
    let mut o = String::new();
    json_str(&mut o, s);
    o
}

fn fail(e: &str) -> i32 {
    println!("{{\"error\":{}}}", qs(e));
    1
}

/// Строка без управляющих символов и кавычек, длина в пределах.
fn plain(s: &str, min: usize, max: usize) -> bool {
    let n = s.chars().count();
    n >= min && n <= max && !s.chars().any(|c| c.is_control() || c == '"' || c == '\\')
}

/// Проверка одного значения из формы → текст для yamledit::set.
fn yaml_value(key: &str, v: &Value) -> Result<String, String> {
    let s = |v: &Value| v.as_str().map(String::from).ok_or_else(|| format!("{key}: expected a string"));
    match key {
        "report.enabled" | "hub.enabled" => match v {
            Value::Bool(b) => Ok(b.to_string()),
            _ => Err(format!("{key}: expected yes/no")),
        },
        "report.urls" => {
            let Value::List(l) = v else { return Err(format!("{key}: expected a list of addresses")) };
            let mut out = Vec::new();
            for x in l.iter().take(8) {
                let u = x.as_str().unwrap_or("").trim().to_string();
                if !u.is_empty() {
                    if !plain(&u, 8, 200) || !u.starts_with("http://") {
                        return Err(format!("hub address {u:?}: expected http://address:7788/api/v1/report"));
                    }
                    out.push(qs(&u));
                }
            }
            Ok(format!("[{}]", out.join(", ")))
        }
        "web.password" => {
            let p = s(v)?;
            if !plain(&p, 6, 64) {
                return Err("password: 6 to 64 characters, no quotes or backslashes".into());
            }
            Ok(qs(&p))
        }
        "report.token" | "hub.token" => {
            let t = s(v)?;
            if !plain(&t, 16, 200) {
                return Err(format!("{key}: token must be at least 16 characters, no quotes"));
            }
            Ok(qs(&t))
        }
        "report.name" => {
            let n = s(v)?;
            if !n.is_empty() && !n.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) || n.len() > 64 {
                return Err("router name: letters, digits, - _ . (up to 64)".into());
            }
            Ok(qs(&n))
        }
        "hub.telegram_bot_token" => {
            let t = s(v)?;
            if !t.is_empty() && (!plain(&t, 20, 100) || !t.contains(':')) {
                return Err("Telegram bot token: like 123456:ABC… (from @BotFather)".into());
            }
            Ok(qs(&t))
        }
        "hub.telegram_chat_id" => {
            let t = s(v)?;
            if !t.is_empty() && !t.chars().all(|c| c.is_ascii_digit() || c == '-') {
                return Err("Telegram chat: a number (chat or user id)".into());
            }
            Ok(qs(&t))
        }
        _ => Err(format!("{key}: not changed here")),
    }
}

/// cgmon luci-set '{"web.password":"…", …}': проверить, вписать, перезапустить.
pub fn set(path: &str, arg: &str) -> i32 {
    let Ok(Value::Map(m)) = parse_json(arg) else { return fail("expected a JSON object") };
    if m.is_empty() {
        return fail("nothing to change");
    }
    let Ok(old) = std::fs::read_to_string(path) else { return fail(&format!("{path}: cannot read")) };
    let mut text = old.clone();
    let cur = config::load(path).unwrap_or_else(|_| config::defaults());
    for (k, v) in &m {
        if !KEYS.contains(&k.as_str()) {
            return fail(&format!("{k}: not changed here"));
        }
        // список ботов уже в cgmon.yaml — одиночный бот не добавлять поверх
        if k.starts_with("hub.telegram_") && cur.hub.telegram.iter().any(|t| !t.bot_token.is_empty()) {
            return fail("Telegram is already configured as the hub.telegram list in cgmon.yaml — change it there");
        }
        match yaml_value(k, v) {
            Ok(y) => text = crate::yamledit::set(&text, k, &y),
            Err(e) => return fail(&e),
        }
    }
    // проверить собранное целиком, до записи
    let probe = format!("{path}.luci-check");
    if crate::util::write_atomic(&probe, text.as_bytes(), 0o600).is_err() {
        return fail(&format!("{path}: write failed"));
    }
    let checked = config::load(&probe).and_then(|c| crate::livecfg::validate(&c).map(|_| c));
    let _ = std::fs::remove_file(&probe);
    let c: Config = match checked {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let _ = crate::util::write_atomic(&format!("{path}.bak-luci"), old.as_bytes(), 0o600);
    if let Err(e) = crate::util::write_atomic(path, text.as_bytes(), 0o600) {
        return fail(&format!("{path}: {e}"));
    }
    // новые настройки — через перезапуск службы (cgmon.yaml читается при старте)
    let restarted = std::path::Path::new("/etc/init.d/cgmon").exists() && std::process::Command::new("/etc/init.d/cgmon").arg("restart").output().map_or(false, |o| o.status.success());
    let _ = c;
    println!("{{\"ok\":true,\"restarted\":{restarted}}}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(yaml_value("web.password", &Value::Str("Pa$s#1".into())).unwrap(), "\"Pa$s#1\"");
        assert!(yaml_value("web.password", &Value::Str("123".into())).is_err());
        assert!(yaml_value("web.password", &Value::Str("ab\"cdef".into())).is_err());
        assert_eq!(yaml_value("report.enabled", &Value::Bool(true)).unwrap(), "true");
        let urls = Value::List(vec![Value::Str("http://10.147.17.5:7788/api/v1/report".into()), Value::Str("".into())]);
        assert_eq!(yaml_value("report.urls", &urls).unwrap(), "[\"http://10.147.17.5:7788/api/v1/report\"]");
        assert!(yaml_value("report.urls", &Value::List(vec![Value::Str("https://x/".into())])).is_err());
        assert!(yaml_value("report.token", &Value::Str("short".into())).is_err());
        assert!(yaml_value("report.name", &Value::Str("chil 18".into())).is_err());
        assert!(yaml_value("hub.telegram_chat_id", &Value::Str("-100123".into())).is_ok());
        assert!(yaml_value("dry_run", &Value::Bool(true)).is_err());
        // встроенные файлы на месте
        assert!(VIEW.contains("__CGMON_BIN__") && ACL.contains("__CGMON_BIN__") && MENU.contains("admin/services/cgmon"));
    }

    #[test]
    fn set_writes_yaml() {
        let dir = std::env::temp_dir().join(format!("cgmon-luci-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("cgmon.yaml").to_string_lossy().into_owned();
        std::fs::write(&p, "# мой конфиг\nweb:\n  # пароль\n  password: \"\"\n").unwrap();
        assert_eq!(set(&p, r#"{"web.password":"secret77"}"#), 0);
        let t = std::fs::read_to_string(&p).unwrap();
        assert!(t.contains("# мой конфиг") && t.contains("# пароль") && t.contains("password: \"secret77\""), "{t}");
        assert_eq!(config::load(&p).unwrap().web.password, "secret77");
        assert_eq!(set(&p, r#"{"dry_run":false}"#), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
