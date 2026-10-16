//! Страница и CGI из бинарника (`web.embedded`, по умолчанию да): при запуске
//! сжатые копии (build.rs) распаковываются busybox `gzip -dc` в /tmp/cgmon/www, а в
//! /www ставятся символьные ссылки — status.html, cgi-bin/api_*, cgmon-plugins. На
//! flash нет ни одного файла страницы (на роутерах с 2–8 МБ это заметно), в RAM —
//! одна распакованная копия (~350 КБ), страница всегда той же версии, что и демон.
//! Ссылка на flash пишется один раз: если она уже указывает куда надо — не трогаем.
//! Раз в минуту проверка: /tmp очищен или ссылки сняты (sysupgrade) — восстановить.

include!(concat!(env!("OUT_DIR"), "/webfiles.rs"));

pub const DIR: &str = "/tmp/cgmon/www";
const WWW: &str = "/www";
/// каталог плагинов страницы (src/plugins.rs) — тоже в /tmp, в /www — ссылка
pub const PLUGINS: &str = "/tmp/cgmon/www/cgmon-plugins";

/// Распаковать (busybox gzip): сжатое — во временный файл, gzip -dc читает его
/// (без второго потока для записи в stdin).
fn gunzip(gz: &[u8]) -> Result<Vec<u8>, String> {
    let tmp = format!("{}/.unpack.{}.gz", crate::util::RUN_DIR, std::process::id());
    let _ = std::fs::create_dir_all(crate::util::RUN_DIR);
    std::fs::write(&tmp, gz).map_err(|e| format!("{tmp}: {e}"))?;
    let o = std::process::Command::new("gzip").arg("-dc").arg(&tmp).stderr(std::process::Stdio::null()).output();
    let _ = std::fs::remove_file(&tmp);
    let o = o.map_err(|e| format!("gzip: {e}"))?;
    if !o.status.success() || o.stdout.is_empty() {
        return Err("gzip -dc: ошибка".into());
    }
    Ok(o.stdout)
}

static ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Куда класть плагины страницы: при встроенной странице — /tmp/cgmon/www/cgmon-plugins
/// (в /www — ссылка), иначе — прямо в /www.
pub fn plugins_dir() -> &'static str {
    if ON.load(std::sync::atomic::Ordering::Relaxed) { PLUGINS } else { "/www/cgmon-plugins" }
}

/// Ссылка /www/<name> → <target>; уже такая — ничего не пишем.
fn link(name: &str, target: &str) -> Result<bool, String> {
    let at = format!("{WWW}/{name}");
    if std::fs::read_link(&at).ok().as_deref() == Some(std::path::Path::new(target)) {
        return Ok(false);
    }
    if let Some(parent) = std::path::Path::new(&at).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::symlink_metadata(&at) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(&at).map_err(|e| format!("{at}: {e}"))?,
        Ok(_) => std::fs::remove_file(&at).map_err(|e| format!("{at}: {e}"))?,
        Err(_) => {}
    }
    std::os::unix::fs::symlink(target, &at).map_err(|e| format!("{at}: {e}"))?;
    Ok(true)
}

/// Выложить страницу: при запуске (`force`) — распаковать всё; иначе — только если
/// /tmp очищен. Ссылки в /www — если есть /www (uhttpd) и не режим только чтения.
pub fn install(force: bool) {
    ON.store(true, std::sync::atomic::Ordering::Relaxed);
    let page = format!("{DIR}/status.html");
    if !force && std::path::Path::new(&page).exists() && links_ok() {
        return;
    }
    let mut n = 0;
    for (name, mode, gz) in FILES {
        let dst = format!("{DIR}/{name}");
        if let Some(p) = std::path::Path::new(&dst).parent() {
            let _ = std::fs::create_dir_all(p);
        }
        match gunzip(gz).and_then(|b| crate::util::write_atomic(&dst, &b, *mode).map_err(|e| format!("{dst}: {e}"))) {
            Ok(()) => n += 1,
            Err(e) => crate::log_err!("web: {name}: {e}"),
        }
    }
    let _ = std::fs::create_dir_all(PLUGINS);
    if crate::util::readonly() || !std::path::Path::new(WWW).is_dir() {
        crate::log_info!("web: page unpacked to {DIR} ({n} files), /www untouched");
        return;
    }
    let mut made = Vec::new();
    for (name, _, _) in FILES {
        match link(name, &format!("{DIR}/{name}")) {
            Ok(true) => made.push(name.to_string()),
            Ok(false) => {}
            Err(e) => crate::log_err!("web: link {e}"),
        }
    }
    match link("cgmon-plugins", PLUGINS) {
        Ok(true) => made.push("cgmon-plugins".into()),
        Ok(false) => {}
        Err(e) => crate::log_err!("web: link {e}"),
    }
    crate::log_info!("web: page unpacked to {DIR} ({n} files){}", if made.is_empty() { String::new() } else { format!(", /www links: {}", made.join(", ")) });
}

fn links_ok() -> bool {
    crate::util::readonly()
        || !std::path::Path::new(WWW).is_dir()
        || FILES.iter().all(|(name, _, _)| std::fs::read_link(format!("{WWW}/{name}")).is_ok())
}

/// Раз в минуту (из такта): восстановить после очистки /tmp или снятия ссылок.
pub fn check(now_ms: i64) {
    // MIPS32 без 64-битных атомиков — Mutex
    static AT: std::sync::Mutex<i64> = std::sync::Mutex::new(0);
    if AT.lock().map_or(false, |a| now_ms - *a < 60_000) {
        return;
    }
    if let Ok(mut a) = AT.lock() {
        *a = now_ms;
    }
    install(false);
}

/// `cgmon --uninstall`: остановить и снять службу, убрать ссылки страницы из /www.
/// Бинарник, конфиг и данные (/opt/cgmon, /etc/cgmon) остаются — удалить вручную.
pub fn uninstall() -> i32 {
    let init = "/etc/init.d/cgmon";
    if std::path::Path::new(init).exists() {
        for a in ["stop", "disable"] {
            let _ = std::process::Command::new(init).arg(a).status();
        }
        match std::fs::remove_file(init) {
            Ok(()) => println!("служба остановлена и снята: {init}"),
            Err(e) => println!("{init}: {e}"),
        }
    }
    let mut n = 0;
    for name in FILES.iter().map(|f| f.0).chain(["cgmon-plugins"]) {
        let at = format!("{WWW}/{name}");
        if std::fs::read_link(&at).map_or(false, |t| t.starts_with(DIR)) && std::fs::remove_file(&at).is_ok() {
            n += 1;
        }
    }
    crate::luci::uninstall();
    let _ = std::fs::remove_dir_all(crate::util::RUN_DIR);
    println!("ссылок страницы убрано: {n}; /tmp/cgmon очищен");
    println!("остались (удалите сами, если не нужны): /opt/cgmon (бинарник), /etc/cgmon (настройки и данные)");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded() {
        // страница и основные CGI встроены; сжатие честное
        let page = FILES.iter().find(|f| f.0 == "status.html").expect("status.html");
        assert!(page.2.len() > 1000 && page.2.len() < 200_000 && page.2[..2] == [0x1f, 0x8b]);
        for n in ["cgi-bin/api_status", "cgi-bin/api_router", "cgi-bin/api_set", "cgi-bin/api_hist"] {
            assert!(FILES.iter().any(|f| f.0 == n && f.1 == 0o755), "{n}");
        }
        let b = gunzip(page.2).unwrap();
        assert!(String::from_utf8_lossy(&b).contains("<title>"));
    }
}
