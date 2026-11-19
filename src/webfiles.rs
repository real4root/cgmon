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
    gunzip_pub(gz)
}

/// Распаковать встроенные сжатые данные (переводы — src/i18n.rs).
pub fn gunzip_pub(gz: &[u8]) -> Result<Vec<u8>, String> {
    let tmp = format!("{}/.unpack.{}.gz", crate::util::RUN_DIR, std::process::id());
    let _ = std::fs::create_dir_all(crate::util::RUN_DIR);
    std::fs::write(&tmp, gz).map_err(|e| format!("{tmp}: {e}"))?;
    let o = std::process::Command::new("gzip").arg("-dc").arg(&tmp).stderr(std::process::Stdio::null()).output();
    let _ = std::fs::remove_file(&tmp);
    let o = o.map_err(|e| format!("gzip: {e}"))?;
    if !o.status.success() || o.stdout.is_empty() {
        return Err(tr!("gzip -dc: ошибка").into());
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
    server_setup(DIR);
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

// ---- веб-сервер роутера: CGI /cgi-bin/api_* ----
// uhttpd (OpenWrt по умолчанию, и Gargoyle) сам запускает /www/cgi-bin/* — ничего не нужно.
// nginx (luci-nginx) CGI не запускает и отдаёт текст скрипта («#!/bin/sh…» вместо
// JSON): LuCI под nginx работает через uwsgi (emperor + плагин cgi) — кладём рядом
// свой vassal и location для /cgi-bin/api_*. Корень CGI — там, где файлы лежат на
// самом деле: uwsgi раскрывает ссылки и не запускает скрипт вне корня.
// lighttpd: mod_cgi, правило для /cgi-bin/api_* в conf.d. Скрипты ходят к демону
// через сокет только для root — lighttpd должен работать от root (иначе в лог совет).
const NGINX_LOC: &str = "/etc/nginx/conf.d/cgmon.locations";
const UWSGI_INI: &str = "/etc/uwsgi/vassals/cgmon-cgi.ini";
const LIGHTTPD_CONF: &str = "/etc/lighttpd/conf.d/90-cgmon.conf";
const MARK: &str = "# cgmon: CGI /cgi-bin/api_* — generated, do not edit";

/// Текст location для nginx; сокет emperor создаёт сам по имени vassal (on-demand).
pub fn nginx_locations() -> String {
    format!("{MARK}\nlocation ~ ^/cgi-bin/api_[a-z_]+$ {{\n\t\tinclude uwsgi_params;\n\t\tuwsgi_param SERVER_ADDR $server_addr;\n\t\tuwsgi_modifier1 9;\n\t\tuwsgi_read_timeout 120;\n\t\tuwsgi_pass unix:////var/run/cgmon-cgi.socket;\n}}\n")
}

/// vassal uwsgi: CGI из `root` (без ссылок), 2 процесса, засыпает без запросов.
pub fn uwsgi_ini(root: &str) -> String {
    format!("{MARK}\n[uwsgi]\nstrict = true\nif-not-env = UWSGI_EMPEROR_FD\nsocket = /var/run/cgmon-cgi.socket\nchmod-socket = 666\ncheap = true\nend-if =\nplugin = cgi\ncgi-mode = true\ncgi = {root}/\nchdir = {root}/\nbuffer-size = 10000\npost-buffering = 8192\nsocket-timeout = 120\nharakiri = 120\nprocesses = 2\nmaster = true\nno-orphans = true\ndisable-logging = true\nidle = 360\n")
}

/// lighttpd: запускать /cgi-bin/api_* как программы (mod_cgi, пустое расширение).
pub fn lighttpd_conf() -> String {
    format!("{MARK}\n$HTTP[\"url\"] =~ \"^/cgi-bin/api_[a-z_]+$\" {{\n\tcgi.assign = ( \"\" => \"\" )\n}}\n")
}

fn exists(p: &str) -> bool {
    std::path::Path::new(p).exists()
}

/// Записать, если отличается; true — записали.
fn put(path: &str, text: &str) -> Result<bool, String> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(text) {
        return Ok(false);
    }
    crate::util::write_atomic(path, text.as_bytes(), 0o644).map_err(|e| format!("{path}: {e}"))?;
    Ok(true)
}

/// Убрать свой файл (только с меткой); true — убрали.
fn drop_own(path: &str) -> bool {
    std::fs::read_to_string(path).map_or(false, |t| t.starts_with(MARK)) && std::fs::remove_file(path).is_ok()
}

/// Перечитать только работающий сервер (reload остановленного его бы запустил).
fn reload(svc: &str) -> &'static str {
    let running = std::process::Command::new("pidof").arg(svc).stdout(std::process::Stdio::null()).status().map_or(false, |s| s.success());
    if !running {
        return "not running";
    }
    let ok = std::process::Command::new(format!("/etc/init.d/{svc}")).arg("reload").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map_or(false, |s| s.success());
    if ok { "reloaded" } else { "reload failed" }
}

/// Пользователь lighttpd из lighttpd.conf (`server.username = "http"`), по умолчанию root.
pub fn lighttpd_user(conf: &str) -> String {
    conf.lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("server.username").and_then(|r| r.trim_start().strip_prefix('=')).map(|v| v.trim().trim_matches('"').to_string()))
        .unwrap_or_else(|| "root".into())
}

/// Настроить веб-сервер роутера под CGI cgmon. Возвращает строки «что сделано/что не так»
/// (для `cgmon web-setup`); в лог — только изменения и предупреждения (раз за запуск).
pub fn server_setup(root: &str) -> Vec<String> {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let mut out = Vec::new();
    let mut warn = Vec::new();
    if crate::util::readonly() {
        out.push("read-only mode: web server config untouched".to_string());
        return out;
    }
    if exists("/usr/sbin/uhttpd") {
        out.push("uhttpd: runs /cgi-bin/* itself — nothing to do".into());
    }
    if std::path::Path::new("/etc/nginx/conf.d").is_dir() {
        if std::path::Path::new("/etc/uwsgi/vassals").is_dir() && exists("/usr/lib/uwsgi/cgi_plugin.so") {
            let r = put(UWSGI_INI, &uwsgi_ini(root)).and_then(|a| put(NGINX_LOC, &nginx_locations()).map(|b| (a, b)));
            match r {
                Ok((_, true)) => {
                    let m = format!("web: nginx: {NGINX_LOC} + {UWSGI_INI} (CGI root {root}), nginx {}", reload("nginx"));
                    crate::log_info!("{m}");
                    out.push(m);
                }
                Ok((a, false)) => {
                    if a {
                        crate::log_info!("web: nginx: {UWSGI_INI} updated (CGI root {root})");
                    }
                    out.push(format!("nginx: {NGINX_LOC} + {UWSGI_INI} in place (CGI root {root})"));
                }
                Err(e) => warn.push(format!("web: nginx: {e}")),
            }
        } else {
            warn.push("web: nginx without uwsgi cgi plugin — /cgi-bin/api_* will not run; install uwsgi uwsgi-cgi-plugin (luci-nginx does)".into());
        }
    }
    if std::path::Path::new("/etc/lighttpd/conf.d").is_dir() {
        if exists("/usr/lib/lighttpd/mod_cgi.so") && exists("/etc/lighttpd/conf.d/30-cgi.conf") {
            match put(LIGHTTPD_CONF, &lighttpd_conf()) {
                Ok(true) => {
                    let m = format!("web: lighttpd: {LIGHTTPD_CONF}, lighttpd {}", reload("lighttpd"));
                    crate::log_info!("{m}");
                    out.push(m);
                }
                Ok(false) => out.push(format!("lighttpd: {LIGHTTPD_CONF} in place")),
                Err(e) => warn.push(format!("web: lighttpd: {e}")),
            }
            let user = lighttpd_user(&std::fs::read_to_string("/etc/lighttpd/lighttpd.conf").unwrap_or_default());
            if user != "root" {
                warn.push(format!("web: lighttpd runs CGI as '{user}': the page shows data, but settings and history need root — remove server.username and server.groupname from /etc/lighttpd/lighttpd.conf (lighttpd refuses uid 0 there)"));
            }
        } else {
            warn.push("web: lighttpd without mod_cgi — /cgi-bin/api_* will not run; install lighttpd-mod-cgi".into());
        }
    }
    if !warn.is_empty() && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        for w in &warn {
            crate::log_err!("{w}");
        }
    }
    out.extend(warn);
    out
}

/// Снять настройку веб-сервера (`--uninstall`): только свои файлы (с меткой).
fn server_remove() -> Vec<&'static str> {
    let mut gone = Vec::new();
    let nginx = [NGINX_LOC, UWSGI_INI].iter().fold(false, |n, p| drop_own(p) || n);
    if nginx {
        reload("nginx");
        gone.extend([NGINX_LOC, UWSGI_INI]);
    }
    if drop_own(LIGHTTPD_CONF) {
        reload("lighttpd");
        gone.push(LIGHTTPD_CONF);
    }
    gone
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
            Ok(()) => println!("{}", tr!("служба остановлена и снята: {}", init)),
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
    let gone = server_remove();
    if !gone.is_empty() {
        println!("{}", tr!("настройка веб-сервера убрана: {}", gone.join(", ")));
    }
    crate::luci::uninstall();
    let _ = std::fs::remove_dir_all(crate::util::RUN_DIR);
    println!("{}", tr!("ссылок страницы убрано: {}; /tmp/cgmon очищен", n));
    println!("{}", tr!("остались (удалите сами, если не нужны): /opt/cgmon (бинарник), /etc/cgmon (настройки и данные)"));
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
        let ini = uwsgi_ini(DIR);
        assert!(ini.contains("cgi = /tmp/cgmon/www/\n") && ini.contains("plugin = cgi") && ini.starts_with(MARK));
        assert!(lighttpd_conf().contains("cgi.assign = ( \"\" => \"\" )"));
        assert_eq!(lighttpd_user("# server.username = \"x\"\nserver.username             = \"http\"\n"), "http");
        assert_eq!(lighttpd_user("server.port = 80\n"), "root");
        let loc = nginx_locations();
        assert!(loc.contains("uwsgi_modifier1 9;") && loc.contains("cgmon-cgi.socket") && loc.matches('{').count() == loc.matches('}').count());
        let b = gunzip(page.2).unwrap();
        assert!(String::from_utf8_lossy(&b).contains("<title>"));
    }
}
