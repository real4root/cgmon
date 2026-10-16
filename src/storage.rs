//! Где лежат промежуточные данные cgmon (`storage` в cgmon.yaml): учёт трафика,
//! платный трафик, метрики по сайтам, учитель отдачи, порты, центр сбора, кеш
//! производителей, напоминания об оплате.
//!
//! - `flash` — /etc/cgmon: ничего не пропадает, но встроенная flash изнашивается;
//! - `tmp` — /tmp/cgmon/data: без износа flash, после перезагрузки данные удаляются;
//! - свой каталог (`/mnt/usb/cgmon`) — USB-флешка или диск: и flash цела, и данные
//!   переживают перезагрузку. Пока носитель не смонтирован — пишем в /tmp/cgmon/data (не на
//!   внутреннюю flash под точкой монтирования), появится — данные переезжают туда.
//!
//! Настройки (cgmon.yaml, runtime.json), свой список бесплатных сетей и состояние
//! DNS-страховки всегда остаются на flash: без них роутер после перезагрузки вёл бы
//! себя иначе. Пути в конфиге не меняются — `path()` переводит /etc/cgmon/<файл> в
//! текущий каталог при каждом чтении и записи, поэтому смена работает на лету.

use std::sync::Mutex;

const FLASH: &str = "/etc/cgmon/";
const TMP: &str = "/tmp/cgmon/data/";
/// всегда на flash
const KEEP: &[&str] = &["cgmon.yaml", "runtime.json", "tasix.txt", "dnsguard.json"];

/// (каталог сейчас — пусто = flash, ошибка своего каталога)
static CUR: Mutex<(String, String)> = Mutex::new((String::new(), String::new()));

/// Путь файла данных с учётом `storage`.
pub fn path(p: &str) -> String {
    let cur = CUR.lock().map(|c| c.0.clone()).unwrap_or_default();
    map(p, &cur)
}

fn map(p: &str, dir: &str) -> String {
    match p.strip_prefix(FLASH) {
        Some(rest) if !dir.is_empty() && !rest.contains('/') && !KEEP.contains(&rest) => format!("{dir}{rest}"),
        _ => p.to_string(),
    }
}

/// Ошибка своего каталога (не смонтирован и т. п.) — для страницы.
pub fn error() -> String {
    CUR.lock().map(|c| c.1.clone()).unwrap_or_default()
}

/// Каталог сейчас (для страницы): /etc/cgmon/, /tmp/cgmon/ или свой.
pub fn dir() -> String {
    let c = CUR.lock().map(|c| c.0.clone()).unwrap_or_default();
    if c.is_empty() { FLASH.into() } else { c }
}

/// Свой каталог — только на сменных носителях и разделах данных (не /proc, /sys, /dev…).
const ROOTS: &[&str] = &["/mnt/", "/media/", "/opt/", "/srv/", "/data/", "/tmp/"];

/// Значение `storage` верно: flash, tmp или свой каталог (в ROOTS, без «..»).
pub fn valid(v: &str) -> bool {
    matches!(v, "flash" | "tmp")
        || (ROOTS.iter().any(|r| v.starts_with(r) && v.len() > r.len()) && v.len() <= 200 && !v.split('/').any(|x| x == ".." || x == ".") && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)) && !v.trim_end_matches('/').is_empty() && !v.starts_with(FLASH.trim_end_matches('/')))
}

fn dev_of(p: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.dev())
}

/// Свой каталог можно использовать: есть (или создаётся) и лежит не на корневой ФС —
/// иначе несмонтированная флешка тихо превратилась бы в запись во внутреннюю flash.
fn custom_ready(d: &str) -> Result<(), String> {
    let d = d.trim_end_matches('/');
    let root = dev_of("/");
    if std::path::Path::new(d).is_dir() {
        return if dev_of(d) == root { Err(format!("{d} на внутренней памяти роутера (носитель не смонтирован?)")) } else { Ok(()) };
    }
    let parent = std::path::Path::new(d).parent().and_then(|p| p.to_str()).unwrap_or("/");
    if !std::path::Path::new(parent).is_dir() || dev_of(parent) == root {
        return Err(format!("{d}: носитель не смонтирован"));
    }
    std::fs::create_dir_all(d).map_err(|e| format!("{d}: {e}"))
}

/// Применить `storage`: при старте (`migrate` = false) и при смене или появлении
/// носителя (true — файлы `files` копируются из старого каталога в новый).
pub fn apply(want: &str, files: &[String], migrate: bool) {
    let (dir, err) = match want {
        "flash" | "" => (String::new(), String::new()),
        "tmp" => (TMP.to_string(), String::new()),
        d => match custom_ready(d) {
            Ok(()) => (format!("{}/", d.trim_end_matches('/')), String::new()),
            Err(e) => (TMP.to_string(), format!("{e} — данные пока в {TMP}")),
        },
    };
    let Ok(mut cur) = CUR.lock() else { return };
    if err != cur.1 {
        if !err.is_empty() {
            crate::log_err!("storage: {err}");
        }
        cur.1 = err;
    }
    if dir == cur.0 {
        return;
    }
    if !dir.is_empty() && !crate::util::readonly() {
        let _ = std::fs::create_dir_all(dir.trim_end_matches('/'));
    }
    if migrate && !crate::util::readonly() {
        for f in files {
            let (old, new) = (map(f, &cur.0), map(f, &dir));
            if old == new {
                continue;
            }
            if let Ok(b) = std::fs::read(&old) {
                match crate::util::write_atomic(&new, &b, 0o600) {
                    Ok(()) => crate::log_info!("storage: {old} → {new}"),
                    Err(e) => crate::log_err!("storage: {old} → {new}: {e}"),
                }
            }
        }
    }
    crate::log_info!("storage: data in {}", if dir.is_empty() { FLASH } else { &dir });
    cur.0 = dir;
}

/// Свой каталог: раз в 30 с проверить носитель (вставили флешку — данные переедут
/// из /tmp/cgmon; отвалилась — запись пойдёт в /tmp/cgmon).
pub fn recheck(want: &str, now_ms: i64, files: impl FnOnce() -> Vec<String>) {
    // MIPS32 без 64-битных атомиков — Mutex
    static AT: std::sync::Mutex<i64> = std::sync::Mutex::new(0);
    if !want.starts_with('/') || AT.lock().map_or(false, |a| now_ms - *a < 30_000) {
        return;
    }
    if let Ok(mut a) = AT.lock() {
        *a = now_ms;
    }
    apply(want, &files(), true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        assert_eq!(map("/etc/cgmon/witness.json", "/tmp/cgmon/data/"), "/tmp/cgmon/data/witness.json");
        assert_eq!(map("/etc/cgmon/runtime.json", "/tmp/cgmon/"), "/etc/cgmon/runtime.json");
        assert_eq!(map("/etc/cgmon/dnsguard.json", "/mnt/usb/c/"), "/etc/cgmon/dnsguard.json");
        assert_eq!(map("/opt/x.json", "/tmp/cgmon/"), "/opt/x.json");
        assert_eq!(map("/etc/cgmon/acct_state.json", ""), "/etc/cgmon/acct_state.json");
        assert!(valid("flash") && valid("tmp") && valid("/mnt/usb/cgmon"));
        assert!(!valid("/mnt/../etc") && !valid("/proc/x") && !valid("/mnt/") && !valid("usb") && !valid("/etc/cgmon") && !valid("/") && !valid("/mnt/a b"));
    }
}
