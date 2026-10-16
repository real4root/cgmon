//! Журнал (формат Go log: «2006/01/02 15:04:05 INFO …» в stderr — procd
//! отправляет в syslog), местное время, RFC 3339 как Go time в JSON,
//! атомарная запись файлов.

use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(1);
static READONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Только чтение (CGMON_READONLY=1): параллельный запуск рядом с рабочим
/// демоном — не трогать nft, общие файлы состояния и журналы.
pub fn readonly() -> bool {
    READONLY.load(Ordering::Relaxed)
}

pub fn init_readonly() {
    READONLY.store(std::env::var("CGMON_READONLY").map_or(false, |v| v == "1"), Ordering::Relaxed);
}

/// error | info | debug (меняется со страницы).
pub fn set_log_level(level: &str) {
    let v = match level.to_ascii_lowercase().as_str() {
        "error" | "err" => 0,
        "debug" => 2,
        _ => 1,
    };
    LEVEL.store(v, Ordering::Relaxed);
}

pub fn log_enabled(lv: u8) -> bool {
    LEVEL.load(Ordering::Relaxed) >= lv
}

pub fn log_line(tag: &str, msg: std::fmt::Arguments) {
    let t = local(crate::evloop::unix_now());
    eprintln!("{:04}/{:02}/{:02} {:02}:{:02}:{:02} {} {}", t.year, t.mon, t.day, t.hour, t.min, t.sec, tag, msg);
}

#[macro_export]
macro_rules! log_err {
    ($($a:tt)*) => { $crate::util::log_line("ERROR", format_args!($($a)*)) };
}
#[macro_export]
macro_rules! log_info {
    ($($a:tt)*) => { if $crate::util::log_enabled(1) { $crate::util::log_line("INFO", format_args!($($a)*)) } };
}
#[macro_export]
macro_rules! log_debug {
    ($($a:tt)*) => { if $crate::util::log_enabled(2) { $crate::util::log_line("DEBUG", format_args!($($a)*)) } };
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tm {
    pub year: i32,
    pub mon: u32,
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
    /// 0 = воскресенье
    pub wday: u32,
    /// смещение от UTC, с
    pub off: i64,
}

/// Местное время (TZ роутера через libc/musl: /etc/TZ, переменная TZ).
#[allow(deprecated)] // time_t: 64 бита на aarch64/x86_64 (musl 1.2 — везде)
pub fn local(unix: i64) -> Tm {
    let t: libc::time_t = unix as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    Tm {
        year: tm.tm_year + 1900,
        mon: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        min: tm.tm_min as u32,
        sec: tm.tm_sec as u32,
        wday: tm.tm_wday as u32,
        off: tm.tm_gmtoff as i64,
    }
}

/// RFC 3339 с наносекундами без хвостовых нулей и смещением, как Go
/// time.Time в encoding/json: 2026-10-14T10:05:20.12+05:00 (UTC — «Z»).
pub fn rfc3339(unix: i64, nanos: u32) -> String {
    rfc3339_tm(&local(unix), nanos)
}

pub fn rfc3339_tm(t: &Tm, nanos: u32) -> String {
    let mut s = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", t.year, t.mon, t.day, t.hour, t.min, t.sec);
    if nanos > 0 {
        let f = format!("{:09}", nanos);
        s.push('.');
        s.push_str(f.trim_end_matches('0'));
    }
    if t.off == 0 {
        s.push('Z');
    } else {
        let (sign, o) = if t.off < 0 { ('-', -t.off) } else { ('+', t.off) };
        s.push_str(&format!("{}{:02}:{:02}", sign, o / 3600, (o % 3600) / 60));
    }
    s
}

/// RFC 3339 без дробной части (как Go time.RFC3339 в записях журналов).
pub fn rfc3339_secs(unix: i64) -> String {
    rfc3339(unix, 0)
}

/// Дни от 1970-01-01 для даты (алгоритм Хиннанта).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Разбор RFC 3339 («2026-10-14T11:17:15.145452829+05:00», «…Z») → (unix, нс).
pub fn parse_rfc3339(s: &str) -> Option<(i64, u32)> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't' && b[10] != b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut i = 19;
    let mut nanos: u32 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let st = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[st..i];
        let mut f = frac.to_string();
        f.truncate(9);
        while f.len() < 9 {
            f.push('0');
        }
        nanos = f.parse().ok()?;
    }
    let off = match b.get(i)? {
        b'Z' | b'z' => 0,
        c @ (b'+' | b'-') => {
            let oh = num(i + 1, i + 3)?;
            let om = num(i + 4, i + 6)?;
            let o = oh * 3600 + om * 60;
            if *c == b'-' {
                -o
            } else {
                o
            }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    Some((days * 86400 + h * 3600 + mi * 60 + se - off, nanos))
}

/// Unix-время с наносекундами (стенные часы).
pub fn now_wall() -> (i64, u32) {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    (ts.tv_sec as i64, ts.tv_nsec as u32)
}

/// Все временные файлы cgmon на роутере — только здесь (подкаталоги — сколько угодно).
pub const RUN_DIR: &str = "/tmp/cgmon";
/// страницу смотрят: CGI трогает файл, демон смотрит на его время
pub const WEB_HB: &str = "/tmp/cgmon/web_hb";

/// Старое имя в /tmp (до 2.4.8: /tmp/cgmon_x, /tmp/cgmon.x, /tmp/cgmon-hub.x) → путь
/// в /tmp/cgmon; None — не старое имя.
pub fn tmp_legacy(p: &str) -> Option<String> {
    let rest = p.strip_prefix("/tmp/cgmon")?;
    let name = rest.strip_prefix('_').or_else(|| rest.strip_prefix('.')).or_else(|| rest.strip_prefix('-'))?;
    (!name.is_empty() && !name.contains('/')).then(|| format!("{RUN_DIR}/{name}"))
}

/// Старт: каталог /tmp/cgmon и перенос файлов, которые прежние версии клали прямо в
/// /tmp (учёт, график, журналы…); то, что пересоздаётся само, — удаляется.
pub fn migrate_tmp() {
    let _ = std::fs::create_dir_all(RUN_DIR);
    if readonly() {
        return;
    }
    let Ok(rd) = std::fs::read_dir("/tmp") else { return };
    for e in rd.flatten() {
        let old = format!("/tmp/{}", e.file_name().to_string_lossy());
        let Some(new) = tmp_legacy(&old) else { continue };
        let regen = ["isolated.json", "wan_stats_dev", "web_hb", "hardlimit.nft"].iter().any(|n| new.ends_with(n));
        if regen || std::path::Path::new(&new).exists() || std::fs::rename(&old, &new).is_err() {
            let _ = std::fs::remove_file(&old);
        } else {
            crate::log_info!("tmp: {old} → {new}");
        }
    }
}

/// Записать через временный файл и rename (читатель не увидит половину).
pub fn write_atomic(path: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.tmp");
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
        f.write_all(data)?;
    }
    std::fs::rename(&tmp, path)
}

/// Программа есть в PATH (или стандартных каталогах OpenWrt).
pub fn have_bin(name: &str) -> bool {
    let path = std::env::var("PATH").unwrap_or_default();
    let found = path.split(':').chain(["/usr/sbin", "/usr/bin", "/sbin", "/bin"]).any(|d| !d.is_empty() && std::path::Path::new(d).join(name).is_file());
    found
}

/// Сравнение без утечки времени (пароль страницы).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmp_paths() {
        assert_eq!(tmp_legacy("/tmp/cgmon_acct_state.json").as_deref(), Some("/tmp/cgmon/acct_state.json"));
        assert_eq!(tmp_legacy("/tmp/cgmon.incidents.jsonl.old").as_deref(), Some("/tmp/cgmon/incidents.jsonl.old"));
        assert_eq!(tmp_legacy("/tmp/cgmon-hub.jsonl").as_deref(), Some("/tmp/cgmon/hub.jsonl"));
        assert_eq!(tmp_legacy("/tmp/cgmon/incidents.jsonl"), None);
        assert_eq!(tmp_legacy("/tmp/cgmon"), None);
        assert_eq!(tmp_legacy("/tmp/other.json"), None);
    }

    #[test]
    fn rfc() {
        let t = Tm { year: 2026, mon: 10, day: 4, hour: 9, min: 5, sec: 3, wday: 0, off: 5 * 3600 };
        assert_eq!(rfc3339_tm(&t, 120_000_000), "2026-10-04T09:05:03.12+05:00");
        assert_eq!(rfc3339_tm(&Tm { off: 0, ..t }, 0), "2026-10-04T09:05:03Z");
        assert_eq!(rfc3339_tm(&Tm { off: -(3 * 3600 + 1800), ..t }, 0), "2026-10-04T09:05:03-03:30");
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"a", b"ab"));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20Z"), Some((1700000000, 0)));
        assert_eq!(parse_rfc3339("2023-11-15T03:13:20.5+05:00"), Some((1700000000, 500_000_000)));
        assert_eq!(parse_rfc3339("0001-01-01T00:00:00Z").map(|x| x.0), Some(-62135596800));
        assert!(parse_rfc3339("garbage").is_none());
    }
}

/// Go time.Duration.Round(секунда).String(): «45s», «5m30s», «1h2m3s», «0s».
pub fn go_secs(ms: u64) -> String {
    let s = (ms + 500) / 1000;
    match s {
        0 => "0s".into(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{}s", s / 60, s % 60),
        s => format!("{}h{}m{}s", s / 3600, s % 3600 / 60, s % 60),
    }
}
