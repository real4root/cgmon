//! Translation of texts the daemon produces itself (journal, events, incidents, log,
//! Telegram, CLI): the source string is the key (gettext style), catalogs per language
//! live in `i18n/<lang>.tsv` (one line `source<TAB>translation`, `\n`/`\t` escaped),
//! are embedded gzipped (build.rs) and only the active language is unpacked.
//!
//! Placeholders: `{}` — next argument, `{0}` … — argument by number (a translation may
//! reorder them), `{:.1}` / `{0:.1}` — number with that many decimals.
//!
//! Language: `lang:` in cgmon.yaml (auto | en | ru | uz | kk | zh), the page switches it
//! together with its own language (when settings may be changed).

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/i18n.rs"));

/// Supported languages, index = language id. 0 is the source language of the code.
pub const LANGS: [&str; 5] = ["ru", "en", "uz", "kk", "zh"];

static CUR: AtomicU8 = AtomicU8::new(0); // до set() — исходный текст (тесты сверяют его)
static MAPS: [OnceLock<HashMap<&'static str, &'static str>>; 5] = [OnceLock::new(), OnceLock::new(), OnceLock::new(), OnceLock::new(), OnceLock::new()];

/// Language code → id; unknown → None.
pub fn id(code: &str) -> Option<u8> {
    let c = code.trim().to_ascii_lowercase();
    let c = c.split(['-', '_', '.']).next().unwrap_or("");
    LANGS.iter().position(|l| *l == c).map(|i| i as u8)
}

/// Active language code.
pub fn code() -> &'static str {
    LANGS[CUR.load(Ordering::Relaxed) as usize]
}

/// Choose the language: an explicit code, or "auto"/"" — LuCI language if it is one of
/// ours, otherwise English.
pub fn set(code: &str) {
    let c = code.trim();
    let l = if c.is_empty() || c == "auto" { auto() } else { id(c).unwrap_or(1) };
    CUR.store(l, Ordering::Relaxed);
}

/// Язык для команд консоли (до разбора конфига): $CGMON_LANG, слой страницы
/// (runtime.json), `lang:` в cgmon.yaml, иначе auto.
pub fn init_cli(config_path: &str) {
    if let Ok(l) = std::env::var("CGMON_LANG") {
        if id(&l).is_some() {
            set(&l);
            return;
        }
    }
    let quoted = |t: &str| -> Option<String> {
        let i = t.find("\"lang\"")?;
        let r = t[i + 6..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
        Some(r[..r.find('"')?].to_string())
    };
    let dir = std::path::Path::new(config_path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "/etc/cgmon".into());
    if let Some(l) = std::fs::read_to_string(format!("{dir}/runtime.json")).ok().as_deref().and_then(quoted) {
        set(&l);
        return;
    }
    let t = std::fs::read_to_string(config_path).unwrap_or_default();
    for line in t.lines() {
        if let Some(v) = line.strip_prefix("lang:") {
            set(v.split('#').next().unwrap_or("").trim().trim_matches(['"', '\'']));
            return;
        }
    }
    set("auto");
}

fn auto() -> u8 {
    let t = std::fs::read_to_string("/etc/config/luci").unwrap_or_default();
    for line in t.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("option lang") {
            let v = v.trim().trim_matches(['\'', '"']);
            if let Some(i) = id(v) {
                return i;
            }
        }
    }
    1
}

fn unescape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            o.push(c);
            continue;
        }
        match it.next() {
            Some('n') => o.push('\n'),
            Some('t') => o.push('\t'),
            Some('\\') => o.push('\\'),
            Some('#') => o.push('#'),
            Some(x) => {
                o.push('\\');
                o.push(x);
            }
            None => o.push('\\'),
        }
    }
    o
}

/// Parse a catalog (also used by tests and `cgmon i18n-check`).
pub fn parse(text: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, t)) = line.split_once('\t') {
            if !t.is_empty() {
                v.push((unescape(k), unescape(t)));
            }
        }
    }
    v
}

fn map(l: u8) -> &'static HashMap<&'static str, &'static str> {
    MAPS[l as usize].get_or_init(|| {
        let mut m = HashMap::new();
        let Some((_, gz)) = CATALOGS.iter().find(|(c, _)| *c == LANGS[l as usize]) else { return m };
        let Ok(raw) = crate::webfiles::gunzip_pub(gz) else { return m };
        let text: &'static str = Box::leak(String::from_utf8_lossy(&raw).into_owned().into_boxed_str());
        for (k, t) in parse(text) {
            m.insert(&*Box::leak(k.into_boxed_str()), &*Box::leak(t.into_boxed_str()));
        }
        m
    })
}

/// Translation of a source string into the active language (no translation — the
/// English one, then the source itself).
pub fn tr(src: &'static str) -> &'static str {
    tr_in(CUR.load(Ordering::Relaxed), src)
}

pub fn tr_in(l: u8, src: &'static str) -> &'static str {
    if l == 0 {
        return src;
    }
    if let Some(t) = map(l).get(src) {
        return t;
    }
    if l != 1 {
        if let Some(t) = map(1).get(src) {
            return t;
        }
    }
    src
}

/// Translation of a source string that is not 'static (texts from data files).
#[allow(dead_code)]
pub fn tr_dyn(src: &str) -> String {
    let l = CUR.load(Ordering::Relaxed);
    if l == 0 {
        return src.to_string();
    }
    map(l).get(src).or_else(|| map(1).get(src)).map(|s| s.to_string()).unwrap_or_else(|| src.to_string())
}

/// Пояснение к настройке (комментарий config.reference.yaml) на активном языке:
/// ключ каталога `cfg:<путь>`; для русского — None (берётся сам комментарий).
pub fn cfg_hint(path: &str) -> Option<String> {
    cfg_hint_in(CUR.load(Ordering::Relaxed), path)
}

/// То же для заданного языка (страница просит пояснения на своём языке).
pub fn cfg_hint_in(l: u8, path: &str) -> Option<String> {
    if l == 0 {
        return None;
    }
    let k = format!("cfg:{path}");
    map(l).get(k.as_str()).or_else(|| map(1).get(k.as_str())).map(|s| s.to_string())
}

/// Пояснения на активном языке поверх русских комментариев.
pub fn localize_hints(h: Vec<(String, String)>) -> Vec<(String, String)> {
    localize_hints_in(CUR.load(Ordering::Relaxed), h)
}

pub fn localize_hints_in(l: u8, h: Vec<(String, String)>) -> Vec<(String, String)> {
    h.into_iter().map(|(p, t)| { let t = cfg_hint_in(l, &p).unwrap_or(t); (p, t) }).collect()
}

/// Fill placeholders of a template.
pub fn fmt(t: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(t.len() + 16);
    let b = t.as_bytes();
    let mut i = 0;
    let mut next = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'{' {
            if b.get(i + 1) == Some(&b'{') {
                out.push('{');
                i += 2;
                continue;
            }
            if let Some(end) = t[i + 1..].find('}') {
                let spec = &t[i + 1..i + 1 + end];
                let (num, prec) = match spec.split_once(':') {
                    Some((n, p)) => (n, p.strip_prefix('.').and_then(|p| p.parse::<usize>().ok())),
                    None => (spec, None),
                };
                let ok = num.is_empty() || num.bytes().all(|x| x.is_ascii_digit());
                if ok {
                    let idx = if num.is_empty() {
                        let k = next;
                        next += 1;
                        k
                    } else {
                        num.parse().unwrap_or(0)
                    };
                    if let Some(a) = args.get(idx) {
                        let s = a.to_string();
                        match prec.and_then(|p| s.parse::<f64>().ok().map(|f| (p, f))) {
                            Some((p, f)) => out.push_str(&format!("{f:.p$}")),
                            None => out.push_str(&s),
                        }
                    }
                    i += end + 2;
                    continue;
                }
            }
        } else if c == b'}' && b.get(i + 1) == Some(&b'}') {
            out.push('}');
            i += 2;
            continue;
        }
        let ch = t[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `tr!("source")` → &'static str; `tr!("source {}", a, b)` → String.
#[macro_export]
macro_rules! tr {
    ($s:literal) => {
        $crate::i18n::tr($s)
    };
    ($s:literal, $($a:expr),+ $(,)?) => {
        $crate::i18n::fmt($crate::i18n::tr($s), &[$(&$a as &dyn std::fmt::Display),+])
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders() {
        assert_eq!(fmt("{} из {}", &[&3, &4]), "3 из 4");
        assert_eq!(fmt("{1} of {0}", &[&3, &4]), "4 of 3");
        assert_eq!(fmt("{:.1} ms", &[&2.345]), "2.3 ms");
        assert_eq!(fmt("{0:.0}/{0}", &[&2.6]), "3/2.6");
        assert_eq!(fmt("{{x}} {}", &[&"a"]), "{x} a");
        assert_eq!(fmt("{name}", &[&1]), "{name}");
    }

    #[test]
    fn catalog_lines() {
        let v = parse("# c\nа {}\tb {}\nпусто\t\nx\\ny\tz\\tw\n");
        assert_eq!(v, vec![("а {}".to_string(), "b {}".to_string()), ("x\ny".to_string(), "z\tw".to_string())]);
    }

    #[test]
    fn lang_ids() {
        assert_eq!(id("ru_RU.UTF-8"), Some(0));
        assert_eq!(id("zh-cn"), Some(4));
        assert_eq!(id("de"), None);
    }

    /// Сообщения, которые демон различает по началу (daemon.rs, incidents.rs), во всех
    /// языках начинаются с перевода этого начала.
    #[test]
    fn prefixes_consistent() {
        for (lang, _) in CATALOGS {
            let text = std::fs::read_to_string(format!("{}/i18n/{lang}.tsv", env!("CARGO_MANIFEST_DIR"))).unwrap();
            let m: HashMap<String, String> = parse(&text).into_iter().collect();
            for p in ["Обход:", "DNS-страховка (адресно)", "Массовые сбои", "DHCP:"] {
                let tp = m.get(p).cloned().unwrap_or_else(|| p.to_string());
                for (k, t) in &m {
                    if k.starts_with(p) {
                        assert!(t.starts_with(&tp), "{lang}: {k:?} → {t:?} must start with {tp:?}");
                    }
                }
            }
        }
    }

    /// Every catalog: placeholders of a translation are the same as in the source.
    #[test]
    fn catalogs_consistent() {
        for (lang, _) in CATALOGS {
            let path = format!("{}/i18n/{lang}.tsv", env!("CARGO_MANIFEST_DIR"));
            let text = std::fs::read_to_string(&path).unwrap();
            for (k, t) in parse(&text) {
                let ph = |s: &str| {
                    let mut v: Vec<String> = Vec::new();
                    let mut n = 0;
                    let b = s.as_bytes();
                    let mut i = 0;
                    while i < b.len() {
                        if b[i] == b'{' && b.get(i + 1) == Some(&b'{') { i += 2; continue; }
                        if b[i] == b'{' {
                            if let Some(e) = s[i + 1..].find('}') {
                                let sp = &s[i + 1..i + 1 + e];
                                let (num, spec) = sp.split_once(':').unwrap_or((sp, ""));
                                if num.is_empty() { v.push(format!("{n}:{spec}")); n += 1; } else if num.bytes().all(|x| x.is_ascii_digit()) { v.push(format!("{num}:{spec}")); }
                                i += e + 2;
                                continue;
                            }
                        }
                        i += 1;
                    }
                    v.sort();
                    v
                };
                assert_eq!(ph(&k), ph(&t), "{lang}: {k:?} → {t:?}");
            }
        }
    }
}
