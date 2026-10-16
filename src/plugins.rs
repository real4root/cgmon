//! Плагины страницы: файл `<имя>.plugin` рядом с бинарником (/opt/cgmon) —
//! JavaScript-блок страницы со строкой заголовка
//!   // cgmon-plugin: name=media watch_ports=8000,6878
//! Демон раз в минуту ищет такие файлы, выкладывает их в
//! /www/cgmon-plugins/<имя>.js (страница подгружает их по списку `plugins`
//! в статусе) и включает то, что просит заголовок: watch_ports — соединения
//! клиентов LAN на эти порты роутера помечают устройство (watching_tv).
//! Нет файла — нет блока и нет работы. Без dlopen: бинарник статический.

use crate::json::J;

const MAX_SIZE: u64 = 256 << 10;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plugin {
    pub name: String,
    pub watch_ports: Vec<u16>,
}

#[derive(Default)]
pub struct Plugins {
    pub list: Vec<Plugin>,
    at: u64,
}

/// Заголовок плагина: (имя, порты); None — не плагин cgmon.
pub fn parse_header(text: &str) -> Option<Plugin> {
    let line = text.lines().take(5).find_map(|l| l.trim().strip_prefix("// cgmon-plugin:"))?;
    let mut p = Plugin::default();
    for kv in line.split_whitespace() {
        match kv.split_once('=') {
            Some(("name", v)) => p.name = v.to_string(),
            Some(("watch_ports", v)) => p.watch_ports = v.split(',').filter_map(|x| x.trim().parse().ok()).filter(|x| *x > 0).collect(),
            _ => {}
        }
    }
    let ok = (1..=32).contains(&p.name.len()) && p.name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-');
    ok.then_some(p)
}

fn bin_dir() -> std::path::PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).unwrap_or_else(|| "/opt/cgmon".into())
}

impl Plugins {
    /// Раз в минуту: найти плагины, выложить их часть страницы.
    pub fn scan(&mut self, now: u64) {
        if self.at != 0 && now - self.at < 60_000 {
            return;
        }
        self.at = now.max(1);
        let mut found = Vec::new();
        if let Ok(rd) = std::fs::read_dir(bin_dir()) {
            for e in rd.flatten() {
                let path = e.path();
                if path.extension().map_or(true, |x| x != "plugin") || e.metadata().map_or(true, |m| m.len() > MAX_SIZE) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                let Some(p) = parse_header(&text) else {
                    crate::log_err!("plugins: {}: нет строки «// cgmon-plugin: name=…»", path.display());
                    continue;
                };
                if !crate::util::readonly() {
                    let web = crate::webfiles::plugins_dir();
                    let dst = format!("{web}/{}.js", p.name);
                    if std::fs::read_to_string(&dst).ok().as_deref() != Some(text.as_str()) {
                        let _ = std::fs::create_dir_all(web);
                        if let Err(e) = crate::util::write_atomic(&dst, text.as_bytes(), 0o644) {
                            crate::log_err!("plugins: {}: {}", dst, e);
                        }
                    }
                }
                found.push(p);
            }
        }
        found.sort_by(|a, b| a.name.cmp(&b.name));
        if found != self.list {
            let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
            crate::log_info!("plugins: {}", if names.is_empty() { "нет".to_string() } else { names.join(", ") });
            // убранный плагин — убрать и со страницы
            if !crate::util::readonly() {
                for old in &self.list {
                    if !found.iter().any(|p| p.name == old.name) {
                        let _ = std::fs::remove_file(format!("{}/{}.js", crate::webfiles::plugins_dir(), old.name));
                    }
                }
            }
            self.list = found;
        }
    }

    pub fn has(&self, name: &str) -> bool {
        self.list.iter().any(|p| p.name == name)
    }

    /// Порты «зрителей» всех плагинов.
    pub fn watch_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.list.iter().flat_map(|p| p.watch_ports.iter().copied()).collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn json(&self, j: &mut J) {
        j.arr();
        for p in &self.list {
            j.str(&p.name);
        }
        j.end_arr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header() {
        let p = parse_header("// cgmon-plugin: name=media watch_ports=8000,6878\n(function(){})();").unwrap();
        assert_eq!(p, Plugin { name: "media".into(), watch_ports: vec![8000, 6878] });
        assert!(parse_header("// cgmon-plugin: name=../x").is_none());
        assert!(parse_header("var a=1;").is_none());
    }
}
