//! Правка cgmon.yaml на месте (мастер установки): значение ключа по пути
//! «секция.ключ» меняется в своей строке — комментарии, порядок и остальные
//! ключи файла не трогаются; отсутствующий ключ дописывается в свой раздел.
//! Значения — JSON-скаляры и списки в одну строку (это и YAML flow).

struct Key {
    path: String,
    line: usize,
    indent: usize,
    /// после «:» есть значение (иначе — раздел или блочный список)
    inline: bool,
}

fn indent_of(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

fn is_noise(l: &str) -> bool {
    let t = l.trim();
    t.is_empty() || t.starts_with('#')
}

/// Ключи файла с путями.
fn keys(lines: &[String]) -> Vec<Key> {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if is_noise(l) {
            continue;
        }
        let ind = indent_of(l);
        let t = l.trim_start();
        if t.starts_with('-') {
            continue; // элемент списка — содержимое ключа выше
        }
        let Some(c) = t.find(':') else { continue };
        let k = t[..c].trim().trim_matches(['"', '\'']);
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            continue;
        }
        while stack.last().map_or(false, |(si, _)| *si >= ind) {
            stack.pop();
        }
        let rest = strip_comment(&t[c + 1..]);
        let mut path: Vec<&str> = stack.iter().map(|(_, k)| k.as_str()).collect();
        path.push(k);
        let p = path.join(".");
        let inline = !rest.trim().is_empty();
        out.push(Key { path: p, line: i, indent: ind, inline });
        if !inline {
            stack.push((ind, k.to_string()));
        }
    }
    out
}

/// Значение без комментария «  # …» (вне кавычек).
fn strip_comment(s: &str) -> &str {
    let (mut q, mut prev_space) = (None::<char>, true);
    for (i, c) in s.char_indices() {
        match q {
            Some(x) if c == x => q = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => q = Some(c),
            None if c == '#' && prev_space => return &s[..i],
            None => {}
        }
        prev_space = c == ' ' || c == '\t';
    }
    s
}

/// Комментарий строки (с ведущими пробелами), если есть.
fn comment_of(rest: &str) -> String {
    let v = strip_comment(rest);
    let c = &rest[v.len()..];
    if c.is_empty() {
        String::new()
    } else {
        format!("{}{}", " ".repeat(2.max(rest[..v.len()].len() - rest[..v.len()].trim_end().len())), c.trim_start())
    }
}

/// Последняя строка содержимого раздела (ключа без значения) по индексу его строки.
fn section_end(lines: &[String], line: usize, indent: usize) -> usize {
    let mut end = line;
    for (i, l) in lines.iter().enumerate().skip(line + 1) {
        if is_noise(l) {
            continue;
        }
        let ind = indent_of(l);
        if ind <= indent && !(ind == indent && l.trim_start().starts_with('-')) {
            break;
        }
        end = i;
    }
    end
}

/// Отступ первого вложенного ключа раздела (по умолчанию +2).
fn child_indent(lines: &[String], line: usize, indent: usize) -> usize {
    for l in lines.iter().skip(line + 1) {
        if is_noise(l) {
            continue;
        }
        let ind = indent_of(l);
        return if ind > indent { ind } else { indent + 2 };
    }
    indent + 2
}

/// Поставить значение (JSON-скаляр или список) ключу path.
pub fn set(text: &str, path: &str, value: &str) -> String {
    set_impl(text, path, Some(value), &[])
}

/// Поставить блочное значение (строки без отступа, напр. «- bot_token: …»).
pub fn set_block(text: &str, path: &str, block: &[String]) -> String {
    if block.is_empty() {
        return set(text, path, "[]");
    }
    set_impl(text, path, None, block)
}

fn set_impl(text: &str, path: &str, value: Option<&str>, block: &[String]) -> String {
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let ks = keys(&lines);
    if let Some(k) = ks.iter().find(|k| k.path == path) {
        let l = lines[k.line].clone();
        let c = l.find(':').unwrap();
        let rest = l[c + 1..].to_string();
        let comment = comment_of(&rest);
        // старое блочное содержимое (элементы списка) — убрать
        if !k.inline {
            let end = section_end(&lines, k.line, k.indent);
            let mut i = k.line + 1;
            let mut removed = 0;
            while i <= end - removed {
                if is_noise(&lines[i]) {
                    i += 1;
                    continue;
                }
                lines.remove(i);
                removed += 1;
            }
        }
        let head = &l[..c + 1];
        match value {
            Some(v) => lines[k.line] = format!("{head} {v}{comment}"),
            None => {
                lines[k.line] = format!("{head}{comment}");
                let ind = " ".repeat(k.indent + 2);
                for (n, b) in block.iter().enumerate() {
                    lines.insert(k.line + 1 + n, format!("{ind}{b}"));
                }
            }
        }
        return lines.join("\n") + "\n";
    }
    // ключа нет: найти ближайший существующий раздел и дописать в его конец
    let parts: Vec<&str> = path.split('.').collect();
    let mut at = None;
    for n in (1..parts.len()).rev() {
        let p = parts[..n].join(".");
        if let Some(k) = ks.iter().find(|k| k.path == p && !k.inline) {
            at = Some((n, k.line, k.indent));
            break;
        }
    }
    let (depth, mut ins, mut ind) = match at {
        Some((n, line, indent)) => (n, section_end(&lines, line, indent) + 1, child_indent(&lines, line, indent)),
        None => {
            if lines.last().map_or(false, |l| !l.trim().is_empty()) {
                lines.push(String::new());
            }
            (0, lines.len(), 0)
        }
    };
    for (n, p) in parts.iter().enumerate().skip(depth) {
        let pad = " ".repeat(ind);
        if n + 1 < parts.len() {
            lines.insert(ins, format!("{pad}{p}:"));
            ins += 1;
            ind += 2;
            continue;
        }
        match value {
            Some(v) => lines.insert(ins, format!("{pad}{p}: {v}")),
            None => {
                lines.insert(ins, format!("{pad}{p}:"));
                for (k, b) in block.iter().enumerate() {
                    lines.insert(ins + 1 + k, format!("{pad}  {b}"));
                }
            }
        }
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const Y: &str = "# шапка\nlog_level: info   # уровень\nweb:\n  # пароль\n  password: \"\"\n\nhub:\n  enabled: false\n  telegram:\n    - bot_token: \"1:a\"\n      chat_ids: [\"5\"]\n  stale_sec: 180\ngate_selector:\n  probes:\n    ipv4: [\"1.1.1.1:443\"]\n";

    #[test]
    fn edits_in_place() {
        let t = set(Y, "log_level", "\"debug\"");
        assert!(t.contains("log_level: \"debug\"   # уровень"), "{t}");
        let t = set(&t, "web.password", "\"s3cret\"");
        assert!(t.contains("  # пароль\n  password: \"s3cret\"\n"), "{t}");
        let t = set(&t, "gate_selector.probes.ipv4", "[\"8.8.8.8:443\"]");
        assert!(t.contains("    ipv4: [\"8.8.8.8:443\"]"), "{t}");
        // блочный список заменён, соседний ключ цел
        let t = set_block(&t, "hub.telegram", &["- bot_token: \"2:b\"".into(), "  chat_ids: [\"7\", \"8\"]".into()]);
        assert!(t.contains("  telegram:\n    - bot_token: \"2:b\"\n      chat_ids: [\"7\", \"8\"]\n  stale_sec: 180"), "{t}");
        assert!(!t.contains("1:a"));
        // нет ключа — дописать в раздел; нет раздела — в конец
        let t = set(&t, "hub.token", "\"abc\"");
        assert!(t.contains("  stale_sec: 180\n  token: \"abc\"\n"), "{t}");
        let t = set(&t, "report.urls", "[\"http://h:7788/api/v1/report\"]");
        assert!(t.ends_with("report:\n  urls: [\"http://h:7788/api/v1/report\"]\n"), "{t}");
        // результат читается тем же разборщиком конфига
        let v = crate::value::parse_yaml(&t).unwrap();
        assert_eq!(v.get("hub").and_then(|h| h.get("token")).and_then(|x| x.as_str()), Some("abc"));
    }
}
