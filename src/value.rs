//! Дерево значений и его разбор: JSON (runtime.json, запросы CGI/сокета) и
//! подмножество YAML, которым пишется cgmon.yaml (блочные словари и списки,
//! списки словарей, [a, b] / {k: v} в строку, строки в кавычках, комментарии,
//! блочные строки | и >). Без serde: маленький код, предсказуемая память.

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Число как в тексте (тип решает получатель: i64 или f64).
    Num(String),
    Str(String),
    List(Vec<Value>),
    /// Порядок ключей сохраняется (страница, мастер настройки).
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    /// JSON-текст значения.
    pub fn to_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Num(n) => out.push_str(n),
            Value::Str(s) => json_str(out, s),
            Value::List(l) => {
                out.push('[');
                for (i, x) in l.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    x.to_json(out);
                }
                out.push(']');
            }
            Value::Map(m) => {
                out.push('{');
                for (i, (k, x)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    json_str(out, k);
                    out.push(':');
                    x.to_json(out);
                }
                out.push('}');
            }
        }
    }
}

pub fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------- JSON ----------------

const MAX_DEPTH: usize = 64;

pub fn parse_json(s: &str) -> Result<Value, String> {
    let mut p = Json { b: s.as_bytes(), i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(format!("json: лишнее после значения (позиция {})", p.i));
    }
    Ok(v)
}

struct Json<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Json<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("json: {} (позиция {})", what, self.i))
    }

    fn lit(&mut self, w: &[u8], v: Value) -> Result<Value, String> {
        if self.b[self.i..].starts_with(w) {
            self.i += w.len();
            Ok(v)
        } else {
            self.err("неизвестное слово")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return self.err("слишком глубоко");
        }
        let Some(&c) = self.b.get(self.i) else { return self.err("неожиданный конец") };
        match c {
            b'{' => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Value::Map(m));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return self.err("ожидается ключ");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return self.err("ожидается :");
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Map(m));
                        }
                        _ => return self.err("ожидается , или }"),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut l = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Value::List(l));
                }
                loop {
                    self.ws();
                    l.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::List(l));
                        }
                        _ => return self.err("ожидается , или ]"),
                    }
                }
            }
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.lit(b"true", Value::Bool(true)),
            b'f' => self.lit(b"false", Value::Bool(false)),
            b'n' => self.lit(b"null", Value::Null),
            b'-' | b'0'..=b'9' => {
                let st = self.i;
                self.i += 1;
                while self.i < self.b.len() && matches!(self.b[self.i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                    self.i += 1;
                }
                let n = std::str::from_utf8(&self.b[st..self.i]).unwrap_or("");
                if n.parse::<f64>().is_err() {
                    return self.err("плохое число");
                }
                Ok(Value::Num(n.to_string()))
            }
            _ => self.err("неожиданный символ"),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return self.err("короткий \\u");
        }
        let h = std::str::from_utf8(&self.b[self.i..self.i + 4]).map_err(|_| "json: \\u".to_string())?;
        let v = u32::from_str_radix(h, 16).map_err(|_| "json: плохой \\u".to_string())?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // "
        let mut out = String::new();
        loop {
            let st = self.i;
            while self.i < self.b.len() && self.b[self.i] != b'"' && self.b[self.i] != b'\\' && self.b[self.i] >= 0x20 {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.b[st..self.i]).map_err(|_| "json: не UTF-8".to_string())?);
            match self.b.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let Some(&e) = self.b.get(self.i) else { return self.err("обрыв строки") };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut c = self.hex4()?;
                            if (0xd800..0xdc00).contains(&c) && self.b[self.i..].starts_with(b"\\u") {
                                self.i += 2;
                                let lo = self.hex4()?;
                                c = 0x10000 + ((c - 0xd800) << 10) + (lo.wrapping_sub(0xdc00) & 0x3ff);
                            }
                            out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                        }
                        _ => return self.err("плохое экранирование"),
                    }
                }
                _ => return self.err("обрыв строки"),
            }
        }
    }
}

// ---------------- YAML (подмножество) ----------------

struct Line {
    no: usize,
    ind: usize,
    text: String,
}

/// Убрать комментарий (# в начале или после пробела, вне кавычек).
fn strip_comment(s: &str) -> &str {
    let b = s.as_bytes();
    let (mut sq, mut dq) = (false, false);
    for i in 0..b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq && (i == 0 || b[i - 1] != b'\\') => dq = !dq,
            b'#' if !sq && !dq && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t') => return s[..i].trim_end(),
            _ => {}
        }
    }
    s.trim_end()
}

/// Позиция «ключ:» (двоеточие + пробел/конец) вне кавычек и скобок.
fn key_colon(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if matches!(b.first(), Some(b'[') | Some(b'{')) {
        return None;
    }
    let (mut sq, mut dq, mut depth) = (false, false, 0i32);
    for i in 0..b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq && (i == 0 || b[i - 1] != b'\\') => dq = !dq,
            b'[' | b'{' if !sq && !dq => depth += 1,
            b']' | b'}' if !sq && !dq => depth -= 1,
            b':' if !sq && !dq && depth == 0 && (i + 1 == b.len() || b[i + 1] == b' ') => return Some(i),
            _ => {}
        }
    }
    None
}

fn unquote(s: &str, no: usize) -> Result<String, String> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        // двойные кавычки — экранирование как в JSON
        return parse_json(s).ok().and_then(|v| if let Value::Str(x) = v { Some(x) } else { None }).ok_or(format!("yaml: строка {}: плохая строка в кавычках", no));
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return Ok(s[1..s.len() - 1].replace("''", "'"));
    }
    Ok(s.to_string())
}

/// Простой скаляр: null / true / false / число / строка (YAML 1.2 core, как yaml.v3).
fn plain(s: &str, no: usize) -> Result<Value, String> {
    let t = s.trim();
    if t.starts_with('"') || t.starts_with('\'') {
        return Ok(Value::Str(unquote(t, no)?));
    }
    match t {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let num = t.strip_prefix(['-', '+']).unwrap_or(t);
    if !num.is_empty() && num.bytes().all(|c| c.is_ascii_digit()) {
        return Ok(Value::Num(t.trim_start_matches('+').to_string()));
    }
    if !num.is_empty() && num.bytes().next().map_or(false, |c| c.is_ascii_digit() || c == b'.') && t.parse::<f64>().is_ok() && !num.contains(char::is_alphabetic) {
        return Ok(Value::Num(t.to_string()));
    }
    Ok(Value::Str(t.to_string()))
}

/// [a, "b", c] и {k: v} в одну строку.
fn flow(s: &str, no: usize) -> Result<Value, String> {
    let t = s.trim();
    let (open, close) = (t.as_bytes()[0], *t.as_bytes().last().unwrap());
    if (open == b'[' && close != b']') || (open == b'{' && close != b'}') {
        return Err(format!("yaml: строка {}: незакрытая скобка (многострочные [ ] не поддерживаются)", no));
    }
    let inner = &t[1..t.len() - 1];
    let mut items = Vec::new();
    let b = inner.as_bytes();
    let (mut sq, mut dq, mut depth, mut st) = (false, false, 0i32, 0usize);
    for i in 0..=b.len() {
        let c = if i < b.len() { b[i] } else { b',' };
        match c {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq && (i == 0 || b[i - 1] != b'\\') => dq = !dq,
            b'[' | b'{' if !sq && !dq => depth += 1,
            b']' | b'}' if !sq && !dq => depth -= 1,
            b',' if !sq && !dq && depth == 0 => {
                let it = inner[st..i].trim();
                if !it.is_empty() {
                    items.push(it);
                }
                st = i + 1;
            }
            _ => {}
        }
    }
    if open == b'[' {
        let mut l = Vec::with_capacity(items.len());
        for it in items {
            l.push(if it.starts_with('[') || it.starts_with('{') { flow(it, no)? } else { plain(it, no)? });
        }
        Ok(Value::List(l))
    } else {
        let mut m = Vec::with_capacity(items.len());
        for it in items {
            let c = key_colon(it).ok_or(format!("yaml: строка {}: ожидается ключ: значение", no))?;
            let v = it[c + 1..].trim();
            m.push((unquote(&it[..c], no)?, if v.starts_with('[') || v.starts_with('{') { flow(v, no)? } else { plain(v, no)? }));
        }
        Ok(Value::Map(m))
    }
}

pub fn parse_yaml(src: &str) -> Result<Value, String> {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let mut lines = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let no = i + 1;
        let lead = raw.len() - raw.trim_start_matches([' ', '\t']).len();
        if raw[..lead].contains('\t') && !raw.trim().is_empty() && !raw.trim_start().starts_with('#') {
            return Err(format!("yaml: строка {}: табуляция в отступе", no));
        }
        let ind = raw.len() - raw.trim_start_matches(' ').len();
        let t = raw.trim();
        if t == "---" || t == "..." {
            continue;
        }
        // текст блочной строки (| >) — с комментариями как есть; решает block()
        lines.push(Line { no, ind, text: raw.to_string() });
    }
    let mut p = Yaml { l: lines, i: 0 };
    p.skip_blank();
    if p.i >= p.l.len() {
        return Ok(Value::Map(Vec::new()));
    }
    let ind = p.l[p.i].ind;
    let v = p.block(ind)?;
    p.skip_blank();
    if p.i < p.l.len() {
        return Err(format!("yaml: строка {}: неожиданный отступ", p.l[p.i].no));
    }
    Ok(v)
}

struct Yaml {
    l: Vec<Line>,
    i: usize,
}

impl Yaml {
    fn content(&self, i: usize) -> &str {
        strip_comment(self.l[i].text.trim_start())
    }

    fn skip_blank(&mut self) {
        while self.i < self.l.len() && self.content(self.i).is_empty() {
            self.i += 1;
        }
    }

    fn block(&mut self, ind: usize) -> Result<Value, String> {
        self.skip_blank();
        let c = self.content(self.i);
        if c == "-" || c.starts_with("- ") {
            self.list(ind)
        } else {
            self.map(ind)
        }
    }

    /// Значение после «ключ:» или «- »: в строке, блочная строка или вложенный блок.
    fn after(&mut self, rest: &str, parent: usize, no: usize, list_ok_same: bool) -> Result<Value, String> {
        let rest = rest.trim();
        if rest.is_empty() {
            self.skip_blank();
            if self.i < self.l.len() {
                let n = self.l[self.i].ind;
                let c = self.content(self.i);
                if n > parent || (list_ok_same && n == parent && (c == "-" || c.starts_with("- "))) {
                    return self.block(n);
                }
            }
            return Ok(Value::Null);
        }
        if rest.starts_with('|') || rest.starts_with('>') {
            let fold = rest.starts_with('>');
            let mut out: Vec<String> = Vec::new();
            let mut bi = None;
            while self.i < self.l.len() {
                let ln = &self.l[self.i];
                if ln.text.trim().is_empty() {
                    out.push(String::new());
                    self.i += 1;
                    continue;
                }
                if ln.ind <= parent {
                    break;
                }
                let b = *bi.get_or_insert(ln.ind);
                out.push(ln.text.get(b.min(ln.ind)..).unwrap_or("").to_string());
                self.i += 1;
            }
            while out.last().map_or(false, |s| s.is_empty()) {
                out.pop();
            }
            let s = if fold { out.join(" ") } else { out.join("\n") };
            return Ok(Value::Str(if rest.contains('-') { s } else { s + "\n" }));
        }
        if rest.starts_with('[') || rest.starts_with('{') {
            return flow(rest, no);
        }
        if rest.starts_with('&') || rest.starts_with('*') || rest.starts_with('!') {
            return Err(format!("yaml: строка {}: якоря и теги не поддерживаются", no));
        }
        plain(rest, no)
    }

    fn map(&mut self, ind: usize) -> Result<Value, String> {
        let mut m: Vec<(String, Value)> = Vec::new();
        loop {
            self.skip_blank();
            if self.i >= self.l.len() || self.l[self.i].ind < ind {
                break;
            }
            let no = self.l[self.i].no;
            if self.l[self.i].ind > ind {
                return Err(format!("yaml: строка {}: неожиданный отступ", no));
            }
            let c = self.content(self.i).to_string();
            if c == "-" || c.starts_with("- ") {
                break; // список на том же уровне — конец словаря
            }
            let k = key_colon(&c).ok_or(format!("yaml: строка {}: ожидается «ключ: значение»", no))?;
            let key = unquote(&c[..k], no)?;
            self.i += 1;
            let v = self.after(&c[k + 1..], ind, no, true)?;
            if let Some(e) = m.iter_mut().find(|(x, _)| *x == key) {
                e.1 = v; // повтор ключа — последний (yaml.v3 ругается; мы мягче)
            } else {
                m.push((key, v));
            }
        }
        Ok(Value::Map(m))
    }

    fn list(&mut self, ind: usize) -> Result<Value, String> {
        let mut l = Vec::new();
        loop {
            self.skip_blank();
            if self.i >= self.l.len() || self.l[self.i].ind != ind {
                break;
            }
            let c = self.content(self.i).to_string();
            if !(c == "-" || c.starts_with("- ")) {
                break;
            }
            let no = self.l[self.i].no;
            let rest = c[1..].trim_start();
            let col = ind + (c.len() - rest.len());
            if !rest.is_empty() && key_colon(rest).is_some() {
                // «- ключ: значение» — словарь с отступом col: подменяем строку
                let raw = self.l[self.i].text.clone();
                let lead = raw.len() - raw.trim_start().len();
                let mut t = String::with_capacity(raw.len());
                t.push_str(&" ".repeat(col));
                t.push_str(raw[lead..].trim_start()[1..].trim_start());
                self.l[self.i].text = t;
                self.l[self.i].ind = col;
                l.push(self.map(col)?);
            } else {
                self.i += 1;
                l.push(self.after(rest, ind, no, false)?);
            }
        }
        Ok(Value::List(l))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Value {
        Value::Str(x.into())
    }
    fn n(x: &str) -> Value {
        Value::Num(x.into())
    }

    #[test]
    fn json_roundtrip() {
        let v = parse_json(r#" {"a": [1, -2.5e3, "x\"\u00e9\ud83d\ude00", true, null], "b": {}} "#).unwrap();
        let mut o = String::new();
        v.to_json(&mut o);
        assert_eq!(o, "{\"a\":[1,-2.5e3,\"x\\\"é😀\",true,null],\"b\":{}}");
        assert!(parse_json("{\"a\":1,}").is_err());
        assert!(parse_json(&"[".repeat(100)).is_err());
        assert!(parse_json("[1] x").is_err());
    }

    #[test]
    fn yaml_config_shapes() {
        let y = "\u{feff}# шапка\nlog_level: info   # комментарий\ndry_run: false\nprobes:\n  ipv4: [\"1.1.1.1:443\", 8.8.8.8:443]\n  ipv6:\n    - \"[2606:4700:4700::1111]:443\"\n    - '[2001:4860:4860::8888]:443'\nhub:\n  token: \"a#b\"\n  url: http://x:7788/api\nlist:\n- a\n- b\npeers:\n  list:\n    - name: p1\n      probe: 10.0.0.1:22\n    - name: p2\n      probe: 10.0.0.2:22\nempty:\nf: 0.5\nneg: -3\nstr: 1.2.3\nmapflow: {a: 1, b: x}\ntext: |\n  строка 1\n  строка 2\n";
        let v = parse_yaml(y).unwrap();
        assert_eq!(v.get("log_level"), Some(&s("info")));
        assert_eq!(v.get("dry_run"), Some(&Value::Bool(false)));
        assert_eq!(v.get("probes").unwrap().get("ipv4"), Some(&Value::List(vec![s("1.1.1.1:443"), s("8.8.8.8:443")])));
        assert_eq!(v.get("probes").unwrap().get("ipv6"), Some(&Value::List(vec![s("[2606:4700:4700::1111]:443"), s("[2001:4860:4860::8888]:443")])));
        assert_eq!(v.get("hub").unwrap().get("token"), Some(&s("a#b")));
        assert_eq!(v.get("hub").unwrap().get("url"), Some(&s("http://x:7788/api")));
        assert_eq!(v.get("list"), Some(&Value::List(vec![s("a"), s("b")])));
        let pl = v.get("peers").unwrap().get("list").unwrap();
        assert_eq!(pl, &Value::List(vec![Value::Map(vec![("name".into(), s("p1")), ("probe".into(), s("10.0.0.1:22"))]), Value::Map(vec![("name".into(), s("p2")), ("probe".into(), s("10.0.0.2:22"))])]));
        assert_eq!(v.get("empty"), Some(&Value::Null));
        assert_eq!(v.get("f"), Some(&n("0.5")));
        assert_eq!(v.get("neg"), Some(&n("-3")));
        assert_eq!(v.get("str"), Some(&s("1.2.3")));
        assert_eq!(v.get("mapflow"), Some(&Value::Map(vec![("a".into(), n("1")), ("b".into(), s("x"))])));
        assert_eq!(v.get("text"), Some(&s("строка 1\nстрока 2\n")));
    }

    #[test]
    fn yaml_errors() {
        assert!(parse_yaml("a:\n\tb: 1\n").is_err());
        assert!(parse_yaml("a: [1, 2\n").is_err());
        assert!(parse_yaml("a: 1\n  b: 2\n").is_err());
    }
}
