//! Запись JSON вручную в переиспользуемый буфер: без serde, без аллокаций
//! на каждый статус (буфер живёт всё время работы демона).

use std::fmt::Write as _;

struct Level {
    n: u32,
}

pub struct J {
    pub b: String,
    st: Vec<Level>,
    after_key: bool,
}

impl J {
    pub fn new() -> Self {
        J { b: String::with_capacity(4096), st: Vec::with_capacity(8), after_key: false }
    }

    pub fn clear(&mut self) {
        self.b.clear();
        self.st.clear();
        self.after_key = false;
    }

    fn pre(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if let Some(t) = self.st.last_mut() {
            if t.n > 0 {
                self.b.push(',');
            }
            t.n += 1;
        }
    }

    pub fn obj(&mut self) -> &mut Self {
        self.pre();
        self.b.push('{');
        self.st.push(Level { n: 0 });
        self
    }

    pub fn arr(&mut self) -> &mut Self {
        self.pre();
        self.b.push('[');
        self.st.push(Level { n: 0 });
        self
    }

    pub fn end_obj(&mut self) -> &mut Self {
        self.st.pop();
        self.b.push('}');
        self
    }

    pub fn end_arr(&mut self) -> &mut Self {
        self.st.pop();
        self.b.push(']');
        self
    }

    /// Пары ключ-значение из готового объекта «{…}» — в текущий объект.
    pub fn raw_kv(&mut self, obj: &str) -> &mut Self {
        let t = obj.trim();
        let inner = t.strip_prefix('{').and_then(|x| x.strip_suffix('}')).unwrap_or(t);
        if !inner.is_empty() {
            self.pre();
            self.b.push_str(inner);
        }
        self
    }

    pub fn key(&mut self, k: &str) -> &mut Self {
        self.pre();
        self.esc(k);
        self.b.push(':');
        self.after_key = true;
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.pre();
        self.esc(s);
        self
    }

    pub fn int(&mut self, v: i64) -> &mut Self {
        self.pre();
        let _ = write!(self.b, "{}", v);
        self
    }

    pub fn uint(&mut self, v: u64) -> &mut Self {
        self.pre();
        let _ = write!(self.b, "{}", v);
        self
    }

    /// Число с фиксированным числом знаков (NaN/бесконечность → 0).
    pub fn num(&mut self, v: f64, prec: usize) -> &mut Self {
        self.pre();
        let v = if v.is_finite() { v } else { 0.0 };
        let _ = write!(self.b, "{:.*}", prec, v);
        self
    }

    /// Готовый JSON-фрагмент как значение.
    pub fn raw(&mut self, s: &str) -> &mut Self {
        self.pre();
        self.b.push_str(s);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.pre();
        self.b.push_str(if v { "true" } else { "false" });
        self
    }

    fn esc(&mut self, s: &str) {
        self.b.push('"');
        for c in s.chars() {
            match c {
                '"' => self.b.push_str("\\\""),
                '\\' => self.b.push_str("\\\\"),
                '\n' => self.b.push_str("\\n"),
                '\r' => self.b.push_str("\\r"),
                '\t' => self.b.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    let _ = write!(self.b, "\\u{:04x}", c as u32);
                }
                c => self.b.push(c),
            }
        }
        self.b.push('"');
    }
}

#[cfg(test)]
mod tests {
    use super::J;

    #[test]
    fn nested() {
        let mut j = J::new();
        j.obj().key("a").int(1).key("s").str("x\"y\n").key("l").arr().int(1).num(2.5, 1).obj().key("t").bool(true).end_obj().end_arr().end_obj();
        assert_eq!(j.b, r#"{"a":1,"s":"x\"y\n","l":[1,2.5,{"t":true}]}"#);
        j.clear();
        j.arr().end_arr();
        assert_eq!(j.b, "[]");
    }
}
