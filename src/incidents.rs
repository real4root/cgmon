//! Журнал инцидентов (перенос incidents.go + inctext.go): открытые
//! outage / degradation / local_pressure по такту, точечные записи
//! (route_change, service_down, dns_guard …), JSONL в wan_monitor.incidents_file
//! (ротация 2 МБ), ≤ 200 в памяти, понятные тексты Text/Result.

use crate::json::J;
use crate::util;
use crate::value::{parse_json, Value};

/// Время как Go time.Time: unix-секунды и наносекунды; (ZERO_TIME, 0) — нулевое.
pub const ZERO_TIME: i64 = -62135596800;

#[derive(Clone, Debug, PartialEq)]
pub struct Incident {
    pub id: i64,
    pub typ: String,
    pub open: bool,
    pub start: (i64, u32),
    pub end: (i64, u32),
    pub dur_sec: i64,
    pub post: bool,
    pub context: String,
    pub text: String,
    pub result: String,
    pub closed_by: String,
    pub start_wan: i64,
    pub start_lan: i64,
    pub start_router: i64,
    pub start_top: String,
    pub start_top_wan: i64,
    pub peak_wan: i64,
    pub peak_lan: i64,
    pub peak_router: i64,
    pub peak_top: String,
    pub peak_top_wan: i64,
    /// пик полезных соединений (без служебных проб cgmon); peak_wan — всех
    pub peak_useful: i64,
    pub min_v4: f64,
    pub min_v6: f64,
    pub actions: Vec<String>,
}

impl Default for Incident {
    fn default() -> Self {
        Incident {
            id: 0,
            typ: String::new(),
            open: false,
            start: (ZERO_TIME, 0),
            end: (ZERO_TIME, 0),
            dur_sec: 0,
            post: false,
            context: String::new(),
            text: String::new(),
            result: String::new(),
            closed_by: String::new(),
            start_wan: 0,
            start_lan: 0,
            start_router: 0,
            start_top: String::new(),
            start_top_wan: 0,
            peak_wan: 0,
            peak_lan: 0,
            peak_router: 0,
            peak_top: String::new(),
            peak_top_wan: 0,
            peak_useful: 0,
            min_v4: 0.0,
            min_v6: 0.0,
            actions: Vec::new(),
        }
    }
}

/// Срез за такт, по которому журнал решает.
#[derive(Clone, Debug, Default)]
pub struct Sample {
    pub now: (i64, u32),
    pub state: String,
    pub diagnosis: String,
    pub wan_total: i64,
    pub lan_to_wan: i64,
    pub router_own: i64,
    /// из wan_total — служебные пробы cgmon
    pub service: i64,
    pub top_ip: String,
    pub top_wan: i64,
    pub v4_success: f64,
    pub v4_count: i64,
    pub v6_success: f64,
    pub v6_count: i64,
    pub v6_available: bool,
    pub wan_up: bool,
    pub post_outage: bool,
    pub pressure: String,
}

/// Служебные типы — в статус только в расширенном режиме (diag).
pub fn diag_type(t: &str) -> bool {
    matches!(t, "local_pressure" | "peer_path" | "flow_penalty" | "upload_learn" | "witness" | "billing_limit")
}

fn time_json(t: (i64, u32)) -> String {
    if t.0 == ZERO_TIME {
        "0001-01-01T00:00:00Z".into()
    } else {
        util::rfc3339(t.0, t.1)
    }
}

impl Incident {
    pub fn to_json(&self, j: &mut J) {
        use crate::config::go_float;
        j.obj();
        j.key("id").int(self.id).key("type").str(&self.typ).key("open").bool(self.open);
        j.key("start").str(&time_json(self.start)).key("end").str(&time_json(self.end));
        if self.dur_sec != 0 {
            j.key("duration_sec").int(self.dur_sec);
        }
        j.key("post_outage").bool(self.post);
        for (k, v) in [("context", &self.context), ("text", &self.text), ("result", &self.result), ("closed_by", &self.closed_by)] {
            if !v.is_empty() {
                j.key(k).str(v);
            }
        }
        j.key("start_wan").int(self.start_wan).key("start_lan").int(self.start_lan).key("start_router").int(self.start_router);
        j.key("start_top").str(&self.start_top).key("start_top_wan").int(self.start_top_wan);
        j.key("peak_wan").int(self.peak_wan).key("peak_lan").int(self.peak_lan).key("peak_router").int(self.peak_router);
        j.key("peak_top").str(&self.peak_top).key("peak_top_wan").int(self.peak_top_wan);
        if self.peak_useful > 0 {
            j.key("peak_useful").int(self.peak_useful);
        }
        j.key("min_v4").raw(&go_float(self.min_v4)).key("min_v6").raw(&go_float(self.min_v6));
        if !self.actions.is_empty() {
            j.key("actions").arr();
            for a in &self.actions {
                j.str(a);
            }
            j.end_arr();
        }
        j.end_obj();
    }

    fn from_value(v: &Value) -> Option<Incident> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let n = |k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
        let t = |k: &str| v.get(k).and_then(|x| x.as_str()).and_then(util::parse_rfc3339).unwrap_or((ZERO_TIME, 0));
        let mut inc = Incident {
            id: n("id") as i64,
            typ: s("type"),
            open: v.get("open").and_then(|x| x.as_bool()).unwrap_or(false),
            start: t("start"),
            end: t("end"),
            dur_sec: n("duration_sec") as i64,
            post: v.get("post_outage").and_then(|x| x.as_bool()).unwrap_or(false),
            context: s("context"),
            text: s("text"),
            result: s("result"),
            closed_by: s("closed_by"),
            start_wan: n("start_wan") as i64,
            start_lan: n("start_lan") as i64,
            start_router: n("start_router") as i64,
            start_top: s("start_top"),
            start_top_wan: n("start_top_wan") as i64,
            peak_wan: n("peak_wan") as i64,
            peak_lan: n("peak_lan") as i64,
            peak_router: n("peak_router") as i64,
            peak_top: s("peak_top"),
            peak_top_wan: n("peak_top_wan") as i64,
            peak_useful: n("peak_useful") as i64,
            min_v4: n("min_v4"),
            min_v6: n("min_v6"),
            actions: Vec::new(),
        };
        if let Some(Value::List(l)) = v.get("actions") {
            inc.actions = l.iter().filter_map(|x| x.as_str().map(String::from)).collect();
        }
        Some(inc)
    }
}

fn pct(v: f64) -> String {
    format!("{}%", (v + 0.5) as i64)
}

fn gate_score(s: &str) -> String {
    if s == "-1" {
        "нет".into()
    } else {
        format!("{s} из 100")
    }
}

/// Имя устройства по IP для текстов (резолвер — когда появится).
pub type NameFn = dyn Fn(&str) -> String;

/// Заполнить Text и Result (перенос describeIncident).
pub fn describe(inc: &mut Incident, name: Option<&NameFn>) {
    let ctx = inc.context.trim().to_string();
    inc.text.clear();
    match inc.typ.as_str() {
        "degradation" => {
            let verb = if inc.open { "не проходят" } else { "не проходили" };
            let mut t = format!("Новые соединения IPv4 {verb}");
            let mut d = Vec::new();
            if inc.min_v4 >= 0.0 && inc.min_v4 < 90.0 {
                d.push(format!("успешных проб до {}", pct(inc.min_v4)));
                if inc.min_v6 >= 90.0 {
                    d.push("IPv6 работал — сбой у провайдера на IPv4 (CGNAT)".into());
                } else if inc.min_v6 >= 0.0 {
                    d.push(format!("IPv6 тоже: {}", pct(inc.min_v6)));
                }
            }
            if !d.is_empty() {
                t += &format!(" ({})", d.join("; "));
            }
            if inc.post {
                t += " — сразу после возврата связи: лавина переподключений";
            }
            // лимит провайдера считает все соединения, пользователю важны полезные
            if inc.peak_wan > 0 {
                t += &format!("; соединений в пике: всего {}", inc.peak_wan);
                if inc.peak_useful > 0 && inc.peak_useful < inc.peak_wan {
                    t += &format!(", полезных {} (остальное — пробы cgmon)", inc.peak_useful);
                }
            }
            if !inc.peak_top.is_empty() && inc.peak_top_wan > 0 {
                let mut who = inc.peak_top.clone();
                if let Some(f) = name {
                    let n = f(&inc.peak_top);
                    if !n.is_empty() {
                        who = format!("{} ({})", n, inc.peak_top);
                    }
                }
                t += &format!("; больше всех соединений у {} — {}", who, inc.peak_top_wan);
            }
            inc.text = t;
        }
        "outage" => inc.text = if inc.open { "Интернета нет: WAN не работает".into() } else { "Интернета не было: WAN не работал".into() },
        "local_pressure" => {
            inc.text = "Роутер перегружен".into();
            if !ctx.is_empty() && ctx != "router local pressure" {
                inc.text += &format!(": {ctx}");
            }
        }
        "wan_degradation" => {
            // «<iface> s4=<n> s6=<n>»
            let f: Vec<&str> = ctx.split(' ').collect();
            if f.len() == 3 && !f[0].is_empty() {
                if let (Some(a), Some(b)) = (f[1].strip_prefix("s4="), f[2].strip_prefix("s6=")) {
                    if a.trim_start_matches('-').parse::<u64>().is_ok() && b.trim_start_matches('-').parse::<u64>().is_ok() {
                        inc.text = format!("Канал {} работает плохо: качество IPv4 {}, IPv6 {}", f[0], gate_score(a), gate_score(b));
                    }
                }
            }
        }
        "failover" | "failback" => {
            // «SWITCH <a> -> <b> (<why>)»
            if let Some(rest) = ctx.strip_prefix("SWITCH ") {
                let f: Vec<&str> = rest.split(' ').collect();
                if f.len() == 4 && f[1] == "->" && f[3].starts_with('(') && f[3].ends_with(')') {
                    let (a, b, why) = (f[0], f[2], &f[3][1..f[3].len() - 1]);
                    inc.text = match why {
                        "failback" => format!("Возврат на основной канал {b} (с {a})"),
                        "link_down" => format!("Переключение на канал {b}: канал {a} потерял связь"),
                        "degraded" => format!("Переключение на канал {b}: канал {a} работал плохо"),
                        _ => format!("Переключение на канал {b} (с {a}, {why})"),
                    };
                }
            }
        }
        "route_change" => {
            if let Some(i) = ctx.find("DEFAULT WAN IFACE ") {
                let f: Vec<&str> = ctx[i + 18..].split(' ').collect();
                if f.len() >= 3 && f[1] == "->" {
                    inc.text = format!("Интернет теперь идёт через {} (было {})", f[2], f[0]);
                }
            } else if let Some(i) = ctx.find("NEW IP (") {
                let rest = &ctx[i + 8..];
                if let Some(c) = rest.find(") ON INTERFACE ") {
                    let iface = rest[c + 15..].split(' ').next().unwrap_or("");
                    inc.text = format!("Новый внешний IP: {} ({})", &rest[..c], iface);
                }
            }
        }
        _ => {}
    }
    if inc.text.is_empty() {
        inc.text = ctx.strip_prefix("Down detector: ").unwrap_or(&ctx).to_string();
    }
    let cb = inc.closed_by.as_str();
    inc.result = if inc.open {
        "идёт сейчас".into()
    } else if cb == "event" || cb.is_empty() {
        String::new()
    } else if cb.starts_with("recovered") {
        "восстановилось".into()
    } else if cb == "wan up" {
        "интернет вернулся".into()
    } else if cb == "local pressure gone" {
        "нагрузка спала".into()
    } else if cb == "cgmon restart" {
        "cgmon перезапущен".into()
    } else {
        cb.into()
    };
}

const JSONL_MAX: u64 = 2 << 20;

/// Дописать строку JSON в журнал (ротация в .old по размеру).
pub fn append_jsonl(path: &str, line: &str, max: u64) {
    if path.is_empty() || crate::util::readonly() {
        return;
    }
    use std::io::Write;
    if std::fs::metadata(path).map(|m| m.len() > max).unwrap_or(false) {
        let _ = std::fs::rename(path, format!("{path}.old"));
    }
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
        let mut b = line.as_bytes().to_vec();
        b.push(b'\n');
        let _ = f.write_all(&b);
    }
}

pub struct Journal {
    pub file: String,
    items: Vec<Incident>,
    /// ключ (outage | degradation | local) → id открытого
    open: Vec<(&'static str, i64)>,
    next_id: i64,
}

impl Journal {
    pub fn new(file: &str) -> Journal {
        let mut j = Journal { file: file.to_string(), items: Vec::new(), open: Vec::new(), next_id: 1 };
        j.load();
        j
    }

    /// Загрузить JSONL: у инцидента несколько записей (open, close) — берём
    /// последнюю версию по ID; незакрытые закрываем последней отметкой.
    fn load(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.file) else { return };
        let mut last_seen: Vec<(i64, (i64, u32))> = Vec::new();
        for line in text.lines() {
            let Ok(rec) = parse_json(line) else { continue };
            if rec.get("type").and_then(|x| x.as_str()) != Some("incident") {
                continue;
            }
            let Some(mut inc) = rec.get("incident").and_then(Incident::from_value) else { continue };
            if let Some(c) = inc.context.strip_prefix("Down detector: ") {
                inc.context = c.to_string();
            }
            if let Some(t) = rec.get("time").and_then(|x| x.as_str()).and_then(util::parse_rfc3339) {
                last_seen.retain(|(i, _)| *i != inc.id);
                last_seen.push((inc.id, t));
            }
            match self.items.iter_mut().find(|x| x.id == inc.id) {
                // первое закрытие — настоящее (поздние — следы старого бага)
                Some(x) => {
                    if x.open {
                        *x = inc.clone();
                    }
                }
                None => self.items.push(inc.clone()),
            }
            if inc.id >= self.next_id {
                self.next_id = inc.id + 1;
            }
        }
        for inc in self.items.iter_mut().filter(|i| i.open) {
            inc.open = false;
            inc.end = last_seen.iter().find(|(i, _)| *i == inc.id).map(|x| x.1).unwrap_or(inc.start);
            if inc.end.0 < inc.start.0 {
                inc.end = inc.start;
            }
            inc.dur_sec = inc.end.0 - inc.start.0;
            inc.closed_by = "cgmon restart".into();
        }
        self.items.sort_by_key(|i| i.start);
        if self.items.len() > 200 {
            self.items.drain(..self.items.len() - 200);
        }
        for inc in &mut self.items {
            describe(inc, None);
        }
        if !self.items.is_empty() {
            crate::log_info!("incidents: loaded {} from {} (nextID={}, open=0)", self.items.len(), self.file, self.next_id);
        }
    }

    fn persist(&self, inc: &Incident, phase: Option<&str>) {
        let mut j = J::new();
        j.obj().key("incident");
        inc.to_json(&mut j);
        if let Some(p) = phase {
            j.key("phase").str(p);
        }
        j.key("time").str(&util::rfc3339_secs(util::now_wall().0)).key("type").str("incident").end_obj();
        append_jsonl(&self.file, &j.b, JSONL_MAX);
    }

    fn get_open(&mut self, key: &str) -> Option<&mut Incident> {
        let id = self.open.iter().find(|(k, _)| *k == key)?.1;
        self.items.iter_mut().find(|i| i.id == id)
    }

    fn new_incident(&mut self, typ: &str, s: &Sample) -> i64 {
        let mut inc = Incident {
            id: self.next_id,
            typ: typ.into(),
            open: true,
            start: s.now,
            start_wan: s.wan_total,
            start_lan: s.lan_to_wan,
            start_router: s.router_own,
            start_top: s.top_ip.clone(),
            start_top_wan: s.top_wan,
            peak_wan: s.wan_total,
            peak_lan: s.lan_to_wan,
            peak_router: s.router_own,
            peak_top: s.top_ip.clone(),
            peak_top_wan: s.top_wan,
            peak_useful: s.wan_total - s.service,
            min_v4: -1.0,
            min_v6: -1.0,
            ..Default::default()
        };
        self.next_id += 1;
        if s.v4_count > 0 {
            inc.min_v4 = s.v4_success;
        }
        if s.v6_available && s.v6_count > 0 {
            inc.min_v6 = s.v6_success;
        }
        describe(&mut inc, None);
        let id = inc.id;
        self.items.push(inc);
        if self.items.len() > 200 {
            self.items.drain(..self.items.len() - 200);
        }
        id
    }

    fn update(inc: &mut Incident, s: &Sample) {
        inc.peak_wan = inc.peak_wan.max(s.wan_total);
        inc.peak_lan = inc.peak_lan.max(s.lan_to_wan);
        inc.peak_router = inc.peak_router.max(s.router_own);
        inc.peak_useful = inc.peak_useful.max(s.wan_total - s.service);
        if s.top_wan > inc.peak_top_wan {
            inc.peak_top_wan = s.top_wan;
            inc.peak_top = s.top_ip.clone();
        }
        if s.v4_count > 0 && (inc.min_v4 < 0.0 || s.v4_success < inc.min_v4) {
            inc.min_v4 = s.v4_success;
        }
        if s.v6_available && s.v6_count > 0 && (inc.min_v6 < 0.0 || s.v6_success < inc.min_v6) {
            inc.min_v6 = s.v6_success;
        }
        describe(inc, None);
    }

    /// Открыть/обновить/закрыть один вид инцидента.
    fn track(&mut self, key: &'static str, typ: &str, active: bool, s: &Sample, ctx: impl Fn(&Sample) -> (String, bool), reason: String) -> bool {
        if active {
            let mut changed = false;
            if self.get_open(key).is_none() {
                let id = self.new_incident(typ, s);
                self.open.push((key, id));
                let (c, post) = ctx(s);
                let inc = self.get_open(key).unwrap();
                inc.context = c;
                inc.post = post;
                let snap = inc.clone();
                self.persist(&snap, Some("open"));
                changed = true;
            }
            let inc = self.get_open(key).unwrap();
            Self::update(inc, s);
            return changed;
        }
        if let Some(inc) = self.get_open(key) {
            inc.open = false;
            inc.end = s.now;
            inc.dur_sec = s.now.0 - inc.start.0;
            inc.closed_by = reason;
            describe(inc, None);
            let snap = inc.clone();
            self.open.retain(|(k, _)| *k != key);
            self.persist(&snap, Some("close"));
            return true;
        }
        false
    }

    /// Такт: true — что-то изменилось.
    pub fn tick(&mut self, s: &Sample) -> bool {
        let mut ch = self.track("outage", "outage", !s.wan_up, s, |_| ("wan down".into(), false), "wan up".into());
        let degr = (s.state == "WARNING" || s.state == "CRITICAL") && s.diagnosis == "IPV4_EXTERNAL_DEGRADATION";
        ch |= self.track("degradation", "degradation", degr, s, |s| if s.post_outage { ("post-outage reconnect storm".into(), true) } else { (String::new(), false) }, format!("recovered: {}/{}", s.state, s.diagnosis));
        ch |= self.track("local", "local_pressure", s.diagnosis == "LOCAL_PRESSURE", s, |s| (if s.pressure.is_empty() { "router local pressure".into() } else { s.pressure.clone() }, false), "local pressure gone".into());
        ch
    }

    /// Точечная запись (закрытый инцидент-событие).
    pub fn record(&mut self, typ: &str, context: &str, at: (i64, u32)) {
        let mut inc = Incident { id: self.next_id, typ: typ.into(), start: at, end: at, closed_by: "event".into(), context: context.into(), ..Default::default() };
        describe(&mut inc, None);
        self.next_id += 1;
        self.items.push(inc.clone());
        self.items.sort_by_key(|i| i.start);
        if self.items.len() > 200 {
            self.items.drain(..self.items.len() - 200);
        }
        let mut j = J::new();
        j.obj().key("incident");
        inc.to_json(&mut j);
        j.key("time").str(&util::rfc3339_secs(at.0)).key("type").str("incident").end_obj();
        append_jsonl(&self.file, &j.b, JSONL_MAX);
    }

    /// Действие лимитера к открытым инцидентам.
    pub fn note_action(&mut self, msg: &str) {
        let ids: Vec<i64> = self.open.iter().map(|x| x.1).collect();
        for inc in self.items.iter_mut().filter(|i| ids.contains(&i.id)) {
            inc.actions.push(msg.into());
        }
    }

    /// Пересобрать тексты (стали известны имена устройств).
    pub fn redescribe(&mut self, name: &NameFn) {
        for inc in &mut self.items {
            describe(inc, Some(name));
        }
    }

    /// Для статуса: за 72 ч, квоты групп — инциденты ≤ 60, сбои сайтов ≤ 40,
    /// служебные ≤ 40; записи адресного режима — не в журнал.
    pub fn status_items(&self, now: i64) -> Vec<&Incident> {
        let cutoff = now - 72 * 3600;
        let recent: Vec<&Incident> = self.items.iter().rev().take_while(|i| i.start.0 >= cutoff).collect();
        if recent.is_empty() {
            return self.items.iter().rev().take(30).collect();
        }
        let (mut main, mut dd, mut diag) = (0, 0, 0);
        let mut out = Vec::new();
        for inc in recent {
            let (n, max) = if inc.typ == "service_down" || inc.typ == "phy" {
                (&mut dd, 40)
            } else if diag_type(&inc.typ) {
                (&mut diag, 40)
            } else if inc.typ == "route_guard" || (inc.typ == "dns_guard" && (inc.text.starts_with("DNS-страховка (адресно)") || inc.context.starts_with("DNS-страховка (адресно)"))) {
                continue;
            } else {
                (&mut main, 60)
            };
            if *n < max {
                *n += 1;
                out.push(inc);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(state: &str, diag: &str, wan_up: bool, t: i64) -> Sample {
        Sample { now: (t, 0), state: state.into(), diagnosis: diag.into(), wan_up, v4_success: 70.0, v4_count: 10, v6_success: 100.0, v6_count: 10, v6_available: true, top_ip: "192.0.2.5".into(), top_wan: 40, ..Default::default() }
    }

    #[test]
    fn degradation_open_close_and_reload() {
        let dir = std::env::temp_dir().join(format!("cgmon-inc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("inc.jsonl").to_string_lossy().into_owned();
        let mut j = Journal::new(&f);
        assert!(j.tick(&sample("WARNING", "IPV4_EXTERNAL_DEGRADATION", true, 1000)));
        assert!(!j.tick(&sample("WARNING", "IPV4_EXTERNAL_DEGRADATION", true, 1010)));
        let inc = &j.items[0];
        assert!(inc.open && inc.text.starts_with("Новые соединения IPv4 не проходят (успешных проб до 70%; IPv6 работал"), "{}", inc.text);
        assert_eq!(inc.result, "идёт сейчас");
        assert!(j.tick(&sample("NORMAL", "HEALTHY", true, 1100)));
        assert_eq!(j.items[0].result, "восстановилось");
        assert_eq!(j.items[0].dur_sec, 100);
        j.record("route_change", "DEFAULT WAN IFACE eth0 -> eth3", (1200, 0));
        assert_eq!(j.items[1].text, "Интернет теперь идёт через eth3 (было eth0)");
        // открытый на момент остановки — закрывается при загрузке
        assert!(j.tick(&sample("NORMAL", "HEALTHY", false, 1300)));
        let j2 = Journal::new(&f);
        assert_eq!(j2.items.len(), 3);
        assert_eq!(j2.next_id, 4);
        let out = j2.items.iter().find(|i| i.typ == "outage").unwrap();
        assert!(!out.open && out.closed_by == "cgmon restart");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn texts() {
        let mut i = Incident { typ: "failover".into(), context: "SWITCH wan -> eth3 (link_down)".into(), closed_by: "event".into(), ..Default::default() };
        describe(&mut i, None);
        assert_eq!(i.text, "Переключение на канал eth3: канал wan потерял связь");
        let mut i = Incident { typ: "wan_degradation".into(), context: "wan s4=30 s6=-1".into(), ..Default::default() };
        describe(&mut i, None);
        assert_eq!(i.text, "Канал wan работает плохо: качество IPv4 30 из 100, IPv6 нет");
        let mut i = Incident { typ: "route_change".into(), context: "NEW IP (198.51.100.7) ON INTERFACE pppoe-wan".into(), ..Default::default() };
        describe(&mut i, None);
        assert_eq!(i.text, "Новый внешний IP: 198.51.100.7 (pppoe-wan)");
    }
}
