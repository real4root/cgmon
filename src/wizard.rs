//! Мастер установки (перенос wizard.go) в трёх вариантах:
//!   min   — только пароль страницы;
//!   basic — то, чего нет на странице: пароль, отправка на центр сбора, центр
//!           и Telegram, учёт трафика, выбор шлюза;
//!   full  — все параметры по разделам (как --advanced-install в Go).
//! Всё, что меняется на странице, в min/basic не спрашивается (по умолчанию).
//! cgmon.yaml правится на месте (yamledit) — комментарии сохраняются; нового
//! файла нет — основа config.reference.yaml. Бекап, проверка, пакеты, служба.

use crate::config::{self, Config, Field};
use crate::value::Value;
use std::io::{BufRead, Write};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Min,
    Basic,
    Full,
}

const CHOICES: &[(&str, &[(&str, &str)])] = &[
    ("log_level", &[("info", "обычный журнал"), ("debug", "подробный (отладка)"), ("error", "только ошибки")]),
    ("wan_check", &[("active", "активные пробы (рекомендуется)"), ("hybrid", "трафик + проба раз в 30 с"), ("passive", "только трафик (эксперимент)")]),
    ("limits.mode", &[("adaptive", "от текущих соединений клиента"), ("static", "фиксированные warning/critical")]),
    ("dns_guard.mode", &[("off", "выключена"), ("observe", "наблюдение (только журнал)"), ("active", "активно: весь протокол"), ("targeted", "адресно: только сети с плохим протоколом (SmartDNS)")]),
    ("counting.mode", &[("lan_to_wan", "только соединения в интернет"), ("lan_only", "внутри LAN"), ("all", "все")]),
    ("gate_selector.repair.method", &[("ubus", "через netifd (ubus)"), ("ifup", "командой ifup")]),
];
const SKIP: &[&str] = &["report.url", "hub.telegram_bot_token", "hub.telegram_chat_id"];
const SECRETS: &[&str] = &["report.token", "hub.token", "web.password"];
const INIT_SCRIPT: &str = include_str!("../openwrt/cgmon.init");

/// Ответ «да» на вопрос (stdin).
pub fn yes_no(q: &str) -> bool {
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    matches!(s.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да" | "1")
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, n, 0) };
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Пароль страницы: 12 знаков без похожих (0/O, 1/l).
fn rand_password() -> String {
    const A: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut b = [0u8; 12];
    unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, 12, 0) };
    b.iter().map(|x| A[*x as usize % A.len()] as char).collect()
}

fn show(f: &Field) -> String {
    match f {
        Field::Bool(b) => if **b { "да" } else { "нет" }.into(),
        Field::Int(v) => v.to_string(),
        Field::Float(v) => config::go_float(**v),
        Field::Str(s) => s.to_string(),
        Field::StrList(l) => l.join(", "),
        Field::IntList(l) => l.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "),
        Field::Complex => String::new(),
    }
}

fn kind(f: &Field) -> &'static str {
    match f {
        Field::Bool(_) => "bool",
        Field::Int(_) => "int",
        Field::Float(_) => "float",
        Field::Str(_) => "string",
        Field::StrList(_) => "list",
        Field::IntList(_) => "intlist",
        Field::Complex => "",
    }
}

fn get(cfg: &Config, path: &str) -> (String, &'static str, String) {
    let mut r = (String::new(), "", String::new());
    cfg.walk("", &mut |p, f| {
        if p == path {
            let mut j = String::new();
            if !matches!(f, Field::Complex) {
                config::field_json(f, &mut j);
            }
            r = (show(&f), kind(&f), j);
        }
    });
    r
}

/// Ответ → значение для livecfg::set_any.
fn raw(ans: &str, kind: &str) -> Value {
    match kind {
        "bool" => Value::Bool(ans == "true"),
        "int" | "float" => Value::Num(ans.to_string()),
        "list" | "intlist" => {
            if ans == "-" {
                return Value::List(Vec::new());
            }
            Value::List(ans.split(|c| c == ',' || c == ' ').filter(|x| !x.is_empty()).map(|x| Value::Str(x.to_string())).collect())
        }
        _ => Value::Str(ans.to_string()),
    }
}

/// Страница меняет этот параметр сама (runtime, основные или «Все настройки»).
#[cfg(test)]
pub fn on_page(path: &str) -> bool {
    const RUNTIME: &[&str] = &["dry_run", "wan_check", "qos.enabled", "qos.upload_kbit", "qos.download_kbit", "qos.flow_cap_up_kbit", "qos.flow_cap_down_kbit", "upload_shaper.enabled", "upload_shaper.sustained_kbit", "flow_watch.enabled", "billing.enabled", "billing.daily_limit_mb", "billing.monthly_limit_mb"];
    crate::livecfg::is_main(path) || !crate::livecfg::is_hidden(path) || RUNTIME.contains(&path)
}

struct W<'a> {
    inp: &'a mut dyn BufRead,
    out: &'a mut dyn Write,
    hints: Vec<(String, String)>,
    tg: Option<Vec<String>>,
}

enum Ans {
    Text(String),
    Eof,
}

impl W<'_> {
    fn ask(&mut self, q: &str) -> Ans {
        let _ = write!(self.out, "{q}");
        let _ = self.out.flush();
        let mut s = String::new();
        match self.inp.read_line(&mut s) {
            Ok(0) | Err(_) => Ans::Eof,
            Ok(_) => Ans::Text(s.trim().to_string()),
        }
    }

    fn hint(&self, p: &str) -> String {
        self.hints.iter().find(|(k, _)| k == p).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    fn say(&mut self, s: &str) {
        let _ = writeln!(self.out, "{s}");
    }

    /// да/нет; None — конец ввода.
    fn yn(&mut self, q: &str, def: bool) -> Option<bool> {
        let d = if def { 1 } else { 2 };
        match self.ask(&format!("{q}\n  1) да  2) нет  [Enter = {d}]: ")) {
            Ans::Eof => None,
            Ans::Text(a) if a.is_empty() => Some(def),
            Ans::Text(a) => Some(a == "1" || a.eq_ignore_ascii_case("y") || a == "да"),
        }
    }

    /// Строка с подсказкой; пусто — оставить cur.
    fn line(&mut self, q: &str, cur: &str) -> Option<String> {
        let d = if cur.is_empty() { "пусто".to_string() } else { cur.to_string() };
        match self.ask(&format!("{q}  [Enter = {d}]: ")) {
            Ans::Eof => None,
            Ans::Text(a) if a.is_empty() => Some(cur.to_string()),
            Ans::Text(a) => Some(a),
        }
    }

    /// Секрет: Enter — оставить текущий или сгенерировать.
    fn secret(&mut self, q: &str, cur: &str, gen: fn() -> String) -> Option<String> {
        let d = if cur.is_empty() { "сгенерировать" } else { "оставить текущий" };
        match self.ask(&format!("{q}  [Enter = {d}]: ")) {
            Ans::Eof => None,
            Ans::Text(a) if !a.is_empty() => Some(a),
            _ if !cur.is_empty() => Some(cur.to_string()),
            _ => {
                let s = gen();
                self.say(&format!("  сгенерирован: {s}  (запишите)"));
                Some(s)
            }
        }
    }

    fn set(&mut self, cfg: &mut Config, path: &str, v: Value) -> bool {
        match crate::livecfg::set_any(cfg, path, &v) {
            Ok(()) => true,
            Err(e) => {
                self.say(&format!("  {path}: {e} — оставлено как было"));
                false
            }
        }
    }

    /// Получатели Telegram центра: бот и чаты (одним блоком).
    fn telegram(&mut self, cfg: &Config) -> Option<()> {
        let n = crate::livecfg::telegram_dests(&cfg.hub).len();
        let q = if n > 0 { format!("Уведомления в Telegram: сейчас получателей {n}. Новый бот (токен от @BotFather, Enter — оставить как есть)") } else { "Уведомления в Telegram: токен бота от @BotFather (Enter — без Telegram)".into() };
        let bot = match self.ask(&format!("{q}: ")) {
            Ans::Eof => return None,
            Ans::Text(a) => a,
        };
        if bot.is_empty() {
            return Some(());
        }
        let chats = match self.ask("  ID чатов через запятую (личка — число, группа -100…, канал @имя): ") {
            Ans::Eof => return None,
            Ans::Text(a) => a,
        };
        let ids: Vec<String> = chats.split(|c| c == ',' || c == ' ').filter(|x| !x.is_empty()).map(|x| format!("\"{x}\"")).collect();
        if ids.is_empty() {
            self.say("  без чатов — Telegram не настроен");
            return Some(());
        }
        self.tg = Some(vec![format!("- bot_token: \"{bot}\""), format!("  chat_ids: [{}]", ids.join(", "))]);
        Some(())
    }
}

/// Мастер; mode None — спросить вариант. Код выхода.
pub fn run(path: &str, mode: Option<Mode>) -> i32 {
    let stdin = std::io::stdin();
    let mut inp = stdin.lock();
    let mut out = std::io::stdout();
    run_io(&mut inp, &mut out, path, mode, std::path::Path::new("/etc/rc.common").exists())
}

pub fn run_io(inp: &mut dyn BufRead, out: &mut dyn Write, path: &str, mode: Option<Mode>, on_router: bool) -> i32 {
    let path = if path.is_empty() { "/etc/cgmon/cgmon.yaml" } else { path };
    let existing = std::path::Path::new(path).exists();
    let mut cfg = config::defaults();
    let mut text = config::REFERENCE.to_string();
    if existing {
        match config::load(path) {
            Ok(c) => {
                cfg = c;
                text = std::fs::read_to_string(path).unwrap_or(text);
            }
            Err(e) => {
                let _ = writeln!(out, "Текущий {path} не читается ({e}) — начинаем со значений по умолчанию.");
            }
        }
    }
    cfg.normalize();
    let orig = cfg.clone();
    let mut w = W { inp, out, hints: crate::livecfg::hints(config::REFERENCE), tg: None };
    w.say(&format!("\ncgmon {} — мастер установки ({path})", crate::VERSION));
    if existing {
        w.say("Значения по умолчанию в вопросах — из текущего файла.");
    }
    let mode = match mode {
        Some(m) => m,
        None => {
            w.say("Вариант настройки (всё, что есть на странице, можно поменять потом там):\n  1) минимальная — только пароль страницы\n  2) обычная — плюс центр сбора, Telegram, учёт трафика, выбор шлюза\n  3) подробная — все параметры по разделам");
            match w.ask("  выбор [Enter = 1]: ") {
                Ans::Eof => return 1,
                Ans::Text(a) => match a.as_str() {
                    "2" => Mode::Basic,
                    "3" => Mode::Full,
                    _ => Mode::Min,
                },
            }
        }
    };
    let ok = match mode {
        Mode::Min | Mode::Basic => ask_short(&mut w, &mut cfg, mode == Mode::Basic),
        Mode::Full => ask_full(&mut w, &mut cfg),
    };
    let Some(()) = ok else {
        w.say("\nВвод закончился — выхожу без сохранения.");
        return 1;
    };
    finish(&mut w, cfg, orig, text, path, existing, on_router)
}

fn ask_password(w: &mut W, cfg: &mut Config) -> Option<()> {
    w.say("\nПароль на изменение настроек со страницы status.html.");
    let p = w.secret("Пароль", &cfg.web.password.clone(), rand_password)?;
    if p.chars().any(|c| c.is_control()) {
        w.say("  недопустимые символы — оставлено как было");
    } else {
        cfg.web.password = p;
    }
    Some(())
}

fn ask_short(w: &mut W, cfg: &mut Config, basic: bool) -> Option<()> {
    ask_password(w, cfg)?;
    if !basic {
        return Some(());
    }
    // отправка на центр сбора
    w.say("\n==== Центр сбора: отправка ====");
    let rep = w.yn("Отправлять состояние этого роутера на центр сбора?", cfg.report.enabled)?;
    cfg.report.enabled = rep;
    if rep {
        let cur = crate::report::urls(&cfg.report).join(", ");
        let u = w.line("Адреса центров (http://адрес:7788/api/v1/report, через запятую)", &cur)?;
        let list: Vec<String> = u.split(|c| c == ',' || c == ' ').filter(|x| !x.is_empty()).map(String::from).collect();
        if list.iter().all(|x| x.starts_with("http://")) {
            cfg.report.urls = list;
            cfg.report.url.clear();
        } else {
            w.say("  нужны адреса http:// — оставлено как было");
        }
        cfg.report.token = w.secret("Общий секрет центра (тот же, что hub.token на центре, ≥16 знаков)", &cfg.report.token.clone(), || rand_hex(24))?;
    }
    // этот роутер — центр
    w.say("\n==== Центр сбора: этот роутер ====");
    let hub = w.yn("Этот роутер — центр сбора (принимает отчёты, шлёт в Telegram)?", cfg.hub.enabled)?;
    cfg.hub.enabled = hub;
    if hub {
        let def = if cfg.hub.token.is_empty() { cfg.report.token.clone() } else { cfg.hub.token.clone() };
        cfg.hub.token = w.secret("Общий секрет центра (≥16 знаков; роутеры шлют с ним же)", &def, || rand_hex(24))?;
        let l = w.line("Порт центра (адрес:порт)", &cfg.hub.listen.clone())?;
        cfg.hub.listen = l;
        w.telegram(cfg)?;
    }
    w.say("\n==== Прочее (нет на странице) ====");
    cfg.accounting.enabled = w.yn("Учёт трафика устройств (счётчики nftables)?", cfg.accounting.enabled)?;
    let gs = w.yn("Резервный канал: проверять несколько WAN и переключать маршрут (gate selector)?", cfg.gate_selector.enabled)?;
    cfg.gate_selector.enabled = gs;
    if gs {
        let found = crate::gatesel::detect(cfg);
        let l: Vec<String> = found.iter().map(|g| format!("{} ({}, приоритет {})", g.name, g.device, g.priority)).collect();
        w.say(&format!("  шлюзы зоны wan: {}", if l.is_empty() { "не найдены — задайте gate_selector.interfaces в cgmon.yaml".into() } else { l.join("; ") }));
        w.say("  пока в режиме наблюдения (gate_selector.dry_run) — переключать начнёт после снятия на странице «Все настройки»");
    }
    Some(())
}

fn ask_full(w: &mut W, cfg: &mut Config) -> Option<()> {
    w.say("Enter — оставить значение, цифра — выбрать вариант, «!» — оставить весь раздел, «?» — пояснение, «q» — выйти без сохранения.");
    let mut fields: Vec<(String, &'static str)> = Vec::new();
    cfg.walk("", &mut |p, f| {
        if !SKIP.contains(&p) {
            fields.push((p.to_string(), kind(&f)));
        }
    });
    let (mut section, mut skip) = (String::from("-"), String::new());
    for (path, k) in fields {
        let top = if path.contains('.') { path.split('.').next().unwrap().to_string() } else { String::new() };
        if top != section {
            section = top.clone();
            skip.clear();
            w.say(&format!("\n==== Раздел: {} ====", if top.is_empty() { "общие" } else { &top }));
            let h = w.hint(&top);
            if !h.is_empty() && !top.is_empty() {
                w.say(&h);
            }
            if top == "web" {
                ask_password(w, cfg)?;
            }
            if top == "hub" && cfg.hub.enabled {
                w.telegram(cfg)?;
            }
        }
        if (!skip.is_empty() && skip == section) || path == "web.password" {
            continue;
        }
        if k.is_empty() {
            if path != "hub.telegram" {
                let h = w.hint(&path).replace('\n', "\n  ");
                w.say(&format!("\n{path} — сложный список, настраивается в cgmon.yaml:\n  {h}"));
            }
            continue;
        }
        loop {
            let (cur, _, _) = get(cfg, &path);
            let h = w.hint(&path).replace('\n', "\n  ");
            w.say(&format!("\n{path}\n  {h}"));
            let choices = CHOICES.iter().find(|(p, _)| *p == path).map(|(_, c)| *c);
            let secret = SECRETS.contains(&path.as_str());
            let a = if k == "bool" {
                let d = if cur == "да" { 1 } else { 2 };
                match w.ask(&format!("  1) да  2) нет  [Enter = {d}]: ")) {
                    Ans::Eof => return None,
                    Ans::Text(a) => match a.as_str() {
                        "" => String::new(),
                        "1" => "true".into(),
                        "2" => "false".into(),
                        x => x.into(),
                    },
                }
            } else if let Some(ch) = choices {
                let mut d = 0;
                for (i, (v, l)) in ch.iter().enumerate() {
                    let m = if *v == cur { d = i + 1; "*" } else { " " };
                    w.say(&format!("  {m}{}) {v} — {l}", i + 1));
                }
                match w.ask(&format!("  выбор [Enter = {d}]: ")) {
                    Ans::Eof => return None,
                    Ans::Text(a) => match a.parse::<usize>() {
                        Ok(n) if (1..=ch.len()).contains(&n) => ch[n - 1].0.to_string(),
                        _ => a,
                    },
                }
            } else {
                let def = if secret {
                    if cur.is_empty() { "<сгенерировать>".to_string() } else { "<оставить текущий>".to_string() }
                } else if cur.is_empty() {
                    "пусто".to_string()
                } else {
                    cur.clone()
                };
                match w.ask(&format!("  [Enter = {def}]: ")) {
                    Ans::Eof => return None,
                    Ans::Text(a) => a,
                }
            };
            match a.as_str() {
                "q" | "Q" => {
                    if let Ans::Text(x) = w.ask("Выйти без сохранения? 1) да  2) нет [2]: ") {
                        if x == "1" {
                            return None;
                        }
                    }
                    continue;
                }
                "?" => {
                    w.say(&format!("  Путь: {path}, тип: {k}, сейчас: {cur:?}"));
                    continue;
                }
                "!" => {
                    skip = section.clone();
                    break;
                }
                "" => {
                    if secret && cur.is_empty() {
                        let t = rand_hex(24);
                        w.say(&format!("  сгенерирован: {t} (запишите — нужен на всех роутерах/центрах)"));
                        if path == "report.token" {
                            cfg.report.token = t;
                        } else {
                            cfg.hub.token = t;
                        }
                    }
                    break;
                }
                _ => {}
            }
            if secret {
                if path == "report.token" {
                    cfg.report.token = a;
                } else {
                    cfg.hub.token = a;
                }
                break;
            }
            if w.set(cfg, &path, raw(&a, k)) {
                break;
            }
        }
    }
    Some(())
}

/// Итог, запись, пакеты, служба.
fn finish(w: &mut W, mut cfg: Config, orig: Config, mut text: String, path: &str, existing: bool, on_router: bool) -> i32 {
    cfg.normalize();
    if let Err(e) = crate::livecfg::validate(&cfg) {
        w.say(&format!("\nВнимание: {e}"));
        match w.ask("1) сохранить всё равно  2) выйти без сохранения [2]: ") {
            Ans::Text(a) if a == "1" => {}
            _ => {
                w.say("Ничего не записано.");
                return 1;
            }
        }
    }
    // изменения
    let mut old: Vec<(String, String)> = Vec::new();
    orig.walk("", &mut |p, f| {
        if !matches!(f, Field::Complex) {
            let mut j = String::new();
            config::field_json(f, &mut j);
            old.push((p.to_string(), j));
        }
    });
    let mut changed: Vec<(String, String)> = Vec::new();
    cfg.walk("", &mut |p, f| {
        if matches!(f, Field::Complex) || SKIP.contains(&p) {
            return;
        }
        let mut j = String::new();
        config::field_json(f, &mut j);
        if old.iter().find(|(k, _)| k == p).map(|(_, v)| v) != Some(&j) {
            changed.push((p.to_string(), j));
        }
    });
    // старое report.url переходит в urls
    if orig.report.url != cfg.report.url {
        changed.push(("report.url".into(), String::new()));
    }
    w.say(&format!("\n==== Итог: изменений {} ====", changed.len() + w.tg.is_some() as usize));
    for (p, v) in &changed {
        if SECRETS.contains(&p.as_str()) {
            w.say(&format!("  {p}: задан"));
        } else if p != "report.url" {
            w.say(&format!("  {p}: {v}"));
        }
    }
    if w.tg.is_some() {
        w.say("  hub.telegram: задан");
    }
    let dest = match w.ask(&format!("Записать в [Enter = {path}]: ")) {
        Ans::Eof => return 1,
        Ans::Text(a) if a.is_empty() => path.to_string(),
        Ans::Text(a) => a,
    };
    if !existing || dest != path {
        let (s, _) = crate::util::now_wall();
        let t = crate::util::local(s);
        let head = format!("# cgmon.yaml — записан мастером cgmon {}, {:04}-{:02}-{:02} {:02}:{:02}.\n# Пояснения ко всем настройкам: cgmon --help-advanced, config.reference.yaml.\n", crate::VERSION, t.year, t.mon, t.day, t.hour, t.min);
        if !existing {
            text = format!("{head}{}", text.lines().skip_while(|l| l.starts_with('#')).collect::<Vec<_>>().join("\n"));
        }
    }
    for (p, v) in &changed {
        text = if p == "report.url" { crate::yamledit::set(&text, p, "\"\"") } else { crate::yamledit::set(&text, p, v) };
    }
    if let Some(b) = &w.tg {
        text = crate::yamledit::set_block(&text, "hub.telegram", b);
    }
    if std::path::Path::new(&dest).exists() {
        let (s, _) = crate::util::now_wall();
        let t = crate::util::local(s);
        let bak = format!("{dest}.bak-{:04}{:02}{:02}-{:02}{:02}{:02}", t.year, t.mon, t.day, t.hour, t.min, t.sec);
        if std::fs::copy(&dest, &bak).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600));
            w.say(&format!("Старый файл сохранён: {bak}"));
        }
    }
    if let Some(dir) = std::path::Path::new(&dest).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = crate::util::write_atomic(&dest, text.as_bytes(), 0o600) {
        w.say(&format!("Ошибка записи: {e}"));
        return 1;
    }
    match config::load(&dest) {
        Err(e) => {
            w.say(&format!("Записанный файл не читается: {e}"));
            return 1;
        }
        Ok(c) => {
            if !c.web.password.is_empty() || cfg.web.password.is_empty() {
                w.say(&format!("Записано: {dest} (права 0600 — в файле секреты)"));
            }
        }
    }
    if !on_router {
        return 0;
    }
    if !crate::deps::print(w.out, &cfg) && !crate::deps::missing_pkgs(&crate::deps::check(&cfg)).is_empty() {
        if let Ans::Text(a) = w.ask("Пакеты: 1) установить сейчас  2) пропустить (функции без них работать не будут) [2]: ") {
            if a == "1" {
                if let Err(e) = crate::deps::install(w.out, &cfg) {
                    w.say(&format!("Не удалось: {e}"));
                }
            }
        }
    }
    let installed = std::path::Path::new("/etc/init.d/cgmon").exists();
    let d = if installed { 2 } else { 1 };
    match w.ask(&format!("Служба: 1) установить/обновить и (пере)запустить  2) только записать конфиг [{d}]: ")) {
        Ans::Text(a) if a == "1" || (a.is_empty() && d == 1) => install(w),
        _ => {}
    }
    0
}

/// Бинарник в /opt/cgmon/cgmon, служба procd, автозапуск, (пере)запуск.
fn install(w: &mut W) {
    const BIN: &str = "/opt/cgmon/cgmon";
    if let Ok(me) = std::env::current_exe() {
        if me.to_string_lossy() != BIN {
            let _ = std::fs::create_dir_all("/opt/cgmon");
            let tmp = format!("{BIN}.new");
            if std::fs::copy(&me, &tmp).is_ok() && std::fs::rename(&tmp, BIN).is_ok() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(BIN, std::fs::Permissions::from_mode(0o755));
                w.say(&format!("Бинарник: {BIN}"));
            }
        }
    }
    if !std::path::Path::new("/etc/init.d/cgmon").exists() && crate::util::write_atomic("/etc/init.d/cgmon", INIT_SCRIPT.as_bytes(), 0o755).is_ok() {
        w.say("Служба: /etc/init.d/cgmon");
    }
    for a in ["enable", "restart"] {
        match std::process::Command::new("/etc/init.d/cgmon").arg(a).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => w.say(&format!("/etc/init.d/cgmon {a}: {}", String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => w.say(&format!("/etc/init.d/cgmon {a}: {e}")),
        }
    }
    w.say("Готово: cgmon запущен. Проверка: cgmon status; страница: http://<роутер>/status.html");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with(input: &str, mode: Mode, file: &str) -> (i32, String) {
        let mut inp = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        let code = run_io(&mut inp, &mut out, file, Some(mode), false);
        (code, String::from_utf8_lossy(&out).into_owned())
    }

    fn tmpfile(n: &str) -> String {
        let d = std::env::temp_dir().join(format!("cgmon-wiz-{}-{n}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let f = d.join("cgmon.yaml").to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&f);
        f
    }

    #[test]
    fn minimal_new_file() {
        let f = tmpfile("min");
        let (code, out) = run_with("pass-123\n\n", Mode::Min, &f);
        assert_eq!(code, 0, "{out}");
        let c = config::load(&f).unwrap();
        assert_eq!(c.web.password, "pass-123");
        let t = std::fs::read_to_string(&f).unwrap();
        assert!(t.starts_with("# cgmon.yaml — записан мастером") && t.contains("# Пароль на изменение настроек"), "{}", &t[..300]);
        // всё остальное — по умолчанию
        assert_eq!(c.dry_run, config::defaults().dry_run);
    }

    #[test]
    fn basic_hub_and_report() {
        let f = tmpfile("basic");
        std::fs::write(&f, "# мой конфиг\nlog_level: debug  # оставить\nweb:\n  password: old\n").unwrap();
        // пароль — оставить; отправка: да, адрес, секрет; центр: да, секрет Enter (тот же), порт Enter, бот, чаты; учёт: да; шлюз: нет; путь Enter
        let input = "\n1\nhttp://10.0.0.1:7788/api/v1/report\n0123456789abcdef-secret\n1\n\n\n123456:abcdefghijklmnop\n111, -1002\n1\n2\n\n";
        let (code, out) = run_with(input, Mode::Basic, &f);
        assert_eq!(code, 0, "{out}");
        let c = config::load(&f).unwrap();
        assert!(c.report.enabled && c.report.urls == vec!["http://10.0.0.1:7788/api/v1/report".to_string()]);
        assert!(c.hub.enabled && c.hub.token == "0123456789abcdef-secret" && c.web.password == "old");
        assert_eq!(crate::livecfg::telegram_dests(&c.hub).len(), 2);
        let t = std::fs::read_to_string(&f).unwrap();
        assert!(t.contains("log_level: debug  # оставить") && t.starts_with("# мой конфиг"), "{t}");
        assert!(!out.contains("0123456789abcdef-secret"), "секрет в итоге: {out}");
        assert!(std::fs::read_dir(std::path::Path::new(&f).parent().unwrap()).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().contains(".bak-")));
    }

    #[test]
    fn page_fields_not_asked() {
        assert!(on_page("dry_run") && on_page("probes.ipv4") && on_page("log_level"));
        assert!(!on_page("web.password") && !on_page("hub.token") && !on_page("accounting.enabled"));
    }
}
