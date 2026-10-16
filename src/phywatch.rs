//! Физический уровень: линк, скорость, дуплекс и ошибки кадров на портах.
//!
//! Порты sysfs (сетевые карты, DSA-порты — любой роутер): carrier и
//! carrier_changes (мигание между опросами), speed/duplex, ошибки
//! rx_crc/frame/length/fifo/missed, tx_carrier. Свитчи swconfig (старые
//! ath79/ramips): по каждому порту `swconfig … port N get link` (раз в 15 с) и
//! `get mib` (раз в минуту; сбор счётчиков в драйвере включается, если выключен) —
//! RxFcsErr, RxAlignErr, RxRunt, RxFragment, TxLateCol, TxExcDefer и др.
//! События — в журнал «phy»: линк пропал/появился (с длительностью), мигал,
//! скорость/дуплекс сменились, ошибки (сумма за окно, не чаще раза в 10 мин на
//! порт); при старте — сводка ошибок, накопленных с загрузки роутера.
//!
//! Память в /etc/cgmon/phy.json (не чаще раза в 10 мин): лучшая скорость порта
//! за 30 дней (предупреждение «работает медленнее» — только если порт реально
//! работал быстрее), события CRC и обрывов за неделю и последние счётчики ядра
//! с boot_id — перезапуск cgmon не повторяет сводку и не теряет то, что было,
//! пока он не работал.

use crate::json::J;
use std::collections::BTreeMap;

const LINK_EVERY: i64 = 15_000;
const MIB_EVERY: i64 = 60_000;
const ERR_REPORT_GAP: i64 = 10 * 60_000;
pub const STATE: &str = "/etc/cgmon/phy.json";
const SAVE_GAP: i64 = 10 * 60_000;
const DAY: i64 = 24 * 3_600_000;
/// лучшая скорость и события помнятся 30 дней
const BEST_KEEP: i64 = 30 * DAY;
const EV_KEEP: i64 = 30 * DAY;
/// оценка CRC «с загрузки роутера» держится неделю с первого опроса
const BOOT_KEEP: i64 = 7 * DAY;
/// окна для страницы: сутки, неделя, 30 дней
const WINS: [i64; 3] = [DAY, 7 * DAY, 30 * DAY];
/// счётчики CRC (sysfs и MIB свитча)
const CRC_KEYS: &[&str] = &["rx_crc_errors", "RxFcsErr"];
/// принятые кадры в MIB свитча (доля CRC считается от них)
const MIB_PKTS: &[&str] = &["RxUnicast", "RxBroad", "RxMulti"];
/// Уровень CRC за сутки. На исправной линии CRC практически нет (цель IEEE 802.3 —
/// ошибка на 10^12 бит); по практике Cisco/Juniper кабель меняют уже при доле CRC
/// от 0,01 % принятых кадров. crit — доля ≥ 1/10000 (при малом трафике — от 100 000
/// кадров, т. е. ≥ 10 штук), или ≥ 1000 штук, или CRC вместе с обрывами линка (кабель
/// умирает); warn — единичные CRC.
pub fn crc_level(crc: u64, frames: u64, drops: u64) -> &'static str {
    if crc == 0 {
        ""
    } else if crc >= 1000 || drops > 0 || crc.saturating_mul(10_000) >= frames.max(100_000) {
        "crit"
    } else {
        "warn"
    }
}
/// счётчики ошибок sysfs: (файл, подпись)
const SYS_ERR: &[(&str, &str)] = &[
    ("rx_crc_errors", "CRC"), ("rx_frame_errors", "кадр"), ("rx_length_errors", "длина"),
    ("rx_fifo_errors", "FIFO"), ("rx_missed_errors", "пропущено"), ("tx_carrier_errors", "несущая"),
];
/// счётчики ошибок MIB свитча (ar8xxx): имя → подпись
const MIB_ERR: &[(&str, &str)] = &[
    ("RxFcsErr", "CRC"), ("RxAlignErr", "выравнивание"), ("RxRunt", "короткие"), ("RxFragment", "обрывки"),
    ("RxOverFlow", "переполнение"), ("RxTooLong", "длинные"), ("TxLateCol", "поздние коллизии"),
    ("TxExcDefer", "отсрочки"), ("TxAbortCol", "сброс по коллизиям"), ("TxUnderRun", "недогрузка"),
];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Link {
    pub up: bool,
    pub speed: i64,
    pub full: bool,
}

#[derive(Default)]
struct Port {
    /// подпись для людей: eth3 / switch0 порт 4 (VLAN 1, 101, 102)
    label: String,
    link: Option<Link>,
    down_at: i64,
    changes: u64,
    errs: BTreeMap<String, u64>,
    /// ошибки с прошлого сообщения
    pend: BTreeMap<String, u64>,
    reported: i64,
    /// за последний час: (время, ошибок всего, обрывов линка всего)
    hist: std::collections::VecDeque<(i64, u64, u64)>,
    /// обрывов линка всего (sysfs — carrier_changes/2, свитч — замеченные опросом)
    downs: u64,
    /// ethtool: что порт умеет и объявляет, что объявляет устройство на другом
    /// конце кабеля (Мбит/с, 0 — неизвестно)
    cap: i64,
    partner: i64,
    /// лучшая скорость линка за 30 дней и когда она была (мс)
    best: i64,
    best_at: i64,
    /// предупреждение о скорости ниже прежней (показано один раз, пока не изменится)
    slow_note: String,
    up_since: i64,
    /// события за неделю: (время, ошибок CRC) и (время, обрывов линка)
    ev_crc: std::collections::VecDeque<(i64, u64)>,
    ev_drop: std::collections::VecDeque<(i64, u64)>,
    /// счётчики ядра прошлого запуска cgmon в эту же загрузку роутера: CRC и carrier_changes
    base_crc: Option<u64>,
    base_chg: Option<u64>,
    /// принятые кадры: (время, счётчик) раз в 10 мин за сутки — доля CRC от кадров;
    /// при сводке с загрузки первая точка — 0 (кадры с загрузки)
    pk: std::collections::VecDeque<(i64, u64)>,
    pk_now: u64,
    /// CRC, накопленные с загрузки роутера до первого опроса (когда — неизвестно), и
    /// принятые кадры за то же время; оценка держится неделю с первого опроса
    boot_crc: u64,
    boot_frames: u64,
    boot_at: i64,
    /// обрывы линка с загрузки до первого опроса (CRC вместе с обрывами — кабель умирает)
    boot_downs: u64,
}

impl Port {
    fn new(label: String) -> Port {
        Port { label, ..Default::default() }
    }

    /// Принятые кадры за сутки (или с первой точки) — знаменатель доли CRC.
    fn frames_day(&self) -> u64 {
        self.pk.front().map_or(0, |f| self.pk_now.saturating_sub(f.1))
    }

    /// (уровень, CRC за сутки, обрывов за сутки)
    fn crc_state(&self, now: i64) -> (&'static str, u64, u64) {
        let (c, d) = (ev_sum(&self.ev_crc, now, DAY), ev_sum(&self.ev_drop, now, DAY));
        (crc_level(c, self.frames_day(), d), c, d)
    }

    /// Уровень CRC, накопленных с загрузки роутера (неделю с первого опроса).
    fn boot_level(&self, now: i64) -> &'static str {
        if self.boot_crc == 0 || now - self.boot_at > BOOT_KEEP {
            return "";
        }
        crc_level(self.boot_crc, self.boot_frames, self.boot_downs)
    }
}

#[derive(Default)]
pub struct PhyWatch {
    ports: BTreeMap<String, Port>,
    boot: String,
    /// когда загрузился роутер (мс): окно длиннее аптайма включает всё «с загрузки»
    boot_ms: i64,
    dirty: bool,
    saved_at: i64,
    /// свитчи swconfig: (имя, порты кроме CPU, VLAN порта)
    switches: Vec<(String, Vec<u32>, BTreeMap<u32, String>)>,
    sw_found_at: i64,
    link_at: i64,
    mib_at: i64,
    started: bool,
}

fn sysf(dev: &str, f: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/{f}")).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Физические порты sysfs (как блок портов страницы: без Wi-Fi и CPU-порта DSA).
fn sys_ports() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else { return Vec::new() };
    let mut l: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|d| {
            let b = format!("/sys/class/net/{d}");
            let phys = std::path::Path::new(&format!("{b}/device")).exists() || !sysf(d, "phys_port_name").is_empty();
            let wifi = std::path::Path::new(&format!("{b}/wireless")).exists() || std::path::Path::new(&format!("{b}/phy80211")).exists();
            phys && !wifi
        })
        .collect();
    l.sort();
    l
}

/// «link: port:4 link:up speed:100baseT full-duplex …» → Link.
pub fn parse_sw_link(s: &str) -> Option<Link> {
    let up = s.contains("link:up");
    if !up && !s.contains("link:down") {
        return None;
    }
    let speed = s.split_whitespace().find_map(|w| w.strip_prefix("speed:")).and_then(|v| v.trim_end_matches(|c: char| !c.is_ascii_digit()).parse().ok()).unwrap_or(0);
    Some(Link { up, speed: if up { speed } else { 0 }, full: s.contains("full-duplex") })
}

/// «RxFcsErr    : 1562» → (имя, значение) для счётчиков ошибок.
pub fn parse_mib(s: &str) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for ln in s.lines() {
        let Some((k, v)) = ln.split_once(':') else { continue };
        let k = k.trim();
        if MIB_ERR.iter().any(|(n, _)| *n == k) {
            if let Some(n) = v.split_whitespace().next().and_then(|x| x.parse::<u64>().ok()) {
                m.insert(k.to_string(), n);
            }
        }
    }
    m
}

/// Принятые кадры порта свитча: RxUnicast + RxBroad + RxMulti.
pub fn mib_packets(s: &str) -> u64 {
    s.lines().filter_map(|l| l.split_once(':')).filter(|(k, _)| MIB_PKTS.contains(&k.trim())).filter_map(|(_, v)| v.split_whitespace().next()?.parse::<u64>().ok()).sum()
}

/// «Found: switch0 - mdio.0» → имена свитчей.
fn parse_sw_list(s: &str) -> Vec<String> {
    s.lines().filter_map(|l| l.strip_prefix("Found: ")).filter_map(|r| r.split_whitespace().next()).map(String::from).collect()
}

fn run(a: &[&str]) -> String {
    std::process::Command::new(a[0]).args(&a[1..]).stderr(std::process::Stdio::null()).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

fn speed_text(l: &Link) -> String {
    if !l.up {
        return "нет линка".into();
    }
    format!("{} Мбит/с{}", l.speed, if l.full { "" } else { ", полудуплекс" })
}

fn crc_of(m: &BTreeMap<String, u64>) -> u64 {
    m.iter().filter(|(k, _)| CRC_KEYS.contains(&k.as_str())).map(|(_, v)| *v).sum()
}

/// Добавить событие (соседние в пределах 10 мин — в одну запись), старше недели — прочь.
fn ev_push(q: &mut std::collections::VecDeque<(i64, u64)>, now: i64, n: u64) {
    if n == 0 {
        return;
    }
    match q.back_mut() {
        Some(b) if now - b.0 < 10 * 60_000 => b.1 += n,
        _ => q.push_back((now, n)),
    }
    while q.len() > 300 || q.front().map_or(false, |f| now - f.0 > EV_KEEP) {
        q.pop_front();
    }
}

fn ev_sum(q: &std::collections::VecDeque<(i64, u64)>, now: i64, win: i64) -> u64 {
    q.iter().filter(|e| now - e.0 <= win).map(|e| e.1).sum()
}

/// Доля CRC по-человечески: « (1 на 6,9 млн кадров)»; пусто — кадры неизвестны.
pub fn per_frames(crc: u64, frames: u64) -> String {
    if crc == 0 || frames == 0 {
        return String::new();
    }
    let n = frames as f64 / crc as f64;
    let t = if n >= 1e6 { format!("{:.1} млн", n / 1e6) } else if n >= 1e3 { format!("{:.1} тыс.", n / 1e3) } else { format!("{:.0}", n.max(1.0)) };
    format!(" (1 на {} кадров)", t.replace('.', ","))
}

/// «16.10 04:18» по местному времени роутера.
fn when(ms: i64) -> String {
    let t = crate::util::local(ms / 1000);
    format!("{:02}.{:02} {:02}:{:02}", t.day, t.mon, t.hour, t.min)
}

fn err_text(m: &BTreeMap<String, u64>, names: &[(&str, &str)]) -> String {
    m.iter().filter(|(_, v)| **v > 0).map(|(k, v)| format!("{} {v}", names.iter().find(|(n, _)| n == k).map(|x| x.1).unwrap_or(k))).collect::<Vec<_>>().join(", ")
}

fn dur(ms: i64) -> String {
    let s = ms / 1000;
    if s < 60 {
        format!("{s} с")
    } else if s < 3600 {
        format!("{} мин {} с", s / 60, s % 60)
    } else {
        format!("{} ч {} мин", s / 3600, s % 3600 / 60)
    }
}

impl PhyWatch {
    /// Такт (лёгкий блок): события для журнала.
    pub fn tick(&mut self, now: i64, uptime_s: i64) -> Vec<String> {
        let mut msgs = Vec::new();
        if now - self.link_at < LINK_EVERY {
            return msgs;
        }
        self.link_at = now;
        let first = !self.started;
        self.started = true;
        if first {
            self.load(now);
        }
        self.boot_ms = now - uptime_s * 1000;
        // ---- порты sysfs ----
        for dev in sys_ports() {
            let p = self.ports.entry(dev.clone()).or_insert_with(|| Port::new(dev.clone()));
            let carrier = sysf(&dev, "carrier");
            if carrier.is_empty() {
                continue; // интерфейс выключен — не следим
            }
            let up = carrier == "1";
            let link = Link { up, speed: if up { sysf(&dev, "speed").parse().unwrap_or(0).max(0) } else { 0 }, full: sysf(&dev, "duplex") == "full" };
            let changes: u64 = sysf(&dev, "carrier_changes").parse().unwrap_or(0);
            if let Some((cap, partner)) = ethtool_modes(&dev) {
                p.cap = cap;
                p.partner = partner;
            }
            let mut errs = BTreeMap::new();
            for (f, _) in SYS_ERR {
                errs.insert(f.to_string(), sysf(&dev, &format!("statistics/{f}")).parse().unwrap_or(0));
            }
            let pk = sysf(&dev, "statistics/rx_packets").parse().unwrap_or(0);
            msgs.extend(Self::observe(p, now, link, Some(changes), errs, pk, SYS_ERR, uptime_s, &mut self.dirty));
        }
        // ---- свитчи swconfig ----
        if self.sw_found_at == 0 || now - self.sw_found_at >= 10 * 60_000 {
            self.sw_found_at = now.max(1);
            self.find_switches();
        }
        let mib_now = now - self.mib_at >= MIB_EVERY;
        if mib_now {
            self.mib_at = now;
        }
        for (sw, ports, vlans) in self.switches.clone() {
            for n in ports {
                let id = format!("{sw}:{n}");
                let label = format!("{sw} порт {n}{}", vlans.get(&n).map(|v| format!(" (VLAN {v})")).unwrap_or_default());
                let Some(link) = parse_sw_link(&run(&["swconfig", "dev", &sw, "port", &n.to_string(), "get", "link"])) else { continue };
                let p = self.ports.entry(id).or_insert_with(|| Port::new(label.clone()));
                p.label = label;
                let (errs, pk) = if mib_now || first {
                    let t = run(&["swconfig", "dev", &sw, "port", &n.to_string(), "get", "mib"]);
                    (parse_mib(&t), mib_packets(&t))
                } else {
                    (p.errs.clone(), p.pk_now)
                };
                msgs.extend(Self::observe(p, now, link, None, errs, pk, MIB_ERR, uptime_s, &mut self.dirty));
            }
        }
        if self.dirty && now - self.saved_at >= SAVE_GAP {
            self.save(now);
        }
        msgs
    }

    /// При остановке cgmon: несохранённое — в файл (перезапуск продолжит счёт).
    pub fn flush(&mut self, now: i64) {
        if self.started && self.dirty {
            self.save(now);
        }
    }

    /// Память прошлых запусков: лучшая скорость, события, счётчики этой загрузки.
    fn load(&mut self, now: i64) {
        self.boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default();
        self.saved_at = now;
        let Some(v) = std::fs::read_to_string(crate::storage::path(STATE)).ok().and_then(|s| crate::value::parse_json(&s).ok()) else { return };
        let same_boot = !self.boot.is_empty() && v.get("boot").and_then(|b| b.as_str()) == Some(self.boot.as_str());
        let Some(crate::value::Value::Map(ports)) = v.get("ports") else { return };
        let num = |x: Option<&crate::value::Value>| x.and_then(|n| n.as_f64()).map(|f| f as i64);
        let evs = |x: Option<&crate::value::Value>| -> std::collections::VecDeque<(i64, u64)> {
            let mut q = std::collections::VecDeque::new();
            if let Some(crate::value::Value::List(l)) = x {
                for e in l.iter().take(300) {
                    if let crate::value::Value::List(p) = e {
                        if let (Some(t), Some(n)) = (num(p.first()), num(p.get(1))) {
                            if now - t <= EV_KEEP && n >= 0 {
                                q.push_back((t, n as u64));
                            }
                        }
                    }
                }
            }
            q
        };
        for (id, pv) in ports.iter().take(64) {
            let p = self.ports.entry(id.clone()).or_insert_with(|| Port::new(id.clone()));
            let (best, best_at) = (num(pv.get("best")).unwrap_or(0), num(pv.get("best_at")).unwrap_or(0));
            if now - best_at <= BEST_KEEP {
                (p.best, p.best_at) = (best, best_at);
            }
            p.ev_crc = evs(pv.get("ev_crc"));
            p.ev_drop = evs(pv.get("ev_drop"));
            if same_boot {
                p.base_crc = num(pv.get("crc")).map(|x| x as u64);
                p.base_chg = num(pv.get("chg")).map(|x| x as u64);
                // кадры за сутки — те же счётчики ядра: доля CRC не завышается после перезапуска
                p.pk = evs(pv.get("pk")).into_iter().filter(|e| now - e.0 <= DAY).collect();
                p.boot_crc = num(pv.get("boot_crc")).unwrap_or(0) as u64;
                p.boot_frames = num(pv.get("boot_frames")).unwrap_or(0) as u64;
                p.boot_at = num(pv.get("boot_at")).unwrap_or(0);
                p.boot_downs = num(pv.get("boot_downs")).unwrap_or(0) as u64;
                p.up_since = num(pv.get("up_at")).unwrap_or(0);
            }
        }
    }

    fn save(&mut self, now: i64) {
        self.saved_at = now;
        self.dirty = false;
        if crate::util::readonly() {
            return;
        }
        let mut j = J::new();
        j.obj().key("boot").str(&self.boot).key("ports").obj();
        for (id, p) in &self.ports {
            j.key(id).obj().key("best").int(p.best).key("best_at").int(p.best_at).key("crc").uint(crc_of(&p.errs)).key("chg").uint(p.changes);
            if p.up_since > 0 {
                j.key("up_at").int(p.up_since);
            }
            if p.boot_crc > 0 {
                j.key("boot_crc").uint(p.boot_crc).key("boot_frames").uint(p.boot_frames).key("boot_at").int(p.boot_at).key("boot_downs").uint(p.boot_downs);
            }
            for (k, q) in [("ev_crc", &p.ev_crc), ("ev_drop", &p.ev_drop), ("pk", &p.pk)] {
                j.key(k).arr();
                for (t, n) in q {
                    j.arr().int(*t).uint(*n).end_arr();
                }
                j.end_arr();
            }
            j.end_obj();
        }
        j.end_obj().end_obj();
        if let Err(e) = crate::util::write_atomic(&crate::storage::path(STATE), j.b.as_bytes(), 0o600) {
            crate::log_debug!("phy: save {STATE}: {e}");
        }
    }

    fn find_switches(&mut self) {
        let mut out = Vec::new();
        for sw in parse_sw_list(&run(&["swconfig", "list"])) {
            let help = run(&["swconfig", "dev", &sw, "help"]);
            // «ports: 7 (cpu @ 0)»
            let (mut n, mut cpu) = (0u32, 0u32);
            if let Some(i) = help.find("ports: ") {
                let rest = &help[i + 7..];
                n = rest.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
                cpu = rest.split("cpu @ ").nth(1).and_then(|x| x.trim_end_matches(|c: char| !c.is_ascii_digit()).split(|c: char| !c.is_ascii_digit()).next()).and_then(|x| x.parse().ok()).unwrap_or(0);
            }
            if n == 0 || n > 16 {
                continue;
            }
            // сбор счётчиков ar8xxx выключен — включить (только опрос драйвером, порты не трогает)
            if run(&["swconfig", "dev", &sw, "get", "ar8xxx_mib_poll_interval"]).trim() == "0" && !crate::util::readonly() {
                let _ = run(&["swconfig", "dev", &sw, "set", "ar8xxx_mib_poll_interval", "30000"]);
                crate::log_info!("phy: {sw}: MIB counters polling enabled (30 s)");
            }
            // порты без VLAN при включённых VLAN — внутренние (второй CPU-порт), не кабели
            let vl = switch_vlans();
            out.push((sw, (0..n).filter(|p| *p != cpu && (vl.is_empty() || vl.contains_key(p))).collect(), vl));
        }
        self.switches = out;
    }

    /// Новое состояние порта → сообщения.
    #[allow(clippy::too_many_arguments)]
    fn observe(p: &mut Port, now: i64, link: Link, changes: Option<u64>, errs: BTreeMap<String, u64>, packets: u64, names: &[(&str, &str)], uptime_s: i64, dirty: &mut bool) -> Vec<String> {
        let mut msgs = Vec::new();
        let label = p.label.clone();
        let first = p.link.is_none();
        // кадры за сутки: первая точка — 0, если CRC считаются с загрузки (доля — от тех же кадров)
        p.pk_now = packets;
        if p.pk.back().map_or(true, |b| now - b.0 >= 10 * 60_000) {
            p.pk.push_back((now, packets));
        }
        while p.pk.len() > 1 && p.pk.front().map_or(false, |f| now - f.0 > DAY) {
            p.pk.pop_front();
        }
        // новые CRC и обрывы: с прошлого опроса; при первом — с прошлого запуска cgmon в эту
        // загрузку роутера или (новая загрузка, первый запуск) всё накопленное с загрузки
        let (crc, crc_was) = (crc_of(&errs), if first { p.base_crc.unwrap_or(0) } else { crc_of(&p.errs) });
        if first && p.base_crc.is_none() {
            // накоплено с загрузки, когда — неизвестно: не «за сутки», отдельная оценка
            if crc > 0 {
                // carrier_changes: первый подъём после загрузки — не обрыв
                let downs = changes.map_or(0, |c| c.saturating_sub(2) / 2);
                (p.boot_crc, p.boot_frames, p.boot_at, p.boot_downs) = (crc, packets, now, downs);
                *dirty = true;
            }
        } else if crc > crc_was {
            ev_push(&mut p.ev_crc, now, crc - crc_was);
            *dirty = true;
        }
        let drops = match changes {
            // carrier_changes: вниз+вверх = 2; первый подъём после загрузки — не обрыв
            Some(c) if first => match p.base_chg {
                Some(b) => (c / 2).saturating_sub(b / 2),
                None => 0, // обрывы с загрузки — только справка (downs), не события суток
            },
            Some(c) => (c / 2).saturating_sub(p.changes / 2),
            None => u64::from(p.link.as_ref().map_or(false, |o| o.up && !link.up)),
        };
        if drops > 0 {
            if first {
                p.up_since = 0; // линк рвался, пока cgmon не работал: прежнее время подъёма неверно
            }
            ev_push(&mut p.ev_drop, now, drops);
            *dirty = true;
        }
        if first {
            // сводка с загрузки роутера: ошибки уже накоплены — сразу видно больной кабель
            // (перезапуск cgmon в ту же загрузку её не повторяет)
            let t = err_text(&errs, names);
            if !t.is_empty() && p.base_crc.is_none() {
                msgs.push(format!("Порт {label}: с загрузки роутера ({}) ошибок: {t}; сейчас {}", dur(uptime_s * 1000), speed_text(&link)));
            }
        } else if let Some(old) = &p.link {
            if old.up && !link.up {
                p.down_at = now;
                msgs.push(format!("Порт {label}: линк пропал (был {})", speed_text(old)));
            } else if !old.up && link.up {
                let d = if p.down_at > 0 { format!(" через {}", dur(now - p.down_at)) } else { String::new() };
                msgs.push(format!("Порт {label}: линк появился{d} — {}", speed_text(&link)));
            } else if old.up && link.up && (old.speed != link.speed || old.full != link.full) {
                let worse = link.speed < old.speed || (old.full && !link.full);
                msgs.push(format!("Порт {label}: {} → {}{}", speed_text(old), speed_text(&link), if worse { " — так бывает при плохом кабеле или разъёме" } else { "" }));
            }
            // мигал между опросами: carrier_changes вырос больше, чем видно по состоянию
            if let Some(c) = changes {
                let seen = if old.up != link.up { 1 } else { 0 };
                if p.changes > 0 && c > p.changes + seen {
                    msgs.push(format!("Порт {label}: линк мигал {} раз за {} с", (c - p.changes - seen + 1) / 2 + ((c - p.changes - seen) % 2), LINK_EVERY / 1000));
                }
            }
            for (k, v) in &errs {
                let was = p.errs.get(k).copied().unwrap_or(*v);
                if *v > was {
                    *p.pend.entry(k.clone()).or_insert(0) += v - was;
                }
            }
            if !p.pend.is_empty() && now - p.reported >= ERR_REPORT_GAP {
                let t = err_text(&p.pend, names);
                if !t.is_empty() {
                    let win = if p.reported > 0 { format!("за {}", dur(now - p.reported)) } else { "с прошлого опроса".into() };
                    msgs.push(format!("Порт {label}: ошибки кадров {win}: {t} ({})", speed_text(&link)));
                }
                p.pend.clear();
                p.reported = now;
            }
        }
        if p.reported == 0 {
            p.reported = now;
        }
        // обрывы: sysfs — по carrier_changes (вниз+вверх = 2), свитч — замеченные опросом
        match changes {
            Some(c) => p.downs = c / 2,
            None => {
                if p.link.as_ref().map_or(false, |o| o.up && !link.up) {
                    p.downs += 1;
                }
            }
        }
        // время подъёма линка — только если cgmon видел сам подъём (при первом опросе
        // неизвестно; прошлый запуск в эту же загрузку оставил его в phy.json)
        if !link.up {
            p.up_since = 0;
        } else if p.link.as_ref().map_or(false, |o| !o.up) {
            p.up_since = now;
            *dirty = true;
        }
        // лучшая скорость за 30 дней: «работает медленнее» — только если реально было быстрее
        if link.up {
            if link.speed > p.best || now - p.best_at > BEST_KEEP {
                (p.best, p.best_at) = (link.speed, now);
                *dirty = true;
            } else if link.speed == p.best && now - p.best_at > DAY {
                p.best_at = now;
                *dirty = true;
            }
            let note = slow_note(&link, p.best, p.best_at, p.cap, p.partner);
            if note != p.slow_note {
                if !note.is_empty() {
                    msgs.push(format!("Порт {label}: {note}"));
                }
                p.slow_note = note;
            }
        }
        let total: u64 = errs.values().sum();
        p.hist.push_back((now, total, p.downs));
        while p.hist.front().map_or(false, |h| now - h.0 > 3_600_000) {
            p.hist.pop_front();
        }
        p.link = Some(link);
        if let Some(c) = changes {
            p.changes = c;
        }
        p.errs = errs;
        msgs
    }

    /// Проблемы портов для центра сбора: (уровень, вид, текст). crit — ошибки CRC за
    /// сутки (кабель или разъём повреждены, ещё немного — и связи не будет) и обрывы
    /// линка за час; warn — CRC за неделю, обрывы за сутки, прочие ошибки кадров за
    /// час, скорость ниже прежней.
    pub fn issues(&self) -> Vec<(&'static str, String, String)> {
        let mut out = Vec::new();
        let now = self.link_at;
        for (id, p) in &self.ports {
            let (Some(f), Some(b)) = (p.hist.front(), p.hist.back()) else { continue };
            let (lv, crc_day, drop_day) = p.crc_state(now);
            let share = |f: u64| per_frames(crc_day, f);
            if lv == "crit" {
                out.push(("crit", format!("phy_crc:{id}"), format!("Порт {}: {crc_day} ошибок CRC за сутки{} — кабель или разъём повреждены, ещё немного — и связи не будет", p.label, share(p.frames_day()))));
            } else if lv == "warn" {
                out.push(("warn", format!("phy_crc:{id}"), format!("Порт {}: {crc_day} ошибок CRC за сутки{} — кабель или разъём под подозрением", p.label, share(p.frames_day()))));
            } else {
                let bl = p.boot_level(now);
                if !bl.is_empty() {
                    let sh = per_frames(p.boot_crc, p.boot_frames);
                    let what = if bl == "crit" { "кабель или разъём повреждены, ещё немного — и связи не будет" } else { "кабель или разъём под подозрением" };
                    let dr = if p.boot_downs > 0 { format!(" и {} обрыв(ов) линка", p.boot_downs) } else { String::new() };
                    out.push((bl, format!("phy_crc:{id}"), format!("Порт {}: {} ошибок CRC{sh}{dr} с загрузки роутера, новых пока нет — {what}", p.label, p.boot_crc)));
                }
            }
            if b.2 > f.2 {
                out.push(("crit", format!("phy_drop:{id}"), format!("Порт {}: {} обрыв(ов) линка за час", p.label, b.2 - f.2)));
            } else if drop_day >= 2 {
                out.push(("warn", format!("phy_drop:{id}"), format!("Порт {}: {drop_day} обрыв(ов) линка за сутки", p.label)));
            }
            // прочие ошибки кадров за час (FIFO, пропущенные — чаще перегрузка, не кабель)
            let other = b.1.saturating_sub(f.1).saturating_sub(ev_sum(&p.ev_crc, now, 3_600_000));
            if other > 0 {
                out.push(("warn", format!("phy_err:{id}"), format!("Порт {}: {other} ошибок кадров за час", p.label)));
            }
            if !p.slow_note.is_empty() && p.link.as_ref().map_or(false, |l| l.up) {
                out.push(("warn", format!("phy_slow:{id}"), format!("Порт {}: {}", p.label, p.slow_note)));
            }
        }
        out
    }

    /// Порты для страницы: подпись, линк, накопленные ошибки.
    pub fn status_json(&self, j: &mut J) {
        j.arr();
        for (id, p) in &self.ports {
            let Some(l) = &p.link else { continue };
            j.obj().key("id").str(id).key("label").str(&p.label).key("up").bool(l.up).key("speed").int(l.speed).key("full").bool(l.full);
            let e: u64 = p.errs.values().sum();
            if e > 0 {
                j.key("errors").uint(e);
                j.key("kinds").obj();
                for (k, v) in p.errs.iter().filter(|x| *x.1 > 0) {
                    j.key(SYS_ERR.iter().chain(MIB_ERR.iter()).find(|(n, _)| n == k).map(|x| x.1).unwrap_or(k)).uint(*v);
                }
                j.end_obj();
            }
            // за последний час — для «Текущих событий»: ошибки и обрывы растут сейчас
            if let (Some(f), Some(b)) = (p.hist.front(), p.hist.back()) {
                if b.1 > f.1 {
                    j.key("err_hour").uint(b.1 - f.1);
                }
                if b.2 > f.2 {
                    j.key("downs_hour").uint(b.2 - f.2);
                }
            }
            if p.downs > 0 {
                j.key("downs").uint(p.downs);
            }
            let now = self.link_at;
            let crc = crc_of(&p.errs);
            if crc > 0 {
                j.key("crc").uint(crc);
            }
            let (lv, cd, dd) = p.crc_state(now);
            if cd > 0 {
                j.key("crc_day").uint(cd).key("crc_level").str(lv).key("frames_day").uint(p.frames_day());
            }
            // за сутки / неделю / 30 дней: события cgmon, а если роутер загрузился позже начала
            // окна — не меньше накопленного с загрузки (оно всё внутри окна)
            let in_boot = |w: i64| self.boot_ms > 0 && now - self.boot_ms <= w;
            j.key("crc_win").arr();
            for w in WINS {
                let e = ev_sum(&p.ev_crc, now, w);
                j.uint(if in_boot(w) { e.max(crc) } else { e });
            }
            j.end_arr().key("drops_win").arr();
            for w in WINS {
                let e = ev_sum(&p.ev_drop, now, w);
                j.uint(if in_boot(w) { e.max(p.downs) } else { e });
            }
            j.end_arr();
            if let Some(l) = p.ev_crc.back() {
                j.key("crc_at").int(l.0).key("crc_week").uint(ev_sum(&p.ev_crc, now, 7 * DAY));
            }
            let bl = p.boot_level(now);
            if !bl.is_empty() {
                j.key("boot_level").str(bl).key("boot_crc").uint(p.boot_crc).key("boot_frames").uint(p.boot_frames).key("boot_downs").uint(p.boot_downs);
            }
            if dd > 0 {
                j.key("downs_day").uint(dd);
            }
            if let Some(l) = p.ev_drop.back() {
                j.key("drop_at").int(l.0).key("downs_week").uint(ev_sum(&p.ev_drop, now, 7 * DAY));
            }
            if p.best > 0 {
                j.key("best").int(p.best).key("best_at").int(p.best_at);
            }
            if p.cap > 0 {
                j.key("cap").int(p.cap);
            }
            if p.partner > 0 {
                j.key("partner").int(p.partner);
            }
            if !p.slow_note.is_empty() {
                j.key("slow").str(&p.slow_note);
            }
            if l.up && p.up_since > 0 {
                j.key("up_ms").int(p.up_since);
            }
            j.end_obj();
        }
        j.end_arr();
    }

    pub fn on(&self) -> bool {
        self.started
    }
}

/// ethtool (ETHTOOL_GSET, без запуска программы): наибольшая скорость, которую порт
/// умеет и объявляет, и наибольшая из объявленных устройством на другом конце
/// кабеля (Мбит/с; 0 — неизвестно).
pub fn ethtool_modes(dev: &str) -> Option<(i64, i64)> {
    if dev.len() >= 16 {
        return None;
    }
    let mut cmd = [0u8; 44];
    cmd[0..4].copy_from_slice(&1u32.to_ne_bytes()); // ETHTOOL_GSET
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in dev.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_data = cmd.as_mut_ptr() as *mut libc::c_char;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let r = unsafe { libc::ioctl(fd, 0x8946 as _, &mut ifr) }; // SIOCETHTOOL
    unsafe { libc::close(fd) };
    if r < 0 {
        return None;
    }
    let u = |o: usize| u32::from_ne_bytes([cmd[o], cmd[o + 1], cmd[o + 2], cmd[o + 3]]);
    let (sup, adv, lp) = (u(4), u(8), u(32));
    Some((modes_max(sup & adv), modes_max(lp)))
}

/// Маска ethtool (legacy) → наибольшая скорость, Мбит/с.
pub fn modes_max(m: u32) -> i64 {
    if m & (1 << 15) != 0 {
        2500
    } else if m & (1 << 12) != 0 {
        10000
    } else if m & 0x30 != 0 {
        1000
    } else if m & 0x0c != 0 {
        100
    } else if m & 0x03 != 0 {
        10
    } else {
        0
    }
}

/// Скорость ниже прежней: что сказать (пусто — всё нормально). Только если за 30
/// дней порт реально работал быстрее (`best`): модем или ONT на 100 Мбит/с — норма.
pub fn slow_note(l: &Link, best: i64, best_at: i64, cap: i64, partner: i64) -> String {
    if !l.up || l.speed == 0 || best <= l.speed {
        return String::new();
    }
    let was = format!("работает на {} Мбит/с, а {} было {best}", l.speed, when(best_at));
    if partner > 0 && partner < best {
        format!("{was} — устройство на другом конце кабеля теперь объявляет только до {partner}: обычно так оно само понижает скорость после сбоев на кабеле (downshift)")
    } else if cap >= best && partner >= best {
        format!("{was}, и обе стороны по-прежнему умеют {best} — почти всегда кабель или разъём (для гигабита нужны все 4 пары)")
    } else {
        format!("{was} — кабель, разъём или устройство на другом конце кабеля")
    }
}

/// Порт свитча → VLAN (из /etc/config/network: switch_vlan vid/vlan + ports).
fn switch_vlans() -> BTreeMap<u32, String> {
    let mut m: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for s in crate::topo::read_uci("/etc/config/network").iter().filter(|s| s.typ == "switch_vlan") {
        let vid = if s.opt("vid").is_empty() { s.opt("vlan").to_string() } else { s.opt("vid").to_string() };
        for p in s.opt("ports").split_whitespace() {
            if let Ok(n) = p.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<u32>() {
                let l = m.entry(n).or_default();
                if !l.contains(&vid) {
                    l.push(vid.clone());
                }
            }
        }
    }
    m.into_iter().map(|(k, v)| (k, v.join(", "))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swconfig_parsing() {
        let l = parse_sw_link("link: port:4 link:up speed:100baseT full-duplex txflow rxflow eee100 auto").unwrap();
        assert_eq!(l, Link { up: true, speed: 100, full: true });
        assert!(!parse_sw_link("link: port:2 link:down").unwrap().up);
        let m = parse_mib("Port 4 MIB counters\nRxFcsErr    : 1562\nRxGoodByte  : 132116359651 (123.0 GiB)\nTxLateCol   : 0\n");
        assert_eq!(m.get("RxFcsErr"), Some(&1562));
        assert!(!m.contains_key("RxGoodByte"));
        assert_eq!(parse_sw_list("Found: switch0 - mdio.0\n"), vec!["switch0".to_string()]);
    }

    #[test]
    fn speed_notes() {
        let l = Link { up: true, speed: 100, full: true };
        assert!(slow_note(&l, 1000, 0, 1000, 1000).contains("4 пары"));
        assert!(slow_note(&l, 1000, 0, 1000, 100).contains("downshift"));
        assert!(slow_note(&l, 100, 0, 1000, 100).is_empty()); // быстрее не было — модем на 100 Мбит/с, норма
        assert!(slow_note(&l, 1000, 0, 0, 0).contains("другом конце"));
        assert_eq!(modes_max(0x3f), 1000);
        assert_eq!(modes_max(0x0f), 100);
    }

    #[test]
    fn events() {
        let mut p = Port::new("eth3".into());
        let up = Link { up: true, speed: 1000, full: true };
        let e0: BTreeMap<String, u64> = [("rx_crc_errors".to_string(), 5)].into_iter().collect();
        let mut d = false;
        let m = PhyWatch::observe(&mut p, 0, up.clone(), Some(1), e0.clone(), 1000, SYS_ERR, 3600, &mut d);
        assert!(m[0].contains("с загрузки") && m[0].contains("CRC 5"), "{m:?}");
        assert_eq!(ev_sum(&p.ev_crc, 0, DAY), 0); // с загрузки — не «за сутки»
        assert_eq!((p.boot_crc, p.boot_level(0)), (5, "warn")); // мало кадров: порог от 100 000
        let down = Link { up: false, speed: 0, full: false };
        let m = PhyWatch::observe(&mut p, 15_000, down.clone(), Some(2), e0.clone(), 2000, SYS_ERR, 0, &mut d);
        assert!(m[0].contains("линк пропал"), "{m:?}");
        let slow = Link { up: true, speed: 100, full: true };
        let m = PhyWatch::observe(&mut p, 45_000, slow.clone(), Some(3), e0.clone(), 3000, SYS_ERR, 0, &mut d);
        assert!(m[0].contains("линк появился через 30 с — 100 Мбит/с"), "{m:?}");
        assert!(m.iter().any(|x| x.contains("было 1000")), "{m:?}");
        // мигание между опросами и ошибки — не чаще раза в 10 мин
        let e1: BTreeMap<String, u64> = [("rx_crc_errors".to_string(), 25)].into_iter().collect();
        let m = PhyWatch::observe(&mut p, 11 * 60_000, slow, Some(7), e1, 1_000_000, SYS_ERR, 0, &mut d);
        assert!(m.iter().any(|x| x.contains("мигал")) && m.iter().any(|x| x.contains("CRC 20")), "{m:?}");
        assert_eq!(ev_sum(&p.ev_crc, 11 * 60_000, DAY), 20);
        assert_eq!(ev_sum(&p.ev_drop, 11 * 60_000, DAY), 3); // 1→2→3→7: обрывы после первого опроса
        assert!(d);
        assert_eq!(p.crc_state(11 * 60_000).0, "crit"); // CRC вместе с обрывами
    }

    #[test]
    fn crc_levels() {
        assert_eq!(crc_level(0, 1000, 0), "");
        assert_eq!(crc_level(3, 10_000_000, 0), "warn"); // единичные на миллионах кадров
        assert_eq!(crc_level(137, 1_000_000, 0), "crit"); // 0,0137 % ≥ 0,01 %
        assert_eq!(crc_level(1000, u64::MAX, 0), "crit");
        assert_eq!(per_frames(137, 944_740_765), " (1 на 6,9 млн кадров)");
        assert_eq!(per_frames(3, 0), "");
        assert_eq!(crc_level(1, u64::MAX, 1), "crit"); // CRC и обрывы — кабель умирает
        assert_eq!(mib_packets("RxBroad     : 10\nRxUnicast   : 5 (x)\nRxFcsErr : 3\n"), 15);
    }

    #[test]
    fn restart_same_boot() {
        // перезапуск cgmon в ту же загрузку: старые CRC не новые, сводка не повторяется
        let mut p = Port::new("eth0".into());
        p.base_crc = Some(137);
        p.base_chg = Some(218);
        let e: BTreeMap<String, u64> = [("rx_crc_errors".to_string(), 140)].into_iter().collect();
        let mut d = false;
        let m = PhyWatch::observe(&mut p, 0, Link { up: true, speed: 100, full: true }, Some(220), e, 5_000_000, SYS_ERR, 3600, &mut d);
        assert!(m.is_empty(), "{m:?}");
        assert_eq!(ev_sum(&p.ev_crc, 0, DAY), 3);
        assert_eq!(ev_sum(&p.ev_drop, 0, DAY), 1);
    }
}
