//! История графика страницы на роутере: открыл страницу — сразу виден график за
//! любой интервал. Два уровня: точка в 2 с за последний час (интервалы 1–60 мин) и
//! точка в минуту за сутки (2–24 ч). В точке — средняя скорость WAN и пять самых
//! активных устройств (роутер — тоже «устройство»): подсветка «кто в пике» и линии
//! выбранных устройств. Источник — тот же согласованный снимок учёта, что и у
//! живого графика. Память: точки без отдельных выделений, ~80 байт каждая —
//! (1800 + 1440) · 80 ≈ 260 КБ, имена устройств ≤2000.
//! Страница забирает историю по запросу (сокет «hist», CGI api_hist) при открытии
//! и смене интервала, дальше дорисовывает живые точки сама.
//! Копия — только в /tmp (раз в 5 мин и при остановке): перезапуск cgmon историю не
//! обнуляет, flash не изнашивается; после перезагрузки роутера история начинается заново.

use crate::json::J;
use std::collections::{HashMap, VecDeque};

const TOP: usize = 5;
/// (шаг, мс; точек) — час по 2 с и сутки по минуте
const TIERS: [(i64, usize); 2] = [(2_000, 1800), (60_000, 1440)];
pub const FILE: &str = "/tmp/cgmon/chart.txt";

#[derive(Clone, Copy)]
struct Pt {
    ms: i64,
    rx: f32,
    tx: f32,
    n: u8,
    /// (номер имени, ↓, ↑), Мбит/с
    top: [(u16, f32, f32); TOP],
}

#[derive(Default)]
struct Tier {
    pts: VecDeque<Pt>,
    /// начало текущего шага: время, устройство WAN, байты WAN и накопленные по id
    base_ms: i64,
    base_dev: String,
    base_wan: (u64, u64),
    base_ids: HashMap<String, (u64, u64)>,
}

#[derive(Default)]
pub struct Chart {
    tiers: [Tier; 2],
    names: Vec<String>,
}

fn mbit(b: u64, s: f64) -> f32 {
    (b as f64 * 8.0 / 1e6 / s) as f32
}

impl Chart {
    /// Такт учёта (снимок одного момента). `ids` — накопленные байты устройств и роутера.
    pub fn step(&mut self, ms: i64, dev: &str, wan: (u64, u64), ids: &[(&str, (u64, u64))]) {
        if ms <= 0 {
            return;
        }
        for t in 0..TIERS.len() {
            let (step, keep) = TIERS[t];
            let tier = &self.tiers[t];
            if tier.base_ms != 0 && ms / step == tier.base_ms / step {
                continue;
            }
            let dt = (ms - tier.base_ms) as f64 / 1000.0;
            let sm = step as f64 / 1000.0;
            // точка — за шаг подряд (пропуски и смена устройства WAN — без точки)
            if tier.base_ms > 0 && dt >= sm * 0.5 && dt <= sm * 2.5 && dev == tier.base_dev && wan.0 >= tier.base_wan.0 && wan.1 >= tier.base_wan.1 {
                let mut top: Vec<(&str, f32, f32)> = ids
                    .iter()
                    .filter_map(|(k, v)| {
                        let b = tier.base_ids.get(*k)?;
                        let (d, u) = (mbit(v.0.saturating_sub(b.0), dt), mbit(v.1.saturating_sub(b.1), dt));
                        (d + u >= 0.01).then_some((*k, d, u))
                    })
                    .collect();
                top.sort_by(|a, b| (b.1 + b.2).total_cmp(&(a.1 + a.2)));
                top.truncate(TOP);
                let (rx, tx) = (mbit(wan.0 - tier.base_wan.0, dt), mbit(wan.1 - tier.base_wan.1, dt));
                let mut p = Pt { ms, rx, tx, n: top.len() as u8, top: [(0, 0.0, 0.0); TOP] };
                for (i, (k, d, u)) in top.into_iter().enumerate() {
                    p.top[i] = (self.name_id(k), d, u);
                }
                let tier = &mut self.tiers[t];
                tier.pts.push_back(p);
                while tier.pts.len() > keep {
                    tier.pts.pop_front();
                }
            }
            let tier = &mut self.tiers[t];
            tier.base_ms = ms;
            tier.base_dev.clear();
            tier.base_dev.push_str(dev);
            tier.base_wan = wan;
            tier.base_ids.clear();
            tier.base_ids.extend(ids.iter().map(|(k, v)| (k.to_string(), *v)));
        }
    }

    fn name_id(&mut self, k: &str) -> u16 {
        if let Some(i) = self.names.iter().position(|n| n == k) {
            return i as u16;
        }
        if self.names.len() >= 2000 {
            self.compact();
        }
        self.names.push(k.to_string());
        (self.names.len() - 1) as u16
    }

    /// Имена, на которые больше не ссылается ни одна точка, — прочь (перенумерация).
    fn compact(&mut self) {
        let mut map: HashMap<u16, u16> = HashMap::new();
        let mut names = Vec::new();
        for tier in self.tiers.iter_mut() {
            for p in tier.pts.iter_mut() {
                for t in p.top[..p.n as usize].iter_mut() {
                    let n = *map.entry(t.0).or_insert_with(|| {
                        names.push(std::mem::take(&mut self.names[t.0 as usize]));
                        (names.len() - 1) as u16
                    });
                    t.0 = n;
                }
            }
        }
        self.names = names;
    }

    /// Копия в /tmp: строки «n имя» и «уровень мс ↓ ↑ имя:↓:↑ …».
    pub fn save(&self) {
        if crate::util::readonly() {
            return;
        }
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64 * 1024);
        for n in &self.names {
            let _ = writeln!(s, "n {n}");
        }
        for (t, tier) in self.tiers.iter().enumerate() {
            for p in &tier.pts {
                let _ = write!(s, "{t} {} {} {}", p.ms, p.rx, p.tx);
                for x in &p.top[..p.n as usize] {
                    let _ = write!(s, " {}:{}:{}", x.0, x.1, x.2);
                }
                s.push('\n');
            }
        }
        let _ = crate::util::write_atomic(FILE, s.as_bytes(), 0o600);
    }

    /// Копия из /tmp (после перезапуска cgmon). Испорченные строки пропускаются.
    pub fn load(&mut self, text: &str) {
        for l in text.lines() {
            if let Some(n) = l.strip_prefix("n ") {
                if self.names.len() < 2000 {
                    self.names.push(n.to_string());
                }
                continue;
            }
            let mut w = l.split(' ');
            let (Some(t), Some(ms), Some(rx), Some(tx)) = (w.next().and_then(|x| x.parse::<usize>().ok()), w.next().and_then(|x| x.parse::<i64>().ok()), w.next().and_then(|x| x.parse::<f32>().ok()), w.next().and_then(|x| x.parse::<f32>().ok())) else { continue };
            if t >= TIERS.len() {
                continue;
            }
            let mut p = Pt { ms, rx, tx, n: 0, top: [(0, 0.0, 0.0); TOP] };
            for x in w.take(TOP) {
                let mut f = x.split(':');
                if let (Some(i), Some(d), Some(u)) = (f.next().and_then(|v| v.parse::<u16>().ok()), f.next().and_then(|v| v.parse::<f32>().ok()), f.next().and_then(|v| v.parse::<f32>().ok())) {
                    if (i as usize) < self.names.len() {
                        p.top[p.n as usize] = (i, d, u);
                        p.n += 1;
                    }
                }
            }
            let tier = &mut self.tiers[t];
            if tier.pts.back().map_or(true, |b| b.ms < ms) {
                tier.pts.push_back(p);
                if tier.pts.len() > TIERS[t].1 {
                    tier.pts.pop_front();
                }
            }
        }
    }

    /// История за `sec` секунд: до часа — точки по 2 с, дольше — по минуте.
    /// {"step":мс,"names":[id…],"pts":[[мс,↓,↑,[[имя,↓,↑]…]]…]}
    pub fn json(&self, sec: i64, now_ms: i64) -> String {
        let t = if sec <= 3600 { 0 } else { 1 };
        let from = now_ms - sec.clamp(60, 86_400) * 1000;
        let mut used: Vec<u16> = Vec::new();
        let pts: Vec<&Pt> = self.tiers[t].pts.iter().filter(|p| p.ms > from).collect();
        for p in &pts {
            for x in &p.top[..p.n as usize] {
                if !used.contains(&x.0) {
                    used.push(x.0);
                }
            }
        }
        let mut j = J::new();
        j.obj().key("step").int(TIERS[t].0).key("names").arr();
        for i in &used {
            j.str(self.names.get(*i as usize).map(|s| s.as_str()).unwrap_or(""));
        }
        j.end_arr().key("pts").arr();
        for p in pts {
            j.arr().int(p.ms).num(p.rx as f64, 3).num(p.tx as f64, 3).arr();
            for x in &p.top[..p.n as usize] {
                let k = used.iter().position(|u| *u == x.0).unwrap_or(0);
                j.arr().int(k as i64).num(x.1 as f64, 3).num(x.2 as f64, 3).end_arr();
            }
            j.end_arr().end_arr();
        }
        j.end_arr().end_obj();
        j.b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers() {
        let mut c = Chart::default();
        let t0 = 1_800_000_000_000i64 - 1_800_000_000_000 % 60_000;
        // 1 Мбит/с ↓ на WAN и у устройства — 125 000 байт в секунду
        for s in 0..=125 {
            let b = s as u64 * 125_000;
            c.step(t0 + s * 1000 + 300, "eth0", (b, b / 10), &[("aa:bb", (b, 0)), ("router", (0, b / 10))]);
        }
        assert!(c.tiers[0].pts.len() >= 60, "{}", c.tiers[0].pts.len());
        assert_eq!(c.tiers[1].pts.len(), 2);
        let p = c.tiers[1].pts[0];
        assert!((p.rx - 1.0).abs() < 0.01 && p.n == 2 && c.names[p.top[0].0 as usize] == "aa:bb", "{}", p.rx);
        let j = c.json(600, t0 + 126_000);
        assert!(j.starts_with("{\"step\":2000,\"names\":[\"aa:bb\",\"router\"]"), "{j}");
        assert!(c.json(7200, t0 + 126_000).starts_with("{\"step\":60000"));
        // смена WAN — без точки
        let n = c.tiers[0].pts.len();
        c.step(t0 + 128_300, "eth3", (1, 1), &[]);
        assert_eq!(c.tiers[0].pts.len(), n);
        // копия в /tmp: та же история после перезапуска
        let mut s = String::new();
        for nm in &c.names {
            s += &format!("n {nm}\n");
        }
        for (t, tier) in c.tiers.iter().enumerate() {
            for p in &tier.pts {
                s += &format!("{t} {} {} {}", p.ms, p.rx, p.tx);
                for x in &p.top[..p.n as usize] {
                    s += &format!(" {}:{}:{}", x.0, x.1, x.2);
                }
                s += "\n";
            }
        }
        let mut d = Chart::default();
        d.load(&(s + "garbage line\n9 1 2 3\n"));
        assert_eq!(d.json(600, t0 + 126_000), c.json(600, t0 + 126_000));
    }
}
