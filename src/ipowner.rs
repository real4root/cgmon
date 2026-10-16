//! Чей адрес (перенос ipowner.go): PTR и автономная система через DNS Team
//! Cymru (TXT <обратный>.origin[6].asn.cymru.com → номер AS,
//! AS<n>.asn.cymru.com → название) — запросы к локальному dnsmasq
//! (127.0.0.1:53). Кэш 6 ч, неудача — повтор через 10 мин, ≤ 2 выяснения сразу.

use crate::dns::{self, Client};
use crate::evloop::Poller;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

const KEEP_MS: u64 = 6 * 3600 * 1000;
const RETRY_MS: u64 = 10 * 60 * 1000;
const TIMEOUT_MS: u64 = 8000;
const MAX_INFO: usize = 5000;
const WORKERS: usize = 2;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct IpInfo {
    pub ptr: String,
    pub asn: String,
    pub as_name: String,
    pub brand: String,
    at: u64,
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Ptr,
    Origin,
    Name,
}

struct Job {
    ip: IpAddr,
    stage: Stage,
    info: IpInfo,
}

pub struct IpOwner {
    info: HashMap<IpAddr, IpInfo>,
    as_name: HashMap<String, String>,
    queue: VecDeque<IpAddr>,
    jobs: HashMap<u64, Job>,
    tag_base: u64,
    next: u64,
    server: SocketAddr,
}

/// Имя TXT-запроса номера AS.
pub fn cymru_origin(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(_) => dns::reverse_name(ip).replace("ip6.arpa", "origin6.asn.cymru.com"),
    }
}

const ASN_BRANDS: &[(&str, &str)] = &[("8193", "Uztelecom")];

const AS_BRANDS: &[(&str, &str)] = &[
    ("TELEGRAM", "Telegram"), ("UZTELECOM", "Uztelecom"), ("FACEBOOK", "Meta (Instagram/WhatsApp/Facebook)"), ("GOOGLE", "Google/YouTube"),
    ("AMAZON", "Amazon AWS"), ("CLOUDFLARE", "Cloudflare"), ("AKAMAI", "Akamai CDN"), ("MICROSOFT", "Microsoft"), ("APPLE", "Apple"),
    ("BYTEDANCE", "TikTok"), ("TIKTOK", "TikTok"), ("ALIBABA", "Alibaba"), ("TAOBAO", "Alibaba"), ("YANDEX", "Yandex"),
    ("VKONTAKTE", "VK"), ("VK-", "VK"), ("HETZNER", "Hetzner"), ("OVH", "OVH"), ("DIGITALOCEAN", "DigitalOcean"),
    ("FASTLY", "Fastly CDN"), ("NETFLIX", "Netflix"), ("TWITTER", "X (Twitter)"), ("EDGECAST", "Edgio CDN"), ("ZOOM", "Zoom"),
    ("DISCORD", "Discord"), ("VALVE", "Steam"), ("TENCENT", "Tencent (WeChat)"), ("HUAWEI", "Huawei Cloud"),
];

/// Бренд по номеру AS (название в реестре бывает историческим), иначе по названию.
pub fn asn_brand(asn: &str, name: &str) -> String {
    let n = asn.trim().trim_start_matches("AS");
    if let Some((_, b)) = ASN_BRANDS.iter().find(|(a, _)| *a == n) {
        return b.to_string();
    }
    as_brand(name)
}

/// «TELEGRAM - Telegram Messenger Inc, VG» → «Telegram»; неизвестные —
/// организация без формы собственности и страны.
pub fn as_brand(as_: &str) -> String {
    if as_.is_empty() {
        return String::new();
    }
    let handle = as_.trim().split(' ').next().unwrap_or("").to_uppercase();
    if let Some((_, b)) = AS_BRANDS.iter().find(|(p, _)| handle.starts_with(p)) {
        return b.to_string();
    }
    let mut org: String = match as_.find(" - ") {
        Some(i) => as_[i + 3..].to_string(),
        None => {
            // только код AS («FLINK-AS, UZ») — без «-AS» и страны, с заглавной
            let mut o = as_.split(',').next().unwrap_or("").trim().to_string();
            for suf in ["-AS", "_AS", "-NET", "-ASN"] {
                if let Some(x) = o.strip_suffix(suf) {
                    o = x.to_string();
                }
            }
            if o == o.to_uppercase() && o.chars().count() > 1 {
                let mut c = o.chars();
                let f = c.next().unwrap();
                o = f.to_string() + &c.as_str().to_lowercase();
            }
            return o;
        }
    };
    if let Some(i) = org.rfind(',') {
        org.truncate(i); // страна
    }
    org = org.replace('_', " ").trim().to_string();
    for suf in [", Inc.", " Inc.", " Inc", " LLC", " Ltd.", " Ltd", " GmbH", " B.V.", " S.A.", " Co.", " LTD", " Joint Stock Company", " Joint-Stock Company", " JSC", " OJSC", " CJSC", " Limited Liability Company", " FE LLC", " MChJ", " XK"] {
        let t = org.trim().to_string();
        org = t.strip_suffix(suf).map(String::from).unwrap_or(t);
    }
    org.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl IpOwner {
    /// tag_base — диапазон меток DNS (младшие 32 бита — номер запроса).
    pub fn new(tag_base: u64) -> IpOwner {
        IpOwner { info: HashMap::new(), as_name: HashMap::new(), queue: VecDeque::new(), jobs: HashMap::new(), tag_base, next: 0, server: "127.0.0.1:53".parse().unwrap() }
    }

    pub fn tags(&self) -> (u64, u64) {
        (self.tag_base, self.tag_base | 0xffff_ffff)
    }

    /// Сведения, если уже выяснены (и не устарели).
    pub fn get(&self, ip: &IpAddr, now: u64) -> Option<&IpInfo> {
        self.info.get(ip).filter(|i| now - i.at <= KEEP_MS)
    }

    /// Выяснить в фоне.
    pub fn want(&mut self, ip: IpAddr, now: u64) {
        if let Some(i) = self.info.get(&ip) {
            if now - i.at <= KEEP_MS {
                return;
            }
            self.info.remove(&ip);
        }
        if self.queue.contains(&ip) || self.jobs.values().any(|j| j.ip == ip) || self.queue.len() >= 64 {
            return;
        }
        self.queue.push_back(ip);
    }

    fn ask(&mut self, c: &mut Client, poller: &Poller, job: Job, name: &str, qtype: u16, now: u64) {
        self.next += 1;
        let tag = self.tag_base | (self.next & 0xffff_ffff);
        c.query(poller, self.server, name, qtype, tag, TIMEOUT_MS, now);
        self.jobs.insert(tag, job);
    }

    /// Шаг: ответы DNS → следующие запросы; новые выяснения из очереди.
    pub fn tick(&mut self, c: &mut Client, poller: &Poller, now: u64) {
        let (lo, hi) = self.tags();
        for (tag, ans) in c.take(lo, hi) {
            let Some(mut job) = self.jobs.remove(&tag) else { continue };
            let a = ans.unwrap_or_default();
            match job.stage {
                Stage::Ptr => {
                    if let Some(n) = a.names.first() {
                        job.info.ptr = n.trim_end_matches('.').to_string();
                    }
                    job.stage = Stage::Origin;
                    let q = cymru_origin(&job.ip);
                    self.ask(c, poller, job, &q, dns::TYPE_TXT, now);
                }
                Stage::Origin => {
                    // несколько AS («13238 208398») — первая
                    if let Some(t) = a.txt.first() {
                        if let Some(f) = t.split('|').next().and_then(|x| x.split_whitespace().next()) {
                            job.info.asn = f.to_string();
                        }
                    }
                    if job.info.asn.is_empty() {
                        self.finish(job, now);
                    } else if let Some(n) = self.as_name.get(&job.info.asn).cloned() {
                        job.info.brand = asn_brand(&job.info.asn, &n);
                        job.info.as_name = n;
                        self.finish(job, now);
                    } else {
                        job.stage = Stage::Name;
                        let q = format!("AS{}.asn.cymru.com", job.info.asn);
                        self.ask(c, poller, job, &q, dns::TYPE_TXT, now);
                    }
                }
                Stage::Name => {
                    let name = a.txt.first().map(|t| t.split('|').collect::<Vec<_>>()).filter(|f| f.len() >= 5).map(|f| f[4].trim().to_string()).unwrap_or_default();
                    job.info.brand = asn_brand(&job.info.asn, &name);
                    job.info.as_name = name;
                    self.finish(job, now);
                }
            }
        }
        while self.jobs.len() < WORKERS {
            let Some(ip) = self.queue.pop_front() else { break };
            let q = dns::reverse_name(&ip);
            self.ask(c, poller, Job { ip, stage: Stage::Ptr, info: IpInfo::default() }, &q, dns::TYPE_PTR, now);
        }
    }

    fn finish(&mut self, mut job: Job, now: u64) {
        // не выяснили — повторить через 10 мин, а не через 6 ч
        job.info.at = if job.info.asn.is_empty() { now.saturating_sub(KEEP_MS - RETRY_MS) } else { now };
        if self.info.len() > MAX_INFO {
            self.info.clear();
        }
        self.info.retain(|_, v| now - v.at <= KEEP_MS);
        if !job.info.asn.is_empty() && !job.info.as_name.is_empty() {
            self.as_name.insert(job.info.asn.clone(), job.info.as_name.clone());
        }
        self.info.insert(job.ip, job.info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brands() {
        // как asBrand в Go
        assert_eq!(as_brand("TELEGRAM - Telegram Messenger Inc, VG"), "Telegram");
        assert_eq!(as_brand("FLINK-AS, UZ"), "Flink");
        assert_eq!(as_brand("ORACLE-BMC-31898 - Oracle Corporation, US"), "Oracle Corporation");
        assert_eq!(as_brand("SPARKLE - Telecom Italia Sparkle S.p.A., IT"), "Telecom Italia Sparkle S.p.A.");
        assert_eq!(asn_brand("8193", "BRM-AS, UZ"), "Uztelecom");
        assert_eq!(cymru_origin(&"192.0.2.7".parse().unwrap()), "7.2.0.192.origin.asn.cymru.com");
        assert!(cymru_origin(&"2001:db8::1".parse().unwrap()).ends_with(".origin6.asn.cymru.com"));
    }
}
