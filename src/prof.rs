//! Профиль по компонентам (сборка с `--features prof`, не для выпуска):
//! время CPU (своё, без вложенных областей; плюс CPU дочерних процессов —
//! nft, tc, ubus, curl…) и живая память кучи (выделено − освобождено) по
//! области, в которой блок был выделен. Без feature — пустые заглушки.
//! Команда `cgmon prof` (сокет) — таблица с момента запуска.

#[cfg(feature = "prof")]
mod imp {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

    pub const N: usize = 96;
    static NAMES: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
    static LIVE: [AtomicI64; N] = [const { AtomicI64::new(0) }; N];
    static PEAK: [AtomicI64; N] = [const { AtomicI64::new(0) }; N];
    static ALLOCS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
    static CPU_NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
    static CHILD_NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
    static CALLS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

    thread_local! {
        // 0 — рабочие потоки (своя область не задана), 1 — основной поток вне областей
        static CUR: Cell<u8> = const { Cell::new(0) };
        static STACK: RefCell<Vec<(u8, u64)>> = const { RefCell::new(Vec::new()) };
        static MARK: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
    }

    const H: usize = 16;

    pub struct Alloc;
    unsafe impl GlobalAlloc for Alloc {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let a = l.align().max(H);
            let h = a.max(H);
            let Ok(real) = Layout::from_size_align(l.size() + h, a) else { return std::ptr::null_mut() };
            let p = System.alloc(real);
            if p.is_null() {
                return p;
            }
            let s = CUR.try_with(|c| c.get()).unwrap_or(0) as usize;
            let q = p.add(h);
            (q.sub(H) as *mut u64).write(s as u64);
            let v = LIVE[s].fetch_add(l.size() as i64, Relaxed) + l.size() as i64;
            if v > PEAK[s].load(Relaxed) {
                PEAK[s].store(v, Relaxed);
            }
            ALLOCS[s].fetch_add(1, Relaxed);
            q
        }
        unsafe fn dealloc(&self, q: *mut u8, l: Layout) {
            let a = l.align().max(H);
            let h = a.max(H);
            let s = (q.sub(H) as *const u64).read() as usize % N;
            LIVE[s].fetch_sub(l.size() as i64, Relaxed);
            System.dealloc(q.sub(h), Layout::from_size_align_unchecked(l.size() + h, a));
        }
    }

    fn thread_ns() -> u64 {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    }
    fn child_ns() -> u64 {
        let mut r: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut r) };
        let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1000;
        tv(r.ru_utime) + tv(r.ru_stime)
    }

    fn id(name: &'static str) -> u8 {
        let mut n = NAMES.lock().unwrap_or_else(|e| e.into_inner());
        if n.is_empty() {
            n.push("workers (потоки)");
            n.push("loop (вне областей)");
        }
        if let Some(i) = n.iter().position(|x| *x == name) {
            return i as u8;
        }
        if n.len() >= N {
            return 1;
        }
        n.push(name);
        (n.len() - 1) as u8
    }

    /// Начислить время с последней отметки текущей области.
    fn charge() {
        let (t, c) = (thread_ns(), child_ns());
        let (t0, c0) = MARK.with(|m| m.get());
        let cur = CUR.with(|x| x.get()) as usize;
        if t0 != 0 {
            CPU_NS[cur].fetch_add(t.saturating_sub(t0), Relaxed);
            CHILD_NS[cur].fetch_add(c.saturating_sub(c0), Relaxed);
        }
        MARK.with(|m| m.set((t, c)));
    }

    pub fn main_thread() {
        id("");
        CUR.with(|c| c.set(1));
        charge();
    }

    pub struct Guard(bool);
    pub fn scope(name: &'static str) -> Guard {
        if CUR.with(|c| c.get()) == 0 {
            return Guard(false); // рабочий поток — не размечаем
        }
        let i = id(name);
        charge();
        let prev = CUR.with(|c| c.replace(i));
        STACK.with(|s| s.borrow_mut().push((prev, 0)));
        CALLS[i as usize].fetch_add(1, Relaxed);
        Guard(true)
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.0 {
                return;
            }
            charge();
            if let Some((prev, _)) = STACK.with(|s| s.borrow_mut().pop()) {
                CUR.with(|c| c.set(prev));
            }
        }
    }

    pub fn report() -> String {
        charge();
        let names = NAMES.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut j = crate::json::J::new();
        j.arr();
        for (i, n) in names.iter().enumerate() {
            j.obj().key("name").str(n).key("cpu_ms").int((CPU_NS[i].load(Relaxed) / 1_000_000) as i64).key("child_ms").int((CHILD_NS[i].load(Relaxed) / 1_000_000) as i64)
                .key("calls").int(CALLS[i].load(Relaxed) as i64).key("live").int(LIVE[i].load(Relaxed)).key("peak").int(PEAK[i].load(Relaxed)).key("allocs").int(ALLOCS[i].load(Relaxed) as i64).end_obj();
        }
        j.end_arr();
        j.b
    }
}

#[cfg(feature = "prof")]
pub use imp::*;

#[cfg(not(feature = "prof"))]
pub struct Guard;
#[cfg(not(feature = "prof"))]
#[inline(always)]
pub fn scope(_: &'static str) -> Guard {
    Guard
}
#[cfg(not(feature = "prof"))]
pub fn main_thread() {}
#[cfg(not(feature = "prof"))]
pub fn report() -> String {
    "{\"error\":\"сборка без --features prof\"}".into()
}
