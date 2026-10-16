//! Один поток, один epoll: сокеты регистрируются с токеном, ожидание с
//! таймаутом до ближайшего таймера. Без tokio и без потоков на задачу.

use std::io;

pub struct Poller {
    ep: i32,
    evs: Vec<libc::epoll_event>,
}

impl Poller {
    pub fn new() -> io::Result<Self> {
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Poller { ep, evs: vec![libc::epoll_event { events: 0, u64: 0 }; 64] })
    }

    fn ctl(&self, op: i32, fd: i32, events: u32, token: u64) -> io::Result<()> {
        let mut ev = libc::epoll_event { events, u64: token };
        if unsafe { libc::epoll_ctl(self.ep, op, fd, &mut ev) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn add(&self, fd: i32, events: u32, token: u64) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_ADD, fd, events, token)
    }

    pub fn del(&self, fd: i32) {
        let _ = self.ctl(libc::EPOLL_CTL_DEL, fd, 0, 0);
    }

    /// Ждать до timeout_ms; готовые (токен, события) → f.
    pub fn wait(&mut self, timeout_ms: i32, mut f: impl FnMut(u64, u32)) -> io::Result<()> {
        let n = unsafe { libc::epoll_wait(self.ep, self.evs.as_mut_ptr(), self.evs.len() as i32, timeout_ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                return Ok(());
            }
            return Err(e);
        }
        for i in 0..n as usize {
            let ev = self.evs[i];
            f(ev.u64, ev.events);
        }
        Ok(())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        unsafe { libc::close(self.ep) };
    }
}

/// Монотонное время в миллисекундах.
pub fn now_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

/// Unix-время в секундах.
pub fn unix_now() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}

/// Периодическая задача: срабатывает каждые every_ms.
pub struct Every {
    pub every_ms: u64,
    next: u64,
}

impl Every {
    pub fn new(every_ms: u64, start: u64) -> Self {
        Every { every_ms, next: start }
    }
    pub fn due(&mut self, now: u64) -> bool {
        if now >= self.next {
            self.next = now + self.every_ms;
            return true;
        }
        false
    }
    pub fn left(&self, now: u64) -> u64 {
        self.next.saturating_sub(now)
    }
}
