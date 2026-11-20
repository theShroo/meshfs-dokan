// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Write-path counters for benchmarks, off unless MESHFS_DOKAN_WRITE_STATS
//! names a file: then each cleanup that follows writes appends one line of
//! counters (since the previous line) to it and resets them. The counters:
//! the requests by path (inline in the event, or a stub fetched with
//! FSCTL_EVENT_WRITE), by size, the time in the host's callback, in the
//! FSCTL_EVENT_WRITE call and in the whole request (event decoded to reply
//! ready), and the paging / non-cached flags the driver set.

use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

static FILE: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();

pub fn enabled() -> bool {
    FILE.get_or_init(|| std::env::var_os("MESHFS_DOKAN_WRITE_STATS").map(Into::into)).is_some()
}

/// Upper bounds of the size buckets (the last is everything above).
const BUCKETS: [u64; 6] = [4 << 10, 32 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20];
const NB: usize = BUCKETS.len() + 1;

#[derive(Default)]
struct Counters {
    inline_n: AtomicU64,
    inline_bytes: AtomicU64,
    inline_ns: AtomicU64,
    large_n: AtomicU64,
    large_bytes: AtomicU64,
    large_ns: AtomicU64,
    fetch_ns: AtomicU64,
    fetch_max_ns: AtomicU64,
    host_inline_ns: AtomicU64,
    host_large_ns: AtomicU64,
    paging: AtomicU64,
    nocache: AtomicU64,
    sizes: [AtomicU64; NB],
}

static C: OnceLock<Counters> = OnceLock::new();

fn c() -> &'static Counters {
    C.get_or_init(Counters::default)
}

/// One write request, timed from its event to its reply.
pub struct Timer {
    t0: Instant,
}

pub fn start() -> Option<Timer> {
    enabled().then(|| Timer { t0: Instant::now() })
}

pub fn host_ns(large: bool, ns: u64) {
    let c = c();
    if large { &c.host_large_ns } else { &c.host_inline_ns }.fetch_add(ns, Relaxed);
}

pub fn fetch_ns(ns: u64) {
    let c = c();
    c.fetch_ns.fetch_add(ns, Relaxed);
    c.fetch_max_ns.fetch_max(ns, Relaxed);
}

impl Timer {
    pub fn done(self, large: bool, bytes: u64, file_flags: u32) {
        let ns = self.t0.elapsed().as_nanos() as u64;
        let c = c();
        let (n, b, t) = if large {
            (&c.large_n, &c.large_bytes, &c.large_ns)
        } else {
            (&c.inline_n, &c.inline_bytes, &c.inline_ns)
        };
        n.fetch_add(1, Relaxed);
        b.fetch_add(bytes, Relaxed);
        t.fetch_add(ns, Relaxed);
        let i = BUCKETS.iter().position(|&u| bytes <= u).unwrap_or(BUCKETS.len());
        c.sizes[i].fetch_add(1, Relaxed);
        if file_flags & crate::proto::DOKAN_PAGING_IO != 0 {
            c.paging.fetch_add(1, Relaxed);
        }
        if file_flags & crate::proto::DOKAN_NOCACHE != 0 {
            c.nocache.fetch_add(1, Relaxed);
        }
    }
}

/// Appends the counters since the last line and resets them (at a cleanup).
pub fn flush() {
    let Some(Some(path)) = FILE.get() else { return };
    let c = c();
    if c.inline_n.load(Relaxed) == 0 && c.large_n.load(Relaxed) == 0 {
        return;
    }
    let take = |a: &AtomicU64| a.swap(0, Relaxed);
    let us = |ns: u64, n: u64| if n == 0 { 0.0 } else { ns as f64 / n as f64 / 1000.0 };
    let (inn, inb, ins) = (take(&c.inline_n), take(&c.inline_bytes), take(&c.inline_ns));
    let (ln, lb, lns) = (take(&c.large_n), take(&c.large_bytes), take(&c.large_ns));
    let (fns, fmax) = (take(&c.fetch_ns), take(&c.fetch_max_ns));
    let (hin, hln) = (take(&c.host_inline_ns), take(&c.host_large_ns));
    let sizes: Vec<String> = c.sizes.iter().map(|a| take(a).to_string()).collect();
    let line = format!(
        "wstats inline n={inn} bytes={inb} us/req={:.2} host_us/req={:.2} | large n={ln} bytes={lb} us/req={:.2} \
         fetch_us/req={:.2} fetch_max_us={:.0} host_us/req={:.2} | paging={} nocache={} | \
         sizes(<=4k,32k,64k,256k,1m,4m,more)={}\n",
        us(ins, inn),
        us(hin, inn),
        us(lns, ln),
        us(fns, ln),
        fmax as f64 / 1000.0,
        us(hln, ln),
        take(&c.paging),
        take(&c.nocache),
        sizes.join(","),
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}
