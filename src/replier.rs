// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! THE REPLY NEVER RUNS ON THE CALLER'S THREAD (20 Nov 2026).
//!
//! A deferred reply is a DeviceIoControl, and the driver completes the IRP it
//! answers INSIDE that call, on the calling thread: a cleanup's completion
//! takes the file's FCB lock exclusively and checks its oplocks
//! (DokanExecuteCleanup), and either can wait on another IRP of the same file
//! that is itself waiting for the file system's answer. md_reply ran the call
//! on the host's answering thread — the trio loop — so that answer could
//! never come: the Windows VM's delete step froze the whole client for 93 s,
//! until the driver's IRP timeout (90 s) cancelled what the cleanup waited
//! behind.
//!
//! So md_reply encodes the reply (the caller's buffers are read before it
//! returns, as before) and queues it here; these threads send it, on an
//! OVERLAPPED handle of their own — on a synchronous handle the I/O manager
//! runs one call at a time, and a reply held in the driver held every other
//! reply (and the timeout resets and token reads on that handle) behind it.
//! A reply the driver holds holds only its own thread: a queued reply always
//! has a waiting thread of its own, started if need be (up to
//! [`MAX_REPLIERS`]), so the answer the held one waits for still goes down.
//!
//! Order: each reply answers its own IRP, matched by serial number; the
//! driver never depended on the order they arrive in (the host answers
//! requests concurrently).

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// Most replier threads at once. Each busy one is a reply the driver is
/// holding; this many at once is a driver that has stopped, not a busy one.
pub const MAX_REPLIERS: usize = 64;
/// Threads kept waiting with nothing to send; the rest end after
/// [`REPLIER_IDLE`] without work.
pub const MIN_REPLIERS: usize = 2;
pub const REPLIER_IDLE: Duration = Duration::from_secs(30);

/// Where the replies go: the driver on Windows, a test's channel elsewhere.
pub trait Sink: Send + Sync + 'static {
    /// Per-thread state (the overlapped call's event).
    type Local;
    fn local(&self) -> Self::Local;
    /// Send one reply; may wait as long as the driver holds it.
    fn send(&self, local: &mut Self::Local, bytes: &[u8]);
    /// At unmount: give up every send still in flight that can be given up
    /// (an overlapped call the driver left pending).
    fn cancel(&self) {}
}

pub struct Repliers<S: Sink> {
    sink: S,
    state: Mutex<State>,
    work: Condvar,
}

#[derive(Default)]
struct State {
    jobs: VecDeque<Vec<u8>>,
    /// Threads waiting for a job.
    idle: usize,
    threads: usize,
    stopping: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl<S: Sink> Repliers<S> {
    pub fn new(sink: S) -> Arc<Self> {
        Arc::new(Repliers { sink, state: Mutex::new(State::default()), work: Condvar::new() })
    }

    /// Queue one reply. Never waits on the sink.
    pub fn send(self: &Arc<Self>, bytes: Vec<u8>) {
        let mut g = lock(&self.state);
        if g.stopping {
            return;
        }
        g.jobs.push_back(bytes);
        // Every queued reply needs a waiting thread of its own: a busy
        // thread may be one the driver holds, and a reply queued behind it
        // would be held with it.
        if g.idle >= g.jobs.len() || g.threads >= MAX_REPLIERS {
            drop(g);
            self.work.notify_one();
            return;
        }
        g.threads += 1;
        drop(g);
        let me = self.clone();
        let spawned =
            std::thread::Builder::new().name("md-reply".into()).stack_size(128 * 1024).spawn(move || me.run());
        if spawned.is_err() {
            lock(&self.state).threads -= 1;
            self.work.notify_one();
        }
    }

    fn run(&self) {
        let mut local = self.sink.local();
        loop {
            let job = {
                let mut g = lock(&self.state);
                loop {
                    if let Some(j) = g.jobs.pop_front() {
                        break j;
                    }
                    if g.stopping {
                        g.threads -= 1;
                        return;
                    }
                    g.idle += 1;
                    let (ng, t) = self.work.wait_timeout(g, REPLIER_IDLE).unwrap_or_else(|e| e.into_inner());
                    g = ng;
                    g.idle -= 1;
                    if t.timed_out() && g.jobs.is_empty() && g.threads > MIN_REPLIERS {
                        g.threads -= 1;
                        return;
                    }
                }
            };
            self.sink.send(&mut local, &job);
        }
    }

    /// At unmount: no more replies (the volume is released; what is still
    /// queued answers nothing), the waiting threads end at once, and the
    /// sends in flight are cancelled where the sink can. Nothing here waits
    /// for a thread: one the driver still holds ends when the driver lets
    /// go, and holds nothing the unmount needs.
    pub fn stop(&self) {
        let mut g = lock(&self.state);
        g.stopping = true;
        g.jobs.clear();
        drop(g);
        self.work.notify_all();
        self.sink.cancel();
    }

    /// (threads, idle) — for the tests.
    pub fn counts(&self) -> (usize, usize) {
        let g = lock(&self.state);
        (g.threads, g.idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    /// Replies whose first byte is 1 are held (as the driver held the
    /// cleanup's) until `release` is sent; the rest go straight through.
    struct Driver {
        sent: Mutex<mpsc::Sender<Vec<u8>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Sink for Driver {
        type Local = ();
        fn local(&self) {}
        fn send(&self, _: &mut (), bytes: &[u8]) {
            if bytes[0] == 1 {
                let _ = lock(&self.release).recv_timeout(Duration::from_secs(10));
            }
            let _ = lock(&self.sent).send(bytes.to_vec());
        }
    }

    fn driver() -> (Arc<Repliers<Driver>>, mpsc::Receiver<Vec<u8>>, mpsc::Sender<()>) {
        let (tx, rx) = mpsc::channel();
        let (rel_tx, rel_rx) = mpsc::channel();
        let r = Repliers::new(Driver { sent: Mutex::new(tx), release: Mutex::new(rel_rx) });
        (r, rx, rel_tx)
    }

    #[test]
    fn a_reply_the_driver_holds_does_not_hold_the_caller() {
        let (r, sent, release) = driver();
        let t = Instant::now();
        r.send(vec![1, 0]); // the cleanup's reply: held in the driver
        assert!(t.elapsed() < Duration::from_secs(1), "send waited on the driver");
        release.send(()).unwrap();
        assert_eq!(sent.recv_timeout(Duration::from_secs(5)).unwrap(), vec![1, 0]);
        r.stop();
    }

    #[test]
    fn a_reply_queued_behind_a_held_one_still_goes_down() {
        // The deadlock: the held reply waits for an IRP whose answer is the
        // next reply. It must go down while the first is held.
        let (r, sent, release) = driver();
        r.send(vec![1, 0]);
        r.send(vec![2, 0]);
        assert_eq!(
            sent.recv_timeout(Duration::from_secs(5)).expect("the second reply waited behind the held one"),
            vec![2, 0]
        );
        release.send(()).unwrap();
        assert_eq!(sent.recv_timeout(Duration::from_secs(5)).unwrap(), vec![1, 0]);
        r.stop();
    }

    #[test]
    fn many_held_replies_each_get_a_thread_and_the_rest_flow() {
        let (r, sent, release) = driver();
        for i in 0..10u8 {
            r.send(vec![1, i]);
        }
        for i in 0..50u8 {
            r.send(vec![2, i]);
        }
        let mut got: Vec<Vec<u8>> = (0..50).map(|_| sent.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
        got.sort();
        assert_eq!(got, (0..50u8).map(|i| vec![2, i]).collect::<Vec<_>>());
        for _ in 0..10 {
            release.send(()).unwrap();
        }
        for _ in 0..10 {
            assert_eq!(sent.recv_timeout(Duration::from_secs(5)).unwrap()[0], 1);
        }
        assert!(r.counts().0 <= MAX_REPLIERS);
        r.stop();
    }

    #[test]
    fn idle_threads_are_reused_not_multiplied() {
        let (r, sent, _release) = driver();
        for i in 0..200u8 {
            r.send(vec![2, i]);
            sent.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        // One at a time: a waiting thread takes each; a few may start while
        // a thread is between jobs, never one per reply.
        assert!(r.counts().0 <= 4, "{:?} threads for one reply at a time", r.counts());
        r.stop();
    }

    #[test]
    fn stop_never_waits_on_a_held_reply_and_lets_idle_threads_go() {
        let (r, sent, release) = driver();
        r.send(vec![2, 0]);
        sent.recv_timeout(Duration::from_secs(5)).unwrap();
        r.send(vec![1, 0]); // held in the driver at unmount
        std::thread::sleep(Duration::from_millis(100));
        let t = Instant::now();
        r.stop();
        assert!(t.elapsed() < Duration::from_millis(500), "stop waited on the held reply");
        // The idle thread ends at once; the held one when the driver lets go.
        let deadline = Instant::now() + Duration::from_secs(5);
        while r.counts().0 > 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(r.counts().0, 1, "an idle replier outlived the unmount");
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while r.counts().0 > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(r.counts().0, 0, "the held replier did not end once let go");
    }

    #[test]
    fn after_stop_nothing_is_sent() {
        let (r, sent, _release) = driver();
        r.stop();
        r.send(vec![2, 0]);
        assert!(sent.recv_timeout(Duration::from_millis(200)).is_err());
    }
}
