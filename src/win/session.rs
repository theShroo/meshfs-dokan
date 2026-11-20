// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/dokan.c (DokanCreateFileSystem,
// DokanStart, DokanCloseHandle, DokanNotifyPath), dokan/mount.c,
// dokan/timeout.c and dokan/access.c:
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! One mount: the version handshake, FSCTL_EVENT_START, the volume device,
//! keepalive and notification handles, the pull threads, deferred replies and
//! unmount.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{JoinHandle, ThreadId};

use super::host::Host;
use super::sys::{self, Handle, Open, Win32Error};
use crate::abi::*;
use crate::marshal::dir::{self, Entry, Listing, Query};
use crate::marshal::{filetime_now, info, reply};
use crate::proto::*;
use crate::replier::Repliers;

pub(crate) fn debug_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("MESHFS_DOKAN_DEBUG").is_some())
}

macro_rules! debug {
    ($($t:tt)*) => { if $crate::win::session::debug_enabled() { eprintln!("meshfs-dokan: {}", format!($($t)*)); } }
}
pub(crate) use debug;

/// Mount options, owned.
pub struct Options {
    pub flags: u32,
    pub mount_point: Vec<u16>,
    pub unc_name: Vec<u16>,
    pub irp_timeout_ms: u32,
    pub fcb_gc_interval_ms: u32,
    pub pull_threads: u32,
    pub sector_size: u32,
    pub allocation_unit_size: u32,
    pub volume_security_descriptor: Vec<u8>,
}

/// What a deferred reply needs to be encoded (copied from the request).
#[derive(Debug, Clone)]
pub enum Plan {
    Create { disposition: u32, options: u32, open_target: bool },
    Cleanup,
    Flush,
    SetSecurity,
    Read { offset: i64, length: u32 },
    Write { offset: i64 },
    QueryInfo { class: u32, buffer_length: u32, name: Vec<u16> },
    SetInfo { class: u32, delete: bool, new_name: Vec<u16> },
    Dir(DirPlan),
    Volume { class: u32, buffer_length: u32 },
    QuerySecurity { buffer_length: u32 },
}

#[derive(Debug, Clone)]
pub struct DirPlan {
    pub class: u32,
    pub index: u32,
    pub irp_flags: u32,
    pub buffer_length: u32,
    pub pattern: Option<Vec<u16>>,
    pub is_root: bool,
}

enum State {
    /// The callback is running; a reply now is kept until it returns.
    InCallback,
    /// md_reply arrived while the callback ran (it then returned PENDING).
    Early(Vec<u8>),
    /// The callback returned STATUS_PENDING; md_reply completes it.
    Waiting,
}

struct Pending {
    context: u64,
    plan: Plan,
    state: State,
}

/// A deferred reply, read out of an `MdReply` by the C ABI layer.
pub struct ReplyIn<'a> {
    pub request_id: u64,
    pub status: NtStatus,
    pub bytes: u32,
    pub data: &'a [u8],
    pub create: Option<MdCreateReply>,
    pub file_info: Option<MdFileInfo>,
    pub volume: Option<MdVolumeInfo>,
    pub entries: Vec<Entry>,
}

const SHARDS: usize = 64;

pub struct Instance {
    pub host: Host,
    /// The volume device, overlapped: the pull threads' handle.
    pub device: Handle,
    /// The volume device, synchronous: timeouts and tokens.
    reply_dev: Handle,
    /// Deferred replies go down on these threads, never the caller's
    /// (`crate::replier`).
    repliers: Arc<Repliers<DeviceSink>>,
    global: Handle,
    keepalive: Mutex<Option<Handle>>,
    notify: Mutex<Option<Handle>>,
    pub device_name: String,
    pub mount_point: Vec<u16>,
    pub sector_size: u32,
    pub allocation_unit: u32,
    pub case_sensitive: bool,
    /// MD_MOUNT_NAMED_STREAMS (ABI 1.1): names are split into path and
    /// stream, FileStreamInformation asks the host's find_streams.
    pub named_streams: bool,
    pub irp_timeout_ms: u32,
    pending: Vec<Mutex<HashMap<u32, Pending>>>,
    listings: Mutex<HashMap<u64, Listing>>,
    pub stopping: AtomicBool,
    live_threads: AtomicUsize,
    unmounted_called: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
    pull_ids: Mutex<Vec<ThreadId>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding one of these locks leaves plain data behind;
    // carry on with it rather than poisoning every later request.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// FSCTL_GET_VERSION on the global device; None if the driver is missing.
pub fn driver_version() -> Option<u32> {
    let g = sys::open(DOKAN_GLOBAL_DEVICE_NAME, Open::Sync).ok()?;
    version_of(&g)
}

fn version_of(g: &Handle) -> Option<u32> {
    let mut out = [0u8; 4];
    match sys::ioctl(g, FSCTL_GET_VERSION, &[], &mut out) {
        Ok(4) => Some(u32::from_le_bytes(out)),
        _ => None,
    }
}

fn is_drive_letter(mp: &[u16]) -> bool {
    let colon = b':' as u16;
    let bs = b'\\' as u16;
    match mp.len() {
        1 => true,
        2 => mp[1] == colon,
        3 => mp[1] == colon && mp[2] == bs,
        _ => false,
    }
}

/// GenerateUnmountPoint: "X:" for a drive letter, else the path without a
/// trailing backslash.
fn unmount_point(mp: &[u16]) -> Vec<u16> {
    if is_drive_letter(mp) {
        vec![mp[0], b':' as u16]
    } else {
        let mut v = mp.to_vec();
        if v.last() == Some(&(b'\\' as u16)) {
            v.pop();
        }
        v
    }
}

/// FSCTL_EVENT_RELEASE on the global device with the mount point
/// (dokan2.dll's DokanRemoveMountPoint).
fn release(global: &Handle, mount_point: &[u16]) -> Result<(), Win32Error> {
    const MAX_PATH: usize = 260;
    let up = unmount_point(mount_point);
    let mut b = vec![0u8; ustr::SIZE + MAX_PATH * 2];
    let n = up.len().min(MAX_PATH - 1);
    wr_u16(&mut b, ustr::LENGTH, (n * 2) as u16);
    wr_u16(&mut b, ustr::MAXIMUM_LENGTH, (MAX_PATH * 2) as u16);
    wr_utf16(&mut b, ustr::BUFFER, &up[..n]);
    sys::ioctl(global, FSCTL_EVENT_RELEASE, &b, &mut []).map(|_| ())
}

fn event_start(o: &Options, version: u32) -> Vec<u8> {
    let mut b = vec![0u8; es::SIZE];
    wr_u32(&mut b, es::USER_VERSION, version);
    if o.flags & MD_MOUNT_NETWORK != 0 {
        wr_u32(&mut b, es::DEVICE_TYPE, DOKAN_NETWORK_FILE_SYSTEM);
    }
    let map = [
        (MD_MOUNT_WRITE_PROTECT, DOKAN_EVENT_WRITE_PROTECT),
        (MD_MOUNT_REMOVABLE, DOKAN_EVENT_REMOVABLE),
        (MD_MOUNT_MOUNT_MANAGER, DOKAN_EVENT_MOUNT_MANAGER),
        (MD_MOUNT_CURRENT_SESSION, DOKAN_EVENT_CURRENT_SESSION),
        (MD_MOUNT_ENABLE_NETWORK_UNMOUNT, DOKAN_EVENT_ENABLE_NETWORK_UNMOUNT),
        (MD_MOUNT_CASE_SENSITIVE, DOKAN_EVENT_CASE_SENSITIVE),
        // The driver keeps stream names in the file names it sends
        // (dokan2.dll's DOKAN_OPTION_ALT_STREAM).
        (MD_MOUNT_NAMED_STREAMS, DOKAN_EVENT_ALTERNATIVE_STREAM_ON),
    ];
    let mut flags = 0;
    for (m, d) in map {
        if o.flags & m != 0 {
            flags |= d;
        }
    }
    // No IPC batching: one request per pull and one reply per call. The
    // driver matches a batch of replies against its pending list in one pass
    // and silently drops every reply after one whose IRP was cancelled, which
    // a deferred reply can easily hit (design 4.1.1, note in 3.1).
    wr_u32(&mut b, es::FLAGS, flags);
    wr_utf16(&mut b, es::MOUNT_POINT, &o.mount_point[..o.mount_point.len().min(es::MOUNT_POINT_CHARS - 1)]);
    wr_utf16(&mut b, es::UNC_NAME, &o.unc_name[..o.unc_name.len().min(es::UNC_NAME_CHARS - 1)]);
    wr_u32(&mut b, es::IRP_TIMEOUT, o.irp_timeout_ms);
    wr_u32(&mut b, es::FCB_GC_INTERVAL_MS, if o.fcb_gc_interval_ms == 0 { 2000 } else { o.fcb_gc_interval_ms });
    let sd = &o.volume_security_descriptor;
    wr_u32(&mut b, es::VOLUME_SECURITY_DESCRIPTOR_LENGTH, sd.len() as u32);
    b[es::VOLUME_SECURITY_DESCRIPTOR..es::VOLUME_SECURITY_DESCRIPTOR + sd.len()].copy_from_slice(sd);
    b
}

/// CheckAllocationUnitSectorSize
fn unit_sizes(o: &Options) -> (u32, u32) {
    let ok = |v: u32| (512..=65536).contains(&v) && v.is_power_of_two();
    let s = if o.sector_size == 0 { DOKAN_DEFAULT_SECTOR_SIZE } else { o.sector_size };
    let a = if o.allocation_unit_size == 0 { DOKAN_DEFAULT_ALLOCATION_UNIT_SIZE } else { o.allocation_unit_size };
    if ok(s) && ok(a) { (s, a) } else { (DOKAN_DEFAULT_SECTOR_SIZE, DOKAN_DEFAULT_ALLOCATION_UNIT_SIZE) }
}

pub fn mount(o: Options, host: Host) -> Result<Arc<Instance>, i32> {
    if (o.flags & MD_MOUNT_NAMED_STREAMS != 0 && !host.has_find_streams())
        || o.mount_point.is_empty()
        || o.mount_point.len() >= es::MOUNT_POINT_CHARS
        || o.unc_name.len() >= es::UNC_NAME_CHARS
        || o.volume_security_descriptor.len() > VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE
        || (o.flags & MD_MOUNT_NETWORK != 0 && o.unc_name.is_empty())
    {
        return Err(MD_ERR_ARGS);
    }
    let global = sys::open(DOKAN_GLOBAL_DEVICE_NAME, Open::Sync).map_err(|_| MD_ERR_DRIVER_MISSING)?;
    let version = version_of(&global).ok_or(MD_ERR_DRIVER_MISSING)?;
    if !SUPPORTED_DRIVER_VERSIONS.iter().any(|(v, _)| *v == version) {
        debug!("driver protocol 0x{version:x} is not supported");
        return Err(MD_ERR_DRIVER_VERSION);
    }
    let start = event_start(&o, version);
    let mut di = vec![0u8; edi::SIZE];
    // dokan2.dll ignores this call's result and reads the status instead.
    let _ = sys::ioctl(&global, FSCTL_EVENT_START, &start, &mut di);
    let status = rd_u32(&di, edi::STATUS).unwrap_or(0);
    if status == DOKAN_START_FAILED {
        let dv = rd_u32(&di, edi::DRIVER_VERSION).unwrap_or(0);
        debug!("start failed: driver version 0x{dv:x}, flags 0x{:x}", rd_u32(&di, edi::FLAGS).unwrap_or(0));
        return Err(if dv != version { MD_ERR_DRIVER_VERSION } else { MD_ERR_MOUNT });
    }
    if status != DOKAN_MOUNTED {
        return Err(MD_ERR_MOUNT);
    }
    let name_units = rd_utf16(&di, edi::DEVICE_NAME, edi::DEVICE_NAME_CHARS).unwrap_or_default();
    let end = name_units.iter().position(|&c| c == 0).unwrap_or(name_units.len());
    let device_name = String::from_utf16_lossy(&name_units[..end]);
    let mut mount_point = o.mount_point.clone();
    if is_drive_letter(&mount_point)
        && o.flags & MD_MOUNT_MOUNT_MANAGER != 0
        && let Some(l) = rd_u16(&di, edi::ACTUAL_DRIVE_LETTER).filter(|&l| l != 0)
    {
        mount_point[0] = l;
    }
    let raw = format!(r"\\.{device_name}");
    let opened = sys::open(&raw, Open::Overlapped)
        .and_then(|d| Ok((d, sys::open(&raw, Open::Sync)?, sys::open(&raw, Open::Overlapped)?)));
    let (device, reply_dev, replies_dev) = match opened {
        Ok(p) => p,
        Err(e) => {
            debug!("cannot open {raw}: {e}");
            let _ = release(&global, &mount_point);
            return Err(MD_ERR_START);
        }
    };
    let (sector_size, allocation_unit) = unit_sizes(&o);
    let threads = match o.pull_threads {
        0 => std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(2).clamp(2, 16),
        n => n.clamp(1, 64),
    };
    let inst = Arc::new(Instance {
        host,
        device,
        reply_dev,
        repliers: Repliers::new(DeviceSink(replies_dev)),
        global,
        keepalive: Mutex::new(None),
        notify: Mutex::new(None),
        device_name,
        mount_point,
        sector_size,
        allocation_unit,
        case_sensitive: o.flags & MD_MOUNT_CASE_SENSITIVE != 0,
        named_streams: o.flags & MD_MOUNT_NAMED_STREAMS != 0,
        irp_timeout_ms: o.irp_timeout_ms,
        pending: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        listings: Mutex::new(HashMap::new()),
        stopping: AtomicBool::new(false),
        live_threads: AtomicUsize::new(0),
        unmounted_called: AtomicBool::new(false),
        threads: Mutex::new(Vec::new()),
        pull_ids: Mutex::new(Vec::new()),
    });
    for i in 0..threads {
        let me = inst.clone();
        inst.live_threads.fetch_add(1, Ordering::SeqCst);
        let spawned = std::thread::Builder::new()
            .name(format!("md-pull-{i}"))
            .stack_size(256 * 1024)
            .spawn(move || super::pull::run(me));
        match spawned {
            Ok(h) => {
                lock(&inst.pull_ids).push(h.thread().id());
                lock(&inst.threads).push(h);
            }
            Err(_) => {
                inst.live_threads.fetch_sub(1, Ordering::SeqCst);
                inst.unmounted_called.store(true, Ordering::SeqCst);
                let _ = inst.stop();
                return Err(MD_ERR_START);
            }
        }
    }
    // The keepalive handle: if this process dies, the handle closes and the
    // driver unmounts the volume itself. Not fatal if it fails (dokan2.dll).
    let ka_path = format!(r"\\?{}{}", inst.device_name, DOKAN_KEEPALIVE_FILE_NAME);
    match sys::open(&ka_path, Open::Keepalive) {
        Ok(h) => {
            if let Err(e) = sys::ioctl(&h, FSCTL_ACTIVATE_KEEPALIVE, &[], &mut []) {
                debug!("keepalive activation failed: {e}");
            }
            *lock(&inst.keepalive) = Some(h);
        }
        Err(e) => debug!("cannot open the keepalive file: {e}"),
    }
    let nt_path = format!(r"\\?{}{}", inst.device_name, DOKAN_NOTIFICATION_FILE_NAME);
    match sys::open(&nt_path, Open::Notify) {
        Ok(h) => *lock(&inst.notify) = Some(h),
        Err(e) => debug!("cannot open the notification file: {e}"),
    }
    let dn: Vec<u16> = inst.device_name.encode_utf16().collect();
    inst.host.mounted(&inst.mount_point, &dn);
    Ok(inst)
}

impl Instance {
    pub fn on_pull_thread(&self) -> bool {
        lock(&self.pull_ids).contains(&std::thread::current().id())
    }

    /// Releases the volume (idempotent).
    pub fn request_release(&self) {
        if !self.stopping.swap(true, Ordering::SeqCst)
            && let Err(e) = release(&self.global, &self.mount_point)
        {
            debug!("release failed: {e}");
        }
    }

    /// Unmounts and waits for the pull threads (md_unmount).
    pub fn stop(&self) -> Result<(), i32> {
        if self.on_pull_thread() {
            return Err(MD_ERR_THREAD);
        }
        self.request_release();
        let threads: Vec<_> = lock(&self.threads).drain(..).collect();
        for t in threads {
            let _ = t.join();
        }
        lock(&self.keepalive).take();
        lock(&self.notify).take();
        self.repliers.stop();
        for s in &self.pending {
            lock(s).clear();
        }
        lock(&self.listings).clear();
        self.notify_unmounted();
        Ok(())
    }

    pub fn notify_unmounted(&self) {
        if !self.unmounted_called.swap(true, Ordering::SeqCst) {
            self.host.unmounted();
        }
    }

    /// Called by each pull thread as it exits.
    pub fn pull_thread_exited(&self) {
        if self.live_threads.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify_unmounted();
        }
    }

    // ---- deferred replies -------------------------------------------------

    fn shard(&self, serial: u32) -> &Mutex<HashMap<u32, Pending>> {
        &self.pending[serial as usize % SHARDS]
    }

    /// Registers a request before its callback runs, so md_reply can arrive
    /// from another thread at any time.
    pub fn begin_pending(&self, serial: u32, context: u64, plan: Plan) {
        lock(self.shard(serial)).insert(serial, Pending { context, plan, state: State::InCallback });
    }

    /// After the callback: true if it went pending (an early reply, if any,
    /// is sent now); false if it answered (the registration is dropped).
    pub fn end_pending(&self, serial: u32, status: NtStatus) -> bool {
        let mut g = lock(self.shard(serial));
        if status != STATUS_PENDING {
            if let Some(Pending { state: State::Early(_), .. }) = g.remove(&serial) {
                debug!("request {serial}: md_reply and a callback result; the callback's wins");
            }
            return false;
        }
        let is_early = matches!(g.get(&serial), Some(Pending { state: State::Early(_), .. }));
        let early = if is_early {
            match g.remove(&serial) {
                Some(Pending { state: State::Early(bytes), .. }) => Some(bytes),
                _ => None,
            }
        } else {
            if let Some(p) = g.get_mut(&serial) {
                p.state = State::Waiting;
            }
            None
        };
        drop(g);
        if let Some(bytes) = early {
            self.send_reply(bytes);
        }
        true
    }

    /// A reply on its own (not riding on a pull). It is handed to a replier
    /// thread and this returns at once: see `crate::replier`.
    pub fn send_reply(&self, bytes: Vec<u8>) {
        self.repliers.send(bytes);
    }

    /// md_reply for one request. Err: unknown or already answered.
    #[allow(clippy::result_unit_err)]
    pub fn reply(&self, r: &ReplyIn) -> Result<(), ()> {
        let serial = r.request_id as u32;
        if r.request_id > u32::MAX as u64 || r.status == STATUS_PENDING {
            return Err(());
        }
        let mut g = lock(self.shard(serial));
        let Some(p) = g.get_mut(&serial) else { return Err(()) };
        match p.state {
            State::Early(_) => Err(()),
            State::InCallback => {
                let bytes = self.encode_deferred(serial, p.context, &p.plan, r);
                p.state = State::Early(bytes);
                Ok(())
            }
            State::Waiting => {
                let p = g.remove(&serial).ok_or(())?;
                drop(g);
                let bytes = self.encode_deferred(serial, p.context, &p.plan, r);
                self.send_reply(bytes);
                Ok(())
            }
        }
    }

    fn encode_deferred(&self, serial: u32, context: u64, plan: &Plan, r: &ReplyIn) -> Vec<u8> {
        let mut b = vec![0u8; ei::SIZE];
        let n = match plan {
            Plan::Create { disposition, options, open_target } => reply::create(
                &mut b,
                serial,
                *disposition,
                *options,
                *open_target,
                r.status,
                &r.create.unwrap_or_default(),
            ),
            Plan::Cleanup => reply::status_only(&mut b, serial, context, STATUS_SUCCESS),
            Plan::Flush => reply::status_only(&mut b, serial, context, flush_status(r.status)),
            Plan::SetSecurity => reply::status_only(&mut b, serial, context, r.status),
            Plan::Read { offset, length } => {
                let n = r.data.len().min(*length as usize);
                b.resize(ei::BUFFER + n.max(8), 0);
                b[ei::BUFFER..ei::BUFFER + n].copy_from_slice(&r.data[..n]);
                let bytes = if r.data.len() > *length as usize { r.data.len() as u32 } else { n as u32 };
                reply::read(&mut b, serial, context, *offset, *length, r.status, bytes)
            }
            Plan::Write { offset } => reply::write(&mut b, serial, context, *offset, r.status, r.bytes),
            Plan::QueryInfo { class, buffer_length, name } => {
                b.resize(ei::BUFFER + (*buffer_length as usize).max(8), 0);
                let (st, fi) = match (r.status, r.file_info) {
                    (STATUS_SUCCESS, None) => (STATUS_INTERNAL_ERROR, MdFileInfo::default()),
                    (s, fi) => (s, fi.unwrap_or_default()),
                };
                info::query_info(&mut b, serial, context, *class, *buffer_length, name, st, &fi, self.allocation_unit)
            }
            Plan::SetInfo { class, delete, new_name } => {
                b.resize(ei::BUFFER + (new_name.len() * 2).max(8), 0);
                reply::set_info(&mut b, serial, context, *class, *delete, new_name, r.status)
            }
            Plan::Dir(d) => {
                let st = r.status;
                self.complete_dir(&mut b, serial, context, d, st, r.entries.clone())
            }
            Plan::Volume { class, buffer_length } => {
                b.resize(ei::BUFFER + (*buffer_length as usize).max(8), 0);
                let (st, v) = match r.status {
                    STATUS_NOT_IMPLEMENTED => (STATUS_SUCCESS, info::default_volume()),
                    STATUS_SUCCESS if r.volume.is_none() => (STATUS_INTERNAL_ERROR, MdVolumeInfo::default()),
                    s => (s, r.volume.unwrap_or_default()),
                };
                info::query_volume(
                    &mut b,
                    serial,
                    context,
                    *class,
                    *buffer_length,
                    st,
                    &v,
                    self.sector_size,
                    self.allocation_unit,
                )
            }
            Plan::QuerySecurity { buffer_length } => {
                let cap = *buffer_length as usize;
                b.resize(ei::BUFFER + cap.max(8), 0);
                let n = r.data.len().min(cap);
                b[ei::BUFFER..ei::BUFFER + n].copy_from_slice(&r.data[..n]);
                let needed = if r.bytes != 0 { r.bytes } else { r.data.len() as u32 };
                reply::query_security(&mut b, serial, context, *buffer_length, r.status, needed)
            }
        };
        b.truncate(n);
        b
    }

    // ---- directory listings -----------------------------------------------

    /// Encodes from the listing kept for this open if the query may resume
    /// from it; None if the host must list again.
    pub fn dir_from_kept(&self, r: &mut [u8], serial: u32, context: u64, d: &DirPlan) -> Option<usize> {
        if context == 0 {
            return None;
        }
        let g = lock(&self.listings);
        let kept = g.get(&context);
        if dir::force_scan(kept, d.pattern.as_deref(), d.irp_flags) {
            return None;
        }
        let q = self.query(d);
        Some(dir::write_results(r, serial, context, &q, &kept?.entries))
    }

    fn query<'a>(&self, d: &'a DirPlan) -> Query<'a> {
        Query {
            class: d.class,
            index: d.index,
            irp_flags: d.irp_flags,
            buffer_length: d.buffer_length,
            pattern: d.pattern.as_deref(),
            case_sensitive: self.case_sensitive,
            allocation_unit: self.allocation_unit,
        }
    }

    /// EndFindFilesCommon: encodes a fresh listing and keeps it for the open.
    pub fn complete_dir(
        &self,
        r: &mut Vec<u8>,
        serial: u32,
        context: u64,
        d: &DirPlan,
        status: NtStatus,
        mut entries: Vec<Entry>,
    ) -> usize {
        let need = ei::BUFFER + (d.buffer_length as usize).max(8);
        if r.len() < need {
            r.resize(need, 0);
        }
        if status != STATUS_SUCCESS {
            let st = if status == STATUS_PENDING { STATUS_INTERNAL_ERROR } else { status };
            return reply::status_only(r, serial, context, st);
        }
        dir::add_dots(&mut entries, d.is_root, d.pattern.as_deref(), filetime_now());
        let n = dir::write_results(r, serial, context, &self.query(d), &entries);
        if context != 0 {
            lock(&self.listings).insert(context, Listing { entries, pattern: d.pattern.clone() });
        }
        n
    }

    pub fn forget_listing(&self, context: u64) {
        if context != 0 {
            lock(&self.listings).remove(&context);
        }
    }

    // ---- other driver calls -----------------------------------------------

    /// FSCTL_GET_ACCESS_TOKEN for a pending create.
    pub fn requester_token(&self, request_id: u64) -> Option<isize> {
        let mut b = vec![0u8; ei::SIZE];
        wr_u32(&mut b, ei::SERIAL_NUMBER, request_id as u32);
        let mut out = vec![0u8; ei::SIZE];
        out.copy_from_slice(&b);
        match sys::ioctl(&self.reply_dev, FSCTL_GET_ACCESS_TOKEN, &b, &mut out) {
            Ok(_) => rd_u64(&out, ei::ACCESS_TOKEN_HANDLE).map(|h| h as isize).filter(|&h| h != 0),
            Err(e) => {
                debug!("access token for {request_id}: {e}");
                None
            }
        }
    }

    /// FSCTL_RESET_TIMEOUT (DokanResetTimeout).
    pub fn reset_timeout(&self, request_id: u64, timeout_ms: u32) -> Result<(), Win32Error> {
        let mut b = vec![0u8; ei::SIZE];
        wr_u32(&mut b, ei::SERIAL_NUMBER, request_id as u32);
        let t = if timeout_ms == 0 { self.irp_timeout_ms.max(15_000) } else { timeout_ms };
        wr_u32(&mut b, ei::RESET_TIMEOUT, t);
        sys::ioctl(&self.reply_dev, FSCTL_RESET_TIMEOUT, &b, &mut []).map(|_| ())
    }

    /// FSCTL_NOTIFY_PATH (DokanNotifyPath); `path` is relative to the volume.
    pub fn notify_path(&self, path: &[u16], filter: u32, action: u32) -> Result<(), Win32Error> {
        let g = lock(&self.notify);
        let h = g.as_ref().ok_or(windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
        let mut b = vec![0u8; notify::SIZE + path.len() * 2];
        wr_u32(&mut b, notify::COMPLETION_FILTER, filter);
        wr_u32(&mut b, notify::ACTION, action);
        wr_u16(&mut b, notify::LENGTH, (path.len() * 2).min(u16::MAX as usize) as u16);
        wr_utf16(&mut b, notify::BUFFER, path);
        sys::ioctl(h, FSCTL_NOTIFY_PATH, &b, &mut []).map(|_| ())
    }
}

/// dokan2.dll: a flush the host does not implement succeeds. Other statuses
/// are passed on (dokan2.dll turns every failure into STATUS_NOT_SUPPORTED;
/// for MeshFS a flush is a commit and its real failure matters).
pub fn flush_status(s: NtStatus) -> NtStatus {
    if s == STATUS_NOT_IMPLEMENTED { STATUS_SUCCESS } else { s }
}

/// What the replier threads send with: the overlapped volume handle and a
/// manual-reset event per thread.
pub struct DeviceSink(Handle);

impl crate::replier::Sink for DeviceSink {
    type Local = Result<sys::Event, Win32Error>;

    fn local(&self) -> Self::Local {
        sys::Event::new()
    }

    fn send(&self, ev: &mut Self::Local, bytes: &[u8]) {
        let sent = match ev {
            Ok(ev) => sys::ioctl_overlapped(&self.0, ev, FSCTL_EVENT_PROCESS_N_PULL, bytes, &mut []),
            Err(e) => Err(*e),
        };
        if let Err(e) = sent {
            debug!("reply failed: {e}");
        }
    }

    fn cancel(&self) {
        sys::cancel_all(&self.0);
    }
}
