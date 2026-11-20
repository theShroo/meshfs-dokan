// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/dokan.c (DispatchDedicatedIoCallback,
// SendAndPullEventInformation, DispatchEvent) and the dispatch files create.c,
// cleanup.c, close.c, read.c, write.c, fileinfo.c, setfile.c, directory.c,
// volume.c, security.c, flush.c, lock.c:
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! The pull threads: send the last reply and pull the next request in one
//! FSCTL_EVENT_PROCESS_N_PULL, decode it, call the host, encode the reply.
//! A request the host leaves pending is answered later by md_reply.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::session::{DirPlan, Instance, Plan, debug, flush_status};
use super::sys::{self, Event};
use super::wstats;
use crate::abi::*;
use crate::marshal::{self, Event as Ev, Header, Op, Str, info, reply};
use crate::proto::*;

/// The reply buffer kept per thread: a pre-touched header plus a data area
/// sized to the largest request seen, up to this; above it, a buffer is
/// grown for the one request and shrunk back afterwards.
const RETAIN: usize = 16 << 20;
const INITIAL: usize = ei::BUFFER + (128 << 10);

/// Grows `v` to `n` bytes, touching every new page now so no read pays for
/// page faults on its reply (dokan2.dll mallocs a fresh buffer per read
/// above 128 KiB).
fn ensure(v: &mut Vec<u8>, n: usize) {
    if v.len() < n {
        let old = v.len();
        v.resize(n, 0);
        let mut i = old;
        while i < n {
            v[i] = 0xA5;
            i += 4096;
        }
        std::hint::black_box(&v[..]);
    }
}

pub fn run(inst: Arc<Instance>) {
    let ev = match Event::new() {
        Ok(e) => e,
        Err(e) => {
            debug!("CreateEvent: {e}");
            inst.request_release();
            inst.pull_thread_exited();
            return;
        }
    };
    // The pull's output buffer is METHOD_BUFFERED: the I/O manager allocates
    // (and clears) a system buffer of max(input, output) bytes on every
    // pull, so its size is paid per request (~8 us at 128 KiB against 32
    // KiB on the test machine). Every event fits in PULL_SMALL but a large-write
    // stub for a very long path; the driver leaves an event that does not
    // fit queued and the pull returns empty, so after an empty pull the
    // thread pulls once with the full PULL_BUFFER_SIZE.
    let mut pull = vec![0u8; PULL_SMALL];
    let mut pull_big: Vec<u8> = Vec::new();
    let mut use_big = false;
    let mut reply_buf = Vec::new();
    ensure(&mut reply_buf, INITIAL);
    let mut wbuf: Vec<u8> = Vec::new();
    let mut reply_len = 0usize;
    loop {
        // The reply rides on the next pull (one call; the thread is waiting
        // again as soon as the IRP completes). Replying first with a separate
        // call measured slower: 28.5 against 19.6 us per 4 KiB write.
        let input = &reply_buf[..reply_len];
        if use_big && pull_big.is_empty() {
            pull_big = vec![0u8; PULL_BUFFER_SIZE];
        }
        let out = if use_big { &mut pull_big } else { &mut pull };
        let n = match sys::ioctl_overlapped(&inst.device, &ev, FSCTL_EVENT_PROCESS_N_PULL, input, out) {
            Ok(n) => n,
            Err(e) => {
                if !inst.stopping.load(Ordering::SeqCst) {
                    // A failed pull leaves the volume half served; end it all,
                    // as dokan2.dll's HandleProcessIoFatalError does.
                    debug!("pull failed: {e}; unmounting");
                    inst.request_release();
                }
                break;
            }
        };
        reply_len = 0;
        let pulled = if use_big { &pull_big[..n] } else { &pull[..n] };
        use_big = n == 0;
        if reply_buf.len() > RETAIN {
            reply_buf.truncate(INITIAL);
            reply_buf.shrink_to_fit();
        }
        if wbuf.len() > RETAIN {
            wbuf = Vec::new();
        }
        for one in marshal::split_events(pulled) {
            let Ok(evb) = one else {
                debug!("malformed pull output");
                break;
            };
            if reply_len > 0 {
                // More than one event in a pull (not expected without IPC
                // batching): the previous reply goes on its own.
                inst.send_reply(reply_buf[..reply_len].to_vec());
            }
            let r = catch_unwind(AssertUnwindSafe(|| handle(&inst, evb, &mut reply_buf, &mut wbuf, &ev)));
            reply_len = match r {
                Ok(n) => n.unwrap_or(0),
                Err(_) => {
                    // A bug in this library: answer rather than hang the IRP.
                    let serial = rd_u32(evb, ec::SERIAL_NUMBER).unwrap_or(0);
                    let major = rd_u8(evb, ec::MAJOR_FUNCTION).unwrap_or(0);
                    inst.end_pending(serial, STATUS_INTERNAL_ERROR);
                    if major == IRP_MJ_CLOSE {
                        0
                    } else {
                        let ctx = rd_u64(evb, ec::CONTEXT).unwrap_or(0);
                        ensure(&mut reply_buf, ei::SIZE);
                        reply::status_only(&mut reply_buf, serial, ctx, STATUS_INTERNAL_ERROR)
                    }
                }
            };
        }
    }
    inst.pull_thread_exited();
}

/// Decodes one event (fetching a large write's data) and dispatches it.
fn handle(inst: &Instance, evb: &[u8], r: &mut Vec<u8>, wbuf: &mut Vec<u8>, ev: &Event) -> Option<usize> {
    let e = match marshal::decode(evb) {
        Ok(e) => e,
        Err(err) => {
            debug!("undecodable event: {err:?}");
            let serial = rd_u32(evb, ec::SERIAL_NUMBER)?;
            if rd_u8(evb, ec::MAJOR_FUNCTION)? == IRP_MJ_CLOSE {
                return None;
            }
            ensure(r, ei::SIZE);
            return Some(reply::status_only(
                r,
                serial,
                rd_u64(evb, ec::CONTEXT).unwrap_or(0),
                STATUS_INVALID_PARAMETER,
            ));
        }
    };
    if let Op::Write { request_length, data, .. } = e.op {
        let timer = wstats::start();
        let large = request_length > 0;
        let mut bytes = data.map_or(0, |d| d.1);
        let out = if large {
            large_write(inst, &e.header, request_length, r, wbuf, ev, &mut bytes)
        } else {
            dispatch(inst, evb, &e, r)
        };
        if let Some(t) = timer {
            t.done(large, bytes as u64, e.header.file_flags);
        }
        return out;
    }
    dispatch(inst, evb, &e, r)
}

/// A write too large for the event: FSCTL_EVENT_WRITE copies the whole event
/// (data included) into a buffer of RequestLength bytes.
fn large_write(
    inst: &Instance,
    h: &Header,
    request_length: u32,
    r: &mut Vec<u8>,
    wbuf: &mut Vec<u8>,
    ev: &Event,
    data_len: &mut usize,
) -> Option<usize> {
    ensure(r, ei::SIZE);
    let mut info = [0u8; ei::SIZE];
    wr_u32(&mut info, ei::SERIAL_NUMBER, h.serial);
    wr_u64(&mut info, ei::CONTEXT, h.context);
    let n = request_length as usize;
    if wbuf.len() < n {
        // The old contents are dead: a fresh buffer, not a copying resize.
        *wbuf = Vec::new();
        ensure(wbuf, n);
    }
    let t = wstats::enabled().then(std::time::Instant::now);
    let fetched = sys::ioctl_overlapped(&inst.device, ev, FSCTL_EVENT_WRITE, &info, &mut wbuf[..n]);
    if let Some(t) = t {
        wstats::fetch_ns(t.elapsed().as_nanos() as u64);
    }
    match fetched {
        Ok(_) => {}
        Err(e) => {
            let st = if e == sys::ERROR_OPERATION_ABORTED { STATUS_CANCELLED } else { STATUS_INVALID_PARAMETER };
            debug!("FSCTL_EVENT_WRITE: {e}");
            return Some(reply::status_only(r, h.serial, h.context, st));
        }
    }
    let full = &wbuf[..n];
    let e = match marshal::decode(full) {
        Ok(e) if matches!(e.op, Op::Write { request_length: 0, .. }) => e,
        _ => return Some(reply::status_only(r, h.serial, h.context, STATUS_INVALID_PARAMETER)),
    };
    // The full event carries no serial of its own in some paths; use the stub's.
    let mut e = e;
    e.header.serial = h.serial;
    if let Op::Write { data: Some((_, l)), .. } = e.op {
        *data_len = l;
    }
    dispatch(inst, full, &e, r)
}

fn file_flags(f: u32) -> u32 {
    let map = [
        (DOKAN_PAGING_IO, MD_FILE_PAGING_IO),
        (DOKAN_SYNCHRONOUS_IO, MD_FILE_SYNCHRONOUS_IO),
        (DOKAN_NOCACHE, MD_FILE_NOCACHE),
        (DOKAN_WRITE_TO_END_OF_FILE, MD_FILE_WRITE_TO_END_OF_FILE),
        (DOKAN_DELETE_ON_CLOSE, MD_FILE_DELETE_ON_CLOSE),
        (DOKAN_FILE_DIRECTORY, MD_FILE_DIRECTORY),
    ];
    map.iter().filter(|(d, _)| f & d != 0).fold(0, |a, (_, m)| a | m)
}

/// A pointer to a name inside the event, or to a copy if it is not 2-aligned.
fn wide<'a>(ev: &'a [u8], s: Str, tmp: &'a mut Vec<u16>) -> (*const u16, u32) {
    let p = ev[s.off..].as_ptr();
    if (p as usize).is_multiple_of(2) {
        (p as *const u16, s.len as u32)
    } else {
        *tmp = s.to_vec(ev);
        (tmp.as_ptr(), s.len as u32)
    }
}

/// The request header for a name in the event; with named streams on
/// (ABI 1.1) `path` is the file and `stream` the stream it names
/// (`marshal::split_stream`), both pointing into the event (or `tmp`).
fn req_for(inst: &Instance, h: &Header, ev: &[u8], name: Str, tmp: &mut Vec<u16>) -> MdRequest {
    let (p, n) = wide(ev, name, tmp);
    let mut req = request(h, (p, n));
    if inst.named_streams && n > 0 {
        // SAFETY: `wide` returns a pointer valid for `n` units (into `ev`
        // or `tmp`, both alive for this request).
        let units = unsafe { core::slice::from_raw_parts(p, n as usize) };
        with_stream(&mut req, units);
    }
    req
}

/// Splits `req`'s path (which is `units`) into path + stream in place.
fn with_stream(req: &mut MdRequest, units: &[u16]) {
    let sp = marshal::split_stream(units);
    req.path_len = sp.path_len as u32;
    if let Some((o, l)) = sp.stream {
        req.stream = units[o..].as_ptr();
        req.stream_len = l as u32;
    }
}

fn request(h: &Header, path: (*const u16, u32)) -> MdRequest {
    MdRequest {
        request_id: h.serial as u64,
        context: h.context,
        process_id: h.process_id,
        irp_flags: h.flags,
        file_flags: file_flags(h.file_flags),
        major_function: h.major,
        minor_function: h.minor,
        _reserved: 0,
        path: path.0,
        path_len: path.1,
        _reserved2: 0,
        stream: core::ptr::null(),
        stream_len: 0,
        _reserved3: 0,
    }
}

/// Calls the host for one request; Some(reply size) or None (no reply now).
fn dispatch(inst: &Instance, ev: &[u8], e: &Ev, r: &mut Vec<u8>) -> Option<usize> {
    let h = &e.header;
    let (serial, ctx) = (h.serial, h.context);
    let mut tmp = Vec::new();
    // Ops that may go pending: register, call, then either reply or wait.
    macro_rules! call {
        ($plan:expr, $call:expr) => {{
            inst.begin_pending(serial, ctx, $plan);
            let st = $call;
            if inst.end_pending(serial, st) {
                return None;
            }
            st
        }};
    }
    match e.op {
        Op::Create(cr) => {
            let disposition = cr.disposition();
            let mut options = cr.options();
            let mut flags = 0;
            if h.flags & SL_CASE_SENSITIVE != 0 {
                flags |= MD_CREATE_CASE_SENSITIVE;
            }
            let mut full = cr.name.to_vec(ev);
            // ABI 1.1, named streams: the create names a file and a stream;
            // the open-target rule below works on the file's name.
            let mut stream: Vec<u16> = Vec::new();
            if inst.named_streams {
                let sp = marshal::split_stream(&full);
                if let Some((o, l)) = sp.stream {
                    stream = full[o..o + l].to_vec();
                }
                full.truncate(sp.path_len);
                if full.is_empty() {
                    full.push(b'\\' as u16);
                }
            }
            let mut path = full.clone();
            let open_target = options & FILE_DIRECTORY_FILE == 0 && h.flags & SL_OPEN_TARGET_DIRECTORY != 0;
            if open_target {
                // Strip the last part of the path: open the parent directory.
                flags |= MD_CREATE_OPEN_TARGET_DIRECTORY;
                options = (options | FILE_DIRECTORY_FILE) & !FILE_NON_DIRECTORY_FILE;
                let last = (0..path.len())
                    .rev()
                    .find(|&i| (path[i] == b'\\' as u16 || path[i] == b'/' as u16) && i + 1 < path.len());
                path.truncate(last.unwrap_or(path.len()));
                if path.is_empty() {
                    path.push(b'\\' as u16);
                }
            }
            ensure(r, ei::SIZE);
            if options & FILE_NON_DIRECTORY_FILE != 0 && options & FILE_DIRECTORY_FILE != 0 {
                return Some(reply::create(
                    r,
                    serial,
                    disposition,
                    options,
                    open_target,
                    STATUS_INVALID_PARAMETER,
                    &MdCreateReply::default(),
                ));
            }
            let (sd, sd_len) = match cr.security_descriptor {
                Some((o, l)) => (ev[o..].as_ptr(), l as u32),
                None => (core::ptr::null(), 0),
            };
            let params = MdCreateRequest {
                desired_access: cr.desired_access,
                file_attributes: cr.file_attributes,
                share_access: cr.share_access,
                disposition,
                create_options: options,
                flags,
                original_desired_access: cr.original_desired_access,
                remaining_desired_access: cr.remaining_desired_access,
                previously_granted_access: cr.previously_granted_access,
                access_state_flags: cr.access_state_flags,
                security_descriptor: sd,
                security_descriptor_len: sd_len,
                target_len: if open_target { full.len() as u32 } else { 0 },
                target: if open_target { full.as_ptr() } else { core::ptr::null() },
            };
            let mut req = request(h, (path.as_ptr(), path.len() as u32));
            if !stream.is_empty() {
                req.stream = stream.as_ptr();
                req.stream_len = stream.len() as u32;
            }
            let mut out = MdCreateReply::default();
            let st =
                call!(Plan::Create { disposition, options, open_target }, inst.host.create(&req, &params, &mut out));
            Some(reply::create(r, serial, disposition, options, open_target, st, &out))
        }
        Op::Cleanup { name } => {
            let req = req_for(inst, h, ev, name, &mut tmp);
            call!(Plan::Cleanup, inst.host.cleanup(&req));
            wstats::flush();
            ensure(r, ei::SIZE);
            // "return success at any case"
            Some(reply::status_only(r, serial, ctx, STATUS_SUCCESS))
        }
        Op::Close { name } => {
            inst.forget_listing(ctx);
            let req = req_for(inst, h, ev, name, &mut tmp);
            inst.host.close(&req);
            None
        }
        Op::Read { name, offset, length } => {
            let req = req_for(inst, h, ev, name, &mut tmp);
            ensure(r, ei::BUFFER + (length as usize).max(8));
            let mut bytes = 0u32;
            let st = call!(
                Plan::Read { offset, length },
                inst.host.read(&req, offset, &mut r[ei::BUFFER..ei::BUFFER + length as usize], &mut bytes)
            );
            Some(reply::read(r, serial, ctx, offset, length, st, bytes))
        }
        Op::Write { name, offset, data: Some((o, l)), .. } => {
            let req = req_for(inst, h, ev, name, &mut tmp);
            let mut written = 0u32;
            let t = wstats::enabled().then(std::time::Instant::now);
            let st = call!(Plan::Write { offset }, inst.host.write(&req, offset, &ev[o..o + l], &mut written));
            if let Some(t) = t {
                wstats::host_ns(ev.len() > EVENT_CONTEXT_MAX_SIZE, t.elapsed().as_nanos() as u64);
            }
            ensure(r, ei::SIZE);
            Some(reply::write(r, serial, ctx, offset, st, written))
        }
        Op::Write { .. } => {
            ensure(r, ei::SIZE);
            Some(reply::status_only(r, serial, ctx, STATUS_INVALID_PARAMETER))
        }
        Op::Flush { name } => {
            let req = req_for(inst, h, ev, name, &mut tmp);
            let st = call!(Plan::Flush, inst.host.flush(&req));
            ensure(r, ei::SIZE);
            Some(reply::status_only(r, serial, ctx, flush_status(st)))
        }
        Op::QueryInfo { name, class, buffer_length } => {
            ensure(r, ei::BUFFER + (buffer_length as usize).max(8));
            if let info::QueryPlan::Answer(st) = info::query_plan(class) {
                return Some(reply::status_only(r, serial, ctx, st));
            }
            if class == FILE_STREAM_INFORMATION && inst.named_streams {
                // ABI 1.1: the host's streams, written straight into the
                // reply. Synchronous: find_streams may not pend.
                let req = req_for(inst, h, ev, name, &mut tmp);
                return Some(info::query_streams(r, serial, ctx, buffer_length, inst.allocation_unit, |w| match inst
                    .host
                    .find_streams(&req, w)
                {
                    STATUS_PENDING => STATUS_INTERNAL_ERROR,
                    st => st,
                }));
            }
            let name_v = if info::needs_name(class) { name.to_vec(ev) } else { Vec::new() };
            let req = req_for(inst, h, ev, name, &mut tmp);
            let mut fi = MdFileInfo::default();
            let st = call!(
                Plan::QueryInfo { class, buffer_length, name: name_v.clone() },
                inst.host.query_info(&req, class, &mut fi)
            );
            Some(info::query_info(r, serial, ctx, class, buffer_length, &name_v, st, &fi, inst.allocation_unit))
        }
        Op::SetInfo { name, class, buffer } => {
            let si = match marshal::decode_set_info(ev, class, buffer) {
                Ok(si) => si,
                Err(st) => {
                    ensure(r, ei::SIZE);
                    return Some(reply::status_only(r, serial, ctx, st));
                }
            };
            ensure(r, ei::BUFFER + (si.new_name.len() * 2).max(8));
            let params = MdSetInfoRequest {
                kind: si.kind,
                info_class: class,
                attributes: si.attributes,
                _reserved: 0,
                creation_time: si.times[0],
                last_access_time: si.times[1],
                last_write_time: si.times[2],
                change_time: si.times[3],
                size: si.size,
                delete: si.delete as u8,
                replace_if_exists: si.replace_if_exists as u8,
                _pad: 0,
                ex_flags: si.ex_flags,
                new_name: si.new_name.as_ptr(),
                new_name_len: si.new_name.len() as u32,
                _reserved2: 0,
            };
            let req = req_for(inst, h, ev, name, &mut tmp);
            let st = call!(
                Plan::SetInfo { class, delete: si.delete, new_name: si.new_name.clone() },
                inst.host.set_info(&req, &params)
            );
            Some(reply::set_info(r, serial, ctx, class, si.delete, &si.new_name, st))
        }
        Op::Directory { dir, class, index, buffer_length, pattern } => {
            ensure(r, ei::BUFFER + (buffer_length as usize).max(8));
            if !marshal::dir::class_supported(class) {
                return Some(reply::status_only(r, serial, ctx, STATUS_INVALID_PARAMETER));
            }
            let d = DirPlan {
                class,
                index,
                irp_flags: h.flags,
                buffer_length,
                pattern: pattern.map(|p| p.to_vec(ev)),
                is_root: dir.len == 1 && rd_u16(ev, dir.off) == Some(b'\\' as u16),
            };
            if let Some(n) = inst.dir_from_kept(r, serial, ctx, &d) {
                return Some(n);
            }
            let req = req_for(inst, h, ev, dir, &mut tmp);
            let mut entries = Vec::new();
            let st = call!(Plan::Dir(d.clone()), inst.host.find_files(&req, d.pattern.as_deref(), &mut entries));
            Some(inst.complete_dir(r, serial, ctx, &d, st, entries))
        }
        Op::Volume { class, buffer_length } => {
            ensure(r, ei::BUFFER + (buffer_length as usize).max(8));
            let req = request(h, (core::ptr::null(), 0));
            let mut v = MdVolumeInfo::default();
            let st = call!(Plan::Volume { class, buffer_length }, inst.host.query_volume(&req, &mut v));
            let (st, mut v) =
                if st == STATUS_NOT_IMPLEMENTED { (STATUS_SUCCESS, info::default_volume()) } else { (st, v) };
            // Named streams are declared exactly when the mount serves them
            // (dokan2.dll clears the flag without DOKAN_OPTION_ALT_STREAM).
            if inst.named_streams {
                v.fs_flags |= FILE_NAMED_STREAMS;
            } else {
                v.fs_flags &= !FILE_NAMED_STREAMS;
            }
            Some(info::query_volume(
                r,
                serial,
                ctx,
                class,
                buffer_length,
                st,
                &v,
                inst.sector_size,
                inst.allocation_unit,
            ))
        }
        Op::QuerySecurity { name, info: si, buffer_length } => {
            ensure(r, ei::BUFFER + (buffer_length as usize).max(8));
            let req = req_for(inst, h, ev, name, &mut tmp);
            let mut needed = 0u32;
            let st = call!(
                Plan::QuerySecurity { buffer_length },
                inst.host.query_security(
                    &req,
                    si,
                    &mut r[ei::BUFFER..ei::BUFFER + buffer_length as usize],
                    &mut needed
                )
            );
            Some(reply::query_security(r, serial, ctx, buffer_length, st, needed))
        }
        Op::SetSecurity { name, info: si, descriptor: (o, l) } => {
            let req = req_for(inst, h, ev, name, &mut tmp);
            let st = call!(Plan::SetSecurity, inst.host.set_security(&req, si, &ev[o..o + l]));
            ensure(r, ei::SIZE);
            Some(reply::status_only(r, serial, ctx, st))
        }
        // No FILELOCK_USER_MODE: the kernel keeps byte-range locks.
        Op::Lock { .. } => {
            ensure(r, ei::SIZE);
            Some(reply::status_only(r, serial, ctx, STATUS_NOT_IMPLEMENTED))
        }
        Op::Log => None,
        Op::Unknown => {
            debug!("unsupported IRP 0x{:x}", h.major);
            ensure(r, ei::SIZE);
            Some(reply::status_only(r, serial, ctx, STATUS_INVALID_PARAMETER))
        }
    }
}
