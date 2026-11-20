// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! The exported functions (design 3.1; contract in include/meshfs_dokan.h).
//! No panic crosses this boundary: every export runs under catch_unwind.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use super::host;
use super::session::{self, Instance, Options, ReplyIn};
use crate::abi::*;
use crate::proto::{STATUS_INTERNAL_ERROR, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// # Safety
/// `p` is null or a NUL-terminated UTF-16 string.
unsafe fn wstr(p: *const u16) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut n = 0usize;
    // SAFETY: the caller guarantees a terminator; we stop at it (bounded at
    // 32767 units, the longest path Windows has).
    while n < 32767 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: the `n` units before the terminator are readable.
    unsafe { core::slice::from_raw_parts(p, n) }.to_vec()
}

/// # Safety
/// `inst` must be a live handle from md_mount (not yet passed to md_unmount).
unsafe fn instance<'a>(inst: *mut MdInstance) -> Option<&'a Arc<Instance>> {
    if inst.is_null() {
        return None;
    }
    // SAFETY: md_mount made `inst` from Box<Arc<Instance>>; it stays alive
    // until md_unmount, which the caller has not called yet.
    Some(unsafe { &*(inst as *const Arc<Instance>) })
}

/// The ABI version: major << 16 | minor.
#[unsafe(no_mangle)]
pub extern "C" fn md_abi_version() -> u32 {
    MD_ABI_VERSION
}

/// The driver's protocol version (FSCTL_GET_VERSION), 0 if it is not there.
#[unsafe(no_mangle)]
pub extern "C" fn md_driver_version() -> u32 {
    guard(0, || session::driver_version().unwrap_or(0))
}

/// Whether this library speaks driver protocol `version` (1) or not (0).
#[unsafe(no_mangle)]
pub extern "C" fn md_driver_version_supported(version: u32) -> i32 {
    crate::proto::SUPPORTED_DRIVER_VERSIONS.iter().any(|(v, _)| *v == version) as i32
}

/// Mounts. On MD_OK `*out` is the instance.
///
/// # Safety
/// `options` and `host` point to valid structures as the header describes;
/// `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_mount(
    options: *const MdMountOptions,
    host: *const MdHostV1,
    out: *mut *mut MdInstance,
) -> i32 {
    guard(MD_ERR_INTERNAL, || {
        if options.is_null() || out.is_null() {
            return MD_ERR_ARGS;
        }
        // SAFETY: `out` is writable (caller contract).
        unsafe { *out = core::ptr::null_mut() };
        // SAFETY: `options` points to at least its `size` field.
        let size = unsafe { core::ptr::addr_of!((*options).size).read_unaligned() } as usize;
        if size < core::mem::size_of::<MdMountOptions>() {
            return MD_ERR_ARGS;
        }
        // SAFETY: the full structure is readable (size checked).
        let o = unsafe { &*options };
        // SAFETY: `host` points to a table of at least its declared size.
        let Some(h) = (unsafe { host::from_table(host) }) else { return MD_ERR_ARGS };
        let sd = if o.volume_security_descriptor.is_null() || o.volume_security_descriptor_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the caller declares the descriptor readable for its length.
            unsafe {
                core::slice::from_raw_parts(o.volume_security_descriptor, o.volume_security_descriptor_len as usize)
            }
            .to_vec()
        };
        let opts = Options {
            flags: o.flags,
            // SAFETY: NUL-terminated strings or null (caller contract).
            mount_point: unsafe { wstr(o.mount_point) },
            // SAFETY: as above.
            unc_name: unsafe { wstr(o.unc_name) },
            irp_timeout_ms: o.irp_timeout_ms,
            fcb_gc_interval_ms: o.fcb_gc_interval_ms,
            pull_threads: o.pull_threads,
            sector_size: o.sector_size,
            allocation_unit_size: o.allocation_unit_size,
            volume_security_descriptor: sd,
        };
        match session::mount(opts, h) {
            Ok(inst) => {
                // SAFETY: `out` is writable (caller contract).
                unsafe { *out = Box::into_raw(Box::new(inst)) as *mut MdInstance };
                MD_OK
            }
            Err(e) => e,
        }
    })
}

/// Unmounts, waits for the pull threads, calls `unmounted` (once) and frees
/// the instance. Not from a pull thread (MD_ERR_THREAD, nothing freed).
///
/// # Safety
/// `inst` is a live instance; it is invalid after MD_OK.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_unmount(inst: *mut MdInstance) -> i32 {
    guard(MD_ERR_INTERNAL, || {
        // SAFETY: caller contract.
        let Some(i) = (unsafe { instance(inst) }) else { return MD_ERR_ARGS };
        if let Err(e) = i.stop() {
            return e;
        }
        // SAFETY: made by Box::into_raw in md_mount and freed exactly once here.
        drop(unsafe { Box::from_raw(inst as *mut Arc<Instance>) });
        MD_OK
    })
}

/// Completes requests whose callbacks returned STATUS_PENDING; each goes to
/// the driver as its own reply-only call. Returns how many were accepted
/// (an unknown or already answered request_id is skipped). Never waits on
/// the driver: each reply is encoded here and sent by the library's replier
/// threads (`crate::replier`), because the driver completes the IRP inside
/// the call and that completion can wait for other requests' answers.
///
/// # Safety
/// `inst` is live; `replies` points to `count` valid MdReply values whose
/// pointers are valid for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_reply(inst: *mut MdInstance, replies: *const MdReply, count: u32) -> u32 {
    guard(0, || {
        // SAFETY: caller contract.
        let Some(i) = (unsafe { instance(inst) }) else { return 0 };
        if replies.is_null() {
            return 0;
        }
        // SAFETY: `count` valid replies (caller contract).
        let all = unsafe { core::slice::from_raw_parts(replies, count as usize) };
        let mut ok = 0;
        for r in all {
            // SAFETY: the pointers in `r` are valid for this call (contract).
            let data = unsafe { opt_slice(r.data, r.data_len as usize) };
            let entries = if r.entries.is_null() {
                Vec::new()
            } else {
                // SAFETY: `entry_count` valid entries (contract).
                unsafe { core::slice::from_raw_parts(r.entries, r.entry_count as usize) }
                    .iter()
                    // SAFETY: each entry's name is valid for its length (contract).
                    .map(|e| unsafe { host::entry_from(e) })
                    .collect()
            };
            let input = ReplyIn {
                request_id: r.request_id,
                status: r.status,
                bytes: r.bytes,
                data,
                // SAFETY: null or valid (contract).
                create: unsafe { r.create.as_ref() }.copied(),
                // SAFETY: null or valid (contract).
                file_info: unsafe { r.file_info.as_ref() }.copied(),
                // SAFETY: null or valid (contract).
                volume: unsafe { r.volume.as_ref() }.copied(),
                entries,
            };
            if i.reply(&input).is_ok() {
                ok += 1;
            }
        }
        ok
    })
}

/// # Safety
/// `p` is null or valid for `n` bytes.
unsafe fn opt_slice<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        // SAFETY: caller contract.
        unsafe { core::slice::from_raw_parts(p, n) }
    }
}

/// FSCTL_NOTIFY_PATH: `path` (relative to the volume, e.g. `\dir\f`),
/// FILE_NOTIFY_CHANGE_* filter, FILE_ACTION_* action. 0 or a Win32 error.
///
/// # Safety
/// `inst` is live; `path` is valid for `path_len` units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_notify_path(
    inst: *mut MdInstance,
    path: *const u16,
    path_len: u32,
    filter: u32,
    action: u32,
) -> u32 {
    guard(STATUS_INTERNAL_ERROR as u32, || {
        // SAFETY: caller contract.
        let Some(i) = (unsafe { instance(inst) }) else { return STATUS_INVALID_PARAMETER as u32 };
        if path.is_null() {
            return STATUS_INVALID_PARAMETER as u32;
        }
        // SAFETY: caller contract.
        let p = unsafe { core::slice::from_raw_parts(path, path_len as usize) };
        match i.notify_path(p, filter, action) {
            Ok(()) => 0,
            Err(e) => e,
        }
    })
}

/// FSCTL_GET_ACCESS_TOKEN: the requester's token for a create the host is
/// handling (in its callback or pending). The caller closes it. -1 (as
/// INVALID_HANDLE_VALUE) on failure.
///
/// # Safety
/// `inst` is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_requester_token(inst: *mut MdInstance, request_id: u64) -> isize {
    guard(-1, || {
        // SAFETY: caller contract.
        let Some(i) = (unsafe { instance(inst) }) else { return -1 };
        i.requester_token(request_id).unwrap_or(-1)
    })
}

/// Kept for the ABI: with driver protocol 0x190 there is nothing to switch.
/// The driver never caches handle reads and writes (it never initialises a
/// cache map: every ReadFile/WriteFile reaches the host), and no reply field
/// or mount flag controls the only cached path, pages of memory-mapped
/// views and image sections. Returns STATUS_SUCCESS.
///
/// # Safety
/// `inst` is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_set_no_cache(inst: *mut MdInstance, request_id: u64) -> i32 {
    let _ = (inst, request_id);
    STATUS_SUCCESS
}

/// FSCTL_RESET_TIMEOUT: gives a pending request `timeout_ms` more (0: the
/// mount's IrpTimeout; the driver caps it). 0 or a Win32 error.
///
/// # Safety
/// `inst` is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn md_reset_timeout(inst: *mut MdInstance, request_id: u64, timeout_ms: u32) -> u32 {
    guard(STATUS_INTERNAL_ERROR as u32, || {
        // SAFETY: caller contract.
        let Some(i) = (unsafe { instance(inst) }) else { return STATUS_INVALID_PARAMETER as u32 };
        match i.reset_timeout(request_id, timeout_ms) {
            Ok(()) => 0,
            Err(e) => e,
        }
    })
}
