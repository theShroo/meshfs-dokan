// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Safe wrappers around the host's callback table. The callbacks are the
//! host's C ABI: the `unsafe` here rests on the contract in meshfs_dokan.h
//! (valid function pointers, callable from any thread, no unwinding).

use core::ffi::c_void;
use core::ptr::null;

use crate::abi::*;
use crate::marshal::dir::Entry;
use crate::marshal::info::StreamWriter;
use crate::proto::{STATUS_INTERNAL_ERROR, STATUS_NOT_IMPLEMENTED};

#[derive(Clone, Copy)]
pub struct Host {
    t: MdHostV1,
}

// SAFETY: the ABI contract (meshfs_dokan.h) requires the host's `user`
// pointer and callbacks to be usable from any thread at once.
unsafe impl Send for Host {}
// SAFETY: as above.
unsafe impl Sync for Host {}

/// Reads the host's table, honouring its `size`: entries past it are null.
///
/// # Safety
/// `t` must point to a readable `MdHostV1` prefix of at least `t.size` bytes
/// (and at least the fixed header).
pub unsafe fn from_table(t: *const MdHostV1) -> Option<Host> {
    if t.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the header is readable.
    let size = unsafe { core::ptr::addr_of!((*t).size).read_unaligned() } as usize;
    // SAFETY: as above.
    let version = unsafe { core::ptr::addr_of!((*t).version).read_unaligned() };
    let head = core::mem::offset_of!(MdHostV1, create);
    if size < head || version >> 16 != MD_ABI_MAJOR {
        return None;
    }
    let mut out = MdHostV1 {
        size: size as u32,
        version,
        user: core::ptr::null_mut(),
        create: None,
        cleanup: None,
        close: None,
        read: None,
        write: None,
        flush: None,
        query_info: None,
        set_info: None,
        find_files: None,
        query_volume: None,
        query_security: None,
        set_security: None,
        mounted: None,
        unmounted: None,
        find_streams: None,
    };
    // Whole fields only: a partly declared pointer stays null.
    let n = size.min(core::mem::size_of::<MdHostV1>()) & !7;
    // SAFETY: copies the `n` bytes the host declared readable into a value of
    // the same layout; every field is a pointer or an Option<fn> for which
    // any bit pattern the host wrote per the ABI is valid (null = None).
    unsafe { core::ptr::copy_nonoverlapping(t as *const u8, &mut out as *mut MdHostV1 as *mut u8, n) };
    out.size = size as u32;
    Some(Host { t: out })
}

impl Host {
    pub fn create(&self, req: &MdRequest, p: &MdCreateRequest, out: &mut MdCreateReply) -> NtStatus {
        match self.t.create {
            // SAFETY: valid pointers for the call; host contract.
            Some(f) => unsafe { f(self.t.user, req, p, out) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn cleanup(&self, req: &MdRequest) -> NtStatus {
        match self.t.cleanup {
            // SAFETY: valid pointers for the call; host contract.
            Some(f) => unsafe { f(self.t.user, req) },
            None => 0,
        }
    }

    pub fn close(&self, req: &MdRequest) {
        if let Some(f) = self.t.close {
            // SAFETY: valid pointers for the call; host contract.
            unsafe { f(self.t.user, req) }
        }
    }

    pub fn read(&self, req: &MdRequest, offset: i64, buf: &mut [u8], out_bytes: &mut u32) -> NtStatus {
        match self.t.read {
            // SAFETY: `buf` is valid for writes of its length during the call.
            Some(f) => unsafe { f(self.t.user, req, offset, buf.len() as u32, buf.as_mut_ptr(), out_bytes) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn write(&self, req: &MdRequest, offset: i64, data: &[u8], out_bytes: &mut u32) -> NtStatus {
        match self.t.write {
            // SAFETY: `data` is valid for reads of its length during the call.
            Some(f) => unsafe { f(self.t.user, req, offset, data.as_ptr(), data.len() as u32, out_bytes) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn flush(&self, req: &MdRequest) -> NtStatus {
        match self.t.flush {
            // SAFETY: valid pointers for the call; host contract.
            Some(f) => unsafe { f(self.t.user, req) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn query_info(&self, req: &MdRequest, class: u32, out: &mut MdFileInfo) -> NtStatus {
        match self.t.query_info {
            // SAFETY: valid pointers for the call; host contract.
            Some(f) => unsafe { f(self.t.user, req, class, out) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn set_info(&self, req: &MdRequest, p: &MdSetInfoRequest) -> NtStatus {
        match self.t.set_info {
            // SAFETY: valid pointers for the call; host contract.
            Some(f) => unsafe { f(self.t.user, req, p) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    /// Calls `find_files`; the entries the host fills in land in `sink`.
    pub fn find_files(&self, req: &MdRequest, pattern: Option<&[u16]>, sink: &mut Vec<Entry>) -> NtStatus {
        let Some(f) = self.t.find_files else { return STATUS_NOT_IMPLEMENTED };
        let (pp, pl) = match pattern {
            Some(p) => (p.as_ptr(), p.len() as u32),
            None => (null(), 0),
        };
        // SAFETY: `sink` outlives the call; `fill` only casts `fill_ctx` back
        // to it, and the host may call `fill` only during this call.
        unsafe { f(self.t.user, req, pp, pl, fill, sink as *mut Vec<Entry> as *mut c_void) }
    }

    pub fn query_volume(&self, req: &MdRequest, out: &mut MdVolumeInfo) -> NtStatus {
        match self.t.query_volume {
            // SAFETY: valid pointers for the call; host contract.
            Some(f) => unsafe { f(self.t.user, req, out) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn query_security(&self, req: &MdRequest, info: u32, buf: &mut [u8], needed: &mut u32) -> NtStatus {
        match self.t.query_security {
            // SAFETY: `buf` is valid for writes of its length during the call.
            Some(f) => unsafe { f(self.t.user, req, info, buf.as_mut_ptr(), buf.len() as u32, needed) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn set_security(&self, req: &MdRequest, info: u32, sd: &[u8]) -> NtStatus {
        match self.t.set_security {
            // SAFETY: `sd` is valid for reads of its length during the call.
            Some(f) => unsafe { f(self.t.user, req, info, sd.as_ptr(), sd.len() as u32) },
            None => STATUS_NOT_IMPLEMENTED,
        }
    }

    pub fn mounted(&self, mount_point: &[u16], device_name: &[u16]) {
        if let Some(f) = self.t.mounted {
            // SAFETY: both slices are valid for the call.
            unsafe {
                f(
                    self.t.user,
                    mount_point.as_ptr(),
                    mount_point.len() as u32,
                    device_name.as_ptr(),
                    device_name.len() as u32,
                )
            }
        }
    }

    /// Whether the table has ABI 1.1's `find_streams`.
    pub fn has_find_streams(&self) -> bool {
        self.t.find_streams.is_some()
    }

    /// Calls `find_streams`; the host's entries go straight into `w`.
    pub fn find_streams(&self, req: &MdRequest, w: &mut StreamWriter<'_>) -> NtStatus {
        let Some(f) = self.t.find_streams else { return STATUS_NOT_IMPLEMENTED };
        // SAFETY: `w` outlives the call; `fill_stream` only casts `fill_ctx`
        // back to it, and the host may call it only during this call.
        unsafe { f(self.t.user, req, fill_stream, w as *mut StreamWriter<'_> as *mut c_void) }
    }

    pub fn unmounted(&self) {
        if let Some(f) = self.t.unmounted {
            // SAFETY: host contract.
            unsafe { f(self.t.user) }
        }
    }
}

/// Copies a host-provided find entry.
///
/// # Safety
/// `e.name` must be valid for `e.name_len` units (or `name_len` 0).
pub unsafe fn entry_from(e: &MdFindEntry) -> Entry {
    let name = if e.name.is_null() || e.name_len == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller guarantees the name is valid for its length.
        unsafe { core::slice::from_raw_parts(e.name, e.name_len as usize) }.to_vec()
    };
    Entry {
        name,
        attributes: e.attributes,
        creation_time: e.creation_time,
        last_access_time: e.last_access_time,
        last_write_time: e.last_write_time,
        change_time: e.change_time,
        file_size: e.file_size,
        allocation_size: e.allocation_size,
        file_id: e.file_id,
    }
}

unsafe extern "C" fn fill_stream(ctx: *mut c_void, entry: *const MdStreamEntry) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() || entry.is_null() {
            return 1;
        }
        // SAFETY: `ctx` is the `&mut StreamWriter` find_streams passed, live
        // for that call, during which the host calls us; the entry is valid
        // per the ABI.
        let (w, e) = unsafe { (&mut *(ctx as *mut StreamWriter<'_>), &*entry) };
        let name: &[u16] = if e.name.is_null() || e.name_len == 0 {
            &[]
        } else {
            // SAFETY: the ABI requires `name` valid for `name_len` units.
            unsafe { core::slice::from_raw_parts(e.name, e.name_len as usize) }
        };
        if w.push(name, e.size, e.allocation_size) { 0 } else { crate::proto::STATUS_BUFFER_OVERFLOW }
    }));
    r.unwrap_or(STATUS_INTERNAL_ERROR)
}

unsafe extern "C" fn fill(ctx: *mut c_void, entry: *const MdFindEntry) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() || entry.is_null() {
            return 1;
        }
        // SAFETY: `ctx` is the `&mut Vec<Entry>` find_files passed and is live
        // for the duration of that call, during which the host calls us; the
        // host passes a valid entry per the ABI.
        let (sink, e) = unsafe { (&mut *(ctx as *mut Vec<Entry>), &*entry) };
        // SAFETY: the ABI requires `name` valid for `name_len` units.
        sink.push(unsafe { entry_from(e) });
        0
    }));
    r.unwrap_or(STATUS_INTERNAL_ERROR)
}
