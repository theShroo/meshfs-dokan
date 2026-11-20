// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! The FFI and IOCTL layer: handles, CreateFileW and DeviceIoControl. Every
//! `unsafe` block of the session and pull code is here.

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::{CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::CreateEventW;

pub type Win32Error = u32;

/// An owned kernel handle.
pub struct Handle(HANDLE);

// SAFETY: a kernel handle is a process-wide value; the calls made on it here
// (DeviceIoControl, CloseHandle) are thread-safe.
unsafe impl Send for Handle {}
// SAFETY: as above; concurrent DeviceIoControl calls on one handle are allowed.
unsafe impl Sync for Handle {}

impl Handle {
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned, valid and closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn last_error() -> Win32Error {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

#[derive(Clone, Copy)]
pub enum Open {
    /// Synchronous I/O; access 0 (dokan2.dll's SendToDevice).
    Sync,
    /// FILE_FLAG_OVERLAPPED, so the pull threads' calls are not serialised
    /// on the file object (dokan2.dll opens the volume device this way).
    Overlapped,
    /// The keepalive file: no sharing.
    Keepalive,
    /// The notification file: shared, FILE_FLAG_BACKUP_SEMANTICS.
    Notify,
    /// For the host's own experiments: read/write access.
    ReadWrite,
}

pub fn open(path: &str, mode: Open) -> Result<Handle, Win32Error> {
    let w = wide(path);
    let (access, share, flags) = match mode {
        Open::Sync => (0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0),
        Open::Overlapped => (0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_OVERLAPPED),
        Open::Keepalive => (0, 0, 0),
        Open::Notify => (0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_BACKUP_SEMANTICS),
        Open::ReadWrite => (GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0),
    };
    // SAFETY: `w` is a NUL-terminated UTF-16 string that outlives the call;
    // the other arguments are plain values or null.
    let h = unsafe { CreateFileW(w.as_ptr(), access, share, null(), OPEN_EXISTING, flags, null_mut()) };
    if h == INVALID_HANDLE_VALUE || h.is_null() { Err(last_error()) } else { Ok(Handle(h)) }
}

/// A manual-reset event for overlapped calls, one per thread.
pub struct Event(Handle);

impl Event {
    pub fn new() -> Result<Event, Win32Error> {
        // SAFETY: no security attributes, manual reset, not signalled, no name.
        let h = unsafe { CreateEventW(null(), 1, 0, null()) };
        if h.is_null() { Err(last_error()) } else { Ok(Event(Handle(h))) }
    }
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// DeviceIoControl on a synchronous handle. Returns the bytes written to
/// `output`.
pub fn ioctl(h: &Handle, code: u32, input: &[u8], output: &mut [u8]) -> Result<usize, Win32Error> {
    let mut n: u32 = 0;
    let (ip, il) = if input.is_empty() { (null(), 0) } else { (input.as_ptr() as *const c_void, len32(input.len())) };
    let (op, ol) =
        if output.is_empty() { (null_mut(), 0) } else { (output.as_mut_ptr() as *mut c_void, len32(output.len())) };
    // SAFETY: the buffers are valid for their lengths for the duration of the
    // call (synchronous handle, no OVERLAPPED), `n` is a valid out pointer.
    let ok = unsafe { DeviceIoControl(h.raw(), code, ip, il, op, ol, &mut n, null_mut()) };
    if ok != 0 { Ok(n as usize) } else { Err(last_error()) }
}

/// DeviceIoControl on an overlapped handle, waited for on `ev`.
pub fn ioctl_overlapped(
    h: &Handle,
    ev: &Event,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, Win32Error> {
    let mut n: u32 = 0;
    // SAFETY: OVERLAPPED is plain data; all-zero is its documented initial state.
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.hEvent = ev.0.raw();
    let (ip, il) = if input.is_empty() { (null(), 0) } else { (input.as_ptr() as *const c_void, len32(input.len())) };
    let (op, ol) =
        if output.is_empty() { (null_mut(), 0) } else { (output.as_mut_ptr() as *mut c_void, len32(output.len())) };
    // SAFETY: the buffers and `ov` stay valid and unmoved until the operation
    // completes: on ERROR_IO_PENDING we wait for it below before returning.
    let ok = unsafe { DeviceIoControl(h.raw(), code, ip, il, op, ol, &mut n, &mut ov) };
    if ok != 0 {
        return Ok(n as usize);
    }
    let e = last_error();
    if e != ERROR_IO_PENDING {
        return Err(e);
    }
    // SAFETY: `ov` belongs to the operation just started on `h`; bWait = TRUE
    // blocks until it completes, so the buffers outlive it.
    let ok = unsafe { GetOverlappedResult(h.raw(), &ov, &mut n, 1) };
    if ok != 0 { Ok(n as usize) } else { Err(last_error()) }
}

/// CancelIoEx for every overlapped call any thread has pending on `h`.
pub fn cancel_all(h: &Handle) {
    // SAFETY: a live handle; a null OVERLAPPED cancels all of its I/O.
    unsafe { CancelIoEx(h.raw(), null()) };
}

pub const ERROR_OPERATION_ABORTED: Win32Error = windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED;
