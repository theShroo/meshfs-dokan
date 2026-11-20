// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/dokan.c, create.c, read.c, write.c,
// setfile.c, security.c, flush.c, cleanup.c:
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! `EVENT_INFORMATION` replies. Every encoder takes the whole reply buffer
//! (the header plus the data area, at least `ei::SIZE`) and returns how many
//! bytes to send.

use crate::abi::{MD_CREATE_IS_DIRECTORY, MD_CREATE_TARGET_MISSING, MdCreateReply};
use crate::proto::*;

/// Size of a reply whose `BufferLength` counts data bytes (dokan2.dll's
/// GetEventInfoSize). Write replies are always `ei::SIZE`; so is a security
/// BUFFER_OVERFLOW reply, whose `BufferLength` is the length needed and which
/// carries no data.
pub fn sized(r: &[u8]) -> usize {
    let n = rd_u32(r, ei::BUFFER_LENGTH).unwrap_or(0) as usize;
    (ei::BUFFER + n).max(ei::SIZE)
}

/// Clears the header and `data_len` bytes of the data area, then sets the
/// serial number and the context to echo (dokan2.dll's CreateDispatchCommon
/// with ClearNonPoolBuffer).
pub fn begin(r: &mut [u8], serial: u32, context: u64, data_len: usize) {
    let end = (ei::BUFFER + data_len).max(ei::SIZE).min(r.len());
    r[..end].fill(0);
    wr_u32(r, ei::SERIAL_NUMBER, serial);
    wr_u64(r, ei::CONTEXT, context);
}

/// Clears only the header (the data area is the host's, e.g. read bytes).
pub fn begin_header(r: &mut [u8], serial: u32, context: u64) {
    r[..ei::BUFFER].fill(0);
    wr_u32(r, ei::SERIAL_NUMBER, serial);
    wr_u64(r, ei::CONTEXT, context);
}

pub fn set_status(r: &mut [u8], status: NtStatus) {
    wr_i32(r, ei::STATUS, status);
}

pub fn set_buffer_length(r: &mut [u8], n: u32) {
    wr_u32(r, ei::BUFFER_LENGTH, n);
}

/// A status-only reply (cleanup, flush, set security, lock, unknown).
pub fn status_only(r: &mut [u8], serial: u32, context: u64, status: NtStatus) -> usize {
    begin(r, serial, context, 0);
    set_status(r, status);
    ei::SIZE
}

/// CreateSuccesStatusCheck: OPEN_IF, SUPERSEDE and OVERWRITE_IF report an
/// existing file with STATUS_OBJECT_NAME_COLLISION and still succeed.
pub fn create_succeeded(status: NtStatus, disposition: u32) -> bool {
    nt_success(status)
        || (status == STATUS_OBJECT_NAME_COLLISION
            && matches!(disposition, FILE_OPEN_IF | FILE_SUPERSEDE | FILE_OVERWRITE_IF))
}

/// The create reply (the tail of dokan2.dll's DispatchCreate).
pub fn create(
    r: &mut [u8],
    serial: u32,
    disposition: u32,
    options: u32,
    open_target: bool,
    status: NtStatus,
    host: &MdCreateReply,
) -> usize {
    begin(r, serial, 0, 0);
    if !create_succeeded(status, disposition) {
        let info = if status == STATUS_OBJECT_NAME_COLLISION { FILE_EXISTS } else { FILE_DOES_NOT_EXIST };
        wr_u32(r, ei::CREATE_INFORMATION, info);
        set_status(r, status);
        // A failed create carries no context.
        return ei::SIZE;
    }
    let mut info = FILE_OPENED;
    if matches!(disposition, FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE) {
        info = FILE_CREATED;
        if status == STATUS_OBJECT_NAME_COLLISION {
            info = match disposition {
                FILE_OPEN_IF => FILE_OPENED,
                FILE_OVERWRITE_IF => FILE_OVERWRITTEN,
                FILE_SUPERSEDE => FILE_SUPERSEDED,
                _ => info,
            };
        }
    }
    if disposition == FILE_OVERWRITE {
        info = FILE_OVERWRITTEN;
    }
    // dokan2.dll means to answer FILE_DOES_NOT_EXIST for a missing rename
    // target, but overwrites it with FILE_OPENED; the host's flag decides here.
    if open_target && host.flags & MD_CREATE_TARGET_MISSING != 0 {
        info = FILE_DOES_NOT_EXIST;
    }
    wr_u32(r, ei::CREATE_INFORMATION, info);
    let is_dir = open_target || options & FILE_DIRECTORY_FILE != 0 || host.flags & MD_CREATE_IS_DIRECTORY != 0;
    if is_dir {
        wr_u32(r, ei::CREATE_FLAGS, DOKAN_FILE_DIRECTORY);
    }
    set_status(r, STATUS_SUCCESS);
    wr_u64(r, ei::CONTEXT, host.context);
    ei::SIZE
}

/// The read reply: the data is already in the data area (`bytes` of it).
pub fn read(r: &mut [u8], serial: u32, context: u64, offset: i64, length: u32, status: NtStatus, bytes: u32) -> usize {
    begin_header(r, serial, context);
    if status == STATUS_SUCCESS {
        if bytes == 0 {
            set_status(r, STATUS_END_OF_FILE);
        } else if bytes > length {
            // A host bug; never hand the driver more than it asked for.
            set_status(r, STATUS_INTERNAL_ERROR);
        } else {
            set_status(r, STATUS_SUCCESS);
            set_buffer_length(r, bytes);
            wr_i64(r, ei::CURRENT_BYTE_OFFSET, offset.wrapping_add(bytes as i64));
        }
    } else {
        set_status(r, status);
    }
    sized(r)
}

/// The write reply: `BufferLength` is the bytes written, and the reply is
/// always `sizeof(EVENT_INFORMATION)`.
pub fn write(r: &mut [u8], serial: u32, context: u64, offset: i64, status: NtStatus, written: u32) -> usize {
    begin(r, serial, context, 0);
    set_status(r, status);
    if status == STATUS_SUCCESS {
        set_buffer_length(r, written);
        wr_i64(r, ei::CURRENT_BYTE_OFFSET, offset.wrapping_add(written as i64));
    }
    ei::SIZE
}

/// The set-information reply: a disposition echoes DeletePending, a rename
/// hands the new name back to the driver (it renames its FCB with it).
pub fn set_info(
    r: &mut [u8],
    serial: u32,
    context: u64,
    class: u32,
    delete: bool,
    new_name: &[u16],
    status: NtStatus,
) -> usize {
    let is_rename = matches!(class, FILE_RENAME_INFORMATION | FILE_RENAME_INFORMATION_EX);
    let data = if is_rename && status == STATUS_SUCCESS { new_name.len() * 2 } else { 0 };
    begin(r, serial, context, data);
    set_status(r, status);
    if status == STATUS_SUCCESS {
        if matches!(class, FILE_DISPOSITION_INFORMATION | FILE_DISPOSITION_INFORMATION_EX) {
            wr_u8(r, ei::DELETE_PENDING, delete as u8);
        } else if is_rename {
            wr_utf16(r, ei::BUFFER, new_name);
            set_buffer_length(r, data as u32);
        }
    }
    sized(r)
}

/// The query-security reply. The descriptor (if any) is already in the data
/// area; `needed` is its length.
pub fn query_security(
    r: &mut [u8],
    serial: u32,
    context: u64,
    buffer_length: u32,
    status: NtStatus,
    needed: u32,
) -> usize {
    begin_header(r, serial, context);
    if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
        set_status(r, status);
        return ei::SIZE;
    }
    set_buffer_length(r, needed);
    if buffer_length < needed || status == STATUS_BUFFER_OVERFLOW {
        // "Filesystem Application should return STATUS_BUFFER_OVERFLOW in this
        // case." BufferLength is the length needed; no data follows.
        set_status(r, STATUS_BUFFER_OVERFLOW);
        return ei::SIZE;
    }
    set_status(r, STATUS_SUCCESS);
    sized(r)
}

/// The space a reply needs for its data area, given the request.
pub fn data_capacity(major: u8, request_length: u32) -> usize {
    match major {
        IRP_MJ_READ
        | IRP_MJ_QUERY_INFORMATION
        | IRP_MJ_DIRECTORY_CONTROL
        | IRP_MJ_QUERY_VOLUME_INFORMATION
        | IRP_MJ_QUERY_SECURITY => request_length as usize,
        _ => 0,
    }
}
