// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 sys/public.h:
//   Copyright (C) 2017 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! The driver's protocol: IOCTL codes, flags and the byte layouts of the
//! structures `dokan2.sys` exchanges with user mode (x64), from `sys/public.h`.
//!
//! Layouts are given as byte offsets so the decoders and encoders work on plain
//! byte slices on any platform (the unit tests run on the build host). The
//! Windows tests check every offset against the SDK's own definitions.

/// The protocol versions this library speaks: `FSCTL_GET_VERSION`'s answer and
/// the `EVENT_START.UserVersion` that must equal it. One entry per tested
/// Dokany release; a layout change means a new entry (design 4.1.7).
pub const SUPPORTED_DRIVER_VERSIONS: &[(u32, &str)] = &[(0x190, "Dokany 2.3.1")];

pub const DOKAN_GLOBAL_DEVICE_NAME: &str = r"\\.\Dokan_2";
pub const DOKAN_KEEPALIVE_FILE_NAME: &str = r"\__drive_fs_keepalive";
pub const DOKAN_NOTIFICATION_FILE_NAME: &str = r"\drive_fs_notification";

const FILE_DEVICE_FILE_SYSTEM: u32 = 0x9;
const METHOD_BUFFERED: u32 = 0;
const METHOD_OUT_DIRECT: u32 = 2;
const fn ctl_code(function: u32, method: u32) -> u32 {
    (FILE_DEVICE_FILE_SYSTEM << 16) | (function << 2) | method // FILE_ANY_ACCESS = 0
}
pub const FSCTL_GET_VERSION: u32 = ctl_code(0x800, METHOD_BUFFERED);
pub const FSCTL_EVENT_RELEASE: u32 = ctl_code(0x804, METHOD_BUFFERED);
pub const FSCTL_EVENT_START: u32 = ctl_code(0x805, METHOD_BUFFERED);
pub const FSCTL_EVENT_WRITE: u32 = ctl_code(0x806, METHOD_OUT_DIRECT);
pub const FSCTL_RESET_TIMEOUT: u32 = ctl_code(0x80B, METHOD_BUFFERED);
pub const FSCTL_GET_ACCESS_TOKEN: u32 = ctl_code(0x80C, METHOD_BUFFERED);
pub const FSCTL_ACTIVATE_KEEPALIVE: u32 = ctl_code(0x80F, METHOD_BUFFERED);
pub const FSCTL_NOTIFY_PATH: u32 = ctl_code(0x810, METHOD_BUFFERED);
pub const FSCTL_GET_VOLUME_METRICS: u32 = ctl_code(0x811, METHOD_BUFFERED);
pub const FSCTL_EVENT_PROCESS_N_PULL: u32 = ctl_code(0x812, METHOD_BUFFERED);

pub const EVENT_CONTEXT_MAX_SIZE: usize = 32 * 1024;
pub const VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE: usize = 16 * 1024;
/// dokan2.dll's pull buffer (`BATCH_EVENT_CONTEXT_SIZE`). Any event but a
/// large-write stub fits in `EVENT_CONTEXT_MAX_SIZE`; the buffer must never be
/// smaller, or the driver re-queues the event and the pull returns nothing.
pub const PULL_BUFFER_SIZE: usize = EVENT_CONTEXT_MAX_SIZE * 4;
/// The pull buffer used normally: any event but a large-write stub for a
/// path of more than ~16k characters fits (the driver refuses any other
/// event above EVENT_CONTEXT_MAX_SIZE, DokanRegisterPendingIrp).
pub const PULL_SMALL: usize = EVENT_CONTEXT_MAX_SIZE;

// EVENT_DRIVER_INFO.Status
pub const DOKAN_MOUNTED: u32 = 1;
pub const DOKAN_USED: u32 = 2;
pub const DOKAN_START_FAILED: u32 = 3;

pub const DOKAN_DEFAULT_SECTOR_SIZE: u32 = 512;
pub const DOKAN_DEFAULT_ALLOCATION_UNIT_SIZE: u32 = 512;

// EVENT_CONTEXT.FileFlags (CCB/FCB flags)
pub const DOKAN_FILE_DIRECTORY: u32 = 1;
pub const DOKAN_DELETE_ON_CLOSE: u32 = 16;
pub const DOKAN_PAGING_IO: u32 = 32;
pub const DOKAN_SYNCHRONOUS_IO: u32 = 64;
pub const DOKAN_WRITE_TO_END_OF_FILE: u32 = 128;
pub const DOKAN_NOCACHE: u32 = 256;

// EVENT_START.DeviceType
pub const DOKAN_DISK_FILE_SYSTEM: u32 = 0;
pub const DOKAN_NETWORK_FILE_SYSTEM: u32 = 1;

// EVENT_START.Flags
pub const DOKAN_EVENT_ALTERNATIVE_STREAM_ON: u32 = 1;
pub const DOKAN_EVENT_WRITE_PROTECT: u32 = 1 << 1;
pub const DOKAN_EVENT_REMOVABLE: u32 = 1 << 2;
pub const DOKAN_EVENT_MOUNT_MANAGER: u32 = 1 << 3;
pub const DOKAN_EVENT_CURRENT_SESSION: u32 = 1 << 4;
pub const DOKAN_EVENT_FILELOCK_USER_MODE: u32 = 1 << 5;
pub const DOKAN_EVENT_CASE_SENSITIVE: u32 = 1 << 6;
pub const DOKAN_EVENT_ENABLE_NETWORK_UNMOUNT: u32 = 1 << 7;
pub const DOKAN_EVENT_DISPATCH_DRIVER_LOGS: u32 = 1 << 8;
pub const DOKAN_EVENT_ALLOW_IPC_BATCHING: u32 = 1 << 9;
pub const DOKAN_EVENT_DRIVE_LETTER_IN_USE: u32 = 1 << 10;

/// Driver custom major function: a log line (only with DISPATCH_DRIVER_LOGS).
pub const DOKAN_IRP_LOG_MESSAGE: u8 = 0x20;

// IRP major/minor functions (wdm.h)
pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0a;
pub const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0c;
pub const IRP_MJ_LOCK_CONTROL: u8 = 0x11;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_QUERY_SECURITY: u8 = 0x14;
pub const IRP_MJ_SET_SECURITY: u8 = 0x15;
pub const IRP_MN_LOCK: u8 = 1;
pub const IRP_MN_UNLOCK_SINGLE: u8 = 2;

// IO_STACK_LOCATION.Flags (EVENT_CONTEXT.Flags)
pub const SL_RESTART_SCAN: u32 = 0x01;
pub const SL_RETURN_SINGLE_ENTRY: u32 = 0x02;
pub const SL_INDEX_SPECIFIED: u32 = 0x04;
pub const SL_OPEN_TARGET_DIRECTORY: u32 = 0x04; // on IRP_MJ_CREATE
pub const SL_CASE_SENSITIVE: u32 = 0x80; // on IRP_MJ_CREATE

// Create dispositions, options and results
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_VALID_OPTION_FLAGS: u32 = 0x00ff_ffff;
pub const FILE_SUPERSEDED: u32 = 0;
pub const FILE_OPENED: u32 = 1;
pub const FILE_CREATED: u32 = 2;
pub const FILE_OVERWRITTEN: u32 = 3;
pub const FILE_EXISTS: u32 = 4;
pub const FILE_DOES_NOT_EXIST: u32 = 5;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

// NTSTATUS values used by the protocol
pub type NtStatus = i32;
pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_PENDING: NtStatus = 0x0000_0103;
pub const STATUS_BUFFER_OVERFLOW: NtStatus = 0x8000_0005_u32 as i32;
pub const STATUS_NO_MORE_FILES: NtStatus = 0x8000_0006_u32 as i32;
pub const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC000_0002_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D_u32 as i32;
pub const STATUS_NO_SUCH_DEVICE: NtStatus = 0xC000_000E_u32 as i32;
pub const STATUS_NO_SUCH_FILE: NtStatus = 0xC000_000F_u32 as i32;
pub const STATUS_END_OF_FILE: NtStatus = 0xC000_0011_u32 as i32;
pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017_u32 as i32;
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC000_0022_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023_u32 as i32;
/// FILE_FS_ATTRIBUTE_INFORMATION.FileSystemAttributes: alternate streams.
pub const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034_u32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035_u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009A_u32 as i32;
pub const STATUS_INTERNAL_ERROR: NtStatus = 0xC000_00E5_u32 as i32;
pub const STATUS_CANCELLED: NtStatus = 0xC000_0120_u32 as i32;
pub const STATUS_NOT_FOUND: NtStatus = 0xC000_0225_u32 as i32;

/// NT_SUCCESS: success and informational codes.
pub const fn nt_success(s: NtStatus) -> bool {
    s >= 0
}

// FILE_INFORMATION_CLASS
pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
pub const FILE_INTERNAL_INFORMATION: u32 = 6;
pub const FILE_EA_INFORMATION: u32 = 7;
pub const FILE_NAME_INFORMATION: u32 = 9;
pub const FILE_RENAME_INFORMATION: u32 = 10;
pub const FILE_NAMES_INFORMATION: u32 = 12;
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_POSITION_INFORMATION: u32 = 14;
pub const FILE_ALL_INFORMATION: u32 = 18;
pub const FILE_ALLOCATION_INFORMATION: u32 = 19;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 20;
pub const FILE_ALTERNATE_NAME_INFORMATION: u32 = 21;
pub const FILE_STREAM_INFORMATION: u32 = 22;
pub const FILE_COMPRESSION_INFORMATION: u32 = 28;
pub const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u32 = 35;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u32 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u32 = 38;
pub const FILE_VALID_DATA_LENGTH_INFORMATION: u32 = 39;
pub const FILE_NORMALIZED_NAME_INFORMATION: u32 = 48;
pub const FILE_ID_INFORMATION: u32 = 59;
pub const FILE_ID_EXTD_DIRECTORY_INFORMATION: u32 = 60;
pub const FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION: u32 = 63;
pub const FILE_DISPOSITION_INFORMATION_EX: u32 = 64;
pub const FILE_RENAME_INFORMATION_EX: u32 = 65;
pub const FILE_DISPOSITION_DELETE: u32 = 0x1;

// FS_INFORMATION_CLASS
pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;

/// `EVENT_CONTEXT` (x64). The union `Operation` starts at 40 (8-aligned) and is
/// 136 bytes (its largest member is `UNMOUNT_CONTEXT`), so `sizeof` is 176.
pub mod ec {
    pub const LENGTH: usize = 0;
    pub const MOUNT_ID: usize = 4;
    pub const SERIAL_NUMBER: usize = 8;
    pub const PROCESS_ID: usize = 12;
    pub const MAJOR_FUNCTION: usize = 16;
    pub const MINOR_FUNCTION: usize = 17;
    pub const FLAGS: usize = 20;
    pub const FILE_FLAGS: usize = 24;
    pub const CONTEXT: usize = 32;
    pub const OPERATION: usize = 40;
    pub const SIZE: usize = 176;

    /// `DIRECTORY_CONTEXT`. The pattern lies at `SEARCH_PATTERN_BASE +
    /// SearchPatternOffset` (the driver sets the offset to the name's length).
    pub mod dir {
        pub const FILE_INFORMATION_CLASS: usize = 40;
        pub const FILE_INDEX: usize = 44;
        pub const BUFFER_LENGTH: usize = 48;
        pub const DIRECTORY_NAME_LENGTH: usize = 52;
        pub const SEARCH_PATTERN_LENGTH: usize = 56;
        pub const SEARCH_PATTERN_OFFSET: usize = 60;
        pub const DIRECTORY_NAME: usize = 64;
        pub const SEARCH_PATTERN_BASE: usize = 66;
    }
    pub mod read {
        pub const BYTE_OFFSET: usize = 40;
        pub const BUFFER_LENGTH: usize = 48;
        pub const FILE_NAME_LENGTH: usize = 52;
        pub const FILE_NAME: usize = 56;
    }
    /// `WRITE_CONTEXT`: the data lies at `EVENT_CONTEXT + BufferOffset`.
    pub mod write {
        pub const BYTE_OFFSET: usize = 40;
        pub const BUFFER_LENGTH: usize = 48;
        pub const BUFFER_OFFSET: usize = 52;
        pub const REQUEST_LENGTH: usize = 56;
        pub const FILE_NAME_LENGTH: usize = 60;
        pub const FILE_NAME: usize = 64;
    }
    /// `FILEINFO_CONTEXT`
    pub mod file {
        pub const FILE_INFORMATION_CLASS: usize = 40;
        pub const BUFFER_LENGTH: usize = 44;
        pub const FILE_NAME_LENGTH: usize = 48;
        pub const FILE_NAME: usize = 52;
    }
    /// `CREATE_CONTEXT`. Offsets inside the access state are relative to it
    /// (40); the file name lies at `40 + FileNameOffset`.
    pub mod create {
        pub const ACCESS_STATE: usize = 40;
        pub const SECURITY_EVALUATED: usize = 40;
        pub const ACCESS_STATE_FLAGS: usize = 44;
        pub const REMAINING_DESIRED_ACCESS: usize = 48;
        pub const PREVIOUSLY_GRANTED_ACCESS: usize = 52;
        pub const ORIGINAL_DESIRED_ACCESS: usize = 56;
        pub const SECURITY_DESCRIPTOR_OFFSET: usize = 60;
        pub const OBJECT_NAME_OFFSET: usize = 64;
        pub const OBJECT_TYPE_OFFSET: usize = 68;
        pub const DESIRED_ACCESS: usize = 72;
        pub const FILE_ATTRIBUTES: usize = 76;
        pub const CREATE_OPTIONS: usize = 80;
        pub const SHARE_ACCESS: usize = 84;
        pub const FILE_NAME_LENGTH: usize = 88;
        pub const FILE_NAME_OFFSET: usize = 92;
        pub const BASE: usize = 40;
    }
    /// `CLEANUP_CONTEXT`, `CLOSE_CONTEXT`, `FLUSH_CONTEXT`
    pub mod name_only {
        pub const FILE_NAME_LENGTH: usize = 40;
        pub const FILE_NAME: usize = 44;
    }
    /// `SETFILE_CONTEXT`: the information lies at `EVENT_CONTEXT + BufferOffset`.
    pub mod setfile {
        pub const FILE_INFORMATION_CLASS: usize = 40;
        pub const BUFFER_LENGTH: usize = 44;
        pub const BUFFER_OFFSET: usize = 48;
        pub const FILE_NAME_LENGTH: usize = 52;
        pub const FILE_NAME: usize = 56;
    }
    pub mod lock {
        pub const BYTE_OFFSET: usize = 40;
        pub const LENGTH: usize = 48;
        pub const KEY: usize = 56;
        pub const FILE_NAME_LENGTH: usize = 60;
        pub const FILE_NAME: usize = 64;
    }
    pub mod volume {
        pub const FS_INFORMATION_CLASS: usize = 40;
        pub const BUFFER_LENGTH: usize = 44;
    }
    pub mod security {
        pub const SECURITY_INFORMATION: usize = 40;
        pub const BUFFER_LENGTH: usize = 44;
        pub const FILE_NAME_LENGTH: usize = 48;
        pub const FILE_NAME: usize = 52;
    }
    /// `SET_SECURITY_CONTEXT`: the descriptor lies at `EVENT_CONTEXT + BufferOffset`.
    pub mod set_security {
        pub const SECURITY_INFORMATION: usize = 40;
        pub const BUFFER_LENGTH: usize = 44;
        pub const BUFFER_OFFSET: usize = 48;
        pub const FILE_NAME_LENGTH: usize = 52;
        pub const FILE_NAME: usize = 56;
    }
}

/// `EVENT_INFORMATION` (x64): the reply. `Buffer` starts at 40; `sizeof` is 48.
pub mod ei {
    pub const SERIAL_NUMBER: usize = 0;
    pub const STATUS: usize = 4;
    pub const FLAGS: usize = 8;
    pub const OPERATION: usize = 16;
    pub const DIRECTORY_INDEX: usize = 16;
    pub const CREATE_FLAGS: usize = 16;
    pub const CREATE_INFORMATION: usize = 20;
    pub const CURRENT_BYTE_OFFSET: usize = 16;
    pub const DELETE_PENDING: usize = 16;
    pub const RESET_TIMEOUT: usize = 16;
    pub const ACCESS_TOKEN_HANDLE: usize = 16;
    pub const CONTEXT: usize = 24;
    pub const BUFFER_LENGTH: usize = 32;
    pub const PULL_EVENT_TIMEOUT_MS: usize = 36;
    pub const BUFFER: usize = 40;
    pub const SIZE: usize = 48;
}

/// `EVENT_START` (x64).
pub mod es {
    pub const USER_VERSION: usize = 0;
    pub const DEVICE_TYPE: usize = 4;
    pub const FLAGS: usize = 8;
    pub const MOUNT_POINT: usize = 12;
    pub const MOUNT_POINT_CHARS: usize = 260;
    pub const UNC_NAME: usize = 532;
    pub const UNC_NAME_CHARS: usize = 64;
    pub const IRP_TIMEOUT: usize = 660;
    pub const FCB_GC_INTERVAL_MS: usize = 664;
    pub const VOLUME_SECURITY_DESCRIPTOR_LENGTH: usize = 668;
    pub const VOLUME_SECURITY_DESCRIPTOR: usize = 672;
    pub const SIZE: usize = 672 + super::VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE;
}

/// `EVENT_DRIVER_INFO` (x64).
pub mod edi {
    pub const DRIVER_VERSION: usize = 0;
    pub const STATUS: usize = 4;
    pub const FLAGS: usize = 8;
    pub const DEVICE_NUMBER: usize = 12;
    pub const MOUNT_ID: usize = 16;
    pub const DEVICE_NAME: usize = 20;
    pub const DEVICE_NAME_CHARS: usize = 64;
    pub const ACTUAL_DRIVE_LETTER: usize = 148;
    pub const SIZE: usize = 152;
}

/// `DOKAN_NOTIFY_PATH_INTERMEDIATE`: the path (relative to the volume) at 10.
pub mod notify {
    pub const COMPLETION_FILTER: usize = 0;
    pub const ACTION: usize = 4;
    pub const LENGTH: usize = 8;
    pub const BUFFER: usize = 10;
    pub const SIZE: usize = 12;
}

/// `DOKAN_UNICODE_STRING_INTERMEDIATE`: Length, MaximumLength, then the text.
pub mod ustr {
    pub const LENGTH: usize = 0;
    pub const MAXIMUM_LENGTH: usize = 2;
    pub const BUFFER: usize = 4;
    pub const SIZE: usize = 6;
}

/// `DOKAN_RENAME_INFORMATION`: ReplaceIfExists (or Ex flags), length, name.
pub mod rename {
    pub const REPLACE_IF_EXISTS: usize = 0;
    pub const FILE_NAME_LENGTH: usize = 4;
    pub const FILE_NAME: usize = 8;
}

// ---------------------------------------------------------------------------
// Little-endian field access on byte slices. Every read is bounds-checked: the
// input comes from the kernel, but it is parsed defensively anyway.

#[inline]
pub fn rd_u8(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}
#[inline]
pub fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}
#[inline]
pub fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}
#[inline]
pub fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off.checked_add(8)?)?.try_into().ok()?))
}
#[inline]
pub fn rd_i64(b: &[u8], off: usize) -> Option<i64> {
    rd_u64(b, off).map(|v| v as i64)
}

#[inline]
pub fn wr_u8(b: &mut [u8], off: usize, v: u8) {
    b[off] = v;
}
#[inline]
pub fn wr_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn wr_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn wr_i32(b: &mut [u8], off: usize, v: i32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn wr_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn wr_i64(b: &mut [u8], off: usize, v: i64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
/// Writes UTF-16 code units, little-endian.
pub fn wr_utf16(b: &mut [u8], off: usize, s: &[u16]) {
    for (i, c) in s.iter().enumerate() {
        wr_u16(b, off + 2 * i, *c);
    }
}
/// Reads `len` UTF-16 code units at `off`.
pub fn rd_utf16(b: &[u8], off: usize, len: usize) -> Option<Vec<u16>> {
    let bytes = b.get(off..off.checked_add(len.checked_mul(2)?)?)?;
    Some(bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect())
}

/// `QuadAlign`
pub const fn quad_align(n: usize) -> usize {
    (n + 7) & !7
}
