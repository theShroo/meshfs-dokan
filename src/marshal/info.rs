// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/fileinfo.c and dokan/volume.c:
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! File and volume information classes, encoded from the host's one answer.

use super::reply::{begin, set_buffer_length, set_status, sized};
use crate::abi::{MdFileInfo, MdVolumeInfo};
use crate::proto::*;

/// What the query-information dispatch does with a class: ask the host, or
/// answer at once (dokan2.dll answers these without useful host data).
pub enum QueryPlan {
    AskHost,
    Answer(NtStatus),
}

pub fn query_plan(class: u32) -> QueryPlan {
    match class {
        FILE_BASIC_INFORMATION
        | FILE_ID_INFORMATION
        | FILE_INTERNAL_INFORMATION
        | FILE_EA_INFORMATION
        | FILE_STANDARD_INFORMATION
        | FILE_ALL_INFORMATION
        | FILE_ATTRIBUTE_TAG_INFORMATION
        | FILE_NAME_INFORMATION
        | FILE_NORMALIZED_NAME_INFORMATION
        | FILE_NETWORK_OPEN_INFORMATION
        | FILE_POSITION_INFORMATION
        | FILE_STREAM_INFORMATION => QueryPlan::AskHost,
        FILE_ALTERNATE_NAME_INFORMATION | FILE_COMPRESSION_INFORMATION => QueryPlan::Answer(STATUS_NOT_IMPLEMENTED),
        _ => QueryPlan::Answer(STATUS_INVALID_PARAMETER),
    }
}

/// Whether the class needs the request's file name to be encoded.
pub fn needs_name(class: u32) -> bool {
    matches!(class, FILE_NAME_INFORMATION | FILE_NORMALIZED_NAME_INFORMATION)
}

/// ALIGN_ALLOCATION_SIZE, or the host's own allocation size.
pub fn allocation(size: u64, host_allocation: u64, unit: u32) -> u64 {
    if host_allocation != 0 {
        return host_allocation;
    }
    let unit = unit.max(1) as u64;
    let r = size % unit;
    if r > 0 { size.saturating_add(unit - r) } else { size }
}

fn change_time(fi: &MdFileInfo) -> u64 {
    if fi.change_time != 0 { fi.change_time } else { fi.last_write_time }
}

fn basic(b: &mut [u8], fi: &MdFileInfo) {
    wr_u64(b, 0, fi.creation_time);
    wr_u64(b, 8, fi.last_access_time);
    wr_u64(b, 16, fi.last_write_time);
    wr_u64(b, 24, change_time(fi));
    wr_u32(b, 32, fi.attributes);
}

fn standard(b: &mut [u8], fi: &MdFileInfo, unit: u32) {
    wr_u64(b, 0, allocation(fi.file_size, fi.allocation_size, unit));
    wr_u64(b, 8, fi.file_size);
    wr_u32(b, 16, fi.number_of_links);
    // DeletePending (20) is filled in by the driver.
    wr_u8(b, 21, (fi.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) as u8);
}

pub const SIZEOF_FILE_BASIC_INFORMATION: usize = 40;
pub const SIZEOF_FILE_STANDARD_INFORMATION: usize = 24;
pub const SIZEOF_FILE_INTERNAL_INFORMATION: usize = 8;
pub const SIZEOF_FILE_EA_INFORMATION: usize = 4;
pub const SIZEOF_FILE_POSITION_INFORMATION: usize = 8;
pub const SIZEOF_FILE_ALL_INFORMATION: usize = 104;
pub const OFFSETOF_FILE_ALL_INFORMATION_NAME: usize = 100;
pub const SIZEOF_FILE_NAME_INFORMATION: usize = 8;
pub const SIZEOF_FILE_ATTRIBUTE_TAG_INFORMATION: usize = 8;
pub const SIZEOF_FILE_NETWORK_OPEN_INFORMATION: usize = 56;
pub const SIZEOF_FILE_ID_INFORMATION: usize = 24;
pub const SIZEOF_FILE_STREAM_INFORMATION: usize = 32;

/// The query-information reply (DokanEndDispatchGetFileInformation). `name`
/// is the request's raw file name, used by the name classes.
#[allow(clippy::too_many_arguments)]
pub fn query_info(
    r: &mut [u8],
    serial: u32,
    context: u64,
    class: u32,
    buffer_length: u32,
    name: &[u16],
    status: NtStatus,
    fi: &MdFileInfo,
    allocation_unit: u32,
) -> usize {
    let cap = buffer_length as usize;
    begin(r, serial, context, cap);
    if status != STATUS_SUCCESS {
        // dokan2.dll answers every host failure with STATUS_INVALID_PARAMETER;
        // the host's own status is more useful and is passed on.
        set_status(r, status);
        return ei::SIZE;
    }
    let b = &mut r[ei::BUFFER..ei::BUFFER + cap];
    let fits = |n: usize| cap >= n;
    let (st, used) = match class {
        FILE_BASIC_INFORMATION if fits(SIZEOF_FILE_BASIC_INFORMATION) => {
            basic(b, fi);
            (STATUS_SUCCESS, SIZEOF_FILE_BASIC_INFORMATION)
        }
        FILE_ID_INFORMATION if fits(SIZEOF_FILE_ID_INFORMATION) => {
            wr_u64(b, 0, fi.volume_serial as u64);
            wr_u32(b, 8, fi.file_index as u32);
            wr_u32(b, 12, (fi.file_index >> 32) as u32);
            (STATUS_SUCCESS, SIZEOF_FILE_ID_INFORMATION)
        }
        FILE_INTERNAL_INFORMATION if fits(SIZEOF_FILE_INTERNAL_INFORMATION) => {
            wr_u64(b, 0, fi.file_index);
            (STATUS_SUCCESS, SIZEOF_FILE_INTERNAL_INFORMATION)
        }
        // "status = STATUS_NOT_IMPLEMENTED;" was dropped upstream: an empty EA.
        FILE_EA_INFORMATION => (STATUS_SUCCESS, SIZEOF_FILE_EA_INFORMATION.min(cap)),
        FILE_STANDARD_INFORMATION if fits(SIZEOF_FILE_STANDARD_INFORMATION) => {
            standard(b, fi, allocation_unit);
            (STATUS_SUCCESS, SIZEOF_FILE_STANDARD_INFORMATION)
        }
        FILE_ALL_INFORMATION if fits(SIZEOF_FILE_ALL_INFORMATION) => {
            basic(&mut b[0..], fi);
            standard(&mut b[40..], fi, allocation_unit);
            wr_u64(b, 64, fi.file_index);
            // EaSize (72), Access (76), Position (80), Mode, Alignment: zero;
            // the driver fills in the position and the name.
            (STATUS_SUCCESS, OFFSETOF_FILE_ALL_INFORMATION_NAME)
        }
        FILE_ATTRIBUTE_TAG_INFORMATION if fits(SIZEOF_FILE_ATTRIBUTE_TAG_INFORMATION) => {
            wr_u32(b, 0, fi.attributes);
            (STATUS_SUCCESS, SIZEOF_FILE_ATTRIBUTE_TAG_INFORMATION)
        }
        FILE_NAME_INFORMATION | FILE_NORMALIZED_NAME_INFORMATION
            if fits(SIZEOF_FILE_NAME_INFORMATION + name.len() * 2) =>
        {
            wr_u32(b, 0, (name.len() * 2) as u32);
            wr_utf16(b, 4, name);
            (STATUS_SUCCESS, 4 + name.len() * 2)
        }
        FILE_NETWORK_OPEN_INFORMATION if fits(SIZEOF_FILE_NETWORK_OPEN_INFORMATION) => {
            wr_u64(b, 0, fi.creation_time);
            wr_u64(b, 8, fi.last_access_time);
            wr_u64(b, 16, fi.last_write_time);
            wr_u64(b, 24, change_time(fi));
            wr_u64(b, 32, allocation(fi.file_size, fi.allocation_size, allocation_unit));
            wr_u64(b, 40, fi.file_size);
            wr_u32(b, 48, fi.attributes);
            (STATUS_SUCCESS, SIZEOF_FILE_NETWORK_OPEN_INFORMATION)
        }
        FILE_POSITION_INFORMATION if fits(SIZEOF_FILE_POSITION_INFORMATION) => {
            (STATUS_SUCCESS, SIZEOF_FILE_POSITION_INFORMATION)
        }
        FILE_STREAM_INFORMATION => stream(b, fi, allocation_unit),
        FILE_BASIC_INFORMATION
        | FILE_ID_INFORMATION
        | FILE_INTERNAL_INFORMATION
        | FILE_STANDARD_INFORMATION
        | FILE_ALL_INFORMATION
        | FILE_ATTRIBUTE_TAG_INFORMATION
        | FILE_NAME_INFORMATION
        | FILE_NORMALIZED_NAME_INFORMATION
        | FILE_NETWORK_OPEN_INFORMATION
        | FILE_POSITION_INFORMATION => (STATUS_BUFFER_OVERFLOW, 0),
        FILE_ALTERNATE_NAME_INFORMATION | FILE_COMPRESSION_INFORMATION => (STATUS_NOT_IMPLEMENTED, 0),
        _ => (STATUS_INVALID_PARAMETER, 0),
    };
    set_status(r, st);
    set_buffer_length(r, used as u32);
    sized(r)
}

/// FileStreamInformation without alternate streams: one `::$DATA` entry for a
/// file, none for a directory (dokan2.dll asks FindStreams; this library has
/// no streams, so it answers what NTFS would for a file without any).
fn stream(b: &mut [u8], fi: &MdFileInfo, unit: u32) -> (NtStatus, usize) {
    if b.len() < SIZEOF_FILE_STREAM_INFORMATION {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    if fi.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return (STATUS_SUCCESS, 0);
    }
    let name: Vec<u16> = "::$DATA".encode_utf16().collect();
    let size = quad_align(24 + name.len() * 2);
    if b.len() < size {
        return (STATUS_BUFFER_OVERFLOW, 0);
    }
    // NextEntryOffset 0, StreamNameLength, StreamSize, AllocationSize, name.
    wr_u32(b, 0, 0);
    wr_u32(b, 4, (name.len() * 2) as u32);
    wr_u64(b, 8, fi.file_size);
    wr_u64(b, 16, allocation(fi.file_size, fi.allocation_size, unit));
    wr_utf16(b, 24, &name);
    (STATUS_SUCCESS, 24 + name.len() * 2)
}

/// FileStreamInformation from the host's `find_streams` (ABI 1.1, named
/// streams on): the entries are written straight into the reply's data
/// area as the host reports them (no copy, no allocation), each 8-aligned
/// and chained by NextEntryOffset, in the NTFS form `::$DATA` /
/// `:name:$DATA`. Entries that do not fit are left out and the answer is
/// STATUS_BUFFER_OVERFLOW (NTFS's partial answer).
pub struct StreamWriter<'a> {
    b: &'a mut [u8],
    unit: u32,
    /// Where the last entry starts, and its unpadded end.
    last: Option<(usize, usize)>,
    overflow: bool,
}

const DATA_SUFFIX: [u16; 6] = [b':' as u16, b'$' as u16, b'D' as u16, b'A' as u16, b'T' as u16, b'A' as u16];

impl<'a> StreamWriter<'a> {
    pub fn new(b: &'a mut [u8], unit: u32) -> StreamWriter<'a> {
        StreamWriter { b, unit, last: None, overflow: false }
    }

    /// Adds one stream (`name` bare; empty = the unnamed data stream).
    /// False once the buffer is full (later pushes are dropped too).
    pub fn push(&mut self, name: &[u16], size: u64, allocation_size: u64) -> bool {
        if self.overflow {
            return false;
        }
        let at = match self.last {
            Some((_, end)) => quad_align(end),
            None => 0,
        };
        let units = 1 + name.len() + DATA_SUFFIX.len();
        let end = at + 24 + units * 2;
        if end > self.b.len() {
            self.overflow = true;
            return false;
        }
        if let Some((prev, _)) = self.last {
            wr_u32(self.b, prev, (at - prev) as u32);
        }
        wr_u32(self.b, at, 0);
        wr_u32(self.b, at + 4, (units * 2) as u32);
        wr_u64(self.b, at + 8, size);
        wr_u64(self.b, at + 16, allocation(size, allocation_size, self.unit));
        wr_utf16(self.b, at + 24, &[b':' as u16]);
        wr_utf16(self.b, at + 26, name);
        wr_utf16(self.b, at + 26 + name.len() * 2, &DATA_SUFFIX);
        self.last = Some((at, end));
        true
    }

    /// (status, bytes used)
    pub fn finish(&self) -> (NtStatus, usize) {
        let used = self.last.map_or(0, |(_, end)| end);
        if self.overflow {
            if self.last.is_none() && self.b.len() < SIZEOF_FILE_STREAM_INFORMATION {
                return (STATUS_BUFFER_TOO_SMALL, 0);
            }
            return (STATUS_BUFFER_OVERFLOW, used);
        }
        (STATUS_SUCCESS, used)
    }
}

/// The FileStreamInformation reply with named streams on: `f` asks the
/// host (it fills the writer) and returns the host's status.
pub fn query_streams(
    r: &mut [u8],
    serial: u32,
    context: u64,
    buffer_length: u32,
    allocation_unit: u32,
    f: impl FnOnce(&mut StreamWriter<'_>) -> NtStatus,
) -> usize {
    let cap = buffer_length as usize;
    begin(r, serial, context, cap);
    let (st, used) = {
        let mut w = StreamWriter::new(&mut r[ei::BUFFER..ei::BUFFER + cap], allocation_unit);
        let st = f(&mut w);
        if st == STATUS_SUCCESS { w.finish() } else { (st, 0) }
    };
    set_status(r, st);
    if st != STATUS_SUCCESS && st != STATUS_BUFFER_OVERFLOW {
        return ei::SIZE;
    }
    set_buffer_length(r, used as u32);
    sized(r)
}

/// dokan2.dll's defaults when the host does not answer volume queries.
pub fn default_volume() -> MdVolumeInfo {
    let mut v = MdVolumeInfo {
        total_bytes: 1024 * 1024 * 1024,
        free_bytes: 512 * 1024 * 1024,
        available_bytes: 512 * 1024 * 1024,
        serial: 0x1983_1116,
        max_component_length: 256,
        // FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
        // FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK
        fs_flags: 0x1 | 0x2 | 0x100 | 0x4,
        ..MdVolumeInfo::default()
    };
    for (i, c) in "DOKAN".encode_utf16().enumerate() {
        v.label[i] = c;
    }
    v.label_len = 5;
    for (i, c) in "NTFS".encode_utf16().enumerate() {
        v.fs_name[i] = c;
    }
    v.fs_name_len = 4;
    v
}

pub const SIZEOF_FILE_FS_VOLUME_INFORMATION: usize = 24;
pub const OFFSETOF_FILE_FS_VOLUME_INFORMATION_LABEL: usize = 18;
pub const SIZEOF_FILE_FS_SIZE_INFORMATION: usize = 24;
pub const SIZEOF_FILE_FS_ATTRIBUTE_INFORMATION: usize = 16;
pub const OFFSETOF_FILE_FS_ATTRIBUTE_INFORMATION_NAME: usize = 12;
pub const SIZEOF_FILE_FS_FULL_SIZE_INFORMATION: usize = 32;

/// The volume-information reply (DispatchQueryVolumeInformation). `status`
/// and `v` are the host's answer, already replaced by the defaults when the
/// host answered STATUS_NOT_IMPLEMENTED.
#[allow(clippy::too_many_arguments)]
pub fn query_volume(
    r: &mut [u8],
    serial: u32,
    context: u64,
    class: u32,
    buffer_length: u32,
    status: NtStatus,
    v: &MdVolumeInfo,
    sector_size: u32,
    allocation_unit: u32,
) -> usize {
    let cap = buffer_length as usize;
    begin(r, serial, context, cap);
    let b = &mut r[ei::BUFFER..ei::BUFFER + cap];
    let unit = allocation_unit.max(1) as u64;
    let label = &v.label[..(v.label_len as usize).min(v.label.len())];
    let fs_name = &v.fs_name[..(v.fs_name_len as usize).min(v.fs_name.len())];
    let (st, used) = match class {
        FILE_FS_VOLUME_INFORMATION => {
            if cap < SIZEOF_FILE_FS_VOLUME_INFORMATION {
                (STATUS_BUFFER_OVERFLOW, 0)
            } else {
                // dokan2.dll ignores the host's status for this class.
                wr_u64(b, 0, 0);
                wr_u32(b, 8, v.serial);
                let room = cap - OFFSETOF_FILE_FS_VOLUME_INFORMATION_LABEL;
                let bytes = (label.len() * 2).min(room) / 2 * 2;
                wr_u32(b, 12, bytes as u32);
                wr_u8(b, 16, 0);
                wr_utf16(b, OFFSETOF_FILE_FS_VOLUME_INFORMATION_LABEL, &label[..bytes / 2]);
                (STATUS_SUCCESS, OFFSETOF_FILE_FS_VOLUME_INFORMATION_LABEL + bytes)
            }
        }
        FILE_FS_SIZE_INFORMATION => {
            if cap < SIZEOF_FILE_FS_SIZE_INFORMATION {
                (STATUS_BUFFER_OVERFLOW, 0)
            } else if status != STATUS_SUCCESS {
                (status, 0)
            } else {
                wr_u64(b, 0, v.total_bytes / unit);
                wr_u64(b, 8, v.available_bytes / unit);
                wr_u32(b, 16, allocation_unit / sector_size.max(1));
                wr_u32(b, 20, sector_size);
                (STATUS_SUCCESS, SIZEOF_FILE_FS_SIZE_INFORMATION)
            }
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            if cap < SIZEOF_FILE_FS_ATTRIBUTE_INFORMATION {
                (STATUS_BUFFER_OVERFLOW, 0)
            } else if status != STATUS_SUCCESS {
                (status, 0)
            } else {
                wr_u32(b, 0, v.fs_flags);
                wr_u32(b, 4, v.max_component_length);
                let room = cap - OFFSETOF_FILE_FS_ATTRIBUTE_INFORMATION_NAME;
                let mut st = STATUS_SUCCESS;
                let mut bytes = fs_name.len() * 2;
                if room < bytes {
                    bytes = room / 2 * 2;
                    st = STATUS_BUFFER_OVERFLOW;
                }
                wr_u32(b, 8, bytes as u32);
                wr_utf16(b, OFFSETOF_FILE_FS_ATTRIBUTE_INFORMATION_NAME, &fs_name[..bytes / 2]);
                (st, OFFSETOF_FILE_FS_ATTRIBUTE_INFORMATION_NAME + bytes)
            }
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            if cap < SIZEOF_FILE_FS_FULL_SIZE_INFORMATION {
                (STATUS_BUFFER_OVERFLOW, 0)
            } else if status != STATUS_SUCCESS {
                (status, 0)
            } else {
                wr_u64(b, 0, v.total_bytes / unit);
                wr_u64(b, 8, v.available_bytes / unit);
                wr_u64(b, 16, v.free_bytes / unit);
                wr_u32(b, 24, allocation_unit / sector_size.max(1));
                wr_u32(b, 28, sector_size);
                (STATUS_SUCCESS, SIZEOF_FILE_FS_FULL_SIZE_INFORMATION)
            }
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    };
    set_status(r, st);
    set_buffer_length(r, used as u32);
    sized(r)
}
