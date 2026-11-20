// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/directory.c:
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Directory listings: the per-open listing kept between queries (dokan2.dll's
//! DOKAN_OPEN_INFO.DirList), wildcard filtering, the resume index and the
//! eight directory information classes.

use super::info::allocation;
use super::pattern::is_name_in_expression;
use super::reply::{begin, set_buffer_length, set_status, sized};
use crate::proto::*;

/// One directory entry, owned (dokan2.dll's WIN32_FIND_DATAW).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    pub name: Vec<u16>,
    pub attributes: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_size: u64,
    pub allocation_size: u64,
    pub file_id: u64,
}

/// The listing kept per open between queries.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub pattern: Option<Vec<u16>>,
}

pub fn class_supported(class: u32) -> bool {
    matches!(
        class,
        FILE_DIRECTORY_INFORMATION
            | FILE_FULL_DIRECTORY_INFORMATION
            | FILE_BOTH_DIRECTORY_INFORMATION
            | FILE_NAMES_INFORMATION
            | FILE_ID_BOTH_DIRECTORY_INFORMATION
            | FILE_ID_FULL_DIRECTORY_INFORMATION
            | FILE_ID_EXTD_DIRECTORY_INFORMATION
            | FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION
    )
}

const STAR: [u16; 1] = [b'*' as u16];

/// Whether a query must list the directory again rather than resume from the
/// listing kept for the open (dokan2.dll's forceScan).
pub fn force_scan(kept: Option<&Listing>, pattern: Option<&[u16]>, irp_flags: u32) -> bool {
    let force = match kept {
        None => true,
        Some(l) => match (pattern, l.pattern.as_deref()) {
            (Some(p), Some(k)) => p != k,
            (Some(p), None) => p != STAR,
            (None, Some(k)) => k != STAR,
            (None, None) => false,
        },
    };
    // In FastFat SL_INDEX_SPECIFIED overrides SL_RESTART_SCAN.
    force || (irp_flags & SL_INDEX_SPECIFIED == 0 && irp_flags & SL_RESTART_SCAN != 0)
}

/// AddMissingCurrentAndParentFolder: "." and ".." go first in a listing of a
/// directory other than the root, unless a pattern other than "*" is used.
pub fn add_dots(entries: &mut Vec<Entry>, dir_is_root: bool, pattern: Option<&[u16]>, now: u64) {
    if dir_is_root || pattern.is_some_and(|p| p != STAR) {
        return;
    }
    let dot: Vec<u16> = vec![b'.' as u16];
    let dotdot: Vec<u16> = vec![b'.' as u16, b'.' as u16];
    let has_dot = entries.iter().any(|e| e.name == dot);
    let has_dotdot = entries.iter().any(|e| e.name == dotdot);
    let mk = |name: Vec<u16>| Entry {
        name,
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        creation_time: now,
        last_access_time: now,
        last_write_time: now,
        ..Entry::default()
    };
    if !has_dot || !has_dotdot {
        if !has_dotdot {
            entries.insert(0, mk(dotdot));
        }
        if !has_dot {
            entries.insert(0, mk(dot));
        }
    }
}

/// (sizeof, FileName offset) of each directory information class.
pub fn layout(class: u32) -> (usize, usize) {
    match class {
        FILE_DIRECTORY_INFORMATION => (72, 64),
        FILE_FULL_DIRECTORY_INFORMATION => (72, 68),
        FILE_ID_FULL_DIRECTORY_INFORMATION => (88, 80),
        FILE_NAMES_INFORMATION => (16, 12),
        FILE_BOTH_DIRECTORY_INFORMATION => (96, 94),
        FILE_ID_BOTH_DIRECTORY_INFORMATION => (112, 104),
        FILE_ID_EXTD_DIRECTORY_INFORMATION => (96, 88),
        FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION => (120, 114),
        _ => (0, 0),
    }
}

/// DokanFillDirectoryInformation: writes one entry at the start of `b` and
/// returns its (8-aligned) size, or 0 if it does not fit in `remaining`.
pub fn fill_entry(class: u32, b: &mut [u8], remaining: &mut usize, e: &Entry, index: u32, unit: u32) -> usize {
    let (size, name_off) = layout(class);
    let name_bytes = e.name.len() * 2;
    let this = quad_align(size + name_bytes);
    if *remaining < this || b.len() < this {
        return 0;
    }
    b[..this].fill(0);
    wr_u32(b, 4, index); // FileIndex
    if class == FILE_NAMES_INFORMATION {
        wr_u32(b, 8, name_bytes as u32);
    } else {
        let change = if e.change_time != 0 { e.change_time } else { e.last_write_time };
        wr_u64(b, 8, e.creation_time);
        wr_u64(b, 16, e.last_access_time);
        wr_u64(b, 24, e.last_write_time);
        wr_u64(b, 32, change);
        wr_u64(b, 40, e.file_size);
        wr_u64(b, 48, allocation(e.file_size, e.allocation_size, unit));
        wr_u32(b, 56, e.attributes);
        wr_u32(b, 60, name_bytes as u32);
        // EaSize (64), ShortNameLength and ReparsePointTag stay 0.
        match class {
            FILE_ID_FULL_DIRECTORY_INFORMATION => wr_u64(b, 72, e.file_id),
            FILE_ID_BOTH_DIRECTORY_INFORMATION => wr_u64(b, 96, e.file_id),
            FILE_ID_EXTD_DIRECTORY_INFORMATION | FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION => {
                wr_u64(b, 72, e.file_id) // FILE_ID_128, low half
            }
            _ => {}
        }
    }
    wr_utf16(b, name_off, &e.name);
    *remaining -= this;
    this
}

/// The parameters of one directory query.
#[derive(Debug, Clone, Copy)]
pub struct Query<'a> {
    pub class: u32,
    pub index: u32,
    pub irp_flags: u32,
    pub buffer_length: u32,
    pub pattern: Option<&'a [u16]>,
    pub case_sensitive: bool,
    pub allocation_unit: u32,
}

/// MatchFiles + WriteDirectoryResults: encodes entries from the resume index
/// on into the reply and sets the status and the next index.
pub fn write_results(r: &mut [u8], serial: u32, context: u64, q: &Query, entries: &[Entry]) -> usize {
    let cap = q.buffer_length as usize;
    begin(r, serial, context, cap);
    let pattern_check = q.pattern.is_some_and(|p| p != STAR);
    let mut remaining = cap;
    let mut cur = 0usize;
    let mut last = 0usize;
    let mut index: u32 = 0;
    let mut overflow = false;
    {
        let b = &mut r[ei::BUFFER..ei::BUFFER + cap];
        for e in entries {
            let hit = !pattern_check || is_name_in_expression(q.pattern.unwrap_or(&[]), &e.name, !q.case_sensitive);
            if !hit {
                continue;
            }
            if q.index <= index {
                // index + 1: the entry's FileIndex is the index of the next one.
                let size =
                    fill_entry(q.class, &mut b[cur..], &mut remaining, e, index.wrapping_add(1), q.allocation_unit);
                if size == 0 {
                    overflow = true;
                    break;
                }
                last = cur;
                if q.irp_flags & SL_RETURN_SINGLE_ENTRY != 0 {
                    index += 1;
                    break;
                }
                wr_u32(b, cur, size as u32); // NextEntryOffset
                cur += size;
            }
            index += 1;
        }
        if cap >= 4 {
            wr_u32(b, last, 0);
        }
    }
    set_buffer_length(r, (cap - remaining) as u32);
    if index <= q.index {
        let st = if overflow {
            STATUS_BUFFER_OVERFLOW
        } else if q.index == 0 {
            STATUS_NO_SUCH_FILE
        } else {
            STATUS_NO_MORE_FILES
        };
        set_status(r, st);
        wr_u32(r, ei::DIRECTORY_INDEX, q.index);
    } else {
        set_status(r, STATUS_SUCCESS);
        wr_u32(r, ei::DIRECTORY_INDEX, index);
    }
    sized(r)
}
