// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/dokan.c, create.c, read.c, write.c,
// setfile.c, security.c, lock.c:
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Request decoding and reply encoding, on byte slices (no OS calls): what
//! dokan2.dll's dispatch files do between the driver and the file system's
//! callbacks.

pub mod dir;
pub mod info;
pub mod pattern;
pub mod reply;

use crate::proto::*;

/// A UTF-16 string inside an event: byte offset and length in code units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Str {
    pub off: usize,
    pub len: usize,
}

impl Str {
    pub fn to_vec(self, ev: &[u8]) -> Vec<u16> {
        rd_utf16(ev, self.off, self.len).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Shorter than its header or than its own Length field claims.
    Truncated,
    /// A name, buffer or offset lies outside the event.
    OutOfBounds,
}

/// The `EVENT_CONTEXT` header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    pub length: u32,
    pub mount_id: u32,
    pub serial: u32,
    pub process_id: u32,
    pub major: u8,
    pub minor: u8,
    pub flags: u32,
    pub file_flags: u32,
    pub context: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateOp {
    pub name: Str,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_options: u32,
    pub original_desired_access: u32,
    pub remaining_desired_access: u32,
    pub previously_granted_access: u32,
    pub access_state_flags: u32,
    /// (offset, length) of the new object's security descriptor.
    pub security_descriptor: Option<(usize, usize)>,
}

impl CreateOp {
    pub fn disposition(&self) -> u32 {
        (self.create_options >> 24) & 0xff
    }
    pub fn options(&self) -> u32 {
        self.create_options & FILE_VALID_OPTION_FLAGS
    }
}

/// One decoded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create(CreateOp),
    Cleanup {
        name: Str,
    },
    Close {
        name: Str,
    },
    Read {
        name: Str,
        offset: i64,
        length: u32,
    },
    /// `data` is (offset, length) of the bytes when inline; a large write has
    /// `request_length` > 0 and its data must be fetched with FSCTL_EVENT_WRITE.
    Write {
        name: Str,
        offset: i64,
        length: u32,
        data: Option<(usize, usize)>,
        request_length: u32,
    },
    QueryInfo {
        name: Str,
        class: u32,
        buffer_length: u32,
    },
    SetInfo {
        name: Str,
        class: u32,
        buffer: (usize, usize),
    },
    Directory {
        dir: Str,
        class: u32,
        index: u32,
        buffer_length: u32,
        pattern: Option<Str>,
    },
    Volume {
        class: u32,
        buffer_length: u32,
    },
    Lock {
        name: Str,
        offset: i64,
        length: i64,
        key: u32,
    },
    Flush {
        name: Str,
    },
    QuerySecurity {
        name: Str,
        info: u32,
        buffer_length: u32,
    },
    SetSecurity {
        name: Str,
        info: u32,
        descriptor: (usize, usize),
    },
    Log,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub header: Header,
    pub op: Op,
}

/// A request name split into the file and the stream it names (ABI 1.1,
/// named streams on): `path` is `name[..path_len]`; the stream, when there
/// is one, is `name[s.0..s.0 + s.1]` without its `:$DATA` type. `\a\f` and
/// `\a\f::$DATA` name the unnamed data stream (None); `\a\f:s` and
/// `\a\f:s:$DATA` name `s`; a type other than `$DATA` stays on
/// (`s:$INDEX_ALLOCATION`), for the host to refuse. NTFS's own parse (the
/// first colon after the last backslash); no policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSplit {
    pub path_len: usize,
    pub stream: Option<(usize, usize)>,
}

pub fn split_stream(name: &[u16]) -> StreamSplit {
    let colon = b':' as u16;
    let bs = b'\\' as u16;
    let start = name.iter().rposition(|&c| c == bs).map_or(0, |i| i + 1);
    let Some(rel) = name[start..].iter().position(|&c| c == colon) else {
        return StreamSplit { path_len: name.len(), stream: None };
    };
    let c1 = start + rel;
    let rest = &name[c1 + 1..];
    let (sname_len, kind) = match rest.iter().position(|&c| c == colon) {
        Some(i) => (i, Some(&rest[i + 1..])),
        None => (rest.len(), None),
    };
    let stream = match kind {
        // "f:s:$DATA" -> s; "f::$DATA" -> the data stream.
        Some(k) if is_data_type(k) => (sname_len > 0).then_some((c1 + 1, sname_len)),
        // "f:s:$OTHER": the whole remainder.
        Some(_) => Some((c1 + 1, rest.len())),
        // "f:s" -> s; "f:" -> the data stream.
        None => (sname_len > 0).then_some((c1 + 1, sname_len)),
    };
    StreamSplit { path_len: c1, stream }
}

fn is_data_type(k: &[u16]) -> bool {
    let d = *b"$DATA";
    let up = |c: u16| if (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c };
    k.len() == d.len() && k.iter().zip(d).all(|(&a, b)| up(a) == b as u16)
}

/// Splits a pull's output into its events by their `Length` fields.
pub fn split_events(buf: &[u8]) -> impl Iterator<Item = Result<&[u8], DecodeError>> {
    let mut rest = buf;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let len = match rd_u32(rest, ec::LENGTH) {
            Some(l) => l as usize,
            None => {
                rest = &[];
                return Some(Err(DecodeError::Truncated));
            }
        };
        if len < ec::OPERATION || len > rest.len() {
            rest = &[];
            return Some(Err(DecodeError::Truncated));
        }
        let (ev, tail) = rest.split_at(len);
        rest = tail;
        Some(Ok(ev))
    })
}

/// dokan2.dll's CheckFileName on a name given as (offset, byte length): stops
/// at the first NUL (it uses wcslen), turns a leading `\\` into `\`, and drops
/// a trailing `\` from names longer than two characters.
pub fn name_at(ev: &[u8], off: usize, byte_len: usize) -> Result<Str, DecodeError> {
    let units = byte_len / 2;
    let end = off.checked_add(units * 2).ok_or(DecodeError::OutOfBounds)?;
    if end > ev.len() {
        return Err(DecodeError::OutOfBounds);
    }
    let at = |i: usize| rd_u16(ev, off + 2 * i).unwrap_or(0);
    let mut len = (0..units).find(|&i| at(i) == 0).unwrap_or(units);
    let mut start = off;
    if len >= 2 && at(0) == b'\\' as u16 && at(1) == b'\\' as u16 {
        start += 2;
        len -= 1;
    }
    let at2 = |i: usize| rd_u16(ev, start + 2 * i).unwrap_or(0);
    if len > 2 && at2(len - 1) == b'\\' as u16 {
        len -= 1;
    }
    Ok(Str { off: start, len })
}

fn need(ev: &[u8], off: usize) -> Result<u32, DecodeError> {
    rd_u32(ev, off).ok_or(DecodeError::Truncated)
}

fn range(ev: &[u8], off: usize, len: usize) -> Result<(usize, usize), DecodeError> {
    match off.checked_add(len) {
        Some(end) if end <= ev.len() => Ok((off, len)),
        _ => Err(DecodeError::OutOfBounds),
    }
}

/// Decodes one event (a slice exactly `Length` long, from `split_events`).
pub fn decode(ev: &[u8]) -> Result<Event, DecodeError> {
    if ev.len() < ec::OPERATION {
        return Err(DecodeError::Truncated);
    }
    let header = Header {
        length: need(ev, ec::LENGTH)?,
        mount_id: need(ev, ec::MOUNT_ID)?,
        serial: need(ev, ec::SERIAL_NUMBER)?,
        process_id: need(ev, ec::PROCESS_ID)?,
        major: rd_u8(ev, ec::MAJOR_FUNCTION).ok_or(DecodeError::Truncated)?,
        minor: rd_u8(ev, ec::MINOR_FUNCTION).ok_or(DecodeError::Truncated)?,
        flags: need(ev, ec::FLAGS)?,
        file_flags: need(ev, ec::FILE_FLAGS)?,
        context: rd_u64(ev, ec::CONTEXT).ok_or(DecodeError::Truncated)?,
    };
    let op = match header.major {
        IRP_MJ_CREATE => {
            use ec::create as c;
            let name_len = need(ev, c::FILE_NAME_LENGTH)? as usize;
            let name_off = c::BASE + need(ev, c::FILE_NAME_OFFSET)? as usize;
            let sd_off = need(ev, c::SECURITY_DESCRIPTOR_OFFSET)? as usize;
            let security_descriptor = if sd_off > 0 {
                let at = c::ACCESS_STATE + sd_off;
                // The descriptor's length is not sent; it runs to the next
                // part of the event (the object name), at most to the end.
                let next = c::ACCESS_STATE + need(ev, c::OBJECT_NAME_OFFSET)? as usize;
                let end = if next > at { next.min(ev.len()) } else { ev.len() };
                Some(range(ev, at, end.saturating_sub(at))?)
            } else {
                None
            };
            Op::Create(CreateOp {
                name: name_at(ev, name_off, name_len)?,
                desired_access: need(ev, c::DESIRED_ACCESS)?,
                file_attributes: need(ev, c::FILE_ATTRIBUTES)?,
                share_access: need(ev, c::SHARE_ACCESS)?,
                create_options: need(ev, c::CREATE_OPTIONS)?,
                original_desired_access: need(ev, c::ORIGINAL_DESIRED_ACCESS)?,
                remaining_desired_access: need(ev, c::REMAINING_DESIRED_ACCESS)?,
                previously_granted_access: need(ev, c::PREVIOUSLY_GRANTED_ACCESS)?,
                access_state_flags: need(ev, c::ACCESS_STATE_FLAGS)?,
                security_descriptor,
            })
        }
        IRP_MJ_CLEANUP | IRP_MJ_CLOSE | IRP_MJ_FLUSH_BUFFERS => {
            use ec::name_only as n;
            let name = name_at(ev, n::FILE_NAME, need(ev, n::FILE_NAME_LENGTH)? as usize)?;
            match header.major {
                IRP_MJ_CLEANUP => Op::Cleanup { name },
                IRP_MJ_CLOSE => Op::Close { name },
                _ => Op::Flush { name },
            }
        }
        IRP_MJ_READ => {
            use ec::read as r;
            Op::Read {
                name: name_at(ev, r::FILE_NAME, need(ev, r::FILE_NAME_LENGTH)? as usize)?,
                offset: rd_i64(ev, r::BYTE_OFFSET).ok_or(DecodeError::Truncated)?,
                length: need(ev, r::BUFFER_LENGTH)?,
            }
        }
        IRP_MJ_WRITE => {
            use ec::write as w;
            let length = need(ev, w::BUFFER_LENGTH)?;
            let request_length = need(ev, w::REQUEST_LENGTH)?;
            let data = if request_length == 0 {
                Some(range(ev, need(ev, w::BUFFER_OFFSET)? as usize, length as usize)?)
            } else {
                None
            };
            Op::Write {
                name: name_at(ev, w::FILE_NAME, need(ev, w::FILE_NAME_LENGTH)? as usize)?,
                offset: rd_i64(ev, w::BYTE_OFFSET).ok_or(DecodeError::Truncated)?,
                length,
                data,
                request_length,
            }
        }
        IRP_MJ_QUERY_INFORMATION => {
            use ec::file as f;
            Op::QueryInfo {
                name: name_at(ev, f::FILE_NAME, need(ev, f::FILE_NAME_LENGTH)? as usize)?,
                class: need(ev, f::FILE_INFORMATION_CLASS)?,
                buffer_length: need(ev, f::BUFFER_LENGTH)?,
            }
        }
        IRP_MJ_SET_INFORMATION => {
            use ec::setfile as s;
            Op::SetInfo {
                name: name_at(ev, s::FILE_NAME, need(ev, s::FILE_NAME_LENGTH)? as usize)?,
                class: need(ev, s::FILE_INFORMATION_CLASS)?,
                buffer: range(ev, need(ev, s::BUFFER_OFFSET)? as usize, need(ev, s::BUFFER_LENGTH)? as usize)?,
            }
        }
        IRP_MJ_DIRECTORY_CONTROL => {
            use ec::dir as d;
            let name_len = need(ev, d::DIRECTORY_NAME_LENGTH)? as usize;
            let pattern_len = need(ev, d::SEARCH_PATTERN_LENGTH)? as usize;
            let pattern = if pattern_len > 0 {
                let off = d::SEARCH_PATTERN_BASE + need(ev, d::SEARCH_PATTERN_OFFSET)? as usize;
                let s = name_at_raw(ev, off, pattern_len)?;
                Some(s)
            } else {
                None
            };
            Op::Directory {
                dir: name_at(ev, d::DIRECTORY_NAME, name_len)?,
                class: need(ev, d::FILE_INFORMATION_CLASS)?,
                index: need(ev, d::FILE_INDEX)?,
                buffer_length: need(ev, d::BUFFER_LENGTH)?,
                pattern,
            }
        }
        IRP_MJ_QUERY_VOLUME_INFORMATION => Op::Volume {
            class: need(ev, ec::volume::FS_INFORMATION_CLASS)?,
            buffer_length: need(ev, ec::volume::BUFFER_LENGTH)?,
        },
        IRP_MJ_LOCK_CONTROL => {
            use ec::lock as l;
            Op::Lock {
                name: name_at(ev, l::FILE_NAME, need(ev, l::FILE_NAME_LENGTH)? as usize)?,
                offset: rd_i64(ev, l::BYTE_OFFSET).ok_or(DecodeError::Truncated)?,
                length: rd_i64(ev, l::LENGTH).ok_or(DecodeError::Truncated)?,
                key: need(ev, l::KEY)?,
            }
        }
        IRP_MJ_QUERY_SECURITY => {
            use ec::security as s;
            Op::QuerySecurity {
                name: name_at(ev, s::FILE_NAME, need(ev, s::FILE_NAME_LENGTH)? as usize)?,
                info: need(ev, s::SECURITY_INFORMATION)?,
                buffer_length: need(ev, s::BUFFER_LENGTH)?,
            }
        }
        IRP_MJ_SET_SECURITY => {
            use ec::set_security as s;
            Op::SetSecurity {
                name: name_at(ev, s::FILE_NAME, need(ev, s::FILE_NAME_LENGTH)? as usize)?,
                info: need(ev, s::SECURITY_INFORMATION)?,
                descriptor: range(ev, need(ev, s::BUFFER_OFFSET)? as usize, need(ev, s::BUFFER_LENGTH)? as usize)?,
            }
        }
        DOKAN_IRP_LOG_MESSAGE => Op::Log,
        _ => Op::Unknown,
    };
    Ok(Event { header, op })
}

/// A string taken as is (no CheckFileName): stops at the first NUL only.
fn name_at_raw(ev: &[u8], off: usize, byte_len: usize) -> Result<Str, DecodeError> {
    let units = byte_len / 2;
    let end = off.checked_add(units * 2).ok_or(DecodeError::OutOfBounds)?;
    if end > ev.len() {
        return Err(DecodeError::OutOfBounds);
    }
    let len = (0..units).find(|&i| rd_u16(ev, off + 2 * i) == Some(0)).unwrap_or(units);
    Ok(Str { off, len })
}

/// The decoded parameters of a set-information request (dokan2.dll's
/// setfile.c), or the status to answer without asking the host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetInfo {
    pub kind: u32,
    pub class: u32,
    pub attributes: u32,
    pub times: [i64; 4],
    pub size: i64,
    pub delete: bool,
    pub replace_if_exists: bool,
    pub ex_flags: u32,
    pub new_name: Vec<u16>,
}

pub fn decode_set_info(ev: &[u8], class: u32, buffer: (usize, usize)) -> Result<SetInfo, NtStatus> {
    use crate::abi::*;
    let (off, len) = buffer;
    let b = &ev[off..off + len];
    let short = STATUS_INVALID_PARAMETER;
    let mut s = SetInfo { class, ..SetInfo::default() };
    match class {
        FILE_ALLOCATION_INFORMATION | FILE_END_OF_FILE_INFORMATION | FILE_VALID_DATA_LENGTH_INFORMATION => {
            s.kind = match class {
                FILE_ALLOCATION_INFORMATION => MD_SET_ALLOCATION,
                FILE_END_OF_FILE_INFORMATION => MD_SET_END_OF_FILE,
                _ => MD_SET_VALID_DATA_LENGTH,
            };
            s.size = rd_i64(b, 0).ok_or(short)?;
        }
        FILE_BASIC_INFORMATION => {
            s.kind = MD_SET_BASIC;
            for (i, t) in s.times.iter_mut().enumerate() {
                *t = rd_i64(b, 8 * i).ok_or(short)?;
            }
            s.attributes = rd_u32(b, 32).ok_or(short)?;
        }
        FILE_DISPOSITION_INFORMATION => {
            s.kind = MD_SET_DISPOSITION;
            s.delete = rd_u8(b, 0).ok_or(short)? != 0;
        }
        FILE_DISPOSITION_INFORMATION_EX => {
            s.kind = MD_SET_DISPOSITION;
            s.ex_flags = rd_u32(b, 0).ok_or(short)?;
            s.delete = s.ex_flags & FILE_DISPOSITION_DELETE != 0;
        }
        FILE_RENAME_INFORMATION | FILE_RENAME_INFORMATION_EX => {
            s.kind = MD_SET_RENAME;
            if class == FILE_RENAME_INFORMATION {
                s.replace_if_exists = rd_u8(b, rename::REPLACE_IF_EXISTS).ok_or(short)? != 0;
            } else {
                s.ex_flags = rd_u32(b, rename::REPLACE_IF_EXISTS).ok_or(short)?;
                s.replace_if_exists = s.ex_flags & 1 != 0; // FILE_RENAME_REPLACE_IF_EXISTS
            }
            let name_len = rd_u32(b, rename::FILE_NAME_LENGTH).ok_or(short)? as usize;
            s.new_name = rd_utf16(b, rename::FILE_NAME, name_len / 2).ok_or(short)?;
        }
        // "this case is dealt with by the driver"
        FILE_POSITION_INFORMATION => return Err(STATUS_NOT_IMPLEMENTED),
        _ => return Err(STATUS_INVALID_PARAMETER),
    }
    Ok(s)
}

/// FILETIME now, for the "." and ".." entries dokan2.dll adds.
pub fn filetime_now() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    116_444_736_000_000_000u64 + (since.as_nanos() / 100) as u64
}

#[cfg(test)]
mod tests;
