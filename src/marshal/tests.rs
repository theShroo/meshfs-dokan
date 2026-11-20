// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Decoder and encoder tests on hand-built events laid out as the driver lays
//! them out (sys/*.c), checked field by field against the C offsets.

use super::dir::{self, Entry, Listing, Query};
use super::info;
use super::reply;
use super::*;
use crate::abi::*;

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// An event as AllocateEventContext makes it: zeroed, `sizeof(EVENT_CONTEXT)`
/// plus `extra` bytes, with the header filled in.
fn event(major: u8, extra: usize, serial: u32, context: u64) -> Vec<u8> {
    let len = ec::SIZE + extra;
    let mut b = vec![0u8; len];
    wr_u32(&mut b, ec::LENGTH, len as u32);
    wr_u32(&mut b, ec::MOUNT_ID, 7);
    wr_u32(&mut b, ec::SERIAL_NUMBER, serial);
    wr_u32(&mut b, ec::PROCESS_ID, 4242);
    wr_u8(&mut b, ec::MAJOR_FUNCTION, major);
    wr_u32(&mut b, ec::FILE_FLAGS, DOKAN_SYNCHRONOUS_IO);
    wr_u64(&mut b, ec::CONTEXT, context);
    b
}

fn put_name(b: &mut [u8], len_off: usize, name_off: usize, name: &str) {
    let n = w(name);
    wr_u32(b, len_off, (n.len() * 2) as u32);
    wr_utf16(b, name_off, &n);
}

fn s(ev: &[u8], st: Str) -> String {
    String::from_utf16(&st.to_vec(ev)).unwrap()
}

#[test]
fn layout_constants() {
    assert_eq!(FSCTL_GET_VERSION, 0x0009_2000);
    assert_eq!(FSCTL_EVENT_START, 0x0009_2014);
    assert_eq!(FSCTL_EVENT_WRITE, 0x0009_201A);
    assert_eq!(FSCTL_EVENT_PROCESS_N_PULL, 0x0009_2048);
    assert_eq!(es::SIZE, 17056);
    assert_eq!(edi::SIZE, 152);
    assert_eq!(ei::SIZE, 48);
    assert_eq!(ei::BUFFER % 8, 0, "DokanInit asserts the Buffer is 8-aligned");
}

#[test]
fn read_event() {
    let mut b = event(IRP_MJ_READ, 64, 11, 0xABCD);
    wr_i64(&mut b, ec::read::BYTE_OFFSET, 1 << 33);
    wr_u32(&mut b, ec::read::BUFFER_LENGTH, 65536);
    put_name(&mut b, ec::read::FILE_NAME_LENGTH, ec::read::FILE_NAME, "\\dir\\a.bin");
    let e = decode(&b).unwrap();
    assert_eq!(e.header.serial, 11);
    assert_eq!(e.header.process_id, 4242);
    assert_eq!(e.header.context, 0xABCD);
    match e.op {
        Op::Read { name, offset, length } => {
            assert_eq!(s(&b, name), "\\dir\\a.bin");
            assert_eq!(offset, 1 << 33);
            assert_eq!(length, 65536);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn check_file_name() {
    let mut b = event(IRP_MJ_CLEANUP, 64, 1, 0);
    put_name(&mut b, ec::name_only::FILE_NAME_LENGTH, ec::name_only::FILE_NAME, "\\\\dir\\");
    let Op::Cleanup { name } = decode(&b).unwrap().op else { panic!() };
    assert_eq!(s(&b, name), "\\dir");
    let mut b = event(IRP_MJ_CLOSE, 64, 1, 0);
    put_name(&mut b, ec::name_only::FILE_NAME_LENGTH, ec::name_only::FILE_NAME, "\\");
    let Op::Close { name } = decode(&b).unwrap().op else { panic!() };
    assert_eq!(s(&b, name), "\\");
}

#[test]
fn hostile_lengths_are_refused() {
    let mut b = event(IRP_MJ_READ, 0, 1, 0);
    wr_u32(&mut b, ec::read::FILE_NAME_LENGTH, 0xFFFF_FFF0);
    assert_eq!(decode(&b), Err(DecodeError::OutOfBounds));
    let mut b = event(IRP_MJ_WRITE, 16, 1, 0);
    wr_u32(&mut b, ec::write::BUFFER_OFFSET, 100);
    wr_u32(&mut b, ec::write::BUFFER_LENGTH, 1 << 20);
    assert_eq!(decode(&b), Err(DecodeError::OutOfBounds));
    assert_eq!(decode(&[0u8; 12]), Err(DecodeError::Truncated));
    // A batch whose second event claims more than is there.
    let mut two = event(IRP_MJ_CLOSE, 0, 1, 0);
    let mut bad = event(IRP_MJ_CLOSE, 0, 2, 0);
    wr_u32(&mut bad, ec::LENGTH, 9999);
    two.extend_from_slice(&bad);
    let got: Vec<_> = split_events(&two).collect();
    assert_eq!(got.len(), 2);
    assert!(got[0].is_ok());
    assert_eq!(got[1], Err(DecodeError::Truncated));
}

#[test]
fn write_event_inline_and_large() {
    let name = w("\\f");
    let data = b"hello world";
    let off = ec::write::FILE_NAME + name.len() * 2 + 2; // the driver's BufferOffset
    let mut b = event(IRP_MJ_WRITE, (off + data.len()).saturating_sub(ec::SIZE) + 8, 3, 9);
    wr_i64(&mut b, ec::write::BYTE_OFFSET, 5);
    wr_u32(&mut b, ec::write::BUFFER_LENGTH, data.len() as u32);
    wr_u32(&mut b, ec::write::BUFFER_OFFSET, off as u32);
    put_name(&mut b, ec::write::FILE_NAME_LENGTH, ec::write::FILE_NAME, "\\f");
    b[off..off + data.len()].copy_from_slice(data);
    let Op::Write { data: Some((o, l)), offset, request_length, .. } = decode(&b).unwrap().op else { panic!() };
    assert_eq!(&b[o..o + l], data);
    assert_eq!((offset, request_length), (5, 0));
    // The stub of a large write: no data, RequestLength set.
    let mut b = event(IRP_MJ_WRITE, 16, 4, 9);
    wr_u32(&mut b, ec::write::BUFFER_LENGTH, 1 << 20);
    wr_u32(&mut b, ec::write::REQUEST_LENGTH, (1 << 20) + 300);
    let Op::Write { data: None, request_length, length, .. } = decode(&b).unwrap().op else { panic!() };
    assert_eq!((request_length, length), ((1 << 20) + 300, 1 << 20));
}

#[test]
fn create_event() {
    // Laid out as sys/create.c does: the pointer-aligned EVENT_CONTEXT, then
    // the descriptor, the object name, the type name and the file name.
    let base = 176; // PointerAlignSize(sizeof(EVENT_CONTEXT))
    let sd = [1u8, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let name = w("\\new.txt");
    let objname_at = base + 24;
    let file_at = objname_at + 16;
    let mut b = event(IRP_MJ_CREATE, file_at + name.len() * 2 + 2 - ec::SIZE, 5, 0);
    use ec::create as c;
    wr_u32(&mut b, c::SECURITY_DESCRIPTOR_OFFSET, (base - c::ACCESS_STATE) as u32);
    b[base..base + sd.len()].copy_from_slice(&sd);
    wr_u32(&mut b, c::OBJECT_NAME_OFFSET, (objname_at - c::ACCESS_STATE) as u32);
    wr_u32(&mut b, c::DESIRED_ACCESS, 0x0012_019F);
    wr_u32(&mut b, c::FILE_ATTRIBUTES, 0x80);
    wr_u32(&mut b, c::SHARE_ACCESS, 7);
    wr_u32(&mut b, c::CREATE_OPTIONS, (FILE_OPEN_IF << 24) | FILE_NON_DIRECTORY_FILE);
    wr_u32(&mut b, c::FILE_NAME_LENGTH, (name.len() * 2) as u32);
    wr_u32(&mut b, c::FILE_NAME_OFFSET, (file_at - c::BASE) as u32);
    wr_utf16(&mut b, file_at, &name);
    let Op::Create(cr) = decode(&b).unwrap().op else { panic!() };
    assert_eq!(s(&b, cr.name), "\\new.txt");
    assert_eq!(cr.disposition(), FILE_OPEN_IF);
    assert_eq!(cr.options(), FILE_NON_DIRECTORY_FILE);
    assert_eq!(cr.desired_access, 0x0012_019F);
    assert_eq!(cr.share_access, 7);
    let (o, l) = cr.security_descriptor.unwrap();
    assert_eq!(o, base);
    assert_eq!(&b[o..o + 4], &sd[..4]);
    assert_eq!(l, 24);
}

#[test]
fn directory_event() {
    let dirn = w("\\docs");
    let pat = w("*.txt");
    let mut b = event(IRP_MJ_DIRECTORY_CONTROL, 64, 6, 33);
    use ec::dir as d;
    wr_u32(&mut b, d::FILE_INFORMATION_CLASS, FILE_ID_BOTH_DIRECTORY_INFORMATION);
    wr_u32(&mut b, d::FILE_INDEX, 3);
    wr_u32(&mut b, d::BUFFER_LENGTH, 4096);
    wr_u32(&mut b, d::DIRECTORY_NAME_LENGTH, (dirn.len() * 2) as u32);
    wr_utf16(&mut b, d::DIRECTORY_NAME, &dirn);
    wr_u32(&mut b, d::SEARCH_PATTERN_LENGTH, (pat.len() * 2) as u32);
    wr_u32(&mut b, d::SEARCH_PATTERN_OFFSET, (dirn.len() * 2) as u32);
    wr_utf16(&mut b, d::SEARCH_PATTERN_BASE + dirn.len() * 2, &pat);
    let Op::Directory { dir, class, index, buffer_length, pattern } = decode(&b).unwrap().op else { panic!() };
    assert_eq!(s(&b, dir), "\\docs");
    assert_eq!(s(&b, pattern.unwrap()), "*.txt");
    assert_eq!((class, index, buffer_length), (FILE_ID_BOTH_DIRECTORY_INFORMATION, 3, 4096));
}

#[test]
fn set_info_decoding() {
    let mut b = event(IRP_MJ_SET_INFORMATION, 128, 7, 1);
    let new = w("\\b\\renamed.txt");
    let at = 120;
    wr_u8(&mut b, at, 1);
    wr_u32(&mut b, at + rename::FILE_NAME_LENGTH, (new.len() * 2) as u32);
    wr_utf16(&mut b, at + rename::FILE_NAME, &new);
    wr_u32(&mut b, ec::setfile::FILE_INFORMATION_CLASS, FILE_RENAME_INFORMATION);
    wr_u32(&mut b, ec::setfile::BUFFER_OFFSET, at as u32);
    wr_u32(&mut b, ec::setfile::BUFFER_LENGTH, (8 + new.len() * 2) as u32);
    let Op::SetInfo { class, buffer, .. } = decode(&b).unwrap().op else { panic!() };
    let si = decode_set_info(&b, class, buffer).unwrap();
    assert_eq!(si.kind, MD_SET_RENAME);
    assert!(si.replace_if_exists);
    assert_eq!(si.new_name, new);
    // Disposition, EOF, the position class and an unknown class.
    let bytes = [1u8, 0, 0, 0, 0, 0, 0, 0];
    assert!(decode_set_info(&bytes, FILE_DISPOSITION_INFORMATION, (0, 1)).unwrap().delete);
    assert!(decode_set_info(&bytes, FILE_DISPOSITION_INFORMATION_EX, (0, 4)).unwrap().delete);
    assert_eq!(decode_set_info(&bytes, FILE_END_OF_FILE_INFORMATION, (0, 8)).unwrap().size, 1);
    assert_eq!(decode_set_info(&bytes, FILE_POSITION_INFORMATION, (0, 8)), Err(STATUS_NOT_IMPLEMENTED));
    assert_eq!(decode_set_info(&bytes, 999, (0, 8)), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(decode_set_info(&bytes, FILE_BASIC_INFORMATION, (0, 8)), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn create_replies() {
    let mut r = vec![0xAAu8; 64];
    let ok = MdCreateReply { context: 77, flags: 0, _reserved: 0 };
    let n = reply::create(&mut r, 9, FILE_OPEN_IF, 0, false, STATUS_OBJECT_NAME_COLLISION, &ok);
    assert_eq!(n, 48);
    assert_eq!(rd_u32(&r, ei::SERIAL_NUMBER), Some(9));
    assert_eq!(rd_u32(&r, ei::STATUS), Some(0));
    assert_eq!(rd_u32(&r, ei::CREATE_INFORMATION), Some(FILE_OPENED));
    assert_eq!(rd_u64(&r, ei::CONTEXT), Some(77));
    reply::create(&mut r, 9, FILE_CREATE, FILE_DIRECTORY_FILE, false, STATUS_SUCCESS, &ok);
    assert_eq!(rd_u32(&r, ei::CREATE_INFORMATION), Some(FILE_CREATED));
    assert_eq!(rd_u32(&r, ei::CREATE_FLAGS), Some(DOKAN_FILE_DIRECTORY));
    reply::create(&mut r, 9, FILE_CREATE, 0, false, STATUS_OBJECT_NAME_COLLISION, &ok);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_OBJECT_NAME_COLLISION as u32));
    assert_eq!(rd_u32(&r, ei::CREATE_INFORMATION), Some(FILE_EXISTS));
    assert_eq!(rd_u64(&r, ei::CONTEXT), Some(0), "a failed create carries no context");
    reply::create(&mut r, 9, FILE_OVERWRITE_IF, 0, false, STATUS_OBJECT_NAME_COLLISION, &ok);
    assert_eq!(rd_u32(&r, ei::CREATE_INFORMATION), Some(FILE_OVERWRITTEN));
    let missing = MdCreateReply { context: 1, flags: MD_CREATE_TARGET_MISSING, _reserved: 0 };
    reply::create(&mut r, 9, FILE_OPEN, FILE_DIRECTORY_FILE, true, STATUS_SUCCESS, &missing);
    assert_eq!(rd_u32(&r, ei::CREATE_INFORMATION), Some(FILE_DOES_NOT_EXIST));
}

#[test]
fn read_write_replies() {
    let mut r = vec![0u8; 40 + 100];
    r[40..50].copy_from_slice(b"0123456789");
    let n = reply::read(&mut r, 1, 5, 1000, 100, STATUS_SUCCESS, 10);
    assert_eq!(n, 50);
    assert_eq!(&r[40..50], b"0123456789", "the host's bytes are kept");
    assert_eq!(rd_u32(&r, ei::BUFFER_LENGTH), Some(10));
    assert_eq!(rd_i64(&r, ei::CURRENT_BYTE_OFFSET), Some(1010));
    assert_eq!(rd_u64(&r, ei::CONTEXT), Some(5));
    reply::read(&mut r, 1, 5, 0, 100, STATUS_SUCCESS, 0);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_END_OF_FILE as u32));
    reply::read(&mut r, 1, 5, 0, 100, STATUS_SUCCESS, 101);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_INTERNAL_ERROR as u32));
    let n = reply::write(&mut r, 2, 5, 4096, STATUS_SUCCESS, 512);
    assert_eq!(n, 48);
    assert_eq!(rd_u32(&r, ei::BUFFER_LENGTH), Some(512));
    assert_eq!(rd_i64(&r, ei::CURRENT_BYTE_OFFSET), Some(4608));
}

#[test]
fn set_info_and_security_replies() {
    let mut r = vec![0u8; 256];
    let name = w("\\x\\y");
    let n = reply::set_info(&mut r, 3, 8, FILE_RENAME_INFORMATION, false, &name, STATUS_SUCCESS);
    assert_eq!(n, 40 + 8);
    assert_eq!(rd_utf16(&r, 40, 4).unwrap(), name);
    reply::set_info(&mut r, 3, 8, FILE_DISPOSITION_INFORMATION, true, &[], STATUS_SUCCESS);
    assert_eq!(rd_u8(&r, ei::DELETE_PENDING), Some(1));
    // Security: fits, too small, host failure.
    let n = reply::query_security(&mut r, 4, 8, 100, STATUS_SUCCESS, 60);
    assert_eq!((n, rd_u32(&r, ei::STATUS), rd_u32(&r, ei::BUFFER_LENGTH)), (100, Some(0), Some(60)));
    let n = reply::query_security(&mut r, 4, 8, 20, STATUS_SUCCESS, 60);
    assert_eq!(n, 48, "an overflow reply carries no data");
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_BUFFER_OVERFLOW as u32));
    assert_eq!(rd_u32(&r, ei::BUFFER_LENGTH), Some(60));
    reply::query_security(&mut r, 4, 8, 20, STATUS_ACCESS_DENIED, 60);
    assert_eq!(rd_u32(&r, ei::BUFFER_LENGTH), Some(0));
}

fn file_info() -> MdFileInfo {
    MdFileInfo {
        attributes: 0x20,
        number_of_links: 1,
        creation_time: 1,
        last_access_time: 2,
        last_write_time: 3,
        change_time: 0,
        file_size: 1000,
        allocation_size: 0,
        file_index: 0x1_0000_0002,
        volume_serial: 0x1234,
        _reserved: 0,
    }
}

#[test]
fn query_info_classes() {
    let fi = file_info();
    let mut r = vec![0u8; 40 + 512];
    let name = w("\\dir\\f");
    let mut q = |class: u32, cap: u32| {
        let n = info::query_info(&mut r, 1, 2, class, cap, &name, STATUS_SUCCESS, &fi, 512);
        (n, rd_u32(&r, ei::STATUS).unwrap() as i32, rd_u32(&r, ei::BUFFER_LENGTH).unwrap(), r.clone())
    };
    let (_, st, len, b) = q(FILE_BASIC_INFORMATION, 40);
    assert_eq!((st, len), (0, 40));
    assert_eq!(rd_u64(&b, 40 + 24), Some(3), "ChangeTime = LastWriteTime");
    assert_eq!(rd_u32(&b, 40 + 32), Some(0x20));
    let (_, st, len, b) = q(FILE_STANDARD_INFORMATION, 24);
    assert_eq!((st, len), (0, 24));
    assert_eq!(rd_u64(&b, 40), Some(1024), "allocation rounded to the unit");
    assert_eq!(rd_u64(&b, 48), Some(1000));
    let (_, st, len, b) = q(FILE_ALL_INFORMATION, 300);
    assert_eq!((st, len), (0, 100));
    assert_eq!(rd_u64(&b, 40 + 48), Some(1000));
    assert_eq!(rd_u64(&b, 40 + 64), Some(0x1_0000_0002));
    let (_, st, _, _) = q(FILE_ALL_INFORMATION, 100);
    assert_eq!(st, STATUS_BUFFER_OVERFLOW);
    let (_, st, len, b) = q(FILE_NAME_INFORMATION, 100);
    assert_eq!((st, len), (0, 4 + 12));
    assert_eq!(rd_utf16(&b, 44, 6).unwrap(), name);
    let (_, st, len, b) = q(FILE_ID_INFORMATION, 24);
    assert_eq!((st, len), (0, 24));
    assert_eq!((rd_u64(&b, 40), rd_u32(&b, 48), rd_u32(&b, 52)), (Some(0x1234), Some(2), Some(1)));
    let (_, st, len, b) = q(FILE_NETWORK_OPEN_INFORMATION, 56);
    assert_eq!((st, len), (0, 56));
    assert_eq!(rd_u32(&b, 40 + 48), Some(0x20));
    let (_, st, len, b) = q(FILE_STREAM_INFORMATION, 100);
    assert_eq!((st, len), (0, 24 + 14));
    assert_eq!(rd_utf16(&b, 64, 7).unwrap(), w("::$DATA"));
    assert_eq!(q(FILE_ALTERNATE_NAME_INFORMATION, 100).1, STATUS_NOT_IMPLEMENTED);
    assert_eq!(q(77, 100).1, STATUS_INVALID_PARAMETER);
    // A host failure is passed on, with no data.
    let n = info::query_info(&mut r, 1, 2, FILE_BASIC_INFORMATION, 40, &name, STATUS_ACCESS_DENIED, &fi, 512);
    assert_eq!((n, rd_u32(&r, ei::BUFFER_LENGTH)), (48, Some(0)));
}

#[test]
fn volume_classes() {
    let v = info::default_volume();
    let mut r = vec![0u8; 40 + 200];
    let n = info::query_volume(&mut r, 1, 0, FILE_FS_VOLUME_INFORMATION, 200, 0, &v, 512, 4096);
    assert_eq!(n, 40 + 18 + 10);
    assert_eq!(rd_u32(&r, 48), Some(0x1983_1116));
    assert_eq!(rd_utf16(&r, 58, 5).unwrap(), w("DOKAN"));
    info::query_volume(&mut r, 1, 0, FILE_FS_FULL_SIZE_INFORMATION, 200, 0, &v, 512, 4096);
    assert_eq!(rd_u64(&r, 40), Some((1 << 30) / 4096));
    assert_eq!(rd_u32(&r, 40 + 24), Some(8));
    assert_eq!(rd_u32(&r, 40 + 28), Some(512));
    // The file system name cut short: BUFFER_OVERFLOW with the partial data.
    let n = info::query_volume(&mut r, 1, 0, FILE_FS_ATTRIBUTE_INFORMATION, 16, 0, &v, 512, 4096);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_BUFFER_OVERFLOW as u32));
    assert_eq!(n, 40 + 16);
    assert_eq!(rd_u32(&r, 40 + 8), Some(4));
}

fn entries(names: &[&str]) -> Vec<Entry> {
    names.iter().enumerate().map(|(i, n)| Entry { name: w(n), file_size: 10 * i as u64, ..Entry::default() }).collect()
}

/// Walks the NextEntryOffset chain of a FILE_NAMES_INFORMATION reply.
fn names_in(r: &[u8]) -> Vec<String> {
    let len = rd_u32(r, ei::BUFFER_LENGTH).unwrap() as usize;
    let mut out = vec![];
    let mut at = 0;
    if len == 0 {
        return out;
    }
    loop {
        let b = &r[40 + at..];
        let nl = rd_u32(b, 8).unwrap() as usize / 2;
        out.push(String::from_utf16(&rd_utf16(b, 12, nl).unwrap()).unwrap());
        let next = rd_u32(b, 0).unwrap() as usize;
        if next == 0 {
            break;
        }
        at += next;
    }
    out
}

#[test]
fn directory_listing_resume_and_patterns() {
    let list = entries(&["a.txt", "b.bin", "c.txt", "d.txt"]);
    let mut r = vec![0u8; 40 + 4096];
    let mut q = Query {
        class: FILE_NAMES_INFORMATION,
        index: 0,
        irp_flags: 0,
        buffer_length: 4096,
        pattern: None,
        case_sensitive: false,
        allocation_unit: 512,
    };
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(names_in(&r), ["a.txt", "b.bin", "c.txt", "d.txt"]);
    assert_eq!(rd_u32(&r, ei::DIRECTORY_INDEX), Some(4));
    // Resume past the end.
    q.index = 4;
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_NO_MORE_FILES as u32));
    assert_eq!(rd_u32(&r, ei::DIRECTORY_INDEX), Some(4));
    // A pattern; the index counts matching entries only.
    let pat = w("*.TXT");
    q.pattern = Some(&pat);
    q.index = 1;
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(names_in(&r), ["c.txt", "d.txt"]);
    assert_eq!(rd_u32(&r, ei::DIRECTORY_INDEX), Some(3));
    q.case_sensitive = true;
    q.index = 0;
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_NO_SUCH_FILE as u32));
    // Single entry; a buffer too small for even one entry.
    q.case_sensitive = false;
    q.pattern = None;
    q.irp_flags = SL_RETURN_SINGLE_ENTRY;
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(names_in(&r), ["a.txt"]);
    assert_eq!(rd_u32(&r, ei::DIRECTORY_INDEX), Some(1));
    q.irp_flags = 0;
    q.buffer_length = 8;
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_BUFFER_OVERFLOW as u32));
    // A buffer for two entries returns two and resumes at the third.
    q.buffer_length = 2 * quad_align(16 + 10) as u32;
    dir::write_results(&mut r, 1, 0, &q, &list);
    assert_eq!(names_in(&r), ["a.txt", "b.bin"]);
    assert_eq!(rd_u32(&r, ei::DIRECTORY_INDEX), Some(2));
}

#[test]
fn directory_entry_layouts() {
    let e = Entry {
        name: w("x"),
        attributes: 0x10,
        creation_time: 1,
        last_access_time: 2,
        last_write_time: 3,
        change_time: 4,
        file_size: 5,
        allocation_size: 0,
        file_id: 0x77,
    };
    for (class, size, name_off, id_off) in [
        (FILE_DIRECTORY_INFORMATION, 72, 64, None),
        (FILE_FULL_DIRECTORY_INFORMATION, 72, 68, None),
        (FILE_ID_FULL_DIRECTORY_INFORMATION, 88, 80, Some(72)),
        (FILE_BOTH_DIRECTORY_INFORMATION, 96, 94, None),
        (FILE_ID_BOTH_DIRECTORY_INFORMATION, 112, 104, Some(96)),
        (FILE_ID_EXTD_DIRECTORY_INFORMATION, 96, 88, Some(72)),
        (FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION, 120, 114, Some(72)),
    ] {
        let mut b = vec![0xFFu8; 256];
        let mut remaining = 256;
        let n = dir::fill_entry(class, &mut b, &mut remaining, &e, 9, 512);
        assert_eq!(n, quad_align(size + 2), "class {class}");
        assert_eq!(rd_u32(&b, 4), Some(9));
        assert_eq!(rd_u64(&b, 32), Some(4));
        assert_eq!(rd_u64(&b, 48), Some(512));
        assert_eq!(rd_u32(&b, 60), Some(2));
        assert_eq!(rd_u16(&b, name_off), Some(b'x' as u16));
        if let Some(o) = id_off {
            assert_eq!(rd_u64(&b, o), Some(0x77));
        }
    }
}

#[test]
fn force_scan_and_dots() {
    let star = w("*");
    let txt = w("*.txt");
    assert!(dir::force_scan(None, None, 0));
    let kept = Listing { entries: vec![], pattern: None };
    assert!(!dir::force_scan(Some(&kept), None, 0));
    assert!(!dir::force_scan(Some(&kept), Some(&star), 0));
    assert!(dir::force_scan(Some(&kept), Some(&txt), 0));
    assert!(dir::force_scan(Some(&kept), None, SL_RESTART_SCAN));
    assert!(!dir::force_scan(Some(&kept), None, SL_RESTART_SCAN | SL_INDEX_SPECIFIED));
    let kept = Listing { entries: vec![], pattern: Some(txt.clone()) };
    assert!(!dir::force_scan(Some(&kept), Some(&txt), 0));
    assert!(dir::force_scan(Some(&kept), None, 0));

    let mut l = entries(&["a"]);
    dir::add_dots(&mut l, false, None, 5);
    let names: Vec<_> = l.iter().map(|e| String::from_utf16(&e.name).unwrap()).collect();
    assert_eq!(names, [".", "..", "a"]);
    let mut l = entries(&["a"]);
    dir::add_dots(&mut l, true, None, 5);
    assert_eq!(l.len(), 1, "no dots at the root");
    let mut l = entries(&["a"]);
    dir::add_dots(&mut l, false, Some(&txt), 5);
    assert_eq!(l.len(), 1, "no dots with a real pattern");
}

#[test]
fn abi_sizes() {
    use core::mem::size_of;
    // The same numbers are asserted in include/meshfs_dokan.h.
    assert_eq!(size_of::<MdRequest>(), 64, "ABI 1.1: stream, stream_len appended");
    assert_eq!(size_of::<MdCreateRequest>(), 64);
    assert_eq!(size_of::<MdCreateReply>(), 16);
    assert_eq!(size_of::<MdFileInfo>(), 72);
    assert_eq!(size_of::<MdSetInfoRequest>(), 80);
    assert_eq!(size_of::<MdFindEntry>(), 72);
    assert_eq!(size_of::<MdVolumeInfo>(), 144);
    assert_eq!(size_of::<MdReply>(), 64);
    assert_eq!(size_of::<MdMountOptions>(), 56);
    assert_eq!(size_of::<MdHostV1>(), 16 + 15 * 8, "ABI 1.1: find_streams appended");
    assert_eq!(size_of::<MdStreamEntry>(), 32);
    // 1.1 only APPENDS: every 1.0 field keeps its offset, so a 1.0 host
    // reading the 1.0 prefix of a 1.1 request (and a 1.0 table read by a
    // 1.1 library through its `size`) see what they always saw.
    assert_eq!(core::mem::offset_of!(MdRequest, path), 32);
    assert_eq!(core::mem::offset_of!(MdRequest, path_len), 40);
    assert_eq!(core::mem::offset_of!(MdRequest, stream), 48);
    assert_eq!(core::mem::offset_of!(MdHostV1, unmounted), 120);
    assert_eq!(core::mem::offset_of!(MdHostV1, find_streams), 128);
    assert_eq!(MD_ABI_VERSION, 0x0001_0001);
}

fn split(s: &str) -> (String, Option<String>) {
    let v = w(s);
    let sp = split_stream(&v);
    (String::from_utf16(&v[..sp.path_len]).unwrap(), sp.stream.map(|(o, l)| String::from_utf16(&v[o..o + l]).unwrap()))
}

#[test]
fn stream_names_split_as_ntfs_does() {
    let s = |p: &str, st: Option<&str>| (p.to_string(), st.map(str::to_string));
    assert_eq!(split("\\a\\f.exe"), s("\\a\\f.exe", None));
    assert_eq!(split("\\a\\f.exe:Zone.Identifier"), s("\\a\\f.exe", Some("Zone.Identifier")));
    assert_eq!(split("\\a\\f.exe:Zone.Identifier:$DATA"), s("\\a\\f.exe", Some("Zone.Identifier")));
    assert_eq!(split("\\a\\f.exe:Zone.Identifier:$data"), s("\\a\\f.exe", Some("Zone.Identifier")));
    assert_eq!(split("\\a\\f.exe::$DATA"), s("\\a\\f.exe", None), "the unnamed data stream");
    assert_eq!(split("\\a\\f.exe:"), s("\\a\\f.exe", None));
    assert_eq!(
        split("\\a\\d:s:$INDEX_ALLOCATION"),
        s("\\a\\d", Some("s:$INDEX_ALLOCATION")),
        "kept for the host to refuse"
    );
    assert_eq!(split("\\:s"), s("\\", Some("s")), "a stream on the root");
    assert_eq!(split("\\a.b\\c"), s("\\a.b\\c", None));
    assert_eq!(split(""), s("", None));
    // A colon in a folder name is not a stream of the file (NTFS refuses
    // such a name anyway; the split looks after the last backslash only).
    assert_eq!(split("\\x:y\\f"), s("\\x:y\\f", None));
}

#[test]
fn stream_information_from_the_hosts_entries() {
    let mut b = vec![0xEEu8; 200];
    let mut wr = info::StreamWriter::new(&mut b, 512);
    assert!(wr.push(&[], 1000, 0));
    assert!(wr.push(&w("Zone.Identifier"), 26, 0));
    assert_eq!(wr.finish(), (STATUS_SUCCESS, 40 + 24 + 2 * 22));
    // Entry 1: "::$DATA", 8-aligned next offset.
    assert_eq!(rd_u32(&b, 0), Some(40), "24 + 14 bytes, aligned to 40");
    assert_eq!(rd_u32(&b, 4), Some(14));
    assert_eq!(rd_u64(&b, 8), Some(1000));
    assert_eq!(rd_u64(&b, 16), Some(1024), "allocation rounded up");
    assert_eq!(rd_utf16(&b, 24, 7).unwrap(), w("::$DATA"));
    // Entry 2: ":Zone.Identifier:$DATA", the last (next offset 0).
    assert_eq!(rd_u32(&b, 40), Some(0));
    assert_eq!(rd_u32(&b, 44), Some(44));
    assert_eq!(rd_u64(&b, 48), Some(26));
    assert_eq!(rd_utf16(&b, 64, 22).unwrap(), w(":Zone.Identifier:$DATA"));
}

#[test]
fn stream_information_that_does_not_fit() {
    // Room for the first entry only: a partial answer, as NTFS gives.
    let mut b = vec![0u8; 50];
    let mut wr = info::StreamWriter::new(&mut b, 512);
    assert!(wr.push(&[], 5, 0));
    assert!(!wr.push(&w("Zone.Identifier"), 26, 0));
    assert!(!wr.push(&[], 1, 0), "nothing after the first that did not fit");
    assert_eq!(wr.finish(), (STATUS_BUFFER_OVERFLOW, 38));
    assert_eq!(rd_u32(&b, 0), Some(0), "the last entry written ends the chain");
    let mut b = vec![0u8; 16];
    let mut wr = info::StreamWriter::new(&mut b, 512);
    assert!(!wr.push(&[], 5, 0));
    assert_eq!(wr.finish(), (STATUS_BUFFER_TOO_SMALL, 0));
    // A directory: no entries at all, success.
    let mut b = vec![0u8; 64];
    assert_eq!(info::StreamWriter::new(&mut b, 512).finish(), (STATUS_SUCCESS, 0));
}

#[test]
fn stream_reply_encodes_the_writer() {
    let mut r = vec![0u8; ei::BUFFER + 256];
    let n = info::query_streams(&mut r, 9, 3, 256, 512, |wr| {
        wr.push(&[], 10, 0);
        wr.push(&w("Zone.Identifier"), 26, 0);
        STATUS_SUCCESS
    });
    assert_eq!(rd_u32(&r, ei::SERIAL_NUMBER), Some(9));
    assert_eq!(rd_u32(&r, ei::STATUS), Some(STATUS_SUCCESS as u32));
    assert_eq!(rd_u32(&r, ei::BUFFER_LENGTH), Some(40 + 24 + 44));
    assert_eq!(n, ei::BUFFER + 108);
    // A host failure: status only.
    let n = info::query_streams(&mut r, 9, 3, 256, 512, |_| STATUS_ACCESS_DENIED);
    assert_eq!(
        (n, rd_u32(&r, ei::STATUS), rd_u32(&r, ei::BUFFER_LENGTH)),
        (ei::SIZE, Some(STATUS_ACCESS_DENIED as u32), Some(0))
    );
}

/// The decoders never panic, whatever the bytes (the input comes from the
/// kernel, but is parsed defensively): valid events with random fields
/// overwritten, truncated, or batched.
#[test]
fn random_events_never_panic() {
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let majors = [
        IRP_MJ_CREATE,
        IRP_MJ_CLOSE,
        IRP_MJ_READ,
        IRP_MJ_WRITE,
        IRP_MJ_QUERY_INFORMATION,
        IRP_MJ_SET_INFORMATION,
        IRP_MJ_FLUSH_BUFFERS,
        IRP_MJ_QUERY_VOLUME_INFORMATION,
        IRP_MJ_DIRECTORY_CONTROL,
        IRP_MJ_LOCK_CONTROL,
        IRP_MJ_CLEANUP,
        IRP_MJ_QUERY_SECURITY,
        IRP_MJ_SET_SECURITY,
        DOKAN_IRP_LOG_MESSAGE,
        0x7f,
    ];
    for i in 0..100_000u32 {
        let extra = (next() % 300) as usize;
        let mut b = event(majors[i as usize % majors.len()], extra, i, next());
        for _ in 0..(next() % 8) {
            let at = (next() as usize) % (b.len() - 4);
            let v = match next() % 4 {
                0 => 0,
                1 => 0xFFFF_FFFF,
                2 => (next() % 512) as u32,
                _ => next() as u32,
            };
            wr_u32(&mut b, at, v);
        }
        if i % 7 == 0 {
            let cut = (next() as usize) % (b.len() + 1);
            b.truncate(cut);
        }
        for ev in split_events(&b).flatten() {
            let Ok(e) = decode(ev) else { continue };
            if let Op::SetInfo { class, buffer, .. } = e.op {
                let _ = decode_set_info(ev, class, buffer);
            }
            // Every name the decoder hands out lies inside the event.
            let names: Vec<Str> = match e.op {
                Op::Create(c) => vec![c.name],
                Op::Read { name, .. } | Op::Cleanup { name } | Op::Close { name } | Op::Flush { name } => vec![name],
                Op::Directory { dir, pattern, .. } => [Some(dir), pattern].into_iter().flatten().collect(),
                _ => vec![],
            };
            for n in names {
                assert!(n.off + 2 * n.len <= ev.len());
            }
        }
    }
}
