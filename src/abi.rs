// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! The versioned C ABI's types (design section 3.1). `include/meshfs_dokan.h`
//! is the same contract in C; the two are kept in step by hand and a test
//! checks the sizes.
//!
//! Strings are UTF-16 (pointer + length in code units, no terminator) and are
//! valid only during the call that hands them over. Times are FILETIME values
//! (100 ns since 1601) as `u64`.

use core::ffi::c_void;

pub use crate::proto::NtStatus;

/// ABI version: major in the high 16 bits. A host refuses an unknown major;
/// minor versions only append fields to the end of tables and structs that
/// carry their own size.
pub const MD_ABI_MAJOR: u32 = 1;
pub const MD_ABI_MINOR: u32 = 1;
pub const MD_ABI_VERSION: u32 = (MD_ABI_MAJOR << 16) | MD_ABI_MINOR;

// md_mount results
pub const MD_OK: i32 = 0;
/// Bad arguments: a null pointer, a short table or options, an unknown major.
pub const MD_ERR_ARGS: i32 = 1;
/// The driver's global device could not be opened (Dokany not installed or
/// the dokan2 service not running).
pub const MD_ERR_DRIVER_MISSING: i32 = 2;
/// The driver speaks a protocol version this library does not know.
pub const MD_ERR_DRIVER_VERSION: i32 = 3;
/// The driver refused or failed the mount (letter in use, bad mount point...).
pub const MD_ERR_MOUNT: i32 = 4;
/// Opening the volume device or starting the pull threads failed.
pub const MD_ERR_START: i32 = 5;
/// A panic was caught at the boundary.
pub const MD_ERR_INTERNAL: i32 = 6;
/// The call is not allowed from this thread (md_unmount on a pull thread).
pub const MD_ERR_THREAD: i32 = 7;

// MdMountOptions.flags
pub const MD_MOUNT_CASE_SENSITIVE: u32 = 1 << 0;
pub const MD_MOUNT_MOUNT_MANAGER: u32 = 1 << 1;
pub const MD_MOUNT_CURRENT_SESSION: u32 = 1 << 2;
pub const MD_MOUNT_WRITE_PROTECT: u32 = 1 << 3;
pub const MD_MOUNT_REMOVABLE: u32 = 1 << 4;
pub const MD_MOUNT_NETWORK: u32 = 1 << 5;
pub const MD_MOUNT_ENABLE_NETWORK_UNMOUNT: u32 = 1 << 6;
/// ABI 1.1: named streams (alternate data streams). The library declares
/// FILE_NAMED_STREAMS, asks the driver for stream names
/// (DOKAN_EVENT_ALTERNATIVE_STREAM_ON), splits every request's name into
/// `path` + `stream`, and answers FileStreamInformation from the host's
/// `find_streams`. Requires a 1.1 table with `find_streams` (else
/// MD_ERR_ARGS). Which streams exist, and what they hold, is the host's.
pub const MD_MOUNT_NAMED_STREAMS: u32 = 1 << 7;

// MdRequest.file_flags (from EVENT_CONTEXT.FileFlags)
pub const MD_FILE_PAGING_IO: u32 = 1 << 0;
pub const MD_FILE_SYNCHRONOUS_IO: u32 = 1 << 1;
pub const MD_FILE_NOCACHE: u32 = 1 << 2;
pub const MD_FILE_WRITE_TO_END_OF_FILE: u32 = 1 << 3;
pub const MD_FILE_DELETE_ON_CLOSE: u32 = 1 << 4;
pub const MD_FILE_DIRECTORY: u32 = 1 << 5;

// MdCreateRequest.flags
/// SL_OPEN_TARGET_DIRECTORY: `path` is the parent directory of `target`; open
/// that directory. Say in the reply whether `target` exists.
pub const MD_CREATE_OPEN_TARGET_DIRECTORY: u32 = 1 << 0;
/// SL_CASE_SENSITIVE
pub const MD_CREATE_CASE_SENSITIVE: u32 = 1 << 1;

// MdCreateReply.flags
/// The open is a directory (set it whenever a directory is opened, also
/// without FILE_DIRECTORY_FILE).
pub const MD_CREATE_IS_DIRECTORY: u32 = 1 << 0;
/// With MD_CREATE_OPEN_TARGET_DIRECTORY: the target does not exist.
pub const MD_CREATE_TARGET_MISSING: u32 = 1 << 1;

// MdSetInfoRequest.kind
pub const MD_SET_BASIC: u32 = 1;
pub const MD_SET_ALLOCATION: u32 = 2;
pub const MD_SET_END_OF_FILE: u32 = 3;
pub const MD_SET_VALID_DATA_LENGTH: u32 = 4;
pub const MD_SET_DISPOSITION: u32 = 5;
pub const MD_SET_RENAME: u32 = 6;

/// Every callback's first argument after `user`: the decoded request header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdRequest {
    /// The driver's serial number: what `md_reply`, `md_reset_timeout` and
    /// `md_requester_token` take.
    pub request_id: u64,
    /// The host's per-open context from the create reply (0 on create).
    pub context: u64,
    pub process_id: u32,
    /// The IRP stack flags (`SL_*`).
    pub irp_flags: u32,
    /// `MD_FILE_*`
    pub file_flags: u32,
    pub major_function: u8,
    pub minor_function: u8,
    pub _reserved: u16,
    /// The file name relative to the volume (`\dir\file`), normalised as
    /// dokan2.dll's CheckFileName does.
    pub path: *const u16,
    pub path_len: u32,
    pub _reserved2: u32,
    /// ABI 1.1, with MD_MOUNT_NAMED_STREAMS: the stream the request names,
    /// without its `:$DATA` type (`file:Zone.Identifier:$DATA` ->
    /// `Zone.Identifier`), and `path` is the file's name alone. Empty (0
    /// units) for the unnamed data stream (`file` and `file::$DATA` alike).
    /// A type other than `$DATA` is left on (`name:$INDEX_ALLOCATION`). Null
    /// with 0 units otherwise. A 1.0 host never reads these fields.
    pub stream: *const u16,
    pub stream_len: u32,
    pub _reserved3: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdCreateRequest {
    /// `DesiredAccess` from the IO_SECURITY_CONTEXT.
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    /// FILE_SUPERSEDE .. FILE_OVERWRITE_IF
    pub disposition: u32,
    /// The low 24 bits of CreateOptions (FILE_DIRECTORY_FILE, ...). With
    /// MD_CREATE_OPEN_TARGET_DIRECTORY, FILE_DIRECTORY_FILE is set and
    /// FILE_NON_DIRECTORY_FILE cleared, as dokan2.dll does.
    pub create_options: u32,
    /// `MD_CREATE_*`
    pub flags: u32,
    /// From the ACCESS_STATE.
    pub original_desired_access: u32,
    pub remaining_desired_access: u32,
    pub previously_granted_access: u32,
    pub access_state_flags: u32,
    /// The new object's security descriptor (self-relative), if any.
    pub security_descriptor: *const u8,
    pub security_descriptor_len: u32,
    pub target_len: u32,
    /// With MD_CREATE_OPEN_TARGET_DIRECTORY: the full original name.
    pub target: *const u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MdCreateReply {
    /// The host's context for this open, returned on every later request.
    pub context: u64,
    /// `MD_CREATE_IS_DIRECTORY`, `MD_CREATE_TARGET_MISSING`
    pub flags: u32,
    pub _reserved: u32,
}

/// What `query_info` answers; meshfs-dokan encodes every information class
/// from it (dokan2.dll's BY_HANDLE_FILE_INFORMATION).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MdFileInfo {
    pub attributes: u32,
    pub number_of_links: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    /// 0 means "same as last_write_time" (dokan2.dll reports that).
    pub change_time: u64,
    pub file_size: u64,
    /// 0 means "file_size rounded up to the allocation unit".
    pub allocation_size: u64,
    pub file_index: u64,
    pub volume_serial: u32,
    pub _reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdSetInfoRequest {
    /// `MD_SET_*`
    pub kind: u32,
    /// The raw FILE_INFORMATION_CLASS.
    pub info_class: u32,
    /// MD_SET_BASIC: FILE_BASIC_INFORMATION as sent (0 = leave unchanged,
    /// -1 = stop updating that time).
    pub attributes: u32,
    pub _reserved: u32,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    /// MD_SET_ALLOCATION / END_OF_FILE / VALID_DATA_LENGTH
    pub size: i64,
    /// MD_SET_DISPOSITION: delete (1) or undelete (0) on close.
    pub delete: u8,
    /// MD_SET_RENAME
    pub replace_if_exists: u8,
    pub _pad: u16,
    /// FILE_RENAME_INFORMATION_EX / FILE_DISPOSITION_INFORMATION_EX flags.
    pub ex_flags: u32,
    /// MD_SET_RENAME: the new name, relative to the volume.
    pub new_name: *const u16,
    pub new_name_len: u32,
    pub _reserved2: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdFindEntry {
    pub name: *const u16,
    pub name_len: u32,
    pub attributes: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    /// 0 means "same as last_write_time".
    pub change_time: u64,
    pub file_size: u64,
    /// 0 means "file_size rounded up to the allocation unit".
    pub allocation_size: u64,
    pub file_id: u64,
}

/// ABI 1.1: one stream of a file, for `find_streams`. `name` is the bare
/// stream name (0 units = the unnamed data stream); the library writes the
/// NTFS form (`::$DATA`, `:name:$DATA`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdStreamEntry {
    pub name: *const u16,
    pub name_len: u32,
    pub _reserved: u32,
    pub size: u64,
    /// 0 means "size rounded up to the allocation unit".
    pub allocation_size: u64,
}

/// Called by the host during `find_streams`, once per stream. Returns 0;
/// nonzero (STATUS_BUFFER_OVERFLOW) when the caller's buffer is full: the
/// host may stop.
pub type MdStreamFill = unsafe extern "C" fn(fill_ctx: *mut c_void, entry: *const MdStreamEntry) -> i32;

/// Called by the host during `find_files`, once per entry. Returns 0.
pub type MdFindFill = unsafe extern "C" fn(fill_ctx: *mut c_void, entry: *const MdFindEntry) -> i32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MdVolumeInfo {
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// Free bytes available to the caller.
    pub available_bytes: u64,
    pub serial: u32,
    pub max_component_length: u32,
    /// FILE_CASE_SENSITIVE_SEARCH etc.
    pub fs_flags: u32,
    pub label_len: u32,
    pub fs_name_len: u32,
    pub _reserved: u32,
    pub label: [u16; 32],
    pub fs_name: [u16; 16],
}

/// One deferred reply for `md_reply`: the fields that apply to the request's
/// operation are read, the others ignored.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdReply {
    pub request_id: u64,
    pub status: NtStatus,
    /// write: bytes written. query_security: the length needed.
    pub bytes: u32,
    /// read: the bytes read. query_security: the descriptor.
    pub data: *const u8,
    pub data_len: u32,
    /// find_files: the number of `entries`.
    pub entry_count: u32,
    pub create: *const MdCreateReply,
    pub file_info: *const MdFileInfo,
    pub volume: *const MdVolumeInfo,
    pub entries: *const MdFindEntry,
}

impl MdReply {
    /// A reply that carries only a status.
    pub fn status(request_id: u64, status: NtStatus) -> MdReply {
        MdReply {
            request_id,
            status,
            bytes: 0,
            data: core::ptr::null(),
            data_len: 0,
            entry_count: 0,
            create: core::ptr::null(),
            file_info: core::ptr::null(),
            volume: core::ptr::null(),
            entries: core::ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdMountOptions {
    /// sizeof(MdMountOptions)
    pub size: u32,
    /// `MD_MOUNT_*`
    pub flags: u32,
    /// "T:", "T:\" or an empty NTFS folder; NUL-terminated UTF-16.
    pub mount_point: *const u16,
    /// For MD_MOUNT_NETWORK; NUL-terminated UTF-16 or null.
    pub unc_name: *const u16,
    /// IrpTimeout in ms; 0 = the driver's default (15 s). The driver caps it.
    pub irp_timeout_ms: u32,
    /// 0 = 2000, as dokan2.dll.
    pub fcb_gc_interval_ms: u32,
    /// 0 = the processor count, clamped to 2..16 (dokan2.dll's rule).
    pub pull_threads: u32,
    /// 0 = 512. Powers of two in 512..65536, else both reset to 512.
    pub sector_size: u32,
    pub allocation_unit_size: u32,
    pub volume_security_descriptor_len: u32,
    /// Self-relative, at most 16 KiB; null = none.
    pub volume_security_descriptor: *const u8,
}

pub type CbCreate = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    params: *const MdCreateRequest,
    out: *mut MdCreateReply,
) -> NtStatus;
pub type CbStatus = unsafe extern "C" fn(user: *mut c_void, req: *const MdRequest) -> NtStatus;
pub type CbClose = unsafe extern "C" fn(user: *mut c_void, req: *const MdRequest);
pub type CbRead = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    offset: i64,
    length: u32,
    buffer: *mut u8,
    out_bytes: *mut u32,
) -> NtStatus;
pub type CbWrite = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    offset: i64,
    data: *const u8,
    length: u32,
    out_bytes: *mut u32,
) -> NtStatus;
pub type CbQueryInfo =
    unsafe extern "C" fn(user: *mut c_void, req: *const MdRequest, info_class: u32, out: *mut MdFileInfo) -> NtStatus;
pub type CbSetInfo =
    unsafe extern "C" fn(user: *mut c_void, req: *const MdRequest, params: *const MdSetInfoRequest) -> NtStatus;
pub type CbFindFiles = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    pattern: *const u16,
    pattern_len: u32,
    fill: MdFindFill,
    fill_ctx: *mut c_void,
) -> NtStatus;
pub type CbQueryVolume =
    unsafe extern "C" fn(user: *mut c_void, req: *const MdRequest, out: *mut MdVolumeInfo) -> NtStatus;
pub type CbQuerySecurity = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    security_information: u32,
    buffer: *mut u8,
    buffer_len: u32,
    out_needed: *mut u32,
) -> NtStatus;
pub type CbSetSecurity = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    security_information: u32,
    descriptor: *const u8,
    descriptor_len: u32,
) -> NtStatus;
pub type CbMounted = unsafe extern "C" fn(
    user: *mut c_void,
    mount_point: *const u16,
    mount_point_len: u32,
    device_name: *const u16,
    device_name_len: u32,
);
pub type CbUnmounted = unsafe extern "C" fn(user: *mut c_void);
/// ABI 1.1: the streams of the open `req` names. Synchronous: it must not
/// return STATUS_PENDING (answered STATUS_INTERNAL_ERROR).
pub type CbFindStreams = unsafe extern "C" fn(
    user: *mut c_void,
    req: *const MdRequest,
    fill: MdStreamFill,
    fill_ctx: *mut c_void,
) -> NtStatus;

/// The host's callback table. A null entry answers STATUS_NOT_IMPLEMENTED
/// (or dokan2.dll's default, noted per field).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdHostV1 {
    /// sizeof(MdHostV1) as the host was built; entries past it are null.
    pub size: u32,
    /// MD_ABI_VERSION the host was built against.
    pub version: u32,
    pub user: *mut c_void,
    pub create: Option<CbCreate>,
    /// Always answered STATUS_SUCCESS (dokan2.dll), unless the host pends.
    pub cleanup: Option<CbStatus>,
    /// No reply. Arrives after the kernel completed every IRP of the open.
    pub close: Option<CbClose>,
    pub read: Option<CbRead>,
    pub write: Option<CbWrite>,
    /// null: STATUS_SUCCESS (dokan2.dll).
    pub flush: Option<CbStatus>,
    pub query_info: Option<CbQueryInfo>,
    pub set_info: Option<CbSetInfo>,
    pub find_files: Option<CbFindFiles>,
    /// null or STATUS_NOT_IMPLEMENTED: dokan2.dll's defaults.
    pub query_volume: Option<CbQueryVolume>,
    pub query_security: Option<CbQuerySecurity>,
    pub set_security: Option<CbSetSecurity>,
    pub mounted: Option<CbMounted>,
    pub unmounted: Option<CbUnmounted>,
    /// ABI 1.1 (the table's `size` says whether it is there): the streams
    /// of a file, for FileStreamInformation with MD_MOUNT_NAMED_STREAMS.
    pub find_streams: Option<CbFindStreams>,
}

/// Opaque mount handle.
#[repr(C)]
pub struct MdInstance {
    _private: [u8; 0],
}
