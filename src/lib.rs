// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details. You should have received a copy of the GNU Lesser General
// Public License along with this library (COPYING.LESSER, COPYING). See NOTICE
// for the Dokany notices of the ported code.

//! `meshfs_dokan.dll`: Dokany 2.3.1's user-mode protocol, ported from
//! `dokan2.dll`, for MeshFS's Windows client.
//!
//! It talks to the unmodified `dokan2.sys` driver with `DeviceIoControl` and
//! hands every request to the host through the `MdHostV1` callback table. It
//! holds no file-system logic, cache or security policy.
//!
//! - [`proto`]: driver constants and structure layouts (`sys/public.h`).
//! - [`marshal`]: request decoding and reply encoding, OS-independent.
//! - [`abi`]: the C ABI's types; `include/meshfs_dokan.h` is the same in C.
//! - `win` (Windows only): the session, the pull threads and the exports.
//!
//! All `unsafe` code is in `win::sys` (the FFI and IOCTL layer) and
//! `win::capi` (the exported functions), each block with its safety argument.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod marshal;
pub mod proto;
pub mod replier;

#[cfg(windows)]
pub mod win;
