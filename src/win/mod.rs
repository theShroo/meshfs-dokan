// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! The Windows side: driver calls, the mount session, the pull threads and
//! the exported C ABI.

pub mod capi;
mod host;
mod pull;
pub mod session;
pub mod sys;
mod wstats;
