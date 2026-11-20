// meshfs-dokan device probe.
// Copyright (C) 2026 Harland Consulting
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! `mdprobe \Volume{guid}`: can this process open a mounted volume's device
//! and send it an IOCTL? Uses FSCTL_GET_VOLUME_METRICS (harmless, read-only),
//! never a pull, so it cannot steal the mount's requests.

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    use meshfs_dokan::proto::FSCTL_GET_VOLUME_METRICS;
    use meshfs_dokan::win::sys;
    let dev = std::env::args().nth(1).expect("usage: mdprobe \\Volume{guid}");
    let path = format!(r"\\.{dev}");
    match sys::open(&path, sys::Open::Sync) {
        Err(e) => println!("probe: open denied ({e})"),
        Ok(h) => {
            let mut out = [0u8; 56];
            match sys::ioctl(&h, FSCTL_GET_VOLUME_METRICS, &[], &mut out) {
                Ok(n) => println!("probe: open ok, ioctl ok ({n} bytes)"),
                Err(e) => println!("probe: open ok, ioctl failed ({e})"),
            }
        }
    }
}
