// meshfs-dokan write benchmark.
// Copyright (C) 2026 Harland Consulting
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Sequential writes with CreateFileW/WriteFile, the way an application
//! does them, timed per call.
//!
//! mdwbench DIR [--sizes 4k,64k,256k,1m,4m] [--modes buffered,nobuf,wt]
//!          [--alloc pre,extend] [--writers 1,4] [--mib N] [--max-calls N]
//!
//! Each case writes `--mib` MiB (default 256) per writer to its own file in
//! DIR, in calls of one size, capped at `--max-calls` calls (default 8192),
//! with the file opened buffered (no flags), FILE_FLAG_NO_BUFFERING or
//! FILE_FLAG_WRITE_THROUGH, and either preallocated (SetEndOfFile to the full
//! size first, then written from offset 0) or extended by every write. It
//! prints one line per case: MiB/s over all writers and the per-call latency
//! (p50, p99, mean) in microseconds, then deletes the files. With
//! --ctl-stats it then opens `DIR\.ctl-stats`, mdtest's hook that logs its
//! counters, so the library's MESHFS_DOKAN_WRITE_STATS lines in the same log
//! fall between markers, one group per case.

#[cfg(not(windows))]
fn main() {
    eprintln!("mdwbench runs on Windows only");
}

#[cfg(windows)]
fn main() {
    imp::main()
}

#[cfg(windows)]
mod imp {
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, DeleteFileW, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_FLAG_NO_BUFFERING,
        FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, SetEndOfFile, SetFilePointerEx, WriteFile,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn parse_size(s: &str) -> usize {
        let s = s.trim().to_ascii_lowercase();
        let (n, m) = match s.chars().last() {
            Some('k') => (&s[..s.len() - 1], 1 << 10),
            Some('m') => (&s[..s.len() - 1], 1 << 20),
            _ => (&s[..], 1),
        };
        n.parse::<usize>().expect("size") * m
    }

    /// A page-aligned buffer (FILE_FLAG_NO_BUFFERING needs sector alignment).
    struct Buf(*mut u8);
    impl Buf {
        fn new(n: usize) -> Buf {
            // SAFETY: a fresh committed region; freed in Drop.
            let p = unsafe { VirtualAlloc(std::ptr::null(), n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as *mut u8;
            assert!(!p.is_null());
            // SAFETY: `p` holds `n` writable bytes.
            let s = unsafe { std::slice::from_raw_parts_mut(p, n) };
            for (i, b) in s.iter_mut().enumerate() {
                *b = (i * 31 % 251) as u8;
            }
            Buf(p)
        }
    }
    impl Drop for Buf {
        fn drop(&mut self) {
            // SAFETY: the region VirtualAlloc returned.
            unsafe { VirtualFree(self.0 as _, 0, MEM_RELEASE) };
        }
    }

    struct Result1 {
        lat_ns: Vec<u64>,
        bytes: u64,
    }

    fn one(path: &str, size: usize, calls: usize, flags: u32, pre: bool) -> Result<Result1, String> {
        let w = wide(path);
        // SAFETY: a NUL-terminated path; plain arguments.
        let h: HANDLE = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                std::ptr::null(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | flags,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("CreateFileW {path}: {}", std::io::Error::last_os_error()));
        }
        let total = (size * calls) as i64;
        if pre {
            // SAFETY: our handle.
            let ok =
                unsafe { SetFilePointerEx(h, total, std::ptr::null_mut(), FILE_BEGIN) != 0 && SetEndOfFile(h) != 0 };
            // SAFETY: as above.
            let back = unsafe { SetFilePointerEx(h, 0, std::ptr::null_mut(), FILE_BEGIN) };
            if !ok || back == 0 {
                // SAFETY: our handle.
                unsafe { CloseHandle(h) };
                return Err(format!("preallocate: {}", std::io::Error::last_os_error()));
            }
        }
        let buf = Buf::new(size);
        let mut lat = Vec::with_capacity(calls);
        let mut bytes = 0u64;
        for _ in 0..calls {
            let mut n = 0u32;
            let t = Instant::now();
            // SAFETY: `buf` holds `size` bytes; synchronous handle.
            let ok = unsafe { WriteFile(h, buf.0, size as u32, &mut n, std::ptr::null_mut()) };
            lat.push(t.elapsed().as_nanos() as u64);
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                // SAFETY: our handle.
                unsafe { CloseHandle(h) };
                return Err(format!("WriteFile: {e}"));
            }
            bytes += n as u64;
        }
        // SAFETY: our handle.
        unsafe { CloseHandle(h) };
        Ok(Result1 { lat_ns: lat, bytes })
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let dir = args.get(1).cloned().expect("usage: mdwbench DIR [options]");
        let arg = |k: &str, d: &str| -> String {
            args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned().unwrap_or(d.to_string())
        };
        let sizes: Vec<usize> = arg("--sizes", "4k,64k,256k,1m,4m").split(',').map(parse_size).collect();
        let modes: Vec<String> = arg("--modes", "buffered,nobuf,wt").split(',').map(String::from).collect();
        let allocs: Vec<String> = arg("--alloc", "pre,extend").split(',').map(String::from).collect();
        let writers: Vec<usize> = arg("--writers", "1,4").split(',').map(|v| v.parse().unwrap()).collect();
        let mib: usize = arg("--mib", "256").parse().unwrap();
        let max_calls: usize = arg("--max-calls", "8192").parse().unwrap();
        let ctl = args.iter().any(|a| a == "--ctl-stats");
        println!(
            "{:>6} {:>8} {:>6} {:>2} {:>9} {:>8} {:>8} {:>8}",
            "size", "mode", "alloc", "w", "MiB/s", "p50us", "p99us", "meanus"
        );
        for &nw in &writers {
            for alloc in &allocs {
                for mode in &modes {
                    for &size in &sizes {
                        let flags = match mode.as_str() {
                            "buffered" => 0,
                            "nobuf" => FILE_FLAG_NO_BUFFERING,
                            "wt" => FILE_FLAG_WRITE_THROUGH,
                            "nobufwt" => FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                            m => panic!("mode {m}"),
                        };
                        let calls = ((mib << 20) / size).clamp(1, max_calls);
                        let pre = alloc == "pre";
                        let t0 = Instant::now();
                        let rs: Vec<Result<Result1, String>> = std::thread::scope(|s| {
                            let hs: Vec<_> = (0..nw)
                                .map(|i| {
                                    let p = format!("{dir}\\wb{i}.bin");
                                    s.spawn(move || one(&p, size, calls, flags, pre))
                                })
                                .collect();
                            hs.into_iter().map(|h| h.join().unwrap()).collect()
                        });
                        let secs = t0.elapsed().as_secs_f64();
                        for i in 0..nw {
                            let p = wide(&format!("{dir}\\wb{i}.bin"));
                            // SAFETY: a NUL-terminated path.
                            unsafe { DeleteFileW(p.as_ptr()) };
                        }
                        if ctl {
                            // mdtest logs its counters when this name is opened
                            // (the open itself fails): a marker between cases.
                            let p = wide(&format!("{dir}\\.ctl-stats"));
                            // SAFETY: a NUL-terminated path.
                            unsafe { DeleteFileW(p.as_ptr()) };
                        }
                        let mut lat = Vec::new();
                        let mut bytes = 0;
                        let mut err = None;
                        for r in rs {
                            match r {
                                Ok(r) => {
                                    lat.extend(r.lat_ns);
                                    bytes += r.bytes;
                                }
                                Err(e) => err = Some(e),
                            }
                        }
                        let label =
                            if size >= 1 << 20 { format!("{}m", size >> 20) } else { format!("{}k", size >> 10) };
                        if let Some(e) = err {
                            println!("{label:>6} {mode:>8} {alloc:>6} {nw:>2} error: {e}");
                            continue;
                        }
                        lat.sort_unstable();
                        let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)] as f64 / 1000.0;
                        let mean = lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1000.0;
                        println!(
                            "{label:>6} {mode:>8} {alloc:>6} {nw:>2} {:>9.0} {:>8.1} {:>8.1} {:>8.1}",
                            bytes as f64 / (1 << 20) as f64 / secs,
                            pct(0.5),
                            pct(0.99),
                            mean
                        );
                    }
                }
            }
        }
    }
}
