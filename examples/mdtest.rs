// meshfs-dokan test host: an in-memory file system behind meshfs_dokan.dll.
// Copyright (C) 2026 Harland Consulting
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Loads `meshfs_dokan.dll` with LoadLibraryExW (as meshfs-datapath will),
//! implements `MdHostV1` over an in-memory tree and mounts it.
//!
//! mdtest [--mount T:] [--dll PATH] [--log PATH] [--threads N]
//!        [--timeout MS] [--preload-mib N] [--current-session]
//!        [--lock-device [--lock-dacl SDDL]]  ({user} = this user's SID)
//!
//! Test hooks (names that drive the host from a script):
//! - creating `\.ctl-stats` appends the counters to the log;
//! - `\.ctl-mutate-NAME` flips every byte of `\NAME` behind the kernel's back;
//! - `\.ctl-unmount` makes the main thread call md_unmount;
//! - reads of `\slow*` are answered later (STATUS_PENDING + md_reply);
//!   `\veryslow*` waits 20 s, resetting the timeout every 2 s;
//!   `\stuck*` waits 20 s without resetting it;
//! - listing `\slowdir` and creating `\slowcreate*` are answered later;
//! - creating `\tokcheck*` logs the requester token's user.

#![allow(clippy::missing_safety_doc, clippy::missing_transmute_annotations)]

#[cfg(not(windows))]
fn main() {
    eprintln!("mdtest runs on Windows only");
}

#[cfg(windows)]
fn main() {
    imp::main()
}

#[cfg(windows)]
mod imp {
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, RwLock, mpsc};
    use std::time::Duration;

    use meshfs_dokan::abi::*;
    use meshfs_dokan::proto::*;

    mod w {
        pub use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
        pub use windows_sys::Win32::Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        };
        pub use windows_sys::Win32::Security::{
            GetSecurityDescriptorLength, GetTokenInformation, SetKernelObjectSecurity, TOKEN_USER, TokenUser,
        };
        pub use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        pub use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
        };
        pub use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    }

    const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000_003A_u32 as i32;
    const STATUS_FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BA_u32 as i32;
    const STATUS_NOT_A_DIRECTORY: NtStatus = 0xC000_0103_u32 as i32;
    const STATUS_DIRECTORY_NOT_EMPTY: NtStatus = 0xC000_0101_u32 as i32;

    // ---- the DLL's exports ---------------------------------------------------

    struct Api {
        abi_version: unsafe extern "C" fn() -> u32,
        driver_version: unsafe extern "C" fn() -> u32,
        mount: unsafe extern "C" fn(*const MdMountOptions, *const MdHostV1, *mut *mut MdInstance) -> i32,
        unmount: unsafe extern "C" fn(*mut MdInstance) -> i32,
        reply: unsafe extern "C" fn(*mut MdInstance, *const MdReply, u32) -> u32,
        requester_token: unsafe extern "C" fn(*mut MdInstance, u64) -> isize,
        reset_timeout: unsafe extern "C" fn(*mut MdInstance, u64, u32) -> u32,
        notify_path: unsafe extern "C" fn(*mut MdInstance, *const u16, u32, u32, u32) -> u32,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn load(path: &str) -> Api {
        let p = wide(path);
        // SAFETY: a NUL-terminated path; full path, altered search path.
        let m = unsafe { w::LoadLibraryExW(p.as_ptr(), std::ptr::null_mut(), w::LOAD_WITH_ALTERED_SEARCH_PATH) };
        assert!(!m.is_null(), "LoadLibraryExW({path}) failed");
        macro_rules! sym {
            ($name:literal) => {{
                // SAFETY: a NUL-terminated name; the module is loaded.
                let f = unsafe { w::GetProcAddress(m, concat!($name, "\0").as_ptr()) };
                let f = f.unwrap_or_else(|| panic!("missing export {}", $name));
                // SAFETY: the export has the signature meshfs_dokan.h declares.
                unsafe { std::mem::transmute(f) }
            }};
        }
        Api {
            abi_version: sym!("md_abi_version"),
            driver_version: sym!("md_driver_version"),
            mount: sym!("md_mount"),
            unmount: sym!("md_unmount"),
            reply: sym!("md_reply"),
            requester_token: sym!("md_requester_token"),
            reset_timeout: sym!("md_reset_timeout"),
            notify_path: sym!("md_notify_path"),
        }
    }

    // ---- the in-memory tree ----------------------------------------------------

    struct Node {
        path: Mutex<String>,
        is_dir: bool,
        data: RwLock<Vec<u8>>,
        attrs: Mutex<u32>,
        times: Mutex<[u64; 4]>,
        id: u64,
    }

    struct Fs {
        tree: Mutex<BTreeMap<String, Arc<Node>>>,
        opens: Mutex<std::collections::HashMap<u64, Arc<Node>>>,
        next_ctx: AtomicU64,
        next_id: AtomicU64,
        reads: AtomicU64,
        writes: AtomicU64,
        creates: AtomicU64,
        lists: AtomicU64,
        sd: Vec<u8>,
        log: Mutex<std::fs::File>,
        ctl: Mutex<mpsc::Sender<&'static str>>,
    }

    static FS: OnceLock<Fs> = OnceLock::new();
    static API: OnceLock<Api> = OnceLock::new();
    static INST: AtomicU64 = AtomicU64::new(0);

    fn fs() -> &'static Fs {
        FS.get().unwrap()
    }

    fn logln(s: String) {
        let mut f = fs().log.lock().unwrap();
        let _ = writeln!(f, "{s}");
        let _ = f.flush();
    }

    fn key(p: &str) -> String {
        p.to_lowercase()
    }

    fn parent(p: &str) -> &str {
        match p.rfind('\\') {
            Some(0) | None => "\\",
            Some(i) => &p[..i],
        }
    }

    fn now() -> u64 {
        meshfs_dokan::marshal::filetime_now()
    }

    impl Fs {
        fn get(&self, p: &str) -> Option<Arc<Node>> {
            self.tree.lock().unwrap().get(&key(p)).cloned()
        }

        fn add(&self, p: &str, is_dir: bool, data: Vec<u8>) -> Arc<Node> {
            let t = now();
            let n = Arc::new(Node {
                path: Mutex::new(p.to_string()),
                is_dir,
                data: RwLock::new(data),
                attrs: Mutex::new(if is_dir { 0x10 } else { 0x20 }),
                times: Mutex::new([t, t, t, t]),
                id: self.next_id.fetch_add(1, Ordering::Relaxed),
            });
            self.tree.lock().unwrap().insert(key(p), n.clone());
            n
        }

        fn children(&self, dir: &str) -> Vec<Arc<Node>> {
            let k = key(dir);
            let prefix = if k == "\\" { "\\".to_string() } else { format!("{k}\\") };
            self.tree
                .lock()
                .unwrap()
                .range(prefix.clone()..)
                .take_while(|(p, _)| p.starts_with(&prefix))
                .filter(|(p, _)| p.len() > prefix.len() && !p[prefix.len()..].contains('\\'))
                .map(|(_, n)| n.clone())
                .collect()
        }

        fn node_of(&self, ctx: u64) -> Option<Arc<Node>> {
            self.opens.lock().unwrap().get(&ctx).cloned()
        }

        fn open(&self, n: Arc<Node>) -> u64 {
            let c = self.next_ctx.fetch_add(1, Ordering::Relaxed);
            self.opens.lock().unwrap().insert(c, n);
            c
        }
    }

    fn s16(p: *const u16, n: u32) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: the library passes valid (pointer, length) strings.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n as usize) })
    }

    fn inst() -> *mut MdInstance {
        INST.load(Ordering::SeqCst) as *mut MdInstance
    }

    fn info_of(n: &Node) -> MdFileInfo {
        let t = *n.times.lock().unwrap();
        MdFileInfo {
            attributes: *n.attrs.lock().unwrap(),
            number_of_links: 1,
            creation_time: t[0],
            last_access_time: t[1],
            last_write_time: t[2],
            change_time: t[3],
            file_size: if n.is_dir { 0 } else { n.data.read().unwrap().len() as u64 },
            allocation_size: 0,
            file_index: n.id,
            volume_serial: 0x4D44_5445,
            _reserved: 0,
        }
    }

    // ---- callbacks ---------------------------------------------------------------

    unsafe extern "C" fn cb_create(
        _u: *mut c_void,
        req: *const MdRequest,
        p: *const MdCreateRequest,
        out: *mut MdCreateReply,
    ) -> NtStatus {
        // SAFETY: valid for the call (library contract).
        let (req, p, out) = unsafe { (&*req, &*p, &mut *out) };
        let f = fs();
        f.creates.fetch_add(1, Ordering::Relaxed);
        let path = s16(req.path, req.path_len);
        let name = path.rsplit('\\').next().unwrap_or("").to_string();
        if let Some(cmd) = name.strip_prefix(".ctl-") {
            if cmd == "stats" {
                logln(format!(
                    "stats reads={} writes={} creates={} lists={}",
                    f.reads.load(Ordering::Relaxed),
                    f.writes.load(Ordering::Relaxed),
                    f.creates.load(Ordering::Relaxed),
                    f.lists.load(Ordering::Relaxed)
                ));
            } else if let Some(target) = cmd.strip_prefix("mutate-") {
                if let Some(n) = f.get(&format!("\\{target}")) {
                    for b in n.data.write().unwrap().iter_mut() {
                        *b ^= 0xFF;
                    }
                    logln(format!("mutated {target}"));
                }
            } else if cmd == "unmount" {
                let _ = f.ctl.lock().unwrap().send("unmount");
            }
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if name.starts_with("tokcheck") {
            let api = API.get().unwrap();
            // SAFETY: a live instance; the request is a create in its callback.
            let h = unsafe { (api.requester_token)(inst(), req.request_id) };
            logln(format!("token for {path}: {}", token_user(h)));
        }
        let r = do_create(f, &path, p, out);
        if name.starts_with("slowcreate") {
            let id = req.request_id;
            let reply = *out;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                let mut m = MdReply::status(id, r);
                m.create = &reply;
                let api = API.get().unwrap();
                // SAFETY: a live instance and a reply valid for the call.
                let n = unsafe { (api.reply)(inst(), &m, 1) };
                logln(format!("deferred create {id}: accepted {n}"));
            });
            return STATUS_PENDING;
        }
        r
    }

    fn do_create(f: &Fs, path: &str, p: &MdCreateRequest, out: &mut MdCreateReply) -> NtStatus {
        let disp = p.disposition;
        let want_dir = p.create_options & FILE_DIRECTORY_FILE != 0;
        let want_file = p.create_options & FILE_NON_DIRECTORY_FILE != 0;
        if p.flags & MD_CREATE_OPEN_TARGET_DIRECTORY != 0 {
            let target = s16(p.target, p.target_len);
            if f.get(&target).is_none() {
                out.flags |= MD_CREATE_TARGET_MISSING;
            }
        }
        match f.get(path) {
            Some(n) => {
                if disp == FILE_CREATE {
                    return STATUS_OBJECT_NAME_COLLISION;
                }
                if n.is_dir && want_file {
                    return STATUS_FILE_IS_A_DIRECTORY;
                }
                if !n.is_dir && want_dir {
                    return STATUS_NOT_A_DIRECTORY;
                }
                if !n.is_dir && matches!(disp, FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE) {
                    n.data.write().unwrap().clear();
                }
                if n.is_dir {
                    out.flags |= MD_CREATE_IS_DIRECTORY;
                }
                out.context = f.open(n);
                if matches!(disp, FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE) {
                    STATUS_OBJECT_NAME_COLLISION
                } else {
                    STATUS_SUCCESS
                }
            }
            None => {
                if matches!(disp, FILE_OPEN | FILE_OVERWRITE) {
                    return if f.get(parent(path)).is_some() {
                        STATUS_OBJECT_NAME_NOT_FOUND
                    } else {
                        STATUS_OBJECT_PATH_NOT_FOUND
                    };
                }
                match f.get(parent(path)) {
                    Some(d) if d.is_dir => {}
                    _ => return STATUS_OBJECT_PATH_NOT_FOUND,
                }
                let n = f.add(path, want_dir, Vec::new());
                if want_dir {
                    out.flags |= MD_CREATE_IS_DIRECTORY;
                }
                out.context = f.open(n);
                STATUS_SUCCESS
            }
        }
    }

    fn token_user(h: isize) -> String {
        if h == -1 || h == 0 {
            return "no token".into();
        }
        let h = h as w::HANDLE;
        let mut buf = vec![0u8; 512];
        let mut n = 0u32;
        // SAFETY: a token handle and a writable buffer.
        let ok = unsafe { w::GetTokenInformation(h, w::TokenUser, buf.as_mut_ptr().cast(), 512, &mut n) };
        let mut out = "GetTokenInformation failed".to_string();
        if ok != 0 {
            // SAFETY: GetTokenInformation filled a TOKEN_USER.
            let tu = unsafe { &*(buf.as_ptr() as *const w::TOKEN_USER) };
            let mut s: *mut u16 = std::ptr::null_mut();
            // SAFETY: a valid SID; LocalFree releases the string.
            if unsafe { w::ConvertSidToStringSidW(tu.User.Sid, &mut s) } != 0 {
                let mut l = 0;
                // SAFETY: a NUL-terminated string from the API.
                while unsafe { *s.add(l) } != 0 {
                    l += 1;
                }
                out = s16(s, l as u32);
                // SAFETY: allocated by ConvertSidToStringSidW.
                unsafe { w::LocalFree(s.cast()) };
            }
        }
        // SAFETY: we own the handle md_requester_token returned.
        unsafe { w::CloseHandle(h) };
        out
    }

    unsafe extern "C" fn cb_cleanup(_u: *mut c_void, req: *const MdRequest) -> NtStatus {
        // SAFETY: valid for the call.
        let req = unsafe { &*req };
        let f = fs();
        if req.file_flags & MD_FILE_DELETE_ON_CLOSE != 0
            && let Some(n) = f.node_of(req.context)
        {
            let p = n.path.lock().unwrap().clone();
            f.tree.lock().unwrap().remove(&key(&p));
            let api = API.get().unwrap();
            let rel = wide(&p);
            let filter = if n.is_dir { 0x2 } else { 0x1 }; // FILE_NOTIFY_CHANGE_DIR_NAME / FILE_NAME
            // SAFETY: a live instance and a valid path (we notify a delete; the
            // driver already reports it, this exercises the call).
            let e = unsafe { (api.notify_path)(inst(), rel.as_ptr(), (rel.len() - 1) as u32, filter, 2) };
            if e != 0 {
                logln(format!("notify_path({p}) = {e}"));
            }
        }
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_close(_u: *mut c_void, req: *const MdRequest) {
        // SAFETY: valid for the call.
        let req = unsafe { &*req };
        fs().opens.lock().unwrap().remove(&req.context);
    }

    fn read_into(n: &Node, offset: i64, buf: &mut [u8]) -> u32 {
        let d = n.data.read().unwrap();
        let off = offset.max(0) as usize;
        if off >= d.len() {
            return 0;
        }
        let k = buf.len().min(d.len() - off);
        buf[..k].copy_from_slice(&d[off..off + k]);
        k as u32
    }

    unsafe extern "C" fn cb_read(
        _u: *mut c_void,
        req: *const MdRequest,
        offset: i64,
        length: u32,
        buffer: *mut u8,
        out: *mut u32,
    ) -> NtStatus {
        // SAFETY: valid for the call; `buffer` holds `length` bytes.
        let (req, buf, out) = unsafe { (&*req, std::slice::from_raw_parts_mut(buffer, length as usize), &mut *out) };
        let f = fs();
        f.reads.fetch_add(1, Ordering::Relaxed);
        let Some(n) = f.node_of(req.context) else { return STATUS_INVALID_PARAMETER };
        let name = n.path.lock().unwrap().rsplit('\\').next().unwrap_or("").to_lowercase();
        let (delay, reset) = if name.starts_with("veryslow") {
            (20000, true)
        } else if name.starts_with("stuck") {
            (20000, false)
        } else if name.starts_with("slow") {
            (300, false)
        } else {
            *out = read_into(&n, offset, buf);
            return STATUS_SUCCESS;
        };
        let id = req.request_id;
        std::thread::spawn(move || {
            let api = API.get().unwrap();
            let mut waited = 0;
            while waited < delay {
                std::thread::sleep(Duration::from_millis(500));
                waited += 500;
                if reset && waited % 2000 == 0 {
                    // SAFETY: a live instance.
                    let e = unsafe { (api.reset_timeout)(inst(), id, 6000) };
                    if e != 0 {
                        logln(format!("reset_timeout {id}: {e}"));
                    }
                }
            }
            let mut data = vec![0u8; length as usize];
            let k = read_into(&n, offset, &mut data);
            let mut m = MdReply::status(id, STATUS_SUCCESS);
            m.data = data.as_ptr();
            m.data_len = k;
            // SAFETY: a live instance and a reply valid for the call.
            let acc = unsafe { (api.reply)(inst(), &m, 1) };
            // A second answer for the same request must be refused.
            // SAFETY: as above.
            let again = unsafe { (api.reply)(inst(), &m, 1) };
            logln(format!(
                "deferred read {id} of {name} after {delay} ms: {k} bytes, accepted {acc}, second reply accepted {again}"
            ));
        });
        STATUS_PENDING
    }

    unsafe extern "C" fn cb_write(
        _u: *mut c_void,
        req: *const MdRequest,
        offset: i64,
        data: *const u8,
        length: u32,
        out: *mut u32,
    ) -> NtStatus {
        // SAFETY: valid for the call.
        let (req, data, out) = unsafe { (&*req, std::slice::from_raw_parts(data, length as usize), &mut *out) };
        let f = fs();
        f.writes.fetch_add(1, Ordering::Relaxed);
        let Some(n) = f.node_of(req.context) else { return STATUS_INVALID_PARAMETER };
        let mut d = n.data.write().unwrap();
        let off = if req.file_flags & MD_FILE_WRITE_TO_END_OF_FILE != 0 { d.len() } else { offset.max(0) as usize };
        if req.file_flags & MD_FILE_PAGING_IO != 0 && off >= d.len() {
            *out = 0;
            return STATUS_SUCCESS;
        }
        let mut take = data.len();
        if req.file_flags & MD_FILE_PAGING_IO != 0 {
            take = take.min(d.len() - off);
        }
        if off == d.len() {
            // An append: one pass over the new bytes, not a zero fill and a copy.
            d.extend_from_slice(&data[..take]);
        } else {
            if d.len() < off + take {
                d.resize(off + take, 0);
            }
            d[off..off + take].copy_from_slice(&data[..take]);
        }
        *out = take as u32;
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_flush(_u: *mut c_void, _req: *const MdRequest) -> NtStatus {
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_query_info(
        _u: *mut c_void,
        req: *const MdRequest,
        _class: u32,
        out: *mut MdFileInfo,
    ) -> NtStatus {
        // SAFETY: valid for the call.
        let (req, out) = unsafe { (&*req, &mut *out) };
        match fs().node_of(req.context) {
            Some(n) => {
                *out = info_of(&n);
                STATUS_SUCCESS
            }
            None => STATUS_INVALID_PARAMETER,
        }
    }

    unsafe extern "C" fn cb_set_info(_u: *mut c_void, req: *const MdRequest, p: *const MdSetInfoRequest) -> NtStatus {
        // SAFETY: valid for the call.
        let (req, p) = unsafe { (&*req, &*p) };
        let f = fs();
        let Some(n) = f.node_of(req.context) else { return STATUS_INVALID_PARAMETER };
        match p.kind {
            MD_SET_BASIC => {
                if p.attributes != 0 {
                    *n.attrs.lock().unwrap() = p.attributes | if n.is_dir { 0x10 } else { 0 };
                }
                let mut t = n.times.lock().unwrap();
                for (i, v) in [p.creation_time, p.last_access_time, p.last_write_time, p.change_time].iter().enumerate()
                {
                    if *v > 0 {
                        t[i] = *v as u64;
                    }
                }
                STATUS_SUCCESS
            }
            MD_SET_END_OF_FILE | MD_SET_VALID_DATA_LENGTH => {
                n.data.write().unwrap().resize(p.size.max(0) as usize, 0);
                STATUS_SUCCESS
            }
            MD_SET_ALLOCATION => {
                let mut d = n.data.write().unwrap();
                if (p.size.max(0) as usize) < d.len() {
                    d.truncate(p.size.max(0) as usize);
                }
                STATUS_SUCCESS
            }
            MD_SET_DISPOSITION => {
                let path = n.path.lock().unwrap().clone();
                if p.delete != 0 && n.is_dir && !f.children(&path).is_empty() {
                    return STATUS_DIRECTORY_NOT_EMPTY;
                }
                STATUS_SUCCESS
            }
            MD_SET_RENAME => {
                let new = s16(p.new_name, p.new_name_len);
                let old = n.path.lock().unwrap().clone();
                let mut t = f.tree.lock().unwrap();
                if key(&new) != key(&old) {
                    if let Some(e) = t.get(&key(&new)) {
                        if p.replace_if_exists == 0 {
                            return STATUS_OBJECT_NAME_COLLISION;
                        }
                        if e.is_dir {
                            return STATUS_ACCESS_DENIED;
                        }
                    }
                    if !t.get(&key(parent(&new))).is_some_and(|d| d.is_dir) {
                        return STATUS_OBJECT_PATH_NOT_FOUND;
                    }
                }
                // Move the node and, for a directory, everything under it.
                let ok = key(&old);
                let moved: Vec<(String, Arc<Node>)> = t
                    .iter()
                    .filter(|(k, _)| **k == ok || k.starts_with(&format!("{ok}\\")))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (k, v) in moved {
                    t.remove(&k);
                    let mut p = v.path.lock().unwrap();
                    let np = format!("{new}{}", &p[old.len()..]);
                    *p = np.clone();
                    t.insert(key(&np), v.clone());
                }
                STATUS_SUCCESS
            }
            _ => STATUS_INVALID_PARAMETER,
        }
    }

    fn find_entry(n: &Node, name: &[u16]) -> MdFindEntry {
        let fi = info_of(n);
        MdFindEntry {
            name: name.as_ptr(),
            name_len: name.len() as u32,
            attributes: fi.attributes,
            creation_time: fi.creation_time,
            last_access_time: fi.last_access_time,
            last_write_time: fi.last_write_time,
            change_time: fi.change_time,
            file_size: fi.file_size,
            allocation_size: 0,
            file_id: fi.file_index,
        }
    }

    unsafe extern "C" fn cb_find_files(
        _u: *mut c_void,
        req: *const MdRequest,
        _pattern: *const u16,
        _pattern_len: u32,
        fill: MdFindFill,
        fill_ctx: *mut c_void,
    ) -> NtStatus {
        // SAFETY: valid for the call.
        let req = unsafe { &*req };
        let f = fs();
        f.lists.fetch_add(1, Ordering::Relaxed);
        let dir = s16(req.path, req.path_len);
        let kids = f.children(&dir);
        let names: Vec<Vec<u16>> =
            kids.iter().map(|n| n.path.lock().unwrap().rsplit('\\').next().unwrap().encode_utf16().collect()).collect();
        if key(&dir) == "\\slowdir" {
            let id = req.request_id;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                let entries: Vec<MdFindEntry> = kids.iter().zip(&names).map(|(n, nm)| find_entry(n, nm)).collect();
                let mut m = MdReply::status(id, STATUS_SUCCESS);
                m.entries = entries.as_ptr();
                m.entry_count = entries.len() as u32;
                let api = API.get().unwrap();
                // SAFETY: a live instance; entries and names live for the call.
                let acc = unsafe { (api.reply)(inst(), &m, 1) };
                logln(format!("deferred listing {id}: {} entries, accepted {acc}", entries.len()));
            });
            return STATUS_PENDING;
        }
        for (n, nm) in kids.iter().zip(&names) {
            let e = find_entry(n, nm);
            // SAFETY: the library's fill function, during find_files.
            unsafe { fill(fill_ctx, &e) };
        }
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_query_volume(_u: *mut c_void, _req: *const MdRequest, out: *mut MdVolumeInfo) -> NtStatus {
        // SAFETY: valid for the call.
        let v = unsafe { &mut *out };
        v.total_bytes = 64 << 30;
        v.free_bytes = 32 << 30;
        v.available_bytes = 32 << 30;
        v.serial = 0x4D44_5445;
        v.max_component_length = 255;
        v.fs_flags = 0x2 | 0x4 | 0x8; // case preserved, unicode, persistent ACLs
        for (i, c) in "MDTEST".encode_utf16().enumerate() {
            v.label[i] = c;
        }
        v.label_len = 6;
        for (i, c) in "NTFS".encode_utf16().enumerate() {
            v.fs_name[i] = c;
        }
        v.fs_name_len = 4;
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_query_security(
        _u: *mut c_void,
        _req: *const MdRequest,
        _info: u32,
        buffer: *mut u8,
        len: u32,
        needed: *mut u32,
    ) -> NtStatus {
        let sd = &fs().sd;
        // SAFETY: valid for the call.
        unsafe { *needed = sd.len() as u32 };
        if (len as usize) < sd.len() {
            return STATUS_BUFFER_OVERFLOW;
        }
        // SAFETY: `buffer` holds `len` >= sd.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(sd.as_ptr(), buffer, sd.len()) };
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_set_security(
        _u: *mut c_void,
        _r: *const MdRequest,
        _i: u32,
        _d: *const u8,
        _l: u32,
    ) -> NtStatus {
        STATUS_SUCCESS
    }

    unsafe extern "C" fn cb_mounted(_u: *mut c_void, mp: *const u16, mpl: u32, dn: *const u16, dnl: u32) {
        let (m, d) = (s16(mp, mpl), s16(dn, dnl));
        logln(format!("mounted {m} device {d}"));
        let _ = DEVICE.set(d);
    }

    static DEVICE: OnceLock<String> = OnceLock::new();

    unsafe extern "C" fn cb_unmounted(_u: *mut c_void) {
        logln("unmounted".into());
        let _ = fs().ctl.lock().unwrap().send("gone");
    }

    fn sddl_to_sd(sddl: &str) -> Vec<u8> {
        let s = wide(sddl);
        let mut p: *mut c_void = std::ptr::null_mut();
        let mut n = 0u32;
        // SAFETY: a valid SDDL string; LocalFree releases the descriptor.
        let ok = unsafe { w::ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), 1, &mut p, &mut n) };
        assert!(ok != 0, "bad SDDL {sddl}");
        // SAFETY: `p` holds `n` bytes.
        let v = unsafe { std::slice::from_raw_parts(p as *const u8, n as usize) }.to_vec();
        // SAFETY: the self-relative descriptor is valid; then freed once.
        let _ = unsafe { w::GetSecurityDescriptorLength(p) };
        // SAFETY: allocated by the conversion.
        unsafe { w::LocalFree(p) };
        v
    }

    fn current_user_sid() -> String {
        let mut h: w::HANDLE = std::ptr::null_mut();
        // SAFETY: our own process token, query access.
        unsafe { w::OpenProcessToken(w::GetCurrentProcess(), 0x0008, &mut h) };
        token_user(h as isize)
    }

    /// The spike's question 3a: can the host lock its volume device down at run
    /// time? Sets a DACL of SYSTEM + this user and a Medium no-read-up label.
    fn lock_device(device: &str, dacl: &str) {
        let path = wide(&format!(r"\\.{device}"));
        // WRITE_DAC | WRITE_OWNER | READ_CONTROL
        let access = 0x0004_0000 | 0x0008_0000 | 0x0002_0000;
        // SAFETY: a NUL-terminated path.
        let h = unsafe {
            w::CreateFileW(
                path.as_ptr(),
                access,
                w::FILE_SHARE_READ | w::FILE_SHARE_WRITE,
                std::ptr::null(),
                w::OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h as isize == -1 {
            logln(format!("lock-device: open with WRITE_DAC failed: {}", std::io::Error::last_os_error()));
            return;
        }
        let user = current_user_sid();
        for (what, sddl, info) in
            [("dacl", dacl.replace("{user}", &user), 0x4u32), ("label", "S:(ML;;NWNRNX;;;ME)".to_string(), 0x10u32)]
        {
            let sd = sddl_to_sd(&sddl);
            // SAFETY: a valid handle and descriptor.
            let ok = unsafe { w::SetKernelObjectSecurity(h, info, sd.as_ptr() as *mut c_void) };
            logln(format!(
                "lock-device: set {what} {sddl}: {}",
                if ok != 0 { "ok".to_string() } else { std::io::Error::last_os_error().to_string() }
            ));
        }
        // SAFETY: our handle.
        unsafe { w::CloseHandle(h) };
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let arg = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
        let flag = |k: &str| args.iter().any(|a| a == k);
        let exe = std::env::current_exe().unwrap();
        let default_dll = exe.parent().unwrap().parent().unwrap().join("meshfs_dokan.dll");
        let dll = arg("--dll").unwrap_or(default_dll.to_string_lossy().into_owned());
        let mount_point = arg("--mount").unwrap_or("T:".into());
        let log = arg("--log").unwrap_or("mdtest.log".into());
        let (tx, rx) = mpsc::channel();
        let fsv = Fs {
            tree: Mutex::new(BTreeMap::new()),
            opens: Mutex::new(Default::default()),
            next_ctx: AtomicU64::new(1),
            next_id: AtomicU64::new(1),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            creates: AtomicU64::new(0),
            lists: AtomicU64::new(0),
            sd: sddl_to_sd("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)"),
            log: Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(&log).unwrap()),
            ctl: Mutex::new(tx),
        };
        let _ = FS.set(fsv);
        let f = fs();
        f.add("\\", true, Vec::new());
        f.add("\\slowdir", true, Vec::new());
        for i in 0..3 {
            f.add(&format!("\\slowdir\\f{i}.txt"), false, vec![b'x'; 10 * i]);
        }
        if let Some(mib) = arg("--preload-mib").and_then(|v| v.parse::<usize>().ok()) {
            let mut d = vec![0u8; mib << 20];
            let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
            for c in d.chunks_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
            }
            f.add("\\big.bin", false, d);
        }
        let _ = API.set(load(&dll));
        let api = API.get().unwrap();
        // SAFETY: plain calls into the loaded library.
        let (abi, drv) = unsafe { ((api.abi_version)(), (api.driver_version)()) };
        logln(format!("dll {dll} abi 0x{abi:x} driver 0x{drv:x} pid {}", std::process::id()));
        if abi >> 16 != MD_ABI_MAJOR {
            logln("unknown ABI major; refusing".into());
            std::process::exit(2);
        }
        let host = MdHostV1 {
            size: std::mem::size_of::<MdHostV1>() as u32,
            version: MD_ABI_VERSION,
            user: std::ptr::null_mut(),
            create: Some(cb_create),
            cleanup: Some(cb_cleanup),
            close: Some(cb_close),
            read: Some(cb_read),
            write: Some(cb_write),
            flush: Some(cb_flush),
            query_info: Some(cb_query_info),
            set_info: Some(cb_set_info),
            find_files: Some(cb_find_files),
            query_volume: Some(cb_query_volume),
            query_security: Some(cb_query_security),
            set_security: Some(cb_set_security),
            mounted: Some(cb_mounted),
            unmounted: Some(cb_unmounted),
            find_streams: None,
        };
        let mp = wide(&mount_point);
        let mut flags = 0;
        if flag("--current-session") {
            flags |= MD_MOUNT_CURRENT_SESSION;
        }
        let opts = MdMountOptions {
            size: std::mem::size_of::<MdMountOptions>() as u32,
            flags,
            mount_point: mp.as_ptr(),
            unc_name: std::ptr::null(),
            irp_timeout_ms: arg("--timeout").and_then(|v| v.parse().ok()).unwrap_or(0),
            fcb_gc_interval_ms: 0,
            pull_threads: arg("--threads").and_then(|v| v.parse().ok()).unwrap_or(0),
            sector_size: 0,
            allocation_unit_size: 0,
            volume_security_descriptor_len: 0,
            volume_security_descriptor: std::ptr::null(),
        };
        let mut i: *mut MdInstance = std::ptr::null_mut();
        // SAFETY: valid options and table; `i` is writable.
        let rc = unsafe { (api.mount)(&opts, &host, &mut i) };
        logln(format!("md_mount = {rc}"));
        if rc != MD_OK {
            std::process::exit(1);
        }
        INST.store(i as u64, Ordering::SeqCst);
        if flag("--lock-device")
            && let Some(d) = DEVICE.get()
        {
            lock_device(d, &arg("--lock-dacl").unwrap_or("D:P(A;;GA;;;SY)(A;;GA;;;{user})".into()));
        }
        let why = rx.recv().unwrap_or("gone");
        if why == "gone" {
            logln("the driver ended the mount".into());
        }
        // SAFETY: the live instance, from the main thread (frees it).
        let rc = unsafe { (api.unmount)(i) };
        logln(format!("md_unmount = {rc}"));
    }
}
