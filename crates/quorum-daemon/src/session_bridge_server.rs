//! Silent Interactive-Session Filesystem Bridge Server (`quorum-desktop --session-fs-bridge`).
//!
//! Spawned automatically inside the active interactive desktop session (Session >= 1) by
//! `QuorumRAGDaemon` (running as Windows `LocalSystem` in Session 0) via `WTSQueryUserToken` +
//! `CreateProcessAsUserW`. Because this process executes inside the user's real logon session,
//! per-user Dokan / WinFSP / virtual cloud drives (such as Google Drive `G:\My Drive` and pCloud
//! `P:\`) are natively visible, browsable, readable, watchable, and openable.
//!
//! Security invariants:
//! - Binds strictly to `127.0.0.1:0` (ephemeral loopback port only).
//! - Authenticates every request with a 256-bit shared secret received exclusively via stdin pipe
//!   (never CLI arguments or disk), verified with constant-time comparison (`subtle`).
//! - Canonicalizes every requested path (`std::fs::canonicalize`) after `validate_cloud_drive_path`.
//! - Enforces `CloudPlaceholderPolicy` BEFORE opening or reading any file bytes.
//! - Exits automatically the instant the parent `QuorumRAGDaemon` process exits.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use quorum_types::session_fs_bridge::{
    BridgeDirEntry, BridgeDriveInfo, BridgeStatInfo, BridgeWalkEntry, BridgeWatchEvent,
};
use quorum_types::{
    normalize_prefix_for_match, path_matches_prefix, validate_cloud_drive_path,
    CloudPlaceholderMode,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

const MAX_REQ_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQ_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_CONNS: usize = 16;
const MAX_READ_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WALK_FILES: usize = 250_000;
const MAX_WALK_DIRS: usize = 50_000;
const MAX_QUEUED_EVENTS: usize = 4_096;
const MAX_SOCKET_ITERS: usize = 8_192;

#[derive(Default)]
struct WatchState {
    roots: Vec<PathBuf>,
    snapshots: HashMap<PathBuf, HashMap<String, (u64, i64)>>,
    events: Vec<BridgeWatchEvent>,
}

struct BridgeServerState {
    token: String,
    watch: Mutex<WatchState>,
    drives_cache: Mutex<Option<(std::time::Instant, Vec<BridgeDriveInfo>)>>,
    active_conns: AtomicUsize,
}

struct ConnGuard {
    counter: Arc<BridgeServerState>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.counter.active_conns.fetch_sub(1, Ordering::SeqCst);
    }
}

fn strip_win_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/')
        {
            return rest.to_string();
        }
    }
    s.to_string()
}

fn is_placeholder_meta(meta: &std::fs::Metadata) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
        const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
        const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let attrs = meta.file_attributes();
        (attrs & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)) != 0
            || ((attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN) != 0
                && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = meta;
        false
    }
}

fn should_skip_placeholder(
    is_placeholder: bool,
    size_bytes: u64,
    mode: CloudPlaceholderMode,
    hydration_cap_bytes: u64,
) -> bool {
    if !is_placeholder {
        return false;
    }
    match mode {
        CloudPlaceholderMode::LocallySyncedOnly => true,
        CloudPlaceholderMode::HydrateOnDemand => size_bytes > hydration_cap_bytes,
    }
}

fn is_safe_single_folder_name(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed == "." || trimmed == ".." {
        return false;
    }
    if trimmed.ends_with('.') || trimmed.ends_with(' ') {
        return false;
    }
    !trimmed.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'
            )
    })
}

fn is_blocked_open_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "drv"
            | "bat"
            | "cmd"
            | "ps1"
            | "psm1"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "wsh"
            | "msi"
            | "msp"
            | "scr"
            | "com"
            | "pif"
            | "hta"
            | "cpl"
            | "lnk"
            | "reg"
    )
}

#[cfg(target_os = "windows")]
fn read_hkcu_google_drive_letter_fast() -> Option<char> {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: *mut c_void,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut *mut c_void,
        ) -> i32;
        fn RegQueryValueExW(
            h_key: *mut c_void,
            lp_value_name: *const u16,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegCloseKey(h_key: *mut c_void) -> i32;
    }

    const HKEY_CURRENT_USER: *mut c_void = 0x8000_0001usize as *mut c_void;
    const KEY_READ: u32 = 0x20019;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;

    let sub: Vec<u16> = "Software\\Google\\DriveFS\\Share"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut h_key: *mut c_void = null_mut();
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_READ, &mut h_key) } != 0
        || h_key.is_null()
    {
        return None;
    }

    let mut found: Option<char> = None;
    for val_name in ["MountPoint", "DefaultMountPoint", "SyncTargets"] {
        let val_w: Vec<u16> = val_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut reg_type: u32 = 0;
        let mut buf_len: u32 = 0;
        if unsafe {
            RegQueryValueExW(
                h_key,
                val_w.as_ptr(),
                null_mut(),
                &mut reg_type,
                null_mut(),
                &mut buf_len,
            )
        } != 0
            || buf_len == 0
            || buf_len > 65_536
        {
            continue;
        }
        let mut buf = vec![0u8; buf_len as usize];
        if unsafe {
            RegQueryValueExW(
                h_key,
                val_w.as_ptr(),
                null_mut(),
                &mut reg_type,
                buf.as_mut_ptr(),
                &mut buf_len,
            )
        } != 0
        {
            continue;
        }
        buf.truncate(buf_len as usize);
        if reg_type == REG_SZ || reg_type == REG_EXPAND_SZ {
            let u16s: Vec<u16> = buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&w| w != 0)
                .collect();
            let s = String::from_utf16_lossy(&u16s);
            let trimmed = s.trim();
            if let Some(ch) = trimmed.chars().next() {
                if ch.is_ascii_alphabetic() {
                    found = Some(ch.to_ascii_uppercase());
                    break;
                }
            }
        } else if reg_type == REG_BINARY {
            // Google DriveFS v134 SyncTargets protobuf encodes the mounted drive letter as
            // length-delimited `[0x02, <letter>, b':']` or `[0x03, <letter>, b':', b'\\']`.
            for w in buf.windows(3) {
                if (w[0] == 0x02 || w[0] == 0x03)
                    && w[1].is_ascii_uppercase()
                    && w[2] == b':'
                    && w[1] != b'C'
                {
                    found = Some(w[1] as char);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
    }

    unsafe {
        let _ = RegCloseKey(h_key);
    }
    found
}

fn enumerate_session_drives() -> Vec<BridgeDriveInfo> {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
            fn QueryDosDeviceW(
                lp_device_name: *const u16,
                lp_target_path: *mut u16,
                ucch_max: u32,
            ) -> u32;
            fn GetVolumeInformationW(
                lp_root_path_name: *const u16,
                lp_volume_name_buffer: *mut u16,
                n_volume_name_size: u32,
                lp_volume_serial_number: *mut u32,
                lp_maximum_component_length: *mut u32,
                lp_file_system_flags: *mut u32,
                lp_file_system_name_buffer: *mut u16,
                n_file_system_name_size: u32,
            ) -> i32;
        }

        const DRIVE_UNKNOWN: u32 = 0;
        const DRIVE_NO_ROOT_DIR: u32 = 1;
        const DRIVE_CDROM: u32 = 5;

        let gdrive_hint_letter = read_hkcu_google_drive_letter_fast();

        // Phase 1: Instant (0 ms) kernel DOS-device enumeration (never blocks on Dokan/SMB IRPs).
        let mut base_drives: Vec<BridgeDriveInfo> = Vec::new();
        for letter in b'C'..=b'Z' {
            let ch = letter as char;
            let root_str = format!("{ch}:\\");
            let root_w: Vec<u16> = root_str.encode_utf16().chain(std::iter::once(0)).collect();
            let drive_type = unsafe { GetDriveTypeW(root_w.as_ptr()) };
            if drive_type == DRIVE_UNKNOWN
                || drive_type == DRIVE_NO_ROOT_DIR
                || drive_type == DRIVE_CDROM
            {
                continue;
            }

            let dos_dev = format!("{ch}:");
            let dos_w: Vec<u16> = dos_dev.encode_utf16().chain(std::iter::once(0)).collect();
            let mut target_buf = [0u16; 512];
            let chars = unsafe {
                QueryDosDeviceW(
                    dos_w.as_ptr(),
                    target_buf.as_mut_ptr(),
                    target_buf.len() as u32,
                )
            };
            let nt_target = if chars > 0 {
                let len = target_buf.iter().position(|&c| c == 0).unwrap_or(0);
                String::from_utf16_lossy(&target_buf[..len])
            } else {
                String::new()
            };

            let nt_lower = nt_target.to_ascii_lowercase();
            let is_gdrive_hint = gdrive_hint_letter == Some(ch)
                && !nt_target.starts_with(r"\Device\HarddiskVolume");
            let is_virtual = !nt_target.starts_with(r"\Device\HarddiskVolume")
                || nt_lower.contains("drivefs")
                || nt_lower.contains("dokan")
                || is_gdrive_hint;

            base_drives.push(BridgeDriveInfo {
                letter: ch,
                root: root_str,
                drive_type,
                volume_label: if is_gdrive_hint {
                    "Google Drive".to_string()
                } else {
                    String::new()
                },
                nt_target,
                is_virtual,
                has_my_drive: is_gdrive_hint,
                has_shared_drives: false,
            });
        }

        if base_drives.is_empty() {
            return base_drives;
        }

        // Phase 2: Bounded parallel per-drive metadata enrichment (max 1.2s total budget so a
        // transiently busy Dokan/SMB mount can never stall /bridge/drives or hide C:/D:/G:).
        let (tx, rx) = std::sync::mpsc::channel::<(char, bool, String, bool, bool)>();
        let probe_count = base_drives.len();
        for drv in &base_drives {
            let tx_c = tx.clone();
            let ch = drv.letter;
            let root_str = drv.root.clone();
            std::thread::spawn(move || {
                let is_dir = Path::new(&root_str).is_dir();
                if !is_dir {
                    let _ = tx_c.send((ch, false, String::new(), false, false));
                    return;
                }
                let root_w: Vec<u16> = root_str.encode_utf16().chain(std::iter::once(0)).collect();
                let mut vol_buf = [0u16; 261];
                let mut fs_buf = [0u16; 261];
                let ok = unsafe {
                    GetVolumeInformationW(
                        root_w.as_ptr(),
                        vol_buf.as_mut_ptr(),
                        vol_buf.len() as u32,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        fs_buf.as_mut_ptr(),
                        fs_buf.len() as u32,
                    )
                };
                let volume_label = if ok != 0 {
                    let len = vol_buf.iter().position(|&c| c == 0).unwrap_or(0);
                    String::from_utf16_lossy(&vol_buf[..len])
                } else {
                    String::new()
                };
                let has_my_drive = Path::new(&root_str).join("My Drive").is_dir();
                let has_shared_drives = Path::new(&root_str).join("Shared drives").is_dir();
                let _ = tx_c.send((ch, true, volume_label, has_my_drive, has_shared_drives));
            });
        }
        drop(tx);

        let deadline = std::time::Instant::now() + Duration::from_millis(1200);
        let mut probed: HashMap<char, (bool, String, bool, bool)> = HashMap::new();
        for _ in 0..probe_count {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            match rx.recv_timeout(deadline.saturating_duration_since(now)) {
                Ok((ch, is_dir, lbl, has_md, has_sd)) => {
                    probed.insert(ch, (is_dir, lbl, has_md, has_sd));
                }
                Err(_) => break,
            }
        }

        let mut drives = Vec::with_capacity(base_drives.len());
        for mut drv in base_drives {
            if let Some((is_dir, lbl, has_md, has_sd)) = probed.remove(&drv.letter) {
                if !is_dir {
                    continue;
                }
                if !lbl.is_empty() {
                    drv.volume_label = lbl;
                }
                drv.has_my_drive = has_md;
                drv.has_shared_drives = has_sd;
                let lbl_lower = drv.volume_label.to_ascii_lowercase();
                if lbl_lower.contains("google drive") || lbl_lower.contains("pcloud") {
                    drv.is_virtual = true;
                }
                drives.push(drv);
            } else if drv.is_virtual {
                // Virtual cloud mount (e.g. Dokan G:\) is present in kernel DOS device table +
                // DriveFS registry but momentarily slow (>1.2s); keep its instant fast-path entry!
                drives.push(drv);
            }
        }
        drives
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

fn current_session_id() -> u32 {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcessId() -> u32;
            fn ProcessIdToSessionId(dw_process_id: u32, p_session_id: *mut u32) -> i32;
        }
        let mut sid: u32 = 0;
        unsafe {
            let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut sid);
        }
        sid
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

fn spawn_parent_watchdog(parent_pid: u32) {
    if parent_pid == 0 {
        return;
    }
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
        };
        std::thread::spawn(move || unsafe {
            match OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid) {
                Ok(h) if !h.is_invalid() => {
                    let _ = WaitForSingleObject(h, INFINITE);
                    let _ = CloseHandle(h);
                    std::process::exit(0);
                }
                _ => {
                    // Parent already exited before watchdog attached.
                    std::process::exit(0);
                }
            }
        });
    }
}

fn scan_root_snapshot(root: &Path) -> HashMap<String, (u64, i64)> {
    let mut map = HashMap::new();
    let Ok(canon_root) = std::fs::canonicalize(root) else {
        return map;
    };
    let mut queue = vec![canon_root];
    let mut dirs_visited = 0usize;

    while let Some(dir) = queue.pop() {
        if dirs_visited >= 10_000 || map.len() >= 50_000 {
            break;
        }
        dirs_visited += 1;
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            if map.len() >= 50_000 {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name.starts_with('$') || name.starts_with('~') {
                continue;
            }
            let p = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                queue.push(p);
            } else if meta.is_file() {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let clean = strip_win_verbatim(&p.to_string_lossy());
                map.insert(clean, (meta.len(), mtime));
            }
        }
    }
    map
}

fn spawn_watch_scanner(state: Arc<BridgeServerState>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(2500));
        let roots: Vec<PathBuf> = {
            match state.watch.lock() {
                Ok(g) => g.roots.clone(),
                Err(_) => continue,
            }
        };
        if roots.is_empty() {
            continue;
        }
        let mut new_snaps: Vec<(PathBuf, HashMap<String, (u64, i64)>)> =
            Vec::with_capacity(roots.len());
        for root in roots {
            if root.is_dir() {
                let snap = scan_root_snapshot(&root);
                new_snaps.push((root, snap));
            }
        }
        let Ok(mut guard) = state.watch.lock() else {
            continue;
        };
        for (root, cur_snap) in new_snaps {
            if let Some(prev_snap) = guard.snapshots.get(&root).cloned() {
                for (path, &(size, mtime)) in &cur_snap {
                    if guard.events.len() >= MAX_QUEUED_EVENTS {
                        break;
                    }
                    match prev_snap.get(path) {
                        None => guard.events.push(BridgeWatchEvent {
                            kind: "upsert".to_string(),
                            path: path.clone(),
                            old_path: None,
                        }),
                        Some(&(ps, pm)) if ps != size || pm != mtime => {
                            guard.events.push(BridgeWatchEvent {
                                kind: "upsert".to_string(),
                                path: path.clone(),
                                old_path: None,
                            })
                        }
                        _ => {}
                    }
                }
                for old_path in prev_snap.keys() {
                    if guard.events.len() >= MAX_QUEUED_EVENTS {
                        break;
                    }
                    if !cur_snap.contains_key(old_path) {
                        guard.events.push(BridgeWatchEvent {
                            kind: "remove".to_string(),
                            path: old_path.clone(),
                            old_path: None,
                        });
                    }
                }
            }
            guard.snapshots.insert(root, cur_snap);
        }
    });
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    if !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn write_json(stream: &mut TcpStream, status: u16, value: &serde_json::Value) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    write_http_response(stream, status, reason, "application/json", &body);
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, String, Vec<u8>)> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let mut raw = Vec::with_capacity(2048);
    let mut buf = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut content_length: usize = 0;

    for _ in 0..MAX_SOCKET_ITERS {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len().saturating_add(n) > MAX_REQ_HEADER_BYTES + MAX_REQ_BODY_BYTES {
                    return None;
                }
                raw.extend_from_slice(&buf[..n]);
                if header_end.is_none() {
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let head_str = String::from_utf8_lossy(&raw[..pos]);
                        for line in head_str.lines().skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_length = v.trim().parse::<usize>().unwrap_or(0);
                                    if content_length > MAX_REQ_BODY_BYTES {
                                        return None;
                                    }
                                }
                            }
                        }
                    } else if raw.len() > MAX_REQ_HEADER_BYTES {
                        return None;
                    }
                }
                if let Some(hend) = header_end {
                    if raw.len().saturating_sub(hend) >= content_length {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }

    let hend = header_end?;
    let head_str = String::from_utf8_lossy(&raw[..hend.saturating_sub(4)]);
    let mut lines = head_str.lines();
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut auth_token = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("x-quorum-bridge-token") {
                auth_token = v.trim().to_string();
            }
        }
    }

    let mut body = raw[hend..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    Some((method, target, auth_token, body))
}

fn handle_client(mut stream: TcpStream, state: Arc<BridgeServerState>) {
    let Some((method, target, auth_token, body)) = read_http_request(&mut stream) else {
        return;
    };

    let expected_bytes = state.token.as_bytes();
    let provided_bytes = auth_token.as_bytes();
    let auth_ok = expected_bytes.len() == provided_bytes.len()
        && bool::from(expected_bytes.ct_eq(provided_bytes));
    if !auth_ok {
        write_json(
            &mut stream,
            403,
            &serde_json::json!({"ok": false, "error": "unauthorized"}),
        );
        return;
    }

    match (method.as_str(), target.as_str()) {
        ("GET", "/bridge/health") => {
            write_json(
                &mut stream,
                200,
                &serde_json::json!({
                    "ok": true,
                    "session_id": current_session_id(),
                    "pid": std::process::id(),
                }),
            );
        }
        ("GET", "/bridge/drives") => {
            let cached = state.drives_cache.lock().ok().and_then(|g| {
                g.as_ref()
                    .filter(|(ts, _)| ts.elapsed() < Duration::from_secs(10))
                    .map(|(_, d)| d.clone())
            });
            let drives = match cached {
                Some(d) => d,
                None => {
                    let fresh = enumerate_session_drives();
                    if let Ok(mut g) = state.drives_cache.lock() {
                        *g = Some((std::time::Instant::now(), fresh.clone()));
                    }
                    fresh
                }
            };
            write_json(&mut stream, 200, &serde_json::json!({ "drives": drives }));
        }
        ("POST", "/bridge/stat") => {
            #[derive(Deserialize)]
            struct Req {
                path: String,
            }
            let Ok(req) = serde_json::from_slice::<Req>(&body) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid stat payload"}),
                );
                return;
            };
            let Ok(valid) = validate_cloud_drive_path(&req.path) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid path"}),
                );
                return;
            };
            let p = Path::new(&valid);
            let Ok(canon) = std::fs::canonicalize(p) else {
                write_json(
                    &mut stream,
                    200,
                    &serde_json::to_value(BridgeStatInfo {
                        exists: false,
                        is_dir: false,
                        is_file: false,
                        len: 0,
                        modified_secs: 0,
                        is_placeholder: false,
                        canonical_path: None,
                    })
                    .unwrap_or_default(),
                );
                return;
            };
            let Ok(meta) = std::fs::metadata(&canon) else {
                write_json(
                    &mut stream,
                    200,
                    &serde_json::to_value(BridgeStatInfo {
                        exists: false,
                        is_dir: false,
                        is_file: false,
                        len: 0,
                        modified_secs: 0,
                        is_placeholder: false,
                        canonical_path: None,
                    })
                    .unwrap_or_default(),
                );
                return;
            };
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let info = BridgeStatInfo {
                exists: true,
                is_dir: meta.is_dir(),
                is_file: meta.is_file(),
                len: meta.len(),
                modified_secs: mtime,
                is_placeholder: is_placeholder_meta(&meta),
                canonical_path: Some(strip_win_verbatim(&canon.to_string_lossy())),
            };
            write_json(
                &mut stream,
                200,
                &serde_json::to_value(info).unwrap_or_default(),
            );
        }
        ("POST", "/bridge/browse") => {
            #[derive(Deserialize)]
            struct Req {
                path: String,
                #[serde(default)]
                create_subfolder: Option<String>,
            }
            let Ok(req) = serde_json::from_slice::<Req>(&body) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid browse payload"}),
                );
                return;
            };
            let Ok(valid) = validate_cloud_drive_path(&req.path) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid directory path"}),
                );
                return;
            };
            let Ok(canon) = std::fs::canonicalize(&valid) else {
                write_json(
                    &mut stream,
                    404,
                    &serde_json::json!({"ok": false, "error": format!("Directory does not exist on disk: {}", valid)}),
                );
                return;
            };
            if !canon.is_dir() {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": format!("Path is not a directory: {}", valid)}),
                );
                return;
            }
            if let Some(sub) = req.create_subfolder.as_deref() {
                let sub_trimmed = sub.trim();
                if !sub_trimmed.is_empty() {
                    if !is_safe_single_folder_name(sub_trimmed) {
                        write_json(
                            &mut stream,
                            400,
                            &serde_json::json!({"ok": false, "error": "Invalid subfolder name"}),
                        );
                        return;
                    }
                    let new_dir = canon.join(sub_trimmed);
                    if let Err(e) = std::fs::create_dir_all(&new_dir) {
                        write_json(
                            &mut stream,
                            403,
                            &serde_json::json!({"ok": false, "error": format!("Failed to create folder: {e}")}),
                        );
                        return;
                    }
                }
            }
            let rd = match std::fs::read_dir(&canon) {
                Ok(r) => r,
                Err(e) => {
                    write_json(
                        &mut stream,
                        403,
                        &serde_json::json!({"ok": false, "error": format!("Cannot read directory: {e}")}),
                    );
                    return;
                }
            };
            let mut entries: Vec<BridgeDirEntry> = Vec::new();
            for entry in rd.flatten() {
                if entries.len() >= 10_000 {
                    break;
                }
                let p = entry.path();
                let is_dir = p.is_dir();
                if !is_dir {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('$') {
                    continue;
                }
                entries.push(BridgeDirEntry {
                    name,
                    path: strip_win_verbatim(&p.to_string_lossy()),
                    is_dir: true,
                });
            }
            entries.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
            write_json(
                &mut stream,
                200,
                &serde_json::json!({ "ok": true, "entries": entries }),
            );
        }
        ("POST", "/bridge/walk") => {
            #[derive(Deserialize)]
            struct Req {
                root: String,
                #[serde(default)]
                excluded_prefixes: Vec<String>,
                #[serde(default)]
                max_file_size_bytes: u64,
                #[serde(default = "default_true")]
                skip_hidden: bool,
                #[serde(default)]
                placeholder_mode: CloudPlaceholderMode,
                #[serde(default)]
                hydration_cap_bytes: u64,
            }
            fn default_true() -> bool {
                true
            }
            let Ok(req) = serde_json::from_slice::<Req>(&body) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid walk payload"}),
                );
                return;
            };
            let Ok(valid_root) = validate_cloud_drive_path(&req.root) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid walk root"}),
                );
                return;
            };
            let Ok(canon_root) = std::fs::canonicalize(&valid_root) else {
                write_json(
                    &mut stream,
                    404,
                    &serde_json::json!({"ok": false, "error": "walk root does not exist"}),
                );
                return;
            };
            let norm_excluded: Vec<String> = req
                .excluded_prefixes
                .iter()
                .filter_map(|p| normalize_prefix_for_match(p).ok())
                .collect();
            let max_size = if req.max_file_size_bytes == 0 {
                MAX_READ_FILE_BYTES
            } else {
                req.max_file_size_bytes.min(MAX_READ_FILE_BYTES)
            };

            let mut entries: Vec<BridgeWalkEntry> = Vec::new();
            let mut skipped_placeholder = 0usize;
            let mut dirs_visited = 0usize;
            let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
            let mut stack = vec![canon_root];

            while let Some(dir) = stack.pop() {
                if dirs_visited >= MAX_WALK_DIRS || entries.len() >= MAX_WALK_FILES {
                    break;
                }
                if !visited_dirs.insert(dir.clone()) {
                    continue;
                }
                let dir_clean = strip_win_verbatim(&dir.to_string_lossy());
                if norm_excluded
                    .iter()
                    .any(|ex| path_matches_prefix(&dir_clean, ex).unwrap_or(false))
                {
                    continue;
                }
                dirs_visited += 1;
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in rd.flatten() {
                    if entries.len() >= MAX_WALK_FILES {
                        break;
                    }
                    let name = entry.file_name().to_string_lossy().to_string();
                    if req.skip_hidden && name.starts_with('.') {
                        continue;
                    }
                    let lower_name = name.to_ascii_lowercase();
                    if lower_name.starts_with('$')
                        || lower_name.starts_with('~')
                        || matches!(
                            lower_name.as_str(),
                            "node_modules" | ".git" | "target" | "__pycache__" | ".tmp.driveupload"
                        )
                    {
                        continue;
                    }
                    let p = entry.path();
                    let clean_str = strip_win_verbatim(&p.to_string_lossy());
                    if norm_excluded
                        .iter()
                        .any(|ex| path_matches_prefix(&clean_str, ex).unwrap_or(false))
                    {
                        continue;
                    }
                    let Ok(meta) = std::fs::symlink_metadata(&p) else {
                        continue;
                    };
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if meta.is_dir() {
                        stack.push(p);
                    } else if meta.is_file() {
                        let size_bytes = meta.len();
                        let is_ph = is_placeholder_meta(&meta);
                        if should_skip_placeholder(
                            is_ph,
                            size_bytes,
                            req.placeholder_mode,
                            req.hydration_cap_bytes,
                        ) {
                            skipped_placeholder += 1;
                            continue;
                        }
                        if size_bytes > max_size {
                            continue;
                        }
                        let mtime_secs = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        entries.push(BridgeWalkEntry {
                            path: clean_str,
                            size_bytes,
                            mtime_secs,
                            is_placeholder: is_ph,
                        });
                    }
                }
            }
            write_json(
                &mut stream,
                200,
                &serde_json::json!({
                    "entries": entries,
                    "skipped_placeholder": skipped_placeholder,
                }),
            );
        }
        ("POST", "/bridge/read") => {
            #[derive(Deserialize)]
            struct Req {
                path: String,
                #[serde(default)]
                max_bytes: u64,
                #[serde(default)]
                placeholder_mode: CloudPlaceholderMode,
                #[serde(default)]
                hydration_cap_bytes: u64,
            }
            let Ok(req) = serde_json::from_slice::<Req>(&body) else {
                write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    b"invalid read payload",
                );
                return;
            };
            let Ok(valid) = validate_cloud_drive_path(&req.path) else {
                write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    b"invalid path",
                );
                return;
            };
            let Ok(canon) = std::fs::canonicalize(&valid) else {
                write_http_response(
                    &mut stream,
                    404,
                    "Not Found",
                    "text/plain",
                    b"file not found",
                );
                return;
            };
            let Ok(meta) = std::fs::metadata(&canon) else {
                write_http_response(
                    &mut stream,
                    404,
                    "Not Found",
                    "text/plain",
                    b"file metadata unavailable",
                );
                return;
            };
            if !meta.is_file() {
                write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    b"not a regular file",
                );
                return;
            }
            let size = meta.len();
            if should_skip_placeholder(
                is_placeholder_meta(&meta),
                size,
                req.placeholder_mode,
                req.hydration_cap_bytes,
            ) {
                write_http_response(
                    &mut stream,
                    412,
                    "Precondition Failed",
                    "text/plain",
                    b"skipped cloud-only placeholder file",
                );
                return;
            }
            let limit = if req.max_bytes == 0 {
                MAX_READ_FILE_BYTES
            } else {
                req.max_bytes.min(MAX_READ_FILE_BYTES)
            };
            if size > limit {
                write_http_response(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    "text/plain",
                    b"file exceeds max_bytes limit",
                );
                return;
            }
            match std::fs::read(&canon) {
                Ok(bytes) => write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    "application/octet-stream",
                    &bytes,
                ),
                Err(e) => write_http_response(
                    &mut stream,
                    403,
                    "Forbidden",
                    "text/plain",
                    format!("failed to read file: {e}").as_bytes(),
                ),
            }
        }
        ("POST", "/bridge/watch") => {
            #[derive(Deserialize)]
            struct Req {
                #[serde(default)]
                roots: Vec<String>,
            }
            let Ok(req) = serde_json::from_slice::<Req>(&body) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid watch payload"}),
                );
                return;
            };
            let mut next_roots = Vec::new();
            for raw in &req.roots {
                if let Ok(valid) = validate_cloud_drive_path(raw) {
                    if let Ok(canon) = std::fs::canonicalize(&valid) {
                        if canon.is_dir() && !next_roots.contains(&canon) {
                            next_roots.push(canon);
                        }
                    }
                }
            }
            if let Ok(mut guard) = state.watch.lock() {
                guard.roots = next_roots.clone();
                guard.snapshots.retain(|k, _| next_roots.contains(k));
            }
            write_json(
                &mut stream,
                200,
                &serde_json::json!({ "ok": true, "watched": next_roots.len() }),
            );
        }
        ("GET", "/bridge/events") => {
            let drained = match state.watch.lock() {
                Ok(mut guard) => std::mem::take(&mut guard.events),
                Err(_) => Vec::new(),
            };
            write_json(&mut stream, 200, &serde_json::json!({ "events": drained }));
        }
        ("POST", "/bridge/open-file") => {
            #[derive(Deserialize)]
            struct Req {
                path: String,
            }
            let Ok(req) = serde_json::from_slice::<Req>(&body) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid open-file payload"}),
                );
                return;
            };
            let Ok(valid) = validate_cloud_drive_path(&req.path) else {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"ok": false, "error": "invalid path"}),
                );
                return;
            };
            let Ok(canon) = std::fs::canonicalize(&valid) else {
                write_json(
                    &mut stream,
                    404,
                    &serde_json::json!({"ok": false, "error": "file not found"}),
                );
                return;
            };
            if is_blocked_open_extension(&canon) {
                write_json(
                    &mut stream,
                    403,
                    &serde_json::json!({"ok": false, "error": "refused to open executable or script file"}),
                );
                return;
            }
            if quorum_types::content_safety::check_path_explicit_content(&canon).is_blocked() {
                write_json(
                    &mut stream,
                    403,
                    &serde_json::json!({"ok": false, "error": "blocked by content safety policy"}),
                );
                return;
            }
            let open_str = strip_win_verbatim(&canon.to_string_lossy());
            let res = open::that(&open_str).map_err(|e| e.to_string());
            match res {
                Ok(()) => write_json(&mut stream, 200, &serde_json::json!({ "ok": true })),
                Err(e) => write_json(
                    &mut stream,
                    500,
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        _ => {
            write_json(
                &mut stream,
                404,
                &serde_json::json!({ "ok": false, "error": "unknown bridge route" }),
            );
        }
    }
}

/// Entrypoint for `quorum-desktop --session-fs-bridge --parent-pid <pid>`.
pub fn run_session_fs_bridge(parent_pid: u32) -> i32 {
    let mut token = String::new();
    {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        if reader.read_line(&mut token).is_err() {
            return 1;
        }
    }
    let token = token.trim().to_string();
    if token.len() < 32 {
        return 1;
    }

    spawn_parent_watchdog(parent_pid);

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return 1,
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => return 1,
    };

    {
        let mut out = std::io::stdout();
        if writeln!(out, "READY {port}").is_err() || out.flush().is_err() {
            return 1;
        }
    }

    let state = Arc::new(BridgeServerState {
        token,
        watch: Mutex::new(WatchState::default()),
        drives_cache: Mutex::new(None),
        active_conns: AtomicUsize::new(0),
    });
    spawn_watch_scanner(Arc::clone(&state));

    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            continue;
        };
        let prev = state.active_conns.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_CONCURRENT_CONNS {
            state.active_conns.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let state_c = Arc::clone(&state);
        std::thread::spawn(move || {
            let _guard = ConnGuard {
                counter: Arc::clone(&state_c),
            };
            handle_client(stream, state_c);
        });
    }
    0
}
