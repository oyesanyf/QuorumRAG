//! Loopback Session-1 Filesystem Bridge Client for Windows LocalSystem (Session 0) Services.
//!
//! When `QuorumRAGDaemon` runs as a Windows `LocalSystem` service (Session 0), per-user
//! virtual cloud drives mounted with Dokan / WinFSP (`DOKAN_OPTION_CURRENT_SESSION`), such as
//! Google Drive for Desktop (`G:\My Drive`) or pCloud (`P:\`), exist strictly inside the
//! interactive desktop user's logon session (Session >= 1) and are invisible to Session 0.
//!
//! `quorumrag.exe` automatically spawns a silent GUI-subsystem helper
//! (`quorum-desktop.exe --session-fs-bridge`) inside the active interactive user session via
//! `WTSQueryUserToken` + `CreateProcessAsUserW`. Communication is strictly loopback-only
//! (`127.0.0.1:<ephemeral_port>`) and authenticated with an ephemeral 256-bit random token
//! passed exclusively over an anonymous stdin pipe (never in argv/env/disk).
//!
//! On Linux, macOS, and interactive Windows runs where paths are directly accessible via
//! `std::fs`, all helpers execute locally with zero bridge overhead.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cloud_drives::{CloudPlaceholderMode, CloudPlaceholderPolicy};

/// Maximum response body size accepted from the loopback bridge (default ceiling 256 MiB).
const MAX_BRIDGE_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum HTTP response header bytes read from the loopback bridge.
const MAX_BRIDGE_HEADER_BYTES: usize = 32 * 1024;
/// Maximum loop iterations while reading chunked/streamed socket reads (anti-DoS bound).
const MAX_SOCKET_READ_ITERS: usize = 262_144;

/// Mounted drive information discovered inside the interactive desktop session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDriveInfo {
    pub letter: char,
    pub root: String,
    pub drive_type: u32,
    pub volume_label: String,
    pub nt_target: String,
    pub is_virtual: bool,
    #[serde(default)]
    pub has_my_drive: bool,
    #[serde(default)]
    pub has_shared_drives: bool,
}

/// Stat metadata for a file or directory probed via the Session-1 bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeStatInfo {
    pub exists: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub len: u64,
    pub modified_secs: i64,
    pub is_placeholder: bool,
    pub canonical_path: Option<String>,
}

/// Single directory entry returned by `/bridge/browse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
}

/// Single candidate file returned by `/bridge/walk`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWalkEntry {
    pub path: String,
    pub size_bytes: u64,
    pub mtime_secs: i64,
    pub is_placeholder: bool,
}

/// Filesystem change event observed inside the active interactive user session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWatchEvent {
    /// `"upsert"`, `"remove"`, or `"rename"`.
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub old_path: Option<String>,
}

#[derive(Debug, Clone)]
struct BridgeEndpoint {
    port: u16,
    token: String,
    session_id: u32,
    pid: u32,
}

#[derive(Debug, Default)]
struct BridgeState {
    endpoint: Option<BridgeEndpoint>,
    last_ensure_attempt: Option<Instant>,
}

static BRIDGE_STATE: OnceLock<RwLock<BridgeState>> = OnceLock::new();
static BRIDGE_ENSURER: OnceLock<fn() -> bool> = OnceLock::new();
/// Bitmask of ASCII drive letters (`bit 0 = 'A'`, ..., `bit 25 = 'Z'`) known to be
/// mounted inside the interactive desktop session and NOT directly accessible in Session 0.
static SESSION_ONLY_DRIVE_MASK: AtomicU32 = AtomicU32::new(0);
/// Per-drive-letter short circuit-breaker (indexed `0..26` for `'A'..='Z'`) recording when a
/// virtual cloud mount (e.g. Dokan `G:\`) timed out so background probes fail fast in 0 ms
/// instead of queuing overlapping slow IRPs or respawning the bridge.
static DRIVE_TIMEOUT_BACKOFF: OnceLock<RwLock<[Option<(Instant, String)>; 26]>> = OnceLock::new();

const DRIVE_TIMEOUT_COOLDOWN: Duration = Duration::from_secs(30);

fn state_lock() -> &'static RwLock<BridgeState> {
    BRIDGE_STATE.get_or_init(|| RwLock::new(BridgeState::default()))
}

fn timeout_backoff_lock() -> &'static RwLock<[Option<(Instant, String)>; 26]> {
    DRIVE_TIMEOUT_BACKOFF.get_or_init(|| RwLock::new(std::array::from_fn(|_| None)))
}

fn drive_letter_index(path: &Path) -> Option<usize> {
    let s = path.to_string_lossy();
    let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = trimmed.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        let idx = (b[0].to_ascii_uppercase() - b'A') as usize;
        if idx < 26 {
            return Some(idx);
        }
    }
    None
}

fn format_drive_busy_message(path: &Path) -> String {
    if let Some(idx) = drive_letter_index(path) {
        let ch = (b'A' + idx as u8) as char;
        format!(
            "Drive {ch}:\\ is currently busy or not responding (Google Drive for Desktop may be syncing, applying pending changes, or restarting). Save pending changes or restart Google Drive and click Refresh."
        )
    } else {
        format!(
            "Virtual cloud drive path '{}' timed out while waiting for the cloud sync client. Save pending changes or restart the cloud client and click Refresh.",
            path.display()
        )
    }
}

fn record_drive_timeout(path: &Path, msg: String) {
    if let Some(idx) = drive_letter_index(path) {
        if let Ok(mut guard) = timeout_backoff_lock().write() {
            guard[idx] = Some((Instant::now() + DRIVE_TIMEOUT_COOLDOWN, msg));
        }
    }
}

fn clear_drive_timeout(path: &Path) {
    if let Some(idx) = drive_letter_index(path) {
        if let Ok(mut guard) = timeout_backoff_lock().write() {
            guard[idx] = None;
        }
    }
}

/// Returns the active timeout diagnostic message if `path`'s drive letter recently timed out
/// on a virtual cloud mount (allowing callers to return HTTP 504 instead of false 404).
pub fn drive_timeout_message(path: &Path) -> Option<String> {
    let idx = drive_letter_index(path)?;
    let guard = timeout_backoff_lock().read().ok()?;
    let (until, msg) = guard[idx].as_ref()?;
    if Instant::now() < *until {
        Some(msg.clone())
    } else {
        None
    }
}

/// Clears all per-drive timeout backoff entries (e.g., on explicit user Refresh or in tests).
pub fn clear_drive_timeout_cache() {
    if let Ok(mut guard) = timeout_backoff_lock().write() {
        for slot in guard.iter_mut() {
            *slot = None;
        }
    }
}

/// Records a timeout backoff entry for `path`'s drive letter from a local (non-bridge) bounded
/// virtual-drive probe so interactive Session-1 runs also fail fast when Dokan/Google Drive is busy.
pub fn record_local_drive_timeout(path: &Path) -> String {
    let msg = format_drive_busy_message(path);
    record_drive_timeout(path, msg.clone());
    msg
}

/// Clears any timeout backoff entry for `path`'s drive letter after a successful local probe.
pub fn clear_local_drive_timeout(path: &Path) {
    clear_drive_timeout(path);
}

/// Returns `true` on Windows when `path` targets a drive letter whose kernel DOS device target
/// is NOT `\Device\HarddiskVolume*` (e.g., Dokan / WinFSP / Google Drive `G:\` / pCloud `P:\` /
/// SMB mapped drives). Pure 0 ms kernel `QueryDosDeviceW` call — never sends a filesystem IRP.
pub fn is_local_virtual_drive_path(path: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn QueryDosDeviceW(
                lp_device_name: *const u16,
                lp_target_path: *mut u16,
                ucch_max: u32,
            ) -> u32;
        }
        let Some(idx) = drive_letter_index(path) else {
            return false;
        };
        let ch = (b'A' + idx as u8) as char;
        let dos_dev = format!("{ch}:");
        let dos_w: Vec<u16> = dos_dev.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 512];
        let chars = unsafe { QueryDosDeviceW(dos_w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if chars == 0 {
            return false;
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
        let nt_target = String::from_utf16_lossy(&buf[..len]);
        !nt_target.starts_with(r"\Device\HarddiskVolume")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        false
    }
}

static LOCAL_BLOCKED_FS_PROBES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const MAX_LOCAL_BLOCKED_FS_PROBES: usize = 12;

/// Bounded-timeout directory check safe for local Dokan/WinFSP/SMB virtual drives in interactive
/// Windows sessions. For fixed physical drives (`\Device\HarddiskVolume*`) or non-Windows OSes,
/// runs directly in 0 overhead; for virtual drives, enforces `timeout` and optionally trips the
/// per-drive timeout circuit breaker (`record_timeout_on_miss = true`) instead of hanging startup
/// or HTTP handlers indefinitely.
pub fn local_is_dir_bounded_probe(
    path: &Path,
    require_readable: bool,
    timeout: Duration,
    record_timeout_on_miss: bool,
) -> Result<bool, String> {
    if !is_local_virtual_drive_path(path) {
        let ok = path.is_dir() && (!require_readable || std::fs::read_dir(path).is_ok());
        return Ok(ok);
    }
    if let Some(msg) = drive_timeout_message(path) {
        return Err(msg);
    }
    let prev = LOCAL_BLOCKED_FS_PROBES.fetch_add(1, Ordering::SeqCst);
    if prev >= MAX_LOCAL_BLOCKED_FS_PROBES {
        LOCAL_BLOCKED_FS_PROBES.fetch_sub(1, Ordering::SeqCst);
        let msg = if record_timeout_on_miss {
            record_local_drive_timeout(path)
        } else {
            format_drive_busy_message(path)
        };
        return Err(msg);
    }
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let p_owned = path.to_path_buf();
    std::thread::spawn(move || {
        let ok = p_owned.is_dir() && (!require_readable || std::fs::read_dir(&p_owned).is_ok());
        LOCAL_BLOCKED_FS_PROBES.fetch_sub(1, Ordering::SeqCst);
        let _ = tx.send(ok);
    });
    match rx.recv_timeout(timeout) {
        Ok(ok) => {
            if ok {
                clear_local_drive_timeout(path);
            }
            Ok(ok)
        }
        Err(_) => {
            let msg = if record_timeout_on_miss {
                record_local_drive_timeout(path)
            } else {
                format_drive_busy_message(path)
            };
            Err(msg)
        }
    }
}

/// Bounded-timeout directory check safe for local Dokan/WinFSP/SMB virtual drives in interactive
/// Windows sessions. Trips the per-drive timeout circuit breaker on timeout.
pub fn local_is_dir_bounded(path: &Path, require_readable: bool, timeout: Duration) -> Result<bool, String> {
    local_is_dir_bounded_probe(path, require_readable, timeout, true)
}

/// Bounded-timeout file existence check safe for local virtual drives.
pub fn local_is_file_bounded(path: &Path, timeout: Duration) -> Result<bool, String> {
    if !is_local_virtual_drive_path(path) {
        return Ok(path.is_file());
    }
    if let Some(msg) = drive_timeout_message(path) {
        return Err(msg);
    }
    let prev = LOCAL_BLOCKED_FS_PROBES.fetch_add(1, Ordering::SeqCst);
    if prev >= MAX_LOCAL_BLOCKED_FS_PROBES {
        LOCAL_BLOCKED_FS_PROBES.fetch_sub(1, Ordering::SeqCst);
        return Err(record_local_drive_timeout(path));
    }
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let p_owned = path.to_path_buf();
    std::thread::spawn(move || {
        let ok = p_owned.is_file();
        LOCAL_BLOCKED_FS_PROBES.fetch_sub(1, Ordering::SeqCst);
        let _ = tx.send(ok);
    });
    match rx.recv_timeout(timeout) {
        Ok(ok) => {
            if ok {
                clear_local_drive_timeout(path);
            }
            Ok(ok)
        }
        Err(_) => Err(record_local_drive_timeout(path)),
    }
}

/// Bounded-timeout `std::fs::canonicalize` safe for local virtual drives.
pub fn local_canonicalize_bounded(path: &Path, timeout: Duration) -> Result<Option<PathBuf>, String> {
    if !is_local_virtual_drive_path(path) {
        return Ok(std::fs::canonicalize(path).ok());
    }
    if let Some(msg) = drive_timeout_message(path) {
        return Err(msg);
    }
    let prev = LOCAL_BLOCKED_FS_PROBES.fetch_add(1, Ordering::SeqCst);
    if prev >= MAX_LOCAL_BLOCKED_FS_PROBES {
        LOCAL_BLOCKED_FS_PROBES.fetch_sub(1, Ordering::SeqCst);
        return Err(record_local_drive_timeout(path));
    }
    let (tx, rx) = std::sync::mpsc::channel::<Option<PathBuf>>();
    let p_owned = path.to_path_buf();
    std::thread::spawn(move || {
        let res = std::fs::canonicalize(&p_owned)
            .ok()
            .or_else(|| std::fs::metadata(&p_owned).ok().map(|_| p_owned.clone()));
        LOCAL_BLOCKED_FS_PROBES.fetch_sub(1, Ordering::SeqCst);
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(opt) => {
            if opt.is_some() {
                clear_local_drive_timeout(path);
            }
            Ok(opt)
        }
        Err(_) => Err(record_local_drive_timeout(path)),
    }
}

#[derive(Debug, Clone)]
enum BridgeCallError {
    Transport(String),
    Timeout(String),
}

impl BridgeCallError {
    fn into_message(self) -> String {
        match self {
            Self::Transport(m) | Self::Timeout(m) => m,
        }
    }

    fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }
}

/// Registers the OS-specific launcher callback (`quorum-daemon` on Windows LocalSystem)
/// invoked lazily whenever Session 0 needs to start or reconnect the Session-1 bridge.
pub fn register_bridge_ensurer(ensurer: fn() -> bool) {
    let _ = BRIDGE_ENSURER.set(ensurer);
}

/// Stores the active loopback bridge endpoint details.
pub fn set_bridge_endpoint(port: u16, token: String, session_id: u32, pid: u32) {
    if let Ok(mut guard) = state_lock().write() {
        guard.endpoint = Some(BridgeEndpoint {
            port,
            token,
            session_id,
            pid,
        });
        guard.last_ensure_attempt = Some(Instant::now());
    }
}

/// Clears the active bridge endpoint (e.g., if the helper exited or the user logged out).
pub fn clear_bridge_endpoint() {
    if let Ok(mut guard) = state_lock().write() {
        guard.endpoint = None;
    }
    SESSION_ONLY_DRIVE_MASK.store(0, Ordering::Relaxed);
}

/// Returns `(port, session_id, pid)` if a Session-1 bridge is currently registered.
pub fn active_bridge_info() -> Option<(u16, u32, u32)> {
    state_lock()
        .read()
        .ok()
        .and_then(|g| g.endpoint.as_ref().map(|e| (e.port, e.session_id, e.pid)))
}

/// Returns `true` when an interactive user session bridge is registered and responds to health checks.
pub fn is_bridge_active() -> bool {
    let Some(ep) = get_or_ensure_endpoint() else {
        return false;
    };
    http_request_raw(&ep, "GET", "/bridge/health", None, Duration::from_secs(2))
        .map(|(status, _)| status == 200)
        .unwrap_or(false)
}

fn drive_letter_bit(path: &Path) -> Option<u32> {
    let s = path.to_string_lossy();
    let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = trimmed.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        let idx = (b[0].to_ascii_uppercase() - b'A') as u32;
        if idx < 26 {
            return Some(1u32 << idx);
        }
    }
    None
}

/// Updates the fast lock-free bitmask of drive letters hosted via the Session-1 bridge.
pub fn record_session_only_drive_letters(letters: &[char]) {
    let mut mask = 0u32;
    for &ch in letters {
        if ch.is_ascii_alphabetic() {
            let idx = (ch.to_ascii_uppercase() as u8 - b'A') as u32;
            if idx < 26 {
                mask |= 1u32 << idx;
            }
        }
    }
    SESSION_ONLY_DRIVE_MASK.store(mask, Ordering::Relaxed);
}

/// Returns `true` if `path` resides on a Windows drive letter known to be hosted only in
/// the interactive user session (or if a bridge is registered and `path` isn't locally readable).
pub fn is_known_bridged_drive_path(path: &Path) -> bool {
    if let Some(bit) = drive_letter_bit(path) {
        (SESSION_ONLY_DRIVE_MASK.load(Ordering::Relaxed) & bit) != 0
    } else {
        false
    }
}

fn get_or_ensure_endpoint() -> Option<BridgeEndpoint> {
    if let Ok(guard) = state_lock().read() {
        if let Some(ep) = guard.endpoint.clone() {
            return Some(ep);
        }
        if let Some(last) = guard.last_ensure_attempt {
            if last.elapsed() < Duration::from_secs(5) {
                return None;
            }
        }
    }
    let ensurer = *BRIDGE_ENSURER.get()?;
    if let Ok(mut guard) = state_lock().write() {
        if let Some(ep) = guard.endpoint.clone() {
            return Some(ep);
        }
        if let Some(last) = guard.last_ensure_attempt {
            if last.elapsed() < Duration::from_secs(5) {
                return None;
            }
        }
        guard.last_ensure_attempt = Some(Instant::now());
    }
    if ensurer() {
        state_lock()
            .read()
            .ok()
            .and_then(|g| g.endpoint.clone())
    } else {
        None
    }
}

fn http_request_raw(
    ep: &BridgeEndpoint,
    method: &str,
    path: &str,
    json_body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), BridgeCallError> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, ep.port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| BridgeCallError::Transport(format!("bridge connect failed: {e}")))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let body = json_body.unwrap_or(&[]);
    let header = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Quorum-Bridge-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        ep.port,
        ep.token,
        body.len()
    );
    let mut req_buf = Vec::with_capacity(header.len() + body.len());
    req_buf.extend_from_slice(header.as_bytes());
    req_buf.extend_from_slice(body);
    stream
        .write_all(&req_buf)
        .map_err(|e| BridgeCallError::Transport(format!("bridge request write failed: {e}")))?;
    let _ = stream.flush();

    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 16 * 1024];
    let mut header_end: Option<usize> = None;
    let mut content_length: Option<usize> = None;

    for _ in 0..MAX_SOCKET_READ_ITERS {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len().saturating_add(n) > MAX_BRIDGE_RESPONSE_BYTES + MAX_BRIDGE_HEADER_BYTES
                {
                    return Err(BridgeCallError::Transport(
                        "bridge response exceeded safety size cap".to_string(),
                    ));
                }
                raw.extend_from_slice(&buf[..n]);
                if header_end.is_none() {
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let head_str = String::from_utf8_lossy(&raw[..pos]);
                        for line in head_str.lines().skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    if let Ok(cl) = v.trim().parse::<usize>() {
                                        content_length = Some(cl);
                                    }
                                }
                            }
                        }
                    } else if raw.len() > MAX_BRIDGE_HEADER_BYTES {
                        return Err(BridgeCallError::Transport(
                            "bridge response header exceeded limit".to_string(),
                        ));
                    }
                }
                if let (Some(hend), Some(cl)) = (header_end, content_length) {
                    if raw.len().saturating_sub(hend) >= cl {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionReset
                    && header_end.is_some_and(|hend| {
                        content_length.is_none_or(|cl| raw.len().saturating_sub(hend) >= cl)
                    }) =>
            {
                break;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(BridgeCallError::Timeout(format!(
                    "bridge read timed out: {e}"
                )));
            }
            Err(e) => {
                return Err(BridgeCallError::Transport(format!(
                    "bridge read failed: {e}"
                )));
            }
        }
    }

    let hend = header_end
        .ok_or_else(|| BridgeCallError::Transport("malformed bridge HTTP response".to_string()))?;
    let head_str = String::from_utf8_lossy(&raw[..hend.saturating_sub(4)]);
    let status_line = head_str.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            BridgeCallError::Transport(format!("malformed bridge status line: {status_line}"))
        })?;

    let mut payload = raw[hend..].to_vec();
    if let Some(cl) = content_length {
        if payload.len() > cl {
            payload.truncate(cl);
        }
    }
    Ok((status, payload))
}

fn call_bridge_with_retry_classified(
    method: &str,
    path: &str,
    json_body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), BridgeCallError> {
    let ep = get_or_ensure_endpoint()
        .ok_or_else(|| BridgeCallError::Transport("session fs bridge unavailable".to_string()))?;
    match http_request_raw(&ep, method, path, json_body, timeout) {
        Ok(res) => Ok(res),
        Err(first_err) => {
            if first_err.is_timeout() {
                // A timeout on a virtual cloud mount (e.g., Dokan G:\) does NOT mean the Session-1
                // bridge process crashed. Probe /bridge/health quickly before ever respawning so
                // a slow Google Drive mount can NEVER trigger a bridge respawn storm.
                if http_request_raw(&ep, "GET", "/bridge/health", None, Duration::from_secs(1))
                    .is_ok_and(|(st, _)| st == 200)
                {
                    return Err(first_err);
                }
            }
            // Transport error (or unresponsive health probe) indicates user session restarted or
            // helper exited; reconnect once.
            clear_bridge_endpoint();
            let Some(ep2) = get_or_ensure_endpoint() else {
                return Err(first_err);
            };
            http_request_raw(&ep2, method, path, json_body, timeout)
        }
    }
}

fn call_bridge_with_retry(
    method: &str,
    path: &str,
    json_body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), String> {
    call_bridge_with_retry_classified(method, path, json_body, timeout)
        .map_err(BridgeCallError::into_message)
}

fn placeholder_mode_and_cap(policy: CloudPlaceholderPolicy) -> (CloudPlaceholderMode, u64) {
    match policy {
        CloudPlaceholderPolicy::LocallySyncedOnly => (CloudPlaceholderMode::LocallySyncedOnly, 0),
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes,
        } => (CloudPlaceholderMode::HydrateOnDemand, max_file_size_bytes),
    }
}

/// Lists all ready drives visible inside the interactive desktop user session (e.g., `G:\` Google Drive).
pub fn list_session_drives() -> Vec<BridgeDriveInfo> {
    #[derive(Deserialize)]
    struct Resp {
        drives: Vec<BridgeDriveInfo>,
    }
    let Ok((200, body)) =
        call_bridge_with_retry("GET", "/bridge/drives", None, Duration::from_secs(4))
    else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_slice::<Resp>(&body) else {
        return Vec::new();
    };
    let mut session_only_letters = Vec::new();
    for drv in &parsed.drives {
        if !Path::new(&drv.root).is_dir() {
            session_only_letters.push(drv.letter);
        }
    }
    record_session_only_drive_letters(&session_only_letters);
    parsed.drives
}

/// Probes file/directory metadata locally first, falling back to the Session-1 bridge when running
/// as LocalSystem (Session 0) and the path resides on a per-user virtual drive.
pub fn stat_or_bridged(path: &Path) -> Option<BridgeStatInfo> {
    if let Ok(meta) = std::fs::metadata(path) {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let canon = std::fs::canonicalize(path)
            .ok()
            .map(|c| strip_win_verbatim_str(&c.to_string_lossy()));
        return Some(BridgeStatInfo {
            exists: true,
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            len: meta.len(),
            modified_secs: mtime,
            is_placeholder: is_local_placeholder_meta(&meta),
            canonical_path: canon,
        });
    }
    stat_via_bridge(path)
}

/// Probes metadata strictly through the Session-1 bridge, distinguishing a virtual-drive timeout
/// (`Err((504, msg))`) from an absent path (`Ok(Some(exists: false))`).
pub fn stat_via_bridge_detailed(path: &Path) -> Result<Option<BridgeStatInfo>, (u16, String)> {
    if let Some(msg) = drive_timeout_message(path) {
        return Err((504, msg));
    }
    let payload = serde_json::json!({ "path": path.to_string_lossy() }).to_string();
    match call_bridge_with_retry_classified(
        "POST",
        "/bridge/stat",
        Some(payload.as_bytes()),
        Duration::from_secs(6),
    ) {
        Ok((200, body)) => {
            clear_drive_timeout(path);
            let Some(info) = serde_json::from_slice::<BridgeStatInfo>(&body).ok() else {
                return Ok(None);
            };
            if info.exists {
                if let Some(bit) = drive_letter_bit(path) {
                    SESSION_ONLY_DRIVE_MASK.fetch_or(bit, Ordering::Relaxed);
                }
            }
            Ok(Some(info))
        }
        Ok((504, body)) => {
            let msg = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or_else(|| format_drive_busy_message(path));
            record_drive_timeout(path, msg.clone());
            Err((504, msg))
        }
        Ok((status, body)) => {
            let msg = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or_else(|| format!("bridge stat failed (HTTP {status})"));
            Err((status, msg))
        }
        Err(err) if err.is_timeout() => {
            let msg = format_drive_busy_message(path);
            record_drive_timeout(path, msg.clone());
            Err((504, msg))
        }
        Err(err) => Err((503, err.into_message())),
    }
}

/// Probes metadata strictly through the Session-1 bridge.
pub fn stat_via_bridge(path: &Path) -> Option<BridgeStatInfo> {
    stat_via_bridge_detailed(path).ok().flatten()
}

/// Returns `true` if `path` exists locally OR via the active interactive Session-1 bridge.
pub fn path_exists_or_bridged(path: &Path) -> bool {
    if path.exists() {
        return true;
    }
    stat_via_bridge(path).is_some_and(|s| s.exists)
}

/// Returns `true` if `path` is a directory locally OR via the active interactive Session-1 bridge.
pub fn path_is_dir_or_bridged(path: &Path) -> bool {
    if path.is_dir() {
        return true;
    }
    stat_via_bridge(path).is_some_and(|s| s.exists && s.is_dir)
}

/// Canonicalizes `path` locally first, falling back to the Session-1 bridge canonical path.
pub fn canonicalize_or_bridged(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(path) {
        return Some(PathBuf::from(strip_win_verbatim_str(&c.to_string_lossy())));
    }
    let stat = stat_via_bridge(path)?;
    if !stat.exists {
        return None;
    }
    stat.canonical_path
        .map(|s| PathBuf::from(strip_win_verbatim_str(&s)))
}

/// Browses subdirectories (and optionally creates a safe single subfolder) via the Session-1 bridge.
pub fn browse_dir_bridged(
    path: &str,
    create_subfolder: Option<&str>,
) -> Result<Vec<BridgeDirEntry>, (u16, String)> {
    #[derive(Deserialize)]
    struct Resp {
        ok: bool,
        #[serde(default)]
        entries: Vec<BridgeDirEntry>,
        #[serde(default)]
        error: Option<String>,
    }
    let payload = serde_json::json!({
        "path": path,
        "create_subfolder": create_subfolder,
    })
    .to_string();
    let path_ref = Path::new(path);
    let (status, body) = match call_bridge_with_retry_classified(
        "POST",
        "/bridge/browse",
        Some(payload.as_bytes()),
        Duration::from_secs(8),
    ) {
        Ok(res) => res,
        Err(err) if err.is_timeout() => {
            let msg = format_drive_busy_message(path_ref);
            record_drive_timeout(path_ref, msg.clone());
            return Err((504u16, msg));
        }
        Err(err) => return Err((503u16, err.into_message())),
    };
    let parsed: Resp = serde_json::from_slice(&body)
        .map_err(|e| (502u16, format!("invalid bridge browse payload: {e}")))?;
    if status == 200 && parsed.ok {
        clear_drive_timeout(path_ref);
        Ok(parsed.entries)
    } else if status == 504 {
        let msg = parsed
            .error
            .unwrap_or_else(|| format_drive_busy_message(path_ref));
        record_drive_timeout(path_ref, msg.clone());
        Err((504u16, msg))
    } else {
        Err((
            if status == 200 { 400 } else { status },
            parsed
                .error
                .unwrap_or_else(|| "Bridge directory browse failed".to_string()),
        ))
    }
}

/// Walks a directory tree inside the interactive user session, returning candidate files
/// while enforcing excluded prefixes, size caps, hidden-file policy, and placeholder rules.
pub fn walk_dir_bridged(
    root: &Path,
    excluded_prefixes: &[String],
    max_file_size_bytes: u64,
    skip_hidden: bool,
    policy: CloudPlaceholderPolicy,
) -> Result<(Vec<BridgeWalkEntry>, usize), String> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        entries: Vec<BridgeWalkEntry>,
        #[serde(default)]
        skipped_placeholder: usize,
        #[serde(default)]
        error: Option<String>,
    }
    let (mode, cap) = placeholder_mode_and_cap(policy);
    let payload = serde_json::json!({
        "root": root.to_string_lossy(),
        "excluded_prefixes": excluded_prefixes,
        "max_file_size_bytes": max_file_size_bytes,
        "skip_hidden": skip_hidden,
        "placeholder_mode": mode,
        "hydration_cap_bytes": cap,
    })
    .to_string();
    let (status, body) = call_bridge_with_retry(
        "POST",
        "/bridge/walk",
        Some(payload.as_bytes()),
        Duration::from_secs(120),
    )?;
    let parsed: Resp =
        serde_json::from_slice(&body).map_err(|e| format!("invalid bridge walk payload: {e}"))?;
    if status == 200 {
        Ok((parsed.entries, parsed.skipped_placeholder))
    } else {
        Err(parsed
            .error
            .unwrap_or_else(|| format!("bridge walk failed (HTTP {status})")))
    }
}

/// Reads file bytes from local disk first; if unavailable in Session 0, fetches bytes from the
/// Session-1 bridge while enforcing `max_bytes` and `CloudPlaceholderPolicy` before opening.
pub fn read_bytes_or_bridged(
    path: &Path,
    max_bytes: u64,
    policy: CloudPlaceholderPolicy,
) -> std::io::Result<Vec<u8>> {
    match std::fs::canonicalize(path) {
        Ok(canonical_path) => {
            let meta = std::fs::metadata(&canonical_path)?;
            if !meta.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path is not a regular file",
                ));
            }
            let len = meta.len();
            if is_local_placeholder_meta(&meta) {
                match policy {
                    CloudPlaceholderPolicy::LocallySyncedOnly => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "skipped cloud-only placeholder file (LocallySyncedOnly)",
                        ));
                    }
                    CloudPlaceholderPolicy::HydrateOnDemand {
                        max_file_size_bytes,
                    } if len > max_file_size_bytes => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "skipped cloud-only placeholder exceeding hydration cap ({len} > {max_file_size_bytes})"
                            ),
                        ));
                    }
                    _ => {}
                }
            }
            if max_bytes > 0 && len > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("file exceeds max_bytes ({len} > {max_bytes})"),
                ));
            }
            std::fs::read(&canonical_path)
        }
        Err(local_err) => read_bytes_via_bridge(path, max_bytes, policy).map_err(|msg| {
            if msg.contains("placeholder") {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
            } else if msg.contains("not found") || msg.contains("404") {
                std::io::Error::new(std::io::ErrorKind::NotFound, msg)
            } else if local_err.kind() == std::io::ErrorKind::NotFound {
                local_err
            } else {
                std::io::Error::other(msg)
            }
        }),
    }
}

/// Fetches file bytes strictly via the Session-1 bridge.
pub fn read_bytes_via_bridge(
    path: &Path,
    max_bytes: u64,
    policy: CloudPlaceholderPolicy,
) -> Result<Vec<u8>, String> {
    let (mode, cap) = placeholder_mode_and_cap(policy);
    let payload = serde_json::json!({
        "path": path.to_string_lossy(),
        "max_bytes": max_bytes,
        "placeholder_mode": mode,
        "hydration_cap_bytes": cap,
    })
    .to_string();
    let (status, body) = call_bridge_with_retry(
        "POST",
        "/bridge/read",
        Some(payload.as_bytes()),
        Duration::from_secs(60),
    )?;
    if status == 200 {
        Ok(body)
    } else {
        let msg = String::from_utf8_lossy(&body).trim().to_string();
        Err(if msg.is_empty() {
            format!("bridge read failed (HTTP {status})")
        } else {
            msg
        })
    }
}

/// Updates the list of virtual-drive roots actively watched inside the interactive user session.
pub fn set_watch_roots_bridged(roots: &[PathBuf]) -> bool {
    let root_strings: Vec<String> = roots
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let payload = serde_json::json!({ "roots": root_strings }).to_string();
    call_bridge_with_retry(
        "POST",
        "/bridge/watch",
        Some(payload.as_bytes()),
        Duration::from_secs(5),
    )
    .map(|(status, _)| status == 200)
    .unwrap_or(false)
}

/// Drains queued filesystem change events from the interactive user session bridge.
pub fn poll_watch_events_bridged() -> Vec<BridgeWatchEvent> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        events: Vec<BridgeWatchEvent>,
    }
    let Some(ep) = state_lock().read().ok().and_then(|g| g.endpoint.clone()) else {
        return Vec::new();
    };
    let Ok((200, body)) = http_request_raw(&ep, "GET", "/bridge/events", None, Duration::from_secs(3))
    else {
        return Vec::new();
    };
    serde_json::from_slice::<Resp>(&body)
        .map(|r| r.events)
        .unwrap_or_default()
}

/// Requests the interactive user session bridge to open `path` with the user's default app.
pub fn open_file_bridged(path: &Path) -> Result<(), String> {
    let payload = serde_json::json!({ "path": path.to_string_lossy() }).to_string();
    let (status, body) = call_bridge_with_retry(
        "POST",
        "/bridge/open-file",
        Some(payload.as_bytes()),
        Duration::from_secs(5),
    )?;
    if status == 200 {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&body).trim().to_string())
    }
}

/// A file handle that points either directly to the local filesystem path (zero-copy) or
/// to an automatically-cleaned ephemeral temp copy materialized from the Session-1 bridge
/// (preserving the original extension so extractors, OCR, image/audio indexers, and Magika
/// run identically while retaining `logical_path` for storage and search).
#[derive(Debug)]
pub enum MaterializedFile {
    Local(PathBuf),
    BridgedTemp {
        temp_path: PathBuf,
        logical_path: PathBuf,
    },
}

impl MaterializedFile {
    /// Path to pass to OS file readers, extractors, Magika, OCR, and image decoders.
    pub fn io_path(&self) -> &Path {
        match self {
            Self::Local(p) => p.as_path(),
            Self::BridgedTemp { temp_path, .. } => temp_path.as_path(),
        }
    }

    /// Original logical path (`G:\My Drive\...`) stored in LanceDB, Tantivy, SQLite, and Dedup.
    pub fn logical_path(&self) -> &Path {
        match self {
            Self::Local(p) => p.as_path(),
            Self::BridgedTemp { logical_path, .. } => logical_path.as_path(),
        }
    }

    pub fn is_bridged(&self) -> bool {
        matches!(self, Self::BridgedTemp { .. })
    }
}

impl Drop for MaterializedFile {
    fn drop(&mut self) {
        if let Self::BridgedTemp { temp_path, .. } = self {
            let _ = std::fs::remove_file(temp_path);
        }
    }
}

/// Returns `MaterializedFile::Local` immediately when `path` is locally readable; otherwise
/// fetches bytes over the authenticated loopback Session-1 bridge into a scoped temp file
/// with the exact original filename/extension (cleaned up automatically on `Drop`).
pub fn materialize_file_for_io(
    path: &Path,
    max_bytes: u64,
    policy: CloudPlaceholderPolicy,
) -> std::io::Result<MaterializedFile> {
    if std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) {
        return Ok(MaterializedFile::Local(path.to_path_buf()));
    }
    let bytes = read_bytes_via_bridge(path, max_bytes, policy).map_err(|msg| {
        if msg.contains("placeholder") {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
        } else if msg.contains("not found") || msg.contains("404") {
            std::io::Error::new(std::io::ErrorKind::NotFound, msg)
        } else {
            std::io::Error::other(msg)
        }
    })?;

    let temp_dir = std::env::temp_dir().join("quorumrag_session_bridge");
    std::fs::create_dir_all(&temp_dir)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            e.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(16)
                .collect::<String>()
        })
        .unwrap_or_default();
    let file_name = if ext.is_empty() {
        format!("bridge_{}.bin", uuid::Uuid::new_v4())
    } else {
        format!("bridge_{}.{}", uuid::Uuid::new_v4(), ext)
    };
    let temp_path = temp_dir.join(file_name);
    std::fs::write(&temp_path, &bytes)?;
    Ok(MaterializedFile::BridgedTemp {
        temp_path,
        logical_path: path.to_path_buf(),
    })
}

fn strip_win_verbatim_str(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
            return rest.to_string();
        }
    }
    s.to_string()
}

fn is_local_placeholder_meta(meta: &std::fs::Metadata) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn materialized_local_file_is_zero_copy_and_preserves_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("note.txt");
        std::fs::write(&p, b"hello world").expect("write");
        let mat = materialize_file_for_io(&p, 1024, CloudPlaceholderPolicy::LocallySyncedOnly)
            .expect("materialize");
        assert!(!mat.is_bridged());
        assert_eq!(mat.io_path(), p.as_path());
        assert_eq!(mat.logical_path(), p.as_path());
        drop(mat);
        assert!(p.exists(), "local file must never be deleted on Drop");
    }

    #[test]
    fn loopback_bridge_roundtrip_stat_and_read_and_cleanup() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let token = "test_bridge_secret_0123456789abcdef".to_string();
        let expected_token = token.clone();

        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let mut header_end: Option<usize> = None;
                let mut content_len: usize = 0;
                loop {
                    let n = stream.read(&mut buf).expect("read");
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            let hdr = String::from_utf8_lossy(&raw[..pos]);
                            for line in hdr.lines().skip(1) {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(hend) = header_end {
                        if raw.len().saturating_sub(hend) >= content_len {
                            break;
                        }
                    }
                }
                let req = String::from_utf8_lossy(&raw);
                assert!(req.contains(&format!("X-Quorum-Bridge-Token: {expected_token}")));
                if req.starts_with("POST /bridge/stat ") {
                    let body = serde_json::json!({
                        "exists": true,
                        "is_dir": false,
                        "is_file": true,
                        "len": 11,
                        "modified_secs": 1700000000,
                        "is_placeholder": false,
                        "canonical_path": "G:\\My Drive\\sample.txt"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).expect("write");
                } else if req.starts_with("POST /bridge/read ") {
                    let payload = b"drive-bytes";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    stream.write_all(resp.as_bytes()).expect("write hdr");
                    stream.write_all(payload).expect("write body");
                }
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        });

        let ep = BridgeEndpoint {
            port,
            token,
            session_id: 1,
            pid: std::process::id(),
        };
        let (st, raw) = http_request_raw(
            &ep,
            "POST",
            "/bridge/stat",
            Some(br#"{"path":"G:\\My Drive\\sample.txt"}"#),
            Duration::from_secs(3),
        )
        .expect("stat");
        assert_eq!(st, 200);
        let parsed: BridgeStatInfo = serde_json::from_slice(&raw).expect("json");
        assert!(parsed.exists && parsed.is_file && parsed.len == 11);

        let (st2, bytes) = http_request_raw(
            &ep,
            "POST",
            "/bridge/read",
            Some(br#"{"path":"G:\\My Drive\\sample.txt","max_bytes":1024}"#),
            Duration::from_secs(3),
        )
        .expect("read");
        assert_eq!(st2, 200);
        assert_eq!(bytes, b"drive-bytes");
        server.join().expect("server join");
    }

    #[test]
    fn bridge_504_timeout_preserves_endpoint_and_trips_drive_circuit_breaker() {
        clear_drive_timeout_cache();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let token = "timeout_guard_token_0123456789abcdef0123456789abcdef".to_string();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = serde_json::json!({
                "ok": false,
                "timeout": true,
                "error": "Drive Z:\\ is currently busy or not responding"
            })
            .to_string();
            let resp = format!(
                "HTTP/1.1 504 Gateway Timeout\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).expect("write 504");
            let _ = stream.flush();
        });

        set_bridge_endpoint(port, token, 1, std::process::id());
        let z_path = Path::new(r"Z:\My Drive");
        let err1 = stat_via_bridge_detailed(z_path).expect_err("must return 504");
        assert_eq!(err1.0, 504);
        assert!(err1.1.contains("busy"), "unexpected error: {}", err1.1);

        // Endpoint MUST NOT have been cleared/respawned on HTTP 504.
        assert!(
            active_bridge_info().is_some_and(|(p, _, _)| p == port),
            "HTTP 504 on a slow virtual drive must never clear or respawn a healthy bridge"
        );

        // Circuit breaker must short-circuit repeated probes on Z:\ immediately without hitting TCP.
        let t0 = Instant::now();
        let err2 = stat_via_bridge_detailed(z_path).expect_err("must short-circuit 504");
        assert_eq!(err2.0, 504);
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "circuit breaker should fail-fast without waiting on TCP"
        );
        assert!(drive_timeout_message(z_path).is_some());

        server.join().expect("server join");
        clear_drive_timeout_cache();
        clear_bridge_endpoint();
    }
}
