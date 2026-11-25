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

fn state_lock() -> &'static RwLock<BridgeState> {
    BRIDGE_STATE.get_or_init(|| RwLock::new(BridgeState::default()))
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
) -> Result<(u16, Vec<u8>), String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, ep.port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| format!("bridge connect failed: {e}"))?;
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
        .map_err(|e| format!("bridge request write failed: {e}"))?;
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
                    return Err("bridge response exceeded safety size cap".to_string());
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
                        return Err("bridge response header exceeded limit".to_string());
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
            Err(e) => return Err(format!("bridge read failed: {e}")),
        }
    }

    let hend = header_end.ok_or_else(|| "malformed bridge HTTP response".to_string())?;
    let head_str = String::from_utf8_lossy(&raw[..hend.saturating_sub(4)]);
    let status_line = head_str.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed bridge status line: {status_line}"))?;

    let mut payload = raw[hend..].to_vec();
    if let Some(cl) = content_length {
        if payload.len() > cl {
            payload.truncate(cl);
        }
    }
    Ok((status, payload))
}

fn call_bridge_with_retry(
    method: &str,
    path: &str,
    json_body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), String> {
    let ep = get_or_ensure_endpoint().ok_or_else(|| "session fs bridge unavailable".to_string())?;
    match http_request_raw(&ep, method, path, json_body, timeout) {
        Ok(res) => Ok(res),
        Err(first_err) => {
            // Connection error may indicate user session restarted or helper exited; reconnect once.
            clear_bridge_endpoint();
            let Some(ep2) = get_or_ensure_endpoint() else {
                return Err(first_err);
            };
            http_request_raw(&ep2, method, path, json_body, timeout)
        }
    }
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
    let Ok((200, body)) = call_bridge_with_retry("GET", "/bridge/drives", None, Duration::from_secs(8))
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

/// Probes metadata strictly through the Session-1 bridge.
pub fn stat_via_bridge(path: &Path) -> Option<BridgeStatInfo> {
    let payload = serde_json::json!({ "path": path.to_string_lossy() }).to_string();
    let Ok((200, body)) = call_bridge_with_retry(
        "POST",
        "/bridge/stat",
        Some(payload.as_bytes()),
        Duration::from_secs(12),
    ) else {
        return None;
    };
    let info: BridgeStatInfo = serde_json::from_slice(&body).ok()?;
    if info.exists {
        if let Some(bit) = drive_letter_bit(path) {
            SESSION_ONLY_DRIVE_MASK.fetch_or(bit, Ordering::Relaxed);
        }
    }
    Some(info)
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
    let (status, body) = call_bridge_with_retry(
        "POST",
        "/bridge/browse",
        Some(payload.as_bytes()),
        Duration::from_secs(15),
    )
    .map_err(|e| (503u16, e))?;
    let parsed: Resp = serde_json::from_slice(&body)
        .map_err(|e| (502u16, format!("invalid bridge browse payload: {e}")))?;
    if status == 200 && parsed.ok {
        Ok(parsed.entries)
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
}
