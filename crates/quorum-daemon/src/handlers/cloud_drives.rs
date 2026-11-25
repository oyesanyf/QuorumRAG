//! Cloud Drives Settings, Discovery, Lifecycle Orchestration, and Session-0 Virtual Drive Handlers.
//!
//! Endpoints:
//! - `GET  /api/cloud-drives`
//! - `POST /api/cloud-drives/config`
//! - `POST /api/cloud-drives/reindex`
//! - `POST /api/cloud-drives/relay/register`

use axum::extract::{ConnectInfo, Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::state::{DaemonState, RelayedCloudDriveEntry};
use quorum_coordinator::{global_mesh_dlp_controller, OsoosiMeshDlpController};
use quorum_ingest::cloud_drives::{discover_cloud_drives, DiscoveredCloudDrive};
use quorum_types::{
    normalize_prefix_for_match, path_matches_prefix, validate_cloud_drive_path, AccessTier,
    CloudDriveConfigEntry, CloudDriveMountStatus, CloudDriveProvider, CloudDrivesSettings,
    CloudPlaceholderMode, CloudPlaceholderPolicy,
};

static CLOUD_DRIVES_CONFIG_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn cloud_drives_config_mutex() -> &'static tokio::sync::Mutex<()> {
    CLOUD_DRIVES_CONFIG_MUTEX.get_or_init(|| tokio::sync::Mutex::new(()))
}

const RELAY_TTL: Duration = Duration::from_secs(90);
const MAX_HYDRATION_CAP_MB: u64 = 2048;

fn validate_hydration_cap_mb(max_mb: u64) -> Result<u64, String> {
    if !(1..=MAX_HYDRATION_CAP_MB).contains(&max_mb) {
        return Err(format!(
            "hydration_max_file_size_mb must be between 1 and {MAX_HYDRATION_CAP_MB} MB"
        ));
    }
    Ok(max_mb)
}

fn strip_windows_drive_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/')
        {
            return PathBuf::from(rest);
        }
    }
    p.to_path_buf()
}

/// Returns true when `raw` contains syntactic path-smuggling hazards (NUL/control/bidi chars,
/// percent-encoded traversal/separators, UNC / device-namespace paths, NTFS ADS colons,
/// or Windows trailing-dot/trailing-space segment tricks).
pub fn has_cloud_filter_syntax_hazard(raw: &str) -> bool {
    if raw.len() > 4096 {
        return true;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || raw != trimmed {
        return true;
    }
    if raw.chars().any(|c| c == '\0' || c.is_control()) {
        return true;
    }
    if raw.chars().any(|c| {
        matches!(
            c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
        )
    }) {
        return true;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("%252e")
        || lower.contains("%252f")
        || lower.contains("%255c")
        || lower.contains("%2500")
    {
        return true;
    }
    if lower.starts_with(r"\\?\unc\")
        || lower.starts_with("//?/unc/")
        || lower.starts_with(r"\\.\")
        || lower.starts_with("//./")
    {
        return true;
    }
    let without_verbatim = if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest
    } else if let Some(rest) = raw.strip_prefix("//?/") {
        rest
    } else {
        raw
    };
    if without_verbatim.starts_with(r"\\") || without_verbatim.starts_with("//") {
        return true;
    }
    let stripped_had_verbatim = without_verbatim.len() != raw.len();
    let bytes = without_verbatim.as_bytes();
    let is_win_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if stripped_had_verbatim && !is_win_drive {
        return true;
    }
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b':' && !(idx == 1 && is_win_drive) {
            return true;
        }
    }
    for seg in without_verbatim.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || seg == ".." {
            continue;
        }
        if seg != seg.trim() || seg.ends_with('.') || seg.ends_with(' ') {
            return true;
        }
    }
    false
}

/// Fail-closed canonicalization and validation helper for cloud-drive containment checks.
///
/// - Rejects syntactic hazards (percent-encoded traversal, UNC/device paths, NUL/control/bidi, ADS).
/// - Canonicalizes existing filesystem paths (resolving `..`, `//?/...`, relative paths, 8.3 names,
///   symlinks, and NTFS junctions), strips the Windows `\\?\` drive-letter prefix (keeping UNC
///   rejected), and validates via `quorum_types::normalize_prefix_for_match`.
/// - For non-existent paths: rejects `..`, `.`, `//?/` / `\\?\`, relative paths, and dangling symlinks,
///   while canonicalizing any existing symlinked ancestor before appending clean normal components.
pub fn canonicalize_for_cloud_filter(path: &Path) -> Option<PathBuf> {
    let raw = path.to_string_lossy();
    if has_cloud_filter_syntax_hazard(&raw) {
        return None;
    }

    if !is_test_profile_override_active() {
        match quorum_types::session_fs_bridge::local_canonicalize_bounded(
            path,
            Duration::from_millis(2000),
        ) {
            Ok(Some(canon)) => {
                let clean = strip_windows_drive_verbatim_prefix(&canon);
                let clean_str = clean.to_string_lossy();
                if normalize_prefix_for_match(&clean_str).is_ok() {
                    return Some(clean);
                }
                return None;
            }
            Err(_) => {
                // Virtual drive is currently busy/timed out; avoid blocking on fallback syscalls.
                let clean = strip_windows_drive_verbatim_prefix(path);
                if normalize_prefix_for_match(&clean.to_string_lossy()).is_ok() {
                    return Some(clean);
                }
                return None;
            }
            Ok(None) => {}
        }
    } else if let Ok(canon) = std::fs::canonicalize(path) {
        let clean = strip_windows_drive_verbatim_prefix(&canon);
        let clean_str = clean.to_string_lossy();
        if normalize_prefix_for_match(&clean_str).is_ok() {
            return Some(clean);
        }
        return None;
    }

    if !is_test_profile_override_active() {
        if let Some(canon) = quorum_types::session_fs_bridge::canonicalize_or_bridged(path) {
            let clean = strip_windows_drive_verbatim_prefix(&canon);
            let clean_str = clean.to_string_lossy();
            if normalize_prefix_for_match(&clean_str).is_ok() {
                return Some(clean);
            }
            return None;
        }
    }

    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return None;
    }

    if raw.starts_with("//?/") || raw.starts_with(r"\\?\") {
        return None;
    }
    if path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return None;
    }
    if normalize_prefix_for_match(&raw).is_err() {
        return None;
    }

    let mut tail_parts: Vec<std::ffi::OsString> = Vec::new();
    let mut cur_opt = Some(path);
    while let Some(cur) = cur_opt {
        if cur.as_os_str().is_empty() {
            break;
        }
        if let Ok(canon_anc) = std::fs::canonicalize(cur) {
            let mut joined = strip_windows_drive_verbatim_prefix(&canon_anc);
            for part in tail_parts.iter().rev() {
                joined.push(part);
            }
            let joined_str = joined.to_string_lossy();
            return if normalize_prefix_for_match(&joined_str).is_ok() {
                Some(joined)
            } else {
                None
            };
        }
        match cur.file_name() {
            Some(name) => {
                tail_parts.push(name.to_os_string());
                cur_opt = cur.parent();
            }
            None => break,
        }
    }

    let clean = strip_windows_drive_verbatim_prefix(path);
    if normalize_prefix_for_match(&clean.to_string_lossy()).is_ok() {
        Some(clean)
    } else {
        None
    }
}

/// Returns true when `path` is an actual OS user profile root directory
/// (`<SystemDrive>\Users\<user>`, `C:\Users\<user>`, `/Users/<user>`, `/home/<user>`,
/// or an active `QUORUM_CLOUD_TEST_PROFILE_DIR` / `USERPROFILE` / `HOME` profile root).
pub fn is_user_profile_root_dir(path: &Path) -> bool {
    let clean = canonicalize_for_cloud_filter(path);
    let check_path = clean.as_deref().unwrap_or(path);
    let Ok(check_norm) = normalize_prefix_for_match(&check_path.to_string_lossy()) else {
        return false;
    };

    let norm_env_path = |raw: &str| -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let p = Path::new(trimmed);
        canonicalize_for_cloud_filter(p)
            .and_then(|cp| normalize_prefix_for_match(&cp.to_string_lossy()).ok())
            .or_else(|| normalize_prefix_for_match(trimmed).ok())
    };

    if let Ok(test_profile) = std::env::var("QUORUM_CLOUD_TEST_PROFILE_DIR") {
        if norm_env_path(&test_profile).as_deref() == Some(check_norm.as_str()) {
            return true;
        }
    }

    let Some(parent) = check_path.parent() else {
        return false;
    };
    let Ok(parent_norm) = normalize_prefix_for_match(&parent.to_string_lossy()) else {
        return false;
    };

    #[cfg(windows)]
    {
        if parent_norm == r"c:\users" {
            return true;
        }
        if let Ok(sys_drive) = std::env::var("SystemDrive") {
            let trimmed = sys_drive.trim().trim_end_matches(['\\', '/']);
            if !trimmed.is_empty() {
                let users_base = format!(r"{trimmed}\Users");
                if norm_env_path(&users_base).as_deref() == Some(parent_norm.as_str()) {
                    return true;
                }
            }
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            if norm_env_path(&user_profile).as_deref() == Some(check_norm.as_str()) {
                return true;
            }
        }
        false
    }

    #[cfg(not(windows))]
    {
        if parent_norm == "/users" || parent_norm == "/home" {
            return true;
        }
        if let Ok(home) = std::env::var("HOME") {
            if norm_env_path(&home).as_deref() == Some(check_norm.as_str()) {
                return true;
            }
        }
        false
    }
}

pub fn collect_disabled_cloud_roots_for_settings(
    settings: &CloudDrivesSettings,
    discovered: &[DiscoveredCloudDrive],
    exclude_drive_id: Option<&str>,
) -> Vec<String> {
    let mut disabled = Vec::new();
    let mut push_with_canon = |raw_str: String| {
        let s = raw_str.trim().to_string();
        if s.is_empty() {
            return;
        }
        if !disabled.contains(&s) {
            disabled.push(s.clone());
        }
        if let Some(canon) = canonicalize_for_cloud_filter(Path::new(&s)) {
            let cs = canon.to_string_lossy().to_string();
            if !cs.is_empty() && !disabled.contains(&cs) {
                disabled.push(cs);
            }
        }
    };
    for entry in settings
        .drives
        .iter()
        .filter(|d| !d.enabled && !exclude_drive_id.is_some_and(|ex| d.id.eq_ignore_ascii_case(ex)))
    {
        for raw in entry.root_path.iter().chain(entry.custom_paths.iter()) {
            push_with_canon(raw.clone());
        }
    }
    for disc in discovered {
        if exclude_drive_id.is_some_and(|ex| disc.id.eq_ignore_ascii_case(ex)) {
            continue;
        }
        let is_enabled = settings
            .drives
            .iter()
            .any(|d| d.id.eq_ignore_ascii_case(&disc.id) && d.enabled);
        if !is_enabled {
            for r in disc.root_path.iter().chain(disc.detected_roots.iter()) {
                push_with_canon(r.to_string_lossy().to_string());
            }
        }
    }
    disabled
}

pub fn collect_disabled_cloud_roots(
    controller: &OsoosiMeshDlpController,
    discovered: &[DiscoveredCloudDrive],
) -> Vec<String> {
    let settings = controller.get_cloud_drives_settings();
    collect_disabled_cloud_roots_for_settings(&settings, discovered, None)
}

/// Returns true when `path` is a live directory on local disk or via the active Session-1 bridge
/// (respecting `QUORUM_CLOUD_TEST_PROFILE_DIR` hermetic test isolation).
fn dir_exists_live(path: &Path) -> bool {
    if is_test_profile_override_active() {
        return path.is_dir();
    }
    match quorum_types::session_fs_bridge::local_is_dir_bounded(
        path,
        false,
        Duration::from_millis(2000),
    ) {
        Ok(true) => return true,
        Err(_) => return false,
        Ok(false) => {}
    }
    quorum_types::session_fs_bridge::stat_via_bridge(path)
        .is_some_and(|st| st.exists && st.is_dir)
}

pub fn collect_enabled_cloud_paths_filtered(
    controller: &OsoosiMeshDlpController,
    disabled_cloud_roots: &[String],
) -> Vec<PathBuf> {
    let settings = controller.get_cloud_drives_settings();
    let mut enabled_paths = Vec::new();
    for entry in settings.drives.iter().filter(|d| d.enabled) {
        for raw in entry.root_path.iter().chain(entry.custom_paths.iter()) {
            if let Some(p) = canonicalize_for_cloud_filter(Path::new(raw.trim())) {
                if dir_exists_live(&p) {
                    push_watch_root_excluding_disabled(
                        &p,
                        disabled_cloud_roots,
                        &mut enabled_paths,
                    );
                }
            }
        }
    }
    enabled_paths
}

pub fn collect_enabled_cloud_paths(controller: &OsoosiMeshDlpController) -> Vec<PathBuf> {
    let disabled = collect_disabled_cloud_roots(controller, &[]);
    collect_enabled_cloud_paths_filtered(controller, &disabled)
}

fn check_cloud_drive_path_conflict(clean_p: &Path, disabled_roots: &[String]) -> Option<String> {
    if is_user_profile_root_dir(clean_p) {
        return Some(format!(
            "Cloud drive path cannot be a user profile root directory: {}",
            clean_p.display()
        ));
    }
    if is_disabled_cloud_root(clean_p, disabled_roots) {
        return Some(format!(
            "Path resides inside a disabled cloud drive root and cannot be assigned: {}",
            clean_p.display()
        ));
    }
    if is_strict_ancestor_of_disabled_cloud_root(clean_p, disabled_roots) {
        return Some(format!(
            "Path is an ancestor of a disabled cloud drive root and cannot be assigned wholesale: {}",
            clean_p.display()
        ));
    }
    None
}

fn collect_drive_existing_paths_excluding_disabled(
    entry: &CloudDriveConfigEntry,
    disabled_roots: &[String],
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for raw in entry.root_path.iter().chain(entry.custom_paths.iter()) {
        if let Some(clean_p) = canonicalize_for_cloud_filter(Path::new(raw.trim())) {
            if dir_exists_live(&clean_p) {
                push_watch_root_excluding_disabled(&clean_p, disabled_roots, &mut out);
            }
        }
    }
    out
}

pub fn is_disabled_cloud_root(path: &Path, disabled_roots: &[String]) -> bool {
    let Some(clean) = canonicalize_for_cloud_filter(path) else {
        // Fail closed: invalid, traversal, UNC, ADS, or unnormalizable paths are treated as blocked.
        return true;
    };
    let cand = clean.to_string_lossy();
    disabled_roots.iter().any(|root| {
        if path_matches_prefix(&cand, root).unwrap_or(false) {
            return true;
        }
        if let Some(clean_root) = canonicalize_for_cloud_filter(Path::new(root)) {
            let clean_root_str = clean_root.to_string_lossy();
            return path_matches_prefix(&cand, &clean_root_str).unwrap_or(false);
        }
        false
    })
}

pub fn is_strict_ancestor_of_disabled_cloud_root(dir: &Path, disabled_roots: &[String]) -> bool {
    let Some(clean_dir) = canonicalize_for_cloud_filter(dir) else {
        // Fail closed: never allow unnormalizable/invalid directories to pass watcher guards.
        return true;
    };
    let dir_str = clean_dir.to_string_lossy();
    let Ok(dir_norm) = normalize_prefix_for_match(&dir_str) else {
        return true;
    };
    disabled_roots.iter().any(|root| {
        let root_norm = canonicalize_for_cloud_filter(Path::new(root))
            .and_then(|cr| normalize_prefix_for_match(&cr.to_string_lossy()).ok())
            .or_else(|| normalize_prefix_for_match(root).ok());
        let Some(root_norm) = root_norm else {
            return false;
        };
        root_norm != dir_norm && path_matches_prefix(&root_norm, &dir_norm).unwrap_or(false)
    })
}

fn should_skip_ancestor_child(entry: &std::fs::DirEntry, ft: &std::fs::FileType) -> bool {
    const SKIP_DIRS: &[&str] = &[
        "$recycle.bin",
        "system volume information",
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "recovery",
        "perflogs",
        "msocache",
        "config.msi",
        "appdata",
        "node_modules",
        "target",
        "osoosi_target",
        "python311",
        "docker",
        "chrome_temp_profile",
        ".git",
        ".cargo",
        ".rustup",
        "__pycache__",
        ".venv",
        "venv",
        ".tmp.driveupload",
        ".pytest_cache",
        ".lance",
        "lance",
        ".tantivy",
        "tantivy",
        ".quorumrag-live-data",
        "storage",
        "quorumrag",
        ".quorumrag",
        "documents and settings",
        "all users",
        "default user",
        "default",
        "$winreagent",
    ];

    if ft.is_symlink() {
        return true;
    }
    let name_lossy = entry.file_name().to_string_lossy().to_string();
    let name_lower = name_lossy.to_ascii_lowercase();
    if name_lower.starts_with('.') || name_lower.starts_with('$') {
        return true;
    }
    if SKIP_DIRS.contains(&name_lower.as_str()) {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0002;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0004;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if let Ok(meta) = entry.metadata() {
            let attrs = meta.file_attributes();
            if attrs
                & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_REPARSE_POINT)
                != 0
            {
                return true;
            }
        }
    }
    false
}

fn expand_ancestor_dir_rec(
    dir: &Path,
    disabled_cloud_roots: &[String],
    depth: usize,
    out: &mut Vec<PathBuf>,
) {
    const MAX_ANCESTOR_EXPAND_DEPTH: usize = 6;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if should_skip_ancestor_child(&entry, &ft) {
            continue;
        }
        let Some(child) = canonicalize_for_cloud_filter(&entry.path()) else {
            continue;
        };
        if is_user_profile_root_dir(&child) || is_disabled_cloud_root(&child, disabled_cloud_roots)
        {
            continue;
        }
        if ft.is_dir() {
            if std::fs::read_dir(&child).is_err() {
                continue;
            }
            if is_strict_ancestor_of_disabled_cloud_root(&child, disabled_cloud_roots) {
                if depth < MAX_ANCESTOR_EXPAND_DEPTH {
                    expand_ancestor_dir_rec(&child, disabled_cloud_roots, depth + 1, out);
                }
            } else if !out.contains(&child) {
                out.push(child);
            }
        } else if ft.is_file() && !out.contains(&child) {
            out.push(child);
        }
    }
}

/// Expands physical drives via `ReindexWorker::expand_drive_roots`, skipping user profile roots
/// and disabled cloud roots, and recursively splitting any slice that is a strict ancestor of a
/// disabled cloud root (up to depth 6) so sibling folders remain watched while disabled cloud
/// folders are never watched or crawled without polluting `excluded_paths`.
pub fn expand_physical_watch_paths(
    drives: &[PathBuf],
    disabled_cloud_roots: &[String],
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for slice in quorum_ingest::ReindexWorker::expand_drive_roots(drives) {
        let Some(clean_slice) = canonicalize_for_cloud_filter(&slice) else {
            continue;
        };
        if is_user_profile_root_dir(&clean_slice)
            || is_disabled_cloud_root(&clean_slice, disabled_cloud_roots)
        {
            continue;
        }
        if clean_slice.is_dir()
            && is_strict_ancestor_of_disabled_cloud_root(&clean_slice, disabled_cloud_roots)
        {
            expand_ancestor_dir_rec(&clean_slice, disabled_cloud_roots, 1, &mut out);
        } else if !out.contains(&clean_slice) {
            out.push(clean_slice);
        }
    }
    out
}

pub fn push_watch_root_excluding_disabled(
    root: &Path,
    disabled_cloud_roots: &[String],
    out: &mut Vec<PathBuf>,
) {
    let Some(clean_root) = canonicalize_for_cloud_filter(root) else {
        return;
    };
    if normalize_prefix_for_match(&clean_root.to_string_lossy()).is_err() {
        return;
    }
    if is_user_profile_root_dir(&clean_root)
        || is_disabled_cloud_root(&clean_root, disabled_cloud_roots)
    {
        return;
    }
    if clean_root.is_dir()
        && is_strict_ancestor_of_disabled_cloud_root(&clean_root, disabled_cloud_roots)
    {
        expand_ancestor_dir_rec(&clean_root, disabled_cloud_roots, 1, out);
    } else if !out.contains(&clean_root) {
        out.push(clean_root);
    }
}

/// Builds the startup `initial_watch_dirs` list while ensuring disabled cloud drives (and custom
/// cloud paths) nested inside user document roots, `shared_folders`, or `opt_in_folders` are
/// split and excluded before `ReindexWorker::add_watch_paths` or `FilesystemWatcher` registration.
pub fn collect_filtered_initial_watch_dirs(
    user_roots: &[PathBuf],
    uploaded_docs_dir: Option<&Path>,
    shared_folders: &[PathBuf],
    opt_in_folders: &[PathBuf],
    enabled_cloud_paths: &[PathBuf],
    expanded_watch_paths: &[PathBuf],
    disabled_cloud_roots: &[String],
) -> Vec<PathBuf> {
    let mut initial_watch_dirs = Vec::new();
    for root in user_roots {
        push_watch_root_excluding_disabled(root, disabled_cloud_roots, &mut initial_watch_dirs);
    }
    if let Some(up_dir) = uploaded_docs_dir {
        if up_dir.exists() {
            if let Some(clean_up) = canonicalize_for_cloud_filter(up_dir) {
                if !is_disabled_cloud_root(&clean_up, disabled_cloud_roots)
                    && !initial_watch_dirs.contains(&clean_up)
                {
                    initial_watch_dirs.push(clean_up);
                }
            }
        }
    }
    for folder in shared_folders {
        if folder.exists() {
            push_watch_root_excluding_disabled(
                folder,
                disabled_cloud_roots,
                &mut initial_watch_dirs,
            );
        }
    }
    for folder in opt_in_folders {
        if folder.exists() {
            push_watch_root_excluding_disabled(
                folder,
                disabled_cloud_roots,
                &mut initial_watch_dirs,
            );
        }
    }
    for cp in enabled_cloud_paths {
        push_watch_root_excluding_disabled(cp, disabled_cloud_roots, &mut initial_watch_dirs);
    }
    for expanded in expanded_watch_paths {
        if expanded.is_dir() {
            push_watch_root_excluding_disabled(
                expanded,
                disabled_cloud_roots,
                &mut initial_watch_dirs,
            );
        }
    }
    initial_watch_dirs
}

/// Builds the Pass 0 priority fast-pass root list in `Documents -> Desktop -> Downloads -> ... -> Pictures`
/// order, splitting/excluding any disabled cloud drive roots nested inside user document folders.
pub fn collect_pass0_priority_user_roots(
    user_roots: &[PathBuf],
    uploaded_docs_dir: Option<&Path>,
    disabled_cloud_roots: &[String],
) -> Vec<PathBuf> {
    let mut sorted_roots = user_roots.to_vec();
    sorted_roots.sort_by_key(|r| {
        let name = r
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        match name.as_str() {
            "documents" => 0,
            "desktop" => 1,
            "downloads" => 2,
            "pictures" => 10,
            _ => 5,
        }
    });
    let mut priority_user_roots = Vec::new();
    for root in &sorted_roots {
        push_watch_root_excluding_disabled(root, disabled_cloud_roots, &mut priority_user_roots);
    }
    if let Some(up_dir) = uploaded_docs_dir {
        if up_dir.exists() && !priority_user_roots.contains(&up_dir.to_path_buf()) {
            priority_user_roots.insert(0, up_dir.to_path_buf());
        }
    }
    priority_user_roots
}

pub fn effective_ingest_max_file_size_bytes(settings: &CloudDrivesSettings) -> u64 {
    const BASE_MAX_BYTES: u64 = 50 * 1024 * 1024;
    const MAX_ALLOWED_BYTES: u64 = MAX_HYDRATION_CAP_MB * 1024 * 1024;
    let persisted_cap_bytes = settings
        .hydration_max_file_size_mb
        .saturating_mul(1024 * 1024)
        .min(MAX_ALLOWED_BYTES);
    BASE_MAX_BYTES.max(persisted_cap_bytes)
}

/// Returns true when `QUORUM_CLOUD_TEST_PROFILE_DIR` is set and non-empty.
pub fn is_test_profile_override_active() -> bool {
    std::env::var("QUORUM_CLOUD_TEST_PROFILE_DIR")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

#[cfg(windows)]
fn running_as_local_system() -> bool {
    crate::win_native::is_running_as_local_system()
}

#[cfg(not(windows))]
fn running_as_local_system() -> bool {
    false
}

#[cfg(windows)]
fn is_session_zero() -> bool {
    crate::win_native::is_session_zero()
}

#[cfg(not(windows))]
fn is_session_zero() -> bool {
    false
}

#[derive(Debug, Clone, Default)]
pub struct SessionHintSummary {
    pub provider_id: String,
    pub root_path: String,
}

#[derive(Debug, Clone)]
pub struct CloudDrivesStatusRuntimeContext {
    pub local_system: bool,
    pub session_zero: bool,
    pub allow_session_only_eval: bool,
    pub discovered: Vec<DiscoveredCloudDrive>,
    pub session_hints: Vec<SessionHintSummary>,
    pub relay_snapshot: Option<crate::state::CloudDriveRelaySnapshot>,
}

#[cfg(windows)]
fn probe_session_virtual_drive_hints() -> Vec<SessionHintSummary> {
    if is_test_profile_override_active() {
        return Vec::new();
    }
    let probe = crate::win_native::detect_interactive_session_virtual_drives();
    probe
        .hints
        .into_iter()
        .filter_map(|h| {
            validate_cloud_drive_path(&h.root_path)
                .ok()
                .map(|valid| SessionHintSummary {
                    provider_id: h.provider_id,
                    root_path: valid,
                })
        })
        .collect()
}

#[cfg(not(windows))]
fn probe_session_virtual_drive_hints() -> Vec<SessionHintSummary> {
    Vec::new()
}

/// Reconciles `discover_cloud_drives()` into `controller`'s persisted `CloudDrivesSettings`
/// without overwriting existing user overrides (`enabled`, `access_tier`, `custom_paths`, etc.).
/// Newly discovered drives strictly default to `enabled = false` and `access_tier = 3`.
pub fn reconcile_discovered_cloud_drives(
    controller: &OsoosiMeshDlpController,
    discovered: &[DiscoveredCloudDrive],
) {
    let mut changed = false;
    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());

        for disc in discovered {
            let disc_root = disc
                .root_path
                .as_ref()
                .and_then(|p| validate_cloud_drive_path(&p.to_string_lossy()).ok());

            if let Some(existing) = guard
                .cloud_drives
                .drives
                .iter_mut()
                .find(|e| e.id.eq_ignore_ascii_case(&disc.id))
            {
                let existing_root_valid = existing
                    .root_path
                    .as_deref()
                    .is_some_and(|rp| dir_exists_live(Path::new(rp.trim())));
                if disc_root.is_some()
                    && existing.custom_paths.is_empty()
                    && (!existing_root_valid || existing.root_path.is_none())
                {
                    existing.root_path = disc_root;
                    changed = true;
                } else if !existing.enabled
                    && existing.root_path.is_some()
                    && !existing_root_valid
                    && disc_root.is_none()
                {
                    existing.root_path = None;
                    changed = true;
                }
                if existing.account_kind.is_none() && disc.account_kind.is_some() {
                    existing.account_kind = disc.account_kind.clone();
                    changed = true;
                }
            } else {
                guard
                    .cloud_drives
                    .drives
                    .push(CloudDriveConfigEntry::new_disabled(
                        disc.id.clone(),
                        disc.provider,
                        disc.label.clone(),
                        disc_root,
                        disc.account_kind.clone(),
                    ));
                changed = true;
            }
        }
    }
    if changed {
        controller.save_to_disk();
    }
}

/// Top-level JSON response for `GET /api/cloud-drives` and `POST /api/cloud-drives/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudDrivesStatusResponse {
    pub placeholder_mode: CloudPlaceholderMode,
    pub hydration_max_file_size_mb: u64,
    pub running_as_local_system: bool,
    pub virtual_drive_guidance: Option<String>,
    pub drives: Vec<CloudDriveStatusDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purged_files: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purged_chunks: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_required_for_cap_above_50mb: Option<bool>,
}

/// Per-drive JSON DTO returned in `drives[]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudDriveStatusDto {
    pub id: String,
    /// Uses `CloudDriveProvider::as_str()` so `OneDrive` serializes as `"onedrive"`.
    pub provider: String,
    pub label: String,
    pub account_kind: Option<String>,
    pub detected: bool,
    pub mounted: bool,
    pub status: CloudDriveMountStatus,
    pub status_label: String,
    pub virtual_drive: bool,
    pub session_only: bool,
    pub session_guidance: Option<String>,
    pub enabled: bool,
    pub access_tier: u8,
    pub shared_with_mesh: bool,
    pub root_path: Option<String>,
    pub detected_roots: Vec<String>,
    pub custom_paths: Vec<String>,
    pub indexed_files: usize,
    pub indexed_chunks: usize,
}

const fn default_tier_restricted() -> u8 {
    AccessTier::Tier3Restricted.as_u8()
}

/// Permissive input entry for `POST /api/cloud-drives/config` full `drives` array fallback
/// so `"onedrive"` (from `GET /api/cloud-drives`) and `"one_drive"` are both accepted via
/// `CloudDriveProvider::from_str`.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudDriveConfigEntryInput {
    pub id: String,
    pub provider: String,
    pub label: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub custom_paths: Vec<String>,
    #[serde(default = "default_tier_restricted")]
    pub access_tier: u8,
    #[serde(default)]
    pub account_kind: Option<String>,
}

impl CloudDriveConfigEntryInput {
    fn into_config_entry(self) -> Result<CloudDriveConfigEntry, String> {
        let provider = CloudDriveProvider::from_str(&self.provider).map_err(|e| e.to_string())?;
        Ok(CloudDriveConfigEntry {
            id: self.id,
            provider,
            label: self.label,
            enabled: self.enabled,
            root_path: self.root_path,
            custom_paths: self.custom_paths,
            access_tier: self.access_tier,
            account_kind: self.account_kind,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CloudDrivesConfigPayload {
    pub action: Option<String>,
    pub id: Option<String>,
    pub enabled: Option<bool>,
    pub access_tier: Option<u8>,
    pub root_path: Option<String>,
    pub path: Option<String>,
    pub placeholder_mode: Option<CloudPlaceholderMode>,
    pub hydration_max_file_size_mb: Option<u64>,
    pub drives: Option<Vec<CloudDriveConfigEntryInput>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloudDrivesReindexPayload {
    pub id: String,
    #[serde(default)]
    pub full_rebuild: Option<bool>,
    #[serde(default)]
    pub force_reembed: Option<bool>,
    #[serde(default)]
    pub batch_size: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRelayPayload {
    pub session_id: Option<u32>,
    #[serde(default)]
    pub drives: Vec<RelayedCloudDriveEntry>,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({
            "ok": false,
            "status": "error",
            "error": msg.into(),
        })),
    )
        .into_response()
}

fn status_label_for(status: CloudDriveMountStatus) -> &'static str {
    match status {
        CloudDriveMountStatus::Mounted => "Mounted",
        CloudDriveMountStatus::NotDetected => "Not Detected",
        CloudDriveMountStatus::SessionOnly => "Session Only",
        CloudDriveMountStatus::Error => "Error",
    }
}

fn collect_drive_all_prefixes(entry: &CloudDriveConfigEntry) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in entry.root_path.iter().chain(entry.custom_paths.iter()) {
        if let Ok(norm) = normalize_prefix_for_match(raw) {
            if seen.insert(norm.clone()) {
                out.push(norm);
            }
        }
    }
    out
}

fn collect_active_prefixes_except(
    drives: &[CloudDriveConfigEntry],
    exclude_id: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    for d in drives {
        if !d.enabled || d.id.eq_ignore_ascii_case(exclude_id) {
            continue;
        }
        out.extend(collect_drive_all_prefixes(d));
    }
    out
}

fn is_prefix_covered_upward(target_norm: &str, active_prefixes: &[String]) -> bool {
    active_prefixes
        .iter()
        .any(|active| path_matches_prefix(target_norm, active).unwrap_or(false))
}

fn is_prefix_ancestor_of_any(target_norm: &str, active_prefixes: &[String]) -> bool {
    active_prefixes
        .iter()
        .any(|active| path_matches_prefix(active, target_norm).unwrap_or(false))
}

fn is_prefix_protected(target_norm: &str, active_prefixes: &[String]) -> bool {
    is_prefix_covered_upward(target_norm, active_prefixes)
        || is_prefix_ancestor_of_any(target_norm, active_prefixes)
}

fn merged_entries_in_order(
    settings: &CloudDrivesSettings,
    discovered: &[DiscoveredCloudDrive],
) -> Vec<CloudDriveConfigEntry> {
    let mut out: Vec<CloudDriveConfigEntry> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for disc in discovered {
        let key = disc.id.trim().to_ascii_lowercase();
        if !seen_ids.insert(key) {
            continue;
        }
        if let Some(existing) = settings
            .drives
            .iter()
            .find(|e| e.id.eq_ignore_ascii_case(&disc.id))
        {
            let mut merged = existing.clone();
            if merged.root_path.is_none() && merged.custom_paths.is_empty() {
                merged.root_path = disc
                    .root_path
                    .as_ref()
                    .and_then(|p| validate_cloud_drive_path(&p.to_string_lossy()).ok());
            }
            if merged.account_kind.is_none() {
                merged.account_kind = disc.account_kind.clone();
            }
            out.push(merged);
        } else {
            let disc_root = disc
                .root_path
                .as_ref()
                .and_then(|p| validate_cloud_drive_path(&p.to_string_lossy()).ok());
            out.push(CloudDriveConfigEntry::new_disabled(
                disc.id.clone(),
                disc.provider,
                disc.label.clone(),
                disc_root,
                disc.account_kind.clone(),
            ));
        }
    }

    for entry in &settings.drives {
        let key = entry.id.trim().to_ascii_lowercase();
        if seen_ids.insert(key) {
            out.push(entry.clone());
        }
    }

    out
}

/// Builds the full live `CloudDrivesStatusResponse` using non-blocking catalog and discovery tasks.
pub async fn build_cloud_drives_status_response(
    state: &DaemonState,
    purged_files: Option<usize>,
    purged_chunks: Option<usize>,
) -> CloudDrivesStatusResponse {
    let test_override = is_test_profile_override_active();
    let local_system = running_as_local_system();
    let session_zero = is_session_zero();

    let discovered = tokio::task::spawn_blocking(discover_cloud_drives)
        .await
        .unwrap_or_default();

    let session_hints = if !test_override {
        tokio::task::spawn_blocking(probe_session_virtual_drive_hints)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let relay_snapshot = if !test_override {
        state.active_cloud_drive_relay(RELAY_TTL)
    } else {
        None
    };

    build_cloud_drives_status_response_with_context(
        state,
        CloudDrivesStatusRuntimeContext {
            local_system,
            session_zero,
            allow_session_only_eval: !test_override,
            discovered,
            session_hints,
            relay_snapshot,
        },
        purged_files,
        purged_chunks,
    )
    .await
}

/// Builds `CloudDrivesStatusResponse` from an explicit runtime context (allowing hermetic
/// Session-0 / relay status tests without host registry/WTS side effects).
pub async fn build_cloud_drives_status_response_with_context(
    state: &DaemonState,
    ctx: CloudDrivesStatusRuntimeContext,
    purged_files: Option<usize>,
    purged_chunks: Option<usize>,
) -> CloudDrivesStatusResponse {
    let CloudDrivesStatusRuntimeContext {
        local_system,
        session_zero,
        allow_session_only_eval,
        discovered,
        session_hints,
        relay_snapshot,
    } = ctx;

    let storage = Arc::clone(&state.storage);
    let catalog_identities = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || storage.list_catalog_file_identities()),
    )
    .await
    .ok()
    .and_then(|res| res.ok())
    .and_then(Result::ok)
    .unwrap_or_default();

    let controller = global_mesh_dlp_controller();
    reconcile_discovered_cloud_drives(&controller, &discovered);

    let (settings, mesh_p2p_enabled) = {
        let guard = controller
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner());
        (guard.cloud_drives.clone(), guard.mesh.p2p_enabled)
    };

    let entries = merged_entries_in_order(&settings, &discovered);

    // Offload all filesystem / Session-1 bridge directory existence probes off the Tokio async
    // worker pool in one deduplicated blocking pass so slow virtual drives never starve HTTP handlers.
    let mut probe_paths: Vec<String> = Vec::new();
    let mut seen_probe_paths: HashSet<String> = HashSet::new();
    for entry in &entries {
        let disc_opt = discovered
            .iter()
            .find(|d| d.id.eq_ignore_ascii_case(&entry.id));
        let root_path = entry.root_path.clone().or_else(|| {
            disc_opt
                .and_then(|d| d.root_path.as_ref())
                .map(|p| p.to_string_lossy().to_string())
        });
        if let Some(rp) = root_path {
            if seen_probe_paths.insert(rp.clone()) {
                probe_paths.push(rp);
            }
        }
        for cp in &entry.custom_paths {
            if seen_probe_paths.insert(cp.clone()) {
                probe_paths.push(cp.clone());
            }
        }
    }
    let live_dir_map: std::collections::HashMap<String, bool> =
        tokio::task::spawn_blocking(move || {
            let mut map = std::collections::HashMap::with_capacity(probe_paths.len());
            for rp in probe_paths {
                let exists = dir_exists_live(Path::new(&rp));
                map.insert(rp, exists);
            }
            map
        })
        .await
        .unwrap_or_default();

    let mut drive_dtos = Vec::with_capacity(entries.len());
    let mut any_session_only = false;

    for entry in entries {
        let disc_opt = discovered
            .iter()
            .find(|d| d.id.eq_ignore_ascii_case(&entry.id));

        let detected_roots: Vec<String> = disc_opt
            .map(|d| {
                d.detected_roots
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();

        let root_path = entry.root_path.clone().or_else(|| {
            disc_opt
                .and_then(|d| d.root_path.as_ref())
                .map(|p| p.to_string_lossy().to_string())
        });

        let root_exists_on_disk = root_path
            .as_deref()
            .is_some_and(|rp| live_dir_map.get(rp).copied().unwrap_or(false));
        let custom_exists_on_disk = entry
            .custom_paths
            .iter()
            .any(|cp| live_dir_map.get(cp).copied().unwrap_or(false));

        let disc_mounted = disc_opt.is_some_and(|d| d.mounted) && root_exists_on_disk;
        let mounted = disc_mounted || root_exists_on_disk || custom_exists_on_disk;

        let disc_virtual = disc_opt.is_some_and(|d| d.virtual_drive)
            || matches!(
                entry.provider,
                CloudDriveProvider::GoogleDrive | CloudDriveProvider::Pcloud
            );

        let session_hint_match = session_hints
            .iter()
            .find(|h| h.provider_id.eq_ignore_ascii_case(&entry.id));
        let relay_match = relay_snapshot.as_ref().and_then(|snap| {
            snap.drives
                .iter()
                .find(|rd| rd.id.eq_ignore_ascii_case(&entry.id))
        });

        let hinted_root_for_timeout = root_path
            .as_deref()
            .or_else(|| session_hint_match.map(|h| h.root_path.as_str()));
        let root_timeout_msg = hinted_root_for_timeout
            .and_then(|rp| quorum_types::session_fs_bridge::drive_timeout_message(Path::new(rp)));

        let is_session_scoped = !mounted
            && root_timeout_msg.is_none()
            && allow_session_only_eval
            && (local_system || session_zero)
            && (session_hint_match.is_some() || relay_match.is_some());

        let (status, virtual_drive, session_only, session_guidance, final_root_path, detected) =
            if mounted {
                let effective_root = if root_exists_on_disk {
                    root_path
                } else {
                    None
                };
                (
                    CloudDriveMountStatus::Mounted,
                    disc_virtual && root_exists_on_disk,
                    false,
                    None,
                    effective_root,
                    true,
                )
            } else if let Some(busy_msg) = root_timeout_msg {
                let busy_root = root_path.or_else(|| session_hint_match.map(|h| h.root_path.clone()));
                (
                    CloudDriveMountStatus::Error,
                    disc_virtual,
                    false,
                    Some(busy_msg),
                    busy_root,
                    true,
                )
            } else if is_session_scoped {
                any_session_only = true;
                let hinted_root = root_path
                    .or_else(|| session_hint_match.map(|h| h.root_path.clone()))
                    .or_else(|| relay_match.map(|r| r.root_path.clone()));
                let guidance = if let Some(rd) = relay_match {
                    format!(
                        "Detected in your interactive Windows user session via quorum-desktop relay ({}). Because QuorumRAGDaemon runs as LocalSystem in Session 0, per-user virtual drive letters are not directly readable by the service; switch to Mirror mode or select a local folder.",
                        rd.root_path
                    )
                } else {
                    "Per-user virtual stream drive detected in an interactive Windows session while QuorumRAGDaemon runs as LocalSystem (Session 0). Switch the cloud client to Mirror mode, run `quorum-desktop.exe --cloud-drive-relay` in your user session, or add a local folder.".to_string()
                };
                (
                    CloudDriveMountStatus::SessionOnly,
                    true,
                    true,
                    Some(guidance),
                    hinted_root,
                    true,
                )
            } else if entry.enabled
                && root_path.is_some()
                && !root_exists_on_disk
                && !custom_exists_on_disk
            {
                (
                    CloudDriveMountStatus::Error,
                    disc_virtual,
                    false,
                    Some(
                        "Configured cloud drive path is currently unreachable on disk.".to_string(),
                    ),
                    root_path,
                    disc_opt.is_some_and(|d| d.detected),
                )
            } else {
                (
                    CloudDriveMountStatus::NotDetected,
                    disc_virtual,
                    false,
                    None,
                    None,
                    disc_opt.is_some_and(|d| d.detected),
                )
            };

        let active_prefixes = collect_drive_all_prefixes(&entry);
        let mut indexed_files = 0usize;
        let mut indexed_chunks = 0usize;
        if !active_prefixes.is_empty() {
            for ident in &catalog_identities {
                let matches_drive = active_prefixes
                    .iter()
                    .any(|pref| path_matches_prefix(&ident.file_path, pref).unwrap_or(false));
                if matches_drive {
                    indexed_files += 1;
                    indexed_chunks += ident.chunk_count as usize;
                }
            }
        }

        let effective_tier = AccessTier::from_u8(entry.access_tier)
            .map(|t| t.as_u8())
            .unwrap_or(AccessTier::Tier3Restricted.as_u8());

        let shared_with_mesh = mesh_p2p_enabled
            && effective_tier < AccessTier::Tier3Restricted.as_u8()
            && entry
                .root_path
                .iter()
                .chain(entry.custom_paths.iter())
                .any(|p| {
                    controller
                        .check_file_shared_with_mesh(p)
                        .is_some_and(|sf| sf.access_tier < AccessTier::Tier3Restricted.as_u8())
                });

        drive_dtos.push(CloudDriveStatusDto {
            id: entry.id,
            provider: entry.provider.as_str().to_string(),
            label: entry.label,
            account_kind: entry.account_kind,
            detected,
            mounted,
            status,
            status_label: status_label_for(status).to_string(),
            virtual_drive,
            session_only,
            session_guidance,
            enabled: entry.enabled,
            access_tier: effective_tier,
            shared_with_mesh,
            root_path: final_root_path,
            detected_roots,
            custom_paths: entry.custom_paths,
            indexed_files,
            indexed_chunks,
        });
    }

    let virtual_drive_guidance = if local_system {
        if quorum_types::session_fs_bridge::active_bridge_info().is_some() && !any_session_only {
            Some(
                "QuorumRAGDaemon is running as Windows LocalSystem (Session 0) with the automatic interactive user-session bridge connected. Both folder-backed syncs (OneDrive, Dropbox) and per-user virtual drives (Google Drive G:\\, pCloud P:\\) are directly mountable, selectable, and auto-indexed.".to_string(),
            )
        } else {
            Some(
                "QuorumRAGDaemon is running as Windows LocalSystem (Session 0). Folder-backed cloud syncs under C:\\Users\\* remain directly readable; per-user virtual stream drives (such as Google Drive G:\\) are bridged automatically when an interactive desktop user session is active, or can use Mirror mode / Select Folder.".to_string(),
            )
        }
    } else if any_session_only {
        Some(
            "One or more virtual cloud drives are active only in an interactive user session; switch to Mirror mode or run `quorum-desktop.exe --cloud-drive-relay`.".to_string(),
        )
    } else {
        None
    };

    let live_reindex_max = state
        .reindex_worker
        .config_snapshot()
        .await
        .max_file_size_bytes;
    let live_drift_max = state
        .drift_healer
        .config_snapshot()
        .await
        .max_file_size_bytes;
    let configured_cap_bytes = settings
        .hydration_max_file_size_mb
        .saturating_mul(1024 * 1024);
    let restart_required_for_cap_above_50mb = if settings.hydration_max_file_size_mb > 50
        && (live_reindex_max < configured_cap_bytes || live_drift_max < configured_cap_bytes)
    {
        Some(true)
    } else {
        None
    };

    CloudDrivesStatusResponse {
        placeholder_mode: settings.placeholder_mode,
        hydration_max_file_size_mb: settings.hydration_max_file_size_mb,
        running_as_local_system: local_system,
        virtual_drive_guidance,
        drives: drive_dtos,
        purged_files,
        purged_chunks,
        restart_required_for_cap_above_50mb,
    }
}

/// `GET /api/cloud-drives`
pub async fn get_cloud_drives_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let resp = build_cloud_drives_status_response(&state, None, None).await;
    Json(resp)
}

/// `POST /api/cloud-drives/config`
pub async fn update_cloud_drives_config_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<CloudDrivesConfigPayload>,
) -> Response {
    let _mutation_guard = cloud_drives_config_mutex().lock().await;

    let discovered = tokio::task::spawn_blocking(discover_cloud_drives)
        .await
        .unwrap_or_default();
    let controller = global_mesh_dlp_controller();
    reconcile_discovered_cloud_drives(&controller, &discovered);

    let current_settings = controller.get_cloud_drives_settings();

    let mut paths_to_purge: Vec<String> = Vec::new();
    let mut unwatch_only_prefixes: Vec<String> = Vec::new();
    let mut paths_to_watch: Vec<PathBuf> = Vec::new();
    let mut tier_syncs: Vec<(String, u8)> = Vec::new();
    let mut is_purge_action = false;

    let updated_settings = match payload.action.as_deref().map(|s| s.trim()) {
        Some("set_hydration") => {
            let mut next = current_settings.clone();
            if let Some(mode) = payload.placeholder_mode {
                next.placeholder_mode = mode;
            }
            if let Some(max_mb) = payload.hydration_max_file_size_mb {
                if let Err(msg) = validate_hydration_cap_mb(max_mb) {
                    return error_response(StatusCode::BAD_REQUEST, msg);
                }
                next.hydration_max_file_size_mb = max_mb;
            }
            if let Err(msg) = validate_hydration_cap_mb(next.hydration_max_file_size_mb) {
                return error_response(StatusCode::BAD_REQUEST, msg);
            }
            if let Err(e) = CloudPlaceholderPolicy::from_settings(
                next.placeholder_mode,
                next.hydration_max_file_size_mb,
            ) {
                return error_response(StatusCode::BAD_REQUEST, e.to_string());
            }
            let became_more_permissive = (next.placeholder_mode
                == CloudPlaceholderMode::HydrateOnDemand
                && current_settings.placeholder_mode != CloudPlaceholderMode::HydrateOnDemand)
                || (next.placeholder_mode == CloudPlaceholderMode::HydrateOnDemand
                    && next.hydration_max_file_size_mb
                        > current_settings.hydration_max_file_size_mb);
            if became_more_permissive {
                let disabled_now = collect_disabled_cloud_roots_for_settings(&next, &discovered, None);
                for drv in next.drives.iter().filter(|d| d.enabled) {
                    paths_to_watch.extend(collect_drive_existing_paths_excluding_disabled(
                        drv,
                        &disabled_now,
                    ));
                }
            }
            next
        }
        Some("toggle_drive") => {
            let Some(ref raw_id) = payload.id else {
                return error_response(StatusCode::BAD_REQUEST, "Missing drive 'id'");
            };
            let id_trimmed = raw_id.trim();
            if id_trimmed.is_empty() {
                return error_response(StatusCode::BAD_REQUEST, "Drive 'id' cannot be empty");
            }
            let mut next = current_settings.clone();
            let Some(idx) = next
                .drives
                .iter()
                .position(|d| d.id.eq_ignore_ascii_case(id_trimmed))
            else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("Unknown cloud drive id '{id_trimmed}'"),
                );
            };

            let prev = next.drives[idx].clone();
            let target_enabled = payload.enabled.unwrap_or_else(|| {
                if payload.access_tier.is_some() || payload.root_path.is_some() {
                    prev.enabled
                } else {
                    !prev.enabled
                }
            });

            if let Some(tier) = payload.access_tier {
                if let Err(e) = AccessTier::from_u8(tier) {
                    return error_response(StatusCode::BAD_REQUEST, e.to_string());
                }
                next.drives[idx].access_tier = tier;
            }

            if target_enabled {
                let other_disabled = collect_disabled_cloud_roots_for_settings(
                    &next,
                    &discovered,
                    Some(&next.drives[idx].id),
                );
                if let Some(ref raw_rp) = payload.root_path {
                    let valid_rp = match validate_cloud_drive_path(raw_rp) {
                        Ok(v) => v,
                        Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
                    };
                    let Some(clean_rp) = canonicalize_for_cloud_filter(Path::new(&valid_rp)) else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "Invalid, unsafe, or non-canonical cloud drive root_path",
                        );
                    };
                    if dir_exists_live(&clean_rp) {
                        if let Some(conflict_msg) =
                            check_cloud_drive_path_conflict(&clean_rp, &other_disabled)
                        {
                            return error_response(StatusCode::CONFLICT, conflict_msg);
                        }
                        next.drives[idx].root_path = Some(clean_rp.to_string_lossy().to_string());
                    } else {
                        // If the drive already has valid custom local folder(s) on disk, ignore
                        // a stale or session-only `root_path` hint (such as `G:\My Drive`) and
                        // allow enabling indexing on the configured local folder(s).
                        let has_existing_local = !collect_drive_existing_paths_excluding_disabled(
                            &next.drives[idx],
                            &other_disabled,
                        )
                        .is_empty();
                        if !has_existing_local {
                            let label = next.drives[idx].label.as_str();
                            let msg = if running_as_local_system()
                                && matches!(
                                    next.drives[idx].provider,
                                    CloudDriveProvider::GoogleDrive | CloudDriveProvider::Pcloud
                                ) {
                                format!(
                                    "{label} ({}) is not directly mounted in the Windows service session. Start {label} in Mirror mode or click Select Folder to pick a local sync folder.",
                                    clean_rp.display()
                                )
                            } else {
                                format!(
                                    "{label} sync folder is not mounted on disk ({}). Start {label} or click Select Folder to choose a local folder.",
                                    clean_rp.display()
                                )
                            };
                            return error_response(StatusCode::BAD_REQUEST, msg);
                        }
                    }
                }

                let existing = collect_drive_existing_paths_excluding_disabled(
                    &next.drives[idx],
                    &other_disabled,
                );
                if existing.is_empty() {
                    return error_response(
                        StatusCode::CONFLICT,
                        format!(
                            "Cannot enable {}: no mounted sync folder found on disk yet. Start {} or click Select Folder to choose a local folder.",
                            next.drives[idx].label, next.drives[idx].label
                        ),
                    );
                }
                next.drives[idx].enabled = true;
                if !prev.enabled {
                    for pref in collect_drive_all_prefixes(&next.drives[idx]) {
                        tier_syncs.push((pref, next.drives[idx].access_tier));
                    }
                    paths_to_watch.extend(existing);
                } else {
                    let old_norm_opt = prev
                        .root_path
                        .as_deref()
                        .and_then(|p| normalize_prefix_for_match(p).ok());
                    let new_norm_opt = next.drives[idx]
                        .root_path
                        .as_deref()
                        .and_then(|p| normalize_prefix_for_match(p).ok());
                    if old_norm_opt != new_norm_opt {
                        if let Some(old_norm) = old_norm_opt {
                            let mut surviving =
                                collect_active_prefixes_except(&next.drives, &next.drives[idx].id);
                            if let Some(ref nn) = new_norm_opt {
                                surviving.push(nn.clone());
                            }
                            for cp in &next.drives[idx].custom_paths {
                                if let Ok(cn) = normalize_prefix_for_match(cp) {
                                    surviving.push(cn);
                                }
                            }
                            if !is_prefix_protected(&old_norm, &surviving) {
                                paths_to_purge.push(old_norm);
                                is_purge_action = true;
                            } else if !is_prefix_covered_upward(&old_norm, &surviving) {
                                unwatch_only_prefixes.push(old_norm);
                            }
                        }
                        paths_to_watch.extend(existing);
                    }
                }
                if prev.access_tier != next.drives[idx].access_tier && prev.enabled {
                    for pref in collect_drive_all_prefixes(&next.drives[idx]) {
                        tier_syncs.push((pref, next.drives[idx].access_tier));
                    }
                }
            } else {
                // Disabling NEVER allows `payload.root_path` to overwrite `entry.root_path`
                // or inject an arbitrary path into `paths_to_purge`.
                is_purge_action = true;
                next.drives[idx].enabled = false;
                let other_active =
                    collect_active_prefixes_except(&next.drives, &next.drives[idx].id);
                for pref in collect_drive_all_prefixes(&prev) {
                    if !is_prefix_protected(&pref, &other_active) {
                        paths_to_purge.push(pref);
                    } else if !is_prefix_covered_upward(&pref, &other_active) {
                        unwatch_only_prefixes.push(pref);
                    }
                }
            }
            next
        }
        Some("set_tier") => {
            let Some(ref raw_id) = payload.id else {
                return error_response(StatusCode::BAD_REQUEST, "Missing drive 'id'");
            };
            let Some(tier) = payload.access_tier else {
                return error_response(StatusCode::BAD_REQUEST, "Missing 'access_tier'");
            };
            if let Err(e) = AccessTier::from_u8(tier) {
                return error_response(StatusCode::BAD_REQUEST, e.to_string());
            }
            let mut next = current_settings.clone();
            let Some(entry) = next
                .drives
                .iter_mut()
                .find(|d| d.id.eq_ignore_ascii_case(raw_id.trim()))
            else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("Unknown cloud drive id '{}'", raw_id.trim()),
                );
            };
            entry.access_tier = tier;
            if entry.enabled {
                for pref in collect_drive_all_prefixes(entry) {
                    tier_syncs.push((pref, tier));
                }
            }
            next
        }
        Some("set_root") | Some("select_root") => {
            let Some(ref raw_id) = payload.id else {
                return error_response(StatusCode::BAD_REQUEST, "Missing drive 'id'");
            };
            let Some(ref raw_rp) = payload.root_path.as_ref().or(payload.path.as_ref()) else {
                return error_response(StatusCode::BAD_REQUEST, "Missing 'root_path'");
            };
            let valid_rp = match validate_cloud_drive_path(raw_rp) {
                Ok(v) => v,
                Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
            };
            let Some(clean_rp) = canonicalize_for_cloud_filter(Path::new(&valid_rp)) else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid, unsafe, or non-canonical cloud drive root_path",
                );
            };
            let mut next = current_settings.clone();
            let Some(idx) = next
                .drives
                .iter()
                .position(|d| d.id.eq_ignore_ascii_case(raw_id.trim()))
            else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("Unknown cloud drive id '{}'", raw_id.trim()),
                );
            };
            if next.drives[idx].enabled && !dir_exists_live(&clean_rp) {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Cloud drive root_path does not exist on disk: {}",
                        clean_rp.display()
                    ),
                );
            }
            let other_disabled = collect_disabled_cloud_roots_for_settings(
                &next,
                &discovered,
                Some(&next.drives[idx].id),
            );
            if let Some(conflict_msg) = check_cloud_drive_path_conflict(&clean_rp, &other_disabled)
            {
                return error_response(StatusCode::CONFLICT, conflict_msg);
            }
            let clean_rp_str = clean_rp.to_string_lossy().to_string();
            let old_rp = next.drives[idx].root_path.clone();
            next.drives[idx].root_path = Some(clean_rp_str.clone());
            if next.drives[idx].enabled {
                if let Some(old) = old_rp {
                    if let (Ok(old_n), Ok(new_n)) = (
                        normalize_prefix_for_match(&old),
                        normalize_prefix_for_match(&clean_rp_str),
                    ) {
                        if old_n != new_n {
                            let mut surviving =
                                collect_active_prefixes_except(&next.drives, &next.drives[idx].id);
                            surviving.push(new_n);
                            for cp in &next.drives[idx].custom_paths {
                                if let Ok(cn) = normalize_prefix_for_match(cp) {
                                    surviving.push(cn);
                                }
                            }
                            if !is_prefix_protected(&old_n, &surviving) {
                                paths_to_purge.push(old_n);
                                is_purge_action = true;
                            } else if !is_prefix_covered_upward(&old_n, &surviving) {
                                unwatch_only_prefixes.push(old_n);
                            }
                        }
                    }
                }
                if dir_exists_live(&clean_rp) {
                    if let Ok(norm_new) = normalize_prefix_for_match(&clean_rp_str) {
                        tier_syncs.push((norm_new, next.drives[idx].access_tier));
                    }
                    paths_to_watch.push(clean_rp);
                }
            }
            next
        }
        Some("add_folder") => {
            let Some(ref raw_id) = payload.id else {
                return error_response(StatusCode::BAD_REQUEST, "Missing drive 'id'");
            };
            let Some(ref raw_path) = payload.path else {
                return error_response(StatusCode::BAD_REQUEST, "Missing folder 'path'");
            };
            let valid_path = match validate_cloud_drive_path(raw_path) {
                Ok(v) => v,
                Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
            };
            let Some(clean_p) = canonicalize_for_cloud_filter(Path::new(&valid_path)) else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid, unsafe, or non-canonical folder path",
                );
            };
            if !dir_exists_live(&clean_p) {
                if let Some(busy_msg) =
                    quorum_types::session_fs_bridge::drive_timeout_message(&clean_p)
                {
                    return error_response(StatusCode::GATEWAY_TIMEOUT, busy_msg);
                }
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Folder does not exist on disk: {}", clean_p.display()),
                );
            }
            let clean_str = clean_p.to_string_lossy().to_string();
            let norm_new = match normalize_prefix_for_match(&clean_str) {
                Ok(n) => n,
                Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
            };
            let mut next = current_settings.clone();
            let Some(idx) = next
                .drives
                .iter()
                .position(|d| d.id.eq_ignore_ascii_case(raw_id.trim()))
            else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("Unknown cloud drive id '{}'", raw_id.trim()),
                );
            };
            let disabled_for_add = collect_disabled_cloud_roots_for_settings(
                &next,
                &discovered,
                Some(next.drives[idx].id.as_str()),
            );
            if let Some(conflict_msg) = check_cloud_drive_path_conflict(&clean_p, &disabled_for_add)
            {
                return error_response(StatusCode::CONFLICT, conflict_msg);
            }
            let entry = &mut next.drives[idx];
            let already_present = entry.custom_paths.iter().any(|existing| {
                normalize_prefix_for_match(existing).ok().as_deref() == Some(norm_new.as_str())
            });
            if !already_present {
                entry.custom_paths.push(clean_str);
            }
            if payload.enabled == Some(true) && !entry.enabled {
                entry.enabled = true;
                for pref in collect_drive_all_prefixes(entry) {
                    tier_syncs.push((pref, entry.access_tier));
                }
                let all_existing =
                    collect_drive_existing_paths_excluding_disabled(entry, &disabled_for_add);
                paths_to_watch.extend(all_existing);
            } else if entry.enabled {
                tier_syncs.push((norm_new, entry.access_tier));
                paths_to_watch.push(clean_p);
            }
            next
        }
        Some("remove_folder") => {
            let Some(ref raw_id) = payload.id else {
                return error_response(StatusCode::BAD_REQUEST, "Missing drive 'id'");
            };
            let Some(ref raw_path) = payload.path else {
                return error_response(StatusCode::BAD_REQUEST, "Missing folder 'path'");
            };
            let valid_path = match validate_cloud_drive_path(raw_path) {
                Ok(v) => v,
                Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
            };
            let norm_target = match normalize_prefix_for_match(&valid_path) {
                Ok(n) => n,
                Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
            };
            let mut next = current_settings.clone();
            let Some(idx) = next
                .drives
                .iter()
                .position(|d| d.id.eq_ignore_ascii_case(raw_id.trim()))
            else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("Unknown cloud drive id '{}'", raw_id.trim()),
                );
            };
            let before_len = next.drives[idx].custom_paths.len();
            next.drives[idx].custom_paths.retain(|existing| {
                normalize_prefix_for_match(existing).ok().as_deref() != Some(norm_target.as_str())
            });
            let removed_custom = next.drives[idx].custom_paths.len() < before_len;
            let mut removed_root = false;
            if let Some(ref existing_root) = next.drives[idx].root_path {
                if normalize_prefix_for_match(existing_root).ok().as_deref()
                    == Some(norm_target.as_str())
                {
                    next.drives[idx].root_path = None;
                    removed_root = true;
                }
            }
            if !removed_custom && !removed_root {
                return error_response(
                    StatusCode::NOT_FOUND,
                    "Folder path is not configured on this cloud drive",
                );
            }
            if next.drives[idx].root_path.is_none() && next.drives[idx].custom_paths.is_empty() {
                next.drives[idx].enabled = false;
            }

            is_purge_action = true;
            let mut surviving = collect_active_prefixes_except(&next.drives, &next.drives[idx].id);
            if let Some(ref rp) = next.drives[idx].root_path {
                if let Ok(rn) = normalize_prefix_for_match(rp) {
                    surviving.push(rn);
                }
            }
            for cp in &next.drives[idx].custom_paths {
                if let Ok(cn) = normalize_prefix_for_match(cp) {
                    surviving.push(cn);
                }
            }

            if !is_prefix_protected(&norm_target, &surviving) {
                paths_to_purge.push(norm_target);
            } else if !is_prefix_covered_upward(&norm_target, &surviving) {
                // `norm_target` is an ancestor of an active surviving root/folder: do NOT purge
                // storage by prefix (which would wipe the active child!), only unwatch the
                // removed parent path and ensure active descendants stay watched.
                unwatch_only_prefixes.push(norm_target.clone());
                if next.drives[idx].enabled {
                    for raw_active in next.drives[idx]
                        .root_path
                        .iter()
                        .chain(next.drives[idx].custom_paths.iter())
                    {
                        if path_matches_prefix(raw_active, &norm_target).unwrap_or(false) {
                            let p = PathBuf::from(raw_active.trim());
                            if p.is_dir() && !paths_to_watch.contains(&p) {
                                paths_to_watch.push(p);
                            }
                        }
                    }
                }
            }
            next
        }
        Some(unknown) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("Unknown cloud-drives config action '{unknown}'"),
            );
        }
        None => {
            let Some(new_drive_inputs) = payload.drives else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Missing 'action' or 'drives' payload",
                );
            };
            let mut new_drives = Vec::with_capacity(new_drive_inputs.len());
            for inp in new_drive_inputs {
                match inp.into_config_entry() {
                    Ok(entry) => new_drives.push(entry),
                    Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
                }
            }
            let mut next = current_settings.clone();
            if let Some(mode) = payload.placeholder_mode {
                next.placeholder_mode = mode;
            }
            if let Some(max_mb) = payload.hydration_max_file_size_mb {
                if let Err(msg) = validate_hydration_cap_mb(max_mb) {
                    return error_response(StatusCode::BAD_REQUEST, msg);
                }
                next.hydration_max_file_size_mb = max_mb;
            }
            if let Err(msg) = validate_hydration_cap_mb(next.hydration_max_file_size_mb) {
                return error_response(StatusCode::BAD_REQUEST, msg);
            }
            if let Err(e) = CloudPlaceholderPolicy::from_settings(
                next.placeholder_mode,
                next.hydration_max_file_size_mb,
            ) {
                return error_response(StatusCode::BAD_REQUEST, e.to_string());
            }
            for drv in &mut new_drives {
                if let Err(e) = drv.validate() {
                    return error_response(StatusCode::BAD_REQUEST, e.to_string());
                }
                if let Some(ref mut rp) = drv.root_path {
                    let Some(clean_rp) = canonicalize_for_cloud_filter(Path::new(rp.trim())) else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            format!(
                                "Invalid, unsafe, or non-canonical root_path on '{}'",
                                drv.id
                            ),
                        );
                    };
                    *rp = clean_rp.to_string_lossy().to_string();
                }
                for cp in &mut drv.custom_paths {
                    let Some(clean_cp) = canonicalize_for_cloud_filter(Path::new(cp.trim())) else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            format!(
                                "Invalid, unsafe, or non-canonical custom_path on '{}'",
                                drv.id
                            ),
                        );
                    };
                    *cp = clean_cp.to_string_lossy().to_string();
                }
            }

            let mut candidate_settings = next.clone();
            candidate_settings.drives = new_drives.clone();

            for drv in &new_drives {
                let other_disabled = collect_disabled_cloud_roots_for_settings(
                    &candidate_settings,
                    &discovered,
                    Some(&drv.id),
                );
                if let Some(ref rp) = drv.root_path {
                    if let Some(conflict_msg) =
                        check_cloud_drive_path_conflict(Path::new(rp), &other_disabled)
                    {
                        return error_response(StatusCode::CONFLICT, conflict_msg);
                    }
                }
                for cp in &drv.custom_paths {
                    if let Some(conflict_msg) =
                        check_cloud_drive_path_conflict(Path::new(cp), &other_disabled)
                    {
                        return error_response(StatusCode::CONFLICT, conflict_msg);
                    }
                }
                if drv.enabled
                    && collect_drive_existing_paths_excluding_disabled(drv, &other_disabled)
                        .is_empty()
                {
                    return error_response(
                        StatusCode::CONFLICT,
                        format!(
                            "Cannot enable cloud drive '{}': no permitted mounted root path or existing custom folder found",
                            drv.id
                        ),
                    );
                }
            }

            let mut surviving_active = Vec::new();
            for drv in new_drives.iter().filter(|d| d.enabled) {
                surviving_active.extend(collect_drive_all_prefixes(drv));
            }

            for old_drv in &current_settings.drives {
                let new_match = new_drives
                    .iter()
                    .find(|d| d.id.eq_ignore_ascii_case(&old_drv.id));
                match new_match {
                    None => {
                        if old_drv.enabled {
                            is_purge_action = true;
                            for pref in collect_drive_all_prefixes(old_drv) {
                                if !is_prefix_protected(&pref, &surviving_active) {
                                    paths_to_purge.push(pref);
                                } else if !is_prefix_covered_upward(&pref, &surviving_active) {
                                    unwatch_only_prefixes.push(pref);
                                }
                            }
                        }
                    }
                    Some(new_drv) if old_drv.enabled && !new_drv.enabled => {
                        is_purge_action = true;
                        for pref in collect_drive_all_prefixes(old_drv) {
                            if !is_prefix_protected(&pref, &surviving_active) {
                                paths_to_purge.push(pref);
                            } else if !is_prefix_covered_upward(&pref, &surviving_active) {
                                unwatch_only_prefixes.push(pref);
                            }
                        }
                    }
                    Some(new_drv) if new_drv.enabled && !old_drv.enabled => {
                        let other_disabled = collect_disabled_cloud_roots_for_settings(
                            &candidate_settings,
                            &discovered,
                            Some(&new_drv.id),
                        );
                        paths_to_watch.extend(collect_drive_existing_paths_excluding_disabled(
                            new_drv,
                            &other_disabled,
                        ));
                    }
                    Some(new_drv) if new_drv.enabled => {
                        let other_disabled = collect_disabled_cloud_roots_for_settings(
                            &candidate_settings,
                            &discovered,
                            Some(&new_drv.id),
                        );
                        let old_prefs = collect_drive_all_prefixes(old_drv);
                        let new_prefs = collect_drive_all_prefixes(new_drv);
                        for old_p in &old_prefs {
                            if !new_prefs.contains(old_p) {
                                if !is_prefix_protected(old_p, &surviving_active) {
                                    paths_to_purge.push(old_p.clone());
                                    is_purge_action = true;
                                } else if !is_prefix_covered_upward(old_p, &surviving_active) {
                                    unwatch_only_prefixes.push(old_p.clone());
                                }
                            }
                        }
                        for raw_new in new_drv.root_path.iter().chain(new_drv.custom_paths.iter()) {
                            if let Ok(norm_new) = normalize_prefix_for_match(raw_new) {
                                if !old_prefs.contains(&norm_new) {
                                    let p = PathBuf::from(raw_new.trim());
                                    if dir_exists_live(&p) {
                                        push_watch_root_excluding_disabled(
                                            &p,
                                            &other_disabled,
                                            &mut paths_to_watch,
                                        );
                                    }
                                }
                            }
                        }
                        if old_drv.access_tier != new_drv.access_tier {
                            for pref in new_prefs {
                                tier_syncs.push((pref, new_drv.access_tier));
                            }
                        }
                    }
                    _ => {}
                }
            }
            for new_drv in &new_drives {
                if new_drv.enabled
                    && !current_settings
                        .drives
                        .iter()
                        .any(|d| d.id.eq_ignore_ascii_case(&new_drv.id))
                {
                    let other_disabled = collect_disabled_cloud_roots_for_settings(
                        &candidate_settings,
                        &discovered,
                        Some(&new_drv.id),
                    );
                    paths_to_watch.extend(collect_drive_existing_paths_excluding_disabled(
                        new_drv,
                        &other_disabled,
                    ));
                }
            }
            next.drives = new_drives;
            next
        }
    };

    if let Err(e) = controller.update_cloud_drives_settings(updated_settings) {
        return error_response(StatusCode::BAD_REQUEST, e.to_string());
    }

    if let Err(e) = state.sync_cloud_drives_config_to_workers().await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }

    if !unwatch_only_prefixes.is_empty() {
        let mut surviving_descendants: Vec<PathBuf> = Vec::new();
        let disabled_cloud_roots = collect_disabled_cloud_roots(&controller, &discovered);
        let enabled_cloud_paths =
            collect_enabled_cloud_paths_filtered(&controller, &disabled_cloud_roots);
        for pref in unwatch_only_prefixes {
            if let Err(e) = state.unwatch_exact_prefix(&pref).await {
                tracing::warn!(prefix = %pref, error = %e, "Failed to unwatch parent cloud drive prefix");
            }
            for sp in &enabled_cloud_paths {
                if path_matches_prefix(&sp.to_string_lossy(), &pref).unwrap_or(false)
                    && !surviving_descendants.contains(sp)
                {
                    surviving_descendants.push(sp.clone());
                }
            }
        }
        if !surviving_descendants.is_empty() {
            if let Some(watcher) = state.fs_watcher() {
                for sp in &surviving_descendants {
                    if !is_user_profile_root_dir(sp)
                        && !is_disabled_cloud_root(sp, &disabled_cloud_roots)
                        && !is_strict_ancestor_of_disabled_cloud_root(sp, &disabled_cloud_roots)
                    {
                        let _ = watcher.watch_path(sp);
                    }
                }
            }
            state.reindex_worker.add_watch_paths(&surviving_descendants);
            state.sync_drift_healer_watch_paths().await;
        }
    }

    let mut total_purged_files = 0usize;
    let mut total_purged_chunks = 0usize;
    let mut dedup_purged: HashSet<String> = HashSet::new();
    for pref in paths_to_purge {
        if !dedup_purged.insert(pref.clone()) {
            continue;
        }
        match state.unwatch_and_purge_prefix(&pref).await {
            Ok(rep) => {
                total_purged_files += rep.catalog_docs_deleted;
                total_purged_chunks += rep.lance_chunks_deleted.max(rep.tantivy_chunks_deleted);
            }
            Err(e) => {
                tracing::warn!(prefix = %pref, error = %e, "Failed to purge cloud drive prefix");
            }
        }
    }

    for (pref, new_tier) in tier_syncs {
        if let Err(e) = state.sync_cloud_drive_tier_prefix(&pref, new_tier).await {
            tracing::warn!(
                prefix = %pref,
                new_tier,
                error = %e,
                "Failed to sync cloud drive tier across storage"
            );
        }
    }

    if !paths_to_watch.is_empty() {
        let _ = state.watch_and_index_paths(paths_to_watch).await;
    }

    let resp = build_cloud_drives_status_response(
        &state,
        if is_purge_action {
            Some(total_purged_files)
        } else {
            None
        },
        if is_purge_action {
            Some(total_purged_chunks)
        } else {
            None
        },
    )
    .await;
    Json(resp).into_response()
}

/// `POST /api/cloud-drives/reindex`
pub async fn reindex_cloud_drive_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<CloudDrivesReindexPayload>,
) -> Response {
    let id_trimmed = payload.id.trim();
    if id_trimmed.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Drive 'id' cannot be empty");
    }

    let discovered = tokio::task::spawn_blocking(discover_cloud_drives)
        .await
        .unwrap_or_default();
    let controller = global_mesh_dlp_controller();
    reconcile_discovered_cloud_drives(&controller, &discovered);

    let settings = controller.get_cloud_drives_settings();
    let Some(entry) = settings
        .drives
        .iter()
        .find(|d| d.id.eq_ignore_ascii_case(id_trimmed))
    else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("Unknown cloud drive id '{id_trimmed}'"),
        );
    };

    if !entry.enabled {
        return error_response(
            StatusCode::CONFLICT,
            format!(
                "Cloud drive '{}' is disabled; enable it before reindexing",
                entry.id
            ),
        );
    }

    let other_disabled =
        collect_disabled_cloud_roots_for_settings(&settings, &discovered, Some(&entry.id));
    let paths = collect_drive_existing_paths_excluding_disabled(entry, &other_disabled);
    if paths.is_empty() {
        return error_response(
            StatusCode::CONFLICT,
            format!(
                "Cloud drive '{}' has no mounted root or existing local folder to reindex",
                entry.id
            ),
        );
    }

    if let Err(e) = state.sync_cloud_drives_config_to_workers().await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }

    let triggered_strings: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let wants_full_or_reembed =
        payload.full_rebuild.unwrap_or(false) || payload.force_reembed.unwrap_or(false);
    let task_id = if wants_full_or_reembed {
        if let Some(watcher) = state.fs_watcher() {
            for p in &paths {
                let _ = watcher.watch_path(p);
            }
        }
        state.reindex_worker.add_watch_paths(&paths);
        state.sync_drift_healer_watch_paths().await;
        let opts = quorum_ingest::ReindexOptions {
            target_paths: paths.clone(),
            full_rebuild: payload.full_rebuild.unwrap_or(false),
            force_reembed: payload.force_reembed.unwrap_or(false),
            batch_size: payload.batch_size.unwrap_or(64),
            num_threads: 0,
            dry_run: false,
        };
        match state.reindex_worker.start_reindex(opts).await {
            Ok(tid) => Some(tid),
            Err(quorum_ingest::IngestError::TaskAlreadyRunning(_)) => {
                state.reindex_worker.trigger_paths(paths).await.ok()
            }
            Err(e) => {
                return error_response(
                    StatusCode::CONFLICT,
                    format!("Failed to start cloud drive reindex: {e}"),
                );
            }
        }
    } else {
        state.watch_and_index_paths(paths).await
    };

    let Some(task_id) = task_id else {
        return error_response(
            StatusCode::CONFLICT,
            format!(
                "Unable to dispatch reindex for cloud drive '{}': no permitted mounted paths available",
                entry.id
            ),
        );
    };

    Json(serde_json::json!({
        "ok": true,
        "status": "started",
        "id": entry.id,
        "task_id": task_id,
        "triggered_paths": triggered_strings,
    }))
    .into_response()
}

/// `POST /api/cloud-drives/relay/register`
///
/// Loopback-only endpoint invoked by `quorum-desktop.exe --cloud-drive-relay` from an
/// interactive user session so Session-0 `LocalSystem` services can surface session-scoped
/// virtual drives with clear status guidance.
pub async fn register_relay_handler(
    State(state): State<Arc<DaemonState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(payload): Json<RegisterRelayPayload>,
) -> Response {
    let is_loopback = connect
        .map(|ConnectInfo(addr)| addr.ip().is_loopback())
        .unwrap_or(true);
    if !is_loopback {
        return error_response(
            StatusCode::FORBIDDEN,
            "Cloud drive relay registration is only permitted from loopback 127.0.0.1",
        );
    }

    let mut validated_drives = Vec::with_capacity(payload.drives.len());
    for mut d in payload.drives {
        if d.id.trim().is_empty() {
            return error_response(StatusCode::BAD_REQUEST, "Relayed drive id cannot be empty");
        }
        match validate_cloud_drive_path(&d.root_path) {
            Ok(valid) => {
                d.root_path = valid;
                validated_drives.push(d);
            }
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, e.to_string());
            }
        }
    }

    if is_test_profile_override_active() {
        return error_response(
            StatusCode::FORBIDDEN,
            "Host cloud drive relay registration is disabled under QUORUM_CLOUD_TEST_PROFILE_DIR",
        );
    }

    let count = validated_drives.len();
    state.set_cloud_drive_relay(payload.session_id, validated_drives);

    Json(serde_json::json!({
        "ok": true,
        "registered": count,
        "session_id": payload.session_id,
    }))
    .into_response()
}
