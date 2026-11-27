//! Cross-OS Cloud Drive Auto-Discovery and Files-On-Demand Placeholder Protection.
//!
//! Covers all 8 supported cloud storage providers (`GoogleDrive`, `OneDrive` Personal & Business,
//! `Dropbox`, `IcloudDrive`, `Box`, `Nextcloud`, `ProtonDrive`, `Pcloud`) across Windows, macOS,
//! and Linux. All discovered cloud drive entries default strictly to `enabled = false` (opt-in)
//! and `access_tier = 3` (`Tier3Restricted` / local-only).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use quorum_types::{
    validate_cloud_drive_path, AccessTier, CloudDriveConfigEntry, CloudDriveProvider,
    CloudDrivesSettings, CloudPlaceholderMode, CloudPlaceholderPolicy,
    DEFAULT_HYDRATION_MAX_FILE_SIZE_MB,
};

// ---------------------------------------------------------------------------
// Files-On-Demand Placeholder Constants & Guards (F9 & F10)
// ---------------------------------------------------------------------------

/// Win32 file attribute indicating file data is offline / dehydrated.
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
/// Win32 file attribute indicating Cloud Filter recall-on-open stub.
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
/// Win32 file attribute indicating Cloud Filter recall-on-data-access stub.
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// Combined Win32 mask for cloud-only placeholder files.
pub const WINDOWS_CLOUD_PLACEHOLDER_MASK: u32 =
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN;

/// macOS `st_flags` bit (`SF_DATALESS` from `<sys/stat.h>` / APFS FileProvider).
pub const MACOS_SF_DATALESS: u32 = 0x4000_0000;

/// Pure platform-agnostic check for Windows cloud-placeholder `dwFileAttributes`.
#[inline]
pub const fn is_windows_cloud_placeholder_attrs(file_attributes: u32) -> bool {
    (file_attributes & WINDOWS_CLOUD_PLACEHOLDER_MASK) != 0
}

/// Pure platform-agnostic check for macOS APFS `st_flags` `SF_DATALESS`.
#[inline]
pub const fn is_macos_cloud_placeholder_flags(st_flags: u32) -> bool {
    (st_flags & MACOS_SF_DATALESS) != 0
}

/// Pure policy decision determining whether a file should be skipped without opening.
#[inline]
pub const fn should_skip_cloud_placeholder(
    is_placeholder: bool,
    size_bytes: u64,
    policy: CloudPlaceholderPolicy,
) -> bool {
    if !is_placeholder {
        return false;
    }
    match policy {
        CloudPlaceholderPolicy::LocallySyncedOnly => true,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes,
        } => size_bytes > max_file_size_bytes,
    }
}

/// Inspects `std::fs::Metadata` without opening the file data stream.
pub fn is_cloud_placeholder_metadata(metadata: &std::fs::Metadata) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        is_windows_cloud_placeholder_attrs(metadata.file_attributes())
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        is_macos_cloud_placeholder_flags(metadata.st_flags())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = metadata;
        false
    }
}

/// Fail-closed pre-open guard for secondary file-open sites.
///
/// Uses `std::io::ErrorKind::WouldBlock` so `DocumentExtractor::extract_text` does NOT
/// misclassify a skipped cloud placeholder as an exclusive lock / permission error.
pub fn ensure_open_allowed_for_placeholder(
    path: &Path,
    policy: CloudPlaceholderPolicy,
) -> std::io::Result<()> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if should_skip_cloud_placeholder(
                is_cloud_placeholder_metadata(&meta),
                meta.len(),
                policy,
            ) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    format!(
                        "Skipped cloud placeholder '{}' (size={} bytes) under {:?}",
                        path.display(),
                        meta.len(),
                        policy
                    ),
                ));
            }
            Ok(())
        }
        Err(local_err) => {
            if let Some(st) = quorum_types::session_fs_bridge::stat_via_bridge(path) {
                if !st.exists {
                    return Err(local_err);
                }
                if should_skip_cloud_placeholder(st.is_placeholder, st.len, policy) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        format!(
                            "Skipped bridged cloud placeholder '{}' (size={} bytes) under {:?}",
                            path.display(),
                            st.len,
                            policy
                        ),
                    ));
                }
                return Ok(());
            }
            Err(local_err)
        }
    }
}

/// Reads all bytes of `path` only after passing `ensure_open_allowed_for_placeholder`.
pub fn read_bytes_with_placeholder_policy(
    path: &Path,
    policy: CloudPlaceholderPolicy,
) -> std::io::Result<Vec<u8>> {
    ensure_open_allowed_for_placeholder(path, policy)?;
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(local_err) => quorum_types::session_fs_bridge::read_bytes_via_bridge(path, 0, policy)
            .map_err(|_| local_err),
    }
}

// ---------------------------------------------------------------------------
// Cross-OS Cloud Drive Discovery (F1–F7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    Windows,
    MacOs,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsDriveMount {
    pub letter: char,
    pub root: PathBuf,
    pub volume_label: String,
    pub is_virtual: bool,
    pub nt_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySyncRoot {
    pub provider: CloudDriveProvider,
    pub account_kind: Option<String>,
    pub root_path: PathBuf,
    pub label_hint: Option<String>,
}

/// Injectable OS abstraction enabling deterministic cross-OS discovery testing.
pub trait CloudDiscoveryEnv: Send + Sync {
    fn target_os(&self) -> TargetOs;
    fn user_profiles(&self) -> Vec<PathBuf>;
    fn env_var(&self, key: &str) -> Option<String>;
    fn dir_exists(&self, path: &Path) -> bool;
    fn file_exists(&self, path: &Path) -> bool;
    fn read_dir_names(&self, path: &Path) -> Vec<String>;
    fn read_to_string(&self, path: &Path) -> Option<String>;
    fn windows_drive_mounts(&self) -> Vec<WindowsDriveMount>;
    fn windows_registry_sync_roots(&self) -> Vec<RegistrySyncRoot>;
    fn is_virtual_mount(&self, path: &Path) -> bool;
    fn is_test_profile_override(&self) -> bool {
        false
    }
}

/// Discovered local sync root state for a cloud drive entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredCloudDrive {
    pub id: String,
    pub provider: CloudDriveProvider,
    pub label: String,
    pub account_kind: Option<String>,
    pub detected: bool,
    pub mounted: bool,
    pub virtual_drive: bool,
    pub root_path: Option<PathBuf>,
    pub detected_roots: Vec<PathBuf>,
}

/// Live OS implementation of `CloudDiscoveryEnv`.
pub struct LiveCloudDiscoveryEnv;

impl LiveCloudDiscoveryEnv {
    fn test_profile_dir_override() -> Option<PathBuf> {
        std::env::var("QUORUM_CLOUD_TEST_PROFILE_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    }
}

impl CloudDiscoveryEnv for LiveCloudDiscoveryEnv {
    fn target_os(&self) -> TargetOs {
        #[cfg(target_os = "windows")]
        {
            TargetOs::Windows
        }
        #[cfg(target_os = "macos")]
        {
            TargetOs::MacOs
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            TargetOs::Linux
        }
    }

    fn user_profiles(&self) -> Vec<PathBuf> {
        if let Some(test_dir) = Self::test_profile_dir_override() {
            return vec![test_dir];
        }
        #[cfg(target_os = "windows")]
        {
            crate::config::IngestConfig::discover_user_profile_dirs()
        }
        #[cfg(not(target_os = "windows"))]
        {
            let mut profiles = Vec::new();
            if let Ok(home) = std::env::var("HOME") {
                let p = PathBuf::from(home);
                if p.is_dir() {
                    profiles.push(p);
                }
            }
            let base = if cfg!(target_os = "macos") {
                Path::new("/Users")
            } else {
                Path::new("/home")
            };
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') || name == "Shared" || name == "lost+found" {
                        continue;
                    }
                    if p.is_dir() && !profiles.contains(&p) {
                        profiles.push(p);
                    }
                }
            }
            profiles
        }
    }

    fn env_var(&self, key: &str) -> Option<String> {
        let val = std::env::var(key).ok().filter(|v| !v.trim().is_empty())?;
        if let Some(test_dir) = Self::test_profile_dir_override() {
            if matches!(
                key,
                "OneDrive"
                    | "OneDriveConsumer"
                    | "OneDriveCommercial"
                    | "XDG_CONFIG_HOME"
                    | "APPDATA"
                    | "LOCALAPPDATA"
                    | "HOME"
            ) {
                if !crate::config::path_matches_prefix(Path::new(&val), &test_dir) {
                    return None;
                }
            }
        }
        Some(val)
    }

    fn dir_exists(&self, path: &Path) -> bool {
        if let Some(test_dir) = Self::test_profile_dir_override() {
            if !crate::config::path_matches_prefix(path, &test_dir) {
                return false;
            }
            return path.is_dir() && std::fs::read_dir(path).is_ok();
        }
        match quorum_types::session_fs_bridge::local_is_dir_bounded(
            path,
            true,
            std::time::Duration::from_millis(4500),
        ) {
            Ok(true) => return true,
            Err(_) => return false,
            Ok(false) => {}
        }
        quorum_types::session_fs_bridge::stat_via_bridge(path)
            .is_some_and(|st| st.exists && st.is_dir)
    }

    fn file_exists(&self, path: &Path) -> bool {
        if let Some(test_dir) = Self::test_profile_dir_override() {
            if !crate::config::path_matches_prefix(path, &test_dir) {
                return false;
            }
            return path.is_file();
        }
        match quorum_types::session_fs_bridge::local_is_file_bounded(
            path,
            std::time::Duration::from_millis(2000),
        ) {
            Ok(true) => return true,
            Err(_) => return false,
            Ok(false) => {}
        }
        quorum_types::session_fs_bridge::stat_via_bridge(path)
            .is_some_and(|st| st.exists && st.is_file)
    }

    fn read_dir_names(&self, path: &Path) -> Vec<String> {
        if let Some(test_dir) = Self::test_profile_dir_override() {
            if !crate::config::path_matches_prefix(path, &test_dir) {
                return Vec::new();
            }
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }

    fn read_to_string(&self, path: &Path) -> Option<String> {
        if let Some(test_dir) = Self::test_profile_dir_override() {
            if !crate::config::path_matches_prefix(path, &test_dir) {
                return None;
            }
        }
        std::fs::read_to_string(path).ok()
    }

    fn windows_drive_mounts(&self) -> Vec<WindowsDriveMount> {
        if Self::test_profile_dir_override().is_some() {
            return Vec::new();
        }
        #[cfg(target_os = "windows")]
        {
            live_windows_drive_mounts()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }

    fn windows_registry_sync_roots(&self) -> Vec<RegistrySyncRoot> {
        if Self::test_profile_dir_override().is_some() {
            return Vec::new();
        }
        #[cfg(target_os = "windows")]
        {
            live_windows_registry_sync_roots()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }

    fn is_virtual_mount(&self, path: &Path) -> bool {
        if Self::test_profile_dir_override().is_some() {
            return false;
        }
        #[cfg(target_os = "windows")]
        {
            let s = path.to_string_lossy();
            let b = s.as_bytes();
            if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                let letter = (b[0] as char).to_ascii_uppercase();
                return self
                    .windows_drive_mounts()
                    .into_iter()
                    .find(|m| m.letter.to_ascii_uppercase() == letter)
                    .map(|m| m.is_virtual)
                    .unwrap_or(false);
            }
            false
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = path;
            false
        }
    }

    fn is_test_profile_override(&self) -> bool {
        Self::test_profile_dir_override().is_some()
    }
}

/// Discovers local sync roots for all 8 cloud storage providers using the live OS environment.
pub fn discover_cloud_drives() -> Vec<DiscoveredCloudDrive> {
    discover_cloud_drives_with_env(&LiveCloudDiscoveryEnv)
}

/// Discovers local sync roots across all 8 providers using an injectable `CloudDiscoveryEnv`.
pub fn discover_cloud_drives_with_env(env: &dyn CloudDiscoveryEnv) -> Vec<DiscoveredCloudDrive> {
    let os = env.target_os();
    let profiles = env.user_profiles();
    let win_mounts = if os == TargetOs::Windows {
        env.windows_drive_mounts()
    } else {
        Vec::new()
    };
    let reg_roots = if os == TargetOs::Windows {
        env.windows_registry_sync_roots()
    } else {
        Vec::new()
    };

    let mut google_roots = Vec::new();
    let mut google_virtual = false;
    let mut onedrive_personal_roots = Vec::new();
    let mut onedrive_business_roots = Vec::new();
    let mut dropbox_roots = Vec::new();
    let mut icloud_roots = Vec::new();
    let mut box_roots = Vec::new();
    let mut nextcloud_roots = Vec::new();
    let mut proton_roots = Vec::new();
    let mut pcloud_roots = Vec::new();
    let mut pcloud_virtual = false;

    let try_add_dir = |candidate: PathBuf, out: &mut Vec<PathBuf>| {
        let cleaned = clean_verbatim_path(&candidate);
        let raw = cleaned.to_string_lossy();
        if validate_cloud_drive_path(&raw).is_err() {
            return;
        }
        if env.dir_exists(&cleaned) && !contains_normalized(out, &cleaned) {
            out.push(cleaned);
        }
    };

    // --- Windows Drive Mounts (Google Drive Stream G:\, pCloud virtual drive) & Registry ---
    if os == TargetOs::Windows {
        for mount in &win_mounts {
            let lbl = mount.volume_label.to_ascii_lowercase();
            let nt = mount.nt_target.to_ascii_lowercase();
            if lbl.contains("google drive")
                || nt.contains("googledrivefs")
                || nt.contains("drivefs")
            {
                let my_drive = mount.root.join("My Drive");
                let shared_drives = mount.root.join("Shared drives");
                let before = google_roots.len();
                try_add_dir(my_drive, &mut google_roots);
                try_add_dir(shared_drives, &mut google_roots);
                if google_roots.len() == before {
                    try_add_dir(mount.root.clone(), &mut google_roots);
                }
                if google_roots.len() > before && mount.is_virtual {
                    google_virtual = true;
                }
            } else {
                // Check for Google Drive signature subfolders on virtual/non-C drives (both Stream and Mirror on D:\My Drive etc.)
                if mount.letter.to_ascii_uppercase() != 'C' {
                    let my_drive = mount.root.join("My Drive");
                    if env.dir_exists(&my_drive) {
                        try_add_dir(my_drive, &mut google_roots);
                        try_add_dir(mount.root.join("Shared drives"), &mut google_roots);
                        if mount.is_virtual {
                            google_virtual = true;
                        }
                    } else if !mount.is_virtual {
                        let gdrive_dir = mount.root.join("Google Drive");
                        if env.dir_exists(&gdrive_dir) {
                            try_add_dir(gdrive_dir, &mut google_roots);
                        }
                    }
                }
            }

            if lbl.contains("pcloud") || nt.contains("pcloud") {
                let before = pcloud_roots.len();
                try_add_dir(mount.root.clone(), &mut pcloud_roots);
                if pcloud_roots.len() > before && mount.is_virtual {
                    pcloud_virtual = true;
                }
            }
        }

        for reg in &reg_roots {
            match reg.provider {
                CloudDriveProvider::GoogleDrive => {
                    let is_virt = env.is_virtual_mount(&reg.root_path);
                    let before = google_roots.len();
                    try_add_dir(reg.root_path.clone(), &mut google_roots);
                    if google_roots.len() > before && is_virt {
                        google_virtual = true;
                    }
                }
                CloudDriveProvider::OneDrive => {
                    if reg.account_kind.as_deref() == Some("business") {
                        try_add_dir(reg.root_path.clone(), &mut onedrive_business_roots);
                    } else {
                        try_add_dir(reg.root_path.clone(), &mut onedrive_personal_roots);
                    }
                }
                CloudDriveProvider::IcloudDrive => {
                    try_add_dir(reg.root_path.clone(), &mut icloud_roots);
                }
                CloudDriveProvider::Box => {
                    try_add_dir(reg.root_path.clone(), &mut box_roots);
                }
                CloudDriveProvider::Pcloud => {
                    let is_virt = env.is_virtual_mount(&reg.root_path);
                    let before = pcloud_roots.len();
                    try_add_dir(reg.root_path.clone(), &mut pcloud_roots);
                    if pcloud_roots.len() > before && is_virt {
                        pcloud_virtual = true;
                    }
                }
                _ => {}
            }
        }

        if let Some(p) = env
            .env_var("OneDriveConsumer")
            .or_else(|| env.env_var("OneDrive"))
        {
            let pb = PathBuf::from(&p);
            let name_l = pb
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if name_l.starts_with("onedrive -") && name_l != "onedrive - personal" {
                try_add_dir(pb, &mut onedrive_business_roots);
            } else {
                try_add_dir(pb, &mut onedrive_personal_roots);
            }
        }
        if let Some(p) = env.env_var("OneDriveCommercial") {
            try_add_dir(PathBuf::from(p), &mut onedrive_business_roots);
        }
    }

    // --- Per-Profile Discovery across Windows / macOS / Linux ---
    for profile in &profiles {
        match os {
            TargetOs::Windows => {
                // F1: Google Drive Mirror mode
                try_add_dir(profile.join("My Drive"), &mut google_roots);
                try_add_dir(profile.join("Google Drive"), &mut google_roots);

                // F2: OneDrive Personal & Business
                try_add_dir(profile.join("OneDrive"), &mut onedrive_personal_roots);
                try_add_dir(
                    profile.join("OneDrive - Personal"),
                    &mut onedrive_personal_roots,
                );
                for name in env.read_dir_names(profile) {
                    let lower = name.to_ascii_lowercase();
                    if lower.starts_with("onedrive -") && lower != "onedrive - personal" {
                        try_add_dir(profile.join(&name), &mut onedrive_business_roots);
                    }
                }

                // F3: Dropbox info.json + folders
                for cfg_rel in [
                    r"AppData\Local\Dropbox\info.json",
                    r"AppData\Roaming\Dropbox\info.json",
                ] {
                    let cfg_path = profile.join(cfg_rel);
                    if env.file_exists(&cfg_path) {
                        if let Some(raw) = env.read_to_string(&cfg_path) {
                            for p in parse_dropbox_info_json(&raw) {
                                try_add_dir(p, &mut dropbox_roots);
                            }
                        }
                    }
                }
                try_add_dir(profile.join("Dropbox"), &mut dropbox_roots);
                for name in env.read_dir_names(profile) {
                    if name.to_ascii_lowercase().starts_with("dropbox (") {
                        try_add_dir(profile.join(&name), &mut dropbox_roots);
                    }
                }

                // F4: iCloud Drive
                try_add_dir(profile.join("iCloudDrive"), &mut icloud_roots);
                try_add_dir(profile.join("iCloud Drive"), &mut icloud_roots);

                // F5: Box
                try_add_dir(profile.join("Box"), &mut box_roots);
                try_add_dir(profile.join("Box Sync"), &mut box_roots);

                // F6: Nextcloud config + folders
                for cfg_rel in [
                    r"AppData\Roaming\Nextcloud\nextcloud.cfg",
                    r"AppData\Local\Nextcloud\nextcloud.cfg",
                ] {
                    let cfg_path = profile.join(cfg_rel);
                    if env.file_exists(&cfg_path) {
                        if let Some(raw) = env.read_to_string(&cfg_path) {
                            for p in parse_nextcloud_cfg(&raw) {
                                try_add_dir(p, &mut nextcloud_roots);
                            }
                        }
                    }
                }
                try_add_dir(profile.join("Nextcloud"), &mut nextcloud_roots);
                for name in env.read_dir_names(profile) {
                    let lower = name.to_ascii_lowercase();
                    if lower.starts_with("nextcloud") && lower != "nextcloud" {
                        try_add_dir(profile.join(&name), &mut nextcloud_roots);
                    }
                }

                // F7: Proton Drive & pCloud
                try_add_dir(profile.join("Proton Drive"), &mut proton_roots);
                try_add_dir(profile.join("ProtonDrive"), &mut proton_roots);
                try_add_dir(profile.join("pCloud Drive"), &mut pcloud_roots);
                try_add_dir(profile.join("pCloudDrive"), &mut pcloud_roots);
                try_add_dir(profile.join("pCloud Sync"), &mut pcloud_roots);
            }
            TargetOs::MacOs => {
                let cloud_storage = profile.join("Library").join("CloudStorage");
                for name in env.read_dir_names(&cloud_storage) {
                    let lower = name.to_ascii_lowercase();
                    let full = cloud_storage.join(&name);
                    if lower.starts_with("googledrive-") {
                        let my_drive = full.join("My Drive");
                        if env.dir_exists(&my_drive) {
                            try_add_dir(my_drive, &mut google_roots);
                        } else {
                            try_add_dir(full, &mut google_roots);
                        }
                    } else if lower == "onedrive-personal" || lower == "onedrive - personal" {
                        try_add_dir(full, &mut onedrive_personal_roots);
                    } else if lower.starts_with("onedrive-") || lower.starts_with("onedrive -") {
                        try_add_dir(full, &mut onedrive_business_roots);
                    } else if lower == "dropbox" || lower.starts_with("dropbox-") {
                        try_add_dir(full, &mut dropbox_roots);
                    } else if lower == "icloud drive" || lower.starts_with("iclouddrive") {
                        try_add_dir(full, &mut icloud_roots);
                    } else if lower == "box-box" || lower.starts_with("box-") {
                        try_add_dir(full, &mut box_roots);
                    } else if lower.starts_with("nextcloud") {
                        try_add_dir(full, &mut nextcloud_roots);
                    } else if lower.starts_with("protondrive") {
                        try_add_dir(full, &mut proton_roots);
                    } else if lower.starts_with("pcloud") {
                        try_add_dir(full, &mut pcloud_roots);
                    }
                }

                // Classic / direct paths on macOS
                try_add_dir(profile.join("Google Drive"), &mut google_roots);
                try_add_dir(profile.join("My Drive"), &mut google_roots);
                try_add_dir(profile.join("OneDrive"), &mut onedrive_personal_roots);
                try_add_dir(
                    profile.join("OneDrive - Personal"),
                    &mut onedrive_personal_roots,
                );
                for name in env.read_dir_names(profile) {
                    let lower = name.to_ascii_lowercase();
                    if lower.starts_with("onedrive -") && lower != "onedrive - personal" {
                        try_add_dir(profile.join(&name), &mut onedrive_business_roots);
                    }
                }

                let dropbox_cfg = profile.join(".dropbox").join("info.json");
                if env.file_exists(&dropbox_cfg) {
                    if let Some(raw) = env.read_to_string(&dropbox_cfg) {
                        for p in parse_dropbox_info_json(&raw) {
                            try_add_dir(p, &mut dropbox_roots);
                        }
                    }
                }
                try_add_dir(profile.join("Dropbox"), &mut dropbox_roots);

                try_add_dir(
                    profile
                        .join("Library")
                        .join("Mobile Documents")
                        .join("com~apple~CloudDocs"),
                    &mut icloud_roots,
                );

                try_add_dir(profile.join("Box"), &mut box_roots);
                try_add_dir(profile.join("Box Sync"), &mut box_roots);

                let nc_cfg = profile
                    .join("Library")
                    .join("Preferences")
                    .join("Nextcloud")
                    .join("nextcloud.cfg");
                if env.file_exists(&nc_cfg) {
                    if let Some(raw) = env.read_to_string(&nc_cfg) {
                        for p in parse_nextcloud_cfg(&raw) {
                            try_add_dir(p, &mut nextcloud_roots);
                        }
                    }
                }
                try_add_dir(profile.join("Nextcloud"), &mut nextcloud_roots);

                try_add_dir(profile.join("Proton Drive"), &mut proton_roots);
                try_add_dir(profile.join("pCloud Drive"), &mut pcloud_roots);
                if !env.is_test_profile_override() {
                    try_add_dir(PathBuf::from("/Volumes/pCloud Drive"), &mut pcloud_roots);
                }
            }
            TargetOs::Linux => {
                // F1: Google Drive
                try_add_dir(profile.join("Google Drive"), &mut google_roots);
                try_add_dir(profile.join("My Drive"), &mut google_roots);
                try_add_dir(profile.join("GoogleDrive"), &mut google_roots);
                try_add_dir(profile.join("google-drive"), &mut google_roots);

                // F2: OneDrive Personal & Business
                try_add_dir(profile.join("OneDrive"), &mut onedrive_personal_roots);
                try_add_dir(
                    profile.join("OneDrive - Personal"),
                    &mut onedrive_personal_roots,
                );
                for name in env.read_dir_names(profile) {
                    let lower = name.to_ascii_lowercase();
                    if (lower.starts_with("onedrive -") && lower != "onedrive - personal")
                        || lower.starts_with("onedrive-business")
                    {
                        try_add_dir(profile.join(&name), &mut onedrive_business_roots);
                    }
                }
                let od_cfg = profile.join(".config").join("onedrive").join("config");
                if env.file_exists(&od_cfg) {
                    if let Some(raw) = env.read_to_string(&od_cfg) {
                        for p in parse_linux_onedrive_cfg(&raw) {
                            let name_l = p
                                .file_name()
                                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                                .unwrap_or_default();
                            if (name_l.starts_with("onedrive -") && name_l != "onedrive - personal")
                                || name_l.starts_with("onedrive-business")
                                || (name_l.starts_with("onedrive-")
                                    && name_l != "onedrive-personal")
                            {
                                try_add_dir(p, &mut onedrive_business_roots);
                            } else {
                                try_add_dir(p, &mut onedrive_personal_roots);
                            }
                        }
                    }
                }

                // F3: Dropbox info.json + folders
                let dropbox_cfg = profile.join(".dropbox").join("info.json");
                if env.file_exists(&dropbox_cfg) {
                    if let Some(raw) = env.read_to_string(&dropbox_cfg) {
                        for p in parse_dropbox_info_json(&raw) {
                            try_add_dir(p, &mut dropbox_roots);
                        }
                    }
                }
                try_add_dir(profile.join("Dropbox"), &mut dropbox_roots);
                for name in env.read_dir_names(profile) {
                    if name.to_ascii_lowercase().starts_with("dropbox (") {
                        try_add_dir(profile.join(&name), &mut dropbox_roots);
                    }
                }

                // F4: iCloud Drive
                try_add_dir(profile.join("iCloudDrive"), &mut icloud_roots);
                try_add_dir(profile.join("iCloud Drive"), &mut icloud_roots);

                // F5: Box
                try_add_dir(profile.join("Box"), &mut box_roots);
                try_add_dir(profile.join("Box Sync"), &mut box_roots);

                // F6: Nextcloud
                let mut nc_cfgs = vec![profile
                    .join(".config")
                    .join("Nextcloud")
                    .join("nextcloud.cfg")];
                if let Some(xdg) = env.env_var("XDG_CONFIG_HOME") {
                    nc_cfgs.push(PathBuf::from(xdg).join("Nextcloud").join("nextcloud.cfg"));
                }
                for cfg_path in nc_cfgs {
                    if env.file_exists(&cfg_path) {
                        if let Some(raw) = env.read_to_string(&cfg_path) {
                            for p in parse_nextcloud_cfg(&raw) {
                                try_add_dir(p, &mut nextcloud_roots);
                            }
                        }
                    }
                }
                try_add_dir(profile.join("Nextcloud"), &mut nextcloud_roots);
                for name in env.read_dir_names(profile) {
                    let lower = name.to_ascii_lowercase();
                    if lower.starts_with("nextcloud") && lower != "nextcloud" {
                        try_add_dir(profile.join(&name), &mut nextcloud_roots);
                    }
                }

                // F7: Proton Drive & pCloud
                try_add_dir(profile.join("Proton Drive"), &mut proton_roots);
                try_add_dir(profile.join("ProtonDrive"), &mut proton_roots);
                try_add_dir(profile.join("pCloudDrive"), &mut pcloud_roots);
                try_add_dir(profile.join("pCloud Drive"), &mut pcloud_roots);
            }
        }
    }

    let make_entry = |id: &str,
                      provider: CloudDriveProvider,
                      label: &str,
                      account_kind: Option<&str>,
                      virtual_drive: bool,
                      roots: Vec<PathBuf>| {
        let detected = !roots.is_empty();
        let root_path = roots.first().cloned();
        DiscoveredCloudDrive {
            id: id.to_string(),
            provider,
            label: label.to_string(),
            account_kind: account_kind.map(str::to_string),
            detected,
            mounted: detected,
            virtual_drive,
            root_path,
            detected_roots: roots,
        }
    };

    vec![
        make_entry(
            "google_drive",
            CloudDriveProvider::GoogleDrive,
            "Google Drive",
            None,
            google_virtual,
            google_roots,
        ),
        make_entry(
            "onedrive_personal",
            CloudDriveProvider::OneDrive,
            "OneDrive (Personal)",
            Some("personal"),
            false,
            onedrive_personal_roots,
        ),
        make_entry(
            "onedrive_business",
            CloudDriveProvider::OneDrive,
            "OneDrive (Business)",
            Some("business"),
            false,
            onedrive_business_roots,
        ),
        make_entry(
            "dropbox",
            CloudDriveProvider::Dropbox,
            "Dropbox",
            None,
            false,
            dropbox_roots,
        ),
        make_entry(
            "icloud_drive",
            CloudDriveProvider::IcloudDrive,
            "iCloud Drive",
            None,
            false,
            icloud_roots,
        ),
        make_entry(
            "box",
            CloudDriveProvider::Box,
            "Box",
            None,
            false,
            box_roots,
        ),
        make_entry(
            "nextcloud",
            CloudDriveProvider::Nextcloud,
            "Nextcloud",
            None,
            false,
            nextcloud_roots,
        ),
        make_entry(
            "proton_drive",
            CloudDriveProvider::ProtonDrive,
            "Proton Drive",
            None,
            false,
            proton_roots,
        ),
        make_entry(
            "pcloud",
            CloudDriveProvider::Pcloud,
            "pCloud",
            None,
            pcloud_virtual,
            pcloud_roots,
        ),
    ]
}

/// Converts discovered drives into default `CloudDrivesSettings` with ALL drives
/// strictly disabled (`enabled: false`) and assigned local-only `access_tier = 3`.
pub fn build_default_cloud_drives_settings(
    discovered: &[DiscoveredCloudDrive],
) -> CloudDrivesSettings {
    let drives = discovered
        .iter()
        .map(|d| CloudDriveConfigEntry {
            id: d.id.clone(),
            provider: d.provider,
            label: d.label.clone(),
            enabled: false,
            root_path: d
                .root_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: AccessTier::Tier3Restricted.as_u8(),
            account_kind: d.account_kind.clone(),
        })
        .collect();

    CloudDrivesSettings {
        placeholder_mode: CloudPlaceholderMode::LocallySyncedOnly,
        hydration_max_file_size_mb: DEFAULT_HYDRATION_MAX_FILE_SIZE_MB,
        drives,
    }
}

fn clean_verbatim_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        if !stripped.to_ascii_uppercase().starts_with("UNC\\") {
            return PathBuf::from(stripped);
        }
    }
    p.to_path_buf()
}

fn contains_normalized(existing: &[PathBuf], candidate: &Path) -> bool {
    let cand_str = candidate.to_string_lossy();
    let cand_norm = quorum_types::normalize_prefix_for_match(&cand_str);
    existing.iter().any(|p| {
        if p == candidate {
            return true;
        }
        match (
            &cand_norm,
            quorum_types::normalize_prefix_for_match(&p.to_string_lossy()),
        ) {
            (Ok(a), Ok(b)) => *a == b,
            _ => false,
        }
    })
}

/// Parses Dropbox `info.json` (`personal.path`, `business.path`).
pub fn parse_dropbox_info_json(raw: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) else {
        return paths;
    };
    for key in ["personal", "business"] {
        if let Some(path_str) = val
            .get(key)
            .and_then(|obj| obj.get("path"))
            .and_then(|v| v.as_str())
        {
            let trimmed = path_str.trim();
            if !trimmed.is_empty() {
                paths.push(PathBuf::from(trimmed));
            }
        }
    }
    paths
}

/// Parses Nextcloud `nextcloud.cfg` (`0\Folders\1\localPath=...`).
pub fn parse_nextcloud_cfg(raw: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((key, val)) = trimmed.split_once('=') {
            if key.trim().to_ascii_lowercase().ends_with("localpath") {
                let unquoted = val.trim().trim_matches('"').trim_matches('\'').trim();
                if !unquoted.is_empty() && seen.insert(unquoted.to_string()) {
                    paths.push(PathBuf::from(unquoted));
                }
            }
        }
    }
    paths
}

fn parse_linux_onedrive_cfg(raw: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = trimmed.split_once('=') {
            if key.trim().eq_ignore_ascii_case("sync_dir") {
                let cleaned = val.trim().trim_matches('"').trim_matches('\'').trim();
                if !cleaned.is_empty() {
                    paths.push(PathBuf::from(cleaned));
                }
            }
        }
    }
    paths
}

#[cfg(target_os = "windows")]
fn live_windows_drive_mounts() -> Vec<WindowsDriveMount> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
        fn QueryDosDeviceW(lpDeviceName: *const u16, lpTargetPath: *mut u16, ucchMax: u32) -> u32;
        fn GetVolumeInformationW(
            lpRootPathName: *const u16,
            lpVolumeNameBuffer: *mut u16,
            nVolumeNameSize: u32,
            lpVolumeSerialNumber: *mut u32,
            lpMaximumComponentLength: *mut u32,
            lpFileSystemFlags: *mut u32,
            lpFileSystemNameBuffer: *mut u16,
            nFileSystemNameSize: u32,
        ) -> i32;
    }

    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_NO_ROOT_DIR: u32 = 1;

    let mut mounts = Vec::new();
    for letter in b'C'..=b'Z' {
        let ch = letter as char;
        let root_str = format!("{ch}:\\");
        let wide: Vec<u16> = root_str.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if drive_type == DRIVE_UNKNOWN || drive_type == DRIVE_NO_ROOT_DIR {
            continue;
        }

        let dos_dev = format!("{ch}:");
        let dos_wide: Vec<u16> = dos_dev.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target_buf = [0u16; 512];
        let chars = unsafe {
            QueryDosDeviceW(
                dos_wide.as_ptr(),
                target_buf.as_mut_ptr(),
                target_buf.len() as u32,
            )
        };
        let nt_target = if chars > 0 {
            let target_len = target_buf.iter().position(|&c| c == 0).unwrap_or(0);
            String::from_utf16_lossy(&target_buf[..target_len])
        } else {
            String::new()
        };

        let is_non_harddisk = !nt_target.starts_with(r"\Device\HarddiskVolume");
        let volume_label = if !is_non_harddisk {
            let mut vol_name = [0u16; 261];
            let mut fs_name = [0u16; 261];
            let ok = unsafe {
                GetVolumeInformationW(
                    wide.as_ptr(),
                    vol_name.as_mut_ptr(),
                    vol_name.len() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    fs_name.as_mut_ptr(),
                    fs_name.len() as u32,
                )
            };
            if ok != 0 {
                let vol_len = vol_name.iter().position(|&c| c == 0).unwrap_or(0);
                String::from_utf16_lossy(&vol_name[..vol_len])
            } else {
                String::new()
            }
        } else if quorum_types::session_fs_bridge::drive_timeout_message(Path::new(&root_str))
            .is_some()
        {
            String::new()
        } else {
            // Virtual / Dokan / WinFSP / SMB drive: bound GetVolumeInformationW to 1.0 s so a
            // stalled cloud client (e.g. GoogleDriveFS.exe) can never hang daemon startup.
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            let wide_c = wide.clone();
            std::thread::spawn(move || {
                let mut vol_name = [0u16; 261];
                let mut fs_name = [0u16; 261];
                let ok = unsafe {
                    GetVolumeInformationW(
                        wide_c.as_ptr(),
                        vol_name.as_mut_ptr(),
                        vol_name.len() as u32,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        fs_name.as_mut_ptr(),
                        fs_name.len() as u32,
                    )
                };
                let lbl = if ok != 0 {
                    let vol_len = vol_name.iter().position(|&c| c == 0).unwrap_or(0);
                    String::from_utf16_lossy(&vol_name[..vol_len])
                } else {
                    String::new()
                };
                let _ = tx.send(lbl);
            });
            match rx.recv_timeout(std::time::Duration::from_millis(2000)) {
                Ok(lbl) => lbl,
                Err(_) => {
                    // Volume label lookup is cosmetic; do not poison the per-drive timeout
                    // circuit breaker before the actual directory probe runs.
                    String::new()
                }
            }
        };

        let is_virtual = is_non_harddisk
            || volume_label.to_ascii_lowercase().contains("google drive")
            || volume_label.to_ascii_lowercase().contains("pcloud");

        mounts.push(WindowsDriveMount {
            letter: ch,
            root: PathBuf::from(root_str),
            volume_label,
            is_virtual,
            nt_target,
        });
    }

    // Merge virtual/per-user drives visible inside the active interactive desktop session
    // (e.g., Google Drive G:\ or pCloud P:\ when running as Windows LocalSystem in Session 0).
    for drv in quorum_types::session_fs_bridge::list_session_drives() {
        let upper = drv.letter.to_ascii_uppercase();
        if !mounts
            .iter()
            .any(|m| m.letter.to_ascii_uppercase() == upper)
        {
            mounts.push(WindowsDriveMount {
                letter: upper,
                root: PathBuf::from(drv.root),
                volume_label: drv.volume_label,
                is_virtual: drv.is_virtual,
                nt_target: drv.nt_target,
            });
        }
    }

    mounts
}

#[cfg(target_os = "windows")]
fn live_windows_registry_sync_roots() -> Vec<RegistrySyncRoot> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: *mut std::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn RegEnumKeyExW(
            hKey: *mut std::ffi::c_void,
            dwIndex: u32,
            lpName: *mut u16,
            lpcchName: *mut u32,
            lpReserved: *mut u32,
            lpClass: *mut u16,
            lpcchClass: *mut u32,
            lpftLastWriteTime: *mut std::ffi::c_void,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut std::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *const u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut std::ffi::c_void) -> i32;
    }

    const HKEY_CURRENT_USER: *mut std::ffi::c_void =
        0x8000_0001u32 as usize as *mut std::ffi::c_void;
    const HKEY_USERS: *mut std::ffi::c_void = 0x8000_0003u32 as usize as *mut std::ffi::c_void;
    const KEY_READ: u32 = 0x20019;

    unsafe fn read_reg_sz(h_key: *mut std::ffi::c_void, value_name: &str) -> Option<String> {
        let val_w: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
        let mut data_type = 0u32;
        let mut data_size = 0u32;
        if RegQueryValueExW(
            h_key,
            val_w.as_ptr(),
            std::ptr::null(),
            &mut data_type,
            std::ptr::null_mut(),
            &mut data_size,
        ) != 0
            || data_size == 0
        {
            return None;
        }
        let u16_len = (data_size as usize / 2) + 1;
        let mut buf = vec![0u16; u16_len];
        if RegQueryValueExW(
            h_key,
            val_w.as_ptr(),
            std::ptr::null(),
            &mut data_type,
            buf.as_mut_ptr() as *mut u8,
            &mut data_size,
        ) != 0
        {
            return None;
        }
        let count = (data_size as usize / 2).min(buf.len());
        let slice = &buf[..count];
        let trimmed = slice
            .iter()
            .position(|&c| c == 0)
            .map(|pos| &slice[..pos])
            .unwrap_or(slice);
        let s = String::from_utf16_lossy(trimmed).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    unsafe fn enum_subkeys(h_key: *mut std::ffi::c_void) -> Vec<String> {
        let mut out = Vec::new();
        let mut idx = 0u32;
        let mut name_buf = [0u16; 256];
        loop {
            let mut name_len = name_buf.len() as u32;
            let status = RegEnumKeyExW(
                h_key,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if status != 0 {
                break;
            }
            idx += 1;
            out.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
        }
        out
    }

    unsafe fn scan_onedrive_accounts(
        hive: *mut std::ffi::c_void,
        base_subkey: &str,
        roots: &mut Vec<RegistrySyncRoot>,
    ) {
        let subkey_w: Vec<u16> = base_subkey.encode_utf16().chain(Some(0)).collect();
        let mut h_accounts: *mut std::ffi::c_void = std::ptr::null_mut();
        if RegOpenKeyExW(hive, subkey_w.as_ptr(), 0, KEY_READ, &mut h_accounts) != 0 {
            return;
        }
        for acc_name in enum_subkeys(h_accounts) {
            let acc_w: Vec<u16> = acc_name.encode_utf16().chain(Some(0)).collect();
            let mut h_acc: *mut std::ffi::c_void = std::ptr::null_mut();
            if RegOpenKeyExW(h_accounts, acc_w.as_ptr(), 0, KEY_READ, &mut h_acc) == 0 {
                if let Some(folder) = read_reg_sz(h_acc, "UserFolder") {
                    let kind = if acc_name.eq_ignore_ascii_case("Personal") {
                        Some("personal".to_string())
                    } else {
                        Some("business".to_string())
                    };
                    let display = read_reg_sz(h_acc, "DisplayName");
                    roots.push(RegistrySyncRoot {
                        provider: CloudDriveProvider::OneDrive,
                        account_kind: kind,
                        root_path: PathBuf::from(folder),
                        label_hint: display,
                    });
                }
                RegCloseKey(h_acc);
            }
        }
        RegCloseKey(h_accounts);
    }

    unsafe fn scan_other_provider_roots(
        hive: *mut std::ffi::c_void,
        prefix: &str,
        roots: &mut Vec<RegistrySyncRoot>,
    ) {
        let join_sub = |sub: &str| {
            if prefix.is_empty() {
                sub.to_string()
            } else {
                format!(r"{prefix}\{sub}")
            }
        };

        // Google Drive Mirror/Stream configured mount point (only added later if dir_exists)
        for (sub, val) in [
            (r"Software\Google\DriveFS\Share", "MountPoint"),
            (r"Software\Google\DriveFS", "DefaultMountPoint"),
            (r"Software\Google\DriveFS", "MountPoint"),
        ] {
            let full = join_sub(sub);
            let sub_w: Vec<u16> = full.encode_utf16().chain(Some(0)).collect();
            let mut h_key: *mut std::ffi::c_void = std::ptr::null_mut();
            if RegOpenKeyExW(hive, sub_w.as_ptr(), 0, KEY_READ, &mut h_key) == 0 {
                if let Some(raw) = read_reg_sz(h_key, val) {
                    let trimmed = raw.trim().trim_matches('"');
                    let pb = if trimmed.len() == 1
                        && trimmed.as_bytes()[0].is_ascii_alphabetic()
                    {
                        PathBuf::from(format!(r"{}:\My Drive", trimmed.to_ascii_uppercase()))
                    } else if trimmed.len() == 2
                        && trimmed.as_bytes()[0].is_ascii_alphabetic()
                        && trimmed.as_bytes()[1] == b':'
                    {
                        PathBuf::from(format!(r"{}\My Drive", trimmed))
                    } else if trimmed.len() == 3
                        && trimmed.as_bytes()[0].is_ascii_alphabetic()
                        && trimmed.as_bytes()[1] == b':'
                        && (trimmed.as_bytes()[2] == b'\\' || trimmed.as_bytes()[2] == b'/')
                    {
                        PathBuf::from(format!(r"{}:\My Drive", &trimmed[..1]))
                    } else {
                        PathBuf::from(trimmed)
                    };
                    roots.push(RegistrySyncRoot {
                        provider: CloudDriveProvider::GoogleDrive,
                        account_kind: None,
                        root_path: pb,
                        label_hint: Some("Google Drive".to_string()),
                    });
                }
                RegCloseKey(h_key);
            }
        }

        // iCloud Drive (Windows Store / Classic)
        for (sub, val) in [
            (
                r"Software\Apple Inc.\Internet Services\Shell\iCloudDrive",
                "RootDirectory",
            ),
            (
                r"Software\Apple Inc.\Internet Services",
                "iCloudDrivePath",
            ),
        ] {
            let full = join_sub(sub);
            let sub_w: Vec<u16> = full.encode_utf16().chain(Some(0)).collect();
            let mut h_key: *mut std::ffi::c_void = std::ptr::null_mut();
            if RegOpenKeyExW(hive, sub_w.as_ptr(), 0, KEY_READ, &mut h_key) == 0 {
                if let Some(folder) = read_reg_sz(h_key, val) {
                    roots.push(RegistrySyncRoot {
                        provider: CloudDriveProvider::IcloudDrive,
                        account_kind: None,
                        root_path: PathBuf::from(folder),
                        label_hint: Some("iCloud Drive".to_string()),
                    });
                }
                RegCloseKey(h_key);
            }
        }

        // Box Drive custom sync directory
        let box_full = join_sub(r"Software\Box\Box\preferences");
        let box_w: Vec<u16> = box_full.encode_utf16().chain(Some(0)).collect();
        let mut h_box: *mut std::ffi::c_void = std::ptr::null_mut();
        if RegOpenKeyExW(hive, box_w.as_ptr(), 0, KEY_READ, &mut h_box) == 0 {
            if let Some(folder) = read_reg_sz(h_box, "sync_directory_path") {
                roots.push(RegistrySyncRoot {
                    provider: CloudDriveProvider::Box,
                    account_kind: None,
                    root_path: PathBuf::from(folder),
                    label_hint: Some("Box".to_string()),
                });
            }
            RegCloseKey(h_box);
        }
    }

    let mut roots = Vec::new();
    unsafe {
        scan_onedrive_accounts(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\OneDrive\Accounts",
            &mut roots,
        );
        scan_other_provider_roots(HKEY_CURRENT_USER, "", &mut roots);

        let empty_w = [0u16];
        let mut h_users: *mut std::ffi::c_void = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_USERS, empty_w.as_ptr(), 0, KEY_READ, &mut h_users) == 0 {
            for sid in enum_subkeys(h_users) {
                let lower = sid.to_ascii_lowercase();
                if lower == ".default"
                    || lower.ends_with("_classes")
                    || lower.starts_with("s-1-5-18")
                    || lower.starts_with("s-1-5-19")
                    || lower.starts_with("s-1-5-20")
                {
                    continue;
                }
                let sub = format!(r"{sid}\Software\Microsoft\OneDrive\Accounts");
                scan_onedrive_accounts(HKEY_USERS, &sub, &mut roots);
                scan_other_provider_roots(HKEY_USERS, &sid, &mut roots);
            }
            RegCloseKey(h_users);
        }
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeCloudDiscoveryEnv {
        os: TargetOs,
        profiles: Vec<PathBuf>,
        env_vars: HashMap<String, String>,
        dirs: HashSet<String>,
        files: HashMap<String, String>,
        mounts: Vec<WindowsDriveMount>,
        reg_roots: Vec<RegistrySyncRoot>,
        virtual_paths: HashSet<String>,
    }

    impl FakeCloudDiscoveryEnv {
        fn new(os: TargetOs) -> Self {
            Self {
                os,
                profiles: Vec::new(),
                env_vars: HashMap::new(),
                dirs: HashSet::new(),
                files: HashMap::new(),
                mounts: Vec::new(),
                reg_roots: Vec::new(),
                virtual_paths: HashSet::new(),
            }
        }

        fn norm(&self, p: &Path) -> String {
            let s = p.to_string_lossy().replace('\\', "/");
            if self.os == TargetOs::Windows {
                s.to_ascii_lowercase()
            } else {
                s
            }
        }

        fn add_dir(&mut self, p: impl AsRef<Path>) {
            self.dirs.insert(self.norm(p.as_ref()));
        }

        fn add_file(&mut self, p: impl AsRef<Path>, content: &str) {
            self.files
                .insert(self.norm(p.as_ref()), content.to_string());
        }
    }

    impl CloudDiscoveryEnv for FakeCloudDiscoveryEnv {
        fn target_os(&self) -> TargetOs {
            self.os
        }
        fn user_profiles(&self) -> Vec<PathBuf> {
            self.profiles.clone()
        }
        fn env_var(&self, key: &str) -> Option<String> {
            self.env_vars.get(key).cloned()
        }
        fn dir_exists(&self, path: &Path) -> bool {
            self.dirs.contains(&self.norm(path))
        }
        fn file_exists(&self, path: &Path) -> bool {
            self.files.contains_key(&self.norm(path))
        }
        fn read_dir_names(&self, path: &Path) -> Vec<String> {
            let base = self.norm(path).trim_end_matches('/').to_string();
            let prefix = format!("{base}/");
            let mut names = HashSet::new();
            for d in &self.dirs {
                if let Some(rest) = d.strip_prefix(&prefix) {
                    if let Some(first) = rest.split('/').next() {
                        if !first.is_empty() {
                            names.insert(first.to_string());
                        }
                    }
                }
            }
            names.into_iter().collect()
        }
        fn read_to_string(&self, path: &Path) -> Option<String> {
            self.files.get(&self.norm(path)).cloned()
        }
        fn windows_drive_mounts(&self) -> Vec<WindowsDriveMount> {
            self.mounts.clone()
        }
        fn windows_registry_sync_roots(&self) -> Vec<RegistrySyncRoot> {
            self.reg_roots.clone()
        }
        fn is_virtual_mount(&self, path: &Path) -> bool {
            self.virtual_paths.contains(&self.norm(path))
        }
    }

    #[test]
    fn test_windows_cross_provider_discovery_all_disabled_and_tier3() {
        let mut env = FakeCloudDiscoveryEnv::new(TargetOs::Windows);
        let profile = PathBuf::from(r"C:\Users\Alice");
        env.profiles.push(profile.clone());

        // Google Drive Stream G:\My Drive + Shared drives
        env.mounts.push(WindowsDriveMount {
            letter: 'G',
            root: PathBuf::from(r"G:\"),
            volume_label: "Google Drive".to_string(),
            is_virtual: true,
            nt_target: r"\Device\GoogleDriveFS".to_string(),
        });
        env.add_dir(r"G:\My Drive");
        env.add_dir(r"G:\Shared drives");

        // OneDrive Personal & Business (Registry + Profile)
        env.add_dir(r"C:\Users\Alice\OneDrive");
        env.reg_roots.push(RegistrySyncRoot {
            provider: CloudDriveProvider::OneDrive,
            account_kind: Some("business".to_string()),
            root_path: PathBuf::from(r"C:\Users\Alice\OneDrive - Acme Corp"),
            label_hint: Some("Acme Corp".to_string()),
        });
        env.add_dir(r"C:\Users\Alice\OneDrive - Acme Corp");

        // Dropbox via info.json
        env.add_dir(r"D:\Sync\DropboxPersonal");
        env.add_file(
            r"C:\Users\Alice\AppData\Local\Dropbox\info.json",
            r#"{"personal":{"path":"D:\\Sync\\DropboxPersonal"}}"#,
        );

        // iCloud, Box, Nextcloud (via nextcloud.cfg), Proton Drive, pCloud
        env.add_dir(r"C:\Users\Alice\iCloudDrive");
        env.add_dir(r"C:\Users\Alice\Box");
        env.add_dir(r"D:\Sync\NextcloudWork");
        env.add_file(
            r"C:\Users\Alice\AppData\Roaming\Nextcloud\nextcloud.cfg",
            "[Accounts]\n0\\Folders\\1\\localPath=D:/Sync/NextcloudWork\n",
        );
        env.add_dir(r"C:\Users\Alice\Proton Drive");
        env.mounts.push(WindowsDriveMount {
            letter: 'P',
            root: PathBuf::from(r"P:\"),
            volume_label: "pCloud Drive".to_string(),
            is_virtual: true,
            nt_target: r"\Device\pCloud".to_string(),
        });
        env.add_dir(r"P:\");

        let discovered = discover_cloud_drives_with_env(&env);
        assert_eq!(discovered.len(), 9);
        for d in &discovered {
            assert!(d.detected, "Expected {} to be detected", d.id);
            assert!(d.mounted, "Expected {} to be mounted", d.id);
        }
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "google_drive")
                .unwrap()
                .virtual_drive
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "pcloud")
                .unwrap()
                .virtual_drive
        );
        assert_eq!(
            discovered
                .iter()
                .find(|d| d.id == "onedrive_business")
                .unwrap()
                .root_path,
            Some(PathBuf::from(r"C:\Users\Alice\OneDrive - Acme Corp"))
        );

        let settings = build_default_cloud_drives_settings(&discovered);
        assert_eq!(
            settings.placeholder_mode,
            CloudPlaceholderMode::LocallySyncedOnly
        );
        assert_eq!(settings.hydration_max_file_size_mb, 25);
        for entry in &settings.drives {
            assert!(!entry.enabled, "{} must default to disabled", entry.id);
            assert_eq!(
                entry.access_tier, 3,
                "{} must default to Tier3Restricted",
                entry.id
            );
        }
    }

    #[test]
    fn test_macos_cross_provider_discovery() {
        let mut env = FakeCloudDiscoveryEnv::new(TargetOs::MacOs);
        let profile = PathBuf::from("/Users/alice");
        env.profiles.push(profile);

        env.add_dir("/Users/alice/Library/CloudStorage/GoogleDrive-alice@gmail.com/My Drive");
        env.add_dir("/Users/alice/Library/CloudStorage/OneDrive-Personal");
        env.add_dir("/Users/alice/Library/CloudStorage/OneDrive-AcmeCorp");
        env.add_dir("/Users/alice/Library/CloudStorage/Dropbox");
        env.add_dir("/Users/alice/Library/Mobile Documents/com~apple~CloudDocs");
        env.add_dir("/Users/alice/Library/CloudStorage/Box-Box");
        env.add_dir("/Users/alice/Library/CloudStorage/Nextcloud-Work");
        env.add_dir("/Users/alice/Library/CloudStorage/ProtonDrive-alice@proton.me");
        env.add_dir("/Volumes/pCloud Drive");

        let discovered = discover_cloud_drives_with_env(&env);
        for d in &discovered {
            assert!(d.detected, "Expected macOS {} to be detected", d.id);
        }
        let settings = build_default_cloud_drives_settings(&discovered);
        assert!(settings
            .drives
            .iter()
            .all(|e| !e.enabled && e.access_tier == 3));
    }

    #[test]
    fn test_linux_cross_provider_discovery_and_absent_providers() {
        let mut env = FakeCloudDiscoveryEnv::new(TargetOs::Linux);
        env.profiles.push(PathBuf::from("/home/alice"));

        env.add_dir("/home/alice/Google Drive");
        env.add_dir("/home/alice/OneDrive");
        env.add_dir("/home/alice/OneDrive - Contoso");
        env.add_dir("/home/alice/Dropbox");
        env.add_dir("/home/alice/Nextcloud");
        env.add_dir("/home/alice/Proton Drive");
        env.add_dir("/home/alice/pCloudDrive");
        // Leave iCloud and Box absent on Linux

        let discovered = discover_cloud_drives_with_env(&env);
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "google_drive")
                .unwrap()
                .detected
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "onedrive_personal")
                .unwrap()
                .detected
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "onedrive_business")
                .unwrap()
                .detected
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "dropbox")
                .unwrap()
                .detected
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "nextcloud")
                .unwrap()
                .detected
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "proton_drive")
                .unwrap()
                .detected
        );
        assert!(
            discovered
                .iter()
                .find(|d| d.id == "pcloud")
                .unwrap()
                .detected
        );
        assert!(
            !discovered
                .iter()
                .find(|d| d.id == "icloud_drive")
                .unwrap()
                .detected
        );
        assert!(!discovered.iter().find(|d| d.id == "box").unwrap().detected);
    }

    #[test]
    fn test_placeholder_flag_and_policy_helpers() {
        assert!(is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        ));
        assert!(is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_OFFLINE | 0x20
        ));
        assert!(is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_OPEN
        ));
        assert!(!is_windows_cloud_placeholder_attrs(0x20)); // FILE_ATTRIBUTE_ARCHIVE only

        assert!(is_macos_cloud_placeholder_flags(MACOS_SF_DATALESS));
        assert!(!is_macos_cloud_placeholder_flags(0));
        assert!(!is_macos_cloud_placeholder_flags(0x0002_0000)); // SF_IMMUTABLE

        let locally = CloudPlaceholderPolicy::LocallySyncedOnly;
        assert!(should_skip_cloud_placeholder(true, 0, locally));
        assert!(should_skip_cloud_placeholder(true, 1024, locally));
        assert!(!should_skip_cloud_placeholder(
            false,
            100 * 1024 * 1024,
            locally
        ));

        let cap = 25 * 1024 * 1024;
        let hydrate = CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: cap,
        };
        assert!(!should_skip_cloud_placeholder(true, cap, hydrate));
        assert!(should_skip_cloud_placeholder(true, cap + 1, hydrate));
        assert!(!should_skip_cloud_placeholder(false, cap + 1, hydrate));
    }

    #[test]
    fn test_live_discovery_hermetic_test_profile_dir_suppresses_host_leakage() {
        use std::sync::{Mutex, OnceLock};
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        struct EnvRestore {
            key: &'static str,
            prev: Option<String>,
        }
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let isolated_profile = dir.path().join("isolated_user");
        let isolated_dropbox = isolated_profile.join("Dropbox");
        std::fs::create_dir_all(&isolated_dropbox).unwrap();

        let prev_profile = std::env::var("QUORUM_CLOUD_TEST_PROFILE_DIR").ok();
        let prev_onedrive = std::env::var("OneDrive").ok();
        let prev_appdata = std::env::var("APPDATA").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let _restore_profile = EnvRestore {
            key: "QUORUM_CLOUD_TEST_PROFILE_DIR",
            prev: prev_profile,
        };
        let _restore_onedrive = EnvRestore {
            key: "OneDrive",
            prev: prev_onedrive,
        };
        let _restore_appdata = EnvRestore {
            key: "APPDATA",
            prev: prev_appdata,
        };
        let _restore_xdg = EnvRestore {
            key: "XDG_CONFIG_HOME",
            prev: prev_xdg,
        };
        let outside_dir = dir.path().join("host_outside");
        let outside_file = outside_dir.join("leak.txt");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(&outside_file, "host").unwrap();

        std::env::set_var("QUORUM_CLOUD_TEST_PROFILE_DIR", &isolated_profile);
        std::env::set_var("OneDrive", r"C:\HostLeak\OneDrive");
        std::env::set_var("XDG_CONFIG_HOME", &outside_dir);
        let isolated_appdata = isolated_profile.join("AppData").join("Roaming");
        std::env::set_var("APPDATA", &isolated_appdata);

        let env = LiveCloudDiscoveryEnv;
        assert!(env.is_test_profile_override());
        assert_eq!(env.user_profiles(), vec![isolated_profile.clone()]);
        assert!(env.windows_drive_mounts().is_empty());
        assert!(env.windows_registry_sync_roots().is_empty());
        assert!(!env.is_virtual_mount(Path::new(r"G:\My Drive")));
        assert_eq!(env.env_var("OneDrive"), None);
        assert_eq!(env.env_var("XDG_CONFIG_HOME"), None);
        assert!(!env.dir_exists(&outside_dir));
        assert!(!env.file_exists(&outside_file));
        assert_eq!(
            env.env_var("APPDATA"),
            Some(isolated_appdata.to_string_lossy().to_string())
        );

        let isolated_xdg = isolated_profile.join(".config");
        std::fs::create_dir_all(&isolated_xdg).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &isolated_xdg);
        assert_eq!(
            env.env_var("XDG_CONFIG_HOME"),
            Some(isolated_xdg.to_string_lossy().to_string())
        );

        let discovered = discover_cloud_drives_with_env(&env);
        let dropbox = discovered.iter().find(|d| d.id == "dropbox").unwrap();
        assert!(dropbox.detected);
        assert_eq!(dropbox.detected_roots.len(), 1);
        assert!(crate::config::path_matches_prefix(
            &dropbox.detected_roots[0],
            &isolated_profile
        ));

        // Ensure no discovered root comes from outside the isolated profile directory
        for drive in &discovered {
            for root in &drive.detected_roots {
                assert!(
                    crate::config::path_matches_prefix(root, &isolated_profile),
                    "Detected root {:?} leaked from host outside {:?}",
                    root,
                    isolated_profile
                );
            }
        }
    }

    #[test]
    fn test_onedrive_personal_not_misclassified_as_business_cross_os() {
        // 1. Windows OneDrive env var pointing to "OneDrive - Personal" must go ONLY to personal
        let mut win_env = FakeCloudDiscoveryEnv::new(TargetOs::Windows);
        win_env.profiles.push(PathBuf::from(r"C:\Users\Alice"));
        win_env.add_dir(r"C:\Users\Alice\OneDrive - Personal");
        win_env.env_vars.insert(
            "OneDrive".to_string(),
            r"C:\Users\Alice\OneDrive - Personal".to_string(),
        );
        let win_disc = discover_cloud_drives_with_env(&win_env);
        let win_p = win_disc
            .iter()
            .find(|d| d.id == "onedrive_personal")
            .unwrap();
        let win_b = win_disc
            .iter()
            .find(|d| d.id == "onedrive_business")
            .unwrap();
        assert_eq!(
            win_p.detected_roots,
            vec![PathBuf::from(r"C:\Users\Alice\OneDrive - Personal")]
        );
        assert!(
            !win_b.detected,
            "OneDrive - Personal must NOT appear in onedrive_business on Windows"
        );

        // 2. macOS "OneDrive - Personal" directly under profile must go ONLY to personal
        let mut mac_env = FakeCloudDiscoveryEnv::new(TargetOs::MacOs);
        mac_env.profiles.push(PathBuf::from("/Users/alice"));
        mac_env.add_dir("/Users/alice/OneDrive - Personal");
        let mac_disc = discover_cloud_drives_with_env(&mac_env);
        let mac_p = mac_disc
            .iter()
            .find(|d| d.id == "onedrive_personal")
            .unwrap();
        let mac_b = mac_disc
            .iter()
            .find(|d| d.id == "onedrive_business")
            .unwrap();
        assert_eq!(
            mac_p.detected_roots,
            vec![PathBuf::from("/Users/alice/OneDrive - Personal")]
        );
        assert!(
            !mac_b.detected,
            "OneDrive - Personal must NOT appear in onedrive_business on macOS"
        );

        // 3. Linux "OneDrive - Personal" + .config/onedrive/config pointing to Business folder
        let mut lin_env = FakeCloudDiscoveryEnv::new(TargetOs::Linux);
        lin_env.profiles.push(PathBuf::from("/home/alice"));
        lin_env.add_dir("/home/alice/OneDrive - Personal");
        lin_env.add_dir("/home/alice/OneDrive - Contoso");
        lin_env.add_file(
            "/home/alice/.config/onedrive/config",
            "sync_dir = \"/home/alice/OneDrive - Contoso\"\n",
        );
        let lin_disc = discover_cloud_drives_with_env(&lin_env);
        let lin_p = lin_disc
            .iter()
            .find(|d| d.id == "onedrive_personal")
            .unwrap();
        let lin_b = lin_disc
            .iter()
            .find(|d| d.id == "onedrive_business")
            .unwrap();
        assert_eq!(
            lin_p.detected_roots,
            vec![PathBuf::from("/home/alice/OneDrive - Personal")]
        );
        assert_eq!(
            lin_b.detected_roots,
            vec![PathBuf::from("/home/alice/OneDrive - Contoso")]
        );
    }

    #[test]
    fn test_macos_test_profile_override_skips_host_volumes_pcloud() {
        struct MacOverrideEnv {
            inner: FakeCloudDiscoveryEnv,
        }
        impl CloudDiscoveryEnv for MacOverrideEnv {
            fn target_os(&self) -> TargetOs {
                self.inner.target_os()
            }
            fn user_profiles(&self) -> Vec<PathBuf> {
                self.inner.user_profiles()
            }
            fn env_var(&self, key: &str) -> Option<String> {
                self.inner.env_var(key)
            }
            fn dir_exists(&self, path: &Path) -> bool {
                self.inner.dir_exists(path)
            }
            fn file_exists(&self, path: &Path) -> bool {
                self.inner.file_exists(path)
            }
            fn read_dir_names(&self, path: &Path) -> Vec<String> {
                self.inner.read_dir_names(path)
            }
            fn read_to_string(&self, path: &Path) -> Option<String> {
                self.inner.read_to_string(path)
            }
            fn windows_drive_mounts(&self) -> Vec<WindowsDriveMount> {
                self.inner.windows_drive_mounts()
            }
            fn windows_registry_sync_roots(&self) -> Vec<RegistrySyncRoot> {
                self.inner.windows_registry_sync_roots()
            }
            fn is_virtual_mount(&self, path: &Path) -> bool {
                self.inner.is_virtual_mount(path)
            }
            fn is_test_profile_override(&self) -> bool {
                true
            }
        }

        let mut inner = FakeCloudDiscoveryEnv::new(TargetOs::MacOs);
        inner.profiles.push(PathBuf::from("/Users/isolated"));
        inner.add_dir("/Volumes/pCloud Drive");
        let env = MacOverrideEnv { inner };

        let disc = discover_cloud_drives_with_env(&env);
        let pcloud = disc.iter().find(|d| d.id == "pcloud").unwrap();
        assert!(
            !pcloud.detected,
            "/Volumes/pCloud Drive must be skipped when test_profile_override is active"
        );
    }
}
