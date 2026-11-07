//! Configuration structs for crawler, watcher, chunker, reindexer, and drift remediation.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration parameters governing crawler, watcher, and ingestion pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConfig {
    /// Designated root directories or drive roots to crawl and watch.
    pub watch_paths: Vec<PathBuf>,

    /// Maximum file size permitted for ingestion in bytes (default: 50MB).
    pub max_file_size_bytes: u64,

    /// Minimum file size in bytes (default: 1; 0-byte files produce 0 chunks).
    pub min_file_size_bytes: u64,

    /// Whether to respect .gitignore rules (default: true).
    pub git_ignore: bool,

    /// Whether to respect .ignore rules (default: true).
    pub ignore_files: bool,

    /// Whether to respect global gitignore files (default: true).
    pub git_global: bool,

    /// Whether to skip hidden files and hidden directories (default: true).
    pub skip_hidden: bool,

    /// Whether to follow filesystem symlinks (default: false, prevents traversal loops).
    pub follow_symlinks: bool,

    /// Restrict traversal to the same filesystem / volume (default: false).
    pub same_file_system: bool,

    /// Number of worker threads for directory walking (0 = auto / CPU core count).
    pub crawler_threads: usize,

    /// Watcher debouncing duration in milliseconds (default: 300ms).
    pub debounce_duration_ms: u64,

    /// Internal channel buffer capacity for discovered files (default: 4096).
    pub channel_buffer_size: usize,

    /// Micro-batch size for storage writes (default: 64 chunks).
    pub micro_batch_size: usize,

    /// Micro-batch accumulation timeout in milliseconds (default: 500ms).
    pub batch_timeout_ms: u64,

    /// Access tier policy directory mapping rules: (Path prefix, access_tier 0..3).
    pub access_tier_rules: Vec<(PathBuf, u8)>,

    /// Optional automatic drift healing schedule in seconds.
    pub auto_drift_heal_interval_secs: Option<u64>,

    /// Whether to exclude source code files (`FileCategory::Code`), raw `.dat` blobs, and monolithic dumps during ingestion.
    #[serde(default)]
    pub exclude_source_code: bool,

    /// Optional explicit path to persistent Level-1 deduplication catalog.
    /// If None, falls back to <storage_path>/dedup_catalog.json.
    #[serde(default)]
    pub dedup_catalog_path: Option<PathBuf>,

    /// Directories or paths strictly excluded from crawling and watching
    /// (e.g. internal database storage directories, cache folders).
    #[serde(default)]
    pub excluded_paths: Vec<PathBuf>,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            max_file_size_bytes: 50 * 1024 * 1024, // 50MB
            min_file_size_bytes: 1,
            git_ignore: true,
            ignore_files: true,
            git_global: true,
            skip_hidden: true,
            follow_symlinks: false,
            same_file_system: false,
            crawler_threads: 0,
            debounce_duration_ms: 300,
            channel_buffer_size: 4096,
            micro_batch_size: 64,
            batch_timeout_ms: 500,
            access_tier_rules: Vec::new(),
            auto_drift_heal_interval_secs: None,
            exclude_source_code: false,
            dedup_catalog_path: None,
            excluded_paths: Vec::new(),
        }
    }
}

impl IngestConfig {
    pub fn debounce_duration(&self) -> Duration {
        Duration::from_millis(self.debounce_duration_ms)
    }

    pub fn batch_timeout(&self) -> Duration {
        Duration::from_millis(self.batch_timeout_ms)
    }

    /// Resolve access tier for a path based on longest matching prefix in access_tier_rules.
    pub fn resolve_access_tier(&self, path: &std::path::Path) -> u8 {
        let mut best_tier = 0u8;
        let mut longest_match = 0;

        for (prefix, tier) in &self.access_tier_rules {
            if path.starts_with(prefix) {
                let match_len = prefix.as_os_str().len();
                if match_len > longest_match {
                    longest_match = match_len;
                    best_tier = *tier;
                }
            }
        }

        best_tier
    }

    /// Discovers all mounted fixed physical drives on the host system (excluding CD-ROMs like `F:\`,
    /// removable drives, network shares, VHD/ISO virtual disks, subst drives, and virtual cloud mounts like `Google Drive`).
    pub fn discover_physical_drives() -> Vec<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            #[link(name = "kernel32")]
            extern "system" {
                fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
                fn QueryDosDeviceW(
                    lpDeviceName: *const u16,
                    lpTargetPath: *mut u16,
                    ucchMax: u32,
                ) -> u32;
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
                fn CreateFileW(
                    lpFileName: *const u16,
                    dwDesiredAccess: u32,
                    dwShareMode: u32,
                    lpSecurityAttributes: *const std::ffi::c_void,
                    dwCreationDisposition: u32,
                    dwFlagsAndAttributes: u32,
                    hTemplateFile: *const std::ffi::c_void,
                ) -> isize;
                fn DeviceIoControl(
                    hDevice: isize,
                    dwIoControlCode: u32,
                    lpInBuffer: *const std::ffi::c_void,
                    nInBufferSize: u32,
                    lpOutBuffer: *mut std::ffi::c_void,
                    nOutBufferSize: u32,
                    lpBytesReturned: *mut u32,
                    lpOverlapped: *mut std::ffi::c_void,
                ) -> i32;
                fn CloseHandle(hObject: isize) -> i32;
            }

            const DRIVE_FIXED: u32 = 3;
            const FILE_SHARE_READ: u32 = 0x00000001;
            const FILE_SHARE_WRITE: u32 = 0x00000002;
            const OPEN_EXISTING: u32 = 3;
            const INVALID_HANDLE_VALUE: isize = -1;
            const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
            const BUS_TYPE_ATAPI: u8 = 2; // Optical/CD-ROM bus
            const BUS_TYPE_VIRTUAL: u8 = 14;
            const BUS_TYPE_FILE_BACKED_VIRTUAL: u8 = 15;

            #[repr(C)]
            struct StoragePropertyQuery {
                property_id: u32, // 0 = StorageDeviceProperty
                query_type: u32,  // 0 = PropertyStandardQuery
                additional_parameters: [u8; 4],
            }

            #[repr(C)]
            struct StorageDeviceDescriptorHeader {
                version: u32,
                size: u32,
                device_type: u8,
                device_type_modifier: u8,
                removable_media: u8,
                command_queueing: u8,
                vendor_id_offset: u32,
                product_id_offset: u32,
                product_revision_offset: u32,
                serial_number_offset: u32,
                bus_type: u32,
            }

            let mut data_drives = Vec::new();
            let mut os_drives = Vec::new();

            for letter in b'C'..=b'Z' {
                let root_str = format!("{}:\\", letter as char);
                let wide: Vec<u16> = root_str.encode_utf16().chain(std::iter::once(0)).collect();

                // 1. Must be DRIVE_FIXED (rejects DRIVE_CDROM = 5, DRIVE_REMOVABLE = 2, DRIVE_REMOTE = 4, DRIVE_RAMDISK = 6)
                let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
                if drive_type != DRIVE_FIXED {
                    continue;
                }

                // 2. Kernel NT device path must be \Device\HarddiskVolume* (rejects \Device\CdRom*, \??\ subst, Dokan/WinFsp/Google Drive virtual mounts)
                let dos_dev = format!("{}:", letter as char);
                let dos_wide: Vec<u16> = dos_dev.encode_utf16().chain(std::iter::once(0)).collect();
                let mut target_buf = [0u16; 512];
                let chars = unsafe {
                    QueryDosDeviceW(
                        dos_wide.as_ptr(),
                        target_buf.as_mut_ptr(),
                        target_buf.len() as u32,
                    )
                };
                if chars == 0 {
                    continue;
                }
                let target_len = target_buf.iter().position(|&c| c == 0).unwrap_or(0);
                let nt_target = String::from_utf16_lossy(&target_buf[..target_len]);
                if !nt_target.starts_with("\\Device\\HarddiskVolume") {
                    continue;
                }

                // 3. Hardware Storage Bus check: reject Virtual / FileBackedVirtual / Optical ATAPI / Removable media
                let vol_dev = format!("\\\\.\\{}:", letter as char);
                let vol_wide: Vec<u16> = vol_dev.encode_utf16().chain(std::iter::once(0)).collect();
                let handle = unsafe {
                    CreateFileW(
                        vol_wide.as_ptr(),
                        0, // 0 access rights allows querying storage property without admin privileges
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null(),
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    let query = StoragePropertyQuery {
                        property_id: 0,
                        query_type: 0,
                        additional_parameters: [0; 4],
                    };
                    let mut out_buf = [0u8; 512];
                    let mut bytes_returned = 0u32;
                    let ioctl_ok = unsafe {
                        DeviceIoControl(
                            handle,
                            IOCTL_STORAGE_QUERY_PROPERTY,
                            &query as *const _ as *const std::ffi::c_void,
                            std::mem::size_of::<StoragePropertyQuery>() as u32,
                            out_buf.as_mut_ptr() as *mut std::ffi::c_void,
                            out_buf.len() as u32,
                            &mut bytes_returned,
                            std::ptr::null_mut(),
                        )
                    };
                    unsafe {
                        CloseHandle(handle);
                    }
                    if ioctl_ok != 0
                        && (bytes_returned as usize)
                            >= std::mem::size_of::<StorageDeviceDescriptorHeader>()
                    {
                        let desc = unsafe {
                            &*(out_buf.as_ptr() as *const StorageDeviceDescriptorHeader)
                        };
                        let bus = desc.bus_type as u8;
                        // device_type 0x05 == FILE_DEVICE_CD_ROM /Read-Only Direct Access
                        if desc.removable_media != 0
                            || desc.device_type == 0x05
                            || bus == BUS_TYPE_VIRTUAL
                            || bus == BUS_TYPE_FILE_BACKED_VIRTUAL
                            || bus == BUS_TYPE_ATAPI
                        {
                            continue;
                        }
                    }
                }

                // 4. Filesystem must be NTFS or ReFS and not a cloud mount label
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
                if ok == 0 {
                    continue;
                }

                let vol_len = vol_name.iter().position(|&c| c == 0).unwrap_or(0);
                let fs_len = fs_name.iter().position(|&c| c == 0).unwrap_or(0);
                let vol_label = String::from_utf16_lossy(&vol_name[..vol_len]).to_ascii_lowercase();
                let fs_label = String::from_utf16_lossy(&fs_name[..fs_len]).to_ascii_uppercase();

                if !matches!(fs_label.as_str(), "NTFS" | "REFS" | "EXFAT" | "FAT32") {
                    continue;
                }
                if vol_label.contains("google drive")
                    || vol_label.contains("onedrive")
                    || vol_label.contains("dropbox")
                    || vol_label.contains("virtual")
                {
                    continue;
                }

                let path = PathBuf::from(&root_str);
                if std::fs::read_dir(&path).is_ok() {
                    if letter == b'C' {
                        os_drives.push(path);
                    } else {
                        data_drives.push(path);
                    }
                }
            }

            data_drives.extend(os_drives);
            if data_drives.is_empty() {
                if let Ok(cwd) = std::env::current_dir() {
                    data_drives.push(cwd);
                }
            }
            data_drives
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut drives = Vec::new();
            for candidate in &["/mnt", "/Volumes", "/home", "/Users"] {
                let p = PathBuf::from(candidate);
                if p.exists() && std::fs::read_dir(&p).is_ok() {
                    drives.push(p);
                }
            }
            if drives.is_empty() {
                drives.push(PathBuf::from("/"));
            }
            drives
        }
    }

    /// Discovers user profile directories from Windows Registry ProfileList
    /// (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList),
    /// skipping standard system SIDs (S-1-5-18 LocalSystem, S-1-5-19 LocalService, S-1-5-20 NetworkService).
    #[cfg(target_os = "windows")]
    fn discover_profiles_from_registry() -> Vec<PathBuf> {
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

        #[link(name = "kernel32")]
        extern "system" {
            fn ExpandEnvironmentStringsW(
                lpSrc: *const u16,
                lpDst: *mut u16,
                nSize: u32,
            ) -> u32;
        }

        const HKEY_LOCAL_MACHINE: *mut std::ffi::c_void = 0x80000002u32 as usize as *mut std::ffi::c_void;
        const KEY_READ: u32 = 0x20019;
        const SKIP_SIDS: &[&str] = &["s-1-5-18", "s-1-5-19", "s-1-5-20"];

        let mut profiles = Vec::new();
        unsafe {
            let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\0"
                .encode_utf16()
                .collect();
            let mut h_profile_list: *mut std::ffi::c_void = std::ptr::null_mut();

            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut h_profile_list) != 0 {
                return profiles;
            }

            let mut index = 0u32;
            let mut name_buf = [0u16; 256];
            loop {
                let mut name_len = name_buf.len() as u32;
                let status = RegEnumKeyExW(
                    h_profile_list,
                    index,
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
                index += 1;

                let sid_str = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_ascii_lowercase();
                if SKIP_SIDS.iter().any(|s| sid_str == *s || sid_str.starts_with(&format!("{}.", s))) {
                    continue;
                }

                let sub_subkey: Vec<u16> = format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{}\0", sid_str)
                    .encode_utf16()
                    .collect();
                let mut h_sid: *mut std::ffi::c_void = std::ptr::null_mut();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_subkey.as_ptr(), 0, KEY_READ, &mut h_sid) == 0 {
                    let val_name: Vec<u16> = "ProfileImagePath\0".encode_utf16().collect();
                    let mut data_type = 0u32;
                    let mut data_size = 0u32;

                    if RegQueryValueExW(
                        h_sid,
                        val_name.as_ptr(),
                        std::ptr::null(),
                        &mut data_type,
                        std::ptr::null_mut(),
                        &mut data_size,
                    ) == 0 && data_size > 0 {
                        // Ensure 2-byte alignment for wide string buffer
                        let u16_len = (data_size as usize / 2) + 1;
                        let mut raw_data = vec![0u16; u16_len];
                        if RegQueryValueExW(
                            h_sid,
                            val_name.as_ptr(),
                            std::ptr::null(),
                            &mut data_type,
                            raw_data.as_mut_ptr() as *mut u8,
                            &mut data_size,
                        ) == 0 {
                            let u16_count = (data_size as usize / 2).min(raw_data.len());
                            let u16_slice = &raw_data[..u16_count];
                            let trimmed_u16 = if let Some(pos) = u16_slice.iter().position(|&c| c == 0) {
                                &u16_slice[..pos]
                            } else {
                                u16_slice
                            };

                            let raw_path = String::from_utf16_lossy(trimmed_u16);
                            let src_wide: Vec<u16> = raw_path.encode_utf16().chain(Some(0)).collect();
                            let mut dst_wide = [0u16; 1024];
                            let exp_len = ExpandEnvironmentStringsW(
                                src_wide.as_ptr(),
                                dst_wide.as_mut_ptr(),
                                dst_wide.len() as u32,
                            );
                            let final_path_str = if exp_len > 0 && exp_len <= dst_wide.len() as u32 {
                                String::from_utf16_lossy(&dst_wide[..(exp_len as usize - 1)])
                            } else {
                                raw_path
                            };

                            let path = PathBuf::from(final_path_str);
                            if path.is_dir() && !profiles.contains(&path) {
                                profiles.push(path);
                            }
                        }
                    }
                    RegCloseKey(h_sid);
                }
            }
            RegCloseKey(h_profile_list);
        }
        profiles
    }

    /// Discovers real human user document roots across the host system in Session 0,
    /// strictly avoiding system profiles (LocalSystem systemprofile, LocalService, NetworkService),
    /// virtual/junction directories (All Users, Default User), hidden system profiles (Default),
    /// and non-directory files (desktop.ini), while supporting OneDrive and cloud-sync directory
    /// reparse points without infinite recursion.
    pub fn discover_user_document_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::MetadataExt;

            const SKIP_PROFILE_NAMES: &[&str] = &[
                "all users",
                "default",
                "default user",
                "public",
                "systemprofile",
                "localservice",
                "networkservice",
                "defaultapppool",
                "wdigest",
            ];

            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;
            const FILE_ATTRIBUTE_SYSTEM: u32 = 0x04;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

            let mut candidate_profiles = Vec::new();

            // 1. Discover user profiles via Windows Registry ProfileList (Session 0 LocalSystem support)
            for reg_profile in Self::discover_profiles_from_registry() {
                let name = reg_profile
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                if !name.starts_with('.')
                    && !name.starts_with('$')
                    && !SKIP_PROFILE_NAMES.contains(&name.as_str())
                    && reg_profile.is_dir()
                    && std::fs::read_dir(&reg_profile).is_ok()
                    && !candidate_profiles.contains(&reg_profile)
                {
                    candidate_profiles.push(reg_profile);
                }
            }

            // 2. Discover user profiles via SystemDrive Users directory (usually C:\Users)
            let mut candidate_user_dirs = Vec::new();
            let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
            let primary_users = PathBuf::from(format!("{}\\Users", sys_drive));
            if primary_users.is_dir() {
                candidate_user_dirs.push(primary_users);
            }

            // 3. Discover Users directory on any other fixed physical data drives
            for drive in Self::discover_physical_drives() {
                let users_dir = drive.join("Users");
                if users_dir.is_dir() && !candidate_user_dirs.contains(&users_dir) {
                    candidate_user_dirs.push(users_dir);
                }
            }

            for users_base in candidate_user_dirs {
                let Ok(entries) = std::fs::read_dir(&users_base) else {
                    continue;
                };

                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();

                    if name.starts_with('.') || name.starts_with('$') {
                        continue;
                    }
                    if SKIP_PROFILE_NAMES.contains(&name.as_str()) {
                        continue;
                    }

                    // Check metadata: must be a real directory
                    let Ok(sym_meta) = std::fs::symlink_metadata(&path) else {
                        continue;
                    };

                    if sym_meta.file_type().is_symlink() || !path.is_dir() {
                        continue;
                    }

                    let attrs = sym_meta.file_attributes();
                    // Reject junctions or hidden/system directories at the profile folder level
                    // (e.g. All Users junction, Default User junction, Default profile)
                    if (attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 {
                        continue;
                    }

                    // Must be readable by service account
                    if std::fs::read_dir(&path).is_err() {
                        continue;
                    }

                    if !candidate_profiles.contains(&path) {
                        candidate_profiles.push(path);
                    }
                }
            }

            fn strip_verbatim_unc_prefix(p: &std::path::Path) -> PathBuf {
                let s = p.to_string_lossy();
                if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
                    PathBuf::from(format!(r"\\{}", stripped))
                } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
                    PathBuf::from(stripped)
                } else {
                    p.to_path_buf()
                }
            }

            let mut seen_canonicals: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

            for path in candidate_profiles {
                let mut user_roots = Vec::new();
                let canon_path = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                let clean_root = strip_verbatim_unc_prefix(&canon_path);
                let raw_clean_root = strip_verbatim_unc_prefix(&path);

                // Helper to validate and add document roots safely:
                // allows directory reparse points (OneDrive, cloud sync, junctions to real folders)
                // while strictly rejecting cyclic directory loops or symlinks.
                let mut try_add_folder = |dir: PathBuf, target_vec: &mut Vec<PathBuf>| {
                    if !dir.is_dir() || std::fs::read_dir(&dir).is_err() {
                        return;
                    }
                    // Canonicalize checks for loops and resolves targets
                    if let Ok(canon) = std::fs::canonicalize(&dir) {
                        if !canon.is_dir() || std::fs::read_dir(&canon).is_err() {
                            return;
                        }

                        let clean_canon = strip_verbatim_unc_prefix(&canon);

                        // Reject recursive loops that resolve to profile root or its ancestors
                        if canon == canon_path
                            || canon_path.starts_with(&canon)
                            || clean_canon == clean_root
                            || clean_canon == raw_clean_root
                            || clean_root.starts_with(&clean_canon)
                            || raw_clean_root.starts_with(&clean_canon)
                        {
                            return;
                        }

                        // Reject recursive loops that resolve to dir's parent or ancestor directories
                        if let Some(parent) = dir.parent() {
                            let canon_parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                            let clean_parent = strip_verbatim_unc_prefix(&canon_parent);
                            let raw_clean_parent = strip_verbatim_unc_prefix(parent);
                            if canon == canon_parent
                                || canon_parent.starts_with(&canon)
                                || clean_canon == clean_parent
                                || clean_canon == raw_clean_parent
                                || clean_parent.starts_with(&clean_canon)
                                || raw_clean_parent.starts_with(&clean_canon)
                            {
                                return;
                            }
                        }

                        if seen_canonicals.insert(canon) {
                            target_vec.push(dir);
                        }
                    } else if let Ok(meta) = std::fs::symlink_metadata(&dir) {
                        // If canonicalize failed, ensure it is a real directory and not a symlink
                        if !meta.file_type().is_symlink() && dir.is_dir() && !target_vec.contains(&dir) {
                            target_vec.push(dir);
                        }
                    }
                };

                // Standard document subfolders
                for sub in ["Documents", "Desktop", "Downloads", "Pictures"] {
                    let sub_path = path.join(sub);
                    try_add_folder(sub_path, &mut user_roots);
                }

                // OneDrive & Cloud-sync sync directories (OneDrive, OneDrive - Business, etc.)
                if let Ok(sub_entries) = std::fs::read_dir(&path) {
                    for entry in sub_entries.flatten() {
                        let sub_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                        if sub_name.starts_with("onedrive") {
                            let onedrive_dir = entry.path();
                            if onedrive_dir.is_dir() && std::fs::read_dir(&onedrive_dir).is_ok() {
                                for one_sub in ["Documents", "Desktop", "Pictures"] {
                                    let one_sub_path = onedrive_dir.join(one_sub);
                                    try_add_folder(one_sub_path, &mut user_roots);
                                }
                            }
                        }
                    }
                }

                if user_roots.is_empty() {
                    if let Ok(canon) = std::fs::canonicalize(&path) {
                        if seen_canonicals.insert(canon) {
                            roots.push(path);
                        }
                    } else if !roots.contains(&path) {
                        roots.push(path);
                    }
                } else {
                    roots.extend(user_roots);
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut candidate_bases = Vec::new();
            for base in &["/home", "/Users"] {
                let p = PathBuf::from(base);
                if p.is_dir() {
                    candidate_bases.push(p);
                }
            }

            for base in candidate_bases {
                if let Ok(entries) = std::fs::read_dir(base) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with('.') || name == "lost+found" || name == "Shared" {
                            continue;
                        }
                        if path.is_dir() {
                            let mut found_sub = false;
                            for sub in &["Documents", "Desktop", "Downloads", "Pictures"] {
                                let sub_path = path.join(sub);
                                if sub_path.is_dir() {
                                    roots.push(sub_path);
                                    found_sub = true;
                                }
                            }
                            if !found_sub {
                                roots.push(path);
                            }
                        }
                    }
                }
            }
        }

        // De-duplicate roots while preserving order
        let mut deduped = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for r in roots {
            if seen.insert(r.clone()) {
                deduped.push(r);
            }
        }

        deduped
    }
}

/// Configuration parameters for text chunking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkerConfig {
    /// Target chunk size in characters (default: 500, matching test_ingestion_dedup.rs).
    pub target_chunk_size: usize,
    /// Overlap in characters between adjacent chunks (default: 100).
    pub chunk_overlap: usize,
    /// Minimum chunk length to avoid tiny trailing fragments (default: 40).
    pub min_chunk_size: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            target_chunk_size: 500,
            chunk_overlap: 100,
            min_chunk_size: 40,
        }
    }
}

/// Reindexing execution configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReindexOptions {
    /// Target root paths to reindex. If empty, uses configured daemon watch directories.
    pub target_paths: Vec<PathBuf>,
    /// Full rebuild mode: bypasses mtime and Level-1 BLAKE3 catalogs, re-verifying all files.
    pub full_rebuild: bool,
    /// Force re-embedding all chunks even if Level-2 chunk BLAKE3 cache matches.
    pub force_reembed: bool,
    /// Micro-batch size for storage writes (default: 64).
    pub batch_size: usize,
    /// Number of worker threads for parallel file walking (0 = auto).
    pub num_threads: usize,
    /// Dry run mode: reports files and chunks that would be changed without writing to DB.
    pub dry_run: bool,
}

impl Default for ReindexOptions {
    fn default() -> Self {
        Self {
            target_paths: Vec::new(),
            full_rebuild: false,
            force_reembed: false,
            batch_size: 128,
            num_threads: 0,
            dry_run: false,
        }
    }
}

/// Categories of drift that can be detected and remediated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftType {
    /// Filesystem <-> Database Merkle state drift (untracked or deleted files).
    MerkleState,
    /// LanceDB Vector <-> Tantivy BM25 hybrid index desync.
    HybridIndexDesync,
    /// Obsolete contract hash, dimension, or non-unit L2 norm.
    VectorContract,
    /// ACL access_tier policy mismatch with directory configuration.
    AclPolicy,
    /// Storage fragmentation, tombstones, and unmerged segments.
    StorageCompaction,
}

/// Drift options configuring which drifts to fix and execution mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftFixOptions {
    /// Specific drift types to address. Empty means fix ALL 5 types.
    pub target_drifts: Vec<DriftType>,
    /// Dry run mode: detect and report drift anomalies without modifying storage.
    pub dry_run: bool,
    /// Directory configuration mapping (path prefix -> AccessTier) for ACL drift.
    pub access_tier_rules: Vec<(PathBuf, u8)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_physical_drives_excludes_non_physical() {
        let drives = IngestConfig::discover_physical_drives();
        assert!(!drives.is_empty(), "Must discover at least one physical drive");

        let drive_strings: Vec<String> = drives
            .iter()
            .map(|p| p.to_string_lossy().to_ascii_uppercase())
            .collect();

        #[cfg(target_os = "windows")]
        {
            assert!(
                !drive_strings.contains(&"F:\\".to_string()),
                "F:\\ is not a physical drive (CD-ROM) and must be excluded; got {:?}",
                drive_strings
            );
            assert!(
                !drive_strings.contains(&"G:\\".to_string()),
                "G:\\ is a virtual Google Drive mount and must be excluded; got {:?}",
                drive_strings
            );
            assert!(
                drive_strings.contains(&"D:\\".to_string()) || drive_strings.contains(&"C:\\".to_string()),
                "Must discover physical NTFS drives (D:\\ and/or C:\\); got {:?}",
                drive_strings
            );
        }
    }

    #[test]
    fn test_discover_user_document_roots_filters_system_profiles() {
        let roots = IngestConfig::discover_user_document_roots();
        #[cfg(target_os = "windows")]
        {
            assert!(!roots.is_empty(), "Must discover at least one user document root on Windows");
            for r in &roots {
                let lower = r.to_string_lossy().to_ascii_lowercase();
                assert!(!lower.contains("systemprofile"));
                assert!(!lower.contains("localservice"));
                assert!(!lower.contains("networkservice"));
                assert!(!lower.contains("desktop.ini"));
            }
        }
    }
}

