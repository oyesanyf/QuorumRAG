//! Shared Cloud Drives domain types, placeholder policies, DLP content gate trait,
//! and fail-closed path/prefix validation helpers.

use crate::{AccessTier, TypeError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path};
use std::str::FromStr;

/// Default maximum file size in megabytes for on-demand cloud placeholder hydration.
pub const DEFAULT_HYDRATION_MAX_FILE_SIZE_MB: u64 = 25;

/// Supported cloud storage providers for optional, opt-in local sync-root indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudDriveProvider {
    GoogleDrive,
    OneDrive,
    Dropbox,
    IcloudDrive,
    Box,
    Nextcloud,
    ProtonDrive,
    Pcloud,
}

impl CloudDriveProvider {
    /// Stable snake_case identifier for API/config serialization.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleDrive => "google_drive",
            Self::OneDrive => "onedrive",
            Self::Dropbox => "dropbox",
            Self::IcloudDrive => "icloud_drive",
            Self::Box => "box",
            Self::Nextcloud => "nextcloud",
            Self::ProtonDrive => "proton_drive",
            Self::Pcloud => "pcloud",
        }
    }

    /// Human-readable display name.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::GoogleDrive => "Google Drive",
            Self::OneDrive => "Microsoft OneDrive",
            Self::Dropbox => "Dropbox",
            Self::IcloudDrive => "iCloud Drive",
            Self::Box => "Box",
            Self::Nextcloud => "Nextcloud",
            Self::ProtonDrive => "Proton Drive",
            Self::Pcloud => "pCloud",
        }
    }

    /// All supported cloud drive providers in deterministic UI/discovery order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::GoogleDrive,
            Self::OneDrive,
            Self::Dropbox,
            Self::IcloudDrive,
            Self::Box,
            Self::Nextcloud,
            Self::ProtonDrive,
            Self::Pcloud,
        ]
    }
}

impl fmt::Display for CloudDriveProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CloudDriveProvider {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "google_drive" | "googledrive" | "google drive" => Ok(Self::GoogleDrive),
            "onedrive" | "one_drive" | "one drive" | "microsoft_onedrive" => Ok(Self::OneDrive),
            "dropbox" => Ok(Self::Dropbox),
            "icloud_drive" | "icloud" | "icloud drive" => Ok(Self::IcloudDrive),
            "box" | "box_sync" => Ok(Self::Box),
            "nextcloud" => Ok(Self::Nextcloud),
            "proton_drive" | "protondrive" | "proton drive" => Ok(Self::ProtonDrive),
            "pcloud" | "p_cloud" | "pcloud_drive" => Ok(Self::Pcloud),
            other => Err(TypeError::InvalidCloudDriveConfig(format!(
                "Unknown cloud drive provider '{other}'"
            ))),
        }
    }
}

/// User-facing Files-On-Demand placeholder handling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudPlaceholderMode {
    #[default]
    LocallySyncedOnly,
    HydrateOnDemand,
}

/// Enforcement policy applied before opening any file during classification or extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CloudPlaceholderPolicy {
    #[default]
    LocallySyncedOnly,
    HydrateOnDemand {
        max_file_size_bytes: u64,
    },
}

impl CloudPlaceholderPolicy {
    /// Construct and validate a `CloudPlaceholderPolicy` from settings fields.
    /// Rejects `max_mb == 0` fail-closed.
    pub fn from_settings(mode: CloudPlaceholderMode, max_mb: u64) -> Result<Self, TypeError> {
        if max_mb == 0 {
            return Err(TypeError::InvalidCloudDriveConfig(
                "hydration_max_file_size_mb must be at least 1 MB".to_string(),
            ));
        }
        match mode {
            CloudPlaceholderMode::LocallySyncedOnly => Ok(Self::LocallySyncedOnly),
            CloudPlaceholderMode::HydrateOnDemand => {
                let bytes = max_mb.checked_mul(1024 * 1024).ok_or_else(|| {
                    TypeError::InvalidCloudDriveConfig(
                        "hydration_max_file_size_mb overflows u64 byte limit".to_string(),
                    )
                })?;
                Ok(Self::HydrateOnDemand {
                    max_file_size_bytes: bytes,
                })
            }
        }
    }
}

/// Live mount status for a discovered or configured cloud drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudDriveMountStatus {
    Mounted,
    #[default]
    NotDetected,
    SessionOnly,
    Error,
}

const fn default_restricted_access_tier() -> u8 {
    AccessTier::Tier3Restricted.as_u8()
}

const fn default_hydration_max_file_size_mb() -> u64 {
    DEFAULT_HYDRATION_MAX_FILE_SIZE_MB
}

/// Persisted configuration for an individual cloud drive entry (OFF & Tier 3 by default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudDriveConfigEntry {
    pub id: String,
    pub provider: CloudDriveProvider,
    pub label: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub custom_paths: Vec<String>,
    #[serde(default = "default_restricted_access_tier")]
    pub access_tier: u8,
    #[serde(default)]
    pub account_kind: Option<String>,
}

impl CloudDriveConfigEntry {
    /// Construct a new opt-in cloud drive entry defaulting to `enabled = false`
    /// and local-only `access_tier = 3` (`Tier3Restricted`).
    pub fn new_disabled(
        id: impl Into<String>,
        provider: CloudDriveProvider,
        label: impl Into<String>,
        root_path: Option<String>,
        account_kind: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            provider,
            label: label.into(),
            enabled: false,
            root_path,
            custom_paths: Vec::new(),
            access_tier: AccessTier::Tier3Restricted.as_u8(),
            account_kind,
        }
    }

    /// Validate id, access tier (`0..=3`), `root_path`, and all `custom_paths` fail-closed.
    pub fn validate(&self) -> Result<(), TypeError> {
        if self.id.trim().is_empty() {
            return Err(TypeError::InvalidCloudDriveConfig(
                "Cloud drive entry id cannot be empty".to_string(),
            ));
        }
        if self.label.trim().is_empty() {
            return Err(TypeError::InvalidCloudDriveConfig(format!(
                "Cloud drive '{}' label cannot be empty",
                self.id
            )));
        }
        AccessTier::from_u8(self.access_tier)?;
        if let Some(ref root) = self.root_path {
            validate_cloud_drive_path(root)?;
        }
        for custom in &self.custom_paths {
            validate_cloud_drive_path(custom)?;
        }
        Ok(())
    }
}

/// Top-level persisted Cloud Drives settings block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudDrivesSettings {
    #[serde(default)]
    pub placeholder_mode: CloudPlaceholderMode,
    #[serde(default = "default_hydration_max_file_size_mb")]
    pub hydration_max_file_size_mb: u64,
    #[serde(default)]
    pub drives: Vec<CloudDriveConfigEntry>,
}

impl Default for CloudDrivesSettings {
    fn default() -> Self {
        Self {
            placeholder_mode: CloudPlaceholderMode::LocallySyncedOnly,
            hydration_max_file_size_mb: DEFAULT_HYDRATION_MAX_FILE_SIZE_MB,
            drives: Vec::new(),
        }
    }
}

impl CloudDrivesSettings {
    /// Validate hydration settings and every configured drive entry fail-closed.
    pub fn validate(&self) -> Result<(), TypeError> {
        let _ = self.placeholder_policy()?;
        for drive in &self.drives {
            drive.validate()?;
        }
        Ok(())
    }

    /// Convert settings to a validated `CloudPlaceholderPolicy`.
    pub fn placeholder_policy(&self) -> Result<CloudPlaceholderPolicy, TypeError> {
        CloudPlaceholderPolicy::from_settings(
            self.placeholder_mode,
            self.hydration_max_file_size_mb,
        )
    }
}

/// Fail-closed ingest DLP content inspection gate.
/// Implemented by `OsoosiMeshDlpController` in `quorum-coordinator` and invoked
/// inside `quorum-ingest` before chunking/embedding/storage writes.
pub trait DlpContentGate: Send + Sync {
    fn inspect_ingest_text(
        &self,
        file_path: &str,
        text: &str,
        access_tier: u8,
    ) -> Result<String, String>;
}

/// Fail-closed syntactic validation of a user-supplied or persisted cloud-drive path.
///
/// Rejects:
/// - Empty or whitespace-only paths, leading/trailing whitespace, or paths longer than 4096 bytes
/// - NUL (`\0`), ASCII/Unicode control characters, or Unicode bidirectional control characters
/// - Single- or double-percent-encoded traversal/separators/NUL (`%2e`, `%2f`, `%5c`, `%00`, `%252e`, `%252f`, `%255c`, `%2500`)
/// - UNC / verbatim prefixes (`\\...`, `//...`, `\\?\UNC\...`)
/// - Parent traversal (`..` segment across `/` or `\`, substring `..`, or `Component::ParentDir`)
/// - Path segments (other than `.`) ending with `.` or `' '`, or having leading/trailing whitespace
/// - NTFS Alternate Data Streams (`:` outside a valid Windows `X:\` or `X:/` drive prefix at index 1)
/// - Non-absolute paths
pub fn validate_cloud_drive_path(raw: &str) -> Result<String, TypeError> {
    if raw.len() > 4096 {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path exceeds 4096 bytes".to_string(),
        });
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path cannot be empty".to_string(),
        });
    }
    if raw != trimmed {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path cannot have leading or trailing whitespace".to_string(),
        });
    }
    if raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path contains NUL or control characters".to_string(),
        });
    }
    if raw.chars().any(|c| {
        matches!(
            c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
        )
    }) {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path contains Unicode bidirectional control characters".to_string(),
        });
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
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path contains percent-encoded traversal or separator sequence".to_string(),
        });
    }

    if raw.starts_with(r"\\") || raw.starts_with("//") {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "UNC and verbatim device paths are rejected".to_string(),
        });
    }

    if raw.contains("..")
        || raw.split(['/', '\\']).any(|seg| seg == "..")
        || Path::new(raw)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Parent directory traversal ('..') is rejected".to_string(),
        });
    }

    // Reject trailing '.' segment (`\.` / `/.`) which aliases the parent directory.
    let trimmed_sep = raw.trim_end_matches(['/', '\\']);
    if trimmed_sep.ends_with("/.") || trimmed_sep.ends_with("\\.") || trimmed_sep == "." {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path cannot end with '.' segment".to_string(),
        });
    }

    // Reject Windows trailing-dot / trailing-space / leading-whitespace segment normalization bypasses.
    for seg in raw.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg != seg.trim() || seg.ends_with('.') || seg.ends_with(' ') {
            return Err(TypeError::InvalidCloudDrivePath {
                path: raw.to_string(),
                reason: "Path segment cannot end with '.' or whitespace".to_string(),
            });
        }
    }

    let bytes = raw.as_bytes();
    let is_windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    let is_unix_abs = raw.starts_with('/');

    // Reject colons outside valid Windows drive index 1 (blocks NTFS Alternate Data Streams and `foo:bar`).
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b':' && !(idx == 1 && is_windows_drive) {
            return Err(TypeError::InvalidCloudDrivePath {
                path: raw.to_string(),
                reason: "Invalid colon or NTFS Alternate Data Stream syntax".to_string(),
            });
        }
    }

    if !is_windows_drive && !is_unix_abs {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path must be absolute".to_string(),
        });
    }

    Ok(raw.to_string())
}

fn is_windows_drive_str(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Normalize an absolute path or prefix for deterministic component-boundary matching.
///
/// - Rejects `\\?\UNC\...` fail-closed.
/// - Strips internal `\\?\` prefix only when followed by a Windows drive root (`X:\` / `X:/`).
/// - Validates via `validate_cloud_drive_path`.
/// - Normalizes separators (`/` -> `\` and ASCII-lowercases on Windows drive paths; `/` and case-preserving on Unix paths),
///   collapses `.` and empty segments, and trims trailing separators (keeping `X:\` or `/`).
pub fn normalize_prefix_for_match(raw: &str) -> Result<String, TypeError> {
    if raw.len() > 4096 {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path exceeds 4096 bytes".to_string(),
        });
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path cannot be empty".to_string(),
        });
    }
    if raw != trimmed {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "Path cannot have leading or trailing whitespace".to_string(),
        });
    }

    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\\?\unc\") || lower.starts_with("//?/unc/") {
        return Err(TypeError::InvalidCloudDrivePath {
            path: raw.to_string(),
            reason: "UNC paths are rejected".to_string(),
        });
    }

    let without_verbatim = if let Some(rest) = raw.strip_prefix(r"\\?\") {
        if is_windows_drive_str(rest) {
            rest
        } else {
            return Err(TypeError::InvalidCloudDrivePath {
                path: raw.to_string(),
                reason: "Unsupported verbatim path prefix".to_string(),
            });
        }
    } else {
        raw
    };

    let validated = validate_cloud_drive_path(without_verbatim)?;

    if is_windows_drive_str(&validated) {
        let drive = validated.as_bytes()[0].to_ascii_lowercase() as char;
        let rest = &validated[3..];
        let mut parts: Vec<String> = Vec::new();
        for seg in rest.split(['\\', '/']) {
            if seg.is_empty() || seg == "." {
                continue;
            }
            parts.push(seg.to_ascii_lowercase());
        }
        if parts.is_empty() {
            Ok(format!("{drive}:\\"))
        } else {
            Ok(format!("{drive}:\\{}", parts.join("\\")))
        }
    } else {
        let mut parts: Vec<&str> = Vec::new();
        for seg in validated.split(['/', '\\']) {
            if seg.is_empty() || seg == "." {
                continue;
            }
            parts.push(seg);
        }
        if parts.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(format!("/{}", parts.join("/")))
        }
    }
}

/// Component-boundary-safe prefix check between two validated absolute paths.
///
/// Ensures e.g. `/Users/alice/OneDrive` does NOT match `/Users/alice/OneDrive - Business/doc.txt`.
pub fn path_matches_prefix(candidate: &str, prefix: &str) -> Result<bool, TypeError> {
    let norm_cand = normalize_prefix_for_match(candidate)?;
    let norm_pref = normalize_prefix_for_match(prefix)?;

    if norm_cand == norm_pref {
        return Ok(true);
    }

    let sep = if is_windows_drive_str(&norm_pref) {
        b'\\'
    } else {
        b'/'
    };
    if norm_pref.as_bytes().last() == Some(&sep) {
        Ok(norm_cand.starts_with(&norm_pref))
    } else {
        Ok(norm_cand.starts_with(&norm_pref)
            && norm_cand.as_bytes().get(norm_pref.len()) == Some(&sep))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_drive_provider_all_8_and_roundtrip() {
        let all = CloudDriveProvider::all();
        assert_eq!(all.len(), 8);
        for provider in all {
            let s = provider.as_str();
            let parsed: CloudDriveProvider = s.parse().expect("roundtrip parse");
            assert_eq!(*provider, parsed);
            assert!(!provider.display_name().is_empty());
            let json = serde_json::to_string(provider).unwrap();
            let de: CloudDriveProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(*provider, de);
        }
        assert!("unknown_cloud".parse::<CloudDriveProvider>().is_err());
    }

    #[test]
    fn test_placeholder_policy_and_settings_defaults_and_validation() {
        assert_eq!(
            CloudPlaceholderMode::default(),
            CloudPlaceholderMode::LocallySyncedOnly
        );
        assert_eq!(
            CloudPlaceholderPolicy::default(),
            CloudPlaceholderPolicy::LocallySyncedOnly
        );

        let settings = CloudDrivesSettings::default();
        assert_eq!(
            settings.placeholder_mode,
            CloudPlaceholderMode::LocallySyncedOnly
        );
        assert_eq!(settings.hydration_max_file_size_mb, 25);
        assert!(settings.drives.is_empty());
        assert_eq!(
            settings.placeholder_policy().unwrap(),
            CloudPlaceholderPolicy::LocallySyncedOnly
        );

        let hydrate =
            CloudPlaceholderPolicy::from_settings(CloudPlaceholderMode::HydrateOnDemand, 25)
                .expect("25 MB valid");
        assert_eq!(
            hydrate,
            CloudPlaceholderPolicy::HydrateOnDemand {
                max_file_size_bytes: 25 * 1024 * 1024
            }
        );

        let zero_err =
            CloudPlaceholderPolicy::from_settings(CloudPlaceholderMode::HydrateOnDemand, 0);
        assert!(matches!(
            zero_err,
            Err(TypeError::InvalidCloudDriveConfig(_))
        ));

        let bad_settings = CloudDrivesSettings {
            placeholder_mode: CloudPlaceholderMode::LocallySyncedOnly,
            hydration_max_file_size_mb: 0,
            drives: Vec::new(),
        };
        assert!(bad_settings.validate().is_err());
    }

    #[test]
    fn test_cloud_drive_entry_defaults_off_and_tier_3() {
        let entry = CloudDriveConfigEntry::new_disabled(
            "google_drive",
            CloudDriveProvider::GoogleDrive,
            "Google Drive",
            Some("G:\\My Drive".to_string()),
            None,
        );
        assert!(!entry.enabled);
        assert_eq!(entry.access_tier, 3);
        assert!(entry.validate().is_ok());

        // Deserializing minimal JSON defaults enabled=false and access_tier=3
        let raw_json = r#"{"id":"dropbox","provider":"dropbox","label":"Dropbox"}"#;
        let de: CloudDriveConfigEntry = serde_json::from_str(raw_json).unwrap();
        assert!(!de.enabled);
        assert_eq!(de.access_tier, 3);

        let mut bad_tier = entry.clone();
        bad_tier.access_tier = 4;
        assert_eq!(bad_tier.validate(), Err(TypeError::InvalidAccessTier(4)));

        let mut bad_path = entry;
        bad_path.custom_paths = vec![r"C:\Users\alice\..\secret".to_string()];
        assert!(matches!(
            bad_path.validate(),
            Err(TypeError::InvalidCloudDrivePath { .. })
        ));
    }

    #[test]
    fn test_validate_cloud_drive_path_fail_closed() {
        // Valid absolute paths
        assert!(validate_cloud_drive_path(r"G:\My Drive").is_ok());
        assert!(validate_cloud_drive_path(r"C:\Users\Alice\OneDrive - Contoso").is_ok());
        assert!(
            validate_cloud_drive_path("/Users/alice/Library/CloudStorage/GoogleDrive-a").is_ok()
        );
        assert!(validate_cloud_drive_path("/home/alice/Dropbox").is_ok());

        // Invalid / adversarial paths
        let bad_paths = [
            "",
            "   ",
            "relative/path",
            r"relative\path",
            "..",
            r"C:\Users\..\secret",
            "/home/alice/../etc/passwd",
            "C:/Users/alice/foo%2e%2ebar",
            "C:/Users/alice/foo%2fbar",
            "C:/Users/alice/foo%5cbar",
            "C:/Users/alice/foo%00bar",
            "C:\\Users\\alice\0secret",
            r"\\server\share\docs",
            "//server/share/docs",
            r"\\?\UNC\server\share",
            r"\\?\C:\Users\alice\OneDrive",
            r"C:\Users\alice\file.txt:secret_ads",
            "foo:bar",
            "C:relative",
        ];
        for p in bad_paths {
            assert!(
                validate_cloud_drive_path(p).is_err(),
                "Expected path '{p}' to fail validation"
            );
        }

        let too_long = format!("/home/{}", "a".repeat(4100));
        assert!(validate_cloud_drive_path(&too_long).is_err());
    }

    #[test]
    fn test_normalize_and_path_matches_prefix_boundaries() {
        // Windows mixed slashes, verbatim prefix, trailing slash, case insensitivity
        assert!(path_matches_prefix(
            r"\\?\C:\Users\Alice\OneDrive\Docs\report.pdf",
            r"c:/users/alice/onedrive/"
        )
        .unwrap());

        // Sibling directory must NOT match!
        assert!(!path_matches_prefix(
            r"C:\Users\Alice\OneDrive - Business\secret.docx",
            r"C:\Users\Alice\OneDrive"
        )
        .unwrap());

        // Exact match
        assert!(path_matches_prefix("/home/alice/Nextcloud", "/home/alice/Nextcloud/").unwrap());

        // Unix case preservation and boundary check
        assert!(
            !path_matches_prefix("/home/alice/Nextcloud2/file.txt", "/home/alice/Nextcloud")
                .unwrap()
        );
        assert!(
            !path_matches_prefix("/home/alice/nextcloud/file.txt", "/home/alice/Nextcloud")
                .unwrap()
        );
    }

    #[test]
    fn test_validate_and_normalize_reject_trailing_dot_space_double_encoding_and_bidi() {
        // Windows Win32 trailing-dot / trailing-space / leading-whitespace segment bypasses
        let bypass_paths = [
            r"C:\Users\Alice\OneDrive.",
            r"C:\Users\Alice\OneDrive.\sub",
            r"C:\Users\Alice\OneDrive \sub",
            r"C:\Users\Alice\OneDrive ",
            r" C:\Users\Alice\OneDrive",
            r"C:\Users\Alice\OneDrive\ . ",
            r"C:\Users\Alice\OneDrive\ .",
            r"C:\Users\Alice\OneDrive\. ",
            r"C:\Users\Alice\ OneDrive\sub",
            // Double-percent-encoded traversal / separators / NUL (mixed case)
            r"C:\Users\%252e%252e\secret",
            r"C:\Users\%252E%252E\secret",
            "C:/Users/alice/foo%252fbar",
            "C:/Users/alice/foo%252Fbar",
            "C:/Users/alice/foo%255cbar",
            "C:/Users/alice/foo%255Cbar",
            "C:/Users/alice/foo%2500bar",
            // Unicode bidi override / control characters
            "C:\\Users\\Alice\\bidi\u{202E}txt",
            "C:\\Users\\Alice\\bidi\u{202A}dir",
            "C:\\Users\\Alice\\bidi\u{2066}dir",
            "C:\\Users\\Alice\\bidi\u{2069}dir",
            "C:\\Users\\Alice\\bidi\u{200E}dir",
            "C:\\Users\\Alice\\bidi\u{200F}dir",
        ];
        for p in bypass_paths {
            assert!(
                matches!(
                    validate_cloud_drive_path(p),
                    Err(TypeError::InvalidCloudDrivePath { .. })
                ),
                "Expected validate_cloud_drive_path to reject '{p}'"
            );
            assert!(
                matches!(
                    normalize_prefix_for_match(p),
                    Err(TypeError::InvalidCloudDrivePath { .. })
                ),
                "Expected normalize_prefix_for_match to reject '{p}'"
            );
        }

        // Stripped \\?\ verbatim paths must undergo the exact same segment trailing-dot/space & bidi checks
        let verbatim_bypasses = [
            r"\\?\C:\Users\Alice\OneDrive.",
            r"\\?\C:\Users\Alice\OneDrive.\sub",
            r"\\?\C:\Users\Alice\OneDrive \sub",
            r"\\?\C:\Users\Alice\OneDrive ",
            r"\\?\C:\Users\Alice\OneDrive\ . ",
            r"\\?\C:\Users\%252e%252e\secret",
            "\\\\?\\C:\\Users\\Alice\\bidi\u{202E}txt",
        ];
        for p in verbatim_bypasses {
            assert!(
                matches!(
                    normalize_prefix_for_match(p),
                    Err(TypeError::InvalidCloudDrivePath { .. })
                ),
                "Expected normalize_prefix_for_match to reject verbatim path '{p}'"
            );
            assert!(
                path_matches_prefix(p, r"C:\Users\Alice\OneDrive").is_err(),
                "Expected path_matches_prefix to fail closed on '{p}'"
            );
        }

        // Raw length > 4096 bytes padded with leading/trailing spaces must fail BEFORE trim
        let padded_over_4096 = format!("{}C:\\Users\\Alice\\OneDrive", " ".repeat(5000));
        assert!(matches!(
            validate_cloud_drive_path(&padded_over_4096),
            Err(TypeError::InvalidCloudDrivePath { .. })
        ));
        assert!(matches!(
            normalize_prefix_for_match(&padded_over_4096),
            Err(TypeError::InvalidCloudDrivePath { .. })
        ));

        // Legitimate '.' segment and dotfiles must still be accepted
        assert!(validate_cloud_drive_path(r"C:\Users\Alice\.\OneDrive").is_ok());
        assert!(validate_cloud_drive_path("/home/alice/.dropbox").is_ok());
        assert!(validate_cloud_drive_path(r"C:\Users\Alice\OneDrive\file.txt").is_ok());
    }

    #[test]
    fn t5_validate_cloud_drive_path_rejects_trailing_dot_segment() {
        for trailing_dot in [
            r"C:\Users\Alice\OneDrive\.",
            r"C:\Users\Alice\OneDrive\.\",
            "C:/Users/Alice/OneDrive/.",
            "C:/Users/Alice/OneDrive/./",
            "/home/alice/Dropbox/.",
            "/home/alice/Dropbox/./",
        ] {
            assert!(
                matches!(
                    validate_cloud_drive_path(trailing_dot),
                    Err(TypeError::InvalidCloudDrivePath { .. })
                ),
                "Expected validate_cloud_drive_path to reject trailing dot segment '{trailing_dot}'"
            );
            assert!(
                matches!(
                    normalize_prefix_for_match(trailing_dot),
                    Err(TypeError::InvalidCloudDrivePath { .. })
                ),
                "Expected normalize_prefix_for_match to reject trailing dot segment '{trailing_dot}'"
            );
        }
    }
}
