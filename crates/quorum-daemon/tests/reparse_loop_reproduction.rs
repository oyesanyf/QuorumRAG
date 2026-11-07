//! Milestone M25 Reparse Loop Reproduction Test Suite
//! Genuinely verifies that NTFS directory junctions pointing to profile root
//! or parent directories are strictly rejected.

use quorum_ingest::IngestConfig;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    key: &'static str,
    original_value: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, new_value: &str) -> Self {
        let original_value = std::env::var(key).ok();
        std::env::set_var(key, new_value);
        Self {
            key,
            original_value,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(ref val) = self.original_value {
            std::env::set_var(self.key, val);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[cfg(target_os = "windows")]
fn create_junction(junction: &Path, target: &Path) -> std::io::Result<()> {
    let output = std::process::Command::new("cmd.exe")
        .args([
            "/c",
            "mklink",
            "/J",
            junction.to_str().expect("junction to str"),
            target.to_str().expect("target to str"),
        ])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "mklink failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
#[test]
fn test_rejection_of_onedrive_documents_pointing_to_profile_root() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp = tempdir().expect("tempdir");
    let users_dir = temp.path().join("Users");
    std::fs::create_dir_all(&users_dir).expect("create Users dir");

    let cloud_user = users_dir.join("CloudUser");
    let onedrive = cloud_user.join("OneDrive");
    let onedrive_docs = onedrive.join("Documents");
    let onedrive_desktop = onedrive.join("Desktop");

    std::fs::create_dir_all(&onedrive).expect("create onedrive dir");
    std::fs::create_dir_all(&onedrive_desktop).expect("create onedrive desktop");

    // Create OneDrive\Documents as an NTFS junction pointing back to CloudUser (cyclic loop)
    create_junction(&onedrive_docs, &cloud_user).expect("create cyclic junction loop");

    let temp_root_str = temp.path().to_str().expect("temp path to str");
    let _env_guard = EnvGuard::set("SystemDrive", temp_root_str);

    let discovered = IngestConfig::discover_user_document_roots();

    let synthetic_roots: Vec<PathBuf> = discovered
        .into_iter()
        .filter(|p| p.starts_with(&users_dir))
        .collect();

    let _ = std::fs::remove_dir(&onedrive_docs);

    assert!(
        !synthetic_roots.contains(&onedrive_docs),
        "CRITICAL BUG: Cyclic junction {:?} pointing back to profile root {:?} was NOT rejected! Discovered roots: {:?}",
        onedrive_docs,
        cloud_user,
        synthetic_roots
    );
    assert!(
        synthetic_roots.contains(&onedrive_desktop),
        "Must contain non-cyclic CloudUser/OneDrive/Desktop"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_rejection_of_standard_documents_pointing_to_parent_or_root() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp = tempdir().expect("tempdir");
    let users_dir = temp.path().join("Users");
    std::fs::create_dir_all(&users_dir).expect("create Users dir");

    let user_a = users_dir.join("UserA");
    let user_a_docs = user_a.join("Documents");
    let user_a_desktop = user_a.join("Desktop");

    std::fs::create_dir_all(&user_a).expect("create user_a dir");
    std::fs::create_dir_all(&user_a_desktop).expect("create user_a desktop");

    // Create UserA\Documents as an NTFS junction pointing back to parent profile root (UserA)
    create_junction(&user_a_docs, &user_a).expect("create cyclic junction loop");

    let temp_root_str = temp.path().to_str().expect("temp path to str");
    let _env_guard = EnvGuard::set("SystemDrive", temp_root_str);

    let discovered = IngestConfig::discover_user_document_roots();

    let synthetic_roots: Vec<PathBuf> = discovered
        .into_iter()
        .filter(|p| p.starts_with(&users_dir))
        .collect();

    let _ = std::fs::remove_dir(&user_a_docs);

    assert!(
        !synthetic_roots.contains(&user_a_docs),
        "CRITICAL BUG: Cyclic junction Documents pointing to parent was NOT rejected! Discovered roots: {:?}",
        synthetic_roots
    );
    assert!(
        synthetic_roots.contains(&user_a_desktop),
        "Must contain non-cyclic UserA/Desktop"
    );
}
