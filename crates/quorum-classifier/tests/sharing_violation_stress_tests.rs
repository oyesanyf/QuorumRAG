//! Adversarial empirical tests for Windows Error 32 (Sharing Violation) resilience.
//!
//! Validates:
//! 1. `FileTypeClassifier::open_file_with_retry` recovers when active lock is released during backoff.
//! 2. `FileTypeClassifier::open_file_with_retry` fails cleanly when lock is held beyond backoff window.
//! 3. `FileTypeClassifier::classify_file` succeeds transparently through sharing violation retries.

use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;
use tempfile::tempdir;

use quorum_classifier::{FileCategory, FileTypeClassifier};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[test]
fn test_windows_error_32_retry_recovers_when_lock_released() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("code_sample.rs");
    let content = "fn main() { println!(\"QuorumRAG Error 32 Recovery\"); }";
    std::fs::write(&path, content).unwrap();

    #[cfg(windows)]
    {
        let lock_holder_path = path.clone();
        let (tx_ready, rx_ready) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            let exclusive_file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0) // Win32 FILE_SHARE_NONE -> Error 32 for any concurrent open
                .open(&lock_holder_path)
            {
                Ok(f) => {
                    tx_ready.send(true).unwrap();
                    f
                }
                Err(e) => {
                    tx_ready.send(false).unwrap();
                    panic!("Failed to acquire exclusive lock: {}", e);
                }
            };

            // Hold lock for 40ms: attempt 0 (0ms) and attempt 1 (25ms) will fail,
            // attempt 2 (75ms) will succeed after lock is dropped at 40ms.
            std::thread::sleep(Duration::from_millis(40));
            drop(exclusive_file);
        });

        // Wait until background thread confirms lock is held
        let lock_ok = rx_ready
            .recv_timeout(Duration::from_secs(3))
            .expect("Timed out waiting for lock acquisition");
        assert!(lock_ok, "Background thread failed to acquire exclusive lock");

        // Call open_file_with_retry while lock is initially active
        let file_res = FileTypeClassifier::open_file_with_retry(&path);
        handle.join().unwrap();

        assert!(
            file_res.is_ok(),
            "open_file_with_retry must recover once lock is released within backoff window: {:?}",
            file_res.err()
        );

        let mut read_buf = String::new();
        file_res.unwrap().read_to_string(&mut read_buf).unwrap();
        assert_eq!(read_buf, content);

        // Verify classify_file also succeeds
        let classifier = FileTypeClassifier::new();
        let id_res = classifier.classify_file(&path);
        assert!(id_res.is_ok(), "classify_file must succeed: {:?}", id_res.err());
        assert_eq!(id_res.unwrap().category, FileCategory::Code);
    }
}

#[test]
fn test_windows_error_32_retry_fails_cleanly_when_lock_held_persistently() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("persistently_locked.txt");
    std::fs::write(&path, b"locked content").unwrap();

    #[cfg(windows)]
    {
        let lock_holder_path = path.clone();
        let (tx_ready, rx_ready) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            let exclusive_file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0) // Win32 FILE_SHARE_NONE
                .open(&lock_holder_path)
            {
                Ok(f) => {
                    tx_ready.send(true).unwrap();
                    f
                }
                Err(e) => {
                    tx_ready.send(false).unwrap();
                    panic!("Failed to acquire exclusive lock: {}", e);
                }
            };

            // Hold lock for 500ms (exceeding total backoff window: 25ms + 50ms + 100ms = 175ms)
            std::thread::sleep(Duration::from_millis(500));
            drop(exclusive_file);
        });

        let lock_ok = rx_ready
            .recv_timeout(Duration::from_secs(3))
            .expect("Timed out waiting for lock acquisition");
        assert!(lock_ok, "Background thread failed to acquire exclusive lock");

        let res = FileTypeClassifier::open_file_with_retry(&path);
        handle.join().unwrap();

        assert!(
            res.is_err(),
            "open_file_with_retry must fail when lock is held persistently beyond retry window"
        );
        let err = res.err().unwrap();
        let is_sharing_violation = err.raw_os_error() == Some(32)
            || err.kind() == std::io::ErrorKind::PermissionDenied;
        assert!(
            is_sharing_violation,
            "Error must be Windows Error 32 or PermissionDenied, got {:?}",
            err
        );
    }
}
