//! Integration tests for Milestone M19:
//! Automatic Indexing on MSI Installation, Session 0 User Profile Discovery & Dedup Persistence.

use clap::Parser;
use quorum_daemon::Cli;
use quorum_ingest::{
    DedupAction, FileCatalogEntry, IngestConfig, TwoLevelDedupEngine,
};
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard to safely set and restore an environment variable across test execution.
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


/// 1. Headless Session 0 Profile Discovery:
/// Must discover human user document roots, strictly filtering out
/// system profiles (systemprofile, localservice, networkservice, default, public),
/// junctions/reparse points (All Users, Default User), hidden directories, and non-directories.
#[test]
fn test_discover_user_document_roots_filters_system_profiles_and_junctions() {
    let _lock = ENV_LOCK.lock().unwrap();
    let discovered = IngestConfig::discover_user_document_roots();

    // On Windows development machines, human profile roots (Documents, Desktop, Downloads) must be found
    #[cfg(target_os = "windows")]
    {
        assert!(
            !discovered.is_empty(),
            "Session 0 discovery must return at least one valid user document root on Windows"
        );

        const FORBIDDEN_PROFILE_SUBSTRINGS: &[&str] = &[
            "systemprofile",
            "localservice",
            "networkservice",
            "defaultapppool",
            "wdigest",
            "desktop.ini",
            "ntuser.dat",
        ];

        for root in &discovered {
            assert!(root.exists(), "Discovered path must exist: {:?}", root);
            assert!(root.is_dir(), "Discovered path must be a directory: {:?}", root);

            let lower = root.to_string_lossy().to_ascii_lowercase();
            for forbidden in FORBIDDEN_PROFILE_SUBSTRINGS {
                assert!(
                    !lower.contains(forbidden),
                    "Discovered root {:?} contains forbidden system profile string: '{}'",
                    root,
                    forbidden
                );
            }

            // Verify the discovered directory is NOT a symlink
            let sym_meta = std::fs::symlink_metadata(root)
                .unwrap_or_else(|e| panic!("Failed to read symlink metadata for {:?}: {}", root, e));
            assert!(
                !sym_meta.file_type().is_symlink(),
                "Discovered root {:?} must not be a symlink",
                root
            );

            // Under Milestone M25, directory reparse points for OneDrive and cloud-sync user folders
            // ARE supported. Verify that if a reparse point is returned, it is a genuine traversable
            // directory that resolves cleanly without cyclic loops.
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if (sym_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                let canon = std::fs::canonicalize(root)
                    .unwrap_or_else(|e| panic!("Reparse point root {:?} failed canonicalize: {}", root, e));
                assert!(canon.is_dir(), "Reparse point canonical target must be a directory: {:?}", canon);
                assert!(std::fs::read_dir(&canon).is_ok(), "Reparse point canonical target must be readable: {:?}", canon);
            }
        }

        // Verify that roots do not contain raw 'All Users' or 'Default User'
        for root in &discovered {
            let lower = root.to_string_lossy().to_ascii_lowercase();
            assert!(
                !lower.contains(r"\all users\") && !lower.ends_with(r"\all users"),
                "Discovered root {:?} must not be 'All Users' junction",
                root
            );
            assert!(
                !lower.contains(r"\default user\") && !lower.ends_with(r"\default user"),
                "Discovered root {:?} must not be 'Default User' junction",
                root
            );
        }
    }

    // De-duplication check: all returned paths must be unique
    let mut seen = HashSet::new();
    for root in &discovered {
        assert!(
            seen.insert(root.clone()),
            "Duplicate root returned by discover_user_document_roots: {:?}",
            root
        );
    }
}

/// 2. Dedup Catalog Disk Persistence:
/// Tests atomic file saving, loading, and Level-1 fast path 0-disk-read hit roundtrip.
#[test]
fn test_two_level_dedup_catalog_disk_persistence_roundtrip() {
    let temp = tempdir().expect("tempdir creation");
    let test_dir = temp.path();

    // Create 3 genuine sample files
    let f1_path = test_dir.join("Quarterly_Report_2026.docx");
    let f2_path = test_dir.join("System_Architecture_Blueprint.pdf");
    let f3_path = test_dir.join("Network_Security_Audit.txt");

    {
        let mut f1 = File::create(&f1_path).expect("create f1");
        f1.write_all(b"QuorumRAG Quarterly Report Q4 2026 Content").expect("write f1");

        let mut f2 = File::create(&f2_path).expect("create f2");
        f2.write_all(b"QuorumRAG System Architecture Specification").expect("write f2");

        let mut f3 = File::create(&f3_path).expect("create f3");
        f3.write_all(b"Network Security Audit Findings 2026").expect("write f3");
    }

    let meta1 = std::fs::metadata(&f1_path).expect("meta1");
    let meta2 = std::fs::metadata(&f2_path).expect("meta2");
    let meta3 = std::fs::metadata(&f3_path).expect("meta3");

    let mtime1 = meta1
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let size1 = meta1.len();

    let mtime2 = meta2
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let size2 = meta2.len();

    let mtime3 = meta3
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let size3 = meta3.len();

    // Populate Engine 1
    let engine1 = TwoLevelDedupEngine::new();
    engine1.register_entry(FileCatalogEntry {
        file_path: f1_path.clone(),
        file_blake3: "blake3_hash_report_001".to_string(),
        mtime_secs: mtime1,
        size_bytes: size1,
        chunk_hashes: vec!["c1".to_string(), "c2".to_string()],
    });
    engine1.register_entry(FileCatalogEntry {
        file_path: f2_path.clone(),
        file_blake3: "blake3_hash_arch_002".to_string(),
        mtime_secs: mtime2,
        size_bytes: size2,
        chunk_hashes: vec!["c3".to_string(), "c4".to_string()],
    });
    engine1.register_entry(FileCatalogEntry {
        file_path: f3_path.clone(),
        file_blake3: "blake3_hash_audit_003".to_string(),
        mtime_secs: mtime3,
        size_bytes: size3,
        chunk_hashes: vec!["c5".to_string()],
    });

    assert_eq!(engine1.get_all_tracked_files().len(), 3);

    // Save catalog to disk
    let catalog_path = test_dir.join("catalog_data").join("dedup_catalog.json");
    engine1
        .save_catalog_to_file(&catalog_path)
        .expect("save_catalog_to_file should succeed");
    assert!(catalog_path.exists(), "Persisted catalog file must exist on disk");

    // Engine 2: fresh instance loads from disk
    let engine2 = TwoLevelDedupEngine::new();
    assert_eq!(engine2.get_all_tracked_files().len(), 0);

    engine2
        .load_catalog_from_file(&catalog_path)
        .expect("load_catalog_from_file should succeed");
    assert_eq!(engine2.get_all_tracked_files().len(), 3);

    // Level-1 fast path evaluation: unchanged mtime + size must produce DedupAction::Unchanged
    let action1 = engine2
        .evaluate_file(&f1_path, mtime1, size1)
        .expect("evaluate_file f1");
    assert!(
        matches!(action1, DedupAction::Unchanged { .. }),
        "Engine 2 must hit fast path for unchanged f1, got {:?}",
        action1
    );

    let action2 = engine2
        .evaluate_file(&f2_path, mtime2, size2)
        .expect("evaluate_file f2");
    assert!(
        matches!(action2, DedupAction::Unchanged { .. }),
        "Engine 2 must hit fast path for unchanged f2, got {:?}",
        action2
    );

    // Modified file: different mtime/size triggers ModifiedOrNew
    let action_mod = engine2
        .evaluate_file(&f3_path, mtime3 + 500, size3 + 1024)
        .expect("evaluate_file modified");
    assert!(
        matches!(action_mod, DedupAction::ModifiedOrNew { .. }),
        "Modified file must trigger ModifiedOrNew, got {:?}",
        action_mod
    );

    // Atomic overwrite: saving again to existing file must succeed without permission errors
    engine2
        .save_catalog_to_file(&catalog_path)
        .expect("Overwriting existing catalog file must succeed atomically");
}

/// 3. Unconditional Indexing Watch Paths Resolution:
/// When `--watch-dir` is not explicitly passed, watch paths resolution must
/// default to discovered user document roots + physical fixed drives without hardcoded developer paths.
#[test]
fn test_unconditional_indexing_watch_paths_resolution_without_cli_watch_dir() {
    let _lock = ENV_LOCK.lock().unwrap();
    // A. Parse CLI without --watch-dir
    let cli_default = Cli::parse_from(["quorumrag", "--no-browser", "--port", "3031"]);
    assert!(
        cli_default.watch_dir.is_none(),
        "CLI without --watch-dir must have None for watch_dir"
    );

    // Resolve default watch paths using the production daemon logic
    let mut ingest_config = IngestConfig::default();
    let resolved_paths: Vec<PathBuf> = if let Some(ref watch_path) = cli_default.watch_dir {
        vec![watch_path.clone()]
    } else {
        let user_roots = IngestConfig::discover_user_document_roots();
        let physical_drives = IngestConfig::discover_physical_drives();
        let mut default_paths = user_roots;
        for d in physical_drives {
            if !default_paths.contains(&d) {
                default_paths.push(d);
            }
        }
        default_paths
    };
    ingest_config.watch_paths = resolved_paths;

    assert!(
        !ingest_config.watch_paths.is_empty(),
        "Resolved watch paths must not be empty on host system"
    );

    // Assert that hardcoded developer paths are completely gone
    for p in &ingest_config.watch_paths {
        let path_str = p.to_string_lossy();
        assert!(
            !path_str.contains("Femi_Oyesanya_CV_2026.pdf"),
            "Hardcoded developer path must not exist in watch_paths: {:?}",
            path_str
        );
        assert!(
            !path_str.contains("AI Job Loss Alternatives.docx"),
            "Hardcoded developer path must not exist in watch_paths: {:?}",
            path_str
        );
        assert!(
            !path_str.contains("ChatGPT_Restored_Data"),
            "Hardcoded developer path must not exist in watch_paths: {:?}",
            path_str
        );
    }

    // B. Parse CLI with explicit --watch-dir
    let custom_dir = tempdir().expect("tempdir");
    let custom_path = custom_dir.path().to_path_buf();
    let custom_str = custom_path.to_string_lossy().to_string();

    let cli_custom = Cli::parse_from(["quorumrag", "--watch-dir", &custom_str]);
    assert_eq!(
        cli_custom.watch_dir,
        Some(custom_path.clone()),
        "Explicit --watch-dir must be preserved"
    );

    let mut custom_ingest_config = IngestConfig::default();
    if let Some(ref watch_path) = cli_custom.watch_dir {
        custom_ingest_config.watch_paths.push(watch_path.clone());
    }

    assert_eq!(custom_ingest_config.watch_paths.len(), 1);
    assert_eq!(custom_ingest_config.watch_paths[0], custom_path);
}

/// 4. Adversarial Challenge 1: Dedup Catalog Multi-Cycle Persistence & Concurrency Stress Test
/// - Registers 50 diverse catalog entries with distinct BLAKE3 hashes, mtimes, sizes, chunk hashes, and paths.
/// - Saves to disk, spawns a fresh engine, loads from file, and asserts 100% field-level equality.
/// - Performs multi-cycle mutation (updating entries, adding entries, saving).
/// - Concurrently performs repeated overwrite saves on a writer thread while 4 reader threads
///   continuously load and validate the catalog, asserting that atomic file replacement on Windows
///   NEVER corrupts, truncates, or produces invalid JSON data (`ErrorKind::InvalidData`).
#[test]
fn test_adversarial_dedup_catalog_multi_cycle_persistence_and_concurrency() {
    let temp = tempdir().expect("tempdir");
    let test_dir = temp.path();
    let catalog_path = test_dir.join("adversarial_catalog.json");

    // Phase 1: Register 50 diverse catalog entries
    let engine1 = TwoLevelDedupEngine::new();
    let mut initial_entries = Vec::new();
    for i in 0..50 {
        let entry = FileCatalogEntry {
            file_path: test_dir.join(format!("doc_category_{}", i % 5)).join(format!("file_{:03}.pdf", i)),
            file_blake3: format!("{:064x}", i * 1337 + 42),
            mtime_secs: 1700000000 + (i as i64 * 60),
            size_bytes: (i as u64 + 1) * 8192,
            chunk_hashes: vec![
                format!("chunk_hash_{}_a", i),
                format!("chunk_hash_{}_b", i),
                format!("chunk_hash_{}_c", i),
            ],
        };
        initial_entries.push(entry.clone());
        engine1.register_entry(entry);
    }

    assert_eq!(engine1.get_all_tracked_files().len(), 50);

    // Save Phase 1
    engine1
        .save_catalog_to_file(&catalog_path)
        .expect("save_catalog_to_file should succeed");
    assert!(catalog_path.exists(), "Persisted catalog file must exist on disk");

    // Phase 2: Fresh engine loads and verifies 100% field equality
    let engine2 = TwoLevelDedupEngine::new();
    engine2
        .load_catalog_from_file(&catalog_path)
        .expect("fresh engine load_catalog_from_file should succeed");
    assert_eq!(engine2.get_all_tracked_files().len(), 50);

    for original in &initial_entries {
        let loaded = engine2
            .get_file_entry(&original.file_path)
            .unwrap_or_else(|| panic!("Missing entry for path: {:?}", original.file_path));

        assert_eq!(
            loaded.file_blake3, original.file_blake3,
            "BLAKE3 hash mismatch for {:?}",
            original.file_path
        );
        assert_eq!(
            loaded.mtime_secs, original.mtime_secs,
            "mtime mismatch for {:?}",
            original.file_path
        );
        assert_eq!(
            loaded.size_bytes, original.size_bytes,
            "size mismatch for {:?}",
            original.file_path
        );
        assert_eq!(
            loaded.chunk_hashes, original.chunk_hashes,
            "chunk hashes mismatch for {:?}",
            original.file_path
        );
    }

    // Phase 3: Multi-cycle mutations across distinct engine instances
    // Cycle 1: Update existing entries
    for i in 0..10 {
        let mut updated = initial_entries[i].clone();
        updated.mtime_secs += 500;
        updated.size_bytes += 1024;
        updated.file_blake3 = format!("{:064x}", i * 9999 + 77);
        engine2.register_entry(updated);
    }
    // Cycle 2: Add 25 new entries
    for i in 50..75 {
        let new_entry = FileCatalogEntry {
            file_path: test_dir.join(format!("cycle2_file_{:03}.docx", i)),
            file_blake3: format!("{:064x}", i * 777 + 9),
            mtime_secs: 1710000000 + (i as i64 * 30),
            size_bytes: (i as u64 + 1) * 4096,
            chunk_hashes: vec![format!("chunk_hash_c2_{}", i)],
        };
        engine2.register_entry(new_entry);
    }
    assert_eq!(engine2.get_all_tracked_files().len(), 75);
    engine2
        .save_catalog_to_file(&catalog_path)
        .expect("cycle 2 save should succeed");

    // Engine 3 verifies cycle 2 roundtrip
    let engine3 = TwoLevelDedupEngine::new();
    engine3
        .load_catalog_from_file(&catalog_path)
        .expect("engine 3 load should succeed");
    assert_eq!(engine3.get_all_tracked_files().len(), 75);

    // Phase 4: Repeated overwrite saves with concurrent reads (stress harness)
    let running = Arc::new(AtomicBool::new(true));
    let read_successes = Arc::new(AtomicUsize::new(0));
    let shared_catalog_path = catalog_path.clone();

    // Spawn 4 reader threads
    let mut reader_handles = Vec::new();
    for reader_id in 0..4 {
        let running_clone = Arc::clone(&running);
        let read_successes_clone = Arc::clone(&read_successes);
        let path_clone = shared_catalog_path.clone();

        let handle = thread::spawn(move || {
            let mut iterations = 0;
            while running_clone.load(Ordering::Relaxed) {
                iterations += 1;
                let reader_engine = TwoLevelDedupEngine::new();
                match reader_engine.load_catalog_from_file(&path_clone) {
                    Ok(()) => {
                        let count = reader_engine.get_all_tracked_files().len();
                        assert!(
                            count >= 75,
                            "Reader {} iteration {} loaded partial catalog with only {} entries",
                            reader_id,
                            iterations,
                            count
                        );
                        read_successes_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        // Atomic replacement MUST NEVER leave a partially-written or corrupt JSON file.
                        // io::ErrorKind::InvalidData indicates serde_json syntax/truncation failure.
                        assert_ne!(
                            e.kind(),
                            std::io::ErrorKind::InvalidData,
                            "Dedup catalog JSON corruption / truncation detected during concurrent read in reader {}: {}",
                            reader_id,
                            e
                        );
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });
        reader_handles.push(handle);
    }

    // Main writer thread: 30 consecutive overwrite save cycles with incremental mutations
    let writer_engine = engine3;
    for cycle in 0..30 {
        let additional_entry = FileCatalogEntry {
            file_path: test_dir.join(format!("stress_concurrency_{:03}.txt", cycle)),
            file_blake3: format!("{:064x}", cycle * 5555 + 123),
            mtime_secs: 1720000000 + (cycle as i64 * 10),
            size_bytes: (cycle as u64 + 10) * 1024,
            chunk_hashes: vec![format!("chunk_stress_{}", cycle)],
        };
        writer_engine.register_entry(additional_entry);
        writer_engine
            .save_catalog_to_file(&catalog_path)
            .expect("save_catalog_to_file during stress must succeed");

        thread::sleep(Duration::from_millis(4));
    }

    // Stop readers and join
    running.store(false, Ordering::Relaxed);
    for handle in reader_handles {
        handle.join().expect("reader thread should join cleanly");
    }

    let total_successful_reads = read_successes.load(Ordering::SeqCst);
    assert!(
        total_successful_reads > 0,
        "Expected at least one successful concurrent read, got 0"
    );

    // Final integrity verification
    let engine_final = TwoLevelDedupEngine::new();
    engine_final
        .load_catalog_from_file(&catalog_path)
        .expect("final engine load should succeed");
    assert_eq!(
        engine_final.get_all_tracked_files().len(),
        75 + 30,
        "Final engine should have exactly 105 entries"
    );
}

/// 5. Adversarial Challenge 2: Verification of main.rs Unconditional Auto-Indexing Watch Paths
/// - Evaluates multiple CLI configurations where `cli.watch_dir == None`.
/// - Verifies that `ingest_config.watch_paths` contains:
///   1. Every user document root discovered by `discover_user_document_roots()`.
///   2. Every physical drive discovered by `discover_physical_drives()`.
/// - Asserts that `watch_paths` is never empty.
/// - Asserts that no hardcoded developer usernames or paths exist in `watch_paths`.
#[test]
fn test_adversarial_unconditional_watch_paths_contain_roots_and_drives() {
    let _lock = ENV_LOCK.lock().unwrap();
    let test_cli_invocations = vec![
        vec!["quorumrag"],
        vec!["quorumrag", "--no-browser"],
        vec!["quorumrag", "--port", "4040"],
        vec!["quorumrag", "--host", "127.0.0.1", "--no-browser", "--port", "3031"],
        vec!["quorumrag", "--service"],
    ];

    for args in test_cli_invocations {
        let cli = Cli::parse_from(args);
        assert!(
            cli.watch_dir.is_none(),
            "CLI invocation {:?} must have watch_dir == None",
            cli
        );

        // Execute exact production daemon logic from crates/quorum-daemon/src/main.rs:160-180
        let mut ingest_config = IngestConfig::default();
        ingest_config.exclude_source_code = true;
        ingest_config.max_file_size_bytes = 15 * 1024 * 1024;

        if let Some(ref watch_path) = cli.watch_dir {
            ingest_config.watch_paths.push(watch_path.clone());
        } else {
            let user_roots = IngestConfig::discover_user_document_roots();
            let physical_drives = IngestConfig::discover_physical_drives();
            let mut default_paths = user_roots;
            for d in physical_drives {
                if !default_paths.contains(&d) {
                    default_paths.push(d);
                }
            }
            ingest_config.watch_paths = default_paths;
        }

        // Invariant 1: watch_paths must NEVER be empty
        assert!(
            !ingest_config.watch_paths.is_empty(),
            "ingest_config.watch_paths must not be empty when cli.watch_dir == None"
        );

        // Invariant 2: All discovered user document roots must be present
        let user_roots = IngestConfig::discover_user_document_roots();
        for root in &user_roots {
            assert!(
                ingest_config.watch_paths.contains(root),
                "watch_paths missing discovered user document root: {:?}",
                root
            );
        }

        // Invariant 3: All discovered physical drives must be present
        let physical_drives = IngestConfig::discover_physical_drives();
        for drive in &physical_drives {
            assert!(
                ingest_config.watch_paths.contains(drive),
                "watch_paths missing discovered physical drive: {:?}",
                drive
            );
        }

        // Invariant 4: No paths may be hardcoded developer paths or user names
        for path in &ingest_config.watch_paths {
            let s = path.to_string_lossy().to_ascii_lowercase();
            assert!(
                !s.contains("femi_oyesanya"),
                "watch_paths contains hardcoded developer name: {:?}",
                path
            );
            assert!(
                !s.contains("chatgpt3"),
                "watch_paths contains hardcoded developer path: {:?}",
                path
            );
            assert!(
                !s.contains("d:\\femi"),
                "watch_paths contains hardcoded developer path: {:?}",
                path
            );
            assert!(
                !s.contains("ai job loss alternatives"),
                "watch_paths contains hardcoded file: {:?}",
                path
            );

            // Invariant 5: All watch paths must be absolute
            assert!(
                path.is_absolute(),
                "watch_paths entry must be an absolute path: {:?}",
                path
            );
        }
    }
}

// ============================================================================
// Adversarial Challenger Test Harness for Session 0 User Profile Discovery & Junctions
// ============================================================================

#[cfg(target_os = "windows")]
fn set_file_attributes(path: &std::path::Path, attrs: u32) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    extern "system" {
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    }
    let ret = unsafe { SetFileAttributesW(wide.as_ptr(), attrs) };
    if ret == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn create_junction(junction: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
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

/// 6. Adversarial Challenge 1: Synthetic Mock Filesystem Structures
/// - Normal user folder with Documents, Desktop, Downloads.
/// - Known system profile names (`Default`, `All Users`, `Public`, `SystemProfile`, `LocalService`, `Default User`, `NetworkService`, `DefaultAppPool`, `wdigest`).
/// - Hidden directories (`FILE_ATTRIBUTE_HIDDEN (0x02)`).
/// - System directories (`FILE_ATTRIBUTE_SYSTEM (0x04)`).
/// - Non-directory files (`desktop.ini`, `NTUSER.DAT`, `normal_file.txt`).
/// - Special dot and dollar directories (`.dotfolder`, `$RECYCLE.BIN`).
/// - NTFS Junctions (`JunctionUser` pointing to `NormalUser`).
/// Asserts that:
/// - ONLY genuine human user document folders are returned.
/// - ZERO system profiles, ZERO hidden folders, ZERO system folders, ZERO files, ZERO junctions, and ZERO dot/dollar dirs are included.
#[cfg(target_os = "windows")]
#[test]
fn test_adversarial_synthetic_profile_discovery_filters_system_and_junctions() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp = tempdir().expect("tempdir");
    let users_dir = temp.path().join("Users");
    std::fs::create_dir_all(&users_dir).expect("create Users dir");

    // 1. Genuine human user: "NormalUser" with standard document subfolders
    let normal_user = users_dir.join("NormalUser");
    let normal_docs = normal_user.join("Documents");
    let normal_desktop = normal_user.join("Desktop");
    let normal_downloads = normal_user.join("Downloads");
    std::fs::create_dir_all(&normal_docs).expect("create normal docs");
    std::fs::create_dir_all(&normal_desktop).expect("create normal desktop");
    std::fs::create_dir_all(&normal_downloads).expect("create normal downloads");
    std::fs::write(normal_docs.join("resume.txt"), b"My resume").expect("write normal doc");

    // 2. Known system profile directories
    let system_profile_names = [
        "Default",
        "All Users",
        "Public",
        "SystemProfile",
        "LocalService",
        "NetworkService",
        "Default User",
        "DefaultAppPool",
        "wdigest",
    ];
    for sys_name in &system_profile_names {
        let sys_path = users_dir.join(sys_name);
        let sys_docs = sys_path.join("Documents");
        std::fs::create_dir_all(&sys_docs).expect("create sys profile docs");
        std::fs::write(sys_docs.join("sys.txt"), b"system data").expect("write sys doc");
    }

    // 3. Hidden directory (attribute 0x02)
    let hidden_user = users_dir.join("HiddenUser");
    let hidden_docs = hidden_user.join("Documents");
    std::fs::create_dir_all(&hidden_docs).expect("create hidden docs");
    set_file_attributes(&hidden_user, 0x02).expect("set hidden attribute on directory");

    // 4. System directory (attribute 0x04)
    let system_user = users_dir.join("SystemUser");
    let system_docs = system_user.join("Documents");
    std::fs::create_dir_all(&system_docs).expect("create system user docs");
    set_file_attributes(&system_user, 0x04).expect("set system attribute on directory");

    // 5. Non-directory files in Users directory
    std::fs::write(users_dir.join("desktop.ini"), b"[.ShellClassInfo]\r\n").expect("write desktop.ini");
    std::fs::write(users_dir.join("NTUSER.DAT"), b"registry hive data").expect("write NTUSER.DAT");
    std::fs::write(users_dir.join("normal_file.txt"), b"just a text file").expect("write normal_file.txt");

    // 6. Dot and dollar prefixed directories
    let dot_dir = users_dir.join(".dotfolder").join("Documents");
    let dollar_dir = users_dir.join("$RECYCLE.BIN").join("Documents");
    std::fs::create_dir_all(&dot_dir).expect("create dot dir");
    std::fs::create_dir_all(&dollar_dir).expect("create dollar dir");

    // 7. NTFS Junctions (reparse points)
    let junction_user = users_dir.join("JunctionUser");
    create_junction(&junction_user, &normal_user).expect("create junction");

    // Run discovery by setting SystemDrive to temp root
    let temp_root_str = temp.path().to_str().expect("temp path to str");
    let _env_guard = EnvGuard::set("SystemDrive", temp_root_str);

    let discovered = IngestConfig::discover_user_document_roots();

    // Filter discovered roots to those within our synthetic users directory
    let synthetic_roots: Vec<PathBuf> = discovered
        .into_iter()
        .filter(|p| p.starts_with(&users_dir))
        .collect();

    // Clean up junction before dropping tempdir (removes junction link, leaves normal_user)
    let _ = std::fs::remove_dir(&junction_user);

    // Assertions:
    // Only NormalUser's genuine document folders must be present
    assert_eq!(
        synthetic_roots.len(),
        3,
        "Expected exactly 3 document roots for NormalUser, got {}: {:?}",
        synthetic_roots.len(),
        synthetic_roots
    );

    assert!(synthetic_roots.contains(&normal_docs), "Must contain NormalUser/Documents");
    assert!(synthetic_roots.contains(&normal_desktop), "Must contain NormalUser/Desktop");
    assert!(synthetic_roots.contains(&normal_downloads), "Must contain NormalUser/Downloads");

    // Assert that ZERO system profiles, ZERO hidden folders, ZERO files, ZERO junctions, and ZERO dot/dollar dirs are included
    for root in &synthetic_roots {
        let lower = root.to_string_lossy().to_ascii_lowercase();

        for sys_name in &system_profile_names {
            let lower_sys = sys_name.to_ascii_lowercase();
            assert!(
                !lower.contains(&format!(r"\{}\", lower_sys)) && !lower.ends_with(&format!(r"\{}", lower_sys)),
                "Discovered root {:?} contains system profile '{}'",
                root,
                sys_name
            );
        }

        assert!(!lower.contains("hiddenuser"), "Discovered root must not contain hidden directory: {:?}", root);
        assert!(!lower.contains("systemuser"), "Discovered root must not contain system directory: {:?}", root);
        assert!(!lower.contains("junctionuser"), "Discovered root must not contain junction directory: {:?}", root);
        assert!(!lower.contains("desktop.ini"), "Discovered root must not be a file: {:?}", root);
        assert!(!lower.contains("ntuser.dat"), "Discovered root must not be a file: {:?}", root);
        assert!(!lower.contains("normal_file.txt"), "Discovered root must not be a file: {:?}", root);
        assert!(!lower.contains(".dotfolder"), "Discovered root must not contain dot folder: {:?}", root);
        assert!(!lower.contains("$recycle.bin"), "Discovered root must not contain $ folder: {:?}", root);
    }
}

/// 7. Adversarial Challenge 2: Unicode & Spaces in User Profile Names
/// - Accented vowels and spaces: "José García" (Documents, Desktop, Downloads)
/// - Japanese CJK ideographs with space: "山田 太郎" (Documents)
/// - German umlauts and ampersand: "Müller & Söhne" (Documents)
/// - Consecutive spaces: "User   With   Multiple   Spaces" (Documents, Desktop)
/// Asserts that:
/// - All 7 expected roots are discovered with exact character fidelity without truncation or encoding loss.
/// - Every returned path physically exists and is a directory.
#[cfg(target_os = "windows")]
#[test]
fn test_adversarial_unicode_and_spaces_user_profiles() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp = tempdir().expect("tempdir");
    let users_dir = temp.path().join("Users");
    std::fs::create_dir_all(&users_dir).expect("create Users dir");

    // 1. Spanish user with accented vowels and spaces: "José García"
    let jose = users_dir.join("José García");
    let jose_docs = jose.join("Documents");
    let jose_desktop = jose.join("Desktop");
    let jose_downloads = jose.join("Downloads");
    std::fs::create_dir_all(&jose_docs).expect("create jose docs");
    std::fs::create_dir_all(&jose_desktop).expect("create jose desktop");
    std::fs::create_dir_all(&jose_downloads).expect("create jose downloads");

    // 2. Japanese Kanji/Kana user: "山田 太郎"
    let yamada = users_dir.join("山田 太郎");
    let yamada_docs = yamada.join("Documents");
    std::fs::create_dir_all(&yamada_docs).expect("create yamada docs");

    // 3. German user with umlauts and ampersand: "Müller & Söhne"
    let muller = users_dir.join("Müller & Söhne");
    let muller_docs = muller.join("Documents");
    std::fs::create_dir_all(&muller_docs).expect("create muller docs");

    // 4. User with multiple spaces: "User   With   Multiple   Spaces"
    let spaced = users_dir.join("User   With   Multiple   Spaces");
    let spaced_docs = spaced.join("Documents");
    let spaced_desktop = spaced.join("Desktop");
    std::fs::create_dir_all(&spaced_docs).expect("create spaced docs");
    std::fs::create_dir_all(&spaced_desktop).expect("create spaced desktop");

    // Run discovery by setting SystemDrive to temp root
    let temp_root_str = temp.path().to_str().expect("temp path to str");
    let _env_guard = EnvGuard::set("SystemDrive", temp_root_str);

    let discovered = IngestConfig::discover_user_document_roots();

    // Filter discovered roots to those within our synthetic users directory
    let synthetic_roots: Vec<PathBuf> = discovered
        .into_iter()
        .filter(|p| p.starts_with(&users_dir))
        .collect();

    // Assertions:
    // Exactly 7 roots must be discovered across the 4 Unicode/spaced users
    assert_eq!(
        synthetic_roots.len(),
        7,
        "Expected exactly 7 document roots for Unicode and spaced users, got {}: {:?}",
        synthetic_roots.len(),
        synthetic_roots
    );

    assert!(synthetic_roots.contains(&jose_docs), "Must discover 'José García/Documents'");
    assert!(synthetic_roots.contains(&jose_desktop), "Must discover 'José García/Desktop'");
    assert!(synthetic_roots.contains(&jose_downloads), "Must discover 'José García/Downloads'");
    assert!(synthetic_roots.contains(&yamada_docs), "Must discover '山田 太郎/Documents'");
    assert!(synthetic_roots.contains(&muller_docs), "Must discover 'Müller & Söhne/Documents'");
    assert!(synthetic_roots.contains(&spaced_docs), "Must discover 'User   With   Multiple   Spaces/Documents'");
    assert!(synthetic_roots.contains(&spaced_desktop), "Must discover 'User   With   Multiple   Spaces/Desktop'");

    // Verify all discovered paths physically exist and are directories
    for root in &synthetic_roots {
        assert!(root.exists(), "Discovered path must exist: {:?}", root);
        assert!(root.is_dir(), "Discovered path must be a directory: {:?}", root);
    }
}

/// 8. Adversarial Challenge 3: OneDrive Sync Folders and Directory Reparse Point Support
/// - User "CloudUser" with genuine `OneDrive\Documents` and `OneDrive\Desktop`.
/// - Reparse point support: `OneDrive\Documents` is created as an NTFS directory junction / reparse point
///   (simulating Windows Cloud-Sync reparse points like OneDrive / iCloud) -> MUST be discovered!
/// - Recursive cyclic junction: `OneDrive\CyclicLoop` pointing back to `CloudUser` -> MUST be rejected.
/// Asserts that:
/// - Valid OneDrive directory reparse points ARE discovered and supported under Milestone M25.
/// - Recursive junction loops are strictly rejected.
#[cfg(target_os = "windows")]
#[test]
fn test_adversarial_onedrive_discovery_and_reparse_point_rejection() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp = tempdir().expect("tempdir");
    let users_dir = temp.path().join("Users");
    std::fs::create_dir_all(&users_dir).expect("create Users dir");

    let cloud_user = users_dir.join("CloudUser");
    let onedrive = cloud_user.join("OneDrive");
    let target_docs = temp.path().join("CloudDocsStorage");
    let onedrive_docs = onedrive.join("Documents");
    let onedrive_desktop = onedrive.join("Desktop");
    let onedrive_loop = onedrive.join("CyclicLoop");

    std::fs::create_dir_all(&target_docs).expect("create target docs");
    std::fs::create_dir_all(&onedrive).expect("create onedrive dir");
    std::fs::create_dir_all(&onedrive_desktop).expect("create onedrive desktop");

    // Create OneDrive\Documents as an NTFS junction / directory reparse point pointing to real storage
    create_junction(&onedrive_docs, &target_docs).expect("create onedrive docs junction");

    // Create a recursive cyclic loop junction pointing back to cloud_user
    create_junction(&onedrive_loop, &cloud_user).expect("create cyclic junction loop");

    let temp_root_str = temp.path().to_str().expect("temp path to str");
    let _env_guard = EnvGuard::set("SystemDrive", temp_root_str);

    let discovered = IngestConfig::discover_user_document_roots();

    let synthetic_roots: Vec<PathBuf> = discovered
        .into_iter()
        .filter(|p| p.starts_with(&users_dir))
        .collect();

    // Clean up junctions
    let _ = std::fs::remove_dir(&onedrive_docs);
    let _ = std::fs::remove_dir(&onedrive_loop);

    // M25: OneDrive/Documents (directory reparse point) and OneDrive/Desktop MUST be accepted
    assert!(
        synthetic_roots.contains(&onedrive_docs),
        "Must contain CloudUser/OneDrive/Documents even when it is an NTFS directory reparse point"
    );
    assert!(
        synthetic_roots.contains(&onedrive_desktop),
        "Must contain CloudUser/OneDrive/Desktop"
    );
    // Recursive loop MUST be rejected
    assert!(
        !synthetic_roots.contains(&onedrive_loop),
        "Must NOT contain CloudUser/OneDrive/CyclicLoop because it is a recursive cyclic loop"
    );
}

/// 9. Milestone M25 Registry ProfileList and System Profile Invariants
/// - Verifies that discover_user_document_roots never returns system SIDs (S-1-5-18, S-1-5-19, S-1-5-20).
/// - Verifies that all discovered roots are valid directories and readable.
#[test]
fn test_m25_profile_list_discovery_skips_system_sids() {
    let _lock = ENV_LOCK.lock().unwrap();
    let discovered = IngestConfig::discover_user_document_roots();

    for root in &discovered {
        let lower = root.to_string_lossy().to_ascii_lowercase();
        assert!(!lower.contains("s-1-5-18"), "Must not discover S-1-5-18 system profile: {:?}", root);
        assert!(!lower.contains("s-1-5-19"), "Must not discover S-1-5-19 system profile: {:?}", root);
        assert!(!lower.contains("s-1-5-20"), "Must not discover S-1-5-20 system profile: {:?}", root);
        assert!(!lower.contains("systemprofile"), "Must not discover systemprofile: {:?}", root);
        assert!(!lower.contains("localservice"), "Must not discover localservice: {:?}", root);
        assert!(!lower.contains("networkservice"), "Must not discover networkservice: {:?}", root);
        assert!(root.is_dir(), "Discovered path must be a directory: {:?}", root);
    }
}


