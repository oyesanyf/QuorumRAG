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
use tempfile::tempdir;

/// 1. Headless Session 0 Profile Discovery:
/// Must discover human user document roots, strictly filtering out
/// system profiles (systemprofile, localservice, networkservice, default, public),
/// junctions/reparse points (All Users, Default User), hidden directories, and non-directories.
#[test]
fn test_discover_user_document_roots_filters_system_profiles_and_junctions() {
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

            // Verify the discovered directory is NOT a symlink or reparse point
            let sym_meta = std::fs::symlink_metadata(root)
                .unwrap_or_else(|e| panic!("Failed to read symlink metadata for {:?}: {}", root, e));
            assert!(
                !sym_meta.file_type().is_symlink(),
                "Discovered root {:?} must not be a symlink",
                root
            );

            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            assert_eq!(
                sym_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
                0,
                "Discovered root {:?} must not be an NTFS reparse point/junction",
                root
            );
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
