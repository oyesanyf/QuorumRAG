//! Adversarial stress-test harness for Milestone M7:
//! Zero-Overhead Ingestion Pipeline, Dedup Hydration & Binary Filtering.
//!
//! Written by Empirical Challenger agent to stress-test:
//! 1. Feature 44: Dedup startup hydration with large chunk sets (1,000+ chunks),
//!    empty storage, offline drive paths, and zero-read Level-1 fast path verification.
//! 2. Feature 46: Fast-path binary exclusion for all 23 extensions with mixed/upper case,
//!    ensuring zero disk I/O and zero metadata calls.
//! 3. Feature 46: Non-text data leakage prevention for SQLite, PCAP/PCAPNG, and raw binary.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::COMPILED_BINARY_EXTENSIONS;
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::DocumentChunk;

use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::config::IngestConfig;
use quorum_ingest::dedup::{DedupAction, TwoLevelDedupEngine};

#[tokio::test]
async fn test_adversarial_dedup_hydration_large_scale_1500_chunks_and_fast_path() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_scale_1500");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    // 1. Generate 25 real online files, each with 40 chunks = 1,000 distinct chunks
    let mut chunks = Vec::with_capacity(1500);
    let mut online_files = Vec::new();

    for doc_idx in 0..25 {
        let file_path = dir.path().join(format!("source_doc_{:03}.rs", doc_idx));
        let content = format!(
            "// Document {:03}\npub fn calculate_{}() -> usize {{ {}\n}}\n",
            doc_idx, doc_idx, doc_idx
        );
        std::fs::write(&file_path, content).unwrap();

        let meta = std::fs::metadata(&file_path).unwrap();
        let mtime = meta
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let size = meta.len();

        let doc_blake3 = format!("doc_hash_scale_{:04}", doc_idx);

        for chunk_idx in 0..40 {
            let chunk_text = format!("fn inner_logic_{}_{}() {{ println!(\"eval\"); }}", doc_idx, chunk_idx);
            let chunk_blake3 = format!("chunk_hash_{:04}_{:04}", doc_idx, chunk_idx);

            let chunk_id = format!("{}:{}", doc_blake3, chunk_idx);
            let mut chunk_obj = DocumentChunk::new(
                chunk_id,
                &doc_blake3,
                file_path.to_string_lossy().to_string(),
                (chunk_idx * 5 + 1) as u32,
                (chunk_idx * 5 + 5) as u32,
                0,
                vec![0.05 * (chunk_idx as f32); 768],
                chunk_text,
                None,
            )
            .unwrap();
            chunk_obj.blake3_hash = chunk_blake3;
            chunks.push(chunk_obj);
        }

        online_files.push((file_path, doc_blake3, mtime, size));
    }

    // 2. Generate 10 offline / dismounted drive paths with 50 chunks each = 500 distinct chunks
    for off_idx in 0..10 {
        let offline_path = PathBuf::from(format!("X:\\dismounted_drive\\archive_{:02}\\spec.md", off_idx));
        let doc_blake3 = format!("offline_doc_hash_{:04}", off_idx);

        for chunk_idx in 0..50 {
            let chunk_id = format!("{}:{}", doc_blake3, chunk_idx);
            let mut chunk_obj = DocumentChunk::new(
                chunk_id,
                &doc_blake3,
                offline_path.to_string_lossy().to_string(),
                (chunk_idx * 10 + 1) as u32,
                (chunk_idx * 10 + 10) as u32,
                0,
                vec![0.01 * (off_idx as f32); 768],
                format!("# Architecture Specification Section {}:{}", off_idx, chunk_idx),
                None,
            )
            .unwrap();
            chunk_obj.blake3_hash = format!("offline_chunk_hash_{:04}_{:04}", off_idx, chunk_idx);
            chunks.push(chunk_obj);
        }
    }

    assert_eq!(chunks.len(), 1500, "Must have exactly 1,500 chunks in test set");

    // Insert all 1,500 chunks into storage in batches
    for chunk_batch in chunks.chunks(250) {
        storage.insert_chunks(chunk_batch).await.unwrap();
    }

    // Hydrate fresh TwoLevelDedupEngine
    let dedup = TwoLevelDedupEngine::new();
    let hydrated_count = dedup.hydrate_from_storage(&storage).await.unwrap();
    assert_eq!(hydrated_count, 1500, "Hydrated count must equal 1,500");

    // Assert Level-2 cache capacity expanded to handle all chunks without eviction
    let stats = dedup.cache().stats();
    assert!(
        stats.capacity >= 1500,
        "Level-2 cache capacity must expand to at least 1,500, was {}",
        stats.capacity
    );
    assert_eq!(stats.current_size, 1500);

    // Verify offline documents fall back to (0, 0)
    for off_idx in 0..10 {
        let offline_path = PathBuf::from(format!("X:\\dismounted_drive\\archive_{:02}\\spec.md", off_idx));
        let entry = dedup.get_file_entry(&offline_path).expect("Offline entry must exist in catalog");
        assert_eq!(entry.mtime_secs, 0);
        assert_eq!(entry.size_bytes, 0);
        assert_eq!(entry.chunk_hashes.len(), 50);
    }

    // Verify online documents and EMPIRICALLY PROVE 0 file reads and 0 hashing for Level-1 Fast Path:
    for (file_path, doc_blake3, mtime, size) in &online_files {
        let entry = dedup.get_file_entry(file_path).expect("Online file must exist");
        assert_eq!(&entry.file_blake3, doc_blake3);
        assert_eq!(entry.mtime_secs, *mtime);
        assert_eq!(entry.size_bytes, *size);
        assert_eq!(entry.chunk_hashes.len(), 40);

        // Standard fast path check:
        let action = dedup.evaluate_file(file_path, *mtime, *size).unwrap();
        match action {
            DedupAction::Unchanged { file_blake3, chunk_hashes } => {
                assert_eq!(&file_blake3, doc_blake3);
                assert_eq!(chunk_hashes.len(), 40);
            }
            other => panic!("Expected Unchanged, got {:?}", other),
        }
    }

    // EMPIRICAL ZERO-READ / ZERO-HASHING CHALLENGE:
    // Delete the first online file from the filesystem.
    let (deleted_path, deleted_doc_id, del_mtime, del_size) = &online_files[0];
    std::fs::remove_file(deleted_path).unwrap();
    assert!(!deleted_path.exists(), "File must no longer exist on disk");

    // Fast path: evaluate with matching mtime and size.
    // If evaluate_file attempted to open or read the file, it would fail with std::io::Error (NotFound).
    // Because Level-1 fast path requires 0 disk reads and 0 hashing, it MUST succeed cleanly as Unchanged!
    let fast_action = dedup.evaluate_file(deleted_path, *del_mtime, *del_size)
        .expect("Fast-path evaluation of non-existent file with matching catalog metadata must succeed with 0 disk I/O");
    assert!(
        matches!(fast_action, DedupAction::Unchanged { ref file_blake3, .. } if file_blake3 == deleted_doc_id),
        "Level-1 fast path must return Unchanged without touching disk"
    );

    // Negative control: If mtime is altered by 1 second, it attempts disk read (Step 2) and MUST fail with NotFound error:
    let modified_mtime = del_mtime + 1;
    let fallback_result = dedup.evaluate_file(deleted_path, modified_mtime, *del_size);
    assert!(
        fallback_result.is_err(),
        "Step 2 fallback must attempt disk read and fail when file does not exist: {:?}",
        fallback_result
    );
}

#[tokio::test]
async fn test_adversarial_dedup_hydration_duplicate_chunk_hashes_across_storage() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_dedup_hashes");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    // Create 3 documents where chunks have identical hash (e.g. standard license preamble)
    let shared_hash = "shared_license_preamble_hash_abcdef";
    let chunk0 = DocumentChunk::new(
        "docA:0".to_string(),
        "docA",
        "C:\\repo\\docA.rs",
        1,
        5,
        0,
        vec![0.1; 768],
        "// License preamble",
        None,
    ).unwrap();
    let mut c0 = chunk0.clone();
    c0.blake3_hash = shared_hash.to_string();

    let chunk1 = DocumentChunk::new(
        "docB:0".to_string(),
        "docB",
        "C:\\repo\\docB.rs",
        1,
        5,
        0,
        vec![0.1; 768],
        "// License preamble",
        None,
    ).unwrap();
    let mut c1 = chunk1.clone();
    c1.blake3_hash = shared_hash.to_string();

    // Insert chunks (storage will deduplicate c1 since hash matches c0)
    storage.insert_chunks(&[c0, c1]).await.unwrap();

    let dedup = TwoLevelDedupEngine::new();
    let count = dedup.hydrate_from_storage(&storage).await.unwrap();
    assert_eq!(count, 1, "Only unique chunks stored in LanceDB must be hydrated");

    // Level-2 cache must contain the shared chunk hash without duplicates
    assert!(dedup.cache().has_chunk(shared_hash));
    let stats = dedup.cache().stats();
    assert_eq!(stats.current_size, 1);
}

#[tokio::test]
async fn test_adversarial_dedup_hydration_empty_storage() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_empty_challenge");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    let dedup = TwoLevelDedupEngine::new();
    let result = dedup.hydrate_from_storage(&storage).await;
    assert!(result.is_ok(), "Hydration from empty storage must not error");
    assert_eq!(result.unwrap(), 0);

    assert_eq!(dedup.get_all_tracked_files().len(), 0);
    let stats = dedup.cache().stats();
    assert_eq!(stats.current_size, 0);
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
}

#[test]
fn test_adversarial_fast_path_binary_exclusion_all_29_extensions_mixed_case_no_io() {
    let router = ClassifierRouter::new(IngestConfig::default());

    // All 29 binary extensions from COMPILED_BINARY_EXTENSIONS
    let base_extensions = COMPILED_BINARY_EXTENSIONS;
    assert_eq!(base_extensions.len(), 29);

    // Generate adversarial mixed-case and uppercase variations
    for &ext in base_extensions {
        let upper = ext.to_ascii_uppercase();
        let mixed = {
            let mut chars = ext.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => ext.to_string(),
            }
        };

        for test_ext in &[upper, mixed, ext.to_string()] {
            // Point to a non-existent path on a dummy drive
            let fake_path_str = format!("Z:\\fictitious_drive\\deep\\subsystem\\binary_artifact.{}", test_ext);
            let fake_path = Path::new(&fake_path_str);

            let decision = router.evaluate_file(fake_path);
            match decision {
                FilterDecision::SkipBinary { identity } => {
                    assert_eq!(
                        identity.category,
                        quorum_classifier::FileCategory::Executable,
                        "Extension '{}' failed category check",
                        test_ext
                    );
                    assert!(
                        !identity.is_text,
                        "Extension '{}' must have is_text = false",
                        test_ext
                    );
                }
                other => panic!(
                    "Path with extension '{}' must return SkipBinary without disk I/O, got: {:?}",
                    test_ext, other
                ),
            }
        }
    }

    // Negative control: A non-existent file with a text extension (.txt, .md, .rs) must fail disk I/O
    let fake_text_path = Path::new("Z:\\fictitious_drive\\deep\\subsystem\\missing.txt");
    let text_decision = router.evaluate_file(fake_text_path);
    assert!(
        matches!(text_decision, FilterDecision::SkipIoError { .. }),
        "Non-binary missing path must attempt disk I/O and return SkipIoError, got: {:?}",
        text_decision
    );
}

#[test]
fn test_adversarial_deceptive_binary_content_excluded_via_fast_path() {
    let dir = tempdir().unwrap();
    let router = ClassifierRouter::new(IngestConfig::default());

    // Create a real file named "deceptive.exe" containing legitimate plain text ASCII
    let deceptive_exe = dir.path().join("deceptive.exe");
    std::fs::write(&deceptive_exe, "This is plain ASCII text pretending to be an executable").unwrap();

    // Fast path must exclude it immediately without inspecting content or reading bytes
    let decision = router.evaluate_file(&deceptive_exe);
    assert!(
        matches!(decision, FilterDecision::SkipBinary { .. }),
        "Deceptive .exe must be excluded via extension fast-path before content inspection"
    );

    // Create a real file named "payload.DLL" containing JSON data
    let deceptive_dll = dir.path().join("payload.DLL");
    std::fs::write(&deceptive_dll, "{\"name\": \"malicious\", \"version\": 1}").unwrap();

    let decision = router.evaluate_file(&deceptive_dll);
    assert!(
        matches!(decision, FilterDecision::SkipBinary { .. }),
        "Deceptive .DLL must be excluded via extension fast-path before content inspection"
    );
}

#[test]
fn test_adversarial_non_text_data_leakage_sqlite_pcap_raw_binary() {
    let dir = tempdir().unwrap();
    let router = ClassifierRouter::new(IngestConfig::default());

    // 1. SQLite database with non-standard extension .dat or .cache
    let sqlite_path = dir.path().join("session_store.dat");
    let mut file = File::create(&sqlite_path).unwrap();
    // Valid SQLite 3 100-byte database header
    let mut sqlite_header = vec![0u8; 100];
    sqlite_header[..16].copy_from_slice(b"SQLite format 3\0");
    sqlite_header[16..18].copy_from_slice(&1024u16.to_be_bytes()); // page size
    sqlite_header[18] = 1; // write version
    sqlite_header[19] = 1; // read version
    file.write_all(&sqlite_header).unwrap();
    file.flush().unwrap();

    let decision = router.evaluate_file(&sqlite_path);
    assert!(
        matches!(decision, FilterDecision::SkipBinary { ref identity } if identity.label == "sqlite" && !identity.is_text),
        "SQLite database must be skipped as SkipBinary and NEVER accepted as CandidateKind::Text: got {:?}",
        decision
    );

    // 2. PCAP network captures with all 5 standard magic formats
    let pcap_magics: &[(u32, &str)] = &[
        (0xa1b2c3d4, "standard_tcpdump.pcap"),
        (0xd4c3b2a1, "swapped_tcpdump.pcap"),
        (0xa1b23c4d, "nanosecond_tcpdump.pcap"),
        (0x4d3cb2a1, "swapped_nanosecond.pcap"),
        (0x0a0d0d0a, "pcapng_capture.pcapng"),
    ];

    for (magic, filename) in pcap_magics {
        let pcap_path = dir.path().join(filename);
        let mut pcap_file = File::create(&pcap_path).unwrap();
        pcap_file.write_all(&magic.to_be_bytes()).unwrap();
        pcap_file.write_all(&[0u8; 64]).unwrap(); // trailing packet bytes
        pcap_file.flush().unwrap();

        let pcap_decision = router.evaluate_file(&pcap_path);
        assert!(
            matches!(pcap_decision, FilterDecision::SkipBinary { ref identity } if identity.label == "pcap" && !identity.is_text),
            "PCAP format {:x} must be skipped as SkipBinary and NEVER CandidateKind::Text: got {:?}",
            magic,
            pcap_decision
        );
    }

    // 3. Raw arbitrary binary file with null bytes and high entropy
    let raw_bin_path = dir.path().join("raw_stream.data");
    let mut raw_bytes = Vec::with_capacity(512);
    for i in 0..512 {
        raw_bytes.push((i % 256) as u8);
    }
    // inject multiple null bytes and non-printable control characters
    raw_bytes[0] = 0x00;
    raw_bytes[1] = 0xFF;
    raw_bytes[2] = 0xFE;
    raw_bytes[3] = 0x00;
    std::fs::write(&raw_bin_path, &raw_bytes).unwrap();

    let raw_decision = router.evaluate_file(&raw_bin_path);
    assert!(
        matches!(raw_decision, FilterDecision::SkipBinary { ref identity } if !identity.is_text),
        "Raw binary data must be skipped as SkipBinary and NEVER CandidateKind::Text: got {:?}",
        raw_decision
    );

    // 4. Positive control: Structured text data (JSON, YAML, TOML, CSV, TSV) MUST be accepted as Text
    let json_path = dir.path().join("valid_config.json");
    std::fs::write(&json_path, "{\"quorum\": true, \"version\": \"1.0.0\"}").unwrap();
    let json_decision = router.evaluate_file(&json_path);
    assert!(
        matches!(json_decision, FilterDecision::Accept { kind: CandidateKind::Text { .. }, .. }),
        "Valid JSON structured data must be accepted as CandidateKind::Text: got {:?}",
        json_decision
    );

    let toml_path = dir.path().join("settings.toml");
    std::fs::write(&toml_path, "[server]\nport = 8080\nhost = \"127.0.0.1\"\n").unwrap();
    let toml_decision = router.evaluate_file(&toml_path);
    assert!(
        matches!(toml_decision, FilterDecision::Accept { kind: CandidateKind::Text { .. }, .. }),
        "Valid TOML structured data must be accepted as CandidateKind::Text: got {:?}",
        toml_decision
    );
}
