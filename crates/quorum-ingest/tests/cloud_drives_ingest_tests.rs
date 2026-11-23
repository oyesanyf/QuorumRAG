//! Integration tests for Cloud Drives ingest features (F1–F11):
//! - Fail-closed normalized access tier rules
//! - Decoupled OneDrive from `discover_user_document_roots`
//! - Real OS placeholder protection (`LocallySyncedOnly` vs `HydrateOnDemand`) across primary & secondary sites
//! - `TwoLevelDedupEngine::remove_by_prefix` boundary safety & persistence
//! - Dynamic `ReindexWorker` (`remove_watch_paths`, `update_access_tier_rules`, `update_placeholder_policy`, `set_dlp_gate`)
//! - Layout-preserving `SecretScrubber` + fail-closed `DlpContentGate` across Text/Image/Audio

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::{CloudPlaceholderPolicy, DlpContentGate, DocumentChunk};

use quorum_ingest::audio_indexer::AudioIndexer;
use quorum_ingest::classifier_router::{ClassifierRouter, FilterDecision};
use quorum_ingest::config::{IngestConfig, ReindexOptions};
use quorum_ingest::crawler::FilesystemCrawler;
use quorum_ingest::dedup::{FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine};
use quorum_ingest::document_extractor::DocumentExtractor;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::error::IngestError;
use quorum_ingest::image_indexer::ImageIndexer;
use quorum_ingest::reindex::ReindexWorker;
use quorum_ingest::secret_scrubber::SecretScrubber;

#[derive(Debug, Clone)]
struct TestEmbedder {
    contract: EmbeddingContract,
}

impl Default for TestEmbedder {
    fn default() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
        }
    }
}

impl EmbeddingGenerator for TestEmbedder {
    fn contract(&self) -> &EmbeddingContract {
        &self.contract
    }

    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        let dim = self.contract.dimension;
        let mut vec = Vec::with_capacity(dim);
        let mut hasher = blake3::Hasher::new();
        hasher.update(text.as_bytes());
        for i in 0..dim {
            let mut h = hasher.clone();
            h.update(&(i as u32).to_le_bytes());
            let out = h.finalize();
            let v = u32::from_le_bytes([
                out.as_bytes()[0],
                out.as_bytes()[1],
                out.as_bytes()[2],
                out.as_bytes()[3],
            ]);
            vec.push((v as f32 / u32::MAX as f32) * 2.0 - 1.0);
        }
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut vec {
                *x /= norm;
            }
        }
        Ok(vec)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
        texts.iter().map(|t| self.embed_text(t)).collect()
    }
}

struct BlockingDlpGate {
    blocked_substring: String,
}

impl DlpContentGate for BlockingDlpGate {
    fn inspect_ingest_text(
        &self,
        _file_path: &str,
        text: &str,
        _access_tier: u8,
    ) -> Result<String, String> {
        if text.contains(&self.blocked_substring) {
            Err("Confidential pattern blocked by test DLP gate".to_string())
        } else {
            Ok(text.replace("SANITIZE_ME", "[DLP_MASKED]"))
        }
    }
}

fn minimal_png_bytes() -> Vec<u8> {
    // 1x1 valid PNG
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}

fn png_with_comment_bytes(comment: &str) -> Vec<u8> {
    // 1x1 valid PNG with an injected tEXt chunk (`Comment\0<comment>`) before IEND
    let base = minimal_png_bytes();
    let iend_pos = base.len() - 12;
    let mut out = Vec::new();
    out.extend_from_slice(&base[..iend_pos]);

    let mut payload = Vec::new();
    payload.extend_from_slice(b"Comment\0");
    payload.extend_from_slice(comment.as_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(b"tEXt");
    out.extend_from_slice(&payload);
    out.extend_from_slice(&0u32.to_be_bytes());

    out.extend_from_slice(&base[iend_pos..]);
    out
}

fn build_stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut central = Vec::new();
    for &(name, raw) in files {
        let local_offset = buf.len() as u32;
        let name_b = name.as_bytes();
        let len_u32 = raw.len() as u32;

        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // Stored (method 0)
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&len_u32.to_le_bytes());
        buf.extend_from_slice(&len_u32.to_le_bytes());
        buf.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(name_b);
        buf.extend_from_slice(raw);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // Stored
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&len_u32.to_le_bytes());
        central.extend_from_slice(&len_u32.to_le_bytes());
        central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_b);
    }
    let cd_offset = buf.len() as u32;
    let cd_size = central.len() as u32;
    buf.extend_from_slice(&central);

    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(files.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(files.len() as u16).to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf
}

fn minimal_wav_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"RIFF");
    b.extend_from_slice(&36u32.to_le_bytes());
    b.extend_from_slice(b"WAVE");
    b.extend_from_slice(b"fmt ");
    b.extend_from_slice(&16u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // PCM
    b.extend_from_slice(&1u16.to_le_bytes()); // mono
    b.extend_from_slice(&44100u32.to_le_bytes());
    b.extend_from_slice(&88200u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(b"data");
    b.extend_from_slice(&4u32.to_le_bytes());
    b.extend_from_slice(&[0u8; 4]);
    b
}

#[test]
fn test_resolve_access_tier_normalization_boundaries_and_fail_closed() {
    let cfg = IngestConfig {
        access_tier_rules: vec![
            (PathBuf::from(r"C:\Users\Alice\OneDrive/"), 3),
            (PathBuf::from(r"C:\Users\Alice\OneDrive\Public"), 1),
            (PathBuf::from(r"C:\Users\Alice\OneDrive - Business"), 2),
        ],
        ..Default::default()
    };

    // Mixed slashes, \\?\ prefix, Windows case-insensitivity
    assert_eq!(
        cfg.resolve_access_tier(Path::new(r"\\?\c:/users/alice/onedrive/notes.txt")),
        3
    );
    // Longer nested rule wins
    assert_eq!(
        cfg.resolve_access_tier(Path::new(r"C:\Users\Alice\OneDrive\Public\readme.md")),
        1
    );
    // Sibling does NOT collide with shorter OneDrive rule
    assert_eq!(
        cfg.resolve_access_tier(Path::new(r"C:\Users\Alice\OneDrive - Business\q1.docx")),
        2
    );
    // Unmatched path defaults to 0
    assert_eq!(
        cfg.resolve_access_tier(Path::new(r"D:\LocalDocs\plan.txt")),
        0
    );

    // Invalid path fails closed to 3 in infallible API and Err in try_resolve_access_tier
    assert_eq!(
        cfg.resolve_access_tier(Path::new(r"C:\Users\Alice\..\secret.txt")),
        3
    );
    assert!(cfg
        .try_resolve_access_tier(Path::new(r"C:\Users\Alice\..\secret.txt"))
        .is_err());

    // Invalid tier rule (> 3) fails closed to 3 in infallible API and Err in checked APIs
    let bad_tier_cfg = IngestConfig {
        access_tier_rules: vec![(PathBuf::from(r"C:\Users\Alice\Cloud"), 9)],
        ..Default::default()
    };
    assert!(bad_tier_cfg.validate_access_tier_rules().is_err());
    assert!(bad_tier_cfg
        .try_resolve_access_tier(Path::new(r"C:\Users\Alice\Cloud\doc.txt"))
        .is_err());
    assert_eq!(
        bad_tier_cfg.resolve_access_tier(Path::new(r"C:\Users\Alice\Cloud\doc.txt")),
        3
    );
}

#[test]
fn test_discover_user_document_roots_excludes_onedrive() {
    let roots = IngestConfig::discover_user_document_roots();
    for root in &roots {
        let lower = root.to_string_lossy().to_ascii_lowercase();
        assert!(
            !lower.contains("\\onedrive") && !lower.contains("/onedrive"),
            "OneDrive must be decoupled from auto-shared discover_user_document_roots(): {:?}",
            root
        );
    }
}

#[test]
fn test_dedup_remove_by_prefix_boundary_safety_and_persistence() {
    let dir = tempdir().unwrap();
    let catalog_path = dir.path().join("dedup_catalog.json");
    let dedup = TwoLevelDedupEngine::new();

    let drive_a = dir.path().join("OneDrive");
    let drive_b = dir.path().join("OneDrive - Business");
    let file_a1 = drive_a.join("sub").join("a1.txt");
    let file_b1 = drive_b.join("b1.txt");

    dedup
        .cache()
        .insert("shared_chunk".to_string(), vec![0.5; 4]);
    dedup
        .cache()
        .insert("orphan_chunk".to_string(), vec![0.1; 4]);

    dedup.register_entry(FileCatalogEntry {
        file_path: file_a1.clone(),
        file_blake3: "hash_a1".to_string(),
        mtime_secs: 100,
        size_bytes: 10,
        chunk_hashes: vec!["orphan_chunk".to_string(), "shared_chunk".to_string()],
    });
    dedup.register_entry(FileCatalogEntry {
        file_path: file_b1.clone(),
        file_blake3: "hash_b1".to_string(),
        mtime_secs: 200,
        size_bytes: 20,
        chunk_hashes: vec!["shared_chunk".to_string()],
    });

    // Remove drive_a prefix (with trailing separator / mixed slashes)
    let prefix_with_slash = PathBuf::from(format!("{}/", drive_a.to_string_lossy()));
    let removed = dedup
        .remove_by_prefix_and_save(&prefix_with_slash, Some(&catalog_path))
        .unwrap();
    assert_eq!(removed, 1);

    assert!(dedup.get_file_entry(&file_a1).is_none());
    assert!(
        dedup.get_file_entry(&file_b1).is_some(),
        "Sibling OneDrive - Business must survive"
    );

    // Orphaned chunk evicted, shared chunk preserved
    assert!(!dedup.cache().has_chunk("orphan_chunk"));
    assert!(dedup.cache().has_chunk("shared_chunk"));

    // Persisted JSON reloads without drive_a
    let reloaded = TwoLevelDedupEngine::new();
    reloaded.load_catalog_from_file(&catalog_path).unwrap();
    assert!(reloaded.get_file_entry(&file_a1).is_none());
    assert!(reloaded.get_file_entry(&file_b1).is_some());
}

#[test]
fn test_secret_scrubber_preserves_multiline_layout() {
    let synthetic_key = concat!("sk-", "1234567890abcdefghijklmnop");
    let md = format!("# Architecture\n\n  Line two indented\n  api_key={synthetic_key}\n\n## Next Section\nFinal line");
    let scrubbed = SecretScrubber::scrub_text_preserving_layout(&md);

    assert!(scrubbed.contains("# Architecture\n\n  Line two indented\n"));
    assert!(scrubbed.contains("\n\n## Next Section\nFinal line"));
    assert!(!scrubbed.contains(synthetic_key));
    assert_eq!(scrubbed.lines().count(), md.lines().count());
}

#[tokio::test]
async fn test_reindex_worker_dynamic_controls_and_dlp_fail_closed() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let watch_a = dir.path().join("DriveA");
    let watch_b = dir.path().join("DriveB");
    std::fs::create_dir_all(&watch_a).unwrap();
    std::fs::create_dir_all(&watch_b).unwrap();

    let file_a = watch_a.join("note_a.txt");
    let file_b = watch_b.join("note_b.txt");
    let blocked_file = watch_b.join("secret_note.txt");
    let audio_ok = watch_b.join("track.wav");

    std::fs::write(&file_a, "Alpha content in DriveA").unwrap();
    std::fs::write(&file_b, "Beta content SANITIZE_ME in DriveB").unwrap();
    std::fs::write(&blocked_file, "Contains FORBIDDEN_PAYLOAD inside DriveB").unwrap();
    std::fs::write(&audio_ok, minimal_wav_bytes()).unwrap();

    // Companion lyrics with blocked payload for audio_ok -> blocks audio ingestion via DLP gate!
    std::fs::write(
        watch_b.join("track.lrc"),
        "Lyrics containing FORBIDDEN_PAYLOAD",
    )
    .unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let cfg = IngestConfig {
        watch_paths: vec![watch_a.clone(), watch_b.clone()],
        ..Default::default()
    };

    let gate: Arc<dyn DlpContentGate> = Arc::new(BlockingDlpGate {
        blocked_substring: "FORBIDDEN_PAYLOAD".to_string(),
    });
    let worker = ReindexWorker::new(
        cfg,
        Arc::clone(&storage),
        classifier,
        embedder,
        Arc::clone(&dedup),
    )
    .with_dlp_gate(Arc::clone(&gate));

    // Invalid tier (> 3) must fail closed
    assert!(worker
        .update_access_tier_rules(vec![(watch_b.clone(), 4)])
        .await
        .is_err());

    // Valid rule sets DriveB to tier 2
    worker
        .update_access_tier_rules(vec![(watch_b.clone(), 2)])
        .await
        .unwrap();

    // Remove DriveA watch path before indexing
    worker.remove_watch_paths(&[watch_a.clone()]).await;
    assert!(!worker.all_watch_paths().iter().any(|p| p == &watch_a));

    let prog = worker
        .run_reindex_sync(ReindexOptions::default())
        .await
        .unwrap();
    assert!(prog.files_indexed >= 1);

    let chunks = storage.scan_all_chunks().await.unwrap();
    // DriveA was removed -> never indexed
    assert!(!chunks.iter().any(|c| c.file_path.contains("note_a.txt")));
    // blocked_file and audio_ok (via companion lyrics) were blocked by DLP gate -> 0 chunks & 0 dedup
    assert!(!chunks
        .iter()
        .any(|c| c.file_path.contains("secret_note.txt")));
    assert!(!chunks.iter().any(|c| c.file_path.contains("track.wav")));
    assert!(dedup.get_file_entry(&blocked_file).is_none());
    assert!(dedup.get_file_entry(&audio_ok).is_none());

    // note_b.txt was indexed with tier 2 and sanitized text in BOTH chunks and parent_documents
    let b_chunks: Vec<&DocumentChunk> = chunks
        .iter()
        .filter(|c| c.file_path.contains("note_b.txt"))
        .collect();
    assert!(!b_chunks.is_empty());
    assert!(b_chunks.iter().all(|c| c.access_tier == 2));
    assert!(b_chunks
        .iter()
        .all(|c| c.text_content.contains("[DLP_MASKED]")));
    assert!(b_chunks
        .iter()
        .all(|c| !c.text_content.contains("SANITIZE_ME")));

    // Update placeholder policy dynamically
    worker
        .update_placeholder_policy(CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024 * 1024,
        })
        .await;
    let snap = worker.config_snapshot().await;
    assert_eq!(
        snap.placeholder_policy,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024 * 1024
        }
    );
}

#[tokio::test]
async fn test_ingest_engine_dlp_blocks_text_image_and_audio_fail_closed() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let docs_dir = dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();

    // Gate blocks filename/content containing "BLOCK_IMAGE" or "BLOCK_TEXT" or "BLOCK_AUDIO"
    struct PathAndTextGate;
    impl DlpContentGate for PathAndTextGate {
        fn inspect_ingest_text(
            &self,
            file_path: &str,
            text: &str,
            _access_tier: u8,
        ) -> Result<String, String> {
            if text.contains("BLOCK_SECRET")
                || file_path.contains("blocked_img")
                || file_path.contains("blocked_audio")
            {
                Err("Blocked by PathAndTextGate".to_string())
            } else {
                Ok(text.to_string())
            }
        }
    }

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());

    let cfg = IngestConfig {
        watch_paths: vec![docs_dir.clone()],
        ..Default::default()
    };

    let engine = IngestEngine::new(cfg, Arc::clone(&storage), classifier, embedder)
        .unwrap()
        .with_dlp_gate(Arc::new(PathAndTextGate));

    let txt_path = docs_dir.join("secret.txt");
    let img_path = docs_dir.join("blocked_img.png");
    let wav_path = docs_dir.join("blocked_audio.wav");
    std::fs::write(&txt_path, "This contains BLOCK_SECRET payload").unwrap();
    std::fs::write(&img_path, minimal_png_bytes()).unwrap();
    std::fs::write(&wav_path, minimal_wav_bytes()).unwrap();

    assert!(matches!(
        engine.ingest_file(&txt_path).await,
        Err(IngestError::DlpBlocked { .. })
    ));
    assert!(matches!(
        engine.ingest_file(&img_path).await,
        Err(IngestError::DlpBlocked { .. })
    ));
    assert!(matches!(
        engine.ingest_file(&wav_path).await,
        Err(IngestError::DlpBlocked { .. })
    ));

    let stored = storage.scan_all_chunks().await.unwrap();
    assert!(stored.is_empty());
    assert!(engine.dedup().get_file_entry(&txt_path).is_none());
    assert!(engine.dedup().get_file_entry(&img_path).is_none());
    assert!(engine.dedup().get_file_entry(&wav_path).is_none());
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn test_windows_real_placeholder_attributes_skip_and_size_capped_hydration() {
    use std::os::windows::fs::MetadataExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    }

    fn set_win_attrs(path: &Path, attrs: u32) {
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let ok = unsafe { SetFileAttributesW(wide.as_ptr(), attrs) };
        assert_ne!(ok, 0, "SetFileAttributesW failed for {}", path.display());
    }

    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

    let dir = tempdir().unwrap();
    let stub_small = dir.path().join("small_stub.txt");
    let stub_large = dir.path().join("large_stub.txt");
    let stub_html = dir.path().join("small_stub.html");
    let synced_file = dir.path().join("synced.txt");
    let audio_file = dir.path().join("song.wav");
    let lyrics_stub = dir.path().join("song.lrc");

    std::fs::write(&stub_small, "small cloud placeholder content").unwrap();
    std::fs::write(&stub_large, "x".repeat(2048)).unwrap();
    std::fs::write(
        &stub_html,
        "<html><body><p>Hydrated HTML stub</p></body></html>",
    )
    .unwrap();
    std::fs::write(&synced_file, "locally synced document").unwrap();
    std::fs::write(&audio_file, minimal_wav_bytes()).unwrap();
    std::fs::write(&lyrics_stub, "cloud-only lyrics stub").unwrap();

    // Note: Windows kernel strips FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (0x0040_0000) when called via
    // user-mode SetFileAttributesW outside a Cloud Filter sync root, whereas FILE_ATTRIBUTE_OFFLINE
    // (0x1000) persists on live NTFS. Verify persisted bit directly via metadata.file_attributes().
    set_win_attrs(&stub_small, FILE_ATTRIBUTE_OFFLINE);
    set_win_attrs(&stub_large, FILE_ATTRIBUTE_OFFLINE);
    set_win_attrs(&stub_html, FILE_ATTRIBUTE_OFFLINE);
    set_win_attrs(&lyrics_stub, FILE_ATTRIBUTE_OFFLINE);

    for p in [&stub_small, &stub_large, &stub_html, &lyrics_stub] {
        let attrs = std::fs::metadata(p).unwrap().file_attributes();
        assert_ne!(
            attrs & FILE_ATTRIBUTE_OFFLINE,
            0,
            "FILE_ATTRIBUTE_OFFLINE must persist on {}",
            p.display()
        );
    }

    // Unit checks covering Cloud Filter RECALL_ON_DATA_ACCESS & RECALL_ON_OPEN bitmasks
    assert!(
        quorum_ingest::cloud_drives::is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        )
    );
    assert!(
        quorum_ingest::cloud_drives::is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_OPEN
        )
    );
    assert!(quorum_ingest::cloud_drives::should_skip_cloud_placeholder(
        quorum_ingest::cloud_drives::is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        ),
        512,
        CloudPlaceholderPolicy::LocallySyncedOnly
    ));
    assert!(!quorum_ingest::cloud_drives::should_skip_cloud_placeholder(
        quorum_ingest::cloud_drives::is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        ),
        512,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024
        }
    ));
    assert!(quorum_ingest::cloud_drives::should_skip_cloud_placeholder(
        quorum_ingest::cloud_drives::is_windows_cloud_placeholder_attrs(
            FILE_ATTRIBUTE_RECALL_ON_OPEN
        ),
        2048,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024
        }
    ));

    // 1. Default LocallySyncedOnly skips placeholders in ClassifierRouter & Crawler
    let cfg_local = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        placeholder_policy: CloudPlaceholderPolicy::LocallySyncedOnly,
        ..Default::default()
    };
    let router_local = ClassifierRouter::new(cfg_local.clone());
    assert_eq!(
        router_local.evaluate_file(&stub_small),
        FilterDecision::SkipCloudPlaceholder
    );
    assert_eq!(
        router_local.evaluate_file(&stub_large),
        FilterDecision::SkipCloudPlaceholder
    );
    assert!(matches!(
        router_local.evaluate_file(&synced_file),
        FilterDecision::Accept { .. }
    ));

    // Secondary open-site guards fail closed under LocallySyncedOnly
    let id_txt = FileTypeClassifier::new().classify_by_extension("small_stub.txt", 1.0);
    let id_html = FileTypeClassifier::new().classify_by_extension("small_stub.html", 1.0);
    assert!(Level1DedupCatalog::hash_file_stream(&stub_small).is_err());
    assert!(DocumentExtractor::extract_text(&stub_small, &id_txt).is_err());
    assert!(DocumentExtractor::extract_text(&stub_html, &id_html).is_err());
    assert!(ImageIndexer::run_ocr_on_file(&stub_small).is_none());
    let (has_lyrics, _, _) = AudioIndexer::find_companion_lyrics(&audio_file);
    assert!(
        !has_lyrics,
        "Sibling placeholder .lrc must not be read under LocallySyncedOnly"
    );

    // Crawler reports skipped placeholders without opening them
    let crawler = FilesystemCrawler::new(cfg_local.clone());
    let candidates = crawler.crawl_path_sync(dir.path()).unwrap();
    let cand_paths: HashSet<PathBuf> = candidates.into_iter().map(|c| c.path).collect();
    assert!(cand_paths.contains(&synced_file));
    assert!(!cand_paths.contains(&stub_small));
    assert!(!cand_paths.contains(&stub_large));
    assert!(!cand_paths.contains(&stub_html));
    assert!(!cand_paths.contains(&lyrics_stub));

    // 2. HydrateOnDemand { max_file_size_bytes: 1024 } allows small stub (<= 1024) and skips large (> 1024)
    let cfg_hydrate = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        placeholder_policy: CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024,
        },
        ..Default::default()
    };
    let router_hydrate = ClassifierRouter::new(cfg_hydrate.clone());
    assert!(matches!(
        router_hydrate.evaluate_file(&stub_small),
        FilterDecision::Accept { .. }
    ));
    assert_eq!(
        router_hydrate.evaluate_file(&stub_large),
        FilterDecision::SkipCloudPlaceholder
    );

    // Inner DocumentExtractor HTML extraction respects HydrateOnDemand policy
    let extracted_html = DocumentExtractor::extract_text_with_policy(
        &stub_html,
        &id_html,
        cfg_hydrate.placeholder_policy,
    )
    .expect("HydrateOnDemand within size cap must extract HTML stub");
    assert!(extracted_html.contains("Hydrated HTML stub"));

    // Cleanup attributes before tempdir drop
    set_win_attrs(&stub_small, FILE_ATTRIBUTE_NORMAL);
    set_win_attrs(&stub_large, FILE_ATTRIBUTE_NORMAL);
    set_win_attrs(&stub_html, FILE_ATTRIBUTE_NORMAL);
    set_win_attrs(&lyrics_stub, FILE_ATTRIBUTE_NORMAL);
}

#[tokio::test]
async fn test_image_audio_metadata_json_sanitized_and_docx_core_props_dlp_blocked() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let docs_dir = dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let gate: Arc<dyn DlpContentGate> = Arc::new(BlockingDlpGate {
        blocked_substring: "FORBIDDEN_PAYLOAD".to_string(),
    });

    let cfg = IngestConfig {
        watch_paths: vec![docs_dir.clone()],
        ..Default::default()
    };
    let engine = IngestEngine::new(cfg, Arc::clone(&storage), classifier, embedder)
        .unwrap()
        .with_dlp_gate(Arc::clone(&gate));

    // 1. Image with secret API key + SANITIZE_ME in PNG tEXt Comment metadata
    let secret_key = concat!("sk-", "1234567890abcdefghijklmnop");
    let img_path = docs_dir.join("annotated.png");
    std::fs::write(
        &img_path,
        png_with_comment_bytes(&format!("key={secret_key} note=SANITIZE_ME")),
    )
    .unwrap();

    let img_chunks = engine
        .ingest_file(&img_path)
        .await
        .expect("ingest image")
        .expect("image chunks");
    assert_eq!(img_chunks.len(), 1);

    // 2. Audio with secret API key + SANITIZE_ME in companion .lrc lyrics
    let wav_path = docs_dir.join("memo.wav");
    let lrc_path = docs_dir.join("memo.lrc");
    std::fs::write(&wav_path, minimal_wav_bytes()).unwrap();
    std::fs::write(
        &lrc_path,
        format!("Bearer {secret_key}\nLine two SANITIZE_ME"),
    )
    .unwrap();

    let wav_chunks = engine
        .ingest_file(&wav_path)
        .await
        .expect("ingest audio")
        .expect("audio chunks");
    assert_eq!(wav_chunks.len(), 1);

    // Verify stored chunks in storage have NEITHER raw secret NOR unmasked SANITIZE_ME
    // in BOTH text_content AND metadata_json (valid JSON).
    let stored = storage.scan_all_chunks().await.unwrap();
    let stored_img = stored
        .iter()
        .find(|c| c.file_path.contains("annotated.png"))
        .expect("stored image chunk");
    assert!(!stored_img.text_content.contains(secret_key));
    assert!(!stored_img.text_content.contains("SANITIZE_ME"));
    assert!(stored_img.text_content.contains("[DLP_MASKED]"));
    assert!(
        !stored_img.metadata_json.contains(secret_key),
        "Image metadata_json leaked raw secret: {}",
        stored_img.metadata_json
    );
    assert!(
        !stored_img.metadata_json.contains("SANITIZE_ME"),
        "Image metadata_json leaked unmasked DLP token: {}",
        stored_img.metadata_json
    );
    let img_meta_val: serde_json::Value =
        serde_json::from_str(&stored_img.metadata_json).expect("image metadata_json valid JSON");
    assert!(img_meta_val["user_comment"]
        .as_str()
        .unwrap_or("")
        .contains("[DLP_MASKED]"));

    let stored_wav = stored
        .iter()
        .find(|c| c.file_path.contains("memo.wav"))
        .expect("stored audio chunk");
    assert!(!stored_wav.text_content.contains(secret_key));
    assert!(!stored_wav.text_content.contains("SANITIZE_ME"));
    assert!(stored_wav.text_content.contains("[DLP_MASKED]"));
    assert!(
        !stored_wav.metadata_json.contains(secret_key),
        "Audio metadata_json leaked raw secret: {}",
        stored_wav.metadata_json
    );
    assert!(
        !stored_wav.metadata_json.contains("SANITIZE_ME"),
        "Audio metadata_json leaked unmasked DLP token: {}",
        stored_wav.metadata_json
    );
    let wav_meta_val: serde_json::Value =
        serde_json::from_str(&stored_wav.metadata_json).expect("audio metadata_json valid JSON");
    assert!(wav_meta_val["lyrics_text"]
        .as_str()
        .unwrap_or("")
        .contains("[DLP_MASKED]"));

    // 3. OpenXML .docx with FORBIDDEN_PAYLOAD inside docProps/core.xml <dc:title> must be blocked
    let docx_title_blocked = docs_dir.join("blocked_title.docx");
    let clean_doc_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:body><w:p><w:r><w:t>Benign body paragraph</w:t></w:r></w:p></w:body>
        </w:document>"#;
    let blocked_core_title_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                           xmlns:dc="http://purl.org/dc/elements/1.1/">
          <dc:title>FORBIDDEN_PAYLOAD in title</dc:title>
          <dc:creator>Alice</dc:creator>
        </cp:coreProperties>"#;
    let docx_bytes_1 = build_stored_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", clean_doc_xml),
        ("docProps/core.xml", blocked_core_title_xml),
    ]);
    std::fs::write(&docx_title_blocked, &docx_bytes_1).unwrap();

    assert!(matches!(
        engine.ingest_file(&docx_title_blocked).await,
        Err(IngestError::DlpBlocked { .. })
    ));

    // 4. OpenXML .docx with FORBIDDEN_PAYLOAD inside docProps/core.xml <dc:subject> must also be blocked
    let docx_subj_blocked = docs_dir.join("blocked_subject.docx");
    let blocked_core_subj_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                           xmlns:dc="http://purl.org/dc/elements/1.1/">
          <dc:title>Normal Title</dc:title>
          <dc:subject>FORBIDDEN_PAYLOAD in subject</dc:subject>
        </cp:coreProperties>"#;
    let docx_bytes_2 = build_stored_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", clean_doc_xml),
        ("docProps/core.xml", blocked_core_subj_xml),
    ]);
    std::fs::write(&docx_subj_blocked, &docx_bytes_2).unwrap();

    assert!(matches!(
        engine.ingest_file(&docx_subj_blocked).await,
        Err(IngestError::DlpBlocked { .. })
    ));

    let after_chunks = storage.scan_all_chunks().await.unwrap();
    assert!(!after_chunks
        .iter()
        .any(|c| c.file_path.contains("blocked_title.docx")
            || c.file_path.contains("blocked_subject.docx")));
    assert!(engine.dedup().get_file_entry(&docx_title_blocked).is_none());
    assert!(engine.dedup().get_file_entry(&docx_subj_blocked).is_none());
}

#[tokio::test]
async fn test_runtime_update_max_file_size_bytes_updates_engine_and_workers() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let docs_dir = dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());

    let cfg = IngestConfig {
        watch_paths: vec![docs_dir.clone()],
        max_file_size_bytes: 32,
        ..Default::default()
    };
    let engine = IngestEngine::new(cfg, Arc::clone(&storage), classifier, embedder).unwrap();

    let medium_doc = docs_dir.join("medium.txt");
    std::fs::write(&medium_doc, "a".repeat(128)).unwrap();
    // Under initial 32-byte cap, ingest_file skips via SkipExceedsSizeCap (Ok(None))
    assert!(engine.ingest_file(&medium_doc).await.unwrap().is_none());

    // Raising cap via IngestEngine::update_max_file_size_bytes propagates to engine, ReindexWorker, and DriftHealer
    let new_cap = 100 * 1024 * 1024;
    engine.update_max_file_size_bytes(new_cap).await;
    assert_eq!(engine.config_snapshot().await.max_file_size_bytes, new_cap);
    assert_eq!(
        engine
            .reindex_worker()
            .config_snapshot()
            .await
            .max_file_size_bytes,
        new_cap
    );
    assert_eq!(
        engine
            .drift_healer()
            .config_snapshot()
            .await
            .max_file_size_bytes,
        new_cap
    );
    assert!(engine.ingest_file(&medium_doc).await.unwrap().is_some());

    // Zero clamps to 1 byte on both child workers
    engine.reindex_worker().update_max_file_size_bytes(0).await;
    engine.drift_healer().update_max_file_size_bytes(0).await;
    assert_eq!(
        engine
            .reindex_worker()
            .config_snapshot()
            .await
            .max_file_size_bytes,
        1
    );
    assert_eq!(
        engine
            .drift_healer()
            .config_snapshot()
            .await
            .max_file_size_bytes,
        1
    );
}

#[tokio::test]
async fn test_cross_drive_identical_file_copy_dedup_and_prefix_purge() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let gdrive = dir.path().join("GoogleDrive");
    let dropbox = dir.path().join("Dropbox");
    std::fs::create_dir_all(&gdrive).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();

    let copy_g = gdrive.join("copy_g.txt");
    let copy_d = dropbox.join("copy_d.txt");
    let shared_body =
        "TOKEN_SHARED_COPY_CONTENT identical cryptographic knowledge across cloud drives.";
    std::fs::write(&copy_g, shared_body).unwrap();
    std::fs::write(&copy_d, shared_body).unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let cfg = IngestConfig {
        watch_paths: vec![gdrive.clone(), dropbox.clone()],
        ..Default::default()
    };
    let worker = ReindexWorker::new(
        cfg,
        Arc::clone(&storage),
        classifier,
        embedder,
        Arc::clone(&dedup),
    );

    // 1. Index Google Drive copy first
    let p1 = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![gdrive.clone()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(p1.files_indexed, 1);

    // 2. While copy_g still exists on disk, evaluating copy_d must yield ModifiedOrNew (not MovedOrRenamed)
    let meta_d = std::fs::metadata(&copy_d).unwrap();
    let mtime_d = meta_d
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let act_d = dedup.evaluate_file(&copy_d, mtime_d, meta_d.len()).unwrap();
    assert!(
        matches!(
            act_d,
            quorum_ingest::DedupAction::ModifiedOrNew { is_new: true, .. }
        ),
        "Live copy at a second distinct path must be ModifiedOrNew, got: {act_d:?}"
    );

    // 3. Indexing Dropbox copy inserts copy_d into storage while reusing Level-2 chunk cache
    let p2 = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![dropbox.clone()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(p2.files_indexed, 1);
    assert!(p2.chunks_reused_from_cache >= 1);

    // 4. Purging Google Drive reassigns catalog entry to surviving copy_d and preserves copy_d in storage
    let removed = dedup.remove_by_prefix(&gdrive);
    assert_eq!(removed, 1);
    let _ = storage
        .delete_by_path_prefix(&gdrive.to_string_lossy())
        .await
        .unwrap();
    let surviving_entry = dedup
        .get_file_entry(&copy_d)
        .expect("Surviving copy_d must remain tracked after purging copy_g");
    assert_eq!(surviving_entry.file_path, copy_d);
    let remaining_chunks = storage.scan_all_chunks().await.unwrap();
    assert!(
        remaining_chunks
            .iter()
            .any(|c| c.file_path == copy_d.to_string_lossy()),
        "copy_d must remain indexed in storage after purging Google Drive"
    );
    assert!(
        !remaining_chunks
            .iter()
            .any(|c| c.file_path == copy_g.to_string_lossy()),
        "copy_g must be purged from storage"
    );
}

#[tokio::test]
async fn test_run_reindex_sync_cancel_and_drain_resets_state_and_allows_start_reindex() {
    use quorum_ingest::ReindexPhase;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    struct GateEmbedder {
        inner: TestEmbedder,
        entered_once: AtomicBool,
        entered_notify: Arc<tokio::sync::Notify>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl EmbeddingGenerator for GateEmbedder {
        fn contract(&self) -> &EmbeddingContract {
            self.inner.contract()
        }

        fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
            if !self.entered_once.swap(true, Ordering::SeqCst) {
                self.entered_notify.notify_waiters();
                let (lock, cvar) = &*self.gate;
                let mut open = lock.lock().unwrap_or_else(|e| e.into_inner());
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                while !*open {
                    let rem = deadline.saturating_duration_since(std::time::Instant::now());
                    if rem.is_zero() {
                        break;
                    }
                    let (g, _) = cvar.wait_timeout(open, rem).unwrap();
                    open = g;
                }
            }
            self.inner.embed_text(text)
        }

        fn embed_batch(
            &self,
            texts: &[&str],
        ) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
            texts.iter().map(|t| self.embed_text(t)).collect()
        }
    }

    struct GateReleaseGuard(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for GateReleaseGuard {
        fn drop(&mut self) {
            let (lock, cvar) = &*self.0;
            let mut open = lock.lock().unwrap_or_else(|e| e.into_inner());
            *open = true;
            cvar.notify_all();
        }
    }

    let tmp = tempdir().unwrap();
    let watch_a = tmp.path().join("GoogleDrive");
    let watch_b = tmp.path().join("OneDrive");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&watch_a).unwrap();
    std::fs::create_dir_all(&watch_b).unwrap();

    for i in 0..10 {
        std::fs::write(
            watch_a.join(format!("doc_{i}.txt")),
            format!("GoogleDrive document number {i} for deterministic gate cancel test"),
        )
        .unwrap();
    }
    std::fs::write(
        watch_b.join("surviving.txt"),
        "OneDrive surviving document after cancel and drain",
    )
    .unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());

    let entered_notify = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let _release_guard = GateReleaseGuard(Arc::clone(&gate));

    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(GateEmbedder {
        inner: TestEmbedder::default(),
        entered_once: AtomicBool::new(false),
        entered_notify: Arc::clone(&entered_notify),
        gate: Arc::clone(&gate),
    });
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let cfg = IngestConfig {
        watch_paths: vec![watch_a.clone()],
        ..Default::default()
    };
    let worker = Arc::new(ReindexWorker::new(
        cfg,
        Arc::clone(&storage),
        classifier,
        embedder,
        Arc::clone(&dedup),
    ));

    let worker_bg = Arc::clone(&worker);
    let watch_a_bg = watch_a.clone();
    let entered_wait = entered_notify.notified();
    tokio::pin!(entered_wait);
    entered_wait.as_mut().enable();

    let sync_handle = tokio::spawn(async move {
        worker_bg
            .run_reindex_sync(ReindexOptions {
                target_paths: vec![watch_a_bg],
                batch_size: 2,
                ..Default::default()
            })
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), entered_wait)
        .await
        .expect("GateEmbedder should be entered promptly");

    let active_phase = worker.get_progress().await.map(|p| p.phase);
    assert_eq!(active_phase, Some(ReindexPhase::ChunkingAndVectorizing));

    let drained = worker.cancel_and_drain(Duration::from_secs(3)).await;
    {
        let (lock, cvar) = &*gate;
        let mut open = lock.lock().unwrap();
        *open = true;
        cvar.notify_all();
    }
    assert!(drained, "cancel_and_drain must return true promptly");

    let sync_res = sync_handle.await.unwrap();
    assert!(
        matches!(sync_res, Err(IngestError::Cancelled)),
        "Cancelled run_reindex_sync must return Err(Cancelled), got: {sync_res:?}"
    );
    assert_eq!(
        worker.get_progress().await.map(|p| p.phase),
        Some(ReindexPhase::Cancelled)
    );

    // Purge watch_a and immediately start_reindex on watch_b (must NOT return TaskAlreadyRunning)
    dedup.remove_by_prefix(&watch_a);
    storage
        .delete_by_path_prefix(&watch_a.to_string_lossy())
        .await
        .unwrap();
    worker.remove_watch_paths(&[watch_a.clone()]).await;

    worker
        .start_reindex(ReindexOptions {
            target_paths: vec![watch_b.clone()],
            ..Default::default()
        })
        .await
        .expect("start_reindex must succeed after cancelled run_reindex_sync");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(prog) = worker.get_progress().await {
            if prog.phase == ReindexPhase::Completed {
                break;
            }
            assert_ne!(prog.phase, ReindexPhase::Failed);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "start_reindex on watch_b timed out"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let chunks = storage.scan_all_chunks().await.unwrap();
    assert!(
        chunks.iter().any(|c| c.file_path.contains("surviving.txt")),
        "watch_b must be indexed after cancel_and_drain"
    );
    assert!(
        !chunks.iter().any(|c| {
            c.file_path
                .to_ascii_lowercase()
                .contains(&watch_a.to_string_lossy().to_ascii_lowercase())
        }),
        "Purged watch_a must have 0 chunks in storage"
    );
}

#[tokio::test]
async fn test_reindex_worker_dedup_storage_stress_under_live_io() {
    use quorum_ingest::ReindexPhase;
    use std::time::Duration;

    let tmp = tempdir().unwrap();
    let gdrive = tmp.path().join("GoogleDrive");
    let dropbox = tmp.path().join("Dropbox");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&gdrive).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();

    let shared_payload = "Shared quorum multi-drive payload that creates identical chunk_id across GoogleDrive and Dropbox.";
    let g_shared = gdrive.join("shared.txt");
    let d_shared = dropbox.join("shared.txt");
    std::fs::write(&g_shared, shared_payload).unwrap();
    std::fs::write(&d_shared, shared_payload).unwrap();
    for i in 0..4 {
        std::fs::write(
            gdrive.join(format!("gd_{i}.txt")),
            format!("Google drive stress file {i} unique content."),
        )
        .unwrap();
        std::fs::write(
            dropbox.join(format!("db_{i}.txt")),
            format!("Dropbox stress file {i} unique content."),
        )
        .unwrap();
    }

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let cfg = IngestConfig {
        watch_paths: vec![gdrive.clone(), dropbox.clone()],
        ..Default::default()
    };
    let worker = ReindexWorker::new(
        cfg,
        Arc::clone(&storage),
        classifier,
        embedder,
        Arc::clone(&dedup),
    );

    for cycle in 0..6 {
        worker
            .start_reindex(ReindexOptions {
                target_paths: vec![gdrive.clone(), dropbox.clone()],
                batch_size: 2,
                full_rebuild: cycle % 2 == 0,
                ..Default::default()
            })
            .await
            .expect("start_reindex should start cleanly on every cycle");

        let drained = worker.cancel_and_drain(Duration::from_secs(3)).await;
        assert!(drained, "cancel_and_drain timed out on cycle {cycle}");

        dedup.remove_by_prefix(&gdrive);
        storage
            .delete_by_path_prefix(&gdrive.to_string_lossy())
            .await
            .unwrap();

        let sync_prog = worker
            .run_reindex_sync(ReindexOptions {
                target_paths: vec![dropbox.clone()],
                batch_size: 2,
                ..Default::default()
            })
            .await
            .expect("run_reindex_sync on surviving dropbox must succeed");
        assert_eq!(sync_prog.phase, ReindexPhase::Completed);

        let all_chunks = storage.scan_all_chunks().await.unwrap();
        let g_norm = gdrive.to_string_lossy().to_ascii_lowercase();
        let d_shared_norm = d_shared.to_string_lossy().to_ascii_lowercase();
        assert!(
            !all_chunks
                .iter()
                .any(|c| c.file_path.to_ascii_lowercase().starts_with(&g_norm)),
            "Purged GoogleDrive must have 0 chunks on cycle {cycle}"
        );
        assert!(
            all_chunks
                .iter()
                .any(|c| c.file_path.to_ascii_lowercase() == d_shared_norm),
            "Surviving Dropbox shared copy must stay indexed on cycle {cycle}"
        );
        assert!(
            dedup.get_file_entry(&d_shared).is_some(),
            "Dedup catalog must retain surviving Dropbox shared copy on cycle {cycle}"
        );
    }
}

#[tokio::test]
async fn test_drift_healer_acl_policy_preserves_identical_content_sibling_across_drives() {
    use quorum_ingest::config::{DriftFixOptions, DriftType};
    use quorum_ingest::drift_healer::DriftHealer;

    let tmp = tempdir().unwrap();
    let gdrive = tmp.path().join("GoogleDrive");
    let dropbox = tmp.path().join("Dropbox");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&gdrive).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();

    let identical = "Identical file across Google Drive and Dropbox for ACL drift healing.";
    let g_file = gdrive.join("shared.txt");
    let d_file = dropbox.join("shared.txt");
    std::fs::write(&g_file, identical).unwrap();
    std::fs::write(&d_file, identical).unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let cfg = IngestConfig {
        watch_paths: vec![gdrive.clone(), dropbox.clone()],
        access_tier_rules: vec![(gdrive.clone(), 3), (dropbox.clone(), 3)],
        ..Default::default()
    };
    let worker = ReindexWorker::new(
        cfg.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );
    let prog = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![gdrive.clone(), dropbox.clone()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(prog.files_indexed, 2);

    // Now reclassify GoogleDrive -> Tier 1 while keeping Dropbox at Tier 3
    let new_rules = vec![(gdrive.clone(), 1), (dropbox.clone(), 3)];
    let healer_cfg = IngestConfig {
        watch_paths: vec![gdrive.clone(), dropbox.clone()],
        access_tier_rules: new_rules.clone(),
        ..Default::default()
    };
    let healer = DriftHealer::new(
        healer_cfg,
        Arc::clone(&storage),
        classifier,
        embedder,
        dedup,
    );
    let report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::AclPolicy],
            dry_run: false,
            access_tier_rules: new_rules,
        })
        .await
        .unwrap();
    assert_eq!(report.acl_drifted_chunks_updated, 1);

    let all_chunks = storage.scan_all_chunks().await.unwrap();
    let g_chunk = all_chunks
        .iter()
        .find(|c| c.file_path == g_file.to_string_lossy())
        .expect("GDrive copy must remain in storage");
    let d_chunk = all_chunks
        .iter()
        .find(|c| c.file_path == d_file.to_string_lossy())
        .expect("Dropbox sibling must remain in storage after DriftHealer ACL heal");
    assert_eq!(g_chunk.access_tier, 1);
    assert_eq!(d_chunk.access_tier, 3);
}

#[derive(Debug, Clone)]
struct DelayedTestEmbedder {
    inner: TestEmbedder,
    delay: std::time::Duration,
}

impl EmbeddingGenerator for DelayedTestEmbedder {
    fn contract(&self) -> &EmbeddingContract {
        self.inner.contract()
    }

    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        std::thread::sleep(self.delay);
        self.inner.embed_text(text)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
        std::thread::sleep(self.delay);
        self.inner.embed_batch(texts)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t5_concurrent_run_reindex_sync_vs_cancel_and_drain_no_resurrection() {
    use quorum_ingest::reindex::ReindexPhase;
    use quorum_storage::StorageSearchQuery;

    let tmp = tempdir().unwrap();
    let drive_a = tmp.path().join("DriveA");
    let drive_b = tmp.path().join("DriveB");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&drive_a).unwrap();
    std::fs::create_dir_all(&drive_b).unwrap();

    for i in 0..4 {
        std::fs::write(
            drive_a.join(format!("a_{i}.txt")),
            format!("DriveA baseline file {i} content"),
        )
        .unwrap();
    }
    for i in 0..16 {
        std::fs::write(
            drive_b.join(format!("b_{i}.txt")),
            format!("TOKEN_RESURRECT_PROBE DriveB file {i} secret payload"),
        )
        .unwrap();
    }

    let storage = Arc::new(
        StorageEngine::open(StorageConfig::new(&storage_dir))
            .await
            .unwrap(),
    );
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(DelayedTestEmbedder {
        inner: TestEmbedder::default(),
        delay: std::time::Duration::from_millis(60),
    });
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let catalog_path = storage_dir.join("dedup_catalog.json");

    let cfg = IngestConfig {
        watch_paths: vec![drive_a.clone(), drive_b.clone()],
        access_tier_rules: vec![(drive_a.clone(), 0), (drive_b.clone(), 3)],
        dedup_catalog_path: Some(catalog_path.clone()),
        ..Default::default()
    };
    let worker = Arc::new(ReindexWorker::new(
        cfg,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    for delay_ms in [15u64, 35, 55, 75, 95] {
        // Clear DriveB before each timing trial
        let _ = storage
            .delete_by_path_prefix(&drive_b.to_string_lossy())
            .await;
        let _ = dedup.remove_by_prefix(&drive_b);

        // Task A occupies `self.active_task`
        let _task_a_id = worker
            .start_reindex(ReindexOptions {
                target_paths: vec![drive_a.clone()],
                full_rebuild: true,
                force_reembed: true,
                batch_size: 2,
                num_threads: 1,
                dry_run: false,
            })
            .await
            .expect("Task A start_reindex");

        // Wait until Task A is actively running
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // Task B runs concurrently via `run_reindex_sync` (`use_shared_active == false`)
        let worker_b = Arc::clone(&worker);
        let drive_b_c = drive_b.clone();
        let task_b_handle = tokio::spawn(async move {
            worker_b
                .run_reindex_sync(ReindexOptions {
                    target_paths: vec![drive_b_c],
                    full_rebuild: true,
                    force_reembed: true,
                    batch_size: 4,
                    num_threads: 2,
                    dry_run: false,
                })
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;

        let drained = worker
            .cancel_and_drain(std::time::Duration::from_secs(10))
            .await;
        assert!(
            drained,
            "cancel_and_drain must wait for BOTH Task A and concurrent run_reindex_sync Task B (delay={delay_ms}ms)"
        );

        let _purge_barrier = worker.acquire_purge_barrier().await;
        let _ = storage
            .delete_by_path_prefix(&drive_b.to_string_lossy())
            .await
            .unwrap();
        let _ = dedup.remove_by_prefix_and_save(&drive_b, Some(&catalog_path));
        drop(_purge_barrier);

        let task_b_res = task_b_handle.await.expect("Task B join");
        assert!(
            matches!(task_b_res, Err(IngestError::Cancelled))
                || matches!(
                    task_b_res.as_ref().map(|p| p.phase),
                    Ok(ReindexPhase::Cancelled)
                )
                || task_b_res.is_ok(),
            "Task B finished unexpectedly: {task_b_res:?}"
        );

        // Give scheduler a tick and assert ZERO resurrected chunks/docs/dedup entries for DriveB!
        tokio::task::yield_now().await;
        let kw_hits = storage
            .search(&StorageSearchQuery::keyword("TOKEN_RESURRECT_PROBE", 3, 50))
            .await
            .unwrap();
        let b_norm = quorum_types::normalize_prefix_for_match(&drive_b.to_string_lossy()).unwrap();
        let b_kw = kw_hits
            .iter()
            .filter(|h| {
                quorum_types::path_matches_prefix(&h.chunk.file_path, &b_norm).unwrap_or(false)
            })
            .count();
        let b_lance = storage
            .scan_all_chunks()
            .await
            .unwrap()
            .into_iter()
            .filter(|c| quorum_types::path_matches_prefix(&c.file_path, &b_norm).unwrap_or(false))
            .count();
        let b_cat = storage
            .catalog()
            .list_all_file_identities()
            .unwrap()
            .into_iter()
            .filter(|id| quorum_types::path_matches_prefix(&id.file_path, &b_norm).unwrap_or(false))
            .count();
        let b_dedup = dedup
            .get_all_tracked_files()
            .into_iter()
            .filter(|p| {
                quorum_types::path_matches_prefix(&p.to_string_lossy(), &b_norm).unwrap_or(false)
            })
            .count();
        assert_eq!(b_kw, 0, "Tantivy resurrected chunks at delay={delay_ms}ms");
        assert_eq!(
            b_lance, 0,
            "LanceDB resurrected chunks at delay={delay_ms}ms"
        );
        assert_eq!(
            b_cat, 0,
            "DocumentCatalog resurrected docs at delay={delay_ms}ms"
        );
        assert_eq!(
            b_dedup, 0,
            "Dedup catalog resurrected entries at delay={delay_ms}ms"
        );
    }
}

#[test]
fn t5_dedup_level1_windows_slash_case_variant_fast_path() {
    use quorum_ingest::dedup::DedupAction;

    let tmp = tempdir().unwrap();
    let dir = tmp.path().join("MixedCaseDir");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("ReportDoc.txt");
    std::fs::write(&file_path, "Windows slash and case dedup fast-path payload").unwrap();

    let meta = std::fs::metadata(&file_path).unwrap();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let size = meta.len();

    let mut catalog = Level1DedupCatalog::new();
    let hash = Level1DedupCatalog::hash_file_stream(&file_path).unwrap();
    catalog.register_entry(FileCatalogEntry {
        file_path: file_path.clone(),
        file_blake3: hash.clone(),
        mtime_secs: mtime,
        size_bytes: size,
        chunk_hashes: vec!["ch_0".to_string()],
    });

    if cfg!(windows) {
        let variant = file_path
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let action = catalog
            .evaluate_file_with_policy(
                Path::new(&variant),
                mtime,
                size,
                CloudPlaceholderPolicy::LocallySyncedOnly,
            )
            .unwrap();
        assert!(
            matches!(action, DedupAction::Unchanged { ref file_blake3, .. } if file_blake3 == &hash),
            "Windows slash/case variant '{variant}' must hit L1 Unchanged fast-path, got {action:?}"
        );
    } else {
        let exact = catalog
            .evaluate_file_with_policy(
                &file_path,
                mtime,
                size,
                CloudPlaceholderPolicy::LocallySyncedOnly,
            )
            .unwrap();
        assert!(matches!(exact, DedupAction::Unchanged { .. }));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t5_start_reindex_vs_cancel_and_drain_and_blocked_prefix_no_resurrection() {
    use quorum_ingest::reindex::ReindexPhase;
    use quorum_storage::StorageSearchQuery;

    let tmp = tempdir().unwrap();
    let drive_a = tmp.path().join("DriveA");
    let drive_b = tmp.path().join("DriveB");
    let storage_dir = tmp.path().join("storage");
    std::fs::create_dir_all(&drive_a).unwrap();
    std::fs::create_dir_all(&drive_b).unwrap();

    for i in 0..4 {
        std::fs::write(
            drive_a.join(format!("a_{i}.txt")),
            format!("DriveA surviving file {i} content"),
        )
        .unwrap();
    }
    for i in 0..12 {
        std::fs::write(
            drive_b.join(format!("b_{i}.txt")),
            format!("TOKEN_T5_START_REINDEX_TOCTOU DriveB file {i} secret payload"),
        )
        .unwrap();
    }

    let storage = Arc::new(
        StorageEngine::open(StorageConfig::new(&storage_dir))
            .await
            .unwrap(),
    );
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(DelayedTestEmbedder {
        inner: TestEmbedder::default(),
        delay: std::time::Duration::from_millis(50),
    });
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let catalog_path = storage_dir.join("dedup_catalog.json");

    let cfg = IngestConfig {
        watch_paths: vec![drive_a.clone(), drive_b.clone()],
        access_tier_rules: vec![(drive_a.clone(), 0), (drive_b.clone(), 3)],
        dedup_catalog_path: Some(catalog_path.clone()),
        ..Default::default()
    };
    let worker = Arc::new(ReindexWorker::new(
        cfg,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    let b_norm = quorum_types::normalize_prefix_for_match(&drive_b.to_string_lossy()).unwrap();

    // Part 1: Race `start_reindex` against `cancel_and_drain` across multiple delays & assert purge_epoch advances
    for delay_ms in [5u64, 25, 55, 85] {
        let epoch_before = worker.current_purge_epoch();
        let _ = storage
            .delete_by_path_prefix(&drive_b.to_string_lossy())
            .await;
        let _ = dedup.remove_by_prefix(&drive_b);

        let _task_id = worker
            .start_reindex(ReindexOptions {
                target_paths: vec![drive_b.clone()],
                full_rebuild: true,
                force_reembed: true,
                batch_size: 2,
                num_threads: 2,
                dry_run: false,
            })
            .await
            .expect("start_reindex should succeed");

        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;

        let drained = worker
            .cancel_and_drain(std::time::Duration::from_secs(10))
            .await;
        assert!(
            drained,
            "cancel_and_drain must drain start_reindex task (delay={delay_ms}ms)"
        );
        assert!(
            worker.current_purge_epoch() > epoch_before,
            "cancel_and_drain must monotonically advance purge_epoch"
        );

        let _purge_barrier = worker.acquire_purge_barrier().await;
        let _ = storage
            .delete_by_path_prefix(&drive_b.to_string_lossy())
            .await
            .unwrap();
        let _ = dedup.remove_by_prefix_and_save(&drive_b, Some(&catalog_path));
        drop(_purge_barrier);

        // Immediately start a new task on drive_a (which resets cancel_flag = false)
        // and confirm drive_b stays at 0 across all 4 stores + dedup.
        worker
            .start_reindex(ReindexOptions {
                target_paths: vec![drive_a.clone()],
                batch_size: 4,
                num_threads: 2,
                ..Default::default()
            })
            .await
            .expect("start_reindex on drive_a after cancel_and_drain");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(prog) = worker.get_progress().await {
                if !matches!(
                    prog.phase,
                    ReindexPhase::ScanningFilesystem
                        | ReindexPhase::ChunkingAndVectorizing
                        | ReindexPhase::WritingToStorage
                        | ReindexPhase::CompactingIndexes
                ) {
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "drive_a reindex timed out"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        let kw_hits = storage
            .search(&StorageSearchQuery::keyword(
                "TOKEN_T5_START_REINDEX_TOCTOU",
                3,
                50,
            ))
            .await
            .unwrap();
        assert_eq!(
            kw_hits
                .iter()
                .filter(
                    |h| quorum_types::path_matches_prefix(&h.chunk.file_path, &b_norm)
                        .unwrap_or(false)
                )
                .count(),
            0,
            "Tantivy resurrected chunks at delay={delay_ms}ms"
        );
        assert_eq!(
            storage
                .scan_all_chunks()
                .await
                .unwrap()
                .into_iter()
                .filter(
                    |c| quorum_types::path_matches_prefix(&c.file_path, &b_norm).unwrap_or(false)
                )
                .count(),
            0,
            "LanceDB resurrected chunks at delay={delay_ms}ms"
        );
        assert_eq!(
            storage
                .catalog()
                .list_all_file_identities()
                .unwrap()
                .into_iter()
                .filter(
                    |id| quorum_types::path_matches_prefix(&id.file_path, &b_norm).unwrap_or(false)
                )
                .count(),
            0,
            "DocumentCatalog resurrected docs at delay={delay_ms}ms"
        );
        assert_eq!(
            dedup
                .get_all_tracked_files()
                .into_iter()
                .filter(
                    |p| quorum_types::path_matches_prefix(&p.to_string_lossy(), &b_norm)
                        .unwrap_or(false)
                )
                .count(),
            0,
            "Dedup resurrected entries at delay={delay_ms}ms"
        );
    }

    // Part 2: Verify `blocked_prefixes` post-await enforcement under `commit_gate.read().await`
    // even when a task already passed initial target filtering before `update_blocked_prefixes`.
    let _ = storage
        .delete_by_path_prefix(&drive_b.to_string_lossy())
        .await;
    let _ = dedup.remove_by_prefix(&drive_b);

    worker
        .start_reindex(ReindexOptions {
            target_paths: vec![drive_b.clone()],
            full_rebuild: true,
            force_reembed: true,
            batch_size: 4,
            num_threads: 1,
            dry_run: false,
        })
        .await
        .expect("start_reindex for blocked_prefixes mid-flight test");

    // Allow crawl to complete and extraction to start, then block drive_b mid-flight
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    worker.update_blocked_prefixes(vec![drive_b.to_string_lossy().to_string()]);
    worker.remove_watch_paths(&[drive_b.clone()]).await;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Some(prog) = worker.get_progress().await {
            if !matches!(
                prog.phase,
                ReindexPhase::ScanningFilesystem
                    | ReindexPhase::ChunkingAndVectorizing
                    | ReindexPhase::WritingToStorage
                    | ReindexPhase::CompactingIndexes
            ) {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "mid-flight blocked_prefixes test timed out"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // Purge anything that may have flushed in the initial 20ms window before blocking,
    // and verify a subsequent run_reindex_sync targeting drive_b commits 0 chunks.
    let _ = storage
        .delete_by_path_prefix(&drive_b.to_string_lossy())
        .await;
    let _ = dedup.remove_by_prefix(&drive_b);

    let post_block = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![drive_b.clone()],
            full_rebuild: true,
            force_reembed: true,
            batch_size: 4,
            num_threads: 1,
            dry_run: false,
        })
        .await
        .expect("run_reindex_sync on blocked path completes cleanly with 0 commits");
    assert_eq!(post_block.files_indexed, 0);
    assert_eq!(
        storage
            .scan_all_chunks()
            .await
            .unwrap()
            .into_iter()
            .filter(|c| quorum_types::path_matches_prefix(&c.file_path, &b_norm).unwrap_or(false))
            .count(),
        0,
        "Blocked prefix must never commit chunks to storage"
    );
    assert_eq!(
        dedup
            .get_all_tracked_files()
            .into_iter()
            .filter(
                |p| quorum_types::path_matches_prefix(&p.to_string_lossy(), &b_norm)
                    .unwrap_or(false)
            )
            .count(),
        0,
        "Blocked prefix must never commit entries to dedup catalog"
    );
}

#[tokio::test]
async fn test_drift_healer_cancel_and_drain_prevents_resurrection_under_shared_purge_barrier() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let drive_a = dir.path().join("DriveA");
    let drive_b = dir.path().join("DriveB_Dropbox");
    std::fs::create_dir_all(&drive_a).unwrap();
    std::fs::create_dir_all(&drive_b).unwrap();

    for i in 0..8 {
        std::fs::write(
            drive_a.join(format!("a_{i}.txt")),
            format!("TOKEN_DRIFT_KEEP_A_{i} persistent content"),
        )
        .unwrap();
        std::fs::write(
            drive_b.join(format!("b_{i}.txt")),
            format!("TOKEN_DRIFT_PURGE_B_{i} initial cloud content"),
        )
        .unwrap();
    }

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let cfg = IngestConfig {
        watch_paths: vec![drive_a.clone(), drive_b.clone()],
        ..Default::default()
    };

    let worker = Arc::new(ReindexWorker::new(
        cfg.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));
    let healer = Arc::new(
        quorum_ingest::DriftHealer::new(
            cfg,
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        )
        .with_reindex_barrier(&worker),
    );

    let b_norm = quorum_types::normalize_prefix_for_match(&drive_b.to_string_lossy()).unwrap();

    for delay_ms in [0u64, 5, 15, 35] {
        worker.update_blocked_prefixes(Vec::new());
        worker.add_watch_paths(&[drive_a.clone(), drive_b.clone()]);
        healer
            .update_watch_paths(vec![drive_a.clone(), drive_b.clone()])
            .await;

        worker
            .run_reindex_sync(ReindexOptions {
                target_paths: vec![drive_a.clone(), drive_b.clone()],
                full_rebuild: true,
                force_reembed: true,
                batch_size: 4,
                num_threads: 2,
                dry_run: false,
            })
            .await
            .expect("initial reindex");

        // Modify drive_b files with distinct size/content so MerkleState DriftHealer triggers reingest
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        for i in 0..8 {
            std::fs::write(
                drive_b.join(format!("b_{i}.txt")),
                format!("TOKEN_DRIFT_PURGE_B_{i} modified larger cloud payload iteration_{delay_ms}_extra"),
            )
            .unwrap();
        }

        let healer_c = Arc::clone(&healer);
        let drift_task = tokio::spawn(async move {
            healer_c
                .fix_all_drifts(quorum_ingest::DriftFixOptions {
                    target_drifts: vec![quorum_ingest::DriftType::MerkleState],
                    dry_run: false,
                    access_tier_rules: Vec::new(),
                })
                .await
        });

        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }

        // Simulate disable+purge sequence from DaemonState::unwatch_and_purge_prefix
        healer.update_blocked_prefixes(vec![b_norm.clone()]);
        worker.remove_watch_paths(&[drive_b.clone()]).await;
        healer.remove_watch_paths(&[drive_b.clone()]).await;
        let w_drained = worker
            .cancel_and_drain(std::time::Duration::from_secs(5))
            .await;
        let h_drained = healer
            .cancel_and_drain(std::time::Duration::from_secs(5))
            .await;
        assert!(w_drained, "worker cancel_and_drain timed out");
        assert!(h_drained, "healer cancel_and_drain timed out");
        assert!(healer.shares_commit_gate_with(&worker));
        {
            let _purge_barrier = worker.acquire_purge_barrier().await;
            storage
                .delete_by_path_prefix(&b_norm)
                .await
                .expect("purge drive_b");
            let _ = dedup.remove_by_prefix(&drive_b);
        }

        let drift_res = drift_task.await.expect("drift_task join");
        assert!(
            matches!(drift_res, Ok(_) | Err(IngestError::Cancelled)),
            "Unexpected drift result at delay={delay_ms}ms: {drift_res:?}"
        );

        // Verify drive_b has 0 chunks across LanceDB, Tantivy, SQLite, and Dedup
        let kw_hits = storage
            .search(&quorum_storage::StorageSearchQuery::keyword(
                "TOKEN_DRIFT_PURGE_B",
                3,
                50,
            ))
            .await
            .unwrap();
        assert_eq!(
            kw_hits
                .iter()
                .filter(
                    |h| quorum_types::path_matches_prefix(&h.chunk.file_path, &b_norm)
                        .unwrap_or(false)
                )
                .count(),
            0,
            "Tantivy resurrected chunks from DriftHealer at delay={delay_ms}ms"
        );
        assert_eq!(
            storage
                .scan_all_chunks()
                .await
                .unwrap()
                .into_iter()
                .filter(
                    |c| quorum_types::path_matches_prefix(&c.file_path, &b_norm).unwrap_or(false)
                )
                .count(),
            0,
            "LanceDB resurrected chunks from DriftHealer at delay={delay_ms}ms"
        );
        assert_eq!(
            storage
                .catalog()
                .list_all_file_identities()
                .unwrap()
                .into_iter()
                .filter(
                    |id| quorum_types::path_matches_prefix(&id.file_path, &b_norm).unwrap_or(false)
                )
                .count(),
            0,
            "DocumentCatalog resurrected docs from DriftHealer at delay={delay_ms}ms"
        );
        assert_eq!(
            dedup
                .get_all_tracked_files()
                .into_iter()
                .filter(
                    |p| quorum_types::path_matches_prefix(&p.to_string_lossy(), &b_norm)
                        .unwrap_or(false)
                )
                .count(),
            0,
            "Dedup resurrected entries from DriftHealer at delay={delay_ms}ms"
        );

        // Also verify a subsequent full DriftHealer run with drive_b blocked commits 0 drive_b chunks
        let post_report = healer
            .fix_all_drifts(quorum_ingest::DriftFixOptions::default())
            .await
            .expect("post-purge drift fix");
        assert_eq!(
            storage
                .scan_all_chunks()
                .await
                .unwrap()
                .into_iter()
                .filter(
                    |c| quorum_types::path_matches_prefix(&c.file_path, &b_norm).unwrap_or(false)
                )
                .count(),
            0,
            "Post-purge DriftHealer resurrected blocked drive_b chunks (report={post_report:?})"
        );

        // DriveA must remain intact
        let a_norm = quorum_types::normalize_prefix_for_match(&drive_a.to_string_lossy()).unwrap();
        assert!(
            storage
                .scan_all_chunks()
                .await
                .unwrap()
                .iter()
                .any(|c| quorum_types::path_matches_prefix(&c.file_path, &a_norm).unwrap_or(false)),
            "DriveA must remain indexed"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t5_upgrade_degraded_and_legacy_image_chunks_respect_purge_barrier_no_resurrection() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    struct PauseState {
        armed: AtomicBool,
        entered_count: AtomicUsize,
        released: Mutex<bool>,
        entered_notify: tokio::sync::Notify,
        released_cv: Condvar,
    }

    impl PauseState {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                armed: AtomicBool::new(false),
                entered_count: AtomicUsize::new(0),
                released: Mutex::new(false),
                entered_notify: tokio::sync::Notify::new(),
                released_cv: Condvar::new(),
            })
        }

        fn reset(&self, arm: bool) {
            let mut rel = self.released.lock().unwrap();
            *rel = false;
            self.entered_count.store(0, Ordering::SeqCst);
            self.armed.store(arm, Ordering::SeqCst);
        }

        async fn wait_until_entered(&self, timeout: Duration) -> bool {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let notified = self.entered_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.entered_count.load(Ordering::SeqCst) > 0 {
                    return true;
                }
                let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                if rem.is_zero() {
                    return false;
                }
                let _ = tokio::time::timeout(rem, notified).await;
            }
        }

        fn release(&self) {
            let mut rel = self.released.lock().unwrap();
            *rel = true;
            self.armed.store(false, Ordering::SeqCst);
            self.released_cv.notify_all();
        }
    }

    struct PausingEmbedder {
        inner: TestEmbedder,
        pause: Arc<PauseState>,
    }

    impl EmbeddingGenerator for PausingEmbedder {
        fn contract(&self) -> &EmbeddingContract {
            self.inner.contract()
        }

        fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
            if self.pause.armed.load(Ordering::SeqCst) {
                let mut rel = self.pause.released.lock().unwrap();
                self.pause.entered_count.fetch_add(1, Ordering::SeqCst);
                self.pause.entered_notify.notify_waiters();
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while !*rel {
                    let rem = deadline.saturating_duration_since(std::time::Instant::now());
                    if rem.is_zero() {
                        break;
                    }
                    let (guard, _) = self.pause.released_cv.wait_timeout(rel, rem).unwrap();
                    rel = guard;
                }
            }
            self.inner.embed_text(text)
        }

        fn embed_batch(
            &self,
            texts: &[&str],
        ) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
            texts.iter().map(|t| self.embed_text(t)).collect()
        }
    }

    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let drive_doc = dir.path().join("DriveDoc");
    let drive_img = dir.path().join("DriveImg");
    let drive_blocked = dir.path().join("DriveBlocked");
    std::fs::create_dir_all(&drive_doc).unwrap();
    std::fs::create_dir_all(&drive_img).unwrap();
    std::fs::create_dir_all(&drive_blocked).unwrap();

    let docx_bytes = build_stored_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        (
            "word/document.xml",
            b"<w:document><w:body><w:p><w:r><w:t>TOKEN_T5_UPGRADE_DOC_PURGE recovered body text for native extraction.</w:t></w:r></w:p></w:body></w:document>",
        ),
    ]);
    let doc_path = drive_doc.join("report.docx");
    std::fs::write(&doc_path, &docx_bytes).unwrap();
    let doc_b3 = blake3::hash(&docx_bytes).to_hex().to_string();

    let img_bytes = png_with_comment_bytes("TOKEN_T5_UPGRADE_IMG_PURGE");
    let img_path = drive_img.join("legacy.png");
    std::fs::write(&img_path, &img_bytes).unwrap();
    let img_b3 = blake3::hash(&img_bytes).to_hex().to_string();

    let blocked_doc_path = drive_blocked.join("blocked.docx");
    std::fs::write(&blocked_doc_path, &docx_bytes).unwrap();
    let blocked_img_path = drive_blocked.join("blocked.png");
    std::fs::write(&blocked_img_path, &img_bytes).unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let pause = PauseState::new();
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(PausingEmbedder {
        inner: TestEmbedder::default(),
        pause: Arc::clone(&pause),
    });
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let worker = Arc::new(ReindexWorker::new(
        IngestConfig {
            watch_paths: vec![drive_doc.clone(), drive_img.clone()],
            ..Default::default()
        },
        Arc::clone(&storage),
        classifier,
        embedder,
        Arc::clone(&dedup),
    ));

    // Part 1: Race `upgrade_degraded_document_chunks` during embedding vs `cancel_and_drain` + purge
    let degraded_chunk = DocumentChunk::new(
        format!("{doc_b3}:0"),
        doc_b3.clone(),
        doc_path.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.05; 768],
        "[Word/Document (docx) — report.docx]\n[Content_Types].xml\nword/document.xml",
        None,
    )
    .unwrap();
    storage.insert_chunks(&[degraded_chunk]).await.unwrap();

    pause.reset(true);
    let worker_doc = Arc::clone(&worker);
    let upgrade_doc_task =
        tokio::spawn(async move { worker_doc.upgrade_degraded_document_chunks().await });
    assert!(
        pause.wait_until_entered(Duration::from_secs(5)).await,
        "upgrade_degraded_document_chunks did not enter embedder"
    );

    let doc_norm = quorum_types::normalize_prefix_for_match(&drive_doc.to_string_lossy()).unwrap();
    worker.update_blocked_prefixes(vec![doc_norm.clone()]);
    let drained_doc = worker.cancel_and_drain(Duration::from_secs(5)).await;
    assert!(
        drained_doc,
        "cancel_and_drain must drain/abort active upgrade_degraded_document_chunks"
    );
    {
        let _barrier = worker.acquire_purge_barrier().await;
        storage.delete_by_path_prefix(&doc_norm).await.unwrap();
        let _ = dedup.remove_by_prefix(&drive_doc);
    }
    pause.release();

    let doc_res = upgrade_doc_task.await.expect("doc task join");
    assert!(
        matches!(doc_res, Err(IngestError::Cancelled)),
        "Expected Cancelled from aborted upgrade_degraded_document_chunks, got {doc_res:?}"
    );
    assert!(
        storage
            .scan_all_chunks()
            .await
            .unwrap()
            .into_iter()
            .filter(|c| quorum_types::path_matches_prefix(&c.file_path, &doc_norm).unwrap_or(false))
            .count()
            == 0,
        "upgrade_degraded_document_chunks resurrected purged chunks!"
    );
    assert!(dedup.get_file_entry(&doc_path).is_none());

    // Part 2: Race `upgrade_legacy_image_chunks` during embedding vs `cancel_and_drain` + purge
    let legacy_img_chunk = DocumentChunk::new(
        format!("{img_b3}:img:0"),
        img_b3.clone(),
        img_path.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.05; 768],
        "[Image Document: legacy.png]\nFormat: PNG (image/png)",
        Some("{\"mime_type\":\"image/png\"}".to_string()),
    )
    .unwrap();
    storage.insert_chunks(&[legacy_img_chunk]).await.unwrap();

    pause.reset(true);
    let worker_img = Arc::clone(&worker);
    let upgrade_img_task =
        tokio::spawn(async move { worker_img.upgrade_legacy_image_chunks().await });
    assert!(
        pause.wait_until_entered(Duration::from_secs(5)).await,
        "upgrade_legacy_image_chunks did not enter embedder"
    );

    let img_norm = quorum_types::normalize_prefix_for_match(&drive_img.to_string_lossy()).unwrap();
    worker.update_blocked_prefixes(vec![doc_norm, img_norm.clone()]);
    let drained_img = worker.cancel_and_drain(Duration::from_secs(5)).await;
    assert!(
        drained_img,
        "cancel_and_drain must drain/abort active upgrade_legacy_image_chunks"
    );
    {
        let _barrier = worker.acquire_purge_barrier().await;
        storage.delete_by_path_prefix(&img_norm).await.unwrap();
        let _ = dedup.remove_by_prefix(&drive_img);
    }
    pause.release();

    let img_res = upgrade_img_task.await.expect("img task join");
    assert!(
        matches!(img_res, Err(IngestError::Cancelled)),
        "Expected Cancelled from aborted upgrade_legacy_image_chunks, got {img_res:?}"
    );
    assert!(
        storage
            .scan_all_chunks()
            .await
            .unwrap()
            .into_iter()
            .filter(|c| quorum_types::path_matches_prefix(&c.file_path, &img_norm).unwrap_or(false))
            .count()
            == 0,
        "upgrade_legacy_image_chunks resurrected purged chunks!"
    );
    assert!(dedup.get_file_entry(&img_path).is_none());

    // Part 3: Without cancellation, blocked_prefixes still skips blocked chunks cleanly
    let blocked_norm =
        quorum_types::normalize_prefix_for_match(&drive_blocked.to_string_lossy()).unwrap();
    worker.update_blocked_prefixes(vec![blocked_norm.clone()]);
    let blocked_degraded = DocumentChunk::new(
        "blocked_doc:0",
        doc_b3,
        blocked_doc_path.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.05; 768],
        "[Word/Document (docx) — blocked.docx]\n[Content_Types].xml\nword/document.xml",
        None,
    )
    .unwrap();
    let blocked_legacy_img = DocumentChunk::new(
        format!("{img_b3}:img:0"),
        img_b3,
        blocked_img_path.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.05; 768],
        "[Image Document: blocked.png]\nFormat: PNG (image/png)",
        Some("{\"mime_type\":\"image/png\"}".to_string()),
    )
    .unwrap();
    storage
        .insert_chunks(&[blocked_degraded, blocked_legacy_img])
        .await
        .unwrap();

    assert_eq!(worker.upgrade_degraded_document_chunks().await.unwrap(), 0);
    assert_eq!(worker.upgrade_legacy_image_chunks().await.unwrap(), 0);
    assert!(dedup.get_file_entry(&blocked_doc_path).is_none());
    assert!(dedup.get_file_entry(&blocked_img_path).is_none());
}

#[tokio::test]
async fn t5_ingest_engine_ingest_file_enforces_blocked_prefixes_and_commit_gate() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let drive_allowed = dir.path().join("AllowedDocs");
    let drive_blocked = dir.path().join("BlockedOneDrive");
    std::fs::create_dir_all(&drive_allowed).unwrap();
    std::fs::create_dir_all(&drive_blocked).unwrap();

    let allowed_txt = drive_allowed.join("allowed.txt");
    let allowed_toctou = drive_allowed.join("toctou.txt");
    let blocked_txt = drive_blocked.join("secret.txt");
    let blocked_img = drive_blocked.join("secret.png");
    let blocked_wav = drive_blocked.join("secret.wav");
    std::fs::write(&allowed_txt, "Allowed public note payload.").unwrap();
    std::fs::write(&allowed_toctou, "TOCTOU guarded note payload.").unwrap();
    std::fs::write(&blocked_txt, "Disabled cloud secret note.").unwrap();
    std::fs::write(&blocked_img, minimal_png_bytes()).unwrap();
    std::fs::write(&blocked_wav, minimal_wav_bytes()).unwrap();

    let mut storage_cfg = StorageConfig::default();
    storage_cfg.storage_path = storage_dir;
    let storage = Arc::new(StorageEngine::open(storage_cfg).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbedder::default());
    let engine = IngestEngine::new(
        IngestConfig {
            watch_paths: vec![drive_allowed.clone()],
            ..Default::default()
        },
        Arc::clone(&storage),
        classifier,
        embedder,
    )
    .unwrap();

    let blocked_norm =
        quorum_types::normalize_prefix_for_match(&drive_blocked.to_string_lossy()).unwrap();
    engine
        .reindex_worker()
        .update_blocked_prefixes(vec![blocked_norm.clone()]);

    // Direct ingest_file on blocked paths fails closed with Cancelled and writes 0 chunks
    for p in [&blocked_txt, &blocked_img, &blocked_wav] {
        let res = engine.ingest_file(p).await;
        assert!(
            matches!(res, Err(IngestError::Cancelled)),
            "Expected Err(Cancelled) for blocked path {}, got {res:?}",
            p.display()
        );
        assert!(engine.dedup().get_file_entry(p).is_none());
    }
    assert!(storage.scan_all_chunks().await.unwrap().is_empty());

    // Allowed file ingests cleanly
    let ok_chunks = engine
        .ingest_file(&allowed_txt)
        .await
        .expect("allowed ingest")
        .expect("allowed chunks");
    assert!(!ok_chunks.is_empty());

    // Mid-flight commit_gate + blocked_prefixes race: hold purge barrier while ingest_file runs,
    // block the path before releasing barrier, and verify inside-lock check aborts with 0 writes.
    let barrier = engine.reindex_worker().acquire_purge_barrier().await;
    let engine_c = engine.clone();
    let toctou_c = allowed_toctou.clone();
    let ingest_task = tokio::spawn(async move { engine_c.ingest_file(&toctou_c).await });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let allowed_norm =
        quorum_types::normalize_prefix_for_match(&drive_allowed.to_string_lossy()).unwrap();
    engine
        .reindex_worker()
        .update_blocked_prefixes(vec![blocked_norm, allowed_norm]);
    drop(barrier);

    let toctou_res = ingest_task.await.expect("toctou join");
    assert!(
        matches!(toctou_res, Err(IngestError::Cancelled)),
        "Expected inside-commit_gate check to abort with Cancelled, got {toctou_res:?}"
    );
    assert!(engine.dedup().get_file_entry(&allowed_toctou).is_none());
    let stored = storage.scan_all_chunks().await.unwrap();
    assert!(
        !stored
            .iter()
            .any(|c| c.file_path.contains("toctou.txt") || c.file_path.contains("BlockedOneDrive")),
        "No blocked/TOCTOU chunks may persist in storage: {stored:?}"
    );
}
