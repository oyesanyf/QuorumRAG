//! Adversarial Stress Test Suite for Milestone M19 Remediation (Crawler Isolation & Exclusion Gate).
//!
//! EMPIRICAL CHALLENGER VERIFICATION:
//! 1. Nested storage directories and catalogs are pruned and ignored (even under multi-level paths).
//! 2. Case-insensitive directory matching rejects all casing variations (`STORAGE`, `Storage`, `QuorumRAG`, `QUORUMRAG`, `LANCE`, `Tantivy`).
//! 3. Legitimate user files with partial string overlap (`storage_plan.docx`, `cloud_storage.pdf`, `dedup_whitepaper.txt`, `catalog_summary.md`)
//!    are properly discovered, routed, and indexed.
//! 4. Dynamic path exclusions (`config.excluded_paths`) prune target trees and child files without affecting sibling directories or files.
//! 5. Full End-to-End ReindexWorker lifecycle confirms that Pass 1 indexes all legitimate overlap files and prunes all internal/excluded artifacts,
//!    and Pass 2 (incremental) skips unmodified files with 0 new embeddings and 0 leak discoveries.

use std::fs::{create_dir_all, write};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};

use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::config::{IngestConfig, ReindexOptions};
use quorum_ingest::crawler::FilesystemCrawler;
use quorum_ingest::dedup::TwoLevelDedupEngine;
use quorum_ingest::reindex::{ReindexPhase, ReindexWorker};

/// Deterministic mock embedding generator for tests (canonical 768-dim L2-normalized vectors).
#[derive(Debug, Clone)]
struct TestEmbeddingGenerator {
    contract: EmbeddingContract,
}

impl Default for TestEmbeddingGenerator {
    fn default() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
        }
    }
}

impl EmbeddingGenerator for TestEmbeddingGenerator {
    fn contract(&self) -> &EmbeddingContract {
        &self.contract
    }

    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        let dim = self.contract.dimension;
        let mut vec = Vec::with_capacity(dim);
        let mut hasher = blake3::Hasher::new();
        hasher.update(text.as_bytes());

        for i in 0..dim {
            let mut step_hasher = hasher.clone();
            step_hasher.update(&(i as u32).to_le_bytes());
            let hash = step_hasher.finalize();
            let raw_int = u32::from_le_bytes([
                hash.as_bytes()[0],
                hash.as_bytes()[1],
                hash.as_bytes()[2],
                hash.as_bytes()[3],
            ]);
            let float_val = (raw_int as f32 / u32::MAX as f32) * 2.0 - 1.0;
            vec.push(float_val);
        }

        // L2 normalize
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut vec {
                *v /= norm;
            }
        }
        Ok(vec)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
        texts.iter().map(|t| self.embed_text(t)).collect()
    }
}

// ============================================================================
// TEST 1: NESTED STORAGE PATHS AND CATALOGS ADVERSARIALLY IGNORED
// ============================================================================

#[test]
fn test_nested_storage_directories_and_catalogs_adversarially_ignored() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create a deep hierarchy: root/lvl1/lvl2/lvl3/
    let deep_nested = root.join("lvl1").join("lvl2").join("lvl3");
    let nested_storage = deep_nested.join("storage");
    create_dir_all(&nested_storage).unwrap();

    // Internal artifacts inside nested storage
    write(nested_storage.join("dedup_catalog.json"), "{\"catalog\": {}}").unwrap();
    write(nested_storage.join("document_catalog.db"), "SQLite format 3\0").unwrap();
    write(nested_storage.join("document_catalog.db-wal"), "wal-data").unwrap();
    write(nested_storage.join("document_catalog.db-shm"), "shm-data").unwrap();
    write(nested_storage.join("metadata.json"), "{\"version\": 1}").unwrap();
    write(nested_storage.join(".metadata.json"), "{\"hidden\": true}").unwrap();
    write(nested_storage.join("embedding_contract.json"), "{\"dimension\": 768}").unwrap();
    write(nested_storage.join("leak_candidate.txt"), "This internal file should never leak").unwrap();

    // Subdirectory inside nested storage
    let sub_lance = nested_storage.join("lance").join("fragments");
    create_dir_all(&sub_lance).unwrap();
    write(sub_lance.join("part-0.lance"), "lance-binary-data").unwrap();

    // Legitimate user files outside storage in lvl3
    let legit_txt = deep_nested.join("nested_legitimate_report.txt");
    write(&legit_txt, "Legitimate research findings at lvl3").unwrap();

    let legit_md = deep_nested.join("nested_summary.md");
    write(&legit_md, "# Summary of research").unwrap();

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let crawler = FilesystemCrawler::new(config.clone());
    let discovered = crawler.crawl_path_sync(root).unwrap();

    // Verify legitimate files ARE discovered
    assert!(
        discovered.iter().any(|c| c.path.ends_with("nested_legitimate_report.txt")),
        "nested_legitimate_report.txt must be discovered by crawler"
    );
    assert!(
        discovered.iter().any(|c| c.path.ends_with("nested_summary.md")),
        "nested_summary.md must be discovered by crawler"
    );

    // Verify NONE of the files inside nested storage are discovered
    for disc in &discovered {
        let s = disc.path.to_string_lossy().to_ascii_lowercase();
        assert!(
            !s.contains("nested_storage") && !s.contains("leak_candidate.txt") && !s.contains("dedup_catalog.json"),
            "Internal nested storage file {:?} was discovered!",
            disc.path
        );
    }

    // Layer 3 verification: ClassifierRouter directly rejects all internal catalog files
    let router = ClassifierRouter::new(config);
    let decision = router.evaluate_file(&nested_storage.join("dedup_catalog.json"));
    assert_eq!(decision, FilterDecision::SkipHidden, "Router must reject dedup_catalog.json");

    let decision_doc = router.evaluate_file(&nested_storage.join("document_catalog.db"));
    assert_eq!(decision_doc, FilterDecision::SkipHidden, "Router must reject document_catalog.db");

    let decision_meta = router.evaluate_file(&nested_storage.join("metadata.json"));
    assert_eq!(decision_meta, FilterDecision::SkipHidden, "Router must reject metadata.json");

    let decision_embed = router.evaluate_file(&nested_storage.join("embedding_contract.json"));
    assert_eq!(decision_embed, FilterDecision::SkipHidden, "Router must reject embedding_contract.json");
}

// ============================================================================
// TEST 2: CASE-INSENSITIVE INTERNAL DIRECTORY MATCHING
// ============================================================================

#[test]
fn test_case_insensitive_internal_directory_names_adversarially_ignored() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Case-variant internal directories
    let test_dirs = [
        "STORAGE",
        "Storage",
        "sToRaGe",
        "QuorumRAG",
        "QUORUMRAG",
        "quorumrag",
        ".QUORUMRAG",
        ".QuorumRAG",
        ".quorumrag-live-data",
        ".QUORUMRAG-LIVE-DATA",
        "LANCE",
        "Lance",
        "TANTIVY",
        "Tantivy",
    ];

    for d in &test_dirs {
        let p = root.join(d);
        create_dir_all(&p).unwrap();
        write(p.join("internal_artifact.txt"), "Secret internal state").unwrap();
    }

    // Allowed directories with similar or standard names (must NOT be pruned)
    let allowed_dirs = [
        "Allowed_Storage_Folder",
        "User_QuorumRAG_Research",
        "StoragePlans",
        "General_Documents",
    ];

    for d in &allowed_dirs {
        let p = root.join(d);
        create_dir_all(&p).unwrap();
        write(p.join("legitimate_user_doc.txt"), "Important user document").unwrap();
    }

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let crawler = FilesystemCrawler::new(config);
    let discovered = crawler.crawl_path_sync(root).unwrap();

    // Assert zero internal artifacts discovered
    for disc in &discovered {
        for forbidden in &test_dirs {
            let parent_name = disc.path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("");
            assert_ne!(
                parent_name, *forbidden,
                "Case-variant directory {:?} was not pruned by crawler: file {:?}",
                forbidden, disc.path
            );
        }
    }

    // Assert all allowed directories had their files discovered
    for allowed in &allowed_dirs {
        assert!(
            discovered.iter().any(|c| {
                c.path.parent()
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    .map(|name| name == *allowed)
                    .unwrap_or(false)
            }),
            "Allowed directory {:?} should have been crawled!",
            allowed
        );
    }
}

// ============================================================================
// TEST 3: LEGITIMATE USER FILES WITH PARTIAL STRING OVERLAPS PROPERLY DISCOVERED
// ============================================================================

#[test]
fn test_legitimate_user_files_with_partial_string_overlap_properly_discovered_and_routed() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let docs = root.join("documents");
    create_dir_all(&docs).unwrap();

    // Exact required files from prompt & real-world overlap cases
    let test_files = [
        ("storage_plan.docx", "Detailed storage architecture plan for cloud migration."),
        ("cloud_storage.pdf", "%PDF-1.4\n1 0 obj\n<<>>\nendobj\nstream\nCloud storage whitepaper.\nendstream"),
        ("dedup_whitepaper.txt", "Deduplication algorithms and chunk cache optimization principles."),
        ("catalog_summary.md", "# Catalog Summary\n\nOverview of indexed media."),
        ("STORAGE_ANALYSIS.DOCX", "Upper case storage analysis doc."),
        ("dedup_analysis_report.txt", "Empirical dedup benchmarks."),
        ("cloud_storage_guide.html", "<html><body><h1>Cloud Storage Guide</h1></body></html>"),
        ("metadata_governance.pdf", "%PDF-1.4\nMetadata governance standards."),
        ("embedding_contract_notes.txt", "Notes on embedding contract models and dimensionality."),
        ("document_catalog_draft.txt", "Draft outline for document catalog features."),
    ];

    for (name, content) in &test_files {
        write(docs.join(name), content).unwrap();
    }

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let crawler = FilesystemCrawler::new(config.clone());
    let discovered = crawler.crawl_path_sync(root).unwrap();

    // Verify EVERY test file was discovered by crawler
    for (name, _) in &test_files {
        let found = discovered.iter().any(|c| {
            c.path.file_name()
                .and_then(|n| n.to_str())
                .map(|f| f.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        });
        assert!(found, "File with partial overlap {:?} must NOT be skipped by crawler!", name);
    }

    // Verify ClassifierRouter routes them to valid CandidateKind, NEVER SkipHidden
    let router = ClassifierRouter::new(config);
    for (name, _) in &test_files {
        let path = docs.join(name);
        let decision = router.evaluate_file(&path);
        match decision {
            FilterDecision::Accept { ref kind, .. } => {
                match kind {
                    CandidateKind::Text { .. } => {}
                    CandidateKind::Image { .. } => {}
                    CandidateKind::Audio { .. } => {}
                }
            }
            FilterDecision::SkipHidden => {
                panic!("File {:?} was falsely marked SkipHidden by ClassifierRouter!", name);
            }
            other => {
                assert!(
                    !matches!(other, FilterDecision::SkipHidden | FilterDecision::SkipSymlink),
                    "File {:?} received unexpected filter decision: {:?}",
                    name,
                    other
                );
            }
        }
    }
}

// ============================================================================
// TEST 4: DYNAMIC PATH EXCLUSIONS PRUNE CHILDREN WITHOUT AFFECTING SIBLINGS
// ============================================================================

#[test]
fn test_dynamic_path_exclusions_prune_children_without_affecting_siblings() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let ws = root.join("workspace");
    let target_proj = ws.join("target_project");
    let target_proj_sub = target_proj.join("sub");
    let target_proj_sib = ws.join("target_project_sibling");
    let target_proj_v2 = ws.join("target_project_v2");

    create_dir_all(&target_proj_sub).unwrap();
    create_dir_all(&target_proj_sib).unwrap();
    create_dir_all(&target_proj_v2).unwrap();

    write(target_proj.join("child1.txt"), "Excluded child 1").unwrap();
    write(target_proj_sub.join("child2.txt"), "Excluded child 2").unwrap();
    write(target_proj_sib.join("doc.txt"), "Legitimate sibling document").unwrap();
    write(target_proj_v2.join("notes.txt"), "Legitimate v2 document").unwrap();

    let isolated = root.join("isolated");
    let to_exclude = isolated.join("to_exclude");
    let to_exclude_other = isolated.join("to_exclude_other");

    create_dir_all(&to_exclude).unwrap();
    create_dir_all(&to_exclude_other).unwrap();

    write(to_exclude.join("data.txt"), "Excluded data").unwrap();
    write(to_exclude_other.join("data.txt"), "Allowed sibling data").unwrap();

    let files_dir = root.join("files");
    create_dir_all(&files_dir).unwrap();
    let standalone_ex = files_dir.join("standalone_exclude.txt");
    let standalone_sib = files_dir.join("standalone_exclude_sibling.txt");
    let standalone_ok = files_dir.join("allowed.txt");

    write(&standalone_ex, "Directly excluded file").unwrap();
    write(&standalone_sib, "Sibling with similar prefix").unwrap();
    write(&standalone_ok, "Normal file").unwrap();

    // Set excluded_paths
    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        excluded_paths: vec![
            target_proj.clone(),
            to_exclude.clone(),
            standalone_ex.clone(),
        ],
        ..Default::default()
    };

    let crawler = FilesystemCrawler::new(config.clone());
    let candidates = crawler.crawl_path_sync(root).unwrap();
    let discovered: Vec<PathBuf> = candidates.into_iter().map(|c| c.path).collect();

    // 1. Verify excluded items are NOT discovered
    assert!(!discovered.contains(&target_proj.join("child1.txt")), "child1.txt must be pruned");
    assert!(!discovered.contains(&target_proj_sub.join("child2.txt")), "child2.txt must be pruned");
    assert!(!discovered.contains(&to_exclude.join("data.txt")), "to_exclude/data.txt must be pruned");
    assert!(!discovered.contains(&standalone_ex), "standalone_exclude.txt must be pruned");

    // 2. Verify sibling items ARE discovered
    assert!(
        discovered.contains(&target_proj_sib.join("doc.txt")),
        "target_project_sibling/doc.txt MUST NOT be pruned by target_project exclusion!"
    );
    assert!(
        discovered.contains(&target_proj_v2.join("notes.txt")),
        "target_project_v2/notes.txt MUST NOT be pruned by target_project exclusion!"
    );
    assert!(
        discovered.contains(&to_exclude_other.join("data.txt")),
        "to_exclude_other/data.txt MUST NOT be pruned by to_exclude exclusion!"
    );
    assert!(
        discovered.contains(&standalone_sib),
        "standalone_exclude_sibling.txt MUST NOT be pruned by standalone_exclude.txt exclusion!"
    );
    assert!(
        discovered.contains(&standalone_ok),
        "allowed.txt MUST be discovered!"
    );

    // 3. Verify ClassifierRouter also honors excluded_paths on direct lookup
    let router = ClassifierRouter::new(config);
    assert_eq!(
        router.evaluate_file(&target_proj.join("child1.txt")),
        FilterDecision::SkipHidden,
        "Router must skip child of excluded directory"
    );
    assert_eq!(
        router.evaluate_file(&standalone_ex),
        FilterDecision::SkipHidden,
        "Router must skip directly excluded file"
    );
    assert!(
        !matches!(router.evaluate_file(&target_proj_sib.join("doc.txt")), FilterDecision::SkipHidden),
        "Router must NOT skip sibling doc!"
    );
    assert!(
        !matches!(router.evaluate_file(&standalone_sib), FilterDecision::SkipHidden),
        "Router must NOT skip sibling file!"
    );
}

// ============================================================================
// TEST 5: FULL END-TO-END REINDEX WORKER ADVERSARIAL ISOLATION & INCREMENTAL PURITY
// ============================================================================

#[tokio::test]
async fn test_end_to_end_reindex_worker_adversarial_isolation_and_incremental_stability() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    create_dir_all(&storage_dir).unwrap();

    let catalog_path = storage_dir.join("dedup_catalog.json");

    // Adversarial internal directory structure
    let nested_storage = root.join("deep").join("nested").join("storage");
    create_dir_all(&nested_storage).unwrap();
    write(nested_storage.join("fake_catalog.json"), "{\"leaked\": true}").unwrap();

    let case_storage = root.join("STORAGE");
    create_dir_all(&case_storage).unwrap();
    write(case_storage.join("leak.txt"), "Internal junk").unwrap();

    let case_quorum = root.join("QuorumRAG");
    create_dir_all(&case_quorum).unwrap();
    write(case_quorum.join("state.json"), "{\"internal\": true}").unwrap();

    // Legitimate user files with partial string overlap (5 distinct files)
    let docs = root.join("user_documents");
    create_dir_all(&docs).unwrap();
    let doc_storage_plan = docs.join("storage_plan.docx");
    let doc_cloud_storage = docs.join("cloud_storage.pdf");
    let doc_dedup_paper = docs.join("dedup_whitepaper.txt");
    let doc_catalog_summary = docs.join("catalog_summary.md");

    write(&doc_storage_plan, format!("Storage Plan Content:\n{}", "A".repeat(800))).unwrap();
    write(&doc_cloud_storage, format!("Cloud Storage Whitepaper:\n{}", "B".repeat(800))).unwrap();
    write(&doc_dedup_paper, format!("Dedup Whitepaper Research:\n{}", "C".repeat(800))).unwrap();
    write(&doc_catalog_summary, format!("Catalog Summary Doc:\n{}", "D".repeat(800))).unwrap();

    // Dynamic exclusion tree
    let excluded_tree = root.join("excluded_area");
    create_dir_all(&excluded_tree).unwrap();
    write(excluded_tree.join("excluded_doc.txt"), format!("Excluded Doc:\n{}", "X".repeat(800))).unwrap();

    // Sibling of dynamic exclusion tree (must be indexed)
    let sibling_tree = root.join("excluded_area_sibling");
    create_dir_all(&sibling_tree).unwrap();
    let doc_sibling = sibling_tree.join("valid_sibling.txt");
    write(&doc_sibling, format!("Valid Sibling Doc:\n{}", "E".repeat(800))).unwrap();

    // Configure ReindexWorker
    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![excluded_tree.clone()],
        ..Default::default()
    };

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // ========================================================================
    // PASS 1: INITIAL FULL CRAWL & INDEX
    // ========================================================================
    let prog1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog1.phase, ReindexPhase::Completed);

    // Exactly 5 legitimate files must be indexed:
    // 1. storage_plan.docx
    // 2. cloud_storage.pdf
    // 3. dedup_whitepaper.txt
    // 4. catalog_summary.md
    // 5. valid_sibling.txt
    assert_eq!(
        prog1.files_indexed, 5,
        "Expected exactly 5 legitimate files to be indexed, got {}",
        prog1.files_indexed
    );
    assert_eq!(prog1.files_skipped_unmodified, 0);
    assert!(
        prog1.chunks_newly_embedded >= 5,
        "Expected at least 5 chunks embedded (>=1 per file), got {}",
        prog1.chunks_newly_embedded
    );

    // Verify dedup catalog was written to disk
    assert!(
        catalog_path.exists(),
        "dedup_catalog.json must be persisted to disk after pass 1: {:?}",
        catalog_path
    );

    // ========================================================================
    // PASS 2: INCREMENTAL SECOND PASS (ZERO UNMODIFIED EMBEDDINGS OR LEAKS)
    // ========================================================================
    let prog2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog2.phase, ReindexPhase::Completed);

    // Zero files should be re-indexed, 5 files should be fast-path skipped
    assert_eq!(
        prog2.files_indexed, 0,
        "Pass 2 must index 0 files (none modified, dedup_catalog.json ignored). Got {}",
        prog2.files_indexed
    );
    assert_eq!(
        prog2.files_skipped_unmodified, 5,
        "Pass 2 must skip all 5 unmodified legitimate files via Level-1 fast path. Got {}",
        prog2.files_skipped_unmodified
    );
    assert_eq!(
        prog2.chunks_newly_embedded, 0,
        "Pass 2 must perform 0 new chunk embeddings. Got {}",
        prog2.chunks_newly_embedded
    );
    assert_eq!(
        prog2.chunks_reused_from_cache, 0,
        "Pass 2 must reuse 0 chunks since Level-1 skipped all files. Got {}",
        prog2.chunks_reused_from_cache
    );
}
