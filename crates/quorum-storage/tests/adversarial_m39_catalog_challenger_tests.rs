//! Adversarial empirical test harness for Milestone 39:
//! Catalog File Identity Resolution and Storage Chunk Existence Checks.
//!
//! EMPIRICAL CHALLENGER M39-1:
//! 1. `DocumentCatalog::list_all_file_identities`:
//!    - Verifies correct `mtime_secs` and `size_bytes` resolution through direct fields.
//!    - Verifies fallback through LEFT JOIN with `parent_documents` when catalog fields are 0.
//!    - Verifies missing parent documents safely default to 0.
//!    - Stress-tests across 500+ files with mixed states.
//! 2. `StorageEngine::has_chunk_id`:
//!    - Verifies existing chunks return true in both LanceDB and Tantivy.
//!    - Verifies non-existent chunk IDs return false.
//!    - Verifies SQL injection resistance and special characters (quotes, unicode).
//!    - Verifies post-deletion state reflects immediately.
//!    - Concurrency stress across parallel tokio tasks.

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

use quorum_storage::{
    derive_work_cluster_id, DocumentCatalog, DocumentCatalogEntry,
    StorageConfig, StorageEngine,
};
use quorum_types::{DocumentChunk, DocumentFormat, IngestedParentDocument};

fn create_sample_chunk(
    chunk_id: &str,
    doc_id: &str,
    file_path: &str,
    text: &str,
    vector_val: f32,
) -> DocumentChunk {
    DocumentChunk::new(
        chunk_id,
        doc_id,
        file_path,
        1,
        10,
        0,
        vec![vector_val; 768],
        text,
        Some("{\"m39\":true}".to_string()),
    )
    .expect("Valid sample chunk")
}

fn create_catalog_entry(
    file_path: &str,
    doc_id: &str,
    mtime: i64,
    size: i64,
    chunk_count: i64,
) -> DocumentCatalogEntry {
    DocumentCatalogEntry {
        file_path: file_path.to_string(),
        document_id: doc_id.to_string(),
        work_cluster_id: derive_work_cluster_id(file_path),
        doc_title: format!("Doc Title for {}", file_path),
        doc_authors: "Test Author".to_string(),
        doc_kind: "document".to_string(),
        file_name: std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string(),
        file_extension: "txt".to_string(),
        folder: "test_folder".to_string(),
        normalized_stem: derive_work_cluster_id(file_path),
        author_confidence: "metadata".to_string(),
        access_tier: 0,
        mtime_secs: mtime,
        size_bytes: size,
        chunk_count,
        summary_excerpt: "Summary excerpt for test".to_string(),
        created_at: 1700000000,
    }
}

fn create_parent_doc(
    file_path: &str,
    doc_id: &str,
    mtime: i64,
    size: u64,
) -> IngestedParentDocument {
    IngestedParentDocument {
        doc_id: doc_id.to_string(),
        blake3_hash: blake3::hash(file_path.as_bytes()).to_hex().to_string(),
        source_path: file_path.to_string(),
        os_platform: "windows".to_string(),
        format: DocumentFormat::PlainText,
        title: Some(format!("Parent Title for {}", file_path)),
        author: Some("Author".to_string()),
        created_unix_secs: 1700000000,
        modified_unix_secs: mtime,
        byte_len: size,
        full_text: format!("Full parent document text for {}", file_path),
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_catalog_list_all_file_identities_empty() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("document_catalog.db");
    let catalog = DocumentCatalog::open(&db_path).expect("Open catalog");

    let identities = catalog
        .list_all_file_identities()
        .expect("list_all_file_identities should succeed");
    assert!(
        identities.is_empty(),
        "Empty catalog must yield 0 file identities, got: {}",
        identities.len()
    );
}

#[tokio::test]
async fn test_catalog_list_all_file_identities_direct_mtime_size() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("document_catalog.db");
    let catalog = DocumentCatalog::open(&db_path).expect("Open catalog");

    let entry1 = create_catalog_entry("D:/docs/report1.pdf", "doc_101", 1715000100, 45000, 3);
    let entry2 = create_catalog_entry("D:/docs/report2.pdf", "doc_102", 1715000200, 89000, 5);

    catalog.upsert_entry(&entry1).unwrap();
    catalog.upsert_entry(&entry2).unwrap();

    let identities = catalog.list_all_file_identities().unwrap();
    assert_eq!(identities.len(), 2);

    let id1 = identities.iter().find(|i| i.file_path == "D:/docs/report1.pdf").unwrap();
    assert_eq!(id1.document_id, "doc_101");
    assert_eq!(id1.mtime_secs, 1715000100);
    assert_eq!(id1.size_bytes, 45000);
    assert_eq!(id1.chunk_count, 3);

    let id2 = identities.iter().find(|i| i.file_path == "D:/docs/report2.pdf").unwrap();
    assert_eq!(id2.document_id, "doc_102");
    assert_eq!(id2.mtime_secs, 1715000200);
    assert_eq!(id2.size_bytes, 89000);
    assert_eq!(id2.chunk_count, 5);
}

#[tokio::test]
async fn test_catalog_list_all_file_identities_left_join_parent_fallback() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("document_catalog.db");
    let catalog = DocumentCatalog::open(&db_path).expect("Open catalog");

    // Entry with 0 mtime and 0 size in document_catalog table
    let entry_zero = create_catalog_entry("D:/docs/legacy.docx", "doc_legacy", 0, 0, 2);
    catalog.upsert_entry(&entry_zero).unwrap();

    // Now insert parent_document with actual modified_unix_secs and byte_len
    // Note: upsert_parent_document updates document_catalog, so we test:
    // (a) upsert_parent_document sets them
    // (b) raw insert into parent_documents without updating document_catalog verifies the LEFT JOIN SQL logic itself!
    let parent_doc = create_parent_doc("D:/docs/fallback_only.docx", "doc_fallback", 1719999000, 123456);
    // Directly insert catalog row with 0 mtime and size
    let entry_fallback = create_catalog_entry("D:/docs/fallback_only.docx", "doc_fallback", 0, 0, 4);
    catalog.upsert_entry(&entry_fallback).unwrap();

    // Directly insert into parent_documents table without updating document_catalog
    {
        // Open connection and insert raw parent_document
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO parent_documents (
                file_path, document_id, blake3_hash, os_platform, format,
                title, author, created_unix_secs, modified_unix_secs, byte_len,
                access_tier, full_text, metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                parent_doc.source_path,
                parent_doc.doc_id,
                parent_doc.blake3_hash,
                parent_doc.os_platform,
                parent_doc.format.as_str(),
                parent_doc.title,
                parent_doc.author,
                parent_doc.created_unix_secs,
                parent_doc.modified_unix_secs,
                parent_doc.byte_len as i64,
                0,
                parent_doc.full_text,
                "{}",
            ],
        ).unwrap();
    }

    // Also add an entry with 0 mtime that has NO parent_document row
    let entry_orphan = create_catalog_entry("D:/docs/no_parent.txt", "doc_orphan", 0, 0, 1);
    catalog.upsert_entry(&entry_orphan).unwrap();

    let identities = catalog.list_all_file_identities().unwrap();
    assert_eq!(identities.len(), 3);

    // Verify fallback from parent_documents via LEFT JOIN
    let fallback_ident = identities
        .iter()
        .find(|i| i.file_path == "D:/docs/fallback_only.docx")
        .expect("Found fallback identity");
    assert_eq!(fallback_ident.mtime_secs, 1719999000, "Should resolve from parent_documents modified_unix_secs");
    assert_eq!(fallback_ident.size_bytes, 123456, "Should resolve from parent_documents byte_len");
    assert_eq!(fallback_ident.chunk_count, 4);

    // Verify entry with no parent document defaults to 0 safely
    let orphan_ident = identities
        .iter()
        .find(|i| i.file_path == "D:/docs/no_parent.txt")
        .expect("Found orphan identity");
    assert_eq!(orphan_ident.mtime_secs, 0);
    assert_eq!(orphan_ident.size_bytes, 0);
    assert_eq!(orphan_ident.chunk_count, 1);
}

#[tokio::test]
async fn test_catalog_list_all_file_identities_stress_hundreds_of_files() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("document_catalog.db");
    let catalog = DocumentCatalog::open(&db_path).expect("Open catalog");

    let num_files = 600;
    for i in 0..num_files {
        let path = format!("D:/stress_drive/folder_{}/file_{}.pdf", i / 10, i);
        let doc_id = format!("doc_stress_{}", i);
        let is_direct = i % 2 == 0;

        if is_direct {
            // Direct mtime and size in document_catalog
            let mtime = 1710000000 + (i as i64 * 10);
            let size = 1000 + (i as i64 * 50);
            let entry = create_catalog_entry(&path, &doc_id, mtime, size, (i % 8 + 1) as i64);
            catalog.upsert_entry(&entry).unwrap();
        } else {
            // 0 in catalog, populated via parent document
            let mtime = 1711000000 + (i as i64 * 10);
            let size = 5000 + (i as u64 * 20);
            let entry = create_catalog_entry(&path, &doc_id, 0, 0, (i % 8 + 1) as i64);
            catalog.upsert_entry(&entry).unwrap();

            let parent = create_parent_doc(&path, &doc_id, mtime, size);
            catalog.upsert_parent_document(&parent, 0).unwrap();
        }
    }

    let start = std::time::Instant::now();
    let identities = catalog.list_all_file_identities().unwrap();
    let elapsed = start.elapsed();

    assert_eq!(identities.len(), num_files);
    println!(
        "stress test: listed {} file identities in {:?}",
        identities.len(),
        elapsed
    );
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "Listing 600 identities should finish in < 500ms, took {:?}",
        elapsed
    );

    // Verify integrity of sampled identities
    for i in (0..num_files).step_by(25) {
        let expected_path = format!("D:/stress_drive/folder_{}/file_{}.pdf", i / 10, i);
        let ident = identities.iter().find(|id| id.file_path == expected_path).unwrap();
        assert_eq!(ident.document_id, format!("doc_stress_{}", i));
        assert!(ident.mtime_secs > 0, "mtime must be resolved > 0");
        assert!(ident.size_bytes > 0, "size must be resolved > 0");
    }
}

#[tokio::test]
async fn test_storage_engine_has_chunk_id_lifecycle() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(config).await.expect("StorageEngine open");

    let chunk1 = create_sample_chunk("chunk_m39_alpha", "doc_alpha", "D:/data/a.txt", "Alpha content", 0.1);
    let chunk2 = create_sample_chunk("chunk_m39_beta", "doc_beta", "D:/data/b.txt", "Beta content", 0.2);

    // Before insertion, both must return false
    assert!(!engine.has_chunk_id("chunk_m39_alpha").await.unwrap());
    assert!(!engine.has_chunk_id("chunk_m39_beta").await.unwrap());
    assert!(!engine.has_chunk_id("chunk_m39_gamma").await.unwrap());
    assert!(!engine.has_chunk_id("").await.unwrap());

    // Insert chunks
    let inserted = engine.insert_chunks(&[chunk1, chunk2]).await.unwrap();
    assert_eq!(inserted, 2);

    // Now chunk1 and chunk2 must return true
    assert!(engine.has_chunk_id("chunk_m39_alpha").await.unwrap());
    assert!(engine.has_chunk_id("chunk_m39_beta").await.unwrap());

    // Still false for non-existent chunks
    assert!(!engine.has_chunk_id("chunk_m39_gamma").await.unwrap());
    assert!(!engine.has_chunk_id("unknown_id").await.unwrap());

    // Delete file 'D:/data/a.txt'
    engine.delete_by_file_path("D:/data/a.txt").await.unwrap();

    // After deletion, chunk_m39_alpha must return false, while chunk_m39_beta remains true
    assert!(!engine.has_chunk_id("chunk_m39_alpha").await.unwrap());
    assert!(engine.has_chunk_id("chunk_m39_beta").await.unwrap());
}

#[tokio::test]
async fn test_storage_engine_has_chunk_id_adversarial_and_injection() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(config).await.expect("StorageEngine open");

    // Test malicious / strange chunk IDs
    let strange_ids = [
        "' OR '1'='1",
        "'; DROP TABLE chunks; --",
        "\" OR \"\"=\"",
        "chunk'with'embedded'quotes",
        "chunk with spaces and / \\ slashes",
        "chunk_unicode_🚀_🔥_テスト",
        "\0null_byte_attack",
    ];

    for bad_id in &strange_ids {
        let res = engine.has_chunk_id(bad_id).await;
        assert!(res.is_ok(), "has_chunk_id should not panic or error on string: {:?}", bad_id);
        assert!(!res.unwrap(), "Non-existent adversarial chunk_id should return false");
    }

    // Insert a chunk whose ID actually contains single quotes
    let quote_chunk = create_sample_chunk(
        "chunk_user's_file_#1",
        "doc_quote",
        "D:/user/doc.txt",
        "Quote test content",
        0.3,
    );
    engine.insert_chunks(&[quote_chunk]).await.unwrap();

    // Verify it is found correctly despite the quote
    assert!(
        engine.has_chunk_id("chunk_user's_file_#1").await.unwrap(),
        "Chunk with single quote in ID must be matched"
    );
    // Ensure variation with different quote doesn't falsely match
    assert!(!engine.has_chunk_id("chunk_user's_file_#2").await.unwrap());
}

#[tokio::test]
async fn test_storage_engine_has_chunk_id_concurrent_queries() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = Arc::new(StorageEngine::open(config).await.expect("StorageEngine open"));

    // Insert 50 chunks
    let mut chunks = Vec::new();
    for i in 0..50 {
        let cid = format!("chunk_concurrency_{}", i);
        let path = format!("D:/concurrent/file_{}.txt", i);
        chunks.push(create_sample_chunk(&cid, "doc_conc", &path, "Concurrency test", 0.05));
    }
    engine.insert_chunks(&chunks).await.unwrap();

    // Query 100 tasks concurrently checking existing and non-existing IDs
    let mut tasks = Vec::new();
    for i in 0..100 {
        let eng = Arc::clone(&engine);
        tasks.push(tokio::spawn(async move {
            if i < 50 {
                let cid = format!("chunk_concurrency_{}", i);
                let exists = eng.has_chunk_id(&cid).await.unwrap();
                assert!(exists, "Expected {} to exist", cid);
            } else {
                let cid = format!("chunk_concurrency_missing_{}", i);
                let exists = eng.has_chunk_id(&cid).await.unwrap();
                assert!(!exists, "Expected {} not to exist", cid);
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}
