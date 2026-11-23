use std::collections::HashMap;

use quorum_storage::{
    DocumentCatalogEntry, PrefixPurgeReport, PrefixTierUpdateReport, StorageConfig, StorageEngine,
    StorageError, StorageSearchQuery,
};
use quorum_types::{DocumentChunk, DocumentFormat, IngestedParentDocument, TypeError};
use tempfile::tempdir;

fn make_chunk(
    chunk_id: &str,
    doc_id: &str,
    file_path: &str,
    tier: u8,
    text: &str,
) -> DocumentChunk {
    let mut vec = vec![0.05f32; 768];
    vec[0] = 1.0;
    DocumentChunk::new(
        chunk_id,
        doc_id,
        file_path,
        1,
        10,
        tier,
        vec,
        text,
        Some(r#"{"cloud_drive":"onedrive"}"#.to_string()),
    )
    .expect("valid chunk")
}

fn make_catalog_entry(
    doc_id: &str,
    file_path: &str,
    tier: u8,
    title: &str,
) -> DocumentCatalogEntry {
    DocumentCatalogEntry {
        file_path: file_path.to_string(),
        document_id: doc_id.to_string(),
        work_cluster_id: doc_id.to_string(),
        doc_title: title.to_string(),
        doc_authors: "Alice".to_string(),
        doc_kind: "general_doc".to_string(),
        file_name: file_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or("doc.txt")
            .to_string(),
        file_extension: "txt".to_string(),
        folder: "OneDrive".to_string(),
        normalized_stem: doc_id.to_string(),
        author_confidence: "verified".to_string(),
        access_tier: tier,
        mtime_secs: 1000,
        size_bytes: 128,
        chunk_count: 1,
        summary_excerpt: title.to_string(),
        created_at: 1000,
    }
}

fn make_parent(doc_id: &str, file_path: &str, text: &str) -> IngestedParentDocument {
    IngestedParentDocument {
        doc_id: doc_id.to_string(),
        blake3_hash: blake3::hash(text.as_bytes()).to_hex().to_string(),
        source_path: file_path.to_string(),
        os_platform: "windows".to_string(),
        format: DocumentFormat::PlainText,
        title: Some(doc_id.to_string()),
        author: Some("Alice".to_string()),
        created_unix_secs: 1000,
        modified_unix_secs: 1000,
        byte_len: text.len() as u64,
        full_text: text.to_string(),
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_storage_delete_by_path_prefix_purges_all_4_stores_and_preserves_siblings() {
    let tmp = tempdir().unwrap();
    let cfg = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(cfg).await.unwrap();

    let p_win_1 = r"C:\Users\Alice\OneDrive\Docs\cloud_alpha_report.txt";
    let p_win_2 = "C:/Users/Alice/OneDrive/Notes/cloud_alpha_notes.txt";
    let p_win_3 = r"\\?\c:\users\alice\onedrive\Archive\cloud_alpha_archive.txt";
    let p_sib_1 = r"C:\Users\Alice\OneDrive2\sibling_keep_report.txt";
    let p_sib_2 = r"C:\Users\Alice\OneDrive - Business\business_keep_report.txt";
    let p_unix_u = "/home/alice/Nextcloud/unix_upper_keep.txt";
    let p_unix_l = "/home/alice/nextcloud/unix_lower_keep.txt";

    let files = [
        ("doc_w1", p_win_1, "CloudAlpha token in OneDrive docs"),
        ("doc_w2", p_win_2, "CloudAlpha token in OneDrive slash"),
        ("doc_w3", p_win_3, "CloudAlpha token in OneDrive verbatim"),
        ("doc_s1", p_sib_1, "SiblingKeep token in OneDrive2"),
        ("doc_s2", p_sib_2, "SiblingKeep token in OneDrive Business"),
        ("doc_uu", p_unix_u, "UnixUpperToken in Nextcloud"),
        ("doc_ul", p_unix_l, "UnixLowerToken in nextcloud"),
    ];

    let chunks: Vec<DocumentChunk> = files
        .iter()
        .map(|(id, p, txt)| {
            make_chunk(
                &format!("{id}:0"),
                id,
                p,
                3,
                &format!("Alice worked at QuorumCorp on {txt}."),
            )
        })
        .collect();

    engine.insert_chunks(&chunks).await.unwrap();
    for (id, p, txt) in &files {
        engine
            .catalog()
            .upsert_entry(&make_catalog_entry(id, p, 3, txt))
            .unwrap();
        engine
            .upsert_parent_document(&make_parent(id, p, txt), 3)
            .unwrap();
    }

    // Also insert explicit AtlasKV triples for every file
    let q_vec = chunks[0].vector.clone();
    let kv_records: Vec<quorum_atlaskv::KgTripleRecord> = files
        .iter()
        .map(|(id, p, txt)| {
            quorum_atlaskv::KgTripleRecord::new(
                format!("Entity_{id}"),
                "location",
                *txt,
                *id,
                format!("{id}:0"),
                *p,
                1,
                5,
                *id,
                3,
                "local",
            )
            .unwrap()
        })
        .collect();
    engine
        .atlaskv()
        .insert_triples(
            &kv_records,
            &vec![q_vec.clone(); kv_records.len()],
            &vec![q_vec.clone(); kv_records.len()],
        )
        .unwrap();

    let epoch_before = engine.index_epoch();

    // Fail-closed invalid prefix rejections (must NOT bump epoch or delete anything)
    for bad in [
        "",
        "OneDrive",
        r"C:\Users\Alice\..\OneDrive",
        "C:/Users/Alice/%2e%2e/OneDrive",
        "C:/Users/Alice/%252e%252e/OneDrive",
        r"\\server\share\OneDrive",
        r"C:\Users\Alice\OneDrive:ads",
    ] {
        let err = engine.delete_by_path_prefix(bad).await.unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::Type(TypeError::InvalidCloudDrivePath { .. })
            ),
            "Expected InvalidCloudDrivePath for '{bad}', got {err:?}"
        );
    }
    assert_eq!(engine.index_epoch(), epoch_before);

    // Purge C:\Users\Alice\OneDrive
    let report: PrefixPurgeReport = engine
        .delete_by_path_prefix("C:/Users/Alice/OneDrive/")
        .await
        .unwrap();
    assert!(report.any_deleted());
    assert_eq!(report.lance_chunks_deleted, 3);
    assert_eq!(report.tantivy_chunks_deleted, 3);
    assert_eq!(report.catalog_docs_deleted, 3);
    assert_eq!(report.parent_docs_deleted, 3);
    assert_eq!(report.atlaskv_triples_deleted, 3);
    assert!(report.new_index_epoch > epoch_before);
    assert_eq!(engine.index_epoch(), report.new_index_epoch);

    // VectorStore + Tantivy purged for OneDrive, intact for siblings
    let lance_remaining = engine.scan_all_chunks().await.unwrap();
    assert_eq!(lance_remaining.len(), 4);
    assert!(lance_remaining.iter().all(|c| {
        !c.file_path.to_ascii_lowercase().contains(r"onedrive\")
            && !c.file_path.to_ascii_lowercase().contains("onedrive/")
    }));

    let fts_od_hits = engine
        .search(&StorageSearchQuery::keyword("CloudAlpha", 3, 10))
        .await
        .unwrap();
    assert!(fts_od_hits.is_empty());
    let fts_sib_hits = engine
        .search(&StorageSearchQuery::keyword("SiblingKeep", 3, 10))
        .await
        .unwrap();
    assert_eq!(fts_sib_hits.len(), 2);

    // DocumentCatalog + FTS5 + parent_documents purged for OneDrive, intact for siblings
    assert_eq!(engine.catalog().count_documents().unwrap(), 4);
    assert_eq!(engine.catalog().count_parent_documents().unwrap(), 4);
    assert!(engine
        .catalog()
        .catalog_find_documents("CloudAlpha", 10)
        .unwrap()
        .is_empty());
    assert!(engine.load_parent_document(p_win_1, 3).unwrap().is_none());
    assert!(engine.load_parent_document(p_sib_1, 3).unwrap().is_some());
    assert!(engine.load_parent_document(p_sib_2, 3).unwrap().is_some());

    // AtlasKV purged for OneDrive, intact for siblings
    let (kv_hits, _) = engine.atlaskv().hikvp_search(&q_vec, 3, 20, None).unwrap();
    assert!(kv_hits.iter().all(|h| {
        !h.triple
            .file_path
            .to_ascii_lowercase()
            .contains(r"onedrive\")
            && !h
                .triple
                .file_path
                .to_ascii_lowercase()
                .contains("onedrive/")
    }));
    assert_eq!(engine.atlaskv().stats().active_triples, 4);

    // No-op purge must NOT bump epoch
    let epoch_mid = engine.index_epoch();
    let noop = engine
        .delete_by_path_prefix(r"C:\Users\Alice\NonExistentCloud")
        .await
        .unwrap();
    assert!(!noop.any_deleted());
    assert_eq!(noop.new_index_epoch, epoch_mid);
    assert_eq!(engine.index_epoch(), epoch_mid);

    // Unix case-preserving prefix purge removes only /home/alice/Nextcloud
    let unix_rep = engine
        .delete_by_path_prefix("/home/alice/Nextcloud")
        .await
        .unwrap();
    assert_eq!(unix_rep.lance_chunks_deleted, 1);
    assert_eq!(unix_rep.tantivy_chunks_deleted, 1);
    assert_eq!(unix_rep.catalog_docs_deleted, 1);
    assert_eq!(unix_rep.parent_docs_deleted, 1);
    assert_eq!(unix_rep.atlaskv_triples_deleted, 1);
    assert!(engine.load_parent_document(p_unix_u, 3).unwrap().is_none());
    assert!(engine.load_parent_document(p_unix_l, 3).unwrap().is_some());
}

#[tokio::test]
async fn test_storage_update_chunk_and_prefix_access_tier_syncs_all_4_stores() {
    let tmp = tempdir().unwrap();
    let cfg = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(cfg).await.unwrap();

    let p_drop_1 = r"C:\Users\Alice\Dropbox\plan_a.txt";
    let p_drop_2 = r"C:\Users\Alice\Dropbox\plan_b.txt";
    let p_sib = r"C:\Users\Alice\Dropbox2\plan_sib.txt";

    let c1a = make_chunk("d1:0", "d1", p_drop_1, 3, "DropboxPlanA part zero");
    let c1b = make_chunk("d1:1", "d1", p_drop_1, 3, "DropboxPlanA part one");
    let c2 = make_chunk("d2:0", "d2", p_drop_2, 3, "DropboxPlanB payload");
    let cs = make_chunk("ds:0", "ds", p_sib, 3, "DropboxPlanSib payload");

    engine
        .insert_chunks(&[c1a.clone(), c1b.clone(), c2.clone(), cs.clone()])
        .await
        .unwrap();
    for (id, p, title) in [
        ("d1", p_drop_1, "Plan A"),
        ("d2", p_drop_2, "Plan B"),
        ("ds", p_sib, "Plan Sib"),
    ] {
        engine
            .catalog()
            .upsert_entry(&make_catalog_entry(id, p, 3, title))
            .unwrap();
        engine
            .upsert_parent_document(&make_parent(id, p, title), 3)
            .unwrap();
    }

    let q_vec = c1a.vector.clone();
    let kv_records = vec![
        quorum_atlaskv::KgTripleRecord::new(
            "PlanA0", "tier", "val", "d1", "d1:0", p_drop_1, 1, 5, "d1", 3, "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "PlanA1", "tier", "val", "d1", "d1:1", p_drop_1, 1, 5, "d1", 3, "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "PlanB0", "tier", "val", "d2", "d2:0", p_drop_2, 1, 5, "d2", 3, "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "PlanSib", "tier", "val", "ds", "ds:0", p_sib, 1, 5, "ds", 3, "local",
        )
        .unwrap(),
    ];
    engine
        .atlaskv()
        .insert_triples(
            &kv_records,
            &vec![q_vec.clone(); 4],
            &vec![q_vec.clone(); 4],
        )
        .unwrap();

    // Fail-closed on invalid tier > 3
    assert!(matches!(
        engine.update_chunk_access_tier("d1:0", 4).await,
        Err(StorageError::Type(TypeError::InvalidAccessTier(4)))
    ));
    assert!(matches!(
        engine
            .update_path_prefix_access_tier(r"C:\Users\Alice\Dropbox", 5)
            .await,
        Err(StorageError::Type(TypeError::InvalidAccessTier(5)))
    ));

    // Non-existent chunk must NOT bump index_epoch
    let epoch_before_missing = engine.index_epoch();
    engine
        .update_chunk_access_tier("nonexistent:0", 1)
        .await
        .unwrap();
    assert_eq!(engine.index_epoch(), epoch_before_missing);

    // Update only d1:0 -> tier 1; d1:1 is still tier 3, so catalog & parent_document for d1 MUST stay tier 3,
    // and index_epoch MUST bump so QueryCache cannot serve stale pre-reclassification hits.
    let epoch_before_chunk_0 = engine.index_epoch();
    engine.update_chunk_access_tier("d1:0", 1).await.unwrap();
    let epoch_after_chunk_0 = engine.index_epoch();
    assert!(epoch_after_chunk_0 > epoch_before_chunk_0);
    assert_eq!(
        engine
            .catalog()
            .get_by_file_path(p_drop_1)
            .unwrap()
            .unwrap()
            .access_tier,
        3
    );
    assert!(engine.load_parent_document(p_drop_1, 1).unwrap().is_none());

    // Now update d1:1 -> tier 1; both chunks of d1 are tier 1 so catalog & parent_document drop to tier 1
    engine.update_chunk_access_tier("d1:1", 1).await.unwrap();
    assert!(engine.index_epoch() > epoch_after_chunk_0);
    assert_eq!(
        engine
            .catalog()
            .get_by_file_path(p_drop_1)
            .unwrap()
            .unwrap()
            .access_tier,
        1
    );
    assert!(engine.load_parent_document(p_drop_1, 1).unwrap().is_some());

    let (kv_t1, _) = engine.atlaskv().hikvp_search(&q_vec, 1, 10, None).unwrap();
    assert_eq!(kv_t1.len(), 2);

    // Prefix update Dropbox -> tier 0 across all 4 stores, preserving sibling Dropbox2 at tier 3
    let epoch_before = engine.index_epoch();
    let tier_rep: PrefixTierUpdateReport = engine
        .update_path_prefix_access_tier("C:/Users/Alice/Dropbox", 0)
        .await
        .unwrap();
    assert!(tier_rep.any_updated());
    assert_eq!(tier_rep.lance_chunks_updated, 3);
    assert_eq!(tier_rep.tantivy_chunks_updated, 3);
    assert_eq!(tier_rep.catalog_docs_updated, 2);
    assert_eq!(tier_rep.parent_docs_updated, 2);
    assert_eq!(tier_rep.atlaskv_triples_updated, 3);
    assert!(tier_rep.new_index_epoch > epoch_before);

    let vec_t0 = engine
        .search(&StorageSearchQuery::vector(q_vec.clone(), 0, 10))
        .await
        .unwrap();
    assert_eq!(vec_t0.len(), 3);
    assert!(!vec_t0.iter().any(|c| c.chunk.chunk_id == "ds:0"));

    let fts_t0 = engine
        .search(&StorageSearchQuery::keyword("DropboxPlan", 0, 10))
        .await
        .unwrap();
    assert_eq!(fts_t0.len(), 3);
    assert!(!fts_t0.iter().any(|c| c.chunk.chunk_id == "ds:0"));

    let cat_t0 = engine
        .catalog()
        .catalog_find_documents_extended("*", None, 0, 10)
        .unwrap();
    assert_eq!(cat_t0.len(), 2);
    assert!(engine.load_parent_document(p_sib, 0).unwrap().is_none());

    let (kv_t0, _) = engine.atlaskv().hikvp_search(&q_vec, 0, 10, None).unwrap();
    assert_eq!(kv_t0.len(), 3);
    assert!(!kv_t0.iter().any(|h| h.triple.chunk_id == "ds:0"));
}

#[tokio::test]
async fn test_update_chunk_record_and_tier_for_file_preserve_identical_content_sibling() {
    let tmp = tempdir().unwrap();
    let cfg = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(cfg).await.unwrap();

    let p_gdrive = r"G:\My Drive\dup.txt";
    let p_dropbox = r"C:\Users\Alice\Dropbox\dup.txt";

    let c_g = make_chunk("dup:0", "doc_g", p_gdrive, 3, "IdenticalSiblingPayload");
    let c_d = make_chunk("dup:0", "doc_d", p_dropbox, 3, "IdenticalSiblingPayload");

    engine
        .insert_chunks(&[c_g.clone(), c_d.clone()])
        .await
        .unwrap();
    engine
        .catalog()
        .upsert_entry(&make_catalog_entry("doc_g", p_gdrive, 3, "GDrive Dup"))
        .unwrap();
    engine
        .catalog()
        .upsert_entry(&make_catalog_entry("doc_d", p_dropbox, 3, "Dropbox Dup"))
        .unwrap();
    engine
        .upsert_parent_document(&make_parent("doc_g", p_gdrive, "GDrive Dup"), 3)
        .unwrap();
    engine
        .upsert_parent_document(&make_parent("doc_d", p_dropbox, "Dropbox Dup"), 3)
        .unwrap();

    let q_vec = c_g.vector.clone();
    let kv_records = vec![
        quorum_atlaskv::KgTripleRecord::new(
            "DupEntity",
            "stored_in",
            "GDrive",
            "doc_g",
            "dup:0",
            p_gdrive,
            1,
            5,
            "doc_g",
            3,
            "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "DupEntity",
            "stored_in",
            "Dropbox",
            "doc_d",
            "dup:0",
            p_dropbox,
            1,
            5,
            "doc_d",
            3,
            "local",
        )
        .unwrap(),
    ];
    engine
        .atlaskv()
        .insert_triples(
            &kv_records,
            &vec![q_vec.clone(); 2],
            &vec![q_vec.clone(); 2],
        )
        .unwrap();

    // Update Google Drive record text via update_chunk_record: Dropbox sibling must survive intact
    let mut updated_g = c_g.clone();
    updated_g.text_content = "IdenticalSiblingPayload refreshed on gdrive".to_string();
    engine.update_chunk_record(&updated_g).await.unwrap();

    let drop_lance_after_rec = engine
        .get_chunk_by_id_and_file_path("dup:0", p_dropbox)
        .await
        .unwrap()
        .expect("Dropbox sibling must survive update_chunk_record on GDrive");
    assert_eq!(drop_lance_after_rec.access_tier, 3);

    // Update ONLY Google Drive copy's tier to 1 via update_chunk_access_tier_for_file
    engine
        .update_chunk_access_tier_for_file("dup:0", p_gdrive, 1)
        .await
        .unwrap();

    let g_after = engine
        .get_chunk_by_id_and_file_path("dup:0", p_gdrive)
        .await
        .unwrap()
        .expect("GDrive copy should exist");
    assert_eq!(g_after.access_tier, 1);

    let d_after = engine
        .get_chunk_by_id_and_file_path("dup:0", p_dropbox)
        .await
        .unwrap()
        .expect("Dropbox sibling must remain present");
    assert_eq!(d_after.access_tier, 3);

    // Tier-1 vector & FTS queries see ONLY GDrive; Tier-3 sees both
    let vec_t1 = engine
        .search(&StorageSearchQuery::vector(q_vec.clone(), 1, 10))
        .await
        .unwrap();
    assert_eq!(vec_t1.len(), 1);
    assert_eq!(vec_t1[0].chunk.file_path, p_gdrive);

    let fts_t1 = engine
        .search(&StorageSearchQuery::keyword(
            "IdenticalSiblingPayload",
            1,
            10,
        ))
        .await
        .unwrap();
    assert_eq!(fts_t1.len(), 1);
    assert_eq!(fts_t1[0].chunk.file_path, p_gdrive);

    let fts_t3 = engine
        .search(&StorageSearchQuery::keyword(
            "IdenticalSiblingPayload",
            3,
            10,
        ))
        .await
        .unwrap();
    assert_eq!(fts_t3.len(), 2);

    // Catalog & AtlasKV also keep Dropbox at tier 3 while GDrive is tier 1
    assert_eq!(
        engine
            .catalog()
            .get_by_file_path(p_gdrive)
            .unwrap()
            .unwrap()
            .access_tier,
        1
    );
    assert_eq!(
        engine
            .catalog()
            .get_by_file_path(p_dropbox)
            .unwrap()
            .unwrap()
            .access_tier,
        3
    );
    let (kv_t1, _) = engine.atlaskv().hikvp_search(&q_vec, 1, 10, None).unwrap();
    assert_eq!(kv_t1.len(), 1);
    assert_eq!(kv_t1[0].triple.file_path, p_gdrive);

    let (kv_t3, _) = engine.atlaskv().hikvp_search(&q_vec, 3, 10, None).unwrap();
    assert_eq!(kv_t3.len(), 2);
}

#[tokio::test]
async fn t5_storage_delete_and_tier_update_by_file_path_slash_case_consistency() {
    let tmp = tempdir().unwrap();
    let cfg = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(cfg).await.unwrap();

    let canonical_a = r"C:\Temp\MixedCase\SecretDocA.txt";
    let variant_a = "c:/temp/mixedcase/secretdoca.txt";
    let canonical_b = r"C:\Temp\MixedCase\SecretDocB.txt";
    let variant_b = "c:/temp/mixedcase/secretdocb.txt";
    let sibling = r"C:\Temp\MixedCase\SiblingKeep.txt";

    let ca = make_chunk("ca:0", "doc_a", canonical_a, 0, "MixedCaseSecretAlpha");
    let cb = make_chunk("cb:0", "doc_b", canonical_b, 0, "MixedCaseSecretBeta");
    let cs = make_chunk("cs:0", "doc_s", sibling, 0, "MixedCaseSiblingKeep");

    engine
        .insert_chunks(&[ca.clone(), cb.clone(), cs.clone()])
        .await
        .unwrap();
    for (id, p, title) in [
        ("doc_a", canonical_a, "Secret A"),
        ("doc_b", canonical_b, "Secret B"),
        ("doc_s", sibling, "Sibling"),
    ] {
        engine
            .catalog()
            .upsert_entry(&make_catalog_entry(id, p, 0, title))
            .unwrap();
        engine
            .upsert_parent_document(&make_parent(id, p, title), 0)
            .unwrap();
    }

    let q_vec = ca.vector.clone();
    let kv_records = vec![
        quorum_atlaskv::KgTripleRecord::new(
            "EntityA",
            "secret",
            "alpha",
            "doc_a",
            "ca:0",
            canonical_a,
            1,
            5,
            "doc_a",
            0,
            "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "EntityB",
            "secret",
            "beta",
            "doc_b",
            "cb:0",
            canonical_b,
            1,
            5,
            "doc_b",
            0,
            "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "EntityS", "secret", "keep", "doc_s", "cs:0", sibling, 1, 5, "doc_s", 0, "local",
        )
        .unwrap(),
    ];
    engine
        .atlaskv()
        .insert_triples(
            &kv_records,
            &vec![q_vec.clone(); 3],
            &vec![q_vec.clone(); 3],
        )
        .unwrap();

    // 1. Reclassify SecretDocA from Tier 0 -> Tier 3 using slash/case variant
    engine
        .update_chunk_access_tier_for_file("ca:0", variant_a, 3)
        .await
        .unwrap();

    let kw_t0 = engine
        .search(&StorageSearchQuery::keyword("MixedCaseSecretAlpha", 0, 10))
        .await
        .unwrap();
    assert!(
        kw_t0.is_empty(),
        "Tier 0 keyword search must NOT return SecretDocA after variant update: {kw_t0:?}"
    );
    let vec_t0 = engine
        .search(&StorageSearchQuery::vector(q_vec.clone(), 0, 10))
        .await
        .unwrap();
    assert!(
        !vec_t0.iter().any(|c| c.chunk.chunk_id == "ca:0"),
        "Tier 0 vector search must NOT return SecretDocA after variant update"
    );
    assert_eq!(
        engine
            .catalog()
            .get_by_file_path(canonical_a)
            .unwrap()
            .unwrap()
            .access_tier,
        3
    );
    assert!(engine
        .load_parent_document(canonical_a, 0)
        .unwrap()
        .is_none());
    let (kv_t0, _) = engine.atlaskv().hikvp_search(&q_vec, 0, 10, None).unwrap();
    assert!(!kv_t0.iter().any(|h| h.triple.chunk_id == "ca:0"));

    // 2. Delete SecretDocB using slash/case variant -> all 4 stores must delete consistently (0 desync)
    let del_count = engine.delete_by_file_path(variant_b).await.unwrap();
    assert_eq!(del_count, 1);

    let kw_b = engine
        .search(&StorageSearchQuery::keyword("MixedCaseSecretBeta", 3, 10))
        .await
        .unwrap();
    assert!(
        kw_b.is_empty(),
        "Tantivy must have 0 hits for deleted SecretDocB"
    );
    let lance_chunks = engine.scan_all_chunks().await.unwrap();
    assert!(
        !lance_chunks.iter().any(|c| c.chunk_id == "cb:0"),
        "LanceDB must have 0 chunks for deleted SecretDocB"
    );
    assert!(
        engine
            .catalog()
            .get_by_file_path(canonical_b)
            .unwrap()
            .is_none(),
        "DocumentCatalog must have 0 rows for deleted SecretDocB"
    );
    assert!(engine
        .load_parent_document(canonical_b, 3)
        .unwrap()
        .is_none());
    let (kv_b, _) = engine.atlaskv().hikvp_search(&q_vec, 3, 10, None).unwrap();
    assert!(!kv_b.iter().any(|h| h.triple.chunk_id == "cb:0"));

    // Sibling must remain untouched at Tier 0 across all stores
    assert!(lance_chunks.iter().any(|c| c.chunk_id == "cs:0"));
    assert!(kv_b.iter().any(|h| h.triple.chunk_id == "cs:0"));

    // 3. update_chunk_record + delete_by_file_paths with slash/case variant on SecretDocA
    let mut updated_a = ca.clone();
    updated_a.file_path = variant_a.to_string();
    updated_a.access_tier = 3;
    updated_a.text_content = "MixedCaseSecretAlphaRefreshed".to_string();
    engine.update_chunk_record(&updated_a).await.unwrap();

    let kw_a_old = engine
        .search(&StorageSearchQuery::keyword("MixedCaseSecretAlpha", 3, 10))
        .await
        .unwrap();
    assert!(
        kw_a_old.is_empty(),
        "update_chunk_record with variant path must replace old Tantivy doc"
    );

    engine
        .delete_by_file_paths(&[canonical_a.to_string()])
        .await
        .unwrap();
    let lance_after_paths = engine.scan_all_chunks().await.unwrap();
    assert!(
        !lance_after_paths.iter().any(|c| c.chunk_id == "ca:0"),
        "delete_by_file_paths must normalize slash/case variants in Tantivy has_file_path & LanceDB"
    );
    assert!(lance_after_paths.iter().any(|c| c.chunk_id == "cs:0"));
}

#[tokio::test]
async fn t5_storage_verbatim_vs_plain_delete_tier_and_load_parent_document() {
    let tmp = tempdir().unwrap();
    let cfg = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(cfg).await.unwrap();

    let p_verb_stored = r"\\?\C:\Users\Alice\OneDrive\Verbatim_Secret.txt";
    let p_verb_plain_var = "c:/users/alice/onedrive/verbatim_secret.txt";
    let p_plain_stored = r"C:\Users\Alice\OneDrive\Plain_Secret.txt";
    let p_plain_verb_var = r"\\?\C:\Users\Alice\OneDrive\Plain_Secret.txt";
    let p_delpaths_stored = r"\\?\C:\Users\Alice\OneDrive\DelPaths_Verb.txt";
    let p_delpaths_var = "c:/users/alice/onedrive/delpaths_verb.txt";
    let p_keep = r"C:\Users\Alice\Docs\KeepParent.txt";

    let cv = make_chunk("cv:0", "doc_v", p_verb_stored, 0, "VerbatimSecretToken");
    let cp = make_chunk("cp:0", "doc_p", p_plain_stored, 0, "PlainSecretToken");
    let cd = make_chunk("cd:0", "doc_d", p_delpaths_stored, 0, "DelPathsVerbToken");
    let ck = make_chunk("ck:0", "doc_k", p_keep, 0, "KeepParentToken");

    engine
        .insert_chunks(&[cv.clone(), cp.clone(), cd.clone(), ck.clone()])
        .await
        .unwrap();
    for (id, p, title) in [
        ("doc_v", p_verb_stored, "Verb"),
        ("doc_p", p_plain_stored, "Plain"),
        ("doc_d", p_delpaths_stored, "DelPaths"),
        ("doc_k", p_keep, "Keep"),
    ] {
        engine
            .catalog()
            .upsert_entry(&make_catalog_entry(id, p, 0, title))
            .unwrap();
        engine
            .upsert_parent_document(&make_parent(id, p, title), 0)
            .unwrap();
    }

    let q_vec = cv.vector.clone();
    let kv_records = vec![
        quorum_atlaskv::KgTripleRecord::new(
            "VerbEnt",
            "secret",
            "v",
            "doc_v",
            "cv:0",
            p_verb_stored,
            1,
            5,
            "doc_v",
            0,
            "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "PlainEnt",
            "secret",
            "p",
            "doc_p",
            "cp:0",
            p_plain_stored,
            1,
            5,
            "doc_p",
            0,
            "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "DelPathsEnt",
            "secret",
            "d",
            "doc_d",
            "cd:0",
            p_delpaths_stored,
            1,
            5,
            "doc_d",
            0,
            "local",
        )
        .unwrap(),
        quorum_atlaskv::KgTripleRecord::new(
            "KeepEnt", "secret", "k", "doc_k", "ck:0", p_keep, 1, 5, "doc_k", 0, "local",
        )
        .unwrap(),
    ];
    engine
        .atlaskv()
        .insert_triples(
            &kv_records,
            &vec![q_vec.clone(); 4],
            &vec![q_vec.clone(); 4],
        )
        .unwrap();

    // 1. load_parent_document must resolve slash/case/\\?\ variants in both directions
    assert!(
        engine
            .load_parent_document(p_verb_plain_var, 0)
            .unwrap()
            .is_some(),
        "load_parent_document must match verbatim-stored doc via plain slash/case path"
    );
    assert!(
        engine
            .load_parent_document(p_plain_verb_var, 0)
            .unwrap()
            .is_some(),
        "load_parent_document must match plain-stored doc via verbatim \\\\?\\ path"
    );

    // 2. Reclassify verbatim-stored doc via plain slash/case variant -> Tier 0 AtlasKV/Lance/Tantivy/Catalog must not leak
    engine
        .update_chunk_access_tier_for_file("cv:0", p_verb_plain_var, 3)
        .await
        .unwrap();
    let (kv_t0, _) = engine.atlaskv().hikvp_search(&q_vec, 0, 10, None).unwrap();
    assert!(!kv_t0.iter().any(|h| h.triple.chunk_id == "cv:0"));
    assert!(engine
        .load_parent_document(p_verb_plain_var, 0)
        .unwrap()
        .is_none());
    assert!(engine
        .load_parent_document(p_verb_plain_var, 3)
        .unwrap()
        .is_some());

    // 3. delete_by_file_path across \\?\ vs plain variants must leave 0 active triples in AtlasKV + 0 in Lance/Tantivy/Catalog
    assert_eq!(
        engine.delete_by_file_path(p_verb_plain_var).await.unwrap(),
        1
    );
    assert_eq!(
        engine.delete_by_file_path(p_plain_verb_var).await.unwrap(),
        1
    );

    // 4. delete_by_file_paths across \\?\ vs plain variant
    engine
        .delete_by_file_paths(&[p_delpaths_var.to_string()])
        .await
        .unwrap();

    let lance_rem = engine.scan_all_chunks().await.unwrap();
    assert_eq!(lance_rem.len(), 1);
    assert_eq!(lance_rem[0].chunk_id, "ck:0");

    let (kv_t3, _) = engine.atlaskv().hikvp_search(&q_vec, 3, 10, None).unwrap();
    assert_eq!(kv_t3.len(), 1);
    assert_eq!(kv_t3[0].triple.chunk_id, "ck:0");
    assert_eq!(engine.atlaskv().stats().active_triples, 1);

    assert!(engine
        .load_parent_document(p_verb_stored, 3)
        .unwrap()
        .is_none());
    assert!(engine
        .load_parent_document(p_plain_stored, 3)
        .unwrap()
        .is_none());
    assert!(engine
        .load_parent_document(p_delpaths_stored, 3)
        .unwrap()
        .is_none());
    assert!(engine.load_parent_document(p_keep, 0).unwrap().is_some());
}

#[tokio::test]
async fn t5_storage_unc_verbatim_vs_plain_load_parent_and_delete_by_file_path() {
    let tmp = tempdir().unwrap();
    let cfg = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(cfg).await.unwrap();

    let p_unc_verbatim = r"\\?\UNC\Fileserver\TeamShare\Cloud\SecretPlan.txt";
    let p_unc_plain = r"\\fileserver\teamshare\cloud\secretplan.txt";

    // Cloud-drive validator must remain fail-closed on UNC paths
    assert!(matches!(
        quorum_types::validate_cloud_drive_path(p_unc_plain),
        Err(TypeError::InvalidCloudDrivePath { .. })
    ));
    assert!(matches!(
        quorum_types::validate_cloud_drive_path(p_unc_verbatim),
        Err(TypeError::InvalidCloudDrivePath { .. })
    ));

    let c_unc = make_chunk("unc:0", "doc_unc", p_unc_verbatim, 2, "UncVerbatimToken");
    engine
        .insert_chunks(std::slice::from_ref(&c_unc))
        .await
        .unwrap();
    engine
        .catalog()
        .upsert_entry(&make_catalog_entry("doc_unc", p_unc_verbatim, 2, "UncPlan"))
        .unwrap();
    engine
        .upsert_parent_document(&make_parent("doc_unc", p_unc_verbatim, "UncPlan"), 2)
        .unwrap();

    assert!(
        engine
            .load_parent_document(p_unc_plain, 2)
            .unwrap()
            .is_some(),
        "load_parent_document must match \\\\?\\UNC\\... stored doc via plain \\\\... path"
    );
    assert_eq!(
        engine.delete_by_file_path(p_unc_plain).await.unwrap(),
        1,
        "delete_by_file_path must match \\\\?\\UNC\\... stored doc via plain \\\\... path"
    );
    assert!(engine
        .load_parent_document(p_unc_verbatim, 2)
        .unwrap()
        .is_none());
    assert!(engine.scan_all_chunks().await.unwrap().is_empty());
}
