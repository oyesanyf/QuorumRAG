use std::collections::HashSet;
use std::fs;
use std::time::Instant;

use quorum_atlaskv::{
    dot_f32, export_atlaskv_dataset, format_grounded_kg_context, import_atlaskv_dataset,
    l2_normalize_in_place, read_npy_2d_as_f32, validate_safe_relative_path, AtlasKvError,
    AtlasKvStore, AtlasKvTreeConfig, CandidateKgTripleDto, Kg2KvExtractor, Kg2KvExtractorConfig,
    KgSourceChunk, KgTripleRecord,
};
use tempfile::TempDir;

/// Deterministic 768-dim L2-normalized embedding helper mirroring QuorumRAG's
/// `DeterministicOfflineEngine` (BLAKE3 XOF token hashing on the unit hypersphere).
fn deterministic_embed_768(text: &str) -> Vec<f32> {
    let dim = 768usize;
    let mut vec = vec![0.0f32; dim];
    for raw_tok in text.split(|c: char| !c.is_alphanumeric()) {
        let tok = raw_tok.trim().to_ascii_lowercase();
        if tok.len() < 2 {
            continue;
        }
        let mut reader = blake3::Hasher::new().update(tok.as_bytes()).finalize_xof();
        let mut buf = [0u8; 32];
        reader.fill(&mut buf);
        let (chunks, _) = buf.as_chunks::<4>();
        for &chunk in chunks {
            let h = u32::from_le_bytes(chunk);
            let idx = (h as usize) % dim;
            let sign = if (h & 1) == 0 { 1.0f32 } else { -1.0f32 };
            vec[idx] += sign;
        }
    }
    if !l2_normalize_in_place(&mut vec) {
        vec[0] = 1.0;
    }
    vec
}

/// Deterministic fast PRNG for realistic clustered hypersphere benchmarks.
struct TestRng(u64);
impl TestRng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Generates an approximate standard-normal scalar via Central Limit Theorem (sum of 6 uniforms).
    fn next_normal(&mut self) -> f32 {
        let mut sum = 0.0f64;
        for _ in 0..6 {
            let u = (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64);
            sum += u;
        }
        ((sum - 3.0) * std::f64::consts::SQRT_2) as f32
    }

    fn unit_vec(&mut self, dim: usize) -> Vec<f32> {
        let mut v: Vec<f32> = (0..dim).map(|_| self.next_normal()).collect();
        l2_normalize_in_place(&mut v);
        v
    }

    fn perturbed_unit_vec(&mut self, center: &[f32], noise_scale: f32) -> Vec<f32> {
        let mut v: Vec<f32> = center
            .iter()
            .map(|&c| c + self.next_normal() * noise_scale)
            .collect();
        l2_normalize_in_place(&mut v);
        v
    }
}

#[test]
fn kg2kv_real_documents_and_homonym_disambiguation() {
    let extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig::default());

    let chunks = vec![
        KgSourceChunk {
            chunk_id: "doc1:0".into(),
            document_id: "doc1".into(),
            file_path: r"C:\Corpus\Academic\Women Race Class Summary.docx".into(),
            line_start: 1,
            line_end: 24,
            access_tier: 0,
            text_content: "[Document: \"Women Race Class Summary\" | Author: Angela Davis | Kind: article | File: Women Race Class Summary.docx]\n\
                           Women, Race & Class is a landmark work by Angela Davis, first published in 1981.\n\
                           ISBN: 978-0394713519\n\
                           Accidental token AKIAIOSFODNN7EXAMPLE and SSN 123-45-6789 must be redacted."
                .into(),
            metadata_json: "{}".into(),
            ..Default::default()
        },
        KgSourceChunk {
            chunk_id: "doc2:0".into(),
            document_id: "doc2".into(),
            file_path: r"C:\Corpus\Ministry\Back to Work.docx".into(),
            line_start: 1,
            line_end: 18,
            access_tier: 0,
            text_content: "STEWARD NAMES OF all BOARD MEMBERS PRESENT:\n\
                           S= Shannon Davis\n\
                           T- Toya Johnson\n\
                           E- Eleanor Davis\n\
                           A= Angela Davis Breure & Anthony Davis Jr\n\
                           Recorded by Angela Davis\n\
                           Adjourned with prayer by Anthony Davis"
                .into(),
            metadata_json: "{}".into(),
            ..Default::default()
        },
        KgSourceChunk {
            chunk_id: "doc3:0".into(),
            document_id: "doc3".into(),
            file_path: r"C:\Corpus\Stories\Explaining Nostalgia Simply.docx".into(),
            line_start: 1,
            line_end: 12,
            access_tier: 0,
            text_content: "Tell it from my view as a storyteller Angela Davis, the yarn spinner.\n\
                           Here is your version, told as Angela Davis, the yarn spinner."
                .into(),
            metadata_json: "{}".into(),
            ..Default::default()
        },
        KgSourceChunk {
            chunk_id: "doc4:0".into(),
            document_id: "doc4".into(),
            file_path: r"C:\Corpus\Property\Lease_Agreement_2025_v2.docx".into(),
            line_start: 1,
            line_end: 30,
            access_tier: 0,
            text_content: "Property Address: 412 Oakwood Lane, Suite B\n\
                           Landlord: Angela Davis\n\
                           Monthly Rent: $1,850\n\
                           | Unit | Tenant | Status |\n\
                           |---|---|---|\n\
                           | Suite B | Marcus Reed | Active |"
                .into(),
            metadata_json: "{}".into(),
            ..Default::default()
        },
    ];

    let mut all_triples = Vec::new();
    for ch in &chunks {
        let extracted = extractor.extract_from_chunk(ch).expect("extract chunk");
        assert!(
            !extracted.is_empty(),
            "Expected grounded triples from {}",
            ch.file_path
        );
        all_triples.extend(extracted);
    }

    // Verify secret scrubbing: raw AWS key and SSN MUST NEVER appear in any triple
    for t in &all_triples {
        assert!(!t.entity.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!t.value.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!t.entity.contains("123-45-6789"));
        assert!(!t.value.contains("123-45-6789"));
        assert!(
            t.key_string.starts_with("the "),
            "AtlasKV canonical key_string must start with 'the ': got '{}'",
            t.key_string
        );
    }

    // Verify key facts extracted across all 4 distinct Angela Davis domains
    assert!(
        all_triples
            .iter()
            .any(|t| t.relation == "publication year" && t.value == "1981"),
        "Missing 1981 publication year triple: {:#?}",
        all_triples
    );
    assert!(
        all_triples
            .iter()
            .any(|t| t.relation == "recorder" && t.value == "Angela Davis"),
        "Missing Back to Work recorder triple"
    );
    assert!(
        all_triples
            .iter()
            .any(|t| t.relation == "storyteller persona" && t.value == "yarn spinner"),
        "Missing storyteller yarn spinner triple"
    );
    assert!(
        all_triples
            .iter()
            .any(|t| t.relation == "landlord" && t.value == "Angela Davis"),
        "Missing lease Landlord triple"
    );
    assert!(
        all_triples
            .iter()
            .any(|t| t.entity == "Suite B" && t.relation == "tenant" && t.value == "Marcus Reed"),
        "Missing Markdown table tenant triple"
    );

    // Store & query via AtlasKvStore and verify BLAKE3 dedup + homonym context cluster separation
    let tmp = TempDir::new().unwrap();
    let store = AtlasKvStore::open(tmp.path(), AtlasKvTreeConfig::default()).unwrap();
    let key_vecs: Vec<Vec<f32>> = all_triples
        .iter()
        .map(|t| deterministic_embed_768(&t.key_string))
        .collect();
    let val_vecs: Vec<Vec<f32>> = all_triples
        .iter()
        .map(|t| deterministic_embed_768(&t.value))
        .collect();

    let inserted = store
        .insert_triples(&all_triples, &key_vecs, &val_vecs)
        .unwrap();
    assert_eq!(inserted, all_triples.len());

    // Re-inserting exact same batch must insert 0 duplicates (BLAKE3 dedup)
    let dup_inserted = store
        .insert_triples(&all_triples, &key_vecs, &val_vecs)
        .unwrap();
    assert_eq!(dup_inserted, 0);

    let q_vec = deterministic_embed_768("the landlord and author of Angela Davis");
    let (hits, _trace) = store.hikvp_search(&q_vec, 0, 20, None).unwrap();
    let formatted = format_grounded_kg_context(&hits);
    assert!(formatted.contains("[AtlasKV Grounded Knowledge Graph Triples]"));
    assert!(formatted.contains("Do NOT merge identities across clusters"));
    // Verify distinct work clusters appear separately
    let distinct_clusters: HashSet<&str> = hits
        .iter()
        .map(|h| h.triple.work_cluster_id.as_str())
        .collect();
    assert!(
        distinct_clusters.len() >= 3,
        "Expected >= 3 distinct homonym work clusters, got {:?}",
        distinct_clusters
    );
}

#[test]
fn hikvp_10k_triples_recall_sublinear_pruning_and_persistence() {
    let tmp = TempDir::new().unwrap();
    let dim = 768usize;
    let n_topics = 200usize;
    let per_topic = 50usize;
    let total_triples = n_topics * per_topic; // 10,000 triples

    let cfg = AtlasKvTreeConfig {
        root_top_k_kb: 8,
        inter_top_k_kb: 32,
        leaf_top_k_kb: 20,
        embedding_dim: dim,
        min_triples_for_hierarchy: 512,
        max_inter_clusters: 65_536,
        max_root_clusters: 2_048,
        max_kmeans_iters: 12,
    };

    let mut rng = TestRng(0xCAFE_BABE_1234_5678);
    let topic_centers: Vec<Vec<f32>> = (0..n_topics).map(|_| rng.unit_vec(dim)).collect();

    let mut triples = Vec::with_capacity(total_triples);
    let mut key_vecs = Vec::with_capacity(total_triples);
    let mut val_vecs = Vec::with_capacity(total_triples);

    for (t_idx, center) in topic_centers.iter().enumerate() {
        for j in 0..per_topic {
            let kv = rng.perturbed_unit_vec(center, 0.045);
            let vv = rng.perturbed_unit_vec(center, 0.06);
            let rec = KgTripleRecord::new(
                format!("Entity_{}_{}", t_idx, j),
                format!("attribute_{}", j % 7),
                format!("Verified fact value #{}_{}", t_idx, j),
                format!("doc_{}", t_idx),
                format!("doc_{}:{}", t_idx, j),
                format!("corpus/topic_{}/doc_{}.md", t_idx, t_idx),
                (j + 1) as u32,
                (j + 2) as u32,
                format!("topic {}", t_idx),
                0,
                "local",
            )
            .unwrap();
            triples.push(rec);
            key_vecs.push(kv);
            val_vecs.push(vv);
        }
    }

    let store = AtlasKvStore::open(tmp.path(), cfg.clone()).unwrap();
    let t0 = Instant::now();
    let inserted = store.insert_triples(&triples, &key_vecs, &val_vecs).unwrap();
    let insert_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(inserted, total_triples);

    let t1 = Instant::now();
    let stats = store.rebuild_hierarchy().unwrap();
    let build_ms = t1.elapsed().as_secs_f64() * 1000.0;

    assert!(stats.hierarchy_built);
    assert_eq!(stats.active_triples, total_triples);
    assert!(
        stats.inter_clusters > 0 && stats.inter_clusters <= 465,
        "Expected Inter1 <= ceil(10000^(2/3))=465, got {}",
        stats.inter_clusters
    );
    assert!(
        stats.root_clusters > 0 && stats.root_clusters <= 22,
        "Expected Root <= ceil(10000^(1/3))=22, got {}",
        stats.root_clusters
    );
    assert!(
        stats.estimated_resident_ram_bytes < 10 * 1024 * 1024,
        "Resident hierarchy RAM must stay < 10 MB for 10K triples, got {} bytes",
        stats.estimated_resident_ram_bytes
    );

    // Evaluate 30 queries against brute-force exact cosine scan
    let n_queries = 30usize;
    let mut total_recall = 0.0f64;
    let mut total_scan_ratio = 0.0f64;
    let mut total_query_us = 0u64;
    let mut sample_query = Vec::new();
    let mut sample_top1_id = 0u64;

    for qi in 0..n_queries {
        let topic = (qi * 7) % n_topics;
        let q = rng.perturbed_unit_vec(&topic_centers[topic], 0.035);

        // Exact brute-force Top-10 over all 10,000 triples
        let mut exact: Vec<(u64, f32)> = key_vecs
            .iter()
            .enumerate()
            .map(|(id, kv)| (id as u64, dot_f32(&q, kv)))
            .collect();
        exact.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let exact_top10: HashSet<u64> = exact.iter().take(10).map(|&(id, _)| id).collect();

        // HiKVP 3-level pruned search
        let (hits, trace) = store.hikvp_search(&q, 0, 10, None).unwrap();
        assert!(trace.used_hierarchy);
        assert_eq!(hits.len(), 10);

        let hit_ids: HashSet<u64> = hits.iter().map(|h| h.triple.triple_id).collect();
        let overlap = exact_top10.intersection(&hit_ids).count();
        total_recall += overlap as f64 / 10.0;
        total_scan_ratio += trace.leaf_scan_ratio();
        total_query_us += trace.elapsed_us;

        if qi == 0 {
            sample_query = q;
            sample_top1_id = hits[0].triple.triple_id;
        }
    }

    let mean_recall = total_recall / n_queries as f64;
    let mean_scan_ratio = total_scan_ratio / n_queries as f64;
    let mean_query_ms = (total_query_us as f64 / n_queries as f64) / 1000.0;

    println!(
        "[BENCH 10K 768d] insert={:.1}ms | rebuild_hierarchy={:.1}ms | roots={} inter={} | \
         Recall@10={:.3} | leaf_scanned={:.1}% (pruned {:.1}%) | mean_query={:.2}ms | \
         shard_disk={:.2}MB | resident_ram={:.2}MB",
        insert_ms,
        build_ms,
        stats.root_clusters,
        stats.inter_clusters,
        mean_recall,
        mean_scan_ratio * 100.0,
        (1.0 - mean_scan_ratio) * 100.0,
        mean_query_ms,
        stats.disk_bytes_shards as f64 / (1024.0 * 1024.0),
        stats.estimated_resident_ram_bytes as f64 / (1024.0 * 1024.0),
    );

    assert!(
        mean_recall >= 0.90,
        "Expected Recall@10 >= 0.90, got {:.3}",
        mean_recall
    );
    assert!(
        mean_scan_ratio <= 0.25,
        "Expected HiKVP leaf scan ratio <= 0.25, got {:.3}",
        mean_scan_ratio
    );
    assert!(
        mean_query_ms < 25.0,
        "Expected mean query latency < 25ms, got {:.2}ms",
        mean_query_ms
    );

    // Cold reload persistence check
    drop(store);
    let reloaded = AtlasKvStore::open(tmp.path(), cfg).unwrap();
    let r_stats = reloaded.stats();
    assert!(r_stats.hierarchy_built);
    assert_eq!(r_stats.active_triples, total_triples);
    assert_eq!(r_stats.root_clusters, stats.root_clusters);
    assert_eq!(r_stats.inter_clusters, stats.inter_clusters);

    let (reloaded_hits, reloaded_trace) = reloaded.hikvp_search(&sample_query, 0, 10, None).unwrap();
    assert!(reloaded_trace.used_hierarchy);
    assert_eq!(reloaded_hits[0].triple.triple_id, sample_top1_id);
}

#[test]
fn hikvp_access_tier_folder_and_forensics_airgap_fail_closed() {
    // 1. Forensics Air-Gap Gate (default OFF must yield 0 triples)
    let default_extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig::default());
    let artemis_chunk = KgSourceChunk {
        chunk_id: "art:1".into(),
        document_id: "art".into(),
        file_path: "artemis://host-01/process_tree.jsonl".into(),
        line_start: 1,
        line_end: 5,
        access_tier: 0,
        text_content: "Host: prod-dc-01\nProcess: lsass.exe\nStatus: suspicious".into(),
        metadata_json: r#"{"artemis_dfir":true}"#.into(),
        ..Default::default()
    };
    assert!(
        default_extractor
            .extract_from_chunk(&artemis_chunk)
            .unwrap()
            .is_empty(),
        "Forensics-off default MUST extract 0 triples from artemis:// chunks"
    );

    let enabled_extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig {
        forensics_enabled: true,
        ..Default::default()
    });
    assert!(
        !enabled_extractor
            .extract_from_chunk(&artemis_chunk)
            .unwrap()
            .is_empty(),
        "Forensics-on explicit opt-in should extract artemis triples"
    );

    // 2. Access-Tier & Shared-Folder Fail-Closed Filtering
    let tmp = TempDir::new().unwrap();
    let store = AtlasKvStore::open(tmp.path(), AtlasKvTreeConfig::default()).unwrap();
    let shared_vec = deterministic_embed_768("patient diagnosis clinical chart summary");

    let recs = vec![
        KgTripleRecord::new(
            "PublicGuide",
            "topic",
            "General wellness handbook",
            "d0",
            "d0:0",
            "/shared/public/wellness.md",
            1,
            3,
            "wellness",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "InternalMemo",
            "topic",
            "Department staffing schedule",
            "d1",
            "d1:0",
            "/shared/internal/staffing.md",
            1,
            3,
            "staffing",
            1,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "ConfidentialChart",
            "diagnosis",
            "Restricted patient chart",
            "d2",
            "d2:0",
            "/private/medical/chart_99.pdf",
            1,
            5,
            "chart 99",
            2,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "RestrictedVault",
            "secret",
            "Crown jewel cryptographic key policy",
            "d3",
            "d3:0",
            "/shared/public/vault.md",
            1,
            5,
            "vault",
            3,
            "local",
        )
        .unwrap(),
    ];

    let kvs = vec![shared_vec.clone(); 4];
    let vvs = vec![shared_vec.clone(); 4];
    store.insert_triples(&recs, &kvs, &vvs).unwrap();

    // Tier 0 caller must NEVER see Tier 1, 2, or 3
    let (t0_hits, t0_trace) = store.hikvp_search(&shared_vec, 0, 10, None).unwrap();
    assert_eq!(t0_hits.len(), 1);
    assert_eq!(t0_hits[0].triple.entity, "PublicGuide");
    assert_eq!(t0_trace.access_tier_filtered, 3);

    // Tier 2 caller restricted to `/shared/public` must NOT see `/private/medical` or `/shared/internal`
    let allowed = vec!["/shared/public".to_string()];
    let (folder_hits, folder_trace) = store
        .hikvp_search(&shared_vec, 2, 10, Some(&allowed))
        .unwrap();
    assert_eq!(folder_hits.len(), 1);
    assert_eq!(folder_hits[0].triple.entity, "PublicGuide");
    assert_eq!(folder_trace.folder_filtered, 2);

    // Invalid access tier > 3 fails closed
    assert!(matches!(
        store.hikvp_search(&shared_vec, 4, 10, None),
        Err(AtlasKvError::InvalidAccessTier(4))
    ));

    // VolatileRemoteTriple zeroize lifecycle check
    let dto = CandidateKgTripleDto {
        triple_id: 42,
        entity: "PatientAlpha".into(),
        relation: "status".into(),
        key_string: "the status of PatientAlpha".into(),
        value: "Redacted remote evidence".into(),
        file_path: "remote.docx".into(),
        line_start: 1,
        line_end: 2,
        work_cluster_id: "remote".into(),
        access_tier: 0,
        score: 0.91,
        origin_peer_id: "12D3KooWTestPeer".into(),
    };
    let volatile = dto.into_volatile();
    assert_eq!(volatile.origin_peer_id, "12D3KooWTestPeer");
    drop(volatile);
}

#[test]
fn native_atlaskv_npy_c2id_qkv_roundtrip_interop() {
    let tmp_src = TempDir::new().unwrap();
    let tmp_export = TempDir::new().unwrap();
    let tmp_dst = TempDir::new().unwrap();

    let dim = 768usize;
    let cfg = AtlasKvTreeConfig {
        root_top_k_kb: 8,
        inter_top_k_kb: 24,
        leaf_top_k_kb: 16,
        embedding_dim: dim,
        min_triples_for_hierarchy: 256,
        ..Default::default()
    };

    let mut rng = TestRng(0x00DE_ADBE_EF42);
    let centers: Vec<Vec<f32>> = (0..20).map(|_| rng.unit_vec(dim)).collect();
    let mut records = Vec::new();
    let mut key_vecs = Vec::new();
    let mut val_vecs = Vec::new();

    for i in 0..600usize {
        let c = &centers[i % 20];
        let tier = if i < 550 { 0u8 } else { 2u8 }; // Last 50 are Confidential
        records.push(
            KgTripleRecord::new(
                format!("WikiEntity_{}", i),
                "category",
                format!("Domain fact {}", i),
                format!("wdoc_{}", i),
                format!("wdoc_{}:0", i),
                format!("wiki/article_{}.md", i),
                1,
                2,
                format!("wiki {}", i % 20),
                tier,
                "local",
            )
            .unwrap(),
        );
        key_vecs.push(rng.perturbed_unit_vec(c, 0.04));
        val_vecs.push(rng.perturbed_unit_vec(c, 0.05));
    }

    let src = AtlasKvStore::open(tmp_src.path(), cfg.clone()).unwrap();
    src.insert_triples(&records, &key_vecs, &val_vecs).unwrap();
    src.rebuild_hierarchy().unwrap();

    // Export strictly Tier 0 public subset -> must export exactly 550 triples, excluding 50 Confidential
    let manifest = export_atlaskv_dataset(&src, tmp_export.path(), "quorum_wiki", 0).unwrap();
    assert_eq!(manifest.exported_triples, 550);
    assert!(manifest.root_clusters > 0);
    assert!(manifest.inter_clusters > 0);
    assert!(manifest.qkv_json_path.exists());
    assert!(manifest.key_npy_path.exists());
    assert!(manifest.val_npy_path.exists());
    assert!(manifest.root_npy_path.as_ref().unwrap().exists());
    assert!(manifest.inter1_npy_path.as_ref().unwrap().exists());

    // Verify NumPy magic bytes and exact 2D matrix shapes
    let key_raw = fs::read(&manifest.key_npy_path).unwrap();
    assert_eq!(&key_raw[0..6], b"\x93NUMPY");
    let (_, k_rows, k_cols) = read_npy_2d_as_f32(&manifest.key_npy_path).unwrap();
    assert_eq!((k_rows, k_cols), (550, dim));
    let (_, r_rows, r_cols) = read_npy_2d_as_f32(manifest.root_npy_path.as_ref().unwrap()).unwrap();
    assert_eq!((r_rows, r_cols), (manifest.root_clusters, dim));

    // Verify all 4 AtlasKV c2id/id2c mapping JSON files exist and parse cleanly
    for suffix in [
        "embd_key_root_c2id_mapping.json",
        "embd_key_root_id2c_mapping.json",
        "embd_key_inter1_c2id_mapping.json",
        "embd_key_inter1_id2c_mapping.json",
    ] {
        let p = tmp_export.path().join(format!("quorum_wiki_{}", suffix));
        assert!(p.exists(), "Missing AtlasKV mapping file {:?}", p);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert!(parsed.is_object());
    }

    // Re-import into a brand-new AtlasKvStore and verify identical search result
    let dst = AtlasKvStore::open(tmp_dst.path(), cfg).unwrap();
    let imported = import_atlaskv_dataset(&dst, tmp_export.path(), "quorum_wiki", 0).unwrap();
    assert_eq!(imported, 550);
    dst.rebuild_hierarchy().unwrap();

    let probe = &key_vecs[42];
    let (src_hits, _) = src.hikvp_search(probe, 0, 5, None).unwrap();
    let (dst_hits, _) = dst.hikvp_search(probe, 0, 5, None).unwrap();
    assert_eq!(src_hits[0].triple.entity, "WikiEntity_42");
    assert_eq!(dst_hits[0].triple.entity, "WikiEntity_42");
    assert!((src_hits[0].score - dst_hits[0].score).abs() < 1e-3);
}

#[test]
fn file_delete_sync_and_incremental_append() {
    let tmp = TempDir::new().unwrap();
    let dim = 768usize;
    let cfg = AtlasKvTreeConfig {
        root_top_k_kb: 8,
        inter_top_k_kb: 24,
        leaf_top_k_kb: 16,
        embedding_dim: dim,
        min_triples_for_hierarchy: 256,
        ..Default::default()
    };

    let mut rng = TestRng(0x1122_3344_5566);
    let mut base_recs = Vec::new();
    let mut base_k = Vec::new();
    let mut base_v = Vec::new();
    for i in 0..600usize {
        let v = rng.unit_vec(dim);
        base_recs.push(
            KgTripleRecord::new(
                format!("BaseEnt_{}", i),
                "summary",
                format!("Baseline fact {}", i),
                "base_doc",
                format!("base:{}", i),
                "docs/baseline.docx",
                1,
                2,
                "baseline",
                0,
                "local",
            )
            .unwrap(),
        );
        base_k.push(v.clone());
        base_v.push(v);
    }

    let store = AtlasKvStore::open(tmp.path(), cfg).unwrap();
    store.insert_triples(&base_recs, &base_k, &base_v).unwrap();
    store.rebuild_hierarchy().unwrap();

    // Incremental append WITHOUT rebuild_hierarchy() -> must be immediately searchable via HiKVP
    let target_vec = deterministic_embed_768("the renewal date of Quantum Lease Contract");
    let new_rec = KgTripleRecord::new(
        "Quantum Lease Contract",
        "renewal date",
        "December 31, 2027",
        "new_doc",
        "new_doc:0",
        r"docs\new_contract.docx",
        10,
        12,
        "new contract",
        0,
        "local",
    )
    .unwrap();
    store
        .insert_triples(
            &[new_rec],
            std::slice::from_ref(&target_vec),
            std::slice::from_ref(&target_vec),
        )
        .unwrap();

    let (hits, trace) = store.hikvp_search(&target_vec, 0, 5, None).unwrap();
    assert!(trace.used_hierarchy);
    assert_eq!(hits[0].triple.entity, "Quantum Lease Contract");
    assert_eq!(hits[0].triple.value, "December 31, 2027");

    // Delete file using forward slashes (cross-OS normalization check) -> must purge immediately
    let deleted = store.delete_by_file_path("docs/new_contract.docx").unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(store.stats().active_triples, 600);
    assert_eq!(store.stats().deleted_triples, 1);

    let (post_hits, _) = store.hikvp_search(&target_vec, 0, 10, None).unwrap();
    assert!(
        post_hits
            .iter()
            .all(|h| h.triple.entity != "Quantum Lease Contract"),
        "Deleted file triple leaked after delete_by_file_path!"
    );
}

#[test]
fn path_traversal_and_security_containment() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let malicious = [
        "",
        "../outside",
        "sub/../../outside",
        r"C:\Windows\System32\drivers\etc\hosts",
        "/etc/passwd",
        r"\\evil-server\share\payload",
        "%2e%2e/secret",
        "nested/%2Froot",
        "nested%5csecret",
        "null%00byte.json",
        "dataset.json:ntfs_ads_stream",
        "dir\0evil",
    ];
    for bad in malicious {
        assert!(
            matches!(
                validate_safe_relative_path(base, bad),
                Err(AtlasKvError::PathTraversal(_))
            ),
            "Malicious path '{}' was NOT blocked!",
            bad
        );
    }

    let ok = validate_safe_relative_path(base, "exports/quorum_wiki").unwrap();
    assert!(ok.starts_with(base));
}

#[test]
fn mesh_root_centroid_summary_routing() {
    let dim = 768usize;
    let mut rng = TestRng(0x7777_8888_9999);
    let academic_center = rng.unit_vec(dim);
    let ministry_center = rng.unit_vec(dim);
    let realestate_center = rng.unit_vec(dim);
    let restricted_secret_center = rng.unit_vec(dim);

    let build_peer = |dir: &std::path::Path,
                      peer_name: &str,
                      center: &[f32],
                      extra_restricted: Option<&[f32]>,
                      rng: &mut TestRng| {
        let store = AtlasKvStore::open(dir, AtlasKvTreeConfig::default()).unwrap();
        let mut recs = Vec::new();
        let mut ks = Vec::new();
        let mut vs = Vec::new();
        for i in 0..120usize {
            let v = rng.perturbed_unit_vec(center, 0.04);
            recs.push(
                KgTripleRecord::new(
                    format!("{}_Ent_{}", peer_name, i),
                    "fact",
                    format!("Domain value {}", i),
                    format!("d_{}", i),
                    format!("d_{}:0", i),
                    format!("shared/{}_{}.md", peer_name, i),
                    1,
                    2,
                    peer_name,
                    0,
                    peer_name,
                )
                .unwrap(),
            );
            ks.push(v.clone());
            vs.push(v);
        }
        if let Some(sec_c) = extra_restricted {
            for i in 0..80usize {
                let v = rng.perturbed_unit_vec(sec_c, 0.03);
                recs.push(
                    KgTripleRecord::new(
                        format!("TopSecret_{}", i),
                        "classified",
                        format!("Restricted payload {}", i),
                        format!("s_{}", i),
                        format!("s_{}:0", i),
                        format!("vault/secret_{}.md", i),
                        1,
                        2,
                        "vault",
                        3, // Tier3Restricted — MUST NOT leak into Tier0 centroid summary!
                        peer_name,
                    )
                    .unwrap(),
                );
                ks.push(v.clone());
                vs.push(v);
            }
        }
        store.insert_triples(&recs, &ks, &vs).unwrap();
        store.rebuild_hierarchy().unwrap();
        store.export_root_centroid_summary(peer_name, 0, 64).unwrap()
    };

    let t1 = TempDir::new().unwrap();
    let t2 = TempDir::new().unwrap();
    let t3 = TempDir::new().unwrap();

    let s_acad = build_peer(t1.path(), "12D3KooWAcademic", &academic_center, None, &mut rng);
    let s_min = build_peer(t2.path(), "12D3KooWMinistry", &ministry_center, None, &mut rng);
    let s_re = build_peer(
        t3.path(),
        "12D3KooWRealEstate",
        &realestate_center,
        Some(&restricted_secret_center),
        &mut rng,
    );

    let summaries = [&s_acad, &s_min, &s_re];
    for s in &summaries {
        assert!(s.centroid_count > 0);
        assert!(
            s.payload_bytes() < 200 * 1024,
            "Centroid digest must stay < 200 KB for fast libp2p gossip, got {} bytes",
            s.payload_bytes()
        );
    }

    // Verify Restricted cluster on Peer-RealEstate did NOT leak into its Tier0 centroid digest
    assert_eq!(s_re.active_triple_count, 120);
    let leak_sim = s_re.score_query(&restricted_secret_center).unwrap();
    assert!(
        leak_sim < 0.30,
        "Tier3Restricted centroid leaked into Tier0 summary! sim={:.3}",
        leak_sim
    );

    // Verify centroid-guided routing ranks the exact owning peer #1 for each domain query
    for (query_vec, expected_peer) in [
        (&academic_center, "12D3KooWAcademic"),
        (&ministry_center, "12D3KooWMinistry"),
        (&realestate_center, "12D3KooWRealEstate"),
    ] {
        let mut ranked: Vec<(&str, f32)> = summaries
            .iter()
            .map(|s| (s.peer_id.as_str(), s.score_query(query_vec).unwrap()))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        println!(
            "[MESH ROUTING] expected={} -> ranked={:?}",
            expected_peer, ranked
        );
        assert_eq!(ranked[0].0, expected_peer);
        assert!(ranked[0].1 > 0.80);
    }
}

#[test]
fn query_entity_surface_reversal_curse_like_escaping_and_tier_cluster_isolation() {
    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 8,
        ..Default::default()
    };
    let dummy_vec = vec![0.25f32; 16];
    let store = AtlasKvStore::open(tmp.path(), cfg.clone()).unwrap();

    let mut recs = vec![
        // Reversal-curse exact & punctuation/whitespace-normalized variants (Tier 0, distinct clusters)
        KgTripleRecord::new(
            "Angela Davis",
            "published work",
            "Women, Race & Class",
            "d_acad",
            "d_acad:0",
            "/shared/public/women_race_class.md",
            1,
            2,
            "women race class",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "  angela   davis  ",
            "role in lease",
            "Landlord",
            "d_lease",
            "d_lease:0",
            "/shared/public/lease.md",
            1,
            2,
            "lease agreement",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "\"Angela Davis,\"",
            "storyteller persona",
            "yarn spinner",
            "d_story",
            "d_story:0",
            "/shared/public/story.md",
            1,
            2,
            "back to work",
            0,
            "local",
        )
        .unwrap(),
        // Compound entity (word-boundary match -> score 0.90)
        KgTripleRecord::new(
            "Angela Davis Breure",
            "board role",
            "steward",
            "d_board",
            "d_board:0",
            "/shared/public/board.md",
            1,
            2,
            "board minutes",
            0,
            "local",
        )
        .unwrap(),
        // Higher-tier restricted records that must NEVER leak into max_tier=0 or max_tier=1
        KgTripleRecord::new(
            "Angela Davis",
            "confidential note",
            "Tier 2 private investigation",
            "d_t2",
            "d_t2:0",
            "/shared/public/t2_secret.md",
            1,
            2,
            "confidential",
            2,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "Angela Davis",
            "restricted note",
            "Tier 3 vault secret",
            "d_t3",
            "d_t3:0",
            "/shared/public/t3_vault.md",
            1,
            2,
            "vault",
            3,
            "local",
        )
        .unwrap(),
        // LIKE wildcard escape test records
        KgTripleRecord::new(
            "Entity_1_0",
            "tag",
            "exact underscore entity",
            "d_u1",
            "d_u1:0",
            "/shared/public/u1.md",
            1,
            2,
            "underscores",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "EntityX1Y0",
            "tag",
            "wildcard impostor",
            "d_u2",
            "d_u2:0",
            "/shared/public/u2.md",
            1,
            2,
            "underscores",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "100% Verified",
            "status",
            "literal percent",
            "d_pct",
            "d_pct:0",
            "/shared/public/pct.md",
            1,
            2,
            "percent",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "1000 Verified",
            "status",
            "non-percent impostor",
            "d_pct2",
            "d_pct2:0",
            "/shared/public/pct2.md",
            1,
            2,
            "percent",
            0,
            "local",
        )
        .unwrap(),
        // Folder boundary test records (`/shared/public` vs `/shared/public2`)
        KgTripleRecord::new(
            "SharedEnt",
            "scope",
            "allowed public folder",
            "d_f1",
            "d_f1:0",
            "/shared/public/allowed.md",
            1,
            2,
            "folders",
            0,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "SharedEnt",
            "scope",
            "sibling prefix leak",
            "d_f2",
            "d_f2:0",
            "/shared/public2/leak.md",
            1,
            2,
            "folders",
            0,
            "local",
        )
        .unwrap(),
    ];

    // Add 15 triples in dominant cluster "dominant" + 2 in minority cluster "minority" to test round-robin
    for i in 0..15usize {
        recs.push(
            KgTripleRecord::new(
                "ClusterTestEntity",
                format!("fact_{i}"),
                format!("Dominant val {i}"),
                format!("d_dom_{i}"),
                format!("d_dom_{i}:0"),
                format!("/shared/public/dom_{i}.md"),
                1,
                2,
                "dominant",
                0,
                "local",
            )
            .unwrap(),
        );
    }
    for i in 0..2usize {
        recs.push(
            KgTripleRecord::new(
                "ClusterTestEntity",
                format!("rare_{i}"),
                format!("Minority val {i}"),
                format!("d_min_{i}"),
                format!("d_min_{i}:0"),
                format!("/shared/public/min_{i}.md"),
                1,
                2,
                "minority",
                0,
                "local",
            )
            .unwrap(),
        );
    }

    let kvs = vec![dummy_vec.clone(); recs.len()];
    let vvs = vec![dummy_vec.clone(); recs.len()];
    store.insert_triples(&recs, &kvs, &vvs).unwrap();

    // 1. Exact & normalized matching + reversal-curse lookup + fail-closed tier isolation
    let hits = store
        .query_entity_surface("  ANGELA   davis ", 1, 10, None)
        .unwrap();
    assert_eq!(
        hits.len(),
        4,
        "Expected 4 Tier<=1 hits (3 exact-normalized + 1 compound), got {hits:#?}"
    );
    assert!(hits.iter().all(|h| h.triple.access_tier <= 1));
    assert_eq!(
        hits.iter().filter(|h| (h.score - 1.0).abs() < 1e-6).count(),
        3
    );
    assert!(hits
        .iter()
        .any(|h| h.triple.entity == "Angela Davis Breure" && (h.score - 0.90).abs() < 1e-6));

    // Invalid tier 4 fails closed even with top_k=0 and empty entity
    assert!(matches!(
        store.query_entity_surface("", 4, 0, None),
        Err(AtlasKvError::InvalidAccessTier(4))
    ));

    // 2. LIKE wildcard escaping (`_` and `%` must be literal, not SQLite wildcards)
    let u_hits = store
        .query_entity_surface("Entity_1_0", 0, 10, None)
        .unwrap();
    assert_eq!(u_hits.len(), 1);
    assert_eq!(u_hits[0].triple.entity, "Entity_1_0");

    let pct_hits = store.query_entity_surface("100%", 0, 10, None).unwrap();
    assert_eq!(pct_hits.len(), 1);
    assert_eq!(pct_hits[0].triple.entity, "100% Verified");

    // 3. Component-boundary folder filtering + empty allowed_folders fail-closed
    let folder_hits = store
        .query_entity_surface("SharedEnt", 0, 10, Some(&["/shared/public".to_string()]))
        .unwrap();
    assert_eq!(folder_hits.len(), 1);
    assert_eq!(folder_hits[0].triple.file_path, "/shared/public/allowed.md");

    let empty_folder_hits = store
        .query_entity_surface("SharedEnt", 0, 10, Some(&[]))
        .unwrap();
    assert!(empty_folder_hits.is_empty());

    // 4. Round-robin work_cluster_id preservation under tight top_k
    let cluster_hits = store
        .query_entity_surface("ClusterTestEntity", 0, 4, None)
        .unwrap();
    assert_eq!(cluster_hits.len(), 4);
    let hit_clusters: HashSet<&str> = cluster_hits
        .iter()
        .map(|h| h.triple.work_cluster_id.as_str())
        .collect();
    assert!(
        hit_clusters.contains("dominant") && hit_clusters.contains("minority"),
        "Both dominant and minority work_cluster_ids must be preserved: {hit_clusters:?}"
    );

    // 5. Soft-delete excludes deleted triples immediately
    assert_eq!(
        store
            .delete_by_file_path("/shared/public/allowed.md")
            .unwrap(),
        1
    );
    let post_del = store
        .query_entity_surface("SharedEnt", 0, 10, Some(&["/shared/public".to_string()]))
        .unwrap();
    assert!(post_del.is_empty());

    // 6. Reopen creates `idx_triples_tier_entity_lower` idempotently even if dropped
    drop(store);
    {
        let conn = rusqlite::Connection::open(tmp.path().join("triples_meta.sqlite")).unwrap();
        conn.execute("DROP INDEX IF EXISTS idx_triples_tier_entity_lower", [])
            .unwrap();
    }
    let reopened = AtlasKvStore::open(tmp.path(), cfg).unwrap();
    let check_hits = reopened
        .query_entity_surface("Angela Davis", 0, 10, None)
        .unwrap();
    assert!(!check_hits.is_empty());
    let conn = rusqlite::Connection::open(tmp.path().join("triples_meta.sqlite")).unwrap();
    let idx_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_triples_tier_entity_lower'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx_count, 1);
}

#[test]
fn query_entity_surface_pre_limit_folder_filtering_over_600_disallowed_rows() {
    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 1024,
        ..Default::default()
    };
    let dummy_vec = vec![0.25f32; 16];
    let store = AtlasKvStore::open(tmp.path(), cfg).unwrap();

    let mut recs = Vec::with_capacity(602);
    for i in 0..600usize {
        recs.push(
            KgTripleRecord::new(
                "PreLimitTarget",
                format!("priv_rel_{i}"),
                format!("Private value {i}"),
                format!("p_{i}"),
                format!("p_{i}:0"),
                format!("/private/vault/file_{i}.md"),
                1,
                2,
                "private",
                0,
                "local",
            )
            .unwrap(),
        );
    }
    for i in 0..2usize {
        recs.push(
            KgTripleRecord::new(
                "PreLimitTarget",
                format!("pub_rel_{i}"),
                format!("Public value {i}"),
                format!("pub_{i}"),
                format!("pub_{i}:0"),
                format!("/shared/public/pub_{i}.md"),
                1,
                2,
                "public",
                0,
                "local",
            )
            .unwrap(),
        );
    }
    let kvs = vec![dummy_vec.clone(); recs.len()];
    let vvs = vec![dummy_vec.clone(); recs.len()];
    store.insert_triples(&recs, &kvs, &vvs).unwrap();

    let hits = store
        .query_entity_surface("PreLimitTarget", 0, 5, Some(&["/shared/public".to_string()]))
        .unwrap();
    assert_eq!(hits.len(), 2);
    assert!(hits
        .iter()
        .all(|h| h.triple.file_path.starts_with("/shared/public/")));
}

#[test]
fn query_entity_surface_prevents_cluster_starvation_handles_punctuation_unicode_and_short_tokens() {
    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 2048,
        ..Default::default()
    };
    let dummy_vec = vec![0.25f32; 16];
    let store = AtlasKvStore::open(tmp.path(), cfg).unwrap();

    // Challenge 1: 520 "dominant" exact triples + 2 "minority" exact triples + 1 "board" compound triple
    let mut recs = Vec::with_capacity(530);
    for i in 0..520usize {
        recs.push(
            KgTripleRecord::new(
                "Angela Davis",
                format!("fact_{i}"),
                format!("Dominant career note {i}"),
                format!("d_dom_{i}"),
                format!("d_dom_{i}:0"),
                format!("/shared/public/dom_{i}.md"),
                1,
                2,
                "dominant",
                0,
                "local",
            )
            .unwrap(),
        );
    }
    for i in 0..2usize {
        recs.push(
            KgTripleRecord::new(
                "Angela Davis",
                format!("min_rel_{i}"),
                format!("Minority record {i}"),
                format!("d_min_{i}"),
                format!("d_min_{i}:0"),
                format!("/shared/public/min_{i}.md"),
                1,
                2,
                "minority",
                0,
                "local",
            )
            .unwrap(),
        );
    }
    recs.push(
        KgTripleRecord::new(
            "Angela Davis Breure",
            "board role",
            "steward",
            "d_board",
            "d_board:0",
            "/shared/public/board.md",
            1,
            2,
            "board",
            0,
            "local",
        )
        .unwrap(),
    );

    // Challenge 2: Internal punctuation & non-ASCII case folding
    recs.push(
        KgTripleRecord::new(
            "Women, Race & Class",
            "author",
            "Angela Davis",
            "d_wrc",
            "d_wrc:0",
            "/shared/public/wrc.md",
            1,
            2,
            "works",
            0,
            "local",
        )
        .unwrap(),
    );
    recs.push(
        KgTripleRecord::new(
            "Élodie Laurent",
            "published work",
            "Éloge",
            "d_elodie",
            "d_elodie:0",
            "/shared/public/elodie.md",
            1,
            2,
            "research",
            0,
            "local",
        )
        .unwrap(),
    );

    // Reviewer Challenge 3: short single-token word-boundary guard ("ada" must not match "Canada")
    recs.push(
        KgTripleRecord::new(
            "Canada",
            "capital",
            "Ottawa",
            "d_can",
            "d_can:0",
            "/shared/public/canada.md",
            1,
            2,
            "geo",
            0,
            "local",
        )
        .unwrap(),
    );
    recs.push(
        KgTripleRecord::new(
            "Ada Lovelace",
            "field",
            "computing",
            "d_ada",
            "d_ada:0",
            "/shared/public/ada.md",
            1,
            2,
            "pioneers",
            0,
            "local",
        )
        .unwrap(),
    );

    let kvs = vec![dummy_vec.clone(); recs.len()];
    let vvs = vec![dummy_vec; recs.len()];
    store.insert_triples(&recs, &kvs, &vvs).unwrap();

    // 1. Challenge 1 verification: minority & board clusters must not be starved by 520 dominant rows
    let angela_hits = store
        .query_entity_surface("Angela Davis", 0, 10, None)
        .unwrap();
    let clusters: HashSet<&str> = angela_hits
        .iter()
        .map(|h| h.triple.work_cluster_id.as_str())
        .collect();
    assert!(
        clusters.contains("dominant")
            && clusters.contains("minority")
            && clusters.contains("board"),
        "All three clusters (dominant, minority, board) must appear: {clusters:?}"
    );

    // 2. Challenge 2 verification: internal punctuation & non-ASCII case folding
    let wrc_hits = store
        .query_entity_surface("Women Race & Class", 0, 10, None)
        .unwrap();
    assert_eq!(wrc_hits.len(), 1, "Expected Women, Race & Class match");
    assert!((wrc_hits[0].score - 1.0).abs() < 1e-6);

    let elodie_hits = store
        .query_entity_surface("élodie laurent", 0, 10, None)
        .unwrap();
    assert_eq!(elodie_hits.len(), 1, "Expected Élodie Laurent match");
    assert_eq!(elodie_hits[0].triple.entity, "Élodie Laurent");
    assert!((elodie_hits[0].score - 1.0).abs() < 1e-6);

    // 3. Reviewer Challenge 3 verification: short token "ada" matches "Ada Lovelace", not "Canada"
    let ada_hits = store.query_entity_surface("ada", 0, 10, None).unwrap();
    assert_eq!(ada_hits.len(), 1);
    assert_eq!(ada_hits[0].triple.entity, "Ada Lovelace");
}
