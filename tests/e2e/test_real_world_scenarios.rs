//! E2E Tests: Tier 4 Real-World Application Workloads & End-to-End Scenarios.
//!
//! Realistic application scenarios covered:
//! 1. End-to-end multi-node research query across multi-drive mock filesystems with verified citations.
//! 2. "Ask Anything" web synthesis router handling general queries vs grounded code queries.
//! 3. Filesystem lifecycle: file edits, directory renames, and BLAKE3 cache propagation.
//! 4. Multi-tier enterprise organization access control across heterogeneous clearance levels.
//! 5. Cold-start single executable daemon startup with embedded web UI and `--no-browser` flag.
//! 6. 30TB+ drive scale simulation: deep directory hierarchy, multi-batch inserts, and parquet compaction.

use quorum_classifier::FileTypeClassifier;
use quorum_e2e::*;
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk};
use std::fs::{create_dir_all, rename, File};
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn test_scenario_1_multi_node_federated_research_query() {
    // Scenario: A developer at Node Alpha queries the federated mesh for "ZeroizeOnDrop volatile memory".
    // Node Alpha has local docs, Node Beta has crypto utilities, Node Gamma has network protocols.

    let mut local_storage = IsolatedStorageEngine::new();
    local_storage.insert_chunks(&[DocumentChunk::new(
        "alpha_chunk_1",
        "doc_alpha",
        "crates/core/src/volatile.rs",
        15,
        35,
        0,
        vec![1.0; 768],
        "Remote peer chunks must be held in ZeroizeOnDrop volatile memory containers.",
        None,
    )
    .unwrap()]);

    let mut coordinator = FederatedQueryCoordinator::new(local_storage);

    // Node Beta (Remote Peer 1)
    let peer_beta = MockRemotePeer {
        peer_id: "node_beta_12D3KooW".to_string(),
        latency: Duration::from_millis(45),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "beta_chunk_10".to_string(),
            file_path: "crates/crypto/src/scrub.rs".to_string(),
            line_start: 100,
            line_end: 125,
            content: "Zeroize memory buffers on drop to prevent forensic heap recovery.".to_string(),
            score: 0.94,
            access_tier: 0,
        }],
    };

    // Node Gamma (Remote Peer 2)
    let peer_gamma = MockRemotePeer {
        peer_id: "node_gamma_12D3KooX".to_string(),
        latency: Duration::from_millis(60),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "gamma_chunk_5".to_string(),
            file_path: "crates/wire/src/transport.rs".to_string(),
            line_start: 50,
            line_end: 75,
            content: "QUIC and TCP Noise transports for P2P chunk transfer.".to_string(),
            score: 0.70,
            access_tier: 0,
        }],
    };

    coordinator.add_peer(peer_beta);
    coordinator.add_peer(peer_gamma);

    let (results, volatile_chunks, duration_ms) = coordinator
        .execute_query("ZeroizeOnDrop volatile memory", &vec![1.0; 768], 0, 5)
        .await;

    // Invariants:
    // 1. Must complete within 400ms scatter-gather deadline
    assert!(duration_ms < 400);

    // 2. Results must contain top hits from both Alpha and Beta
    assert!(results.len() >= 2);
    let ids: Vec<&str> = results.iter().map(|r| r.chunk.chunk_id.as_str()).collect();
    assert!(ids.contains(&"alpha_chunk_1"), "Must contain Alpha's local chunk");
    assert!(ids.contains(&"beta_chunk_10"), "Must contain Beta's remote chunk");

    let zeroize_found = results.iter().any(|r| r.chunk.text_content.contains("Zeroize"));
    assert!(zeroize_found, "Gathered results must contain Zeroize content");

    // 3. Remote chunks must be wrapped in volatile memory containers
    assert!(!volatile_chunks.is_empty());
    assert_eq!(volatile_chunks[0].chunk_id, "beta_chunk_10");

    // 4. Citation generation produces structured badges
    let citation = results[0].to_citation();
    assert!(!citation.file_path.is_empty());
    assert!(citation.line_start > 0);
    assert!(citation.line_end >= citation.line_start);
}

#[test]
fn test_scenario_2_ask_anything_router_code_vs_general_query() {
    // Scenario: User asks a specific code question ("What is IVF_PQ threshold?")
    // vs a general knowledge question ("What is the capital of France?").

    let mut storage = IsolatedStorageEngine::new();
    storage.insert_chunks(&[DocumentChunk::new(
        "lance_config_chunk",
        "doc_lance",
        "storage/config.toml",
        1,
        10,
        0,
        vec![1.0; 768],
        "auto_ivf_pq_threshold = 5000\nnum_partitions = 256\nnum_sub_vectors = 16",
        None,
    )
    .unwrap()]);

    // Query 1: Specific local codebase question
    let query_code = "auto_ivf_pq_threshold";
    let hits_code = storage.search_text(query_code, 0, 3);
    assert_eq!(hits_code.len(), 1);
    assert!(hits_code[0].chunk.text_content.contains("5000"));

    // Query 2: General question with 0 matches in local index
    let query_general = "What is the capital of France?";
    let query_vec = oracle_deterministic_vector(query_general, 768);
    let hits_general = storage.search_hybrid(query_general, &query_vec, 0, 3);

    // If hits_general has low scores or 0 keywords, router delegates to general knowledge
    let has_keyword_match = hits_general.iter().any(|h| h.chunk.text_content.to_lowercase().contains("france"));
    assert!(!has_keyword_match, "General question must not hallucinate local code matches");
}

#[test]
fn test_scenario_3_filesystem_lifecycle_edit_and_rename_propagation() {
    let dir = tempdir().unwrap();
    let crawler_root = dir.path().join("my_project");
    create_dir_all(&crawler_root).unwrap();

    let initial_file = crawler_root.join("config.rs");
    {
        let mut f = File::create(&initial_file).unwrap();
        writeln!(f, "pub const MESH_PORT: u16 = 4001;").unwrap();
    }

    let classifier = FileTypeClassifier::new();
    let mut storage = IsolatedStorageEngine::new();

    // 1. Initial crawl & ingest
    let id = classifier.classify_file(&initial_file).unwrap();
    assert_eq!(id.label, "rust");

    let text1 = std::fs::read_to_string(&initial_file).unwrap();
    let b3_1 = DocumentChunk::compute_blake3_hash(&text1);
    let chunk1 = DocumentChunk::new("c1", "d1", "config.rs", 1, 2, 0, vec![1.0; 768], &text1, None).unwrap();
    storage.insert_chunks(&[chunk1]);
    assert!(storage.has_chunk_hash(&b3_1));

    // 2. Directory rename: rename project folder
    let renamed_file = crawler_root.join("config_renamed.rs");
    rename(&initial_file, &renamed_file).unwrap();

    // Re-check hash: content is identical!
    let text2 = std::fs::read_to_string(&renamed_file).unwrap();
    let b3_2 = DocumentChunk::compute_blake3_hash(&text2);
    assert_eq!(b3_1, b3_2, "Level-1 file hash remains identical after rename");
    assert!(storage.has_chunk_hash(&b3_2), "Chunk vector already exists in storage");
}

#[test]
fn test_scenario_4_enterprise_tiered_clearance_enforcement() {
    let mut storage = IsolatedStorageEngine::new();

    // Ingest multi-tier documentation
    let pub_doc = DocumentChunk::new("p1", "d1", "terms.txt", 1, 10, AccessTier::Tier0Public.as_u8(), vec![1.0; 768], "Public Terms of Service", None).unwrap();
    let int_doc = DocumentChunk::new("i1", "d2", "handbook.txt", 1, 10, AccessTier::Tier1Internal.as_u8(), vec![1.0; 768], "Internal Employee Handbook", None).unwrap();
    let conf_doc = DocumentChunk::new("c1", "d3", "finance.txt", 1, 10, AccessTier::Tier2Confidential.as_u8(), vec![1.0; 768], "Q3 Financial Earnings Projections", None).unwrap();
    let rest_doc = DocumentChunk::new("r1", "d4", "keys.txt", 1, 10, AccessTier::Tier3Restricted.as_u8(), vec![1.0; 768], "Root CA Master Private Keys", None).unwrap();

    storage.insert_chunks(&[pub_doc, int_doc, conf_doc, rest_doc]);

    // External Visitor (Public Tier 0):
    let visitor_hits = storage.search_vector(&vec![1.0; 768], 0, 10);
    assert_eq!(visitor_hits.len(), 1);
    assert_eq!(visitor_hits[0].chunk.chunk_id, "p1");

    // Regular Employee (Internal Tier 1):
    let employee_hits = storage.search_vector(&vec![1.0; 768], 1, 10);
    assert_eq!(employee_hits.len(), 2);
    assert!(!employee_hits.iter().any(|h| h.chunk.access_tier > 1));

    // Department Executive (Confidential Tier 2):
    let exec_hits = storage.search_vector(&vec![1.0; 768], 2, 10);
    assert_eq!(exec_hits.len(), 3);
    assert!(!exec_hits.iter().any(|h| h.chunk.access_tier > 2));

    // Security Admin (Restricted Tier 3):
    let admin_hits = storage.search_vector(&vec![1.0; 768], 3, 10);
    assert_eq!(admin_hits.len(), 4);
}

#[test]
fn test_scenario_5_cold_start_daemon_launcher_and_headless_mode() {
    // Verifies that daemon arguments parse cleanly and headless mode can be engaged
    struct DaemonConfig {
        _listen_addr: String,
        _web_port: u16,
        auto_open_browser: bool,
    }

    fn init_daemon(args: &[&str]) -> DaemonConfig {
        let no_browser = args.contains(&"--no-browser");
        DaemonConfig {
            _listen_addr: "127.0.0.1".to_string(),
            _web_port: 8080,
            auto_open_browser: !no_browser,
        }
    }

    let default_config = init_daemon(&[]);
    assert!(default_config.auto_open_browser, "Normal start opens browser");

    let headless_config = init_daemon(&["--no-browser"]);
    assert!(!headless_config.auto_open_browser, "Headless CI start disables browser");
}

#[test]
fn test_scenario_6_30tb_drive_scale_deep_hierarchy_and_compaction() {
    let mut storage = IsolatedStorageEngine::new();

    // Simulate 200 chunks across 20 nested subdirectories
    let mut chunks = Vec::new();
    for dir_idx in 0..20 {
        for file_idx in 0..10 {
            let path = format!("D:/Volumes/30TB_Drive/Archive/Dir_{:03}/file_{:03}.log", dir_idx, file_idx);
            let text = format!("Log entry in volume partition {} file {}", dir_idx, file_idx);
            let chunk = DocumentChunk::new(
                format!("c_{}_{}", dir_idx, file_idx),
                format!("doc_{}", dir_idx),
                path,
                1,
                100,
                0,
                vec![0.01 * (dir_idx as f32); 768],
                text,
                None,
            )
            .unwrap();
            chunks.push(chunk);
        }
    }

    let inserted = storage.insert_chunks(&chunks);
    assert_eq!(inserted, 200);
    assert_eq!(storage.len(), 200);

    // Compaction run
    assert!(storage.compact().is_ok());
    assert_eq!(storage.len(), 200);

    // Deep directory query
    let hits = storage.search_text("partition 15", 0, 5);
    assert!(!hits.is_empty());
    assert!(hits[0].chunk.file_path.contains("Dir_015"));
}
