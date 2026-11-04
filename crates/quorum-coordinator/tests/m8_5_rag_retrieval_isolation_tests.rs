//! Acceptance test suite for Milestone M8.5: RAG Retrieval Isolation (Feature 57).
//!
//! Validates:
//! 1. `test_m8_5_rag_retrieval_isolation_never_returns_code_or_temp_chunks`
//!    Verifies that RAG retrieval strictly isolates documents and images from source code
//!    and temporary/lock files across query execution and synthesis citation generation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use quorum_coordinator::agentic::retrieve::RetrieveMeshNode;
use quorum_coordinator::types::AgenticGraphState;
use quorum_coordinator::{
    AgenticStateGraphRunner, CoordinatorConfig, LocalOnlyDispatcher, PeerAclManager,
    ScatterGatherEngine, StorageSearcher, SynthesisModelFamily,
};
use quorum_types::{DocumentChunk, ScoredChunk};

/// Mock storage searcher returning realistic mixed candidate chunks.
struct MockMixedStorage {
    epoch: AtomicU64,
    chunks: Vec<DocumentChunk>,
}

impl MockMixedStorage {
    fn new(chunks: Vec<DocumentChunk>) -> Self {
        Self {
            epoch: AtomicU64::new(1),
            chunks,
        }
    }
}

#[async_trait::async_trait]
impl StorageSearcher for MockMixedStorage {
    async fn search_hybrid(
        &self,
        query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let q_lower = query_text.to_lowercase();
        let words: Vec<&str> = q_lower
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|w| w.len() >= 3)
            .collect();

        let mut results: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| {
                if c.access_tier > max_tier {
                    return false;
                }
                if words.is_empty() {
                    return true;
                }
                let c_lower = c.text_content.to_lowercase();
                words.iter().any(|&w| c_lower.contains(w))
            })
            .map(|c| ScoredChunk::new(c.clone(), 0.95, "mock_peer", false))
            .collect();
        results.truncate(top_k);
        results
    }

    fn index_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
}

#[tokio::test]
async fn test_m8_5_rag_retrieval_isolation_never_returns_code_or_temp_chunks() {
    // 1. Create a corpus of mixed candidate chunks:
    // - Legitimate document (PDF)
    // - Legitimate image representation (PNG)
    // - Source code file (Rust)
    // - Source code script (Python)
    // - Office temporary lock file (~$*.docx)
    // - Office autosave file (~*.tmp)
    // - Editor backup file (*.bak)
    let chunks = vec![
        DocumentChunk::new(
            "chunk_doc_01",
            "doc_policy",
            "corporate_policy.pdf",
            1,
            25,
            0,
            vec![0.5; 768],
            "The corporate policy coverage provides comprehensive protection against liability, property damage, and data breach incidents.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "chunk_img_01",
            "img_arch",
            "policy_architecture_diagram.png",
            1,
            1,
            0,
            vec![0.5; 768],
            "[Image document: policy_architecture_diagram.png, 1920x1080] Visual map of policy coverage tiers, containment rings, and verification checkpoints.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "chunk_code_rs",
            "code_rs",
            "policy_verifier.rs",
            1,
            40,
            0,
            vec![0.5; 768],
            "// Rust source code implementation for policy verifier\npub fn verify_policy_coverage(limit: u64) -> bool { println!(\"checking policy coverage limit: {}\", limit); limit > 0 }",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "chunk_code_py",
            "code_py",
            "audit_policy.py",
            1,
            30,
            0,
            vec![0.5; 768],
            "def calculate_policy_coverage_risk(score: float):\n    \"\"\"Calculates policy coverage risk.\"\"\"\n    return score * 1.5",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "chunk_lock_docx",
            "lock_docx",
            "~$corporate_policy.docx",
            1,
            2,
            0,
            vec![0.5; 768],
            "Temporary Word lock file buffer for corporate policy coverage document by user admin.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "chunk_temp_wrl",
            "temp_wrl",
            "~WRL0003.tmp",
            1,
            5,
            0,
            vec![0.5; 768],
            "Autosave temporary recovery fragment for policy coverage analysis.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "chunk_backup_bak",
            "backup_bak",
            "policy_draft.bak",
            1,
            10,
            0,
            vec![0.5; 768],
            "Backup snapshot of previous policy coverage terms and indemnity clauses.",
            None,
        ).unwrap(),
    ];

    let mock_storage = Arc::new(MockMixedStorage::new(chunks));
    let engine = ScatterGatherEngine::new(
        mock_storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(), // exclude_source_code: true
        [0x42; 32],
        "test_isolation_node".to_string(),
    );

    // 2. Direct Node Verification: RetrieveMeshNode isolation under non-code prompt
    let prompt = "what is the policy coverage?";
    let mut state = AgenticGraphState::new(prompt, SynthesisModelFamily::AutoFusion, 3);
    let vector = vec![0.5f32; 768];

    RetrieveMeshNode::execute(&mut state, &engine, &vector, 0, 10).await;

    // Verify candidate chunks in state
    assert!(!state.retrieved_chunks.is_empty(), "Must retrieve matching document chunks");
    for scored in &state.retrieved_chunks {
        let file = &scored.chunk.file_path;
        assert!(
            !file.ends_with(".rs") && !file.ends_with(".py"),
            "Source code chunk '{}' must be excluded from retrieval",
            file
        );
        assert!(
            !file.starts_with('~') && !file.starts_with(".~lock"),
            "Office temp/lock chunk '{}' must be excluded from retrieval",
            file
        );
        assert!(
            !file.ends_with(".tmp") && !file.ends_with(".bak"),
            "Temporary file chunk '{}' must be excluded from retrieval",
            file
        );
    }

    // Verify that the legitimate document was retained
    let has_policy_pdf = state
        .retrieved_chunks
        .iter()
        .any(|c| c.chunk.file_path == "corporate_policy.pdf");
    assert!(has_policy_pdf, "corporate_policy.pdf must be retained in retrieval results");

    // 3. Full State Graph End-to-End Verification: Run AgenticStateGraphRunner
    let runner = AgenticStateGraphRunner::new(3, 0.75);
    let (tx, _rx) = tokio::sync::mpsc::channel(50);

    let result = runner
        .run(
            prompt,
            SynthesisModelFamily::AutoFusion,
            &engine,
            &vector,
            0,
            10,
            Some(tx),
        )
        .await;

    assert!(result.is_ok(), "Agentic runner must complete successfully");
    let finished_state = result.unwrap();

    // Verify synthesized response and citations
    assert!(finished_state.synthesized_response.is_some(), "Must produce synthesized response");
    assert!(!finished_state.citations.is_empty(), "Must produce citations");

    for citation in &finished_state.citations {
        let file = &citation.file_path;
        assert!(
            !file.ends_with(".rs") && !file.ends_with(".py"),
            "Citation '{}' must not reference source code",
            file
        );
        assert!(
            !file.starts_with('~'),
            "Citation '{}' must not reference temporary office lock files",
            file
        );
        assert!(
            !file.ends_with(".tmp") && !file.ends_with(".bak"),
            "Citation '{}' must not reference temp/bak files",
            file
        );
    }

    // Verify citation references legitimate corporate policy document
    assert!(
        finished_state.citations.iter().any(|c| c.file_path == "corporate_policy.pdf"),
        "Citations must reference corporate_policy.pdf"
    );

    // 4. Contrast Verification: When query explicitly requests code, code is not excluded
    let code_prompt = "show code for policy verifier";
    let mut code_state = AgenticGraphState::new(code_prompt, SynthesisModelFamily::AutoFusion, 3);
    RetrieveMeshNode::execute(&mut code_state, &engine, &vector, 0, 10).await;

    let has_code_chunk = code_state
        .retrieved_chunks
        .iter()
        .any(|c| c.chunk.file_path == "policy_verifier.rs");
    assert!(
        has_code_chunk,
        "When query explicitly requests code, policy_verifier.rs must be eligible for retrieval"
    );
}
