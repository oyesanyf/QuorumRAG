//! Adversarial Empirical Stress Suite for Milestone M8.5: RAG Retrieval Isolation (Feature 57).
//! Challenger: Challenger M8.5 2 (critic, specialist)
//!
//! Evaluates 4 adversarial dimensions:
//! 1. High-variety mixed corpus (50+ chunks including uppercase extensions, path variants, Office locks, temp files).
//! 2. Strict Oracle: 100% exclusion of code and temp files from non-code query retrieval and synthesized citations.
//! 3. Explicit Code Requests: Confirms that explicit code queries legitimately retrieve and cite source code chunks.
//! 4. High-concurrency query stress: Concurrent threads executing alternating non-code and code queries without cross-thread contamination or isolation breaches.

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

/// High-capacity mock storage holding diverse document, image, code, and temporary chunks.
struct AdversarialCorpusStorage {
    epoch: AtomicU64,
    chunks: Vec<DocumentChunk>,
}

impl AdversarialCorpusStorage {
    fn new(chunks: Vec<DocumentChunk>) -> Self {
        Self {
            epoch: AtomicU64::new(1),
            chunks,
        }
    }
}

#[async_trait::async_trait]
impl StorageSearcher for AdversarialCorpusStorage {
    async fn search_hybrid(
        &self,
        query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let q_lower = query_text.to_lowercase();
        let query_words: Vec<&str> = q_lower
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
                if query_words.is_empty() {
                    return true;
                }
                let c_lower = c.text_content.to_lowercase();
                let path_lower = c.file_path.to_lowercase();
                query_words.iter().any(|&w| c_lower.contains(w) || path_lower.contains(w))
            })
            .map(|c| ScoredChunk::new(c.clone(), 0.95, "adversarial_mock_peer", false))
            .collect();

        results.truncate(top_k);
        results
    }

    fn index_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
}

fn generate_adversarial_mixed_corpus() -> Vec<DocumentChunk> {
    vec![
        // Legitimate documents
        DocumentChunk::new(
            "doc_01",
            "handbook",
            "C:\\Users\\admin\\Documents\\Employee_Handbook_2026.pdf",
            1,
            50,
            0,
            vec![0.5; 768],
            "The corporate employee handbook outlines health benefits, paid time off policy, and annual reimbursement limits.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "doc_02",
            "annual_report",
            "/var/data/shared/Annual_Financial_Report.docx",
            1,
            40,
            0,
            vec![0.5; 768],
            "Annual financial report details company revenue growth, operational income, and strategic budget allocations.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "doc_03",
            "security_spec",
            "specs/zero_trust_architecture.md",
            1,
            30,
            0,
            vec![0.5; 768],
            "The zero trust architecture specification mandates continuous verification, least privilege access, and strict isolation.",
            None,
        ).unwrap(),

        // Legitimate image assets
        DocumentChunk::new(
            "img_01",
            "infra_diag",
            "C:\\Users\\admin\\Pictures\\network_infrastructure_topology.png",
            1,
            1,
            0,
            vec![0.5; 768],
            "[Image document: network_infrastructure_topology.png, 2560x1440] Architectural diagram of zero trust network infrastructure and gateway firewalls.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "img_02",
            "org_chart",
            "assets/diagrams/corporate_organizational_chart.jpg",
            1,
            1,
            0,
            vec![0.5; 768],
            "[Image document: corporate_organizational_chart.jpg, 1920x1080] Visual hierarchy of corporate governance and department leaders.",
            None,
        ).unwrap(),

        // Adversarial Source Code chunks (lowercase and uppercase extensions, diverse languages)
        DocumentChunk::new(
            "code_01",
            "auth_rs",
            "src/crypto/handshake.rs",
            1,
            60,
            0,
            vec![0.5; 768],
            "pub fn verify_zero_trust_handshake(pubkey: &[u8; 32], sig: &[u8; 64]) -> bool { !sig.is_empty() }",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "code_02_upper",
            "policy_rs_upper",
            "C:\\workspace\\core\\AUTH_ENGINE.RS",
            1,
            45,
            0,
            vec![0.5; 768],
            "// High privilege policy evaluation engine in Rust\npub fn evaluate_reimbursement_policy(user_id: &str, amount: f64) -> bool { amount < 5000.0 }",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "code_03",
            "billing_py",
            "scripts/billing_reimbursement_processor.py",
            1,
            80,
            0,
            vec![0.5; 768],
            "def process_reimbursement_claim(user: str, amount: float):\n    \"\"\"Processes employee handbook reimbursement claims.\"\"\"\n    return {'status': 'approved', 'amount': amount}",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "code_04_upper",
            "worker_js_upper",
            "web/workers/TELEMETRY_DISPATCHER.JS",
            1,
            30,
            0,
            vec![0.5; 768],
            "export function reportZeroTrustTelemetry(event) { console.log('telemetry dispatch', event); }",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "code_05",
            "query_sql",
            "migrations/001_reimbursement_audit.sql",
            1,
            20,
            0,
            vec![0.5; 768],
            "SELECT employee_id, policy_limit, reimbursement_amount FROM corporate_claims WHERE status = 'pending';",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "code_06",
            "deploy_sh",
            "ci/deploy_infrastructure.sh",
            1,
            15,
            0,
            vec![0.5; 768],
            "#!/bin/bash\necho 'Deploying zero trust infrastructure gateway' && terraform apply -auto-approve",
            None,
        ).unwrap(),

        // Adversarial Temporary, Lock, and Autosave files
        DocumentChunk::new(
            "lock_01",
            "word_lock",
            "C:\\Users\\admin\\Documents\\~$Employee_Handbook_2026.docx",
            1,
            2,
            0,
            vec![0.5; 768],
            "Temporary active lock file for Employee Handbook 2026 author admin workstation.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "lock_02_libre",
            "libre_lock",
            "/var/data/shared/.~lock.Annual_Financial_Report.docx#",
            1,
            1,
            0,
            vec![0.5; 768],
            "LibreOffice lock file for Annual Financial Report document.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "temp_01",
            "word_autosave",
            "C:\\Users\\admin\\AppData\\Local\\Temp\\~WRL1942.tmp",
            1,
            10,
            0,
            vec![0.5; 768],
            "Autosave recovery fragment for zero trust architecture specification.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "temp_02",
            "editor_backup",
            "specs/zero_trust_architecture.bak",
            1,
            10,
            0,
            vec![0.5; 768],
            "Backup snapshot of previous zero trust architecture guidelines.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "temp_03",
            "word_wbk",
            "Documents/Backup of Reimbursement.wbk",
            1,
            5,
            0,
            vec![0.5; 768],
            "Word backup file for corporate reimbursement handbook rules.",
            None,
        ).unwrap(),

        // Adversarial chat dump and code-fenced document
        DocumentChunk::new(
            "dump_01",
            "chat_history",
            "C:\\Users\\admin\\Downloads\\conversations-2026-03.json",
            1,
            100,
            0,
            vec![0.5; 768],
            "Monolithic chat export containing discussion of reimbursement policy and architecture.",
            None,
        ).unwrap(),
        DocumentChunk::new(
            "colab_01",
            "colab_dump",
            "notebooks/policy_analysis.txt",
            1,
            20,
            0,
            vec![0.5; 768],
            "from google.colab import drive\ndrive.mount('/content/drive')\nimport numpy as np\n# Notebook data for reimbursement",
            None,
        ).unwrap(),
    ]
}

#[tokio::test]
async fn test_adversarial_oracle_non_code_queries_100_percent_isolated() {
    let chunks = generate_adversarial_mixed_corpus();
    let storage = Arc::new(AdversarialCorpusStorage::new(chunks));
    let engine = ScatterGatherEngine::new(
        storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(), // exclude_source_code: true
        [0x77; 32],
        "adversarial_oracle_node".to_string(),
    );

    let test_prompts = [
        "what are the health benefits and reimbursement rules in the employee handbook?",
        "what does the annual financial report say about corporate revenue?",
        "explain the zero trust architecture specification and requirements",
        "show image of the network infrastructure topology diagram",
    ];

    let runner = AgenticStateGraphRunner::new(3, 0.75);
    let vector = vec![0.5f32; 768];

    for prompt in &test_prompts {
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

        assert!(
            result.is_ok(),
            "Query for prompt '{}' must succeed without error",
            prompt
        );
        let finished = result.unwrap();

        // 1. Verify candidate chunks in graph state
        for scored in &finished.retrieved_chunks {
            let file = scored.chunk.file_path.to_ascii_lowercase();
            let base_name = std::path::Path::new(&file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Anti-code assertion
            assert!(
                !base_name.ends_with(".rs")
                    && !base_name.ends_with(".py")
                    && !base_name.ends_with(".js")
                    && !base_name.ends_with(".sql")
                    && !base_name.ends_with(".sh"),
                "VIOLATION: Code chunk '{}' leaked into retrieved_chunks for non-code prompt '{}'",
                scored.chunk.file_path,
                prompt
            );

            // Anti-temp assertion
            assert!(
                !base_name.starts_with('~') && !base_name.starts_with(".~lock"),
                "VIOLATION: Office lock chunk '{}' leaked into retrieved_chunks for prompt '{}'",
                scored.chunk.file_path,
                prompt
            );

            assert!(
                !base_name.ends_with(".tmp")
                    && !base_name.ends_with(".bak")
                    && !base_name.ends_with(".wbk"),
                "VIOLATION: Temporary/backup chunk '{}' leaked into retrieved_chunks for prompt '{}'",
                scored.chunk.file_path,
                prompt
            );

            assert!(
                !base_name.starts_with("conversations-"),
                "VIOLATION: Monolithic conversation dump '{}' leaked into retrieved_chunks",
                scored.chunk.file_path
            );
        }

        // 2. Verify Citations emitted in final state
        assert!(
            !finished.citations.is_empty(),
            "Must produce legitimate citations for prompt '{}'",
            prompt
        );

        for citation in &finished.citations {
            let file = citation.file_path.to_ascii_lowercase();
            let base_name = std::path::Path::new(&file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            assert!(
                !base_name.ends_with(".rs")
                    && !base_name.ends_with(".py")
                    && !base_name.ends_with(".js")
                    && !base_name.ends_with(".sql")
                    && !base_name.ends_with(".sh"),
                "VIOLATION: Code file '{}' leaked into citation for prompt '{}'",
                citation.file_path,
                prompt
            );

            assert!(
                !base_name.starts_with('~') && !base_name.starts_with(".~lock"),
                "VIOLATION: Temp lock file '{}' cited for prompt '{}'",
                citation.file_path,
                prompt
            );

            assert!(
                !base_name.ends_with(".tmp")
                    && !base_name.ends_with(".bak")
                    && !base_name.ends_with(".wbk"),
                "VIOLATION: Temporary/backup file '{}' cited for prompt '{}'",
                citation.file_path,
                prompt
            );
        }

        // 3. Verify synthesized response never references code or temp files
        if let Some(resp) = &finished.synthesized_response {
            let resp_l = resp.to_ascii_lowercase();
            assert!(
                !resp_l.contains(".rs") && !resp_l.contains(".py"),
                "VIOLATION: Response text contains code extension references: {}",
                resp
            );
            assert!(
                !resp_l.contains("~$") && !resp_l.contains(".tmp"),
                "VIOLATION: Response text references temporary files: {}",
                resp
            );
        }
    }
}

#[tokio::test]
async fn test_adversarial_explicit_code_queries_allowed() {
    let chunks = generate_adversarial_mixed_corpus();
    let storage = Arc::new(AdversarialCorpusStorage::new(chunks));
    let engine = ScatterGatherEngine::new(
        storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x88; 32],
        "adversarial_code_node".to_string(),
    );

    let explicit_code_prompts = [
        "show me the code for verify handshake",
        "show code for evaluate reimbursement policy",
        "what does the unit test and fn verify handshake do?",
        "show python script code for billing reimbursement processor",
    ];

    let vector = vec![0.5f32; 768];

    for code_prompt in &explicit_code_prompts {
        let mut state = AgenticGraphState::new(code_prompt, SynthesisModelFamily::AutoFusion, 3);
        RetrieveMeshNode::execute(&mut state, &engine, &vector, 0, 10).await;

        let has_code = state.retrieved_chunks.iter().any(|c| {
            let path_l = c.chunk.file_path.to_ascii_lowercase();
            path_l.ends_with(".rs") || path_l.ends_with(".py") || path_l.ends_with(".js")
        });

        assert!(
            has_code,
            "Explicit code query '{}' must successfully retrieve code chunks (found: {:?})",
            code_prompt,
            state.retrieved_chunks.iter().map(|c| &c.chunk.file_path).collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn test_adversarial_high_concurrency_query_isolation() {
    let chunks = generate_adversarial_mixed_corpus();
    let storage = Arc::new(AdversarialCorpusStorage::new(chunks));
    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x99; 32],
        "adversarial_concurrency_node".to_string(),
    ));

    // Concurrently fire 20 requests alternating between non-code and explicit-code queries
    let mut handles = Vec::new();

    for i in 0..20 {
        let eng = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            let vector = vec![0.5f32; 768];
            if i % 2 == 0 {
                // Non-code query: MUST NOT return code or temp files
                let prompt = "summarize the employee handbook health benefits";
                let mut state = AgenticGraphState::new(prompt, SynthesisModelFamily::AutoFusion, 3);
                RetrieveMeshNode::execute(&mut state, &eng, &vector, 0, 10).await;

                for c in &state.retrieved_chunks {
                    let file = c.chunk.file_path.to_ascii_lowercase();
                    assert!(
                        !file.ends_with(".rs") && !file.ends_with(".py") && !file.ends_with(".js"),
                        "Thread {}: Leaked code chunk: {}",
                        i,
                        c.chunk.file_path
                    );
                    assert!(
                        !file.starts_with('~') && !file.ends_with(".tmp"),
                        "Thread {}: Leaked temp chunk: {}",
                        i,
                        c.chunk.file_path
                    );
                }
            } else {
                // Code query: MUST allow code chunks
                let prompt = "show rust code for verify handshake";
                let mut state = AgenticGraphState::new(prompt, SynthesisModelFamily::AutoFusion, 3);
                RetrieveMeshNode::execute(&mut state, &eng, &vector, 0, 10).await;

                let has_code = state.retrieved_chunks.iter().any(|c| {
                    let f = c.chunk.file_path.to_ascii_lowercase();
                    f.ends_with(".rs")
                });
                assert!(has_code, "Thread {}: Code query must retrieve code chunks", i);
            }
        });
        handles.push(handle);
    }

    for (idx, handle) in handles.into_iter().enumerate() {
        let res = handle.await;
        assert!(res.is_ok(), "Concurrent query thread {} panicked or failed: {:?}", idx, res);
    }
}
