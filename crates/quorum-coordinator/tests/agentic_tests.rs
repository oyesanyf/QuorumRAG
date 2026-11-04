use quorum_coordinator::{
    AgenticStateGraphRunner, AgenticStateName, AgenticTelemetryEvent, AutoFusionRouter,
    CoordinatorConfig, HardwareTelemetry, LocalOnlyDispatcher, PeerAclManager,
    ScatterGatherEngine, StorageSearcher, SynthesisModelFamily,
};
use quorum_types::{DocumentChunk, ScoredChunk};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Default)]
struct DummyStorage;

#[async_trait::async_trait]
impl StorageSearcher for DummyStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        // Return a chunk with intentionally low score (0.2 < threshold 0.6) to force query rewrites
        vec![ScoredChunk::new(
            DocumentChunk::new(
                "low_chunk",
                "doc",
                "notes.txt",
                1,
                2,
                0,
                vec![0.0; 768],
                "Low relevance context",
                None,
            )
            .unwrap(),
            0.20,
            "local",
            false,
        )]
    }
}

#[test]
fn test_hardware_sizing_matrix() {
    // 1. Tier 1: Free RAM >= 48GB or Free VRAM >= 24GB -> 32b
    let hw1 = HardwareTelemetry {
        free_ram_gb: 50.0,
        free_vram_mb: 26_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw1), "qwen2.5:32b");

    // 2. Tier 2: Free RAM >= 24GB or Free VRAM >= 14GB -> 14b
    let hw2 = HardwareTelemetry {
        free_ram_gb: 25.0,
        free_vram_mb: 15_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw2), "qwen2.5:14b");

    // 3. Tier 3: Free RAM >= 12GB or Free VRAM >= 4.5GB -> 7b
    let hw3 = HardwareTelemetry {
        free_ram_gb: 14.0,
        free_vram_mb: 5_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw3), "qwen2.5:7b");

    // 4. Tier 4: Free RAM >= 6GB or Free VRAM >= 2GB -> 3b
    let hw4 = HardwareTelemetry {
        free_ram_gb: 8.0,
        free_vram_mb: 2_500,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw4), "qwen2.5:3b");

    // 5. Tier 5: Free RAM < 6GB -> 1.5b
    let hw5 = HardwareTelemetry {
        free_ram_gb: 4.0,
        free_vram_mb: 500,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw5), "qwen2.5:1.5b");

    // Invariant: Never append -coder
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw1).contains("-coder"));
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw5).contains("-coder"));
}

#[test]
fn test_autofusion_router_intent_and_ast_detection() {
    let hw = HardwareTelemetry {
        free_ram_gb: 16.0,
        free_vram_mb: 8_000,
        ..Default::default()
    };

    // 1. Code AST keywords in prompt -> Qwen25Code
    let (fam_code, tag_code, _) = AutoFusionRouter::select_model(
        SynthesisModelFamily::AutoFusion,
        "fn calculate_hash() in rust",
        &[],
        &hw,
    );
    assert_eq!(fam_code, SynthesisModelFamily::Qwen25Code);
    assert_eq!(tag_code, "qwen2.5:7b");

    // 2. Chunks dominated by code paths -> Qwen25Code
    let code_chunks = vec![
        ScoredChunk::new(
            DocumentChunk::new("c1", "d1", "swarm.rs", 1, 5, 0, vec![0.0; 768], "code", None).unwrap(),
            0.9,
            "local",
            false,
        ),
        ScoredChunk::new(
            DocumentChunk::new("c2", "d2", "router.py", 1, 5, 0, vec![0.0; 768], "code", None).unwrap(),
            0.9,
            "local",
            false,
        ),
    ];
    let (fam_chunks, _, _) = AutoFusionRouter::select_model(
        SynthesisModelFamily::AutoFusion,
        "explain architecture",
        &code_chunks,
        &hw,
    );
    assert_eq!(fam_chunks, SynthesisModelFamily::Qwen25Code);

    // 3. Heavy multi-document context (>16KB) -> Glm4Agentic (128K context)
    let heavy_content = "X".repeat(17_000);
    let heavy_chunks = vec![ScoredChunk::new(
        DocumentChunk::new("c3", "d3", "whitepaper.pdf", 1, 100, 0, vec![0.0; 768], heavy_content, None).unwrap(),
        0.9,
        "local",
        false,
    )];
    let (fam_heavy, tag_heavy, _) = AutoFusionRouter::select_model(
        SynthesisModelFamily::AutoFusion,
        "summarize findings",
        &heavy_chunks,
        &hw,
    );
    assert_eq!(fam_heavy, SynthesisModelFamily::Glm4Agentic);
    assert_eq!(tag_heavy, "glm4:9b");
}

#[test]
fn test_telemetry_event_serialization_and_sse_formatting() {
    let ev = AgenticTelemetryEvent::StateTransition {
        from_state: AgenticStateName::ClassifyIntent,
        to_state: AgenticStateName::RetrieveMesh,
        hop: 1,
        timestamp_ms: 125,
    };

    let sse_line = ev.to_sse_line();
    assert!(sse_line.starts_with("data: "));
    assert!(sse_line.ends_with("\n\n"));
    assert!(sse_line.contains("state_transition"));
    assert!(sse_line.contains("\"hop\":1"));

    let json_str = serde_json::to_string(&ev).unwrap();
    let deserialized: AgenticTelemetryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, ev);
}

#[tokio::test]
async fn test_agentic_loop_convergence_max_hops() {
    let runner = AgenticStateGraphRunner::new(3, 0.60);

    let engine = ScatterGatherEngine::new(
        Arc::new(DummyStorage),
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0u8; 32],
        "node_test".to_string(),
    );

    let (tx, mut rx) = mpsc::channel(64);

    let handle = tokio::spawn(async move {
        let mut transitions = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let AgenticTelemetryEvent::StateTransition { to_state, hop, .. } = ev {
                transitions.push((to_state, hop));
            }
        }
        transitions
    });

    let vector = vec![1.0; 768];
    let result = runner
        .run(
            "Adversarial query testing loop limit",
            SynthesisModelFamily::AutoFusion,
            &engine,
            &vector,
            0,
            5,
            Some(tx),
        )
        .await
        .expect("Graph must converge cleanly");

    assert_eq!(result.hop_count, 3, "Monotonically bounded loop must stop at exactly max_hops (3)");
    assert!(result.synthesized_response.is_some());

    let transitions = handle.await.unwrap();
    assert!(!transitions.is_empty());
}
