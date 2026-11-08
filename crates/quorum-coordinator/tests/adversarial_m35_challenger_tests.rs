//! Adversarial Empirical Stress-Test Harness for Milestone M35:
//! 1. `VaultGemmaPolicyEngine`: Quasi-identifier scrubbing, multi-byte UTF-8 boundary safety, DP epsilon estimation, and abstractive takeaway synthesis.
//! 2. `MarketplaceSanitizer`: Three-Engine Airlock enforcement, trade secret rejection, token volume thresholding, and verbatim citation grounding.
//! 3. `DatasetBuilder`: Parent window byte clamping (0..10,000 bytes) with multi-byte UTF-8 safety, and anchor probe extraction.
//! 4. `BountyRunner`: Jurisdiction filtering, active bounty gating, and candidate airlock batch processing.

use ed25519_dalek::SigningKey;
use quorum_contract::{DataBountySpec, SanitizedRlmStep, TrainingRecordFormat};
use quorum_coordinator::bounty_runner::BountyRunner;
use quorum_coordinator::marketplace_engine::{
    DeidPolicyError, MarketplaceSanitizer, RawTrajectoryCandidate, VaultGemmaDeidPolicy,
    VaultGemmaDeidPolicyEngine, VaultGemmaPolicyEngine,
};
use quorum_storage::{DatasetBuilder, DatasetBuilderConfig, RawDatasetCandidate};
use quorum_types::DocumentChunk;

#[test]
fn test_vaultgemma_quasi_identifier_scrubbing_stress_and_utf8_boundaries() {
    let engine = VaultGemmaPolicyEngine::default();
    let policy = VaultGemmaDeidPolicy::default();

    // 1. Multi-byte UTF-8 characters (emojis, accents, Cyrillic) adjacent to quasi-identifiers
    let text_with_utf8 = "Пациент: Age: 45 — Español 🚀 \u{1F600} | Gender: Non-Binary 🌟 | Ethnicity: Afro-Latino 🩺 | Discharge Location: Suite #402-B, St. Jude's Hospital.";
    let res = engine.redact_and_verify(text_with_utf8, &policy).unwrap();

    // Verify quasi-identifiers are scrubbed
    assert!(!res.scrubbed_text.contains("Age: 45"));
    assert!(!res.scrubbed_text.contains("Gender: Non-Binary"));
    assert!(!res.scrubbed_text.contains("Ethnicity: Afro-Latino"));
    assert!(!res.scrubbed_text.contains("Discharge Location: Suite #402-B"));
    assert!(res.scrubbed_text.contains("[REDACTED:VAULTGEMMA_QUASI_ID]"));

    // Verify multi-byte UTF-8 surrounding content survived cleanly
    assert!(res.scrubbed_text.contains("Пациент:"));
    assert!(res.scrubbed_text.contains("Español"));
    assert!(res.scrubbed_text.contains("🚀"));
    assert!(res.scrubbed_text.contains("🌟"));
    assert!(res.scrubbed_text.contains("🩺"));

    // 2. DP Epsilon calculation check
    assert_eq!(res.detected_spans.len(), 4);
    let expected_epsilon = policy.epsilon * (1.0 + (4.0 * 0.05));
    assert!((res.dp_epsilon_estimate - expected_epsilon).abs() < 1e-6);

    // 3. Monotonic scaling of DP epsilon with matches count
    let single_qi = "Patient details: Age: 30.";
    let res_single = engine.redact_and_verify(single_qi, &policy).unwrap();
    assert_eq!(res_single.detected_spans.len(), 1);
    assert!(res.dp_epsilon_estimate > res_single.dp_epsilon_estimate);
    assert!(res_single.dp_epsilon_estimate > policy.epsilon);

    // 4. Zero matches check
    let clean_text = "QuorumRAG decentralized vector search and Merkle integrity verification.";
    let res_clean = engine.redact_and_verify(clean_text, &policy).unwrap();
    assert!(res_clean.detected_spans.is_empty());
    assert!((res_clean.dp_epsilon_estimate - policy.epsilon).abs() < 1e-6);
    assert_eq!(res_clean.scrubbed_text, clean_text);

    // 5. Empty string check
    let res_empty = engine.redact_and_verify("", &policy).unwrap();
    assert!(res_empty.is_clean);
    assert_eq!(res_empty.dp_epsilon_estimate, 0.0);
    assert!(res_empty.scrubbed_text.is_empty());

    // 6. Policy disablement check
    let disabled_policy = VaultGemmaDeidPolicy {
        scrub_quasi_identifiers: false,
        ..Default::default()
    };
    let res_disabled = engine
        .redact_and_verify(text_with_utf8, &disabled_policy)
        .unwrap();
    assert!(res_disabled.detected_spans.is_empty());
    assert_eq!(res_disabled.scrubbed_text, text_with_utf8);
}

#[test]
fn test_vaultgemma_takeaway_synthesis_adversarial_paths_and_code() {
    let engine = VaultGemmaPolicyEngine::default();

    // Adversarial input containing fenced code, syntactic code, Windows paths, POSIX paths, and multi-byte UTF-8
    let raw_obs = concat!(
        "```rust\n",
        "pub async fn dump_kernel_secrets() -> Vec<u8> {\n",
        "    let key = 0xdeadbeef;\n",
        "    vec![1, 2, 3]\n",
        "}\n",
        "```\n",
        "let mut internal_config = load_private_keys();\n",
        "Found target file at C:\\Users\\Administrator\\AppData\\Local\\secret.dat with patient data.\n",
        "Also inspected /home/developer/.ssh/id_ed25519 and /var/log/audit.log.\n",
        "Verified parent-document window expansion for medical research with international symbols 🌐 🩺."
    );

    let takeaway = engine
        .synthesize_abstracted_takeaway("investigate memory", raw_obs)
        .unwrap();

    // Code blocks must be completely stripped
    assert!(!takeaway.contains("dump_kernel_secrets"));
    assert!(!takeaway.contains("let mut internal_config"));

    // Paths must be stripped or redacted
    assert!(!takeaway.contains("C:\\Users\\Administrator"));
    assert!(!takeaway.contains("/home/developer"));
    assert!(!takeaway.contains("/var/log/audit.log"));

    // Valid observation content is preserved
    assert!(takeaway.contains("Verified parent-document window expansion"));
    assert!(takeaway.contains("Verified multi-step evidence"));

    // Truncation safety: Long observation with multi-byte UTF-8 at truncation boundary
    let long_obs = format!("Evidence: {}", "🦀".repeat(300));
    let long_takeaway = engine
        .synthesize_abstracted_takeaway("check emoji boundary", &long_obs)
        .unwrap();
    assert!(long_takeaway.ends_with("..."));
    assert!(long_takeaway.is_char_boundary(long_takeaway.len()));

    // Empty raw observation fallback
    let empty_takeaway = engine
        .synthesize_abstracted_takeaway("verify cluster health", "")
        .unwrap();
    assert_eq!(
        empty_takeaway,
        "Abstracted verification for query 'verify cluster health'"
    );
}

#[test]
fn test_vaultgemma_rlm_step_adversarial_rejections() {
    let engine = VaultGemmaPolicyEngine::default();

    // 1. RLM step with RFC1918 private IPv4 in query -> rejected
    let step_bad_query = SanitizedRlmStep {
        step_index: 1,
        action_kind: "search".to_string(),
        sanitized_query_or_pattern:
            "query for internal endpoint at 10.200.15.42 on private subnet".to_string(),
        abstracted_takeaway: "Clean observation text without secrets.".to_string(),
    };
    let err = engine
        .sanitize_rlm_step_with_vaultgemma(&step_bad_query, &[])
        .unwrap_err();
    match err {
        DeidPolicyError::TradeSecretPolicyViolation(reason) => {
            assert!(reason.contains("RFC1918"));
        }
        other => panic!("Expected TradeSecretPolicyViolation, got {:?}", other),
    }

    // 1b. RLM step with PEM private key in query -> scrubbed by Three-Engine DLP to [REDACTED:CROWN_JEWEL_SECRET]
    let step_pem_query = SanitizedRlmStep {
        step_index: 1,
        action_kind: "search".to_string(),
        sanitized_query_or_pattern:
            "query for -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC...".to_string(),
        abstracted_takeaway: "Clean observation text without secrets.".to_string(),
    };
    let scrubbed_step = engine
        .sanitize_rlm_step_with_vaultgemma(&step_pem_query, &[])
        .unwrap();
    assert!(scrubbed_step
        .sanitized_query_or_pattern
        .contains("[REDACTED:CROWN_JEWEL_SECRET]"));
    assert!(!scrubbed_step
        .sanitized_query_or_pattern
        .contains("BEGIN OPENSSH PRIVATE KEY"));

    // 2. RLM step with RFC1918 private IPv4 in takeaway -> rejected
    let step_rfc1918 = SanitizedRlmStep {
        step_index: 2,
        action_kind: "peek_slice".to_string(),
        sanitized_query_or_pattern: "inspect peer endpoint".to_string(),
        abstracted_takeaway:
            "Found internal service running on 192.168.1.100 port 8080.".to_string(),
    };
    let err = engine
        .sanitize_rlm_step_with_vaultgemma(&step_rfc1918, &[])
        .unwrap_err();
    match err {
        DeidPolicyError::TradeSecretPolicyViolation(reason) => {
            assert!(reason.contains("RFC1918"));
        }
        other => panic!("Expected TradeSecretPolicyViolation, got {:?}", other),
    }

    // 3. RLM step with IPv6 ULA (fc00::/7) in takeaway -> rejected
    let step_ula = SanitizedRlmStep {
        step_index: 3,
        action_kind: "peek_slice".to_string(),
        sanitized_query_or_pattern: "inspect ipv6 mesh node".to_string(),
        abstracted_takeaway: "Node bound to internal IPv6 address fd00:cafe:beef::1.".to_string(),
    };
    let err = engine
        .sanitize_rlm_step_with_vaultgemma(&step_ula, &[])
        .unwrap_err();
    match err {
        DeidPolicyError::TradeSecretPolicyViolation(reason) => {
            assert!(reason.contains("Unique Local Address"));
        }
        other => panic!("Expected TradeSecretPolicyViolation, got {:?}", other),
    }

    // 4. RLM step with proprietary code >15 lines -> rejected
    let code_18_lines = (0..18)
        .map(|i| format!("pub fn kernel_logic_{}() {{ let z = {}; }}", i, i))
        .collect::<Vec<_>>()
        .join("\n");
    let step_code = SanitizedRlmStep {
        step_index: 4,
        action_kind: "synthesize".to_string(),
        sanitized_query_or_pattern: "extract algorithm".to_string(),
        abstracted_takeaway: code_18_lines,
    };
    let err = engine
        .sanitize_rlm_step_with_vaultgemma(&step_code, &[])
        .unwrap_err();
    match err {
        DeidPolicyError::TradeSecretPolicyViolation(reason) => {
            assert!(reason.contains("proprietary source code"));
        }
        other => panic!("Expected TradeSecretPolicyViolation, got {:?}", other),
    }

    // 5. RLM step with quasi-identifier -> scrubbed and approved
    let step_qi = SanitizedRlmStep {
        step_index: 5,
        action_kind: "summarize".to_string(),
        sanitized_query_or_pattern: "summarize clinical record".to_string(),
        abstracted_takeaway: "Patient intake: Age: 62, Gender: Male. Condition is stable."
            .to_string(),
    };
    let clean_step = engine
        .sanitize_rlm_step_with_vaultgemma(&step_qi, &[])
        .unwrap();
    assert!(!clean_step.abstracted_takeaway.contains("Age: 62"));
    assert!(!clean_step.abstracted_takeaway.contains("Gender: Male"));
    assert!(clean_step
        .abstracted_takeaway
        .contains("[REDACTED:VAULTGEMMA_QUASI_ID]"));
    assert!(clean_step.abstracted_takeaway.contains("Condition is stable"));
}

#[test]
fn test_marketplace_sanitizer_end_to_end_airlock_invariants() {
    let node_seed = [0x55u8; 32];
    let slice_text = "QuorumRAG implements three-engine airlock de-identification uniting Presidio, GLiNER, and VaultGemma-1B for sovereign AI training data export without leaking private records.";
    let verbatim_quote = "three-engine airlock de-identification uniting Presidio, GLiNER, and VaultGemma-1B";

    let base_cand = RawTrajectoryCandidate {
        record_id: "rec-airlock-01".to_string(),
        origin_node_id: "12D3KooWTestOrigin".to_string(),
        format: TrainingRecordFormat::SftTrajectory,
        domain_tags: vec!["sovereign-ai".to_string()],
        prompt: "Explain in detail how QuorumRAG de-identifies training datasets across peer networks and enforces differential privacy guarantees:".to_string(),
        rlm_trajectory: vec![SanitizedRlmStep {
            step_index: 1,
            action_kind: "peek_slice".to_string(),
            sanitized_query_or_pattern: "inspect document window 0..10000".to_string(),
            abstracted_takeaway: "Verified three-engine airlock scrubbing.".to_string(),
        }],
        chosen_response: format!(
            "{} This architecture guarantees mathematical differential privacy bounds, scrubs all quasi-identifiers, and requires 100% verbatim citation substring grounding before signing. Furthermore, all candidate trajectories are vetted for semantic trade-secret compliance, ensuring no private network IPs, proprietary source code exceeding fifteen lines, or cryptographic credentials escape into training sets.",
            slice_text
        ),
        rejected_response: None,
        citations: vec![(slice_text.to_string(), verbatim_quote.to_string())],
        extra_redact_terms: Vec::new(),
        created_unix_secs: 1_760_000_000,
    };

    // 1. Clean candidate passes and produces valid Ed25519 signature
    let approved =
        MarketplaceSanitizer::sanitize_and_sign_record(&base_cand, &node_seed).unwrap();
    assert_eq!(approved.grounding_score_bps, 10_000);
    assert!(approved.pii_scrub_verified);
    assert!(approved.trade_secret_clean);
    assert!(approved.token_count >= 64);
    assert!(!approved.ed25519_signature_hex.is_empty());
    assert!(!approved.blake3_record_hash.is_empty());

    let signing_key = SigningKey::from_bytes(&node_seed);
    assert!(approved.verify_ed25519(&signing_key.verifying_key().to_bytes()));

    // 2. Candidate with 0 citations -> rejected
    let mut cand_no_citations = base_cand.clone();
    cand_no_citations.citations.clear();
    let err = MarketplaceSanitizer::sanitize_and_sign_record(&cand_no_citations, &node_seed)
        .unwrap_err();
    assert!(err.contains("Quality Gate"));

    // 3. Candidate with ungrounded citation -> rejected
    let mut cand_ungrounded = base_cand.clone();
    cand_ungrounded.citations = vec![(
        slice_text.to_string(),
        "THIS STRING DOES NOT EXIST IN SLICE".to_string(),
    )];
    let err =
        MarketplaceSanitizer::sanitize_and_sign_record(&cand_ungrounded, &node_seed).unwrap_err();
    assert!(err.contains("citation grounding score"));

    // 4. Candidate with token count < 64 -> rejected
    let mut cand_short = base_cand.clone();
    cand_short.prompt = "Short prompt:".to_string();
    cand_short.chosen_response = "Short answer.".to_string();
    cand_short.rlm_trajectory.clear();
    cand_short.citations = vec![("Short answer.".to_string(), "Short answer.".to_string())];
    let err =
        MarketplaceSanitizer::sanitize_and_sign_record(&cand_short, &node_seed).unwrap_err();
    assert!(err.contains("minimum required is 64 tokens"));

    // 5. Candidate with high-entropy AWS secret in prompt -> rejected by trade secret filter
    let mut cand_secret = base_cand.clone();
    cand_secret.prompt = "Access key AKIAIOSFODNN7EXAMPLE used for deployment.".to_string();
    let err =
        MarketplaceSanitizer::sanitize_and_sign_record(&cand_secret, &node_seed).unwrap_err();
    assert!(err.contains("Semantic Trade-Secret Filter"));
}

#[test]
fn test_dataset_builder_byte_clamping_and_utf8_char_boundary() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("multibyte_source.txt");

    // Construct text where byte 48..56 contains multi-byte UTF-8 emojis (4 bytes each: 🦀 is 4 bytes)
    // "ASCII Prefix 0123456789ABCDEF0123456789ABCDEF0123456" = 49 bytes.
    let prefix = "ASCII Prefix 0123456789ABCDEF0123456789ABCDEF0123"; // exactly 49 bytes
    let emoji = "🦀"; // 4 bytes (F0 9F A6 80)
    let suffix = " Postfix text for testing window expansion.";
    let full_content = format!("{}{}{}", prefix, emoji, suffix);
    std::fs::write(&file_path, &full_content).unwrap();

    let chunk = DocumentChunk::new(
        "doc-utf8:0",
        "doc-utf8",
        file_path.to_str().unwrap(),
        1,
        10,
        0,
        vec![0.0; 768],
        &full_content,
        None,
    )
    .unwrap();

    // Clamp at 50 bytes: exactly inside the 4-byte emoji (which spans 49..53)!
    // A naive slice `content[..50]` would PANIC with "byte index 50 is not a char boundary".
    let clamped_50 = DatasetBuilder::extract_parent_window(&chunk, 50);
    assert_eq!(clamped_50, prefix); // Backed up safely to byte 49!
    assert!(clamped_50.is_char_boundary(clamped_50.len()));

    // Clamp at 53 bytes: exactly after the 4-byte emoji!
    let clamped_53 = DatasetBuilder::extract_parent_window(&chunk, 53);
    assert_eq!(clamped_53, format!("{}{}", prefix, emoji));

    // Non-existent file fallback to chunk text
    let missing_chunk = DocumentChunk::new(
        "doc-missing:0",
        "doc-missing",
        "C:\\nonexistent\\missing_path_12345.txt",
        1,
        10,
        0,
        vec![0.0; 768],
        &full_content,
        None,
    )
    .unwrap();
    let fallback = DatasetBuilder::extract_parent_window(&missing_chunk, 50);
    assert_eq!(fallback, prefix);

    // Test candidate harvesting from chunks
    let text = "QuorumRAG implements decentralized peer verification using Ed25519 signatures, BLAKE3 Merkle integrity proofs, and Reciprocal Rank Fusion ranking. Federated nodes exchange encrypted candidate trajectories and verify strict compliance with local DLP policies.";
    let valid_chunk = DocumentChunk::new(
        "doc-harvest:0",
        "doc-harvest",
        file_path.to_str().unwrap(),
        1,
        25,
        0,
        vec![0.0; 768],
        text,
        None,
    )
    .unwrap();

    let config = DatasetBuilderConfig {
        domain_tags: vec!["p2p".to_string()],
        max_records: 5,
        parent_window_bytes: 10_000,
        min_token_count: 32,
    };

    let candidates =
        DatasetBuilder::build_candidates_from_chunks(&[valid_chunk], &config).unwrap();
    assert_eq!(candidates.len(), 1);
    let cand = &candidates[0];
    assert_eq!(cand.record_id, "rec-store-doc-harvest-0");
    assert_eq!(cand.source_doc_id, "doc-harvest");
    assert_eq!(cand.domain_tags, vec!["p2p"]);
    assert_eq!(cand.citations.len(), 1);
    let (slice, quote) = &cand.citations[0];
    assert!(slice.contains(quote));
}

#[test]
fn test_bounty_runner_adversarial_jurisdiction_and_airlock() {
    let runner = BountyRunner::default_us_sovereign([0x88u8; 32], "12D3KooWNode88".to_string());

    let bounties = vec![
        // 1. Eligible US bounty
        DataBountySpec {
            bounty_id: "bounty-us-active".to_string(),
            sponsor_entity_name: "US AI Lab".to_string(),
            sponsor_buyer_id: "buyer-us-1".to_string(),
            title: "US Active SFT".to_string(),
            required_domain_tags: vec!["sovereign-rag".to_string()],
            required_format: TrainingRecordFormat::SftTrajectory,
            payout_per_record_cents: 500,
            max_records: 2,
            accepted_records: 0,
            jurisdiction_iso: "us".to_string(), // case-insensitive check
            active: true,
        },
        // 2. Inactive US bounty
        DataBountySpec {
            bounty_id: "bounty-us-inactive".to_string(),
            sponsor_entity_name: "US AI Lab".to_string(),
            sponsor_buyer_id: "buyer-us-1".to_string(),
            title: "US Inactive".to_string(),
            required_domain_tags: vec!["sovereign-rag".to_string()],
            required_format: TrainingRecordFormat::SftTrajectory,
            payout_per_record_cents: 500,
            max_records: 10,
            accepted_records: 0,
            jurisdiction_iso: "US".to_string(),
            active: false,
        },
        // 3. Blocked foreign adversary bounty (CN)
        DataBountySpec {
            bounty_id: "bounty-cn".to_string(),
            sponsor_entity_name: "Adversary Lab".to_string(),
            sponsor_buyer_id: "buyer-cn".to_string(),
            title: "CN Bounty".to_string(),
            required_domain_tags: vec!["sovereign-rag".to_string()],
            required_format: TrainingRecordFormat::SftTrajectory,
            payout_per_record_cents: 1000,
            max_records: 10,
            accepted_records: 0,
            jurisdiction_iso: "CN".to_string(),
            active: true,
        },
    ];

    let eligible = runner.filter_eligible_bounties(&bounties);
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].bounty_id, "bounty-us-active");

    let bounty = &bounties[0];
    let slice = "QuorumRAG verifies all peer messages with Ed25519 signatures, BLAKE3 Merkle integrity proofs, and parent-document byte window expansion across nodes.";
    let quote = "Ed25519 signatures, BLAKE3 Merkle integrity proofs";

    let cand_valid_1 = RawDatasetCandidate {
        record_id: "rec-bounty-1".to_string(),
        source_doc_id: "doc-1".to_string(),
        prompt: "How does QuorumRAG ensure cryptographic integrity, peer authentication, and parent-document continuity across federated peer nodes during multi-step retrieval?".to_string(),
        chosen_response: format!("{} QuorumRAG enforces strict multi-engine de-identification, BLAKE3 Merkle integrity verification, and parent-document byte window expansion across nodes so multi-paragraph context is preserved without exposing raw files or personal identifiers, satisfying all sovereignty airlock constraints.", slice),
        rejected_response: None,
        citations: vec![(slice.to_string(), quote.to_string())],
        domain_tags: vec!["sovereign-rag".to_string()],
    };

    let cand_valid_2 = RawDatasetCandidate {
        record_id: "rec-bounty-2".to_string(),
        source_doc_id: "doc-2".to_string(),
        prompt: "Describe the parent-document window expansion mechanism in QuorumRAG and its privacy preservation properties during decentralized synthesis:".to_string(),
        chosen_response: format!("{} The parent-document window expansion preserves contextual continuity up to 10000 bytes while stripping local filesystem paths, ensuring that decentralized synthesis engines receive complete semantic boundaries rather than isolated fragments.", slice),
        rejected_response: None,
        citations: vec![(slice.to_string(), quote.to_string())],
        domain_tags: vec!["sovereign-rag".to_string()],
    };

    let cand_valid_3 = RawDatasetCandidate {
        record_id: "rec-bounty-3".to_string(),
        source_doc_id: "doc-3".to_string(),
        prompt: "Explain how QuorumRAG integrates three-engine airlock de-identification with differential privacy verification for sovereign training data export:".to_string(),
        chosen_response: format!("{} Additional candidate trajectory exceeding maximum records cap, verifying that the bounty runner respects the configured ceiling.", slice),
        rejected_response: None,
        citations: vec![(slice.to_string(), quote.to_string())],
        domain_tags: vec!["sovereign-rag".to_string()],
    };

    // Candidate with wrong format (DpoPreferencePair instead of SftTrajectory)
    let mut cand_wrong_format = runner.candidate_from_raw_dataset(&cand_valid_1, TrainingRecordFormat::DpoPreferencePair);
    cand_wrong_format.record_id = "rec-wrong-format".to_string();

    // Candidate with mismatched domain tags
    let mut cand_wrong_domain = runner.candidate_from_raw_dataset(&cand_valid_1, TrainingRecordFormat::SftTrajectory);
    cand_wrong_domain.record_id = "rec-wrong-domain".to_string();
    cand_wrong_domain.domain_tags = vec!["unrelated-domain".to_string()];

    // Candidate with trade secret (internal RFC1918 IP)
    let mut cand_trade_secret = runner.candidate_from_raw_dataset(&cand_valid_1, TrainingRecordFormat::SftTrajectory);
    cand_trade_secret.record_id = "rec-trade-secret".to_string();
    cand_trade_secret.chosen_response = format!("{} Server runs at 10.0.0.42 internally.", slice);

    let candidates = vec![
        runner.candidate_from_raw_dataset(&cand_valid_1, TrainingRecordFormat::SftTrajectory),
        cand_wrong_format,
        cand_wrong_domain,
        cand_trade_secret,
        runner.candidate_from_raw_dataset(&cand_valid_2, TrainingRecordFormat::SftTrajectory),
        runner.candidate_from_raw_dataset(&cand_valid_3, TrainingRecordFormat::SftTrajectory), // Exceeds cap of 2
    ];

    let approved = runner.process_bounty_candidates(bounty, &candidates).unwrap();
    // Only cand_valid_1 and cand_valid_2 should be approved (cap = 2)
    assert_eq!(approved.len(), 2);
    assert_eq!(approved[0].record_id, "rec-bounty-1");
    assert_eq!(approved[1].record_id, "rec-bounty-2");

    let match_res = runner.evaluate_bounty_match(bounty, &approved);
    assert_eq!(match_res.matched_record_count, 2);
    assert_eq!(match_res.estimated_payout_cents, 1000); // 2 * 500
    assert!(match_res.total_token_count >= 128);
}
