//! E2E Tests: Gemma Embedding Contract, BLAKE3 Handshake Gating, & Magika Content Identification.
//!
//! Tiers covered:
//! - Tier 1: Feature Coverage (Canonical Gemma 768d spec, BLAKE3 contract hash, constant-time gating, Magika inspection)
//! - Tier 2: Boundary & Corner Cases (empty text, single-bit hash divergence, null byte binary sniff, 0-byte buffer, unicode/emojis)

use quorum_classifier::{FileCategory, FileTypeClassifier};
use quorum_contract::{
    cosine_similarity, verify_contract_handshake, DeterministicOfflineEngine, EmbeddingContract,
    EmbeddingGenerator,
};
use quorum_e2e::*;

// ============================================================================
// TIER 1: FEATURE COVERAGE (>=5 test cases)
// ============================================================================

#[test]
fn test_gemma_canonical_contract_spec_fields() {
    let contract = EmbeddingContract::canonical_gemma_300m();
    assert_eq!(contract.contract_version, 1);
    assert_eq!(contract.model_name, "google/embeddinggemma-300m");
    assert_eq!(contract.dimension, 768);
    assert_eq!(contract.normalization, "L2");
    assert_eq!(contract.distance_metric, "Cosine");
    assert_eq!(contract.pooling_strategy, "MeanPooling");
    assert_eq!(contract.max_sequence_length, 512);
}

#[test]
fn test_gemma_blake3_contract_hash_deterministic() {
    let contract = EmbeddingContract::canonical_gemma_300m();
    let hash = contract.derive_contract_hash();

    // Verify against our independent mathematical oracle
    let oracle_spec = EmbeddingContractSpec::default();
    let expected_oracle_hash = oracle_derive_contract_hash(&oracle_spec);

    assert_eq!(
        hash, expected_oracle_hash,
        "Crate derived hash must match independent reference oracle"
    );
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_gemma_handshake_constant_time_success() {
    let contract = EmbeddingContract::canonical_gemma_300m();
    let local_hash = contract.derive_contract_hash();
    let remote_hash = local_hash;

    // Both nodes adhere to identical contract
    assert!(verify_contract_handshake(&local_hash, &remote_hash).is_ok());
    assert!(oracle_validate_handshake(&local_hash, &remote_hash));
}

#[test]
fn test_gemma_handshake_rejection_on_mismatched_contract() {
    let local_contract = EmbeddingContract::canonical_gemma_300m();
    let local_hash = local_contract.derive_contract_hash();

    // Peer configured with divergent dimension (e.g. 512 instead of 768)
    let mut remote_contract = local_contract.clone();
    remote_contract.dimension = 512;
    let remote_hash = remote_contract.derive_contract_hash();

    let result = verify_contract_handshake(&local_hash, &remote_hash);
    assert!(result.is_err(), "Handshake MUST fail when dimensions mismatch");
    assert!(!oracle_validate_handshake(&local_hash, &remote_hash));

    // Peer configured with divergent distance metric (e.g. "DotProduct" instead of "Cosine")
    let mut remote_contract_metric = local_contract.clone();
    remote_contract_metric.distance_metric = "DotProduct".to_string();
    let remote_hash_metric = remote_contract_metric.derive_contract_hash();
    assert!(verify_contract_handshake(&local_hash, &remote_hash_metric).is_err());
}

#[test]
fn test_gemma_offline_deterministic_embedding_vector_properties() {
    let engine = DeterministicOfflineEngine::new();
    let prompt = "How does QuorumRAG achieve zero-leakage storage isolation?";

    let vec = engine.embed_text(prompt).expect("Embedding generated");

    // Must strictly be 768 dimensions
    assert_eq!(vec.len(), 768);

    // Must strictly be L2 unit-normalized
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4, "L2 norm must equal 1.0");

    // Cosine similarity with self must be ~1.0
    let sim = cosine_similarity(&vec, &vec).expect("Cosine similarity");
    assert!((sim - 1.0).abs() < 1e-4);
}

#[test]
fn test_magika_deep_content_classifier_rust_code() {
    let classifier = FileTypeClassifier::new();
    let rust_code = b"use std::collections::HashMap;\n\npub struct Node {\n    pub peer_id: String,\n}\n";

    let id = classifier.classify_bytes(rust_code, Some("node.rs"));
    assert_eq!(id.label, "rust");
    assert_eq!(id.category, FileCategory::Code);
    assert!(id.is_text);
    assert!(!id.is_binary);
    assert!(id.score >= 0.90);
}

#[test]
fn test_magika_deep_content_classifier_pe_binary() {
    let classifier = FileTypeClassifier::new();
    let mz_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";

    let id = classifier.classify_bytes(mz_header, Some("daemon.exe"));
    assert_eq!(id.label, "pebin");
    assert_eq!(id.category, FileCategory::Executable);
    assert!(id.is_binary);
    assert!(!id.is_text);
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (>=5 test cases)
// ============================================================================

#[test]
fn test_gemma_boundary_empty_text_vector() {
    let engine = DeterministicOfflineEngine::new();
    let vec = engine.embed_text("").expect("Empty text handled gracefully");
    assert_eq!(vec.len(), 768);

    // Empty text must still generate a valid unit-normalized vector without NaNs or infinities
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4);
    for &x in &vec {
        assert!(!x.is_nan() && !x.is_infinite());
    }
}

#[test]
fn test_gemma_boundary_single_bit_hash_corruption() {
    let contract = EmbeddingContract::canonical_gemma_300m();
    let local_hash = contract.derive_contract_hash();

    // Mutate exactly 1 bit in byte 31
    let mut corrupted = local_hash;
    corrupted[31] ^= 0x01;

    let res = verify_contract_handshake(&local_hash, &corrupted);
    assert!(res.is_err(), "Single-bit corruption must trigger HandshakeMismatch");
    assert!(!oracle_validate_handshake(&local_hash, &corrupted));
}

#[test]
fn test_gemma_boundary_whitespace_and_tabs_text() {
    let engine = DeterministicOfflineEngine::new();
    let whitespace_input = "   \t\t\n\r\n   ";
    let vec = engine.embed_text(whitespace_input).unwrap();
    assert_eq!(vec.len(), 768);
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4);
}

#[test]
fn test_magika_boundary_null_bytes_in_apparent_text() {
    let classifier = FileTypeClassifier::new();
    // 100 bytes of ASCII text containing an embedded null byte at byte 50
    let mut payload = vec![b'A'; 100];
    payload[50] = 0x00;

    let id = classifier.classify_bytes(&payload, Some("corrupted.txt"));
    assert!(id.is_binary, "Embedded null byte must trigger binary classification");
    assert!(!id.is_text);
}

#[test]
fn test_magika_boundary_zero_byte_empty_buffer() {
    let classifier = FileTypeClassifier::new();
    let id = classifier.classify_bytes(&[], None);
    assert_eq!(id.label, "empty");
    assert!(id.is_text);
    assert!(!id.is_binary);
}

#[test]
fn test_magika_boundary_huge_text_buffer() {
    let classifier = FileTypeClassifier::new();
    let huge_text = "fn compute_tensor() -> Result<(), ()> { Ok(()) }\n".repeat(1000); // ~50KB

    let id = classifier.classify_bytes(huge_text.as_bytes(), Some("huge.rs"));
    assert_eq!(id.label, "rust");
    assert!(id.is_text);
}

#[test]
fn test_gemma_boundary_complex_unicode_and_emojis() {
    let engine = DeterministicOfflineEngine::new();
    let complex_text = "QuorumRAG 🚀 零知识 检索增强生成 (RAG) 🔒 100% 本地隐私";

    let vec = engine.embed_text(complex_text).unwrap();
    assert_eq!(vec.len(), 768);
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4);
}
