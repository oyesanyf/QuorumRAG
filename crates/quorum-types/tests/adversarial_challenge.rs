//! Adversarial Challenge Test Harness for Milestone 1
//!
//! Stress tests:
//! 1. VolatileRemoteChunk zeroize-on-drop memory validation & concurrency stress
//! 2. AccessTier authorization matrix, SQL predicate generation, and boundary values
//! 3. Serialization integrity, boundary line numbers, Unicode fuzzing, signature slicing, and tampering oracles

use chrono::Utc;
use quorum_types::{
    AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest,
    FederatedQueryResponse, ScoredChunk, TypeError, VolatileRemoteChunk,
};
use std::panic::{self, AssertUnwindSafe};
use std::thread;
use uuid::Uuid;
use zeroize::Zeroize;

// ============================================================================
// Area 1: VolatileRemoteChunk ZeroizeOnDrop Memory Validation & Concurrency
// ============================================================================

#[test]
fn test_volatile_memory_zeroize_inspection() {
    let secret = "CRITICAL_SESSION_TOKEN_XYZ_1234567890_TOP_SECRET".to_string();
    let ptr = secret.as_ptr();
    let len = secret.len();

    let mut volatile = VolatileRemoteChunk {
        chunk_id: "chunk-sec-1".to_string(),
        peer_id: "peer-remote-42".to_string(),
        file_path: "secrets/vault.key".to_string(),
        line_start: 1,
        line_end: 5,
        score: 0.999,
        access_tier: 3,
        content: secret,
    };

    // 1. Confirm before zeroize/drop that content contains sensitive plaintext
    assert_eq!(volatile.content(), "CRITICAL_SESSION_TOKEN_XYZ_1234567890_TOP_SECRET");
    let slice_before = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert_eq!(slice_before, b"CRITICAL_SESSION_TOKEN_XYZ_1234567890_TOP_SECRET");

    // 2. Perform zeroize on volatile chunk
    volatile.zeroize();

    // 3. Confirm that content has been scrubbed
    // String::zeroize() zeroes the underlying buffer bytes and sets length to 0
    assert!(volatile.content.is_empty());
    // Also verify the original buffer memory at raw pointer was overwritten with zeroes
    let slice_after = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        slice_after.iter().all(|&b| b == 0),
        "Memory buffer was not zeroed out! Found non-zero bytes: {:?}",
        slice_after
    );
}

#[test]
fn test_volatile_memory_concurrency_stress() {
    let num_threads = 20;
    let iterations_per_thread = 500;

    let handles: Vec<_> = (0..num_threads)
        .map(|t_idx| {
            thread::spawn(move || {
                for i in 0..iterations_per_thread {
                    let payload = format!(
                        "THREAD_{}_ITER_{}_SENSITIVE_DATA_{}",
                        t_idx,
                        i,
                        "X".repeat((i % 100) * 10)
                    );
                    let dto = CandidateChunkDto {
                        chunk_id: format!("c_{}_{}", t_idx, i),
                        file_path: format!("src/file_{}.rs", i),
                        line_start: 1,
                        line_end: 10,
                        content: payload.clone(),
                        score: 0.85,
                        access_tier: 1,
                    };

                    let volatile = dto.to_volatile_remote_chunk(format!("peer-{}", t_idx));
                    assert_eq!(volatile.content(), payload.as_str());

                    // Test citation extraction
                    let citation = volatile.to_citation();
                    assert_eq!(citation.peer_id, format!("peer-{}", t_idx));
                    if payload.len() > 240 {
                        assert!(citation.snippet.ends_with("..."));
                    } else {
                        assert_eq!(citation.snippet, payload);
                    }

                    // Test cloning volatile chunk (both must cleanly drop and zeroize)
                    let cloned = volatile.clone();
                    assert_eq!(cloned.content(), volatile.content());
                    drop(volatile);
                    drop(cloned);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Concurrent volatile thread panicked");
    }
}

// ============================================================================
// Area 2: AccessTier Authorization & SQL Predicate Stress
// ============================================================================

#[test]
fn test_access_tier_truth_table_and_sql_predicates() {
    let all_tiers = [
        AccessTier::Tier0Public,
        AccessTier::Tier1Internal,
        AccessTier::Tier2Confidential,
        AccessTier::Tier3Restricted,
    ];

    // Verify ordering and numeric representations
    for (expected_val, tier) in all_tiers.iter().enumerate() {
        assert_eq!(tier.as_u8(), expected_val as u8);
        assert_eq!(AccessTier::from_u8(expected_val as u8).unwrap(), *tier);
    }

    // Exhaustive 4x4 authorization matrix
    for req in &all_tiers {
        for max in &all_tiers {
            let expected_auth = req.as_u8() <= max.as_u8();
            assert_eq!(
                req.is_authorized_for(*max),
                expected_auth,
                "Authorization failed for req={:?} (u8={}), max={:?} (u8={})",
                req,
                req.as_u8(),
                max,
                max.as_u8()
            );
        }
    }

    // Verify SQL pushdown generation
    assert_eq!(AccessTier::Tier0Public.sql_filter_lte(), "access_tier <= 0");
    assert_eq!(AccessTier::Tier1Internal.sql_filter_lte(), "access_tier <= 1");
    assert_eq!(AccessTier::Tier2Confidential.sql_filter_lte(), "access_tier <= 2");
    assert_eq!(AccessTier::Tier3Restricted.sql_filter_lte(), "access_tier <= 3");

    // Invalid values
    for invalid in [4u8, 5, 10, 100, 254, 255] {
        assert_eq!(
            AccessTier::from_u8(invalid),
            Err(TypeError::InvalidAccessTier(invalid))
        );
    }
}

#[test]
fn test_access_tier_boundary_in_document_chunk_creation() {
    // Probe whether DocumentChunk::new validates access_tier:
    let chunk_res = DocumentChunk::new(
        "c-invalid-tier",
        "doc-1",
        "file.txt",
        1,
        5,
        255, // Invalid access tier!
        vec![0.0; 768],
        "some text",
        None,
    );

    // DocumentChunk::new validates and rejects invalid access tier bounds (0..=3)
    assert_eq!(chunk_res, Err(TypeError::InvalidAccessTier(255)));
}

#[test]
fn test_access_tier_serde_representation() {
    // Test what serde serializes for AccessTier
    let tier = AccessTier::Tier1Internal;
    let json = serde_json::to_string(&tier).expect("Serialize AccessTier");

    // Rust serde default enum serialization serializes as variant name string
    assert_eq!(json, "\"Tier1Internal\"");

    // Test deserializing from variant name
    let deserialized: AccessTier = serde_json::from_str(&json).expect("Deserialize AccessTier");
    assert_eq!(deserialized, AccessTier::Tier1Internal);

    // Note: Serde does NOT deserialize numeric strings or "1" by default unless configured
    let num_str_err = serde_json::from_str::<AccessTier>("1");
    assert!(num_str_err.is_err(), "Raw number 1 without custom serde fails deserialization");

    // But std::str::FromStr parses "1" and "internal"
    assert_eq!("1".parse::<AccessTier>().unwrap(), AccessTier::Tier1Internal);
    assert_eq!("internal".parse::<AccessTier>().unwrap(), AccessTier::Tier1Internal);
}

// ============================================================================
// Area 3: Serialization Integrity & Fuzzing
// ============================================================================

#[test]
fn test_document_chunk_boundary_line_numbers() {
    // 0 is accepted as line_start and line_end
    let chunk_zero = DocumentChunk::new(
        "c-zero",
        "doc-zero",
        "src/lib.rs",
        0,
        0,
        0,
        vec![0.0; 768],
        "zero line content",
        None,
    );
    assert!(chunk_zero.is_ok());

    // u32::MAX is accepted
    let chunk_max = DocumentChunk::new(
        "c-max",
        "doc-max",
        "src/lib.rs",
        u32::MAX,
        u32::MAX,
        0,
        vec![0.0; 768],
        "max line content",
        None,
    );
    assert!(chunk_max.is_ok());

    // line_start > line_end must fail
    let chunk_invalid = DocumentChunk::new(
        "c-inv",
        "doc-inv",
        "src/lib.rs",
        100,
        50,
        0,
        vec![0.0; 768],
        "invalid line",
        None,
    );
    assert_eq!(
        chunk_invalid.unwrap_err(),
        TypeError::InvalidLineRange { start: 100, end: 50 }
    );

    // Deserialization bypass check:
    // When deserialized directly from JSON, new() is bypassed, so line_start > line_end is loaded
    let json = r#"{
        "chunk_id": "c-bypass",
        "document_id": "doc-bypass",
        "file_path": "bypass.rs",
        "line_start": 500,
        "line_end": 10,
        "blake3_hash": "deadbeef",
        "access_tier": 0,
        "vector": [],
        "text_content": "bypass line validation",
        "metadata_json": "{}"
    }"#;

    let chunk_bypassed: DocumentChunk =
        serde_json::from_str(json).expect("Deserialization bypasses new() validation");
    assert_eq!(chunk_bypassed.line_start, 500);
    assert_eq!(chunk_bypassed.line_end, 10);
    assert!(!chunk_bypassed.verify_hash());
}

#[test]
fn test_document_chunk_huge_and_empty_payloads() {
    // Empty text content
    let empty_chunk = DocumentChunk::new(
        "",
        "",
        "",
        1,
        1,
        0,
        vec![],
        "",
        None,
    )
    .expect("Empty text chunk");

    let expected_empty_hash = blake3::hash(b"").to_hex().to_string();
    assert_eq!(empty_chunk.blake3_hash, expected_empty_hash);
    assert!(empty_chunk.verify_hash());

    // Huge 2MB text content
    let huge_text = "QuorumRAG Enterprise Distributed Search Knowledge Base! ".repeat(35000); // ~2MB
    let huge_chunk = DocumentChunk::new(
        "c-huge",
        "doc-huge",
        "big_data.txt",
        1,
        10000,
        1,
        vec![0.1f32; 768],
        huge_text,
        Some(r#"{"size":"2MB"}"#.to_string()),
    )
    .expect("Huge chunk creation");

    assert!(huge_chunk.verify_hash());
    let json = serde_json::to_string(&huge_chunk).expect("Serialize huge chunk");
    let deser: DocumentChunk = serde_json::from_str(&json).expect("Deserialize huge chunk");
    assert_eq!(huge_chunk.chunk_id, deser.chunk_id);
    assert_eq!(huge_chunk.blake3_hash, deser.blake3_hash);
}

#[test]
fn test_unicode_and_citation_boundary_fuzzing() {
    // Construct text where character boundary falls right around 240 bytes
    // Emojis: 🦀 (4 bytes: F0 9F A6 80)
    // 59 4-byte emojis = 236 bytes
    // 60 4-byte emojis = 240 bytes
    // 61 4-byte emojis = 244 bytes
    let base_emojis = "🦀".repeat(59); // 236 bytes
    let emoji_test_str = format!("{}🔥{}", base_emojis, "a".repeat(20)); // 🔥 is 4 bytes at [236..240]

    let chunk = DocumentChunk::new(
        "c-unicode",
        "doc-u",
        "unicode.rs",
        1,
        5,
        0,
        vec![0.0; 768],
        emoji_test_str,
        None,
    )
    .unwrap();

    let scored = ScoredChunk::new(chunk, 0.95, "peer-alpha", false);
    let citation = scored.to_citation();

    // Verify snippet is valid UTF-8 and truncated cleanly
    assert!(citation.snippet.ends_with("..."));
    let raw_snippet = &citation.snippet[..citation.snippet.len() - 3];
    assert!(raw_snippet.len() <= 240);
    // Char boundary check: iterating chars must succeed
    for _ in raw_snippet.chars() {}

    // Volatile citation truncation
    let volatile = VolatileRemoteChunk {
        chunk_id: "c-v".to_string(),
        peer_id: "peer-1".to_string(),
        file_path: "u.txt".to_string(),
        line_start: 1,
        line_end: 2,
        score: 0.8,
        access_tier: 0,
        content: "中".repeat(85), // 85 * 3 = 255 bytes (multi-byte UTF-8)
    };
    let cit_v = volatile.to_citation();
    assert!(cit_v.snippet.ends_with("..."));
    let raw_v = &cit_v.snippet[..cit_v.snippet.len() - 3];
    assert!(raw_v.len() <= 240);
    for _ in raw_v.chars() {}
}

#[test]
fn test_federated_query_serde_sig64_multibyte_panic_probe() {
    // EMPIRICAL CHALLENGE PROBE:
    // Check if serde_sig64::deserialize panics when receiving a 128-byte string containing multi-byte UTF-8 characters!
    // In serde_sig64:
    // if v.len() != 128 { return Err(...) }
    // for i in 0..64 {
    //     out[i] = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16)...
    // }
    // If v has 128 bytes, but contains a 4-byte emoji, &v[0..2] or &v[2..4] slices inside the emoji and PANICS!

    let bad_sig_content = format!("🔥{}", "0".repeat(124)); // 4 bytes of 🔥 + 124 bytes of '0' = 128 bytes total
    assert_eq!(bad_sig_content.len(), 128); // Exactly 128 bytes!

    let json_payload = format!(
        r#"{{
            "query_id": "00000000-0000-0000-0000-000000000001",
            "sender_peer_id": "malicious-peer",
            "sender_pubkey": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "query_text": "hello",
            "embedding": [],
            "top_k": 5,
            "timestamp": 1234567,
            "signature": "{}"
        }}"#,
        bad_sig_content
    );

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        serde_json::from_str::<FederatedQueryRequest>(&json_payload)
    }));

    match result {
        Ok(serde_result) => {
            // Deserialization should return an error, not panic
            assert!(serde_result.is_err(), "Expected Err on invalid signature, got {:?}", serde_result);
        }
        Err(_panic_err) => {
            panic!("CRITICAL BUG: serde_sig64 panicked on 128-byte multi-byte UTF-8 string!");
        }
    }
}

#[test]
fn test_federated_query_timestamp_overflow_panic_probe() {
    // EMPIRICAL CHALLENGE PROBE:
    // In FederatedQueryRequest::is_fresh(max_drift_secs):
    // let now = Utc::now().timestamp();
    // let drift = (now - self.timestamp).abs();
    // If self.timestamp is i64::MIN, `now - i64::MIN` overflows i64 in debug mode and PANICS!

    let req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "peer-test".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "test".to_string(),
        embedding: vec![],
        top_k: 5,
        timestamp: i64::MIN, // Boundary extreme value
        signature: [0u8; 64],
    };

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        req.is_fresh(60)
    }));

    match result {
        Ok(res) => {
            // Should return Err(TypeError::QueryExpired), not panic
            assert!(res.is_err(), "Expected Err on expired timestamp, got {:?}", res);
        }
        Err(_panic_err) => {
            panic!("CRITICAL BUG: is_fresh() panicked on timestamp=i64::MIN due to integer overflow!");
        }
    }
}

#[test]
fn test_federated_query_canonical_signing_tampering_oracle() {
    // EMPIRICAL ORACLE:
    // Check if modifying top_k, embedding, or sender_pubkey changes canonical_signing_bytes() or canonical_digest()
    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "alice-peer".to_string(),
        sender_pubkey: [1u8; 32],
        query_text: "confidential query".to_string(),
        embedding: vec![0.1f32; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0xabu8; 64],
    };

    let digest_orig = req.canonical_digest();
    let _bytes_orig = req.canonical_signing_bytes();

    // 1. Adversary modifies top_k to 1,000,000 (DoS amplification attack)
    req.top_k = 1_000_000;
    let digest_tampered_top_k = req.canonical_digest();
    assert_ne!(
        digest_orig, digest_tampered_top_k,
        "Tampering top_k must alter canonical digest"
    );

    // 2. Adversary substitutes embedding vector (vector injection / poisoning attack)
    req.embedding = vec![0.99f32; 768];
    let digest_tampered_embedding = req.canonical_digest();
    assert_ne!(
        digest_orig, digest_tampered_embedding,
        "Tampering embedding must alter canonical digest"
    );

    // 3. Adversary alters sender_pubkey
    req.sender_pubkey = [0x99u8; 32];
    let digest_tampered_pubkey = req.canonical_digest();
    assert_ne!(
        digest_orig, digest_tampered_pubkey,
        "Tampering sender_pubkey must alter canonical digest"
    );
}

#[test]
fn test_federated_query_roundtrip_serialization() {
    let req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "peer-valid".to_string(),
        sender_pubkey: [42u8; 32],
        query_text: "What is the capital of France?".to_string(),
        embedding: vec![0.123f32; 768],
        top_k: 10,
        timestamp: Utc::now().timestamp(),
        signature: [0x55u8; 64],
    };

    let json = serde_json::to_string(&req).expect("Serialize FederatedQueryRequest");
    let deser: FederatedQueryRequest = serde_json::from_str(&json).expect("Deserialize FederatedQueryRequest");

    assert_eq!(req, deser);
    assert_eq!(req.signature, deser.signature);

    // Also test FederatedQueryResponse roundtrip
    let resp = FederatedQueryResponse {
        query_id: req.query_id,
        responder_peer_id: "peer-bob".to_string(),
        chunks: vec![
            CandidateChunkDto {
                chunk_id: "chunk-1".to_string(),
                file_path: "paris.md".to_string(),
                line_start: 1,
                line_end: 20,
                content: "Paris is the capital of France.".to_string(),
                score: 0.98,
                access_tier: 0,
            },
        ],
    };

    let resp_json = serde_json::to_string(&resp).expect("Serialize FederatedQueryResponse");
    let resp_deser: FederatedQueryResponse = serde_json::from_str(&resp_json).expect("Deserialize FederatedQueryResponse");
    assert_eq!(resp, resp_deser);
}
