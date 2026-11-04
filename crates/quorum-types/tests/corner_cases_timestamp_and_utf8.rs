//! Empirical Challenger Stress Tests: Timestamp Bounds & Multi-byte UTF-8 Corner Cases.
//!
//! Validates:
//! - Timestamp boundary values (i64::MIN, i64::MIN + 1, i64::MAX, -1, 0, 1) and clock drift
//! - Serde 128-byte signature deserialization with 2-byte, 3-byte, and 4-byte UTF-8 across all offsets
//! - ScoredChunk::to_citation() snippet boundary truncation across 2, 3, and 4-byte codepoints
//! - Canonical signing bytes with Unicode payloads and extreme embedding values

use chrono::Utc;
use quorum_types::{
    CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk, TypeError,
};
use std::panic::{self, AssertUnwindSafe};
use uuid::Uuid;
use zeroize::Zeroize;

#[test]
fn test_timestamp_boundary_extremes_and_overflow_immunity() {
    let now = Utc::now().timestamp();

    // Matrix of extreme timestamp values
    let extreme_timestamps = [
        i64::MIN,
        i64::MIN + 1,
        i64::MIN + 1000,
        -1_000_000_000,
        -1,
        0,
        1,
        now - 61,
        now - 60,
        now - 1,
        now,
        now + 1,
        now + 60,
        now + 61,
        1_000_000_000,
        i64::MAX - 1000,
        i64::MAX - 1,
        i64::MAX,
    ];

    for &ts in &extreme_timestamps {
        let req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: "peer-time".to_string(),
            sender_pubkey: [0u8; 32],
            query_text: "time check".to_string(),
            embedding: vec![],
            top_k: 10,
            timestamp: ts,
            signature: [0u8; 64],
        };

        // 1. is_fresh(60) must never panic
        let catch_res = panic::catch_unwind(AssertUnwindSafe(|| {
            req.is_fresh(60)
        }));
        assert!(
            catch_res.is_ok(),
            "PANIC on is_fresh(60) with timestamp={}",
            ts
        );

        let res = catch_res.unwrap();
        let expected_fresh = (now - 60..=now + 60).contains(&ts);
        if expected_fresh {
            assert!(res.is_ok(), "Expected fresh for ts={}, now={}", ts, now);
        } else {
            assert!(
                matches!(res, Err(TypeError::QueryExpired { .. })),
                "Expected QueryExpired for ts={}, now={}",
                ts,
                now
            );
        }
    }
}

#[test]
fn test_timestamp_with_extreme_max_drift_secs() {
    let now = Utc::now().timestamp();
    let req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "peer-time".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "time check".to_string(),
        embedding: vec![],
        top_k: 10,
        timestamp: now,
        signature: [0u8; 64],
    };

    // Test extreme drift parameters: 0, i64::MAX, -1, i64::MIN
    assert!(req.is_fresh(0).is_ok()); // now == timestamp, drift = 0 <= 0 -> Ok
    assert!(req.is_fresh(i64::MAX).is_ok());
    assert!(req.is_fresh(-1).is_err()); // drift 0 > -1 -> Err
    assert!(req.is_fresh(i64::MIN).is_err());
}

#[test]
fn test_serde_sig64_multibyte_utf8_all_offsets() {
    // 1. 2-byte UTF-8 at every byte offset 0..=126
    for offset in 0..=126 {
        let mut bad_sig = "a".repeat(offset);
        bad_sig.push('\u{00E9}'); // 2 bytes
        bad_sig.push_str(&"a".repeat(126 - offset));
        assert_eq!(bad_sig.len(), 128);

        let json = format!(
            r#"{{"query_id":"{}","sender_peer_id":"p","sender_pubkey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"query_text":"q","embedding":[],"top_k":1,"timestamp":0,"signature":"{}"}}"#,
            Uuid::new_v4(),
            bad_sig
        );

        let catch = panic::catch_unwind(AssertUnwindSafe(|| {
            serde_json::from_str::<FederatedQueryRequest>(&json)
        }));
        assert!(catch.is_ok(), "PANIC at offset {} on 2-byte UTF-8 in serde_sig64", offset);
        assert!(catch.unwrap().is_err());
    }

    // 2. 3-byte CJK at every byte offset 0..=125
    for offset in 0..=125 {
        let mut bad_sig = "a".repeat(offset);
        bad_sig.push('测'); // 3 bytes
        bad_sig.push_str(&"a".repeat(125 - offset));
        assert_eq!(bad_sig.len(), 128);

        let json = format!(
            r#"{{"query_id":"{}","sender_peer_id":"p","sender_pubkey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"query_text":"q","embedding":[],"top_k":1,"timestamp":0,"signature":"{}"}}"#,
            Uuid::new_v4(),
            bad_sig
        );

        let catch = panic::catch_unwind(AssertUnwindSafe(|| {
            serde_json::from_str::<FederatedQueryRequest>(&json)
        }));
        assert!(catch.is_ok(), "PANIC at offset {} on 3-byte CJK in serde_sig64", offset);
        assert!(catch.unwrap().is_err());
    }

    // 3. 4-byte emoji at every byte offset 0..=124
    for offset in 0..=124 {
        let mut bad_sig = "a".repeat(offset);
        bad_sig.push('🦀'); // 4 bytes
        bad_sig.push_str(&"a".repeat(124 - offset));
        assert_eq!(bad_sig.len(), 128);

        let json = format!(
            r#"{{"query_id":"{}","sender_peer_id":"p","sender_pubkey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"query_text":"q","embedding":[],"top_k":1,"timestamp":0,"signature":"{}"}}"#,
            Uuid::new_v4(),
            bad_sig
        );

        let catch = panic::catch_unwind(AssertUnwindSafe(|| {
            serde_json::from_str::<FederatedQueryRequest>(&json)
        }));
        assert!(catch.is_ok(), "PANIC at offset {} on 4-byte emoji in serde_sig64", offset);
        assert!(catch.unwrap().is_err());
    }
}

#[test]
fn test_citation_snippet_truncation_boundary_char_safety() {
    // to_citation truncates at 240 bytes if len > 240.
    // Test placing 2-byte, 3-byte, and 4-byte characters exactly spanning byte index 240.

    // 1. 2-byte character spanning 239..241
    let mut text_2byte = "a".repeat(239);
    text_2byte.push('\u{00E9}'); // bytes 239..241
    text_2byte.push_str(&"b".repeat(50));
    assert!(text_2byte.len() > 240);

    let chunk = DocumentChunk::new(
        "c1", "d1", "f1.txt", 1, 10, 0, vec![0.0; 768], text_2byte, None,
    ).unwrap();
    let scored = ScoredChunk::new(chunk, 0.9, "local", false);
    let cit = scored.to_citation();
    assert!(cit.snippet.ends_with("..."));
    // Ensure snippet before "..." is valid UTF-8 and does not end mid-character
    assert!(cit.snippet.len() <= 244);

    // 2. 3-byte character spanning 238..241 or 239..242
    for offset in 237..=240 {
        let mut text_3byte = "a".repeat(offset);
        text_3byte.push('测'); // 3 bytes
        text_3byte.push_str(&"b".repeat(50));
        let c = DocumentChunk::new("c2", "d1", "f1.txt", 1, 10, 0, vec![0.0; 768], text_3byte, None).unwrap();
        let s = ScoredChunk::new(c, 0.9, "local", false);
        let cit = s.to_citation();
        assert!(cit.snippet.ends_with("..."));
    }

    // 3. 4-byte emoji spanning across 240
    for offset in 237..=240 {
        let mut text_4byte = "a".repeat(offset);
        text_4byte.push('🚀'); // 4 bytes
        text_4byte.push_str(&"b".repeat(50));
        let c = DocumentChunk::new("c3", "d1", "f1.txt", 1, 10, 0, vec![0.0; 768], text_4byte, None).unwrap();
        let s = ScoredChunk::new(c, 0.9, "local", false);
        let cit = s.to_citation();
        assert!(cit.snippet.ends_with("..."));
    }
}

#[test]
fn test_canonical_signing_bytes_with_multibyte_and_extreme_embeddings() {
    let req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "peer-🦀-123".to_string(),
        sender_pubkey: [0x77u8; 32],
        query_text: "你好世界！مرحبا بالعالم 🚀🔥".to_string(),
        embedding: vec![f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.0, -0.0, 1.2345e-30],
        top_k: 42,
        timestamp: Utc::now().timestamp(),
        signature: [0x11u8; 64],
    };

    let bytes = req.canonical_signing_bytes();
    assert!(!bytes.is_empty());

    let digest1 = req.canonical_digest();
    let digest2 = req.canonical_digest();
    assert_eq!(digest1, digest2, "BLAKE3 digest must be strictly deterministic");
}

#[test]
fn test_into_volatile_remote_chunk_zeroize_on_drop_stress() {
    let secret = "SECRET_TOKEN_EMBEDDED_IN_CHUNK_PAYLOAD_9999".to_string();
    let ptr = secret.as_ptr();
    let len = secret.len();

    let dto = CandidateChunkDto {
        chunk_id: "c1".to_string(),
        file_path: "secure.rs".to_string(),
        line_start: 1,
        line_end: 5,
        content: secret,
        score: 0.95,
        access_tier: 2,
    };

    // Consume DTO by value into VolatileRemoteChunk
    let mut volatile = dto.into_volatile_remote_chunk("peer_alice");
    assert_eq!(volatile.content(), "SECRET_TOKEN_EMBEDDED_IN_CHUNK_PAYLOAD_9999");

    // Zeroize volatile container
    volatile.zeroize();

    // Verify memory was wiped with zeroes while buffer is still allocated
    let slice_after = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        slice_after.iter().all(|&b| b == 0),
        "Memory buffer was not zeroed out on zeroize! Found non-zero bytes: {:?}",
        slice_after
    );
    drop(volatile);
}
