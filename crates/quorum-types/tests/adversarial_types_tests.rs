//! Adversarial Stress Tests for QuorumRAG Pure Domain Types.
//!
//! Evaluates Arrow type isolation, AccessTier bounds, DocumentChunk validation,
//! and signature deserialization panic resilience.

use quorum_types::{
    AccessTier, DocumentChunk, FederatedQueryRequest, TypeError, VolatileRemoteChunk,
};
use uuid::Uuid;
use zeroize::Zeroize;

#[test]
fn test_access_tier_boundary_stress() {
    // 1. Valid bounds
    for (val, expected) in [
        (0u8, AccessTier::Tier0Public),
        (1u8, AccessTier::Tier1Internal),
        (2u8, AccessTier::Tier2Confidential),
        (3u8, AccessTier::Tier3Restricted),
    ] {
        assert_eq!(AccessTier::from_u8(val).unwrap(), expected);
        assert_eq!(expected.as_u8(), val);
    }

    // 2. Invalid raw tiers must fail closed
    for bad in [4u8, 5u8, 100u8, 255u8] {
        assert_eq!(AccessTier::from_u8(bad), Err(TypeError::InvalidAccessTier(bad)));
    }

    // 3. Monotonic authorization checks
    assert!(AccessTier::Tier0Public.is_authorized_for(AccessTier::Tier0Public));
    assert!(AccessTier::Tier0Public.is_authorized_for(AccessTier::Tier3Restricted));
    assert!(!AccessTier::Tier1Internal.is_authorized_for(AccessTier::Tier0Public));
    assert!(!AccessTier::Tier2Confidential.is_authorized_for(AccessTier::Tier1Internal));
    assert!(!AccessTier::Tier3Restricted.is_authorized_for(AccessTier::Tier2Confidential));

    // 4. SQL pushdown filter formatting
    assert_eq!(AccessTier::Tier0Public.sql_filter_lte(), "access_tier <= 0");
    assert_eq!(AccessTier::Tier1Internal.sql_filter_lte(), "access_tier <= 1");
    assert_eq!(AccessTier::Tier2Confidential.sql_filter_lte(), "access_tier <= 2");
    assert_eq!(AccessTier::Tier3Restricted.sql_filter_lte(), "access_tier <= 3");
}

#[test]
fn test_document_chunk_line_boundaries() {
    // Line start > line end MUST return InvalidLineRange
    let res = DocumentChunk::new(
        "c1", "d1", "test.rs", 10, 5, 0, vec![0.0; 768], "content", None,
    );
    assert_eq!(res, Err(TypeError::InvalidLineRange { start: 10, end: 5 }));

    // Line start == line end is valid (single line chunk)
    let ok_chunk = DocumentChunk::new(
        "c2", "d1", "test.rs", 42, 42, 0, vec![0.0; 768], "single line", None,
    );
    assert!(ok_chunk.is_ok());
    let chunk = ok_chunk.unwrap();
    assert!(chunk.verify_hash());
}

#[test]
fn test_signature_deserialization_panic_resilience() {
    // Craft JSON payload with signature of exactly 128 bytes, but with multi-byte UTF-8 at odd byte offset
    // 125 'a's + '\u{00E9}' (2 bytes) + 1 'a' = 128 bytes total
    let mut bad_sig = "a".repeat(125);
    bad_sig.push('\u{00E9}'); // byte offset 125..127
    bad_sig.push('a');       // byte offset 127..128
    assert_eq!(bad_sig.len(), 128);

    let json = format!(
        r#"{{"query_id":"{}","sender_peer_id":"peer1","sender_pubkey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"query_text":"test","embedding":[],"top_k":5,"timestamp":1000,"signature":"{}"}}"#,
        Uuid::new_v4(),
        bad_sig
    );

    let catch_result = std::panic::catch_unwind(|| {
        serde_json::from_str::<FederatedQueryRequest>(&json)
    });

    assert!(
        catch_result.is_ok(),
        "CRITICAL BUG: serde_sig64 PANICKED on 128-byte signature string with odd UTF-8 character boundary!"
    );
}

#[test]
fn test_volatile_remote_chunk_zeroization() {
    let mut chunk = VolatileRemoteChunk {
        chunk_id: "remote_1".to_string(),
        peer_id: "peer_xyz".to_string(),
        file_path: "secret.txt".to_string(),
        line_start: 1,
        line_end: 10,
        score: 0.95,
        access_tier: 2,
        content: "TOP SECRET CONFIDENTIAL CONTENT".to_string(),
    };

    assert_eq!(chunk.content(), "TOP SECRET CONFIDENTIAL CONTENT");
    chunk.zeroize();
    // String zeroize clears the contents or fills with zeroes
    assert!(chunk.content.is_empty() || chunk.content.bytes().all(|b| b == 0));
}
