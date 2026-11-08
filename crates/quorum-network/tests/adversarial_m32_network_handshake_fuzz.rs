//! Adversarial Network Handshake Fuzzing for Milestone M32.
//!
//! Validates `verify_peer_contract` and `extract_contract_hash` in `crates/quorum-network/src/handshake.rs`:
//! 1. All 9 pairwise canonical combinations succeed through `verify_peer_contract`.
//! 2. 1-bit flipped hashes fail closed with `NetworkError::ContractMismatch`.
//! 3. Foreign SHA-256 and BLAKE3 hashes fail closed.
//! 4. Malformed, truncated, and multi-byte UTF-8 hex strings fail closed.
//! 5. `extract_contract_hash` boundary stress across protocol and agent versions.

use quorum_contract::EmbeddingContract;
use quorum_network::{
    extract_contract_hash, make_agent_version, make_protocol_version, verify_peer_contract,
    NetworkError,
};

fn format_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// 1. All 9 pairwise canonical combinations succeed via `verify_peer_contract`.
#[test]
fn test_network_handshake_all_9_canonical_pairs_connect() {
    let contracts = [
        ("DeterministicOffline", EmbeddingContract::canonical_deterministic_offline()),
        ("GemmaCandle", EmbeddingContract::canonical_gemma_300m()),
        ("OllamaEmbedding", EmbeddingContract::canonical_ollama_embeddinggemma()),
    ];

    let mut accepted = 0;
    for (name_a, c_a) in &contracts {
        let hex_a = c_a.derive_contract_hash_hex();
        for (name_b, c_b) in &contracts {
            let hex_b = c_b.derive_contract_hash_hex();
            let res = verify_peer_contract("peer_test_node", &hex_a, &hex_b);
            assert!(
                res.is_ok(),
                "Peer verification between {} and {} failed: {:?}",
                name_a,
                name_b,
                res
            );
            accepted += 1;
        }
    }
    assert_eq!(accepted, 9);
}

/// 2. 1-bit flipped hashes fail closed with `NetworkError::ContractMismatch`.
#[test]
fn test_network_handshake_1_bit_flips_fail_closed() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hash = canonical.derive_contract_hash();
    let canonical_hex = canonical.derive_contract_hash_hex();

    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut tampered = canonical_hash;
            tampered[byte_idx] ^= 1 << bit_idx;
            let tampered_hex = format_hex(&tampered);

            let res = verify_peer_contract("peer_tampered", &canonical_hex, &tampered_hex);
            assert!(
                matches!(res, Err(NetworkError::ContractMismatch { .. })),
                "Expected ContractMismatch at byte {}, bit {}",
                byte_idx,
                bit_idx
            );
        }
    }
}

/// 3. Foreign hashes fail closed.
#[test]
fn test_network_handshake_foreign_hashes_fail_closed() {
    let canonical_hex =
        EmbeddingContract::canonical_deterministic_offline().derive_contract_hash_hex();

    let foreign_hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "313d42fb53cb648d88e0db40ce2435f1f2e1dfbd923fc82705a61e7febe06a12",
    ];

    for foreign in &foreign_hashes {
        let res = verify_peer_contract("peer_rogue", &canonical_hex, foreign);
        assert!(
            matches!(res, Err(NetworkError::ContractMismatch { .. })),
            "Expected ContractMismatch for foreign hash {}",
            foreign
        );
    }
}

/// 4. Malformed and truncated hex strings fail closed with `NetworkError::ContractMismatch`.
#[test]
fn test_network_handshake_malformed_and_truncated_fail_closed() {
    let canonical_hex =
        EmbeddingContract::canonical_gemma_300m().derive_contract_hash_hex();

    // Empty string
    assert!(matches!(
        verify_peer_contract("peer_empty", &canonical_hex, ""),
        Err(NetworkError::ContractMismatch { .. })
    ));

    // Truncated lengths (1..63)
    for len in [1, 10, 32, 63] {
        let truncated = &canonical_hex[..len];
        assert!(matches!(
            verify_peer_contract("peer_short", &canonical_hex, truncated),
            Err(NetworkError::ContractMismatch { .. })
        ));
    }

    // Overlong string
    let overlong = format!("{}deadbeef", canonical_hex);
    assert!(matches!(
        verify_peer_contract("peer_long", &canonical_hex, &overlong),
        Err(NetworkError::ContractMismatch { .. })
    ));

    // Non-hex characters
    let mut bad_char = canonical_hex.clone();
    bad_char.replace_range(5..6, "Z");
    assert!(matches!(
        verify_peer_contract("peer_bad_char", &canonical_hex, &bad_char),
        Err(NetworkError::ContractMismatch { .. })
    ));

    // UTF-8 emoji
    let mut emoji_trap = canonical_hex.clone();
    emoji_trap.replace_range(0..4, "🦀");
    assert!(matches!(
        verify_peer_contract("peer_emoji", &canonical_hex, &emoji_trap),
        Err(NetworkError::ContractMismatch { .. })
    ));
}

/// 5. `extract_contract_hash` boundary stress across protocol and agent versions.
#[test]
fn test_network_extract_contract_hash_fuzzing() {
    let canonical = EmbeddingContract::canonical_ollama_embeddinggemma();
    let hex = canonical.derive_contract_hash_hex();

    // Protocol version roundtrip
    let proto = make_protocol_version(&hex);
    assert_eq!(extract_contract_hash(&proto), Some(hex.clone()));

    // Agent version roundtrip
    let agent = make_agent_version(&hex);
    assert_eq!(extract_contract_hash(&agent), Some(hex.clone()));

    // Corrupted protocol prefixes
    assert_eq!(extract_contract_hash("/quorum-rag/1.0.0/contract-"), None);
    assert_eq!(extract_contract_hash("/quorum-rag/1.0.0/contract"), None);
    assert_eq!(extract_contract_hash("contract-"), None);
    assert_eq!(extract_contract_hash(""), None);

    // Truncated hash in protocol string (63 chars)
    let proto_short = format!("/quorum-rag/1.0.0/contract-{}", &hex[..63]);
    assert_eq!(extract_contract_hash(&proto_short), None);

    // Non-hex char in protocol string
    let mut corrupted_hex = hex.clone();
    corrupted_hex.replace_range(20..21, "q");
    let proto_corrupt = format!("/quorum-rag/1.0.0/contract-{}", corrupted_hex);
    assert_eq!(extract_contract_hash(&proto_corrupt), None);

    // Multi-slash agent string: extracts last 64-char hex
    let complex_agent = format!("deep/nested/path/quorumrag/0.6.3/{}", hex);
    assert_eq!(extract_contract_hash(&complex_agent), Some(hex));
}
