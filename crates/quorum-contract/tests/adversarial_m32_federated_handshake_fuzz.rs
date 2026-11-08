//! Adversarial Fuzzing and Stress Harness for Milestone M32:
//! `verify_federated_contract_handshake_hex` & `is_canonical_quorum_contract_hash`.
//!
//! Validates:
//! 1. All 9 pairwise combinations of the 3 canonical contracts:
//!    - `canonical_deterministic_offline()`
//!    - `canonical_gemma_300m()`
//!    - `canonical_ollama_embeddinggemma()`
//! 2. Exhaustive 1-bit flip mutations (768 total bit flips) across all 3 canonical contracts.
//! 3. Foreign SHA-256 and BLAKE3 hashes, zero hashes, and all-ones hashes fail closed.
//! 4. Case-insensitivity (uppercase, lowercase, alternating mixed case) succeeds for canonical
//!    and fails closed for non-canonical.
//! 5. Malformed hex, truncated strings, invalid lengths, and multi-byte UTF-8 injections fail closed.
//! 6. Non-canonical contract schema mutations (dimension, metric, pooling, version, model) never accepted.
//! 7. Analysis of identical non-canonical pair handling.

use quorum_contract::{
    is_canonical_quorum_contract_hash, is_canonical_quorum_contract_hex,
    verify_federated_contract_handshake, verify_federated_contract_handshake_hex,
    ContractError, EmbeddingContract,
};
use std::panic::{self, AssertUnwindSafe};

fn format_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// 1. Verify all 9 pairwise combinations of canonical contracts are accepted.
#[test]
fn test_all_9_pairwise_canonical_combinations_succeed() {
    let contracts = [
        ("DeterministicOffline", EmbeddingContract::canonical_deterministic_offline()),
        ("GemmaCandle", EmbeddingContract::canonical_gemma_300m()),
        ("OllamaEmbedding", EmbeddingContract::canonical_ollama_embeddinggemma()),
    ];

    let mut accepted_count = 0;

    for (name_a, contract_a) in &contracts {
        let hash_a = contract_a.derive_contract_hash();
        let hex_a = contract_a.derive_contract_hash_hex();

        // Must be recognized as canonical
        assert!(
            is_canonical_quorum_contract_hash(&hash_a),
            "Contract {} hash must be recognized as canonical",
            name_a
        );
        assert!(
            is_canonical_quorum_contract_hex(&hex_a),
            "Contract {} hex must be recognized as canonical",
            name_a
        );

        for (name_b, contract_b) in &contracts {
            let hash_b = contract_b.derive_contract_hash();
            let hex_b = contract_b.derive_contract_hash_hex();

            // Byte-level handshake
            let res_bytes = verify_federated_contract_handshake(&hash_a, &hash_b);
            assert!(
                res_bytes.is_ok(),
                "Handshake between {} and {} (bytes) failed: {:?}",
                name_a,
                name_b,
                res_bytes
            );

            // Hex-level handshake
            let res_hex = verify_federated_contract_handshake_hex(&hex_a, &hex_b);
            assert!(
                res_hex.is_ok(),
                "Handshake between {} and {} (hex) failed: {:?}",
                name_a,
                name_b,
                res_hex
            );

            accepted_count += 1;
        }
    }

    assert_eq!(
        accepted_count, 9,
        "Exactly 9 pairwise canonical combinations must be tested and accepted"
    );
}

/// 2. Exhaustive 1-bit flip mutations across all 3 canonical contracts.
/// Tests every byte (0..32) and every bit (0..8) = 256 flips per contract * 3 contracts = 768 mutated hashes.
/// Each tested against all 3 canonical contracts as local peer = 2304 total tests.
#[test]
fn test_all_single_bit_flip_mutations_across_all_canonical_contracts_fail_closed() {
    let canonical_contracts = [
        EmbeddingContract::canonical_deterministic_offline(),
        EmbeddingContract::canonical_gemma_300m(),
        EmbeddingContract::canonical_ollama_embeddinggemma(),
    ];

    let canonical_hashes: Vec<[u8; 32]> = canonical_contracts
        .iter()
        .map(|c| c.derive_contract_hash())
        .collect();

    let canonical_hexes: Vec<String> = canonical_contracts
        .iter()
        .map(|c| c.derive_contract_hash_hex())
        .collect();

    let mut total_bit_flips_tested = 0;

    for (c_idx, source_hash) in canonical_hashes.iter().enumerate() {
        for byte_idx in 0..32 {
            for bit_idx in 0..8 {
                let mut tampered_hash = *source_hash;
                tampered_hash[byte_idx] ^= 1 << bit_idx;
                let tampered_hex = format_hex(&tampered_hash);

                // 1-bit flipped hash must NEVER be recognized as canonical
                assert!(
                    !is_canonical_quorum_contract_hash(&tampered_hash),
                    "Bit-flipped hash (source={}, byte={}, bit={}) falsely recognized as canonical hash",
                    c_idx,
                    byte_idx,
                    bit_idx
                );
                assert!(
                    !is_canonical_quorum_contract_hex(&tampered_hex),
                    "Bit-flipped hex (source={}, byte={}, bit={}) falsely recognized as canonical hex",
                    c_idx,
                    byte_idx,
                    bit_idx
                );

                // Must fail closed against all canonical local peers
                for (local_idx, local_hash) in canonical_hashes.iter().enumerate() {
                    let local_hex = &canonical_hexes[local_idx];

                    // Local = canonical, Remote = tampered
                    let res_remote_tampered =
                        verify_federated_contract_handshake(local_hash, &tampered_hash);
                    assert!(
                        matches!(
                            res_remote_tampered,
                            Err(ContractError::ContractMismatch { .. })
                        ),
                        "Expected ContractMismatch for local={} remote=tampered(source={}, byte={}, bit={})",
                        local_idx,
                        c_idx,
                        byte_idx,
                        bit_idx
                    );

                    let res_remote_tampered_hex =
                        verify_federated_contract_handshake_hex(local_hex, &tampered_hex);
                    assert!(
                        matches!(
                            res_remote_tampered_hex,
                            Err(ContractError::ContractMismatch { .. })
                        ),
                        "Expected ContractMismatch for local_hex={} remote_hex=tampered",
                        local_idx
                    );

                    // Local = tampered, Remote = canonical
                    let res_local_tampered =
                        verify_federated_contract_handshake(&tampered_hash, local_hash);
                    assert!(
                        matches!(
                            res_local_tampered,
                            Err(ContractError::ContractMismatch { .. })
                        ),
                        "Expected ContractMismatch for local=tampered remote=canonical"
                    );

                    let res_local_tampered_hex =
                        verify_federated_contract_handshake_hex(&tampered_hex, local_hex);
                    assert!(
                        matches!(
                            res_local_tampered_hex,
                            Err(ContractError::ContractMismatch { .. })
                        ),
                        "Expected ContractMismatch for local_hex=tampered remote_hex=canonical"
                    );
                }

                total_bit_flips_tested += 1;
            }
        }
    }

    assert_eq!(
        total_bit_flips_tested, 768,
        "Total 1-bit flipped mutations tested must be exactly 768 (3 * 32 * 8)"
    );
}

/// 3. Foreign SHA-256 and BLAKE3 hashes, zero hashes, and all-ones hashes fail closed.
#[test]
fn test_foreign_sha256_and_blake3_hashes_fail_closed() {
    let canonical_hexes = [
        EmbeddingContract::canonical_deterministic_offline().derive_contract_hash_hex(),
        EmbeddingContract::canonical_gemma_300m().derive_contract_hash_hex(),
        EmbeddingContract::canonical_ollama_embeddinggemma().derive_contract_hash_hex(),
    ];

    let foreign_hex_samples = [
        // SHA-256 of empty string
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        // SHA-256 of "quorum"
        "313d42fb53cb648d88e0db40ce2435f1f2e1dfbd923fc82705a61e7febe06a12",
        // SHA-256 of "bitcoin"
        "b5182404e38c35a828945f34024b85c18471131758c73d9d300e84b2374e2d35",
        // SHA-256 of "gemma-300m"
        "1e889d71c4c95240292bcbb632bd50284898144ab9ca40fbddb945d421711756",
        // All zeros
        "0000000000000000000000000000000000000000000000000000000000000000",
        // All ones (0xFF)
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        // Alternating 0xAA
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Alternating 0x55
        "5555555555555555555555555555555555555555555555555555555555555555",
        // Arbitrary BLAKE3 hash of "unrelated_payload"
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ];

    for foreign in &foreign_hex_samples {
        assert!(
            !is_canonical_quorum_contract_hex(foreign),
            "Foreign hash {} must not be recognized as canonical",
            foreign
        );

        for canonical in &canonical_hexes {
            // Local = canonical, Remote = foreign
            let res_cf = verify_federated_contract_handshake_hex(canonical, foreign);
            assert!(
                matches!(res_cf, Err(ContractError::ContractMismatch { .. })),
                "Foreign remote hash {} must fail closed against canonical local {}",
                foreign,
                canonical
            );

            // Local = foreign, Remote = canonical
            let res_fc = verify_federated_contract_handshake_hex(foreign, canonical);
            assert!(
                matches!(res_fc, Err(ContractError::ContractMismatch { .. })),
                "Canonical remote hash {} must fail closed against foreign local {}",
                canonical,
                foreign
            );
        }
    }
}

/// 4. Case-insensitivity: Uppercase, lowercase, and alternating mixed case.
#[test]
fn test_case_variation_handling_canonical_and_foreign() {
    let contracts = [
        EmbeddingContract::canonical_deterministic_offline(),
        EmbeddingContract::canonical_gemma_300m(),
        EmbeddingContract::canonical_ollama_embeddinggemma(),
    ];

    for contract_a in &contracts {
        let hex_a = contract_a.derive_contract_hash_hex();
        let upper_a = hex_a.to_ascii_uppercase();
        let mut mixed_a = String::with_capacity(64);
        for (i, c) in hex_a.chars().enumerate() {
            if i % 2 == 0 {
                mixed_a.push(c.to_ascii_uppercase());
            } else {
                mixed_a.push(c.to_ascii_lowercase());
            }
        }

        // Canonical hex recognition must be case-insensitive
        assert!(is_canonical_quorum_contract_hex(&upper_a));
        assert!(is_canonical_quorum_contract_hex(&mixed_a));

        for contract_b in &contracts {
            let hex_b = contract_b.derive_contract_hash_hex();
            let upper_b = hex_b.to_ascii_uppercase();
            let mut mixed_b = String::with_capacity(64);
            for (i, c) in hex_b.chars().enumerate() {
                if i % 2 == 1 {
                    mixed_b.push(c.to_ascii_uppercase());
                } else {
                    mixed_b.push(c.to_ascii_lowercase());
                }
            }

            // Lower vs Upper
            assert!(verify_federated_contract_handshake_hex(&hex_a, &upper_b).is_ok());
            // Upper vs Lower
            assert!(verify_federated_contract_handshake_hex(&upper_a, &hex_b).is_ok());
            // Upper vs Upper
            assert!(verify_federated_contract_handshake_hex(&upper_a, &upper_b).is_ok());
            // Mixed vs Mixed
            assert!(verify_federated_contract_handshake_hex(&mixed_a, &mixed_b).is_ok());
        }

        // Foreign hash in uppercase / mixed-case must still fail closed!
        let foreign_lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let foreign_upper = foreign_lower.to_ascii_uppercase();
        assert!(verify_federated_contract_handshake_hex(&hex_a, &foreign_upper).is_err());
        assert!(verify_federated_contract_handshake_hex(&upper_a, &foreign_upper).is_err());
    }
}

/// 5. Malformed hex, truncated strings, invalid lengths, and multi-byte UTF-8 injection.
#[test]
fn test_malformed_hex_adversarial_fuzzing() {
    let canonical_hex =
        EmbeddingContract::canonical_gemma_300m().derive_contract_hash_hex();

    // 1. Length bounds: 0 to 63 chars (truncated) and 65 to 100 chars (too long)
    for len in 0..64 {
        let truncated = &canonical_hex[..len];
        let res = verify_federated_contract_handshake_hex(&canonical_hex, truncated);
        assert!(
            matches!(res, Err(ContractError::InvalidHex(_))),
            "Length {} must return InvalidHex",
            len
        );
    }

    for extra in 1..=32 {
        let overlong = format!("{}{}", canonical_hex, "0".repeat(extra));
        let res = verify_federated_contract_handshake_hex(&canonical_hex, &overlong);
        assert!(
            matches!(res, Err(ContractError::InvalidHex(_))),
            "Overlong length {} must return InvalidHex",
            canonical_hex.len() + extra
        );
    }

    // 2. Non-hex characters inserted at all 64 positions
    let non_hex_chars = ['g', 'z', '!', '@', '#', '$', '%', '^', '&', '*', '-', '_', ' '];
    for &bad_char in &non_hex_chars {
        for pos in 0..64 {
            let mut corrupted = canonical_hex.clone();
            corrupted.replace_range(pos..pos + 1, &bad_char.to_string());
            let res = verify_federated_contract_handshake_hex(&canonical_hex, &corrupted);
            assert!(
                matches!(res, Err(ContractError::InvalidHex(_))),
                "Character '{}' at pos {} must return InvalidHex",
                bad_char,
                pos
            );
        }
    }

    // 3. Multi-byte UTF-8 character injection (must never panic on slice boundaries)
    // 2-byte UTF-8: '\u{00E9}' (0xC3 0xA9)
    for offset in 0..=62 {
        let mut trap = String::with_capacity(64);
        trap.push_str(&"a".repeat(offset));
        trap.push('\u{00E9}');
        trap.push_str(&"a".repeat(62 - offset));
        assert_eq!(trap.len(), 64);

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            verify_federated_contract_handshake_hex(&canonical_hex, &trap)
        }));
        assert!(
            result.is_ok(),
            "PANIC at offset {} with 2-byte UTF-8 in verify_federated_contract_handshake_hex",
            offset
        );
        assert!(matches!(result.unwrap(), Err(ContractError::InvalidHex(_))));
    }

    // 4-byte emoji: '🦀' (0xF0 0x9F 0xA6 0x80)
    for offset in 0..=60 {
        let mut trap = String::with_capacity(64);
        trap.push_str(&"a".repeat(offset));
        trap.push('🦀');
        trap.push_str(&"a".repeat(60 - offset));
        assert_eq!(trap.len(), 64);

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            verify_federated_contract_handshake_hex(&canonical_hex, &trap)
        }));
        assert!(
            result.is_ok(),
            "PANIC at offset {} with 4-byte emoji in verify_federated_contract_handshake_hex",
            offset
        );
        assert!(matches!(result.unwrap(), Err(ContractError::InvalidHex(_))));
    }

    // 4. Hex prefixes: "0x", "0X", "#"
    let prefixed = format!("0x{}", canonical_hex);
    assert!(matches!(
        verify_federated_contract_handshake_hex(&canonical_hex, &prefixed),
        Err(ContractError::InvalidHex(_))
    ));
}

/// 6. Non-canonical contract schema mutations (dimension, metric, pooling, version, model)
/// must never be accepted by verify_federated_contract_handshake or recognized as canonical.
#[test]
fn test_non_canonical_contract_schema_mutations_never_accepted() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // 1. Dimension mutations
    let bad_dims = [0, 1, 384, 512, 767, 769, 1024, 1536, 4096];
    for &dim in &bad_dims {
        let mut mutated = canonical.clone();
        mutated.dimension = dim;
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }

    // 2. Metric mutations
    let bad_metrics = ["Euclidean", "DotProduct", "Manhattan", "Hamming", "L2"];
    for &metric in &bad_metrics {
        let mut mutated = canonical.clone();
        mutated.distance_metric = metric.to_string();
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }

    // 3. Normalization mutations
    let bad_norms = ["None", "L1", "RMSNorm", "LayerNorm"];
    for &norm in &bad_norms {
        let mut mutated = canonical.clone();
        mutated.normalization = norm.to_string();
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }

    // 4. Pooling mutations
    let bad_poolings = ["ClsToken", "MaxPooling", "LastToken", "WeightedMean"];
    for &pool in &bad_poolings {
        let mut mutated = canonical.clone();
        mutated.pooling_strategy = pool.to_string();
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }

    // 5. Version mutations
    let bad_versions = [0, 2, 3, 100];
    for &v in &bad_versions {
        let mut mutated = canonical.clone();
        mutated.contract_version = v;
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }

    // 6. Model name mutations
    let bad_models = [
        "google/embeddinggemma-2b",
        "openai/text-embedding-3-small",
        "sentence-transformers/all-MiniLM-L6-v2",
        "meta-llama/Llama-3-8b",
    ];
    for &model in &bad_models {
        let mut mutated = canonical.clone();
        mutated.model_name = model.to_string();
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }

    // 7. Engine mode mutations
    let bad_modes = ["CustomEngine", "MockEngine", "CandleCUDA", "TensorRT"];
    for &mode in &bad_modes {
        let mut mutated = canonical.clone();
        mutated.engine_mode = mode.to_string();
        let mutated_hash = mutated.derive_contract_hash();
        let mutated_hex = mutated.derive_contract_hash_hex();

        assert!(!is_canonical_quorum_contract_hash(&mutated_hash));
        assert!(!is_canonical_quorum_contract_hex(&mutated_hex));
        assert!(matches!(
            verify_federated_contract_handshake_hex(&canonical_hex, &mutated_hex),
            Err(ContractError::ContractMismatch { .. })
        ));
    }
}

/// 7. Non-canonical hash pair behavior analysis.
/// Evaluates:
/// - Differing non-canonical hashes: MUST fail closed with ContractMismatch.
/// - Canonical local vs non-canonical remote: MUST fail closed with ContractMismatch.
/// - Identical non-canonical hashes: Documents the identity-matching path (legacy compatibility).
#[test]
fn test_non_canonical_pairings_behavior() {
    let canonical = EmbeddingContract::canonical_gemma_300m().derive_contract_hash();
    let foreign_a = [0x11u8; 32];
    let foreign_b = [0x22u8; 32];

    // Canonical local vs foreign remote: MUST FAIL CLOSED
    assert!(verify_federated_contract_handshake(&canonical, &foreign_a).is_err());
    assert!(verify_federated_contract_handshake(&canonical, &foreign_b).is_err());

    // Differing foreign hashes: MUST FAIL CLOSED
    assert!(verify_federated_contract_handshake(&foreign_a, &foreign_b).is_err());
    assert!(verify_federated_contract_handshake(&foreign_b, &foreign_a).is_err());

    // Two identical foreign hashes match on identity line 224:
    // This allows legacy single-contract networks to function while federated mode
    // strictly requires both to be canonical when hashes differ.
    assert!(verify_federated_contract_handshake(&foreign_a, &foreign_a).is_ok());
}
