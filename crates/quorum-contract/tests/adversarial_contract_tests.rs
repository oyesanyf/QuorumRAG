//! Adversarial Stress Tests for QuorumRAG Gemma Embedding Contract & Offline Engine.
//!
//! Validates fail-closed contract gating against mutated dimensions, corrupted hashes,
//! bit flips, distance metric mutations, hex anomalies, and vector normalization stability.

use quorum_contract::{
    cosine_similarity, verify_contract_handshake, verify_contract_handshake_hex,
    ContractError, DeterministicOfflineEngine, EmbeddingContract, EmbeddingGenerator,
    GemmaCandleEngine,
};

#[test]
fn test_mutated_dimensions_rejection() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hash = canonical.derive_contract_hash();

    // Mutate dimensions: 767, 769, 0, 1, 512, 1024, 1536
    let test_dims = [767, 769, 0, 1, 512, 1024, 1536, usize::MAX];
    for dim in test_dims {
        let mut mutated = canonical.clone();
        mutated.dimension = dim;
        let mutated_hash = mutated.derive_contract_hash();

        // 1. Hash MUST diverge
        assert_ne!(
            canonical_hash, mutated_hash,
            "Dimension {} produced identical hash to canonical 768",
            dim
        );

        // 2. Handshake MUST fail closed with ContractMismatch
        let res = verify_contract_handshake(&canonical_hash, &mutated_hash);
        assert!(
            matches!(res, Err(ContractError::ContractMismatch { .. })),
            "Expected ContractMismatch for dim {}",
            dim
        );
    }
}

#[test]
fn test_mutated_parameters_handshake_rejection() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hash = canonical.derive_contract_hash();

    // 1. Mutated distance metrics
    let bad_metrics = ["DotProduct", "Euclidean", "cosine", "Manhattan", "", "Cosine "];
    for metric in bad_metrics {
        let mut m = canonical.clone();
        m.distance_metric = metric.to_string();
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }

    // 2. Mutated normalization
    let bad_norms = ["L1", "None", "l2", "L2 ", "softmax", "RMSNorm"];
    for norm in bad_norms {
        let mut m = canonical.clone();
        m.normalization = norm.to_string();
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }

    // 3. Mutated pooling strategy
    let bad_poolings = ["ClsToken", "MaxPooling", "None", "meanpooling", "LastToken"];
    for pool in bad_poolings {
        let mut m = canonical.clone();
        m.pooling_strategy = pool.to_string();
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }

    // 4. Mutated model name
    let bad_models = [
        "google/embeddinggemma-2b",
        "google/embeddinggemma-7b",
        "gemma",
        "google/embeddinggemma-300m-v2",
        "",
    ];
    for model in bad_models {
        let mut m = canonical.clone();
        m.model_name = model.to_string();
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }

    // 5. Mutated contract version
    for v in [0, 2, 3, u32::MAX] {
        let mut m = canonical.clone();
        m.contract_version = v;
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }

    // 6. Mutated max sequence length
    for len in [128, 256, 1024, 2048] {
        let mut m = canonical.clone();
        m.max_sequence_length = len;
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }

    // 7. Mutated engine mode (e.g. DeterministicOffline vs GemmaCandle)
    for mode in ["DeterministicOffline", "MockEngine", "CandleCUDA", "", "gemma_candle"] {
        let mut m = canonical.clone();
        m.engine_mode = mode.to_string();
        let h = m.derive_contract_hash();
        assert_ne!(canonical_hash, h);
        assert!(verify_contract_handshake(&canonical_hash, &h).is_err());
    }
}

#[test]
fn test_all_256_single_bit_flip_tampering() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hash = canonical.derive_contract_hash();

    // Iterate over every single byte (0..32) and every single bit (0..8)
    let mut total_tested = 0;
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut tampered = canonical_hash;
            tampered[byte_idx] ^= 1 << bit_idx;

            assert_ne!(
                canonical_hash, tampered,
                "Bit flip at byte {}, bit {} failed to change hash",
                byte_idx, bit_idx
            );

            let res = verify_contract_handshake(&canonical_hash, &tampered);
            match res {
                Err(ContractError::ContractMismatch { local_hex, remote_hex }) => {
                    assert_eq!(local_hex.len(), 64);
                    assert_eq!(remote_hex.len(), 64);
                    assert_ne!(local_hex, remote_hex);
                }
                other => panic!(
                    "Expected ContractMismatch for bit flip at byte {}, bit {}, got {:?}",
                    byte_idx, bit_idx, other
                ),
            }
            total_tested += 1;
        }
    }
    assert_eq!(total_tested, 256);
}

#[test]
fn test_hex_handshake_tampering_and_adversarial_lengths() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // 1. Empty hex string
    assert!(verify_contract_handshake_hex(&canonical_hex, "").is_err());

    // 2. 63 characters (too short)
    let short_hex = &canonical_hex[..63];
    assert!(verify_contract_handshake_hex(&canonical_hex, short_hex).is_err());

    // 3. 65 characters (too long)
    let long_hex = format!("{}a", canonical_hex);
    assert!(verify_contract_handshake_hex(&canonical_hex, &long_hex).is_err());

    // 4. Non-hex characters
    let mut bad_chars = canonical_hex.clone();
    bad_chars.replace_range(10..11, "z");
    assert!(verify_contract_handshake_hex(&canonical_hex, &bad_chars).is_err());

    // 5. Uppercase hex (should succeed because parse_hex handles standard hex digits)
    let upper_hex = canonical_hex.to_ascii_uppercase();
    assert!(verify_contract_handshake_hex(&canonical_hex, &upper_hex).is_ok());

    // 6. Adversarial multi-byte UTF-8 payload matching 64 bytes
    // Craft 62 'a's + '\u{00E9}' (2-byte UTF-8: 0xC3 0xA9) = 64 bytes total
    let mut utf8_trap = "a".repeat(62);
    utf8_trap.push('\u{00E9}');
    assert_eq!(utf8_trap.len(), 64); // 64 bytes!

    let catch_result = std::panic::catch_unwind(|| {
        verify_contract_handshake_hex(&canonical_hex, &utf8_trap)
    });
    assert!(catch_result.is_ok(), "verify_contract_handshake_hex must NOT panic on 64-byte UTF-8 string!");
    let handshake_res = catch_result.unwrap();
    assert!(handshake_res.is_err(), "Must reject invalid hex containing UTF-8 characters");

    // 7. Adversarial multi-byte UTF-8 at ODD byte offset (61 'a's + '\u{00E9}' + 1 'a' = 64 bytes)
    // Here, '\u{00E9}' is at byte indices 61..63. Slicing at index 62 cuts into character boundary.
    let mut odd_trap = "a".repeat(61);
    odd_trap.push('\u{00E9}');
    odd_trap.push('a');
    assert_eq!(odd_trap.len(), 64);

    let catch_odd = std::panic::catch_unwind(|| {
        verify_contract_handshake_hex(&canonical_hex, &odd_trap)
    });
    assert!(
        catch_odd.is_ok(),
        "CRITICAL BUG DETECTED: verify_contract_handshake_hex PANICKED when 64-byte input has multi-byte UTF-8 at odd byte index!"
    );

}

#[test]
fn test_vector_normalization_100_random_texts_stress() {
    let engine = DeterministicOfflineEngine::new();
    assert_eq!(engine.dimension(), 768);

    // Generate 100 diverse inputs
    let words = [
        "quantum", "neural", "vector", "retrieval", "augmented",
        "generation", "quorum", "consensus", "blake3", "cryptography",
        "federated", "search", "lancedb", "tantivy", "peer",
        "mesh", "zeroize", "memory", "access", "tier",
        "kernel", "isolation", "appcontainer", "scatter", "gather",
    ];

    for i in 0..100 {
        // Construct synthetic text of varying lengths and token combinations
        let mut prompt = String::new();
        let word_count = (i % 25) + 1;
        for j in 0..word_count {
            let idx = (i * 7 + j * 13) % words.len();
            prompt.push_str(words[idx]);
            prompt.push(' ');
        }

        let vector = engine.embed_text(&prompt).expect("embed_text failed");

        // 1. Dimension must be strictly 768
        assert_eq!(
            vector.len(),
            768,
            "Input {} produced vector of length {}, expected 768",
            i,
            vector.len()
        );

        // 2. Compute L2 norm: sqrt(sum(x^2))
        let mut sum_sq = 0.0f64;
        for &val in &vector {
            assert!(!val.is_nan(), "Input {} contains NaN in vector", i);
            assert!(!val.is_infinite(), "Input {} contains Inf in vector", i);
            sum_sq += (val as f64) * (val as f64);
        }
        let norm = sum_sq.sqrt();

        // 3. Vector length must be strictly 1.0 +/- 1e-4
        let diff = (norm - 1.0).abs();
        assert!(
            diff < 1e-4,
            "Input {} vector L2 norm {} deviates from 1.0 by {} (exceeds 1e-4)",
            i,
            norm,
            diff
        );

        // 4. Deterministic Repeatability: re-running embed_text produces exact bitwise match
        let vector2 = engine.embed_text(&prompt).expect("second embed failed");
        assert_eq!(vector, vector2, "Input {} non-deterministic embedding", i);

        // 5. Cosine similarity with itself must equal 1.0 +/- 1e-5
        let sim_self = cosine_similarity(&vector, &vector).expect("self cosine similarity");
        assert!(
            (sim_self - 1.0).abs() < 1e-5,
            "Input {} self cosine similarity {} deviates from 1.0",
            i,
            sim_self
        );
    }
}

#[test]
fn test_edge_case_inputs_and_properties() {
    let engine = DeterministicOfflineEngine::new();

    // 1. Empty string
    let v_empty = engine.embed_text("").expect("empty text");
    assert_eq!(v_empty.len(), 768);
    let norm_empty: f32 = v_empty.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm_empty - 1.0).abs() < 1e-4);

    // 2. Whitespace only
    let v_ws = engine.embed_text("   \t\r\n   ").expect("whitespace");
    assert_eq!(v_ws.len(), 768);
    let norm_ws: f32 = v_ws.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm_ws - 1.0).abs() < 1e-4);

    // 3. Punctuation only
    let v_punct = engine.embed_text("!@#$%^&*()_+-=[]{}|;':\",./<>?").expect("punct");
    assert_eq!(v_punct.len(), 768);

    // 4. Unicode / CJK / Emojis
    let v_unicode = engine.embed_text("Retriever 检索 🤖 🚀 🌟 🦀").expect("unicode");
    assert_eq!(v_unicode.len(), 768);
    let norm_uni: f32 = v_unicode.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm_uni - 1.0).abs() < 1e-4);

    // 5. Huge text (100,000 characters)
    let huge_text = "lorem ipsum dolor sit amet ".repeat(4000);
    let v_huge = engine.embed_text(&huge_text).expect("huge text");
    assert_eq!(v_huge.len(), 768);
    let norm_huge: f32 = v_huge.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm_huge - 1.0).abs() < 1e-4);

    // 6. Text with null bytes
    let v_null = engine.embed_text("hello\0world\0test").expect("null byte text");
    assert_eq!(v_null.len(), 768);

    // 7. Semantic overlap property
    let v_a = engine.embed_text("rust systems programming and memory safety").expect("a");
    let v_b = engine.embed_text("rust memory safety and systems language").expect("b");
    let v_c = engine.embed_text("astronomy telescope planetary observation galaxy").expect("c");

    let sim_ab = cosine_similarity(&v_a, &v_b).expect("sim ab");
    let sim_ac = cosine_similarity(&v_a, &v_c).expect("sim ac");

    assert!(
        sim_ab > sim_ac,
        "Related texts (sim={}) must have higher similarity than unrelated (sim={})",
        sim_ab,
        sim_ac
    );

    // 8. Dimension mismatch in cosine_similarity
    let short_vec = vec![0.5f32; 767];
    let res = cosine_similarity(&v_a, &short_vec);
    assert!(matches!(res, Err(ContractError::DimensionMismatch { expected: 768, actual: 767 })));
}

#[test]
fn test_candle_engine_initialization_and_fallback() {
    let candle_engine = GemmaCandleEngine::new().expect("candle engine init");
    assert_eq!(candle_engine.dimension(), 768);
    assert!(!candle_engine.is_neural_loaded());

    let vec = candle_engine.embed_text("test query").expect("candle embed");
    assert_eq!(vec.len(), 768);
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4);
}
