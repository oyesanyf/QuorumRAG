//! Empirical Challenger Stress Tests: Contract Handshake Gating Corner Cases.
//!
//! Validates:
//! - Multi-byte UTF-8 injection into 64-byte hex strings across all offsets (0..64)
//! - 4-byte emoji injection into 64-byte hex strings
//! - Fullwidth Unicode lookalikes and embedded whitespace
//! - 0x prefixes and invalid length boundaries
//! - Constant-time comparison robustness and field sensitivity

use quorum_contract::{
    verify_contract_handshake, verify_contract_handshake_hex, ContractError, EmbeddingContract,
};
use std::panic::{self, AssertUnwindSafe};

#[test]
fn test_multibyte_utf8_in_64byte_hex_at_every_single_offset() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // 2-byte UTF-8: '\u{00E9}' (0xC3 0xA9)
    // Slicing at odd or even byte offsets must never panic.
    // Length must be exactly 64 bytes: 62 'a's + 2 bytes = 64 bytes total.
    for offset in 0..=62 {
        let mut trap = String::with_capacity(64);
        trap.push_str(&"a".repeat(offset));
        trap.push('\u{00E9}');
        trap.push_str(&"a".repeat(62 - offset));
        assert_eq!(trap.len(), 64, "Offset {} must produce exactly 64 bytes", offset);

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            verify_contract_handshake_hex(&canonical_hex, &trap)
        }));

        assert!(
            result.is_ok(),
            "PANIC at offset {} when 2-byte UTF-8 placed in 64-byte hex string!",
            offset
        );
        let res = result.unwrap();
        assert!(
            matches!(res, Err(ContractError::InvalidHex(_))),
            "Expected InvalidHex at offset {}, got {:?}",
            offset,
            res
        );
    }
}

#[test]
fn test_4byte_emoji_in_64byte_hex_at_every_offset() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // 4-byte emoji: '🦀' (0xF0 0x9F 0xA6 0x80)
    // 60 'a's + 4 bytes = 64 bytes total.
    for offset in 0..=60 {
        let mut trap = String::with_capacity(64);
        trap.push_str(&"a".repeat(offset));
        trap.push('🦀');
        trap.push_str(&"a".repeat(60 - offset));
        assert_eq!(trap.len(), 64);

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            verify_contract_handshake_hex(&canonical_hex, &trap)
        }));

        assert!(
            result.is_ok(),
            "PANIC at offset {} when 4-byte emoji placed in 64-byte hex string!",
            offset
        );
        let res = result.unwrap();
        assert!(matches!(res, Err(ContractError::InvalidHex(_))));
    }
}

#[test]
fn test_fullwidth_unicode_hex_lookalikes_rejected() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // Fullwidth '０'..'９' (U+FF10..U+FF19) and 'ａ'..'ｆ' (U+FF41..U+FF46)
    let fullwidth_sample = "０１２３４５６７８９ａｂｃｄｅｆ０１２３４５６７８９ａｂｃｄｅｆ";
    assert_ne!(fullwidth_sample.len(), 64); // Fullwidth are 3 bytes each in UTF-8

    let res = verify_contract_handshake_hex(&canonical_hex, fullwidth_sample);
    assert!(matches!(res, Err(ContractError::InvalidHex(_))));
}

#[test]
fn test_hex_handshake_whitespace_and_prefix_rejection() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // 1. "0x" prefix before 64-char hex
    let prefixed = format!("0x{}", canonical_hex);
    let res_prefix = verify_contract_handshake_hex(&canonical_hex, &prefixed);
    assert!(matches!(res_prefix, Err(ContractError::InvalidHex(_))));

    // 2. Whitespace inside the hex string (split at byte 32)
    let mut split_hex = canonical_hex.clone();
    split_hex.insert(32, ' ');
    let res_split = verify_contract_handshake_hex(&canonical_hex, &split_hex);
    assert!(matches!(res_split, Err(ContractError::InvalidHex(_))));

    // 3. Tab character inside the hex string
    let mut tab_hex = canonical_hex.clone();
    tab_hex.insert(16, '\t');
    let res_tab = verify_contract_handshake_hex(&canonical_hex, &tab_hex);
    assert!(matches!(res_tab, Err(ContractError::InvalidHex(_))));

    // 4. Pure whitespace strings
    for ws in ["   ", "\t\t", "\n\n", " \t \r\n "] {
        let res_ws = verify_contract_handshake_hex(&canonical_hex, ws);
        assert!(matches!(res_ws, Err(ContractError::InvalidHex(_))));
    }
}

#[test]
fn test_contract_handshake_case_insensitivity() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let canonical_hex = canonical.derive_contract_hash_hex();

    // Lowercase hex (canonical)
    let lower = canonical_hex.to_ascii_lowercase();
    assert!(verify_contract_handshake_hex(&canonical_hex, &lower).is_ok());

    // Uppercase hex
    let upper = canonical_hex.to_ascii_uppercase();
    assert!(verify_contract_handshake_hex(&canonical_hex, &upper).is_ok());

    // Mixed case alternating
    let mut mixed = String::with_capacity(64);
    for (i, c) in canonical_hex.chars().enumerate() {
        if i % 2 == 0 {
            mixed.push(c.to_ascii_uppercase());
        } else {
            mixed.push(c.to_ascii_lowercase());
        }
    }
    assert!(verify_contract_handshake_hex(&canonical_hex, &mixed).is_ok());
}

#[test]
fn test_contract_constant_time_comparison_all_zeros_and_ones() {
    let zero_hash = [0u8; 32];
    let ones_hash = [0xffu8; 32];

    // Comparing identical zero hashes
    assert!(verify_contract_handshake(&zero_hash, &zero_hash).is_ok());

    // Comparing zero vs ones
    let res = verify_contract_handshake(&zero_hash, &ones_hash);
    assert!(matches!(res, Err(ContractError::ContractMismatch { .. })));

    // Differing only by last byte
    let mut almost_zero = [0u8; 32];
    almost_zero[31] = 1;
    let res2 = verify_contract_handshake(&zero_hash, &almost_zero);
    assert!(matches!(res2, Err(ContractError::ContractMismatch { .. })));
}
