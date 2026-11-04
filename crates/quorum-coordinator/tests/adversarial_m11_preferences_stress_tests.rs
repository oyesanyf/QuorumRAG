//! Adversarial Empirical Stress Suite for Milestone M11: UiPreferencesConfig / ChatGptUiSettings Serde
//! Challenger: Challenger M11 1 (critic, specialist)
//!
//! Evaluates the following adversarial dimensions:
//! 1. Empty JSON `{}` Deserialization: Validates that all default fields, booleans, and budgets populate seamlessly.
//! 2. Legacy Field Names: Validates backward compatibility for `agentic_loop_enabled` and `agentic_chunk_size`.
//! 3. New Aliases: Validates `deep_research`, `parent_doc_retrieval`, `map_reduce`, `agentic_loop_chaining`, `agentic_loop_chunk_size`.
//! 4. Extreme Values Stress: Validates boundary values (0, 256, 512, 262144, 1_000_000_000, usize::MAX).
//! 5. Unmodeled Extra Keys: Validates that dynamic / unmodeled keys correctly flatten into the `extra` HashMap without deserialization failure.
//! 6. Fail-Closed Serde Type Mismatches: Validates that invalid strings, negatives, and type violations fail cleanly with Err.
//! 7. Round-trip Invariant: Validates full canonical serialization and re-deserialization round-trip fidelity.

use quorum_coordinator::{ChatGptUiSettings, UiPreferencesConfig};
use serde_json::{json, Value};

#[test]
fn test_serde_empty_json_defaults() {
    let empty_json = json!({});
    let parsed: UiPreferencesConfig =
        serde_json::from_value(empty_json).expect("Deserialization from empty JSON must not fail");

    assert_eq!(
        parsed.max_output_tokens, 262144,
        "max_output_tokens must default to 262144"
    );
    assert!(
        parsed.agentic_loop_enabled,
        "agentic_loop_enabled must default to true"
    );
    assert_eq!(
        parsed.agentic_chunk_size, 4096,
        "agentic_chunk_size must default to 4096"
    );
    assert_eq!(
        parsed.agentic_strategy, "auto_continuation",
        "agentic_strategy must default to 'auto_continuation'"
    );
    assert!(
        parsed.deep_research_iterative_rag,
        "deep_research_iterative_rag must default to true"
    );
    assert!(
        parsed.parent_document_retrieval,
        "parent_document_retrieval must default to true"
    );
    assert!(
        parsed.map_reduce_fact_extraction,
        "map_reduce_fact_extraction must default to true"
    );
    assert!(
        parsed.extra.is_empty(),
        "extra HashMap must be empty on empty JSON"
    );
}

#[test]
fn test_serde_legacy_field_names() {
    let legacy_payload = json!({
        "agentic_loop_enabled": false,
        "agentic_chunk_size": 2048,
        "agentic_strategy": "multi_part_assembly"
    });

    let parsed: UiPreferencesConfig = serde_json::from_value(legacy_payload)
        .expect("Deserialization with legacy field names must succeed");

    assert!(
        !parsed.agentic_loop_enabled,
        "agentic_loop_enabled must parse legacy false"
    );
    assert_eq!(
        parsed.agentic_chunk_size, 2048,
        "agentic_chunk_size must parse legacy 2048"
    );
    assert_eq!(
        parsed.agentic_strategy, "multi_part_assembly",
        "agentic_strategy must parse legacy string"
    );
    // Unspecified fields must adopt default values
    assert!(parsed.deep_research_iterative_rag);
    assert!(parsed.parent_document_retrieval);
    assert!(parsed.map_reduce_fact_extraction);
    assert_eq!(parsed.max_output_tokens, 262144);
}

#[test]
fn test_serde_new_aliases() {
    let alias_payload = json!({
        "deep_research": false,
        "parent_doc_retrieval": false,
        "map_reduce": false,
        "agentic_loop_chaining": false,
        "agentic_loop_chunk_size": 8192
    });

    let parsed: UiPreferencesConfig = serde_json::from_value(alias_payload)
        .expect("Deserialization with new aliases must succeed");

    assert!(
        !parsed.deep_research_iterative_rag,
        "alias deep_research must set deep_research_iterative_rag to false"
    );
    assert!(
        !parsed.parent_document_retrieval,
        "alias parent_doc_retrieval must set parent_document_retrieval to false"
    );
    assert!(
        !parsed.map_reduce_fact_extraction,
        "alias map_reduce must set map_reduce_fact_extraction to false"
    );
    assert!(
        !parsed.agentic_loop_enabled,
        "alias agentic_loop_chaining must set agentic_loop_enabled to false"
    );
    assert_eq!(
        parsed.agentic_chunk_size, 8192,
        "alias agentic_loop_chunk_size must set agentic_chunk_size to 8192"
    );

    // Verify mixed canonical and alias names in a single payload
    let mixed_payload = json!({
        "deep_research_iterative_rag": true,
        "parent_doc_retrieval": false,
        "map_reduce_fact_extraction": true,
        "agentic_loop_chaining": true,
        "agentic_chunk_size": 16384
    });

    let mixed_parsed: UiPreferencesConfig = serde_json::from_value(mixed_payload)
        .expect("Deserialization with mixed canonical and alias names must succeed");

    assert!(mixed_parsed.deep_research_iterative_rag);
    assert!(!mixed_parsed.parent_document_retrieval);
    assert!(mixed_parsed.map_reduce_fact_extraction);
    assert!(mixed_parsed.agentic_loop_enabled);
    assert_eq!(mixed_parsed.agentic_chunk_size, 16384);
}

#[test]
fn test_serde_extreme_values_and_token_boundaries() {
    // 1. Minimum bound: 0
    let zero_payload = json!({
        "max_output_tokens": 0,
        "agentic_chunk_size": 0
    });
    let zero_parsed: UiPreferencesConfig = serde_json::from_value(zero_payload)
        .expect("0 max_output_tokens and chunk_size must deserialize cleanly");
    assert_eq!(zero_parsed.max_output_tokens, 0);
    assert_eq!(zero_parsed.agentic_chunk_size, 0);

    // 2. Micro budget: 256
    let micro_payload = json!({ "max_output_tokens": 256 });
    let micro_parsed: UiPreferencesConfig = serde_json::from_value(micro_payload).unwrap();
    assert_eq!(micro_parsed.max_output_tokens, 256);

    // 3. Short summary: 512
    let short_payload = json!({ "max_output_tokens": 512 });
    let short_parsed: UiPreferencesConfig = serde_json::from_value(short_payload).unwrap();
    assert_eq!(short_parsed.max_output_tokens, 512);

    // 4. Default production: 262144
    let max_prod_payload = json!({ "max_output_tokens": 262144 });
    let max_prod_parsed: UiPreferencesConfig = serde_json::from_value(max_prod_payload).unwrap();
    assert_eq!(max_prod_parsed.max_output_tokens, 262144);

    // 5. Very large numbers: 1_000_000_000
    let large_payload = json!({
        "max_output_tokens": 1_000_000_000usize,
        "agentic_chunk_size": 500_000usize
    });
    let large_parsed: UiPreferencesConfig = serde_json::from_value(large_payload).unwrap();
    assert_eq!(large_parsed.max_output_tokens, 1_000_000_000);
    assert_eq!(large_parsed.agentic_chunk_size, 500_000);

    // 6. Max integer bound: usize::MAX
    let max_usize_payload = json!({
        "max_output_tokens": usize::MAX,
        "agentic_chunk_size": usize::MAX
    });
    let max_usize_parsed: UiPreferencesConfig = serde_json::from_value(max_usize_payload).unwrap();
    assert_eq!(max_usize_parsed.max_output_tokens, usize::MAX);
    assert_eq!(max_usize_parsed.agentic_chunk_size, usize::MAX);
}

#[test]
fn test_serde_unmodeled_keys_in_extra_hashmap() {
    let unmodeled_payload = json!({
        "deep_research": true,
        "max_output_tokens": 8192,
        "custom_experimental_prm": true,
        "quantum_security_key": "x9910-blake3",
        "arbitrary_threshold_score": 0.994,
        "nested_custom_config": {
            "cluster_nodes": ["node-1", "node-2"],
            "retry_limit": 5
        }
    });

    let parsed: UiPreferencesConfig = serde_json::from_value(unmodeled_payload)
        .expect("Deserialization with unmodeled keys must not fail");

    // Verify modeled fields
    assert!(parsed.deep_research_iterative_rag);
    assert_eq!(parsed.max_output_tokens, 8192);

    // Verify unmodeled keys collected into extra
    assert_eq!(
        parsed.extra.get("custom_experimental_prm"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        parsed.extra.get("quantum_security_key"),
        Some(&Value::String("x9910-blake3".to_string()))
    );
    assert_eq!(
        parsed.extra.get("arbitrary_threshold_score"),
        Some(&json!(0.994))
    );
    let nested = parsed.extra.get("nested_custom_config").unwrap();
    assert_eq!(nested["retry_limit"], 5);
    assert_eq!(nested["cluster_nodes"][0], "node-1");

    // Modeled fields must NOT be in extra
    assert!(!parsed.extra.contains_key("deep_research"));
    assert!(!parsed.extra.contains_key("deep_research_iterative_rag"));
    assert!(!parsed.extra.contains_key("max_output_tokens"));

    // Serialization round-trip must preserve extra keys
    let serialized = serde_json::to_string(&parsed).expect("Serialization failed");
    let round_trip: UiPreferencesConfig =
        serde_json::from_str(&serialized).expect("Re-deserialization failed");

    assert_eq!(
        round_trip.extra.get("quantum_security_key"),
        Some(&Value::String("x9910-blake3".to_string()))
    );
    assert_eq!(
        round_trip.extra.get("custom_experimental_prm"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn test_serde_fail_closed_on_type_mismatches() {
    // String instead of integer for max_output_tokens
    let invalid_token_type = json!({ "max_output_tokens": "unlimited" });
    let err1 = serde_json::from_value::<UiPreferencesConfig>(invalid_token_type);
    assert!(err1.is_err(), "String in integer field must fail closed");

    // String instead of boolean for deep_research
    let invalid_bool_type = json!({ "deep_research": "enabled" });
    let err2 = serde_json::from_value::<UiPreferencesConfig>(invalid_bool_type);
    assert!(err2.is_err(), "String in boolean field must fail closed");

    // Negative integer for unsigned max_output_tokens
    let negative_token_type = json!({ "max_output_tokens": -500 });
    let err3 = serde_json::from_value::<UiPreferencesConfig>(negative_token_type);
    assert!(err3.is_err(), "Negative number in usize field must fail closed");
}

#[test]
fn test_type_alias_equivalence() {
    // UiPreferencesConfig and ChatGptUiSettings must be identical types
    let a: UiPreferencesConfig = UiPreferencesConfig::default();
    let b: ChatGptUiSettings = a;
    assert_eq!(b.max_output_tokens, 262144);
    assert!(b.deep_research_iterative_rag);
    assert!(b.parent_document_retrieval);
    assert!(b.map_reduce_fact_extraction);
}
