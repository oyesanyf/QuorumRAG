//! Deterministic BLAKE3 key derivation for QuorumRAG Multi-Layer Caching.

use quorum_storage::SearchMode;
use crate::types::SynthesisModelFamily;

/// Derives the 32-byte deterministic BLAKE3 cache key for text embeddings.
///
/// Formula:
/// BLAKE3("QUORUM_EMBEDDING_CACHE_V1\n" || contract_hash (32 bytes) || "\n" || normalized_text)
pub fn derive_embedding_cache_key(contract_hash: &[u8; 32], raw_text: &str) -> [u8; 32] {
    let normalized = normalize_text_for_caching(raw_text);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"QUORUM_EMBEDDING_CACHE_V1\n");
    hasher.update(contract_hash);
    hasher.update(b"\n");
    hasher.update(normalized.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Derives the 32-byte deterministic BLAKE3 cache key for query retrieval & synthesis.
///
/// Layout:
/// BLAKE3("QUORUM_QUERY_CACHE_V1\n" || normalized_query || "\n" || search_mode (1 byte) ||
///        model_family (1 byte) || access_tier (1 byte) || index_epoch (8 bytes LE))
pub fn derive_query_cache_key(
    query_text: &str,
    search_mode: SearchMode,
    model_family: SynthesisModelFamily,
    access_tier: u8,
    index_epoch: u64,
) -> [u8; 32] {
    let normalized = normalize_text_for_caching(query_text);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"QUORUM_QUERY_CACHE_V1\n");
    hasher.update(normalized.as_bytes());
    hasher.update(b"\n");

    let mode_byte = match search_mode {
        SearchMode::Keyword => 0u8,
        SearchMode::Vector => 1u8,
        SearchMode::Hybrid => 2u8,
    };
    hasher.update(&[mode_byte]);

    let family_byte = match model_family {
        SynthesisModelFamily::Glm4Agentic => 0u8,
        SynthesisModelFamily::Qwen25Code => 1u8,
        SynthesisModelFamily::GemmaProse => 2u8,
        SynthesisModelFamily::AutoFusion => 3u8,
        SynthesisModelFamily::Gemma4_26b => 4u8,
    };
    hasher.update(&[family_byte]);
    hasher.update(&[access_tier]);
    hasher.update(&index_epoch.to_le_bytes());

    *hasher.finalize().as_bytes()
}

/// Normalizes query and chunk text for deterministic caching:
/// Trims leading/trailing whitespace, converts multiple spaces/tabs/newlines to a single space,
/// and converts ASCII to lowercase while preserving non-ASCII unicode boundaries.
pub fn normalize_text_for_caching(text: &str) -> String {
    let trimmed = text.trim();
    let mut normalized = String::with_capacity(trimmed.len());
    let mut in_whitespace = false;

    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !in_whitespace {
                normalized.push(' ');
                in_whitespace = true;
            }
        } else {
            normalized.extend(ch.to_lowercase());
            in_whitespace = false;
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_normalization() {
        assert_eq!(normalize_text_for_caching("  Hello   World \n"), "hello world");
        assert_eq!(normalize_text_for_caching("QUERY\t\ttest"), "query test");
    }

    #[test]
    fn test_derive_embedding_cache_key() {
        let hash = [1u8; 32];
        let k1 = derive_embedding_cache_key(&hash, "Hello world");
        let k2 = derive_embedding_cache_key(&hash, "  hello  world  ");
        assert_eq!(k1, k2);

        let k3 = derive_embedding_cache_key(&hash, "different text");
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_derive_query_cache_key() {
        let k1 = derive_query_cache_key(
            "What is QuorumRAG?",
            SearchMode::Hybrid,
            SynthesisModelFamily::Glm4Agentic,
            1,
            100,
        );
        let k2 = derive_query_cache_key(
            "  what is quorumrag? ",
            SearchMode::Hybrid,
            SynthesisModelFamily::Glm4Agentic,
            1,
            100,
        );
        assert_eq!(k1, k2);

        // Change epoch -> different key!
        let k_epoch_bump = derive_query_cache_key(
            "What is QuorumRAG?",
            SearchMode::Hybrid,
            SynthesisModelFamily::Glm4Agentic,
            1,
            101,
        );
        assert_ne!(k1, k_epoch_bump);

        // Change tier -> different key!
        let k_tier = derive_query_cache_key(
            "What is QuorumRAG?",
            SearchMode::Hybrid,
            SynthesisModelFamily::Glm4Agentic,
            2,
            100,
        );
        assert_ne!(k1, k_tier);
    }
}
