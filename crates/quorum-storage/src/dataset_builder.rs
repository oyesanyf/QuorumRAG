//! Dataset Builder for the Opt-In Sovereign AI Training Data Marketplace.
//!
//! Harvests document chunks, extracts parent-document byte windows (0..10,000 bytes),
//! validates citation substring anchors, and formats raw SFT and DPO training pairs.

use crate::error::StorageError;
use quorum_types::DocumentChunk;
use serde::{Deserialize, Serialize};

/// Configuration for harvesting and formatting dataset candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetBuilderConfig {
    pub domain_tags: Vec<String>,
    pub max_records: usize,
    pub parent_window_bytes: usize,
    pub min_token_count: usize,
}

impl Default for DatasetBuilderConfig {
    fn default() -> Self {
        Self {
            domain_tags: vec!["general".to_string()],
            max_records: 100,
            parent_window_bytes: 10_000,
            min_token_count: 64,
        }
    }
}

/// A raw training dataset candidate harvested from storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawDatasetCandidate {
    pub record_id: String,
    pub source_doc_id: String,
    pub prompt: String,
    pub chosen_response: String,
    pub rejected_response: Option<String>,
    pub citations: Vec<(String, String)>,
    pub domain_tags: Vec<String>,
}

pub struct DatasetBuilder;

impl DatasetBuilder {
    /// Extracts a parent window up to `max_bytes` from the chunk or document source file,
    /// falling back to the chunk's text if the file is not on disk or inaccessible.
    pub fn extract_parent_window(chunk: &DocumentChunk, max_bytes: usize) -> String {
        let path = std::path::Path::new(&chunk.file_path);
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(path) {
                let limit = max_bytes.min(content.len());
                let mut end = limit;
                while end > 0 && !content.is_char_boundary(end) {
                    end -= 1;
                }
                return content[..end].to_string();
            }
        }
        // Fallback to chunk text_content
        let text = &chunk.text_content;
        let limit = max_bytes.min(text.len());
        let mut end = limit;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    }

    /// Builds training candidates from a slice of document chunks.
    pub fn build_candidates_from_chunks(
        chunks: &[DocumentChunk],
        config: &DatasetBuilderConfig,
    ) -> Result<Vec<RawDatasetCandidate>, StorageError> {
        let mut candidates = Vec::new();
        for (idx, chunk) in chunks.iter().enumerate() {
            if candidates.len() >= config.max_records {
                break;
            }
            if chunk.text_content.trim().len() < 120 {
                continue;
            }

            let parent_window = Self::extract_parent_window(chunk, config.parent_window_bytes);
            let quote = crate::tantivy_fts_anchor_probe(&chunk.text_content).to_string();
            if quote.is_empty()
                || (!chunk.text_content.contains(&quote) && !parent_window.contains(&quote))
            {
                continue;
            }

            let slice_text = if parent_window.contains(&quote) {
                parent_window
            } else {
                chunk.text_content.clone()
            };

            let record_id = format!("rec-store-{}-{}", chunk.document_id, idx);
            let prompt = format!(
                "Explain the key architectural and factual concepts documented in section {} of {}:",
                chunk.chunk_id, chunk.file_path
            );
            let response = chunk.text_content.clone();

            candidates.push(RawDatasetCandidate {
                record_id,
                source_doc_id: chunk.document_id.clone(),
                prompt,
                chosen_response: response,
                rejected_response: None,
                citations: vec![(slice_text, quote)],
                domain_tags: config.domain_tags.clone(),
            });
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_builder_candidate_harvesting() {
        let text = "QuorumRAG implements decentralized peer verification using Ed25519 signatures, BLAKE3 Merkle integrity proofs, and Reciprocal Rank Fusion ranking. Federated nodes exchange encrypted candidate trajectories and verify strict compliance with local DLP policies.";
        let chunk = DocumentChunk::new(
            "doc-1:0",
            "doc-1",
            "docs/architecture.md",
            1,
            12,
            0,
            vec![0.0; 768],
            text,
            None,
        )
        .unwrap();

        let config = DatasetBuilderConfig {
            domain_tags: vec!["rust-security".to_string(), "p2p-rag".to_string()],
            max_records: 10,
            parent_window_bytes: 10_000,
            min_token_count: 32,
        };

        let candidates = DatasetBuilder::build_candidates_from_chunks(&[chunk], &config).unwrap();
        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.record_id, "rec-store-doc-1-0");
        assert_eq!(cand.source_doc_id, "doc-1");
        assert!(cand.prompt.contains("docs/architecture.md"));
        assert!(cand
            .chosen_response
            .contains("QuorumRAG implements decentralized"));
        assert_eq!(cand.domain_tags, vec!["rust-security", "p2p-rag"]);
        assert_eq!(cand.citations.len(), 1);
        let (slice, quote) = &cand.citations[0];
        assert!(slice.contains(quote));
        assert!(!quote.is_empty());
    }

    #[test]
    fn test_dataset_builder_max_records_and_length_filter() {
        let short_chunk = DocumentChunk::new(
            "doc-short:0",
            "doc-short",
            "docs/short.txt",
            1,
            2,
            0,
            vec![0.0; 768],
            "Too short text.",
            None,
        )
        .unwrap();

        let config = DatasetBuilderConfig::default();
        let candidates =
            DatasetBuilder::build_candidates_from_chunks(&[short_chunk], &config).unwrap();
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_dataset_builder_parent_window_file_reading() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("source_doc.txt");
        let parent_content = "Header: Architecture Specification.\nThis document describes the three-engine airlock de-identification pipeline.\nSection 1: Presidio, GLiNER, and VaultGemma-1B collaborate to eliminate all PII, PHI, and quasi-identifiers.";
        std::fs::write(&file_path, parent_content).unwrap();

        let chunk = DocumentChunk::new(
            "doc-file:0",
            "doc-file",
            file_path.to_str().unwrap(),
            1,
            5,
            0,
            vec![0.0; 768],
            parent_content,
            None,
        )
        .unwrap();

        let parent_window = DatasetBuilder::extract_parent_window(&chunk, 10_000);
        assert_eq!(parent_window, parent_content);

        let capped_window = DatasetBuilder::extract_parent_window(&chunk, 50);
        assert_eq!(capped_window.len(), 50);
    }
}
