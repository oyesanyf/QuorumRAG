pub mod alignment;
pub mod consensus;
pub mod extraction;

pub use alignment::ExampleData;
pub use consensus::{ConsensusExtractionResult, LlmFusionArmReport, LlmFusionConsensus};
pub use extraction::{extract_chat_candidates, filter_grounded, ground_extraction, Extraction};

use std::collections::BTreeMap;

/// Helper to parse query-time scalar constraints (e.g. `filetype:pdf`, `ext:rs`, `author:alice`, `date:2026`)
/// to guide `ClassifyIntentNode` and `RetrieveMeshNode`.
pub fn extract_query_metadata_filters(query: &str) -> Option<BTreeMap<String, String>> {
    let mut filters = BTreeMap::new();
    for token in query.split_whitespace() {
        if let Some((key, val)) = token.split_once(':') {
            let k = key.trim().to_lowercase();
            let v = val.trim().to_string();
            if !k.is_empty() && !v.is_empty() {
                match k.as_str() {
                    "filetype" | "ext" | "type" => {
                        filters.insert("filetype".to_string(), v.trim_start_matches('.').to_lowercase());
                    }
                    "author" | "user" | "owner" => {
                        filters.insert("author".to_string(), v);
                    }
                    "date" | "year" | "time" => {
                        filters.insert("date".to_string(), v);
                    }
                    "tier" | "access" => {
                        filters.insert("tier".to_string(), v);
                    }
                    "tag" | "label" => {
                        filters.insert("tag".to_string(), v);
                    }
                    _ => {
                        filters.insert(k, v);
                    }
                }
            }
        }
    }

    if filters.is_empty() {
        None
    } else {
        Some(filters)
    }
}
