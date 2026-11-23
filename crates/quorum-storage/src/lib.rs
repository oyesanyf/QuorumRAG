//! # QuorumRAG Storage Engine
//!
//! Production-grade embedded vector and full-text search engine for QuorumRAG.
//!
//! ## Architecture & Arrow Isolation
//! All `arrow-array`, `arrow-schema`, `lancedb`, and `tantivy` dependencies are
//! strictly encapsulated inside crate-internal `pub(crate)` modules.
//! ZERO Arrow or LanceDB types are exposed in the public interface.
//!
//! ## Features
//! - Embedded LanceDB vector storage with Cosine similarity and SQL pre-filtering pushdown (`only_if`).
//! - Co-located Tantivy BM25 full-text search with numeric range filtering over access tiers.
//! - Storage-level Reciprocal Rank Fusion (RRF) combining vector and lexical rankings.
//! - Automated Level-2 BLAKE3 deduplication on insertion.
//! - Parquet fragment compaction and version pruning.

pub(crate) mod arrow_interop;
pub mod config;
pub mod dataset_builder;
pub mod document_catalog;
pub mod engine;
pub mod error;
pub mod query_framing;
pub(crate) mod tantivy_fts;
pub(crate) mod vector_store;

pub use config::StorageConfig;
pub use dataset_builder::{DatasetBuilder, DatasetBuilderConfig, RawDatasetCandidate};
pub use document_catalog::{
    derive_work_cluster_id, CatalogFileIdentity, DocumentCatalog, DocumentCatalogEntry,
};
pub use engine::{
    CompactionStats, PrefixPurgeReport, PrefixTierUpdateReport, SearchMode, StorageEngine,
    StorageSearchQuery,
};
pub use error::StorageError;
pub use tantivy_fts::DistinctWorkHit;

pub(crate) fn file_path_compare_key(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let unc_rewritten: Option<String> = {
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with(r"\\?\unc\") || lower.starts_with("//?/unc/") {
            Some(format!(r"\\{}", &trimmed[8..]))
        } else if lower.starts_with(r"\\?\") || lower.starts_with("//?/") {
            Some(trimmed[4..].to_string())
        } else {
            None
        }
    };
    let effective = unc_rewritten.as_deref().unwrap_or(trimmed);

    if let Ok(norm) = quorum_types::normalize_prefix_for_match(effective) {
        return norm;
    }

    let bytes = effective.as_bytes();
    let is_win_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let is_unc = effective.starts_with(r"\\") || effective.starts_with("//");
    if cfg!(windows) || is_win_drive || is_unc {
        let replaced = effective.replace('/', "\\");
        let mut out = String::with_capacity(replaced.len());
        let mut chars = replaced.chars().peekable();
        if replaced.starts_with(r"\\") {
            out.push_str(r"\\");
            while matches!(chars.peek(), Some('\\')) {
                chars.next();
            }
        }
        let mut prev_sep = false;
        for ch in chars {
            if ch == '\\' {
                if !prev_sep {
                    out.push('\\');
                }
                prev_sep = true;
            } else {
                out.push(ch.to_ascii_lowercase());
                prev_sep = false;
            }
        }
        if out.len() > 3 && out.ends_with('\\') {
            out.pop();
        }
        out
    } else {
        let mut out = String::with_capacity(effective.len());
        let mut prev_sep = false;
        for ch in effective.chars() {
            if ch == '/' || ch == '\\' {
                if !prev_sep {
                    out.push('/');
                }
                prev_sep = true;
            } else {
                out.push(ch);
                prev_sep = false;
            }
        }
        if out.len() > 1 && out.ends_with('/') {
            out.pop();
        }
        out
    }
}

pub(crate) fn tantivy_fts_anchor_probe(anchor_text: &str) -> &str {
    let trimmed = anchor_text.trim();
    if !trimmed.starts_with("[Document:") && !trimmed.starts_with("[Image Document:") {
        let mut end = trimmed.len().min(96);
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        return trimmed[..end].trim();
    }
    // Skip synthetic header lines to locate body text in raw parent document
    for line in trimmed.lines().skip(1) {
        let l = line.trim();
        if l.is_empty()
            || l.starts_with("Path:")
            || l.starts_with("Author:")
            || l.starts_with("Title:")
            || l.starts_with("Section:")
        {
            continue;
        }
        let mut end = l.len().min(96);
        while end > 0 && !l.is_char_boundary(end) {
            end -= 1;
        }
        return l[..end].trim();
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::file_path_compare_key;

    #[test]
    fn t5_file_path_compare_key_unc_verbatim_parity() {
        let plain = file_path_compare_key(r"\\Fileserver\Share\Cloud\Secret.txt");
        let fwd = file_path_compare_key("//fileserver/share/cloud/secret.txt");
        let verb = file_path_compare_key(r"\\?\UNC\Fileserver\Share\Cloud\Secret.txt");
        let verb_fwd = file_path_compare_key("//?/unc/Fileserver/Share/Cloud/Secret.txt");

        assert_eq!(plain, r"\\fileserver\share\cloud\secret.txt");
        assert_eq!(fwd, plain);
        assert_eq!(verb, plain);
        assert_eq!(verb_fwd, plain);
    }
}
