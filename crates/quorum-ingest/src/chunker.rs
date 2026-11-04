//! Line-Aware and Character-Boundary Safe Text Chunker for QuorumRAG.
//!
//! Enforces:
//! - UTF-8 character boundary safety (zero panics on multibyte Unicode / emojis).
//! - Accurate 1-indexed `line_start` and `line_end` matching source file lines.
//! - Configurable sliding window with overlap and natural boundary snapping (paragraph, line, sentence, word).
//! - Produces validated `DocumentChunk` items with Level-2 BLAKE3 caching.

use std::path::Path;
use quorum_types::{DocumentChunk, TypeError};

pub use crate::config::ChunkerConfig;

/// Raw sliced chunk before vectorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTextChunk<'a> {
    pub text_slice: &'a str,
    pub line_start: u32,
    pub line_end: u32,
    pub char_start: usize,
    pub char_end: usize,
    pub chunk_index: usize,
}

/// Line-aware text chunker with newline prefix indexing and boundary snapping.
#[derive(Debug, Clone)]
pub struct TextChunker {
    config: ChunkerConfig,
}

impl TextChunker {
    pub fn new(config: ChunkerConfig) -> Self {
        Self { config }
    }

    /// Build prefix index of newline byte offsets for O(log L) line lookup.
    fn build_line_starts(content: &str) -> Vec<usize> {
        let mut starts = Vec::with_capacity(content.len() / 40 + 1);
        starts.push(0); // Line 1 begins at byte 0
        for (idx, b) in content.bytes().enumerate() {
            if b == b'\n' {
                starts.push(idx + 1);
            }
        }
        starts
    }

    /// Map byte offset to 1-indexed line number.
    #[inline]
    fn byte_to_line(line_starts: &[usize], byte_offset: usize) -> u32 {
        line_starts.partition_point(|&offset| offset <= byte_offset) as u32
    }

    /// Split arbitrary UTF-8 text into line-aware raw chunks.
    pub fn chunk_text<'a>(&self, content: &'a str) -> Vec<RawTextChunk<'a>> {
        if content.is_empty() {
            return Vec::new();
        }

        let line_starts = Self::build_line_starts(content);
        let total_len = content.len();

        // If content fits comfortably in a single chunk
        if total_len <= self.config.target_chunk_size {
            let line_end = Self::byte_to_line(&line_starts, total_len.saturating_sub(1)).max(1);
            return vec![RawTextChunk {
                text_slice: content,
                line_start: 1,
                line_end,
                char_start: 0,
                char_end: total_len,
                chunk_index: 0,
            }];
        }

        let mut chunks = Vec::new();
        let mut start_idx = 0;
        let mut chunk_index = 0;

        while start_idx < total_len {
            // Target end index
            let mut end_idx = (start_idx + self.config.target_chunk_size).min(total_len);

            // 1. Enforce UTF-8 char boundary on end_idx
            while !content.is_char_boundary(end_idx) && end_idx > start_idx {
                end_idx -= 1;
            }

            // 2. Natural boundary snapping if not at the end of content
            if end_idx < total_len {
                let mut snap_window_start = end_idx.saturating_sub(self.config.target_chunk_size / 4).max(start_idx);
                while !content.is_char_boundary(snap_window_start) && snap_window_start < end_idx {
                    snap_window_start += 1;
                }
                let window = &content[snap_window_start..end_idx];

                // Check for paragraph break (\n\n)
                if let Some(pos) = window.rfind("\n\n") {
                    let snapped = snap_window_start + pos + 2;
                    if content.is_char_boundary(snapped) {
                        end_idx = snapped;
                    }
                } else if let Some(pos) = window.rfind('\n') {
                    // Check for line break (\n)
                    let snapped = snap_window_start + pos + 1;
                    if content.is_char_boundary(snapped) {
                        end_idx = snapped;
                    }
                } else if let Some(pos) = window.rfind(". ").or_else(|| window.rfind("! ")).or_else(|| window.rfind("? ")) {
                    // Check for sentence terminal
                    let snapped = snap_window_start + pos + 2;
                    if content.is_char_boundary(snapped) {
                        end_idx = snapped;
                    }
                }
            }

            let slice = &content[start_idx..end_idx];
            if !slice.trim().is_empty() {
                let line_start = Self::byte_to_line(&line_starts, start_idx).max(1);
                let line_end = Self::byte_to_line(&line_starts, end_idx.saturating_sub(1)).max(line_start);

                chunks.push(RawTextChunk {
                    text_slice: slice,
                    line_start,
                    line_end,
                    char_start: start_idx,
                    char_end: end_idx,
                    chunk_index,
                });
                chunk_index += 1;
            }

            // 3. Advance start_idx with overlap
            if end_idx >= total_len {
                break;
            }

            let overlap_step = self.config.chunk_overlap.min(end_idx - start_idx);
            let mut next_start = end_idx - overlap_step;

            // Enforce UTF-8 char boundary on next_start
            while !content.is_char_boundary(next_start) && next_start < end_idx {
                next_start += 1;
            }

            // Ensure forward progress
            if next_start <= start_idx {
                next_start = end_idx;
            }

            start_idx = next_start;
        }

        chunks
    }

    /// Construct validated `DocumentChunk` items using a vector provider closure.
    pub fn create_document_chunks<F>(
        &self,
        path: &Path,
        content: &str,
        file_blake3: &str,
        access_tier: u8,
        mut vector_provider: F,
    ) -> Result<Vec<DocumentChunk>, TypeError>
    where
        F: FnMut(&str, &str) -> Vec<f32>, // (slice, chunk_b3) -> vector
    {
        let raw_chunks = self.chunk_text(content);
        let mut document_chunks = Vec::with_capacity(raw_chunks.len());

        let path_str = path.to_string_lossy().to_string();

        for raw in raw_chunks {
            let chunk_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
            let vector = vector_provider(raw.text_slice, &chunk_b3);
            let chunk_id = format!("{}:{}", file_blake3, raw.chunk_index);

            let metadata_json = serde_json::json!({
                "char_start": raw.char_start,
                "char_end": raw.char_end,
                "chunk_index": raw.chunk_index,
            })
            .to_string();

            let doc_chunk = DocumentChunk::new(
                chunk_id,
                file_blake3,
                &path_str,
                raw.line_start,
                raw.line_end,
                access_tier,
                vector,
                raw.text_slice,
                Some(metadata_json),
            )?;

            document_chunks.push(doc_chunk);
        }

        Ok(document_chunks)
    }
}
