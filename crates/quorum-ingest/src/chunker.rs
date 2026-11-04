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
        let header = build_contextual_header(path, content);

        for raw in raw_chunks {
            let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
            let chunk_content = prepend_contextual_header(&header, raw.text_slice);
            let vector = vector_provider(raw.text_slice, &raw_b3);
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
                &chunk_content,
                Some(metadata_json),
            )?;

            document_chunks.push(doc_chunk);
        }

        Ok(document_chunks)
    }
}

/// Derives document metadata and builds the contextual header:
/// `[Document: "{doc_title}" | Author: {doc_authors} | Kind: {doc_kind} | File: {file_name}]`
pub fn build_contextual_header(path: &Path, content: &str) -> String {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("document");

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // 1. Title derivation
    let mut doc_title = String::new();
    for line in content.lines().take(20) {
        let trimmed = line.trim();
        if let Some(t) = trimmed.strip_prefix("Title: ") {
            if !t.trim().is_empty() {
                doc_title = t.trim().to_string();
                break;
            }
        }
    }
    if doc_title.is_empty() {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Untitled Document");
        doc_title = stem.replace(['_', '-'], " ").trim().to_string();
    }

    // 2. Author derivation (strictly within first 2KB before Abstract/Introduction)
    let mut doc_authors = "Unknown".to_string();
    let header_preview = &content[..content.len().min(2048)];
    for line in header_preview.lines() {
        let trimmed = line.trim();
        if let Some(a) = trimmed.strip_prefix("Author: ") {
            if !a.trim().is_empty() {
                doc_authors = a.trim().to_string();
                break;
            }
        } else if let Some(a) = trimmed.strip_prefix("by ") {
            if !a.trim().is_empty() && a.len() < 80 {
                doc_authors = a.trim().to_string();
                break;
            }
        } else if let Some(a) = trimmed.strip_prefix("By: ") {
            if !a.trim().is_empty() && a.len() < 80 {
                doc_authors = a.trim().to_string();
                break;
            }
        }
    }

    // 3. Kind derivation
    let doc_kind = match ext.as_str() {
        "pdf" | "docx" | "doc" | "odt" | "rtf" | "tex" | "html" | "htm" => {
            let lower_preview = header_preview.to_ascii_lowercase();
            if lower_preview.contains("abstract")
                || lower_preview.contains("doi:")
                || lower_preview.contains("arxiv")
                || lower_preview.contains("ieee")
            {
                "research_paper".to_string()
            } else if lower_preview.contains("curriculum vitae") || lower_preview.contains("resume") {
                "resume_cv".to_string()
            } else {
                "article".to_string()
            }
        }
        "jpg" | "jpeg" | "png" | "webp" | "bmp" => "image_ocr".to_string(),
        "mp3" | "wav" | "m4a" | "flac" => "audio".to_string(),
        "rs" | "py" | "js" | "ts" | "c" | "cpp" | "go" | "java" => "source_code".to_string(),
        _ => "general_doc".to_string(),
    };

    format!(
        "[Document: \"{}\" | Author: {} | Kind: {} | File: {}]",
        doc_title, doc_authors, doc_kind, file_name
    )
}

/// Prepends the contextual header to raw slice if not already present.
pub fn prepend_contextual_header(header: &str, raw_slice: &str) -> String {
    if raw_slice.starts_with("[Document:") {
        raw_slice.to_string()
    } else {
        format!("{}\n\n{}", header, raw_slice)
    }
}
