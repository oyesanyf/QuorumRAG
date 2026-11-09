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

/// Header item in the active section hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SectionHeader {
    pub level: u8,
    pub title: String,
    pub line_number: u32,
    pub byte_offset: usize,
}

/// Active hierarchical section breadcrumb tracker.
#[derive(Debug, Clone, Default)]
pub struct SectionHierarchyStack {
    headers: Vec<SectionHeader>,
}

impl SectionHierarchyStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, level: u8, title: String, line_number: u32, byte_offset: usize) {
        self.headers.retain(|h| h.level < level);
        self.headers.push(SectionHeader {
            level,
            title,
            line_number,
            byte_offset,
        });
    }

    pub fn breadcrumb_string(&self) -> String {
        self.headers
            .iter()
            .map(|h| h.title.as_str())
            .collect::<Vec<_>>()
            .join(" > ")
    }

    pub fn hierarchy_titles(&self) -> Vec<String> {
        self.headers.iter().map(|h| h.title.clone()).collect()
    }

    pub fn current_level(&self) -> u8 {
        self.headers.last().map(|h| h.level).unwrap_or(0)
    }

    pub fn current_title(&self) -> String {
        self.headers.last().map(|h| h.title.clone()).unwrap_or_default()
    }
}

/// Structure-aware raw chunk with parent-child linkage and heading hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureAwareRawChunk<'a> {
    pub text_slice: &'a str,
    pub line_start: u32,
    pub line_end: u32,
    pub char_start: usize,
    pub char_end: usize,
    pub chunk_index: usize,
    pub parent_chunk_index: usize,
    pub section_path: String,
    pub section_title: String,
    pub section_hierarchy: Vec<String>,
    pub section_level: u8,
}

/// Parses a heading line into a `SectionHeader` if it conforms to Markdown or Section heading styles.
pub fn parse_section_header_line(line: &str, line_num: u32, byte_offset: usize) -> Option<SectionHeader> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Markdown headers: # Title, ## Subtitle, etc.
    if trimmed.starts_with('#') {
        let hashes = trimmed.chars().take_while(|&c| c == '#').count();
        if hashes <= 6 {
            let title = trimmed[hashes..].trim().to_string();
            if !title.is_empty() {
                return Some(SectionHeader {
                    level: hashes as u8,
                    title,
                    line_number: line_num,
                    byte_offset,
                });
            }
        }
    }

    // Explicit Section prefixes: "Section 1.2: Architecture" or "Chapter 3: Storage"
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("section ") || lower.starts_with("chapter ") {
        let title = trimmed.to_string();
        return Some(SectionHeader {
            level: 2,
            title,
            line_number: line_num,
            byte_offset,
        });
    }

    None
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

    /// Snaps a candidate chunk start offset to a natural sentence, paragraph, line, or word boundary.
    ///
    /// Searches within +/- 60 bytes of `nominal_start` for:
    /// 1. Paragraph breaks (`\n\n`)
    /// 2. Sentence terminals (`. `, `! `, `? ` followed by uppercase/whitespace)
    /// 3. Line breaks (`\n`)
    /// 4. Fallback: snaps to nearest whitespace boundary; if `nominal_start` falls inside an
    ///    alphanumeric word, advances forward to the start of the next word so chunks never start mid-word.
    pub fn snap_to_sentence_boundary(
        content: &str,
        nominal_start: usize,
        min_bound: usize,
        max_bound: usize,
    ) -> usize {
        let total_len = content.len();
        if total_len == 0 {
            return 0;
        }

        // 1. Normalize min_bound and max_bound to valid character boundaries
        let mut safe_min = min_bound.min(total_len);
        while !content.is_char_boundary(safe_min) && safe_min < total_len {
            safe_min += 1;
        }
        let mut safe_max = max_bound.min(total_len);
        while !content.is_char_boundary(safe_max) && safe_max > safe_min {
            safe_max -= 1;
        }
        if safe_min >= safe_max {
            return safe_max;
        }

        let cand_start = nominal_start.clamp(safe_min, safe_max);

        // 2. Search window within +/- 60 bytes of cand_start for structural boundaries
        let mut search_min = cand_start.saturating_sub(60).max(safe_min);
        let mut search_max = (cand_start + 60).min(safe_max);

        while !content.is_char_boundary(search_min) && search_min < search_max {
            search_min += 1;
        }
        while !content.is_char_boundary(search_max) && search_max > search_min {
            search_max -= 1;
        }

        if search_min < search_max {
            let window = &content[search_min..search_max];

            // 1. Paragraph breaks (\n\n)
            let mut best_para: Option<(usize, usize)> = None;
            for (idx, _) in window.match_indices("\n\n") {
                let mut cand = search_min + idx + 2;
                while cand < safe_max && content.as_bytes().get(cand).map_or(false, |b| b.is_ascii_whitespace()) {
                    cand += 1;
                }
                if cand >= safe_min && cand <= safe_max && content.is_char_boundary(cand) {
                    let dist = cand.abs_diff(cand_start);
                    if best_para.map_or(true, |(_, d)| dist < d) {
                        best_para = Some((cand, dist));
                    }
                }
            }
            if let Some((cand, _)) = best_para {
                return cand;
            }

            // 2. Sentence terminals (. , ! , ? followed by whitespace or uppercase)
            let mut best_sent: Option<(usize, usize)> = None;
            for term in [". ", "! ", "? "] {
                for (idx, _) in window.match_indices(term) {
                    let term_pos = search_min + idx;
                    if term == ". " && term_pos > 0 {
                        let bytes = content.as_bytes();
                        if bytes[term_pos - 1].is_ascii_digit() {
                            continue;
                        }
                        if bytes[term_pos - 1].is_ascii_uppercase()
                            && (term_pos < 2 || !bytes[term_pos - 2].is_ascii_alphanumeric())
                        {
                            continue;
                        }
                    }
                    let mut cand = term_pos + 2;
                    while cand < safe_max && content.as_bytes().get(cand).map_or(false, |b| b.is_ascii_whitespace()) {
                        cand += 1;
                    }
                    if cand >= safe_min && cand <= safe_max && content.is_char_boundary(cand) {
                        let dist = cand.abs_diff(cand_start);
                        if best_sent.map_or(true, |(_, d)| dist < d) {
                            best_sent = Some((cand, dist));
                        }
                    }
                }
            }
            if let Some((cand, _)) = best_sent {
                return cand;
            }

            // 3. Line breaks (\n)
            let mut best_line: Option<(usize, usize)> = None;
            for (idx, _) in window.match_indices('\n') {
                let mut cand = search_min + idx + 1;
                while cand < safe_max && (content.as_bytes().get(cand) == Some(&b'\r') || content.as_bytes().get(cand) == Some(&b' ')) {
                    cand += 1;
                }
                if cand >= safe_min && cand <= safe_max && content.is_char_boundary(cand) {
                    let dist = cand.abs_diff(cand_start);
                    if best_line.map_or(true, |(_, d)| dist < d) {
                        best_line = Some((cand, dist));
                    }
                }
            }
            if let Some((cand, _)) = best_line {
                return cand;
            }
        }

        // 4. Fallback: snap to nearest whitespace / word boundary.
        // If cand_start falls inside an alphanumeric word, advance forward to the start of the next word.
        let mut cand = cand_start;
        while !content.is_char_boundary(cand) && cand < safe_max {
            cand += 1;
        }

        let is_inside_word = if cand > 0 && cand < total_len {
            let prev_alpha = content[..cand].chars().next_back().map_or(false, |c| c.is_alphanumeric());
            let next_alpha = content[cand..].chars().next().map_or(false, |c| c.is_alphanumeric());
            prev_alpha && next_alpha
        } else {
            false
        };

        if is_inside_word {
            // Advance forward past the rest of this word
            while cand < safe_max && content[cand..].chars().next().map_or(false, |c| !c.is_whitespace()) {
                cand += content[cand..].chars().next().unwrap().len_utf8();
            }
            // Advance forward past whitespace to start of next word
            while cand < safe_max && content[cand..].chars().next().map_or(false, |c| c.is_whitespace()) {
                cand += content[cand..].chars().next().unwrap().len_utf8();
            }
            if cand >= safe_min && cand < safe_max {
                return cand;
            }
            // If forward advancement reached or exceeded safe_max, snap to safe_max so chunks never start mid-word
            return safe_max;
        } else if cand < total_len && content[cand..].chars().next().map_or(false, |c| c.is_whitespace()) {
            while cand < safe_max && content[cand..].chars().next().map_or(false, |c| c.is_whitespace()) {
                cand += content[cand..].chars().next().unwrap().len_utf8();
            }
            if cand >= safe_min && cand < safe_max {
                return cand;
            }
            return safe_max;
        }

        let mut final_start = cand.clamp(safe_min, safe_max);
        while !content.is_char_boundary(final_start) && final_start < safe_max {
            final_start += 1;
        }
        while !content.is_char_boundary(final_start) && final_start > safe_min {
            final_start -= 1;
        }
        final_start
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
                if content[end_idx..].trim().is_empty() {
                    end_idx = total_len;
                } else {
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
                    } else if let Some(pos) = window.rfind(char::is_whitespace) {
                        // Fallback to whitespace boundary so chunks never terminate mid-word
                        let snapped = snap_window_start + pos;
                        if snapped > start_idx && content.is_char_boundary(snapped) {
                            end_idx = snapped;
                        }
                    }

                    // Fallback guarantee: if end_idx still terminates mid-word, snap back to last whitespace
                    if end_idx < total_len && end_idx > start_idx {
                        let prev_alpha = content[..end_idx].chars().next_back().map_or(false, |c| c.is_alphanumeric());
                        let next_alpha = content[end_idx..].chars().next().map_or(false, |c| c.is_alphanumeric());
                        if prev_alpha && next_alpha {
                            if let Some(pos) = content[start_idx..end_idx].rfind(char::is_whitespace) {
                                let snapped = start_idx + pos;
                                if snapped > start_idx && content.is_char_boundary(snapped) {
                                    end_idx = snapped;
                                }
                            } else if let Some(pos) = content[start_idx..end_idx].rfind(|c: char| !c.is_alphanumeric()) {
                                let snapped = start_idx + pos + content[start_idx + pos..].chars().next().unwrap().len_utf8();
                                if snapped > start_idx && snapped < end_idx && content.is_char_boundary(snapped) {
                                    end_idx = snapped;
                                }
                            }
                        }
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

            let min_step = content[start_idx..].chars().next().map_or(1, |c| c.len_utf8());
            let min_bound = (start_idx + min_step).min(end_idx);

            let mut next_start = if self.config.chunk_overlap == 0 {
                // When overlap is 0, advance cleanly past whitespace following end_idx
                let mut s = end_idx;
                while s < total_len && content[s..].chars().next().map_or(false, |c| c.is_whitespace()) {
                    s += content[s..].chars().next().unwrap().len_utf8();
                }
                s
            } else {
                let overlap_step = self.config.chunk_overlap.min(end_idx - start_idx);
                let nominal_start = end_idx - overlap_step;
                Self::snap_to_sentence_boundary(content, nominal_start, min_bound, end_idx)
            };

            // Ensure next_start advances past whitespace if it landed on whitespace and is not at EOF
            while next_start < total_len && content[next_start..].chars().next().map_or(false, |c| c.is_whitespace()) {
                next_start += content[next_start..].chars().next().unwrap().len_utf8();
            }

            start_idx = if next_start > start_idx && content.is_char_boundary(next_start) {
                next_start
            } else {
                end_idx
            };
        }

        chunks
    }

    /// Slices content into structure-aware child chunks linked to containing parent chunks,
    /// tracking active section headers line by line.
    ///
    /// Section header boundaries demarcate discrete chunks even when text is shorter than
    /// `target_chunk_size`. If a section exceeds `target_chunk_size`, it is sub-chunked
    /// while preserving the active section's breadcrumb hierarchy.
    pub fn chunk_text_structure_aware<'a>(&self, content: &'a str) -> Vec<StructureAwareRawChunk<'a>> {
        if content.is_empty() {
            return Vec::new();
        }

        let line_starts = Self::build_line_starts(content);
        let mut header_events = Vec::new();
        for (line_idx, &start_byte) in line_starts.iter().enumerate() {
            let next_byte = if line_idx + 1 < line_starts.len() {
                line_starts[line_idx + 1]
            } else {
                content.len()
            };
            if start_byte < next_byte && content.is_char_boundary(start_byte) && content.is_char_boundary(next_byte) {
                let line_str = &content[start_byte..next_byte];
                if let Some(header) = parse_section_header_line(line_str, (line_idx + 1) as u32, start_byte) {
                    header_events.push(header);
                }
            }
        }

        let parent_window_chunks = 4;

        // If there are no structural section headers, fallback to standard sliding-window chunking
        if header_events.is_empty() {
            let raw_chunks = self.chunk_text(content);
            return raw_chunks
                .into_iter()
                .map(|raw| {
                    let parent_idx = raw.chunk_index / parent_window_chunks;
                    StructureAwareRawChunk {
                        text_slice: raw.text_slice,
                        line_start: raw.line_start,
                        line_end: raw.line_end,
                        char_start: raw.char_start,
                        char_end: raw.char_end,
                        chunk_index: raw.chunk_index,
                        parent_chunk_index: parent_idx,
                        section_path: String::new(),
                        section_title: String::new(),
                        section_hierarchy: Vec::new(),
                        section_level: 0,
                    }
                })
                .collect();
        }

        let mut stack = SectionHierarchyStack::default();
        let mut result = Vec::new();
        let mut chunk_index = 0;

        // 1. Preamble before the first header (if any non-whitespace content exists)
        let first_header_offset = header_events[0].byte_offset;
        if first_header_offset > 0 {
            let preamble = &content[..first_header_offset];
            if !preamble.trim().is_empty() {
                if preamble.len() <= self.config.target_chunk_size {
                    let line_end = Self::byte_to_line(&line_starts, first_header_offset.saturating_sub(1)).max(1);
                    result.push(StructureAwareRawChunk {
                        text_slice: preamble,
                        line_start: 1,
                        line_end,
                        char_start: 0,
                        char_end: first_header_offset,
                        chunk_index,
                        parent_chunk_index: chunk_index / parent_window_chunks,
                        section_path: String::new(),
                        section_title: String::new(),
                        section_hierarchy: Vec::new(),
                        section_level: 0,
                    });
                    chunk_index += 1;
                } else {
                    let sub_chunks = self.chunk_text(preamble);
                    for sub in sub_chunks {
                        let cs = sub.char_start;
                        let ce = sub.char_end;
                        let ls = Self::byte_to_line(&line_starts, cs).max(1);
                        let le = Self::byte_to_line(&line_starts, ce.saturating_sub(1)).max(ls);
                        result.push(StructureAwareRawChunk {
                            text_slice: &content[cs..ce],
                            line_start: ls,
                            line_end: le,
                            char_start: cs,
                            char_end: ce,
                            chunk_index,
                            parent_chunk_index: chunk_index / parent_window_chunks,
                            section_path: String::new(),
                            section_title: String::new(),
                            section_hierarchy: Vec::new(),
                            section_level: 0,
                        });
                        chunk_index += 1;
                    }
                }
            }
        }

        // 2. Iterate each section demarcated by header boundaries
        for (i, h) in header_events.iter().enumerate() {
            stack.push(h.level, h.title.clone(), h.line_number, h.byte_offset);
            let start_byte = h.byte_offset;
            let end_byte = if i + 1 < header_events.len() {
                header_events[i + 1].byte_offset
            } else {
                content.len()
            };

            let section_text = &content[start_byte..end_byte];
            if section_text.trim().is_empty() {
                continue;
            }

            let section_path = stack.breadcrumb_string();
            let section_title = stack.current_title();
            let section_hierarchy = stack.hierarchy_titles();
            let section_level = stack.current_level();

            if section_text.len() <= self.config.target_chunk_size {
                let line_start = Self::byte_to_line(&line_starts, start_byte).max(1);
                let line_end = Self::byte_to_line(&line_starts, end_byte.saturating_sub(1)).max(line_start);
                result.push(StructureAwareRawChunk {
                    text_slice: section_text,
                    line_start,
                    line_end,
                    char_start: start_byte,
                    char_end: end_byte,
                    chunk_index,
                    parent_chunk_index: chunk_index / parent_window_chunks,
                    section_path,
                    section_title,
                    section_hierarchy,
                    section_level,
                });
                chunk_index += 1;
            } else {
                let sub_chunks = self.chunk_text(section_text);
                for sub in sub_chunks {
                    let cs = start_byte + sub.char_start;
                    let ce = start_byte + sub.char_end;
                    let ls = Self::byte_to_line(&line_starts, cs).max(1);
                    let le = Self::byte_to_line(&line_starts, ce.saturating_sub(1)).max(ls);
                    result.push(StructureAwareRawChunk {
                        text_slice: &content[cs..ce],
                        line_start: ls,
                        line_end: le,
                        char_start: cs,
                        char_end: ce,
                        chunk_index,
                        parent_chunk_index: chunk_index / parent_window_chunks,
                        section_path: section_path.clone(),
                        section_title: section_title.clone(),
                        section_hierarchy: section_hierarchy.clone(),
                        section_level,
                    });
                    chunk_index += 1;
                }
            }
        }

        result
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
        let structure_chunks = self.chunk_text_structure_aware(content);
        let mut document_chunks = Vec::with_capacity(structure_chunks.len());

        let path_str = path.to_string_lossy().to_string();
        let resolved_meta = resolve_document_metadata(path, content);
        let header = build_contextual_header(path, content);

        for raw in structure_chunks {
            let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
            let chunk_content = prepend_contextual_header_with_section(&header, &raw.section_path, raw.text_slice);
            let vector = vector_provider(raw.text_slice, &raw_b3);
            let chunk_id = format!("{}:{}", file_blake3, raw.chunk_index);

            let metadata_json = serde_json::json!({
                "char_start": raw.char_start,
                "char_end": raw.char_end,
                "chunk_index": raw.chunk_index,
                "parent_doc_id": file_blake3,
                "parent_chunk_id": format!("{}:p{}", file_blake3, raw.parent_chunk_index),
                "doc_title": resolved_meta.title,
                "doc_author": resolved_meta.author,
                "doc_revision": resolved_meta.revision,
                "heading_path": raw.section_path,
                "section_path": raw.section_path,
                "section_title": raw.section_title,
                "section_hierarchy": raw.section_hierarchy,
                "section_level": raw.section_level,
                "source_path": path_str,
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

/// Resolved parent-document metadata propagated across all child chunks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedDocumentMetadata {
    pub title: String,
    pub author: String,
    pub revision: Option<String>,
    pub kind: String,
    pub file_name: String,
}

/// Deterministically resolves parent-document metadata (`title`, `author`, `revision`, `kind`)
/// from document headers, `[PDF Metadata]` / `[Document Metadata]` banners, OpenXML core properties,
/// and filename fallbacks.
pub fn resolve_document_metadata(path: &Path, content: &str) -> ResolvedDocumentMetadata {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("document")
        .to_string();

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut doc_title = String::new();
    let mut doc_authors = String::new();
    let mut doc_revision: Option<String> = None;

    // 0. If this is an OpenXML / ODF document on disk, inspect core properties first
    if matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp") && path.exists() {
        if let Ok(bytes) = std::fs::read(path) {
            let props = crate::document_extractor::DocumentExtractor::extract_openxml_core_props(&bytes);
            if let Some(t) = props.get("doc_title").filter(|s| !s.trim().is_empty()) {
                doc_title = t.trim().to_string();
            }
            if let Some(a) = props.get("doc_author").filter(|s| !s.trim().is_empty()) {
                doc_authors = a.trim().to_string();
            }
            if let Some(r) = props.get("doc_revision").filter(|s| !s.trim().is_empty()) {
                doc_revision = Some(r.trim().to_string());
            }
        }
    }

    let mut preview_end = content.len().min(2048);
    while !content.is_char_boundary(preview_end) && preview_end > 0 {
        preview_end -= 1;
    }
    let header_preview = &content[..preview_end];

    // 1. Parse structured metadata banners and header key-values within the first 2KB
    for line in header_preview.lines().take(25) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("[PDF Metadata]")
            .or_else(|| trimmed.strip_prefix("[Document Metadata]"))
        {
            for seg in rest.split('|') {
                if let Some((k, v)) = seg.split_once(':') {
                    let key_l = k.trim().to_ascii_lowercase();
                    let val = v.trim();
                    if val.is_empty() {
                        continue;
                    }
                    match key_l.as_str() {
                        "title" if doc_title.is_empty() => doc_title = val.to_string(),
                        "author" | "creator" if doc_authors.is_empty() => doc_authors = val.to_string(),
                        "revision" | "version" | "rev" if doc_revision.is_none() => {
                            doc_revision = Some(val.to_string());
                        }
                        _ => {}
                    }
                }
            }
            continue;
        }

        if doc_title.is_empty() {
            if let Some(t) = trimmed.strip_prefix("Title:").or_else(|| trimmed.strip_prefix("title:")) {
                if !t.trim().is_empty() {
                    doc_title = t.trim().to_string();
                }
            }
        }
        if doc_authors.is_empty() {
            if let Some(a) = trimmed
                .strip_prefix("Author:")
                .or_else(|| trimmed.strip_prefix("Authors:"))
                .or_else(|| trimmed.strip_prefix("By:"))
            {
                if !a.trim().is_empty() && a.trim().len() < 120 {
                    doc_authors = a.trim().to_string();
                }
            } else if let Some(a) = trimmed.strip_prefix("by ") {
                if !a.trim().is_empty() && a.trim().len() < 80 {
                    doc_authors = a.trim().to_string();
                }
            }
        }
        if doc_revision.is_none() {
            if let Some(r) = trimmed
                .strip_prefix("Revision:")
                .or_else(|| trimmed.strip_prefix("Version:"))
                .or_else(|| trimmed.strip_prefix("Rev:"))
            {
                if !r.trim().is_empty() && r.trim().len() < 64 {
                    doc_revision = Some(r.trim().to_string());
                }
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
    if doc_authors.is_empty() {
        doc_authors = "Unknown".to_string();
    }

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

    ResolvedDocumentMetadata {
        title: doc_title,
        author: doc_authors,
        revision: doc_revision,
        kind: doc_kind,
        file_name,
    }
}

/// Derives document metadata and builds the contextual header:
/// `[Document: "{doc_title}" | Author: {doc_authors} | Kind: {doc_kind} | File: {file_name}]`
/// (with `| Rev: {revision}` included when a revision is present).
pub fn build_contextual_header(path: &Path, content: &str) -> String {
    let meta = resolve_document_metadata(path, content);
    if let Some(ref rev) = meta.revision {
        format!(
            "[Document: \"{}\" | Author: {} | Rev: {} | Kind: {} | File: {}]",
            meta.title, meta.author, rev, meta.kind, meta.file_name
        )
    } else {
        format!(
            "[Document: \"{}\" | Author: {} | Kind: {} | File: {}]",
            meta.title, meta.author, meta.kind, meta.file_name
        )
    }
}

/// Prepends the contextual header to raw slice if not already present.
pub fn prepend_contextual_header(header: &str, raw_slice: &str) -> String {
    if raw_slice.starts_with("[Document:") {
        raw_slice.to_string()
    } else {
        format!("{}\n\n{}", header, raw_slice)
    }
}

/// Prepends the contextual header and active section breadcrumb to raw slice.
pub fn prepend_contextual_header_with_section(header: &str, section_path: &str, raw_slice: &str) -> String {
    if raw_slice.starts_with("[Document:") || raw_slice.starts_with("[Section:") {
        raw_slice.to_string()
    } else if !section_path.is_empty() {
        format!("{}\n[Section: {}]\n\n{}", header, section_path, raw_slice)
    } else {
        format!("{}\n\n{}", header, raw_slice)
    }
}
