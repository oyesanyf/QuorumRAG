//! Deterministic, character-span-grounded KG2KV triple extraction from QuorumRAG chunks.
//!
//! Converts ingested document chunks into AtlasKV `(entity, relation, value)` records
//! with canonical `key_string = "the {relation} of {entity}"` keys, BLAKE3 deduplication,
//! secret/PII scrubbing, work-cluster homonym grouping, and fail-closed `artemis://` air-gap enforcement.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use crate::error::AtlasKvError;
use crate::types::{validate_access_tier, KgSourceChunk, KgTripleRecord};

/// Configuration for deterministic KG2KV triple extraction.
#[derive(Debug, Clone)]
pub struct Kg2KvExtractorConfig {
    /// Maximum triples extracted per source chunk.
    pub max_triples_per_chunk: usize,
    /// Must stay `false` by default — mirrors `ArtemisDfirSettings::default().enabled == false`.
    pub forensics_enabled: bool,
    /// Minimum character length for extracted entity or value fields.
    pub min_field_chars: usize,
    /// Maximum character length for extracted value payloads.
    pub max_value_chars: usize,
}

impl Default for Kg2KvExtractorConfig {
    fn default() -> Self {
        Self {
            max_triples_per_chunk: 16,
            forensics_enabled: false,
            min_field_chars: 2,
            max_value_chars: 240,
        }
    }
}

/// Deterministic, zero-network, character-span-grounded KG2KV triple extractor.
#[derive(Debug, Clone, Default)]
pub struct Kg2KvExtractor {
    config: Kg2KvExtractorConfig,
}

impl Kg2KvExtractor {
    pub fn new(config: Kg2KvExtractorConfig) -> Self {
        Self { config }
    }

    /// Derives a canonical `work_cluster_id` matching `quorum-storage`'s `derive_work_cluster_id`.
    pub fn derive_work_cluster_id(file_name_or_path: &str) -> String {
        let normalized = file_name_or_path.replace('\\', "/");
        let stem = Path::new(&normalized)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&normalized);
        let mut lower = stem.to_ascii_lowercase();
        static REVISION_RE: OnceLock<Regex> = OnceLock::new();
        let re = REVISION_RE.get_or_init(|| {
            Regex::new(r"(_v\d+(_\d+)?|_final|_corrected|_rewritten|_typesetting|_arxiv|_draft|_copy|-\d+$|\(\d+\))")
                .expect("valid revision regex")
        });
        lower = re.replace_all(&lower, "").to_string();
        lower
            .replace(['_', '-', '.', ' '], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Checks whether a chunk belongs to the air-gapped Artemis DFIR forensics namespace.
    pub fn is_airgap_forensics_chunk(file_path: &str, metadata_json: &str) -> bool {
        let lower_path = file_path.trim().to_ascii_lowercase();
        lower_path.starts_with("artemis://")
            || metadata_json.contains("\"artemis_dfir\":true")
            || metadata_json.contains("\"artemis_dfir\": true")
    }

    /// Extracts verified, secret-scrubbed, BLAKE3-deduplicated KG2KV triples from a document chunk.
    pub fn extract_from_chunk(
        &self,
        chunk: &KgSourceChunk,
    ) -> Result<Vec<KgTripleRecord>, AtlasKvError> {
        validate_access_tier(chunk.access_tier)?;

        // Fail-closed air-gap forensics gate
        if !self.config.forensics_enabled
            && Self::is_airgap_forensics_chunk(&chunk.file_path, &chunk.metadata_json)
        {
            return Ok(Vec::new());
        }

        let clean_text = scrub_sensitive_tokens(&chunk.text_content);
        if clean_text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let work_cluster = Self::derive_work_cluster_id(&chunk.file_path);
        let fallback_subject = derive_display_title(&chunk.file_path);
        let mut out = Vec::with_capacity(self.config.max_triples_per_chunk.min(16));
        let mut seen_hashes: HashSet<String> = HashSet::new();

        // Track document title if parsed from contextual header
        let mut active_subject = fallback_subject.clone();

        // 1. Contextual Document Header `[Document: "..." | Author: ... | Kind: ... | File: ...]`
        if let Some((title, author, kind)) = parse_contextual_header(&clean_text) {
            if !title.is_empty() {
                active_subject = title.clone();
            }
            if !author.is_empty() && !author.eq_ignore_ascii_case("unknown") {
                self.push_grounded(
                    &mut out,
                    &mut seen_hashes,
                    &clean_text,
                    &active_subject,
                    "author",
                    &author,
                    chunk,
                    &work_cluster,
                )?;
                self.push_grounded(
                    &mut out,
                    &mut seen_hashes,
                    &clean_text,
                    &author,
                    "authored work",
                    &active_subject,
                    chunk,
                    &work_cluster,
                )?;
            }
            if !kind.is_empty() {
                self.push_grounded(
                    &mut out,
                    &mut seen_hashes,
                    &clean_text,
                    &active_subject,
                    "document category",
                    &kind,
                    chunk,
                    &work_cluster,
                )?;
            }
        }

        // 2. Markdown tables (`| Header 1 | Header 2 | ... |`)
        self.extract_markdown_tables(
            &clean_text,
            chunk,
            &work_cluster,
            &mut out,
            &mut seen_hashes,
        )?;

        // 3. Structured Key: Value, Roster (`S= Name`), and Lease/Board metadata lines
        self.extract_structured_lines(
            &clean_text,
            &active_subject,
            chunk,
            &work_cluster,
            &mut out,
            &mut seen_hashes,
        )?;

        // 4. Grounded prose factual patterns (publication year, authorship, storyteller role, board recorder)
        self.extract_prose_relations(
            &clean_text,
            &active_subject,
            chunk,
            &work_cluster,
            &mut out,
            &mut seen_hashes,
        )?;

        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_grounded(
        &self,
        out: &mut Vec<KgTripleRecord>,
        seen_hashes: &mut HashSet<String>,
        source_text: &str,
        entity: &str,
        relation: &str,
        value: &str,
        chunk: &KgSourceChunk,
        work_cluster: &str,
    ) -> Result<(), AtlasKvError> {
        if out.len() >= self.config.max_triples_per_chunk {
            return Ok(());
        }
        let ent = sanitize_field(entity, 120);
        let rel = sanitize_field(relation, 64).to_ascii_lowercase();
        let val = sanitize_field(value, self.config.max_value_chars);

        if ent.len() < self.config.min_field_chars
            || rel.len() < self.config.min_field_chars
            || val.len() < self.config.min_field_chars
        {
            return Ok(());
        }
        if ent.eq_ignore_ascii_case(&val) {
            return Ok(());
        }
        // Strict source-span grounding: value (or its leading clean phrase) must appear in source_text
        if !is_substring_grounded(source_text, &val) {
            return Ok(());
        }

        let rec = KgTripleRecord::new(
            ent,
            rel,
            val,
            chunk.document_id.clone(),
            chunk.chunk_id.clone(),
            chunk.file_path.clone(),
            chunk.line_start,
            chunk.line_end,
            work_cluster.to_string(),
            chunk.access_tier,
            "local",
        )?;

        if seen_hashes.insert(rec.blake3_hash.clone()) {
            out.push(rec);
        }
        Ok(())
    }

    fn extract_markdown_tables(
        &self,
        text: &str,
        chunk: &KgSourceChunk,
        work_cluster: &str,
        out: &mut Vec<KgTripleRecord>,
        seen_hashes: &mut HashSet<String>,
    ) -> Result<(), AtlasKvError> {
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i + 2 < lines.len() && out.len() < self.config.max_triples_per_chunk {
            let hdr = lines[i].trim();
            let sep = lines[i + 1].trim();
            if hdr.starts_with('|') && sep.starts_with('|') && sep.contains("---") {
                let headers: Vec<String> = split_md_row(hdr);
                if headers.len() >= 2 {
                    let mut r = i + 2;
                    while r < lines.len() && out.len() < self.config.max_triples_per_chunk {
                        let row_line = lines[r].trim();
                        if !row_line.starts_with('|') {
                            break;
                        }
                        let cells = split_md_row(row_line);
                        if cells.len() >= 2 {
                            // Choose first non-trivial cell (skipping short index refs like `[1]`) as entity
                            let (ent_idx, ent) = if cells[0].starts_with('[') && cells.len() >= 3 {
                                (1usize, cells[1].as_str())
                            } else {
                                (0usize, cells[0].as_str())
                            };
                            for (col_idx, cell) in cells.iter().enumerate() {
                                if col_idx == ent_idx || col_idx >= headers.len() {
                                    continue;
                                }
                                let col_hdr = headers[col_idx].trim();
                                if col_hdr.is_empty() || cell.trim().is_empty() {
                                    continue;
                                }
                                self.push_grounded(
                                    out,
                                    seen_hashes,
                                    text,
                                    ent,
                                    col_hdr,
                                    cell,
                                    chunk,
                                    work_cluster,
                                )?;
                            }
                        }
                        r += 1;
                    }
                    i = r;
                    continue;
                }
            }
            i += 1;
        }
        Ok(())
    }

    fn extract_structured_lines(
        &self,
        text: &str,
        active_subject: &str,
        chunk: &KgSourceChunk,
        work_cluster: &str,
        out: &mut Vec<KgTripleRecord>,
        seen_hashes: &mut HashSet<String>,
    ) -> Result<(), AtlasKvError> {
        static KV_LINE_RE: OnceLock<Regex> = OnceLock::new();
        static BOARD_INITIAL_RE: OnceLock<Regex> = OnceLock::new();

        let kv_re = KV_LINE_RE.get_or_init(|| {
            Regex::new(r"(?m)^(?:[-*•]\s*)?([A-Za-z][A-Za-z0-9 /&_'-]{1,42}):\s+([^\r\n]{2,180})$")
                .expect("valid kv regex")
        });
        let roster_re = BOARD_INITIAL_RE.get_or_init(|| {
            Regex::new(r"\b([A-Z])[ \t]*[=-][ \t]*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+(?:[ \t]+(?:Jr\.?|Sr\.?|III|II|[A-Z][a-z]+))?)(?:[ \t]*&[ \t]*[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+(?:[ \t]+(?:Jr\.?|Sr\.?))?))?)")
                .expect("valid roster regex")
        });

        for cap in kv_re.captures_iter(text) {
            if out.len() >= self.config.max_triples_per_chunk {
                break;
            }
            let key = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let val = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            let key_lower = key.to_ascii_lowercase();
            // Skip synthetic transport/chat turn labels or URLs
            if matches!(
                key_lower.as_str(),
                "http" | "https" | "user" | "assistant" | "system" | "note" | "warning" | "path" | "file"
            ) {
                continue;
            }
            self.push_grounded(
                out,
                seen_hashes,
                text,
                active_subject,
                key,
                val,
                chunk,
                work_cluster,
            )?;
            // If key is a person-role field (Landlord, Tenant, Author, Recorder, Chair, Steward),
            // also emit the inverse entity-centric triple `(Person, role in <doc>, <key>)`!
            if matches!(
                key_lower.as_str(),
                "landlord" | "lessor" | "property manager" | "tenant" | "lessee" | "author" | "recorder" | "chair" | "president" | "secretary" | "steward"
            ) {
                self.push_grounded(
                    out,
                    seen_hashes,
                    text,
                    val,
                    &format!("role in {}", active_subject),
                    key,
                    chunk,
                    work_cluster,
                )?;
            }
        }

        // Board roster lines like `S= Shannon Davis`, `A= Angela Davis Breure & Anthony Davis Jr`
        if text.to_ascii_lowercase().contains("board") || text.to_ascii_lowercase().contains("steward") {
            for cap in roster_re.captures_iter(text) {
                if out.len() >= self.config.max_triples_per_chunk {
                    break;
                }
                let member = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                if !member.is_empty() {
                    self.push_grounded(
                        out,
                        seen_hashes,
                        text,
                        active_subject,
                        "board member",
                        member,
                        chunk,
                        work_cluster,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn extract_prose_relations(
        &self,
        text: &str,
        active_subject: &str,
        chunk: &KgSourceChunk,
        work_cluster: &str,
        out: &mut Vec<KgTripleRecord>,
        seen_hashes: &mut HashSet<String>,
    ) -> Result<(), AtlasKvError> {
        static PUBLISHED_BY_RE: OnceLock<Regex> = OnceLock::new();
        static RECORDED_BY_RE: OnceLock<Regex> = OnceLock::new();
        static STORYTELLER_RE: OnceLock<Regex> = OnceLock::new();
        static LANDMARK_WORK_RE: OnceLock<Regex> = OnceLock::new();

        // e.g., "Women, Race & Class is a landmark work by Angela Davis, first published in 1981"
        let landmark_re = LANDMARK_WORK_RE.get_or_init(|| {
            Regex::new(r"([A-Z][A-Za-z0-9,&'\- ]{2,60}?)[ \t]+is[ \t]+(?:a|an|the)[ \t]+([a-z][a-z\- ]{2,35}?)[ \t]+by[ \t]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})(?:,[ \t]*first[ \t]+published[ \t]+in[ \t]+(\d{4}))?")
                .expect("valid landmark work regex")
        });
        for cap in landmark_re.captures_iter(text) {
            if out.len() >= self.config.max_triples_per_chunk {
                break;
            }
            let work = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let author = cap.get(3).map(|m| m.as_str().trim()).unwrap_or("");
            self.push_grounded(out, seen_hashes, text, work, "author", author, chunk, work_cluster)?;
            self.push_grounded(out, seen_hashes, text, author, "published work", work, chunk, work_cluster)?;
            if let Some(yr) = cap.get(4) {
                self.push_grounded(
                    out,
                    seen_hashes,
                    text,
                    work,
                    "publication year",
                    yr.as_str(),
                    chunk,
                    work_cluster,
                )?;
            }
        }

        // e.g., "Women race and class by angela davis written in 1981"
        let pub_re = PUBLISHED_BY_RE.get_or_init(|| {
            Regex::new(r"(?i)\b([A-Za-z][A-Za-z0-9,&'\- ]{3,50}?)[ \t]+by[ \t]+([A-Za-z]+[ \t]+[A-Za-z]+)[ \t]+(?:written|published)[ \t]+in[ \t]+(\d{4})\b")
                .expect("valid published-by regex")
        });
        for cap in pub_re.captures_iter(text) {
            if out.len() >= self.config.max_triples_per_chunk {
                break;
            }
            let work = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let author = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            let yr = cap.get(3).map(|m| m.as_str().trim()).unwrap_or("");
            self.push_grounded(out, seen_hashes, text, work, "author", author, chunk, work_cluster)?;
            self.push_grounded(out, seen_hashes, text, work, "publication year", yr, chunk, work_cluster)?;
        }

        // e.g., "Recorded by Angela Davis", "Meeting adjourned with prayer by Anthony Davis"
        let rec_re = RECORDED_BY_RE.get_or_init(|| {
            Regex::new(r"\b(Recorded|Written|Signed|Prepared|Chaired|Adjourned with prayer)[ \t]+by[ \t]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})")
                .expect("valid recorded-by regex")
        });
        for cap in rec_re.captures_iter(text) {
            if out.len() >= self.config.max_triples_per_chunk {
                break;
            }
            let verb = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let person = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            let rel = match verb.to_ascii_lowercase().as_str() {
                "recorded" => "recorder",
                "written" => "writer",
                "signed" => "signatory",
                "prepared" => "preparer",
                "chaired" => "chair",
                _ => "closing prayer leader",
            };
            self.push_grounded(out, seen_hashes, text, active_subject, rel, person, chunk, work_cluster)?;
            self.push_grounded(
                out,
                seen_hashes,
                text,
                person,
                &format!("{} of", rel),
                active_subject,
                chunk,
                work_cluster,
            )?;
        }

        // e.g., "told as Angela Davis, the yarn spinner" or "as a storyteller Angela Davis, the yarn spinner"
        let story_re = STORYTELLER_RE.get_or_init(|| {
            Regex::new(r"\b(?:as[ \t]+a[ \t]+storyteller[ \t]+|told[ \t]+as[ \t]+)([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2}),[ \t]+the[ \t]+([a-z][a-z\- ]{2,35})")
                .expect("valid storyteller regex")
        });
        for cap in story_re.captures_iter(text) {
            if out.len() >= self.config.max_triples_per_chunk {
                break;
            }
            let person = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let persona = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            self.push_grounded(out, seen_hashes, text, person, "storyteller persona", persona, chunk, work_cluster)?;
        }

        Ok(())
    }
}

/// Scrubs obvious high-risk secrets, credentials, PEM keys, and SSNs before KG persistence.
pub fn scrub_sensitive_tokens(text: &str) -> String {
    static SECRET_RE: OnceLock<Regex> = OnceLock::new();
    let re = SECRET_RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            (-----BEGIN\s+[A-Z0-9\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z0-9\s]+PRIVATE\s+KEY-----)
            | (\bAKIA[0-9A-Z]{16}\b)
            | (\bghp_[A-Za-z0-9]{20,}\b)
            | (\bgithub_pat_[A-Za-z0-9_]{20,}\b)
            | (\bsk-[A-Za-z0-9]{20,}\b)
            | (\b\d{3}-\d{2}-\d{4}\b)
            ",
        )
        .expect("valid secret regex")
    });
    re.replace_all(text, "[REDACTED_SECRET]").into_owned()
}

fn parse_contextual_header(text: &str) -> Option<(String, String, String)> {
    let first_line = text.lines().next()?.trim();
    if !first_line.starts_with("[Document:") || !first_line.ends_with(']') {
        return None;
    }
    let inner = &first_line[1..first_line.len() - 1];
    let mut title = String::new();
    let mut author = String::new();
    let mut kind = String::new();
    for part in inner.split(" | ") {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("Document:") {
            title = v.trim().trim_matches('"').to_string();
        } else if let Some(v) = p.strip_prefix("Author:") {
            author = v.trim().to_string();
        } else if let Some(v) = p.strip_prefix("Kind:") {
            kind = v.trim().to_string();
        }
    }
    if title.is_empty() && author.is_empty() && kind.is_empty() {
        None
    } else {
        Some((title, author, kind))
    }
}

fn derive_display_title(file_path: &str) -> String {
    let normalized = file_path.replace('\\', "/");
    let stem = Path::new(&normalized)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Document");
    stem.replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn split_md_row(line: &str) -> Vec<String> {
    let trimmed = line.trim().trim_start_matches('|').trim_end_matches('|');
    trimmed
        .split('|')
        .map(|s| s.trim().to_string())
        .collect()
}

fn sanitize_field(s: &str, max_chars: usize) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim_matches(|c: char| matches!(c, '"' | '\'' | ';' | ',' | '.'));
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        trimmed.chars().take(max_chars).collect()
    }
}

fn is_substring_grounded(source_text: &str, candidate: &str) -> bool {
    let src_lower = source_text.to_ascii_lowercase();
    let cand_lower = candidate.trim().to_ascii_lowercase();
    if cand_lower.is_empty() {
        return false;
    }
    if src_lower.contains(&cand_lower) {
        return true;
    }
    // Allow title derived from filename / stem or whitespace-normalized match
    let src_norm: String = src_lower.split_whitespace().collect::<Vec<_>>().join(" ");
    let cand_norm: String = cand_lower.split_whitespace().collect::<Vec<_>>().join(" ");
    src_norm.contains(&cand_norm)
}
