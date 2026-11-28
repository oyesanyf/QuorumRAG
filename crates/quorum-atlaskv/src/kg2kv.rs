//! Deterministic, character-span-grounded KG2KV triple extraction from QuorumRAG chunks.
//!
//! Converts ingested document chunks into AtlasKV `(entity, relation, value)` records
//! with canonical `key_string = "the {relation} of {entity}"` keys, BLAKE3 deduplication,
//! secret/PII scrubbing, work-cluster homonym grouping, and fail-closed `artemis://` air-gap enforcement.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::AtlasKvError;
use crate::types::{validate_access_tier, KgSourceChunk, KgTripleRecord};

/// Result of verifying whether a chunk is semantically self-contained or begins with
/// unresolved anaphoric references (MeMo Pipeline Step 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfContainmentAudit {
    pub is_self_contained: bool,
    pub unresolved_anaphors: Vec<String>,
    pub resolved_subject: Option<String>,
}

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
        let scrubbed_resolved = chunk
            .resolved_subject
            .as_deref()
            .map(scrub_sensitive_tokens)
            .map(|s| sanitize_field(&s, 120))
            .filter(|s| s.len() >= self.config.min_field_chars);

        let audit = audit_chunk_self_containment(&clean_text, scrubbed_resolved.as_deref());
        let mut out = Vec::with_capacity(self.config.max_triples_per_chunk.min(16));
        let mut seen_hashes: HashSet<String> = HashSet::new();

        let header = parse_contextual_header(&clean_text);
        let header_title = header
            .as_ref()
            .map(|(t, _, _)| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string());
        let non_generic_header_title = header_title
            .as_ref()
            .filter(|t| !is_generic_heading(t))
            .cloned();
        let header_author = header
            .as_ref()
            .map(|(_, a, _)| a.trim())
            .filter(|a| !a.is_empty() && !a.eq_ignore_ascii_case("unknown"))
            .map(|a| a.to_string());

        // Document-level subject for header/document-scoped metadata without mutating text_content
        let doc_subject = non_generic_header_title
            .clone()
            .or_else(|| scrubbed_resolved.clone())
            .or_else(|| header_title.clone())
            .unwrap_or_else(|| fallback_subject.clone());

        // Entity-level subject for anaphoric chunks and structured lines
        let in_chunk_subject = infer_in_chunk_leading_subject(&clean_text);
        let entity_subject = if !audit.is_self_contained {
            audit
                .resolved_subject
                .clone()
                .or_else(|| header_author.clone())
                .unwrap_or_else(|| doc_subject.clone())
        } else {
            in_chunk_subject
                .clone()
                .unwrap_or_else(|| doc_subject.clone())
        };

        // Explicit person/entity subject for personal pronouns (`she`/`he`/`they`):
        // only bind when resolved via antecedent, header author, or explicit in-chunk subject
        // (never invent a person binding from a generic filename stem when none exists).
        let anaphoric_person_subject: Option<String> = if !audit.is_self_contained {
            audit.resolved_subject.clone().or_else(|| header_author.clone())
        } else {
            in_chunk_subject.or_else(|| header_author.clone())
        };

        // Document-referential subject for `"This agreement..."` / `"It requires..."`:
        // prefer non-empty, non-generic `header_title` on the chunk itself over cross-chunk
        // `scrubbed_resolved` so a prior chunk's author/person cannot hijack a new titled section.
        let anaphoric_doc_subject: Option<String> = if !audit.is_self_contained {
            Some(
                non_generic_header_title
                    .clone()
                    .or_else(|| audit.resolved_subject.clone())
                    .or_else(|| header_title.clone())
                    .unwrap_or_else(|| doc_subject.clone()),
            )
        } else {
            non_generic_header_title
                .clone()
                .or_else(|| header_title.clone())
                .or_else(|| Some(doc_subject.clone()))
        };

        // 1. Contextual Document Header `[Document: "..." | Author: ... | Kind: ... | File: ...]`
        if let Some((title, author, kind)) = header {
            let header_subject = if !title.is_empty() {
                title
            } else {
                doc_subject.clone()
            };
            if !author.is_empty() && !author.eq_ignore_ascii_case("unknown") {
                self.push_grounded(
                    &mut out,
                    &mut seen_hashes,
                    &clean_text,
                    &header_subject,
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
                    &header_subject,
                    chunk,
                    &work_cluster,
                )?;
            }
            if !kind.is_empty() {
                self.push_grounded(
                    &mut out,
                    &mut seen_hashes,
                    &clean_text,
                    &header_subject,
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
            &entity_subject,
            chunk,
            &work_cluster,
            &mut out,
            &mut seen_hashes,
        )?;

        // 4. Grounded prose factual patterns (publication year, authorship, storyteller role, board recorder, anaphoric)
        self.extract_prose_relations(
            &clean_text,
            &doc_subject,
            anaphoric_person_subject.as_deref(),
            anaphoric_doc_subject.as_deref(),
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

    #[allow(clippy::too_many_arguments)]
    fn extract_prose_relations(
        &self,
        text: &str,
        active_subject: &str,
        anaphoric_person_subject: Option<&str>,
        anaphoric_doc_subject: Option<&str>,
        chunk: &KgSourceChunk,
        work_cluster: &str,
        out: &mut Vec<KgTripleRecord>,
        seen_hashes: &mut HashSet<String>,
    ) -> Result<(), AtlasKvError> {
        static PUBLISHED_BY_RE: OnceLock<Regex> = OnceLock::new();
        static RECORDED_BY_RE: OnceLock<Regex> = OnceLock::new();
        static STORYTELLER_RE: OnceLock<Regex> = OnceLock::new();
        static LANDMARK_WORK_RE: OnceLock<Option<Regex>> = OnceLock::new();
        static ANAPHORIC_PUB_RE: OnceLock<Option<Regex>> = OnceLock::new();
        static ANAPHORIC_AFFIL_RE: OnceLock<Option<Regex>> = OnceLock::new();
        static ANAPHORIC_DOC_RE: OnceLock<Option<Regex>> = OnceLock::new();

        // e.g., "Women, Race & Class is a landmark work by Angela Davis, first published in 1981"
        if let Some(landmark_re) = LANDMARK_WORK_RE
            .get_or_init(|| {
                Regex::new(r"([\p{Lu}][\p{L}0-9,&'\- ]{2,60}?)[ \t]+is[ \t]+(?:a|an|the)[ \t]+([a-z][a-z\- ]{2,35}?)[ \t]+by[ \t]+(\p{Lu}[\p{L}'\-]+(?:[ \t]+\p{Lu}[\p{L}'\-]+){1,2})(?:,[ \t]*first[ \t]+published[ \t]+in[ \t]+(\d{4}))?")
                    .ok()
            })
            .as_ref()
        {
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

        // Anaphoric prose extraction bound to resolved_subject / intra-chunk subject (no source mutation)
        if let Some(person_subj) = anaphoric_person_subject {
            if let Some(anaphoric_pub_re) = ANAPHORIC_PUB_RE
                .get_or_init(|| {
                    Regex::new(r"\b(?:[Hh]e|[Ss]he|[Tt]hey)\b(?:[ \t]+(?:also|later|subsequently|then|first|soon|famously))*[ \t]+(published|wrote|authored|co-authored|edited)[ \t]+(?:the[ \t]+(?:book|paper|work|article|study|report|monograph|essay)[ \t]+)?(\p{Lu}[^\r\n.;]{2,100})")
                        .ok()
                })
                .as_ref()
            {
                for cap in anaphoric_pub_re.captures_iter(text) {
                    if out.len() >= self.config.max_triples_per_chunk {
                        break;
                    }
                    let verb = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                    let raw_obj = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                    let (work, year_opt) = split_trailing_year(raw_obj);
                    if work.is_empty() {
                        continue;
                    }
                    let rel = match verb.to_ascii_lowercase().as_str() {
                        "published" => "published work",
                        "edited" => "edited work",
                        _ => "authored work",
                    };
                    self.push_grounded(out, seen_hashes, text, person_subj, rel, work, chunk, work_cluster)?;
                    if let Some(yr) = year_opt {
                        self.push_grounded(out, seen_hashes, text, work, "publication year", yr, chunk, work_cluster)?;
                        self.push_grounded(out, seen_hashes, text, person_subj, "publication year", yr, chunk, work_cluster)?;
                    }
                }
            }

            if let Some(anaphoric_affil_re) = ANAPHORIC_AFFIL_RE
                .get_or_init(|| {
                    Regex::new(r"\b(?:[Hh]e|[Ss]he|[Tt]hey)\b(?:[ \t]+(?:also|later|subsequently|then|first|previously))*[ \t]+(taught at|studied at|graduated from|worked at|co-founded|founded|led|chaired|directed)[ \t]+(\p{Lu}[^\r\n.;]{2,80})")
                        .ok()
                })
                .as_ref()
            {
                for cap in anaphoric_affil_re.captures_iter(text) {
                    if out.len() >= self.config.max_triples_per_chunk {
                        break;
                    }
                    let verb = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                    let raw_org = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                    let (org, _) = split_trailing_year(raw_org);
                    if org.is_empty() {
                        continue;
                    }
                    let rel = match verb.to_ascii_lowercase().as_str() {
                        "taught at" => "taught at",
                        "studied at" => "studied at",
                        "graduated from" => "alma mater",
                        "worked at" => "affiliation",
                        "founded" | "co-founded" => "founded",
                        _ => "leadership",
                    };
                    self.push_grounded(out, seen_hashes, text, person_subj, rel, org, chunk, work_cluster)?;
                }
            }
        }

        if let Some(doc_subj) = anaphoric_doc_subject {
            if let Some(anaphoric_doc_re) = ANAPHORIC_DOC_RE
                .get_or_init(|| {
                    Regex::new(r"(?i)\b(?:It|This[ \t]+(?:agreement|contract|lease|policy|document|section)|The[ \t]+(?:agreement|contract|lease|tenant|landlord|lessor|lessee|author|company|organization))\b(?:[ \t]+(?:also|further|explicitly))*[ \t]+(requires|specifies|states|sets|establishes|provides|includes|covers|pays|charges)[ \t]+([^\r\n.;]{3,120})")
                        .ok()
                })
                .as_ref()
            {
                for cap in anaphoric_doc_re.captures_iter(text) {
                    if out.len() >= self.config.max_triples_per_chunk {
                        break;
                    }
                    let clause = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                    if !clause.is_empty() {
                        self.push_grounded(out, seen_hashes, text, doc_subj, "provision", clause, chunk, work_cluster)?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Audits whether `text` is semantically self-contained or starts with unresolved anaphors
/// (leading pronouns / definite NPs lacking an explicit preceding subject).
pub fn audit_chunk_self_containment(
    text: &str,
    fallback_subject: Option<&str>,
) -> SelfContainmentAudit {
    let clean_fallback = fallback_subject
        .map(scrub_sensitive_tokens)
        .map(|s| sanitize_field(&s, 120))
        .filter(|s| s.len() >= 2);

    let scrubbed = scrub_sensitive_tokens(text);
    let (body, header_author, heading_subject) = strip_synthetic_banners(&scrubbed);
    let trimmed_body = body.trim();
    if trimmed_body.is_empty() {
        return SelfContainmentAudit {
            is_self_contained: true,
            unresolved_anaphors: Vec::new(),
            resolved_subject: None,
        };
    }

    let opening = take_char_prefix(trimmed_body, 160);
    let opening_unquoted = opening.trim_start_matches(|c: char| {
        matches!(c, '"' | '\'' | '\u{201c}' | '\u{2018}') || c.is_whitespace()
    });
    let mut unresolved: Vec<String> = Vec::new();
    let mut seen_norm: HashSet<String> = HashSet::new();
    let has_header_author = header_author.is_some();
    let has_heading_subject = heading_subject.is_some();

    let mut push_anaphor = |label: &str| {
        let norm = label.trim().to_ascii_lowercase();
        if !norm.is_empty() && seen_norm.insert(norm.clone()) {
            unresolved.push(norm);
        }
    };

    // 1. Check leading definite noun phrases at start of stripped body (after optional opening quotes)
    let leading_definite_match_len = if !has_heading_subject {
        match_leading_definite_np(opening_unquoted)
    } else {
        None
    };
    if let Some((matched_phrase, _end_idx)) = leading_definite_match_len {
        push_anaphor(matched_phrase);
    } else if !has_heading_subject {
        // 2. Check leading standalone pronoun at start of stripped body (after optional opening quotes)
        if let Some((pronoun, is_personal)) = match_leading_pronoun(opening_unquoted) {
            if !(is_personal && has_header_author) {
                push_anaphor(pronoun);
            }
        }
    }

    // 3. Check mid-opening personal pronouns inside the first 160 chars unless preceded by an explicit subject
    static PERSONAL_PRONOUN_RE: OnceLock<Option<Regex>> = OnceLock::new();
    if let Some(pron_re) = PERSONAL_PRONOUN_RE
        .get_or_init(|| Regex::new(r"(?i)\b(she|he|they|her|his|their|him|them|hers|theirs)\b").ok())
        .as_ref()
    {
        for m in pron_re.find_iter(opening) {
            if m.start() == 0 {
                continue;
            }
            if has_header_author || has_heading_subject {
                continue;
            }
            let prefix_before = &opening[..m.start()];
            if !has_explicit_subject_before(prefix_before) {
                push_anaphor(m.as_str());
            }
        }
    }

    let is_self_contained = unresolved.is_empty();
    let resolved_subject = if !is_self_contained {
        clean_fallback
    } else {
        None
    };

    SelfContainmentAudit {
        is_self_contained,
        unresolved_anaphors: unresolved,
        resolved_subject,
    }
}

/// Extracts a strong canonical subject anchor from chunk text, `metadata_json`, and `file_path`
/// for `(document_id, access_tier)`-partitioned antecedent tracking. Returns `None` on anaphoric
/// chunks lacking explicit headers/entities so filename stems never overwrite strong prior anchors.
pub fn infer_chunk_subject_anchor(
    text: &str,
    metadata_json: &str,
    file_path: &str,
) -> Option<String> {
    let scrubbed = scrub_sensitive_tokens(text);

    // 1. Explicit person/entity Key: Value lines
    if let Some(val) = extract_strong_kv_subject(&scrubbed) {
        return Some(val);
    }

    // 2. Contextual header Author (if non-Unknown)
    let header = parse_contextual_header(&scrubbed);
    if let Some((_, ref author, _)) = header {
        let clean = sanitize_field(author, 120);
        if clean.len() >= 2 && !clean.eq_ignore_ascii_case("unknown") {
            return Some(clean);
        }
    }

    // 3. Metadata JSON hints (`resolved_entity_anchor`, `doc_author`, non-generic `doc_title`/`section_title`)
    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(metadata_json) {
        for key in ["resolved_entity_anchor", "doc_author"] {
            if let Some(v) = meta.get(key).and_then(|x| x.as_str()) {
                let clean = sanitize_field(&scrub_sensitive_tokens(v), 120);
                if clean.len() >= 2 && !clean.eq_ignore_ascii_case("unknown") {
                    return Some(clean);
                }
            }
        }
        let stem_title = derive_display_title(file_path);
        for key in ["doc_title", "section_title"] {
            if let Some(v) = meta.get(key).and_then(|x| x.as_str()) {
                let clean = sanitize_field(&scrub_sensitive_tokens(v), 120);
                if clean.len() >= 2
                    && !is_generic_heading(&clean)
                    && !clean.eq_ignore_ascii_case(&stem_title)
                {
                    return Some(clean);
                }
            }
        }
    }

    // 4. Explicit named subject in chunk body (leading Proper Name + verb, proper heading, or landmark/pub author)
    if let Some(subj) = infer_in_chunk_leading_subject(&scrubbed) {
        return Some(subj);
    }

    // 5. Contextual header Document title (non-empty & non-generic)
    if let Some((ref title, _, _)) = header {
        let clean = sanitize_field(title, 120);
        if clean.len() >= 2 && !is_generic_heading(&clean) {
            return Some(clean);
        }
    }

    None
}

/// Deterministic ordering key for chunks within a `(document_id, access_tier)` batch so
/// out-of-order batches process chunk `0` before chunk `1`.
pub fn parse_chunk_order_key(
    chunk_id: &str,
    metadata_json: &str,
    line_start: u32,
    fallback_idx: usize,
) -> (usize, u32, usize) {
    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(metadata_json) {
        if let Some(idx) = meta.get("chunk_index").and_then(|v| v.as_u64()) {
            return (idx as usize, line_start, fallback_idx);
        }
    }
    if let Some((_, tail)) = chunk_id.rsplit_once(':') {
        if let Ok(idx) = tail.trim().parse::<usize>() {
            return (idx, line_start, fallback_idx);
        }
    }
    (usize::MAX, line_start, fallback_idx)
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

pub fn derive_display_title(file_path: &str) -> String {
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
    let src_lower = source_text.to_lowercase();
    let cand_lower = candidate.trim().to_lowercase();
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

fn take_char_prefix(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

fn strip_md_heading(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if !trimmed.starts_with('#') {
        return None;
    }
    let after_hashes = trimmed.trim_start_matches('#');
    if !after_hashes.starts_with(char::is_whitespace) {
        return None;
    }
    let heading = after_hashes.trim();
    if heading.is_empty() {
        None
    } else {
        Some(heading)
    }
}

pub fn is_generic_heading(heading: &str) -> bool {
    let norm = heading
        .trim()
        .trim_matches(|c: char| !c.is_alphanumeric() && !c.is_whitespace())
        .to_ascii_lowercase();
    if norm.is_empty() {
        return true;
    }
    matches!(
        norm.as_str(),
        "overview"
            | "background"
            | "publications"
            | "works"
            | "selected works"
            | "notes"
            | "summary"
            | "introduction"
            | "history"
            | "biography"
            | "career"
            | "details"
            | "terms"
            | "provisions"
            | "conclusion"
            | "references"
            | "appendix"
            | "document"
            | "untitled"
            | "untitled document"
    ) || norm.starts_with("section ")
        || norm.starts_with("chapter ")
        || norm.starts_with("part ")
}

fn is_section_label(tok: &str) -> bool {
    let clean = tok
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase();
    matches!(
        clean.as_str(),
        "note"
            | "notes"
            | "warning"
            | "caution"
            | "important"
            | "summary"
            | "overview"
            | "abstract"
            | "appendix"
            | "section"
            | "chapter"
            | "part"
            | "todo"
            | "tbd"
            | "faq"
            | "url"
            | "http"
            | "https"
            | "pdf"
            | "ii"
            | "iii"
            | "iv"
            | "vi"
            | "vii"
            | "viii"
            | "ix"
            | "xi"
            | "xii"
    )
}

fn is_acronym_token(clean: &str) -> bool {
    let char_count = clean.chars().count();
    (2..=8).contains(&char_count)
        && clean.chars().any(|c| c.is_uppercase())
        && clean
            .chars()
            .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '&')
        && !is_section_label(clean)
}

fn is_capitalized_name_token(tok: &str) -> bool {
    let clean = tok.trim_matches(|c: char| {
        matches!(
            c,
            ',' | '.' | ';' | ':' | '"' | '\'' | '\u{201c}' | '\u{201d}' | '\u{2018}' | '\u{2019}' | '(' | ')'
        )
    });
    if clean.chars().count() < 2 {
        return false;
    }
    let mut chars = clean.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_uppercase() {
        return false;
    }
    chars.any(|c| c.is_lowercase()) || is_acronym_token(clean)
}

fn is_non_subject_starter(tok: &str) -> bool {
    let clean = tok
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase();
    matches!(
        clean.as_str(),
        "in" | "on"
            | "at"
            | "by"
            | "for"
            | "with"
            | "from"
            | "to"
            | "of"
            | "as"
            | "the"
            | "a"
            | "an"
            | "this"
            | "that"
            | "these"
            | "those"
            | "such"
            | "however"
            | "moreover"
            | "furthermore"
            | "therefore"
            | "meanwhile"
            | "later"
            | "earlier"
            | "during"
            | "after"
            | "before"
            | "under"
            | "since"
            | "while"
            | "although"
            | "when"
            | "where"
            | "she"
            | "he"
            | "they"
            | "it"
            | "we"
            | "you"
            | "there"
            | "here"
            | "both"
            | "each"
            | "all"
            | "some"
            | "many"
            | "most"
            | "one"
            | "none"
            | "someone"
            | "somebody"
            | "anyone"
            | "anybody"
            | "everyone"
            | "everybody"
            | "nobody"
            | "nothing"
            | "everything"
            | "something"
            | "who"
            | "whom"
            | "whose"
            | "which"
            | "what"
            | "why"
            | "how"
            | "today"
            | "monday"
            | "tuesday"
            | "wednesday"
            | "thursday"
            | "friday"
            | "saturday"
            | "sunday"
            | "january"
            | "february"
            | "march"
            | "april"
            | "may"
            | "june"
            | "july"
            | "august"
            | "september"
            | "october"
            | "november"
            | "december"
    )
}

fn looks_like_named_subject(s: &str) -> bool {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if !(2..=5).contains(&tokens.len()) {
        return false;
    }
    let mut cap_count = 0usize;
    for (i, tok) in tokens.iter().enumerate() {
        let lower = tok.to_lowercase();
        if i > 0 && matches!(lower.as_str(), "of" | "the" | "and" | "&" | "de" | "van" | "von") {
            continue;
        }
        if is_non_subject_starter(tok) || is_section_label(tok) || !is_capitalized_name_token(tok) {
            return false;
        }
        cap_count += 1;
    }
    cap_count >= 2
}

fn strip_synthetic_banners(text: &str) -> (&str, Option<String>, Option<String>) {
    let mut header_author: Option<String> = None;
    let mut heading_subject: Option<String> = None;
    let mut rest = text;

    loop {
        let trimmed_start = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        if trimmed_start.is_empty() {
            rest = trimmed_start;
            break;
        }
        let line_end = trimmed_start.find('\n').unwrap_or(trimmed_start.len());
        let line = trimmed_start[..line_end].trim();
        let after_line = if line_end < trimmed_start.len() {
            &trimmed_start[line_end + 1..]
        } else {
            ""
        };

        if line.starts_with("[Document:") && line.ends_with(']') {
            if let Some((_, author, _)) = parse_contextual_header(line) {
                let clean = sanitize_field(&author, 120);
                if clean.len() >= 2 && !clean.eq_ignore_ascii_case("unknown") {
                    header_author = Some(clean);
                }
            }
            rest = after_line;
            continue;
        }
        if (line.starts_with("[Image Document:") || line.starts_with("[Section:"))
            && line.ends_with(']')
        {
            rest = after_line;
            continue;
        }
        if let Some(heading_text) = strip_md_heading(line) {
            if !is_generic_heading(heading_text) && looks_like_named_subject(heading_text) {
                heading_subject = Some(sanitize_field(heading_text, 120));
            }
            rest = after_line;
            continue;
        }
        rest = trimmed_start;
        break;
    }

    (rest, header_author, heading_subject)
}

fn match_leading_definite_np(opening: &str) -> Option<(&'static str, usize)> {
    const DEFINITE_NPS: &[&str] = &[
        "the aforementioned",
        "this organization",
        "the organization",
        "this agreement",
        "the agreement",
        "the researcher",
        "this document",
        "this contract",
        "the contract",
        "this section",
        "this company",
        "the landlord",
        "the plaintiff",
        "the defendant",
        "the company",
        "the patient",
        "the subject",
        "this policy",
        "this report",
        "this lease",
        "this study",
        "this paper",
        "the tenant",
        "the lessor",
        "the lessee",
        "the author",
        "this work",
        "the lease",
        "the above",
    ];
    for &phrase in DEFINITE_NPS {
        if let Some(prefix) = opening.get(..phrase.len()) {
            if prefix.eq_ignore_ascii_case(phrase) {
                let next_ok = opening[phrase.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric());
                if next_ok {
                    return Some((phrase, phrase.len()));
                }
            }
        }
    }
    None
}

fn match_leading_pronoun(opening: &str) -> Option<(&'static str, bool)> {
    const PRONOUNS: &[(&str, bool)] = &[
        ("theirs", true),
        ("their", true),
        ("these", false),
        ("those", false),
        ("they", true),
        ("them", true),
        ("hers", true),
        ("this", false),
        ("such", false),
        ("she", true),
        ("her", true),
        ("his", true),
        ("him", true),
        ("its", false),
        ("he", true),
        ("it", false),
    ];
    for &(pronoun, is_personal) in PRONOUNS {
        if let Some(prefix) = opening.get(..pronoun.len()) {
            if prefix.eq_ignore_ascii_case(pronoun) {
                let next_ok = opening[pronoun.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric());
                if next_ok {
                    return Some((pronoun, is_personal));
                }
            }
        }
    }
    None
}

fn extract_strong_kv_subject(text: &str) -> Option<String> {
    static STRONG_KV_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let re = STRONG_KV_RE
        .get_or_init(|| {
            Regex::new(r"(?m)^(?:[-*•]\s*)?([A-Za-z][A-Za-z0-9 /&_'-]{1,42}):\s+([^\r\n]{2,120})$")
                .ok()
        })
        .as_ref()?;
    for cap in re.captures_iter(text) {
        let key = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        let val = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        let key_lower = key.to_ascii_lowercase();
        if matches!(
            key_lower.as_str(),
            "author"
                | "tenant"
                | "landlord"
                | "lessor"
                | "lessee"
                | "owner"
                | "subject"
                | "patient"
                | "recorder"
                | "chair"
                | "president"
                | "secretary"
                | "pastor"
                | "steward"
                | "name"
                | "speaker"
                | "narrator"
                | "witness"
                | "plaintiff"
                | "defendant"
                | "researcher"
                | "company"
                | "organization"
                | "party"
        ) {
            let clean = sanitize_field(val, 120);
            if clean.len() >= 2 && !clean.eq_ignore_ascii_case("unknown") {
                return Some(clean);
            }
        }
    }
    None
}

fn is_finite_verb_token(tok: &str) -> bool {
    let clean = tok
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
        .to_ascii_lowercase();
    matches!(
        clean.as_str(),
        "is" | "was"
            | "were"
            | "are"
            | "has"
            | "had"
            | "have"
            | "published"
            | "wrote"
            | "authored"
            | "co-authored"
            | "edited"
            | "founded"
            | "co-founded"
            | "taught"
            | "studied"
            | "graduated"
            | "worked"
            | "served"
            | "born"
            | "signed"
            | "owns"
            | "manages"
            | "led"
            | "chaired"
            | "directed"
            | "announced"
            | "created"
            | "built"
            | "designed"
            | "developed"
            | "launched"
            | "released"
            | "acquired"
            | "merged"
            | "reported"
            | "stated"
            | "noted"
            | "argued"
            | "explained"
            | "discovered"
            | "proved"
            | "won"
            | "received"
            | "joined"
            | "became"
            | "left"
            | "moved"
            | "lived"
            | "lives"
            | "died"
            | "runs"
            | "operates"
            | "produces"
            | "makes"
            | "offers"
            | "provides"
            | "requires"
            | "specifies"
            | "plans"
    )
}

fn is_adverb_modifier_token(tok: &str) -> bool {
    let clean = tok
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
        .to_ascii_lowercase();
    matches!(
        clean.as_str(),
        "later"
            | "also"
            | "subsequently"
            | "previously"
            | "first"
            | "recently"
            | "originally"
            | "formerly"
            | "soon"
            | "famously"
    )
}

fn strip_leading_prepositional_intros(mut s: &str) -> &str {
    for _ in 0..3 {
        let trimmed = s.trim_start();
        let Some(first_ws) = trimmed.find(char::is_whitespace) else {
            return trimmed;
        };
        let first_word = trimmed[..first_ws]
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase();
        if !matches!(
            first_word.as_str(),
            "in" | "at"
                | "on"
                | "from"
                | "during"
                | "after"
                | "before"
                | "under"
                | "over"
                | "with"
                | "without"
                | "throughout"
                | "between"
                | "near"
        ) {
            return trimmed;
        }
        let search_window = take_char_prefix(trimmed, 80);
        let Some(comma_idx) = search_window.find(',') else {
            return trimmed;
        };
        let before_comma = &trimmed[..comma_idx];
        if before_comma.contains(['.', ';', '\n', '\r']) {
            return trimmed;
        }
        if before_comma.split_whitespace().any(is_finite_verb_token) {
            return trimmed;
        }
        s = trimmed[comma_idx + 1..].trim_start();
    }
    s.trim_start()
}

fn is_valid_leading_subject_candidate(s: &str) -> bool {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.len() == 1 {
        let tok = tokens[0];
        !is_non_subject_starter(tok)
            && !is_section_label(tok)
            && !is_generic_heading(tok)
            && is_capitalized_name_token(tok)
    } else {
        looks_like_named_subject(s)
    }
}

fn has_explicit_subject_before(prefix: &str) -> bool {
    if extract_strong_kv_subject(prefix).is_some() {
        return true;
    }
    let effective = strip_leading_prepositional_intros(prefix);
    let tokens: Vec<&str> = effective.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }
    // 1. Check for 2..=4 consecutive capitalized non-stopword tokens in `effective`
    let mut run = 0usize;
    for tok in &tokens {
        let clean = tok.trim_matches(|c: char| {
            matches!(
                c,
                ',' | '.' | ';' | ':' | '"' | '\'' | '\u{201c}' | '\u{201d}' | '\u{2018}' | '\u{2019}' | '(' | ')'
            )
        });
        if is_capitalized_name_token(clean)
            && !is_non_subject_starter(clean)
            && !is_section_label(clean)
        {
            run += 1;
            if run >= 2 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    // 2. Check for single-word proper name / acronym followed by (optional adverb +) finite verb
    for i in 0..tokens.len() {
        let clean = tokens[i].trim_matches(|c: char| {
            matches!(
                c,
                ',' | '.' | ';' | ':' | '"' | '\'' | '\u{201c}' | '\u{201d}' | '\u{2018}' | '\u{2019}' | '(' | ')'
            )
        });
        if !is_capitalized_name_token(clean)
            || is_non_subject_starter(clean)
            || is_section_label(clean)
            || is_generic_heading(clean)
        {
            continue;
        }
        if tokens[i].ends_with(['.', '!', '?']) {
            continue;
        }
        if let Some(next1) = tokens.get(i + 1) {
            if is_finite_verb_token(next1) {
                return true;
            }
            if is_adverb_modifier_token(next1) {
                if let Some(next2) = tokens.get(i + 2) {
                    if is_finite_verb_token(next2) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn infer_in_chunk_leading_subject(text: &str) -> Option<String> {
    let (body, _, heading_subject) = strip_synthetic_banners(text);
    if let Some(h) = heading_subject {
        return Some(h);
    }

    static LEADING_SUBJECT_VERB_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let trimmed = strip_leading_prepositional_intros(body.trim()).trim_start_matches(|c: char| {
        matches!(c, '"' | '\'' | '\u{201c}' | '\u{2018}') || c.is_whitespace()
    });
    if let Some(subj_re) = LEADING_SUBJECT_VERB_RE
        .get_or_init(|| {
            Regex::new(
                r"^((?:\p{Lu}[\p{L}'\-]+|\p{Lu}[\p{Lu}0-9&]{1,7})(?:[ \t]+(?:of|the|and|&|de|van|von|\p{Lu}[\p{L}'\-]+|\p{Lu}[\p{Lu}0-9&]{1,7})){0,3})[ \t]+(?:(?:later|also|subsequently|previously|first|recently|originally|formerly|soon|famously)[ \t]+)?(?:is|was|were|are|has|had|have|published|wrote|authored|co-authored|edited|founded|co-founded|taught|studied|graduated|worked|served|born|signed|owns|manages|led|chaired|directed|announced|created|built|designed|developed|launched|released|acquired|merged|reported|stated|noted|argued|explained|discovered|proved|won|received|joined|became|left|moved|lived|lives|died|runs|operates|produces|makes|offers|provides|requires|specifies|plans)\b",
            )
            .ok()
        })
        .as_ref()
    {
        if let Some(cap) = subj_re.captures(trimmed) {
            if let Some(m) = cap.get(1) {
                let candidate = m.as_str().trim();
                if is_valid_leading_subject_candidate(candidate) {
                    return Some(sanitize_field(candidate, 120));
                }
            }
        }
    }

    static LANDMARK_AUTHOR_RE: OnceLock<Option<Regex>> = OnceLock::new();
    if let Some(author_re) = LANDMARK_AUTHOR_RE
        .get_or_init(|| {
            Regex::new(r"[\p{Lu}][\p{L}0-9,&'\- ]{2,60}?[ \t]+is[ \t]+(?:a|an|the)[ \t]+[a-z][a-z\- ]{2,35}?[ \t]+by[ \t]+(\p{Lu}[\p{L}'\-]+(?:[ \t]+\p{Lu}[\p{L}'\-]+){1,2})")
                .ok()
        })
        .as_ref()
    {
        if let Some(cap) = author_re.captures(trimmed) {
            if let Some(m) = cap.get(1) {
                let clean = sanitize_field(m.as_str(), 120);
                if clean.chars().count() >= 2 {
                    return Some(clean);
                }
            }
        }
    }

    None
}

fn split_trailing_year(raw: &str) -> (&str, Option<&str>) {
    static TRAILING_YEAR_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let trimmed = raw.trim().trim_end_matches(['.', ';', ',', ' ']);
    if let Some(re) = TRAILING_YEAR_RE
        .get_or_init(|| Regex::new(r"^(.+?)[ \t]+in[ \t]+(\d{4})$").ok())
        .as_ref()
    {
        if let Some(cap) = re.captures(trimmed) {
            let head = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let yr = cap.get(2).map(|m| m.as_str().trim());
            if !head.is_empty() {
                return (head, yr);
            }
        }
    }
    (trimmed, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chunk_self_containment_flags_anaphoric_openings() {
        let audit_she = audit_chunk_self_containment(
            "She later published Women, Race & Class in 1981.",
            Some("Angela Davis"),
        );
        assert!(!audit_she.is_self_contained);
        assert_eq!(audit_she.unresolved_anaphors, vec!["she".to_string()]);
        assert_eq!(audit_she.resolved_subject.as_deref(), Some("Angela Davis"));

        let audit_banner = audit_chunk_self_containment(
            "[Document: \"Notes\" | Author: Unknown | Kind: article | File: notes.txt]\n[Section: Works]\n\nShe later published Women, Race & Class in 1981.",
            Some("Angela Davis"),
        );
        assert!(!audit_banner.is_self_contained);
        assert_eq!(audit_banner.unresolved_anaphors, vec!["she".to_string()]);
        assert_eq!(
            audit_banner.resolved_subject.as_deref(),
            Some("Angela Davis")
        );

        let audit_np = audit_chunk_self_containment(
            "This agreement requires a security deposit of $1,850.",
            Some("2018 Rental Agreement"),
        );
        assert!(!audit_np.is_self_contained);
        assert_eq!(
            audit_np.unresolved_anaphors,
            vec!["this agreement".to_string()]
        );
        assert_eq!(
            audit_np.resolved_subject.as_deref(),
            Some("2018 Rental Agreement")
        );

        let audit_mid = audit_chunk_self_containment(
            "In 1981, she published Women, Race & Class.",
            Some("Angela Davis"),
        );
        assert!(!audit_mid.is_self_contained);
        assert_eq!(audit_mid.unresolved_anaphors, vec!["she".to_string()]);
    }

    #[test]
    fn test_audit_chunk_self_containment_preserves_self_contained_chunks() {
        let audit = audit_chunk_self_containment(
            "Angela Davis was born in Birmingham. She later published Women, Race & Class in 1981.",
            Some("Other Person"),
        );
        assert!(audit.is_self_contained);
        assert!(audit.unresolved_anaphors.is_empty());
        assert_eq!(audit.resolved_subject, None);
    }

    #[test]
    fn test_extract_from_chunk_anaphoric_resolution_preserves_substring_grounding() {
        let extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig::default());
        let original_text = "She later published Women, Race & Class in 1981.".to_string();
        let chunk = KgSourceChunk {
            chunk_id: "doc-angela:1".into(),
            document_id: "doc-angela".into(),
            file_path: "D:/Docs/bio_notes.txt".into(),
            line_start: 10,
            line_end: 15,
            access_tier: 0,
            text_content: original_text.clone(),
            metadata_json: "{}".into(),
            resolved_subject: Some("Angela Davis".into()),
        };

        let triples = extractor.extract_from_chunk(&chunk).expect("extract ok");
        assert_eq!(chunk.text_content, original_text);
        assert!(
            triples.iter().any(|t| {
                t.entity == "Angela Davis"
                    && t.relation == "published work"
                    && t.value == "Women, Race & Class"
            }),
            "Expected resolved published work triple, got {triples:#?}"
        );
        assert!(
            triples.iter().any(|t| {
                t.entity == "Women, Race & Class"
                    && t.relation == "publication year"
                    && t.value == "1981"
            }),
            "Expected publication year triple, got {triples:#?}"
        );
        for t in &triples {
            assert!(
                is_substring_grounded(&chunk.text_content, &t.value),
                "Triple value '{}' is not substring-grounded in source text",
                t.value
            );
        }
    }

    #[test]
    fn test_extract_from_chunk_airgap_and_tier_fail_closed_with_resolved_subject() {
        let extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig::default());
        let artemis_chunk = KgSourceChunk {
            chunk_id: "art:1".into(),
            document_id: "art".into(),
            file_path: "artemis://host/event.jsonl".into(),
            line_start: 1,
            line_end: 2,
            access_tier: 0,
            text_content: "She later published Secret Memo in 2024.".into(),
            metadata_json: "{}".into(),
            resolved_subject: Some("Alice".into()),
        };
        assert!(extractor
            .extract_from_chunk(&artemis_chunk)
            .unwrap()
            .is_empty());

        let invalid_tier_chunk = KgSourceChunk {
            chunk_id: "bad:1".into(),
            document_id: "bad".into(),
            file_path: "notes.txt".into(),
            line_start: 1,
            line_end: 2,
            access_tier: 4,
            text_content: "She later published Public Memo in 2024.".into(),
            metadata_json: "{}".into(),
            resolved_subject: Some("Alice".into()),
        };
        assert!(matches!(
            extractor.extract_from_chunk(&invalid_tier_chunk),
            Err(AtlasKvError::InvalidAccessTier(4))
        ));
    }

    #[test]
    fn test_infer_chunk_subject_anchor_and_order_key() {
        assert_eq!(
            infer_chunk_subject_anchor(
                "Angela Davis is an American political activist and scholar.",
                "{}",
                "D:/Docs/bio_notes.txt"
            )
            .as_deref(),
            Some("Angela Davis")
        );
        assert_eq!(
            infer_chunk_subject_anchor(
                "She later published Women, Race & Class in 1981.",
                "{}",
                "D:/Docs/bio_notes.txt"
            ),
            None
        );
        assert_eq!(
            parse_chunk_order_key("doc:2", "{}", 10, 0),
            (2, 10, 0)
        );
        assert_eq!(
            parse_chunk_order_key("chunk_a", r#"{"chunk_index": 5}"#, 20, 1),
            (5, 20, 1)
        );
    }

    #[test]
    fn regression_challenge3_and_4a_prepositional_single_word_acronyms_unicode_quotes_headings_and_banner_priority() {
        let extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig::default());

        // 1. Prepositional location clause before pronoun must NOT block fallback resolution
        let audit_ny = audit_chunk_self_containment(
            "In New York, she published Women, Race & Class in 1981.",
            Some("Angela Davis"),
        );
        assert!(!audit_ny.is_self_contained);
        assert_eq!(audit_ny.unresolved_anaphors, vec!["she".to_string()]);
        assert_eq!(audit_ny.resolved_subject.as_deref(), Some("Angela Davis"));

        let chunk_ny = KgSourceChunk {
            chunk_id: "ny:1".into(),
            document_id: "ny".into(),
            file_path: "D:/Docs/bio_notes.txt".into(),
            line_start: 1,
            line_end: 3,
            access_tier: 0,
            text_content: "In New York, she published Women, Race & Class in 1981.".into(),
            metadata_json: "{}".into(),
            resolved_subject: Some("Angela Davis".into()),
        };
        let triples_ny = extractor.extract_from_chunk(&chunk_ny).unwrap();
        assert!(
            triples_ny.iter().any(|t| {
                t.entity == "Angela Davis"
                    && t.relation == "published work"
                    && t.value == "Women, Race & Class"
            }),
            "Expected Angela Davis published work triple, got {triples_ny:#?}"
        );

        // 2. Leading prepositional date/place intro before explicit subject resolves in_chunk_subject
        assert_eq!(
            infer_chunk_subject_anchor(
                "In 1969, Angela Davis taught at UCLA. She later published Women, Race & Class in 1981.",
                "{}",
                "D:/Docs/bio_notes.txt"
            )
            .as_deref(),
            Some("Angela Davis")
        );

        // 3. Single-word proper name subject must NOT be hijacked by stale fallback_subject ("Bob")
        let audit_alice = audit_chunk_self_containment(
            "Alice was born in 1990. She later published Memo in 2024.",
            Some("Bob"),
        );
        assert!(audit_alice.is_self_contained);
        assert_eq!(audit_alice.resolved_subject, None);

        let chunk_alice = KgSourceChunk {
            chunk_id: "alice:0".into(),
            document_id: "alice".into(),
            file_path: "D:/Docs/notes.txt".into(),
            line_start: 1,
            line_end: 3,
            access_tier: 0,
            text_content: "Alice was born in 1990. She later published Memo in 2024.".into(),
            metadata_json: "{}".into(),
            resolved_subject: Some("Bob".into()),
        };
        let triples_alice = extractor.extract_from_chunk(&chunk_alice).unwrap();
        assert!(
            triples_alice
                .iter()
                .any(|t| t.entity == "Alice" && t.relation == "published work" && t.value == "Memo"),
            "Expected Alice to own Memo, got {triples_alice:#?}"
        );
        assert!(
            !triples_alice.iter().any(|t| t.entity == "Bob"),
            "Stale fallback Bob must not steal Alice's work: {triples_alice:#?}"
        );

        // 4. Acronyms and non-ASCII Unicode names followed by finite verbs
        assert_eq!(
            infer_chunk_subject_anchor(
                "IBM announced a new chip. It plans major investments.",
                "{}",
                "D:/Docs/tech.txt"
            )
            .as_deref(),
            Some("IBM")
        );
        assert_eq!(
            infer_chunk_subject_anchor(
                "Élodie Laurent is a researcher. She later published Éloge in 2021.",
                "{}",
                "D:/Docs/research.txt"
            )
            .as_deref(),
            Some("Élodie Laurent")
        );
        let audit_elodie = audit_chunk_self_containment(
            "Élodie Laurent is a researcher. She later published Éloge in 2021.",
            Some("Bob"),
        );
        assert!(audit_elodie.is_self_contained);

        // 5. Quoted definite NP and numeric Markdown heading before definite NP
        let audit_quoted = audit_chunk_self_containment(
            "\"This agreement requires a security deposit of $1,850.\"",
            Some("2018 Rental Agreement"),
        );
        assert!(!audit_quoted.is_self_contained);
        assert_eq!(
            audit_quoted.unresolved_anaphors,
            vec!["this agreement".to_string()]
        );

        let audit_heading = audit_chunk_self_containment(
            "# 2018 Rental Agreement\nThis agreement requires a security deposit of $1,850.",
            Some("2018 Rental Agreement"),
        );
        assert!(!audit_heading.is_self_contained);
        assert_eq!(
            audit_heading.unresolved_anaphors,
            vec!["this agreement".to_string()]
        );

        // 6. Challenge 4a: non-generic header_title overrides cross-chunk resolved_subject for "It requires..."
        let chunk_banner_shift = KgSourceChunk {
            chunk_id: "shift:1".into(),
            document_id: "shift".into(),
            file_path: "D:/Docs/notes.txt".into(),
            line_start: 1,
            line_end: 3,
            access_tier: 0,
            text_content:
                "[Document: \"Memo\" | Author: Bob Smith | Kind: report | File: notes.txt]\nIt requires annual audits."
                    .into(),
            metadata_json: "{}".into(),
            resolved_subject: Some("Angela Davis".into()),
        };
        let triples_shift = extractor.extract_from_chunk(&chunk_banner_shift).unwrap();
        assert!(
            triples_shift.iter().any(|t| {
                t.entity == "Memo" && t.relation == "provision" && t.value == "annual audits"
            }),
            "Expected Memo provision triple, got {triples_shift:#?}"
        );
        assert!(
            !triples_shift
                .iter()
                .any(|t| t.entity == "Angela Davis" && t.relation == "provision"),
            "Cross-chunk subject Angela Davis must not hijack Memo provision: {triples_shift:#?}"
        );
    }
}
