//! Structured Ollama Synthesis Schema (`schemars` + `serde`) & Deterministic GFM Markdown Renderer.
//!
//! Uses Ollama's native JSON Schema `format` parameter (GBNF grammar-constrained decoding) so local
//! models (`qwen2.5:7b`, `gemma4:26b`, `glm4:9b`, etc.) emit strongly typed, exhaustive synthesis
//! payloads that Rust renders deterministically into clean GitHub Flavored Markdown:
//! - Zero raw document walls dumped inline in prose
//! - Zero malformed or unbalanced `**bold**` markers
//! - Zero echoed raw query strings in headings
//! - Zero content reduction: every grounded fact, clause, date, address, financial term, theme,
//!   and document `[1]..[N]` is preserved in structured narrative sections + real GFM tables +
//!   expandable `<details>` verified document excerpts.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use quorum_types::ScoredChunk;
use regex::Regex;
use schemars::gen::SchemaGenerator;
use schemars::schema::{InstanceType, Metadata, ObjectValidation, Schema, SchemaObject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn schema_with_desc(schema: Schema, description: &str) -> Schema {
    let mut obj = schema.into_object();
    obj.metadata = Some(Box::new(Metadata {
        description: Some(description.to_string()),
        ..Default::default()
    }));
    Schema::Object(obj)
}

/// A single grounded factual attribute extracted strictly from the retrieved documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredKeyFact {
    /// Short category label, e.g. "Research & Scholarship", "Role", "Addresses", "Financial Terms", "Dates", "Board Members".
    pub category: String,
    /// Complete, unabbreviated grounded detail (never truncated mid-word or mid-number).
    pub detail: String,
    /// 1-indexed source citation numbers matching Reference Excerpts `[1]..[N]`.
    #[serde(default)]
    pub citations: Vec<usize>,
}

impl JsonSchema for StructuredKeyFact {
    fn schema_name() -> String {
        "StructuredKeyFact".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut object = ObjectValidation::default();
        object.properties.insert(
            "category".to_string(),
            schema_with_desc(
                gen.subschema_for::<String>(),
                "Short category label such as Research & Scholarship, Role, Addresses, Financial Terms, Dates, or Board Members.",
            ),
        );
        object.properties.insert(
            "detail".to_string(),
            schema_with_desc(
                gen.subschema_for::<String>(),
                "Complete, unabbreviated grounded detail extracted strictly from retrieved documents.",
            ),
        );
        object.properties.insert(
            "citations".to_string(),
            schema_with_desc(
                gen.subschema_for::<Vec<usize>>(),
                "1-indexed source citation numbers matching Reference Excerpts [1]..[N].",
            ),
        );
        object.required.insert("category".to_string());
        object.required.insert("detail".to_string());
        object.required.insert("citations".to_string());
        object.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(object)),
            ..Default::default()
        })
    }
}

/// Summary row for a single attested source document inside a domain table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredSummaryRow {
    /// 1-indexed citation number `[1]..[N]`.
    pub ref_num: usize,
    /// Exact source document filename.
    pub document_name: String,
    /// Complete one-sentence grounded summary of what this document establishes.
    pub summary: String,
}

impl JsonSchema for StructuredSummaryRow {
    fn schema_name() -> String {
        "StructuredSummaryRow".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut object = ObjectValidation::default();
        object.properties.insert(
            "ref_num".to_string(),
            schema_with_desc(
                gen.subschema_for::<usize>(),
                "1-indexed citation number [1]..[N].",
            ),
        );
        object.properties.insert(
            "document_name".to_string(),
            schema_with_desc(
                gen.subschema_for::<String>(),
                "Exact source document filename.",
            ),
        );
        object.properties.insert(
            "summary".to_string(),
            schema_with_desc(
                gen.subschema_for::<String>(),
                "Complete one-sentence grounded summary of what this document establishes.",
            ),
        );
        object.required.insert("ref_num".to_string());
        object.required.insert("document_name".to_string());
        object.required.insert("summary".to_string());
        object.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(object)),
            ..Default::default()
        })
    }
}

/// A thematic or disambiguated entity domain section with exhaustive prose, key facts, and table rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredDomainSection {
    /// Clean domain or identity heading (never echo the raw user question).
    pub section_title: String,
    /// Exhaustive, flowing multi-paragraph analytical prose covering EVERY source document and concrete
    /// detail in this section with inline `[N]` citations (no content reduction or brevity shortcuts).
    pub narrative_paragraphs: Vec<String>,
    /// Grounded factual highlights extracted strictly from this section's documents.
    #[serde(default)]
    pub key_facts: Vec<StructuredKeyFact>,
    /// Per-document summary entries for this section.
    #[serde(default)]
    pub document_table: Vec<StructuredSummaryRow>,
}

impl JsonSchema for StructuredDomainSection {
    fn schema_name() -> String {
        "StructuredDomainSection".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut object = ObjectValidation::default();
        object.properties.insert(
            "section_title".to_string(),
            schema_with_desc(
                gen.subschema_for::<String>(),
                "Clean domain or identity heading (never echo the raw user question).",
            ),
        );
        object.properties.insert(
            "narrative_paragraphs".to_string(),
            schema_with_desc(
                gen.subschema_for::<Vec<String>>(),
                "Exhaustive multi-paragraph analytical prose covering every source document and concrete detail with inline [N] citations.",
            ),
        );
        object.properties.insert(
            "key_facts".to_string(),
            schema_with_desc(
                gen.subschema_for::<Vec<StructuredKeyFact>>(),
                "Grounded factual highlights extracted strictly from this section's documents.",
            ),
        );
        object.properties.insert(
            "document_table".to_string(),
            schema_with_desc(
                gen.subschema_for::<Vec<StructuredSummaryRow>>(),
                "Per-document summary entries for this section.",
            ),
        );
        object.required.insert("section_title".to_string());
        object.required.insert("narrative_paragraphs".to_string());
        object.required.insert("key_facts".to_string());
        object.required.insert("document_table".to_string());
        object.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(object)),
            ..Default::default()
        })
    }
}

/// Top-level structured synthesis response enforced by Ollama's native `format` JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredSynthesisResponse {
    /// Direct, thorough multi-sentence overview answering every part of the user's question with inline `[N]` citations.
    pub direct_answer: String,
    /// Distinct domain or identity sections containing full exhaustive synthesis.
    #[serde(default)]
    pub sections: Vec<StructuredDomainSection>,
    /// All 1-indexed source citation numbers `[1]..[N]` covered by this response.
    #[serde(default)]
    pub cited_sources: Vec<usize>,
}

impl JsonSchema for StructuredSynthesisResponse {
    fn schema_name() -> String {
        "StructuredSynthesisResponse".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut object = ObjectValidation::default();
        object.properties.insert(
            "direct_answer".to_string(),
            schema_with_desc(
                gen.subschema_for::<String>(),
                "Direct, thorough multi-sentence overview answering every part of the user's question with inline [N] citations.",
            ),
        );
        object.properties.insert(
            "sections".to_string(),
            schema_with_desc(
                gen.subschema_for::<Vec<StructuredDomainSection>>(),
                "Distinct domain or identity sections containing full exhaustive synthesis.",
            ),
        );
        object.properties.insert(
            "cited_sources".to_string(),
            schema_with_desc(
                gen.subschema_for::<Vec<usize>>(),
                "All 1-indexed source citation numbers [1]..[N] covered by this response.",
            ),
        );
        object.required.insert("direct_answer".to_string());
        object.required.insert("sections".to_string());
        object.required.insert("cited_sources".to_string());
        object.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(object)),
            ..Default::default()
        })
    }
}

/// Returns the JSON Schema value passed to Ollama's `/api/chat` `"format"` field so the model
/// decodes under a strict GBNF grammar.
pub fn ollama_response_json_schema() -> serde_json::Value {
    static SCHEMA: OnceLock<serde_json::Value> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            let settings = schemars::gen::SchemaSettings::draft07().with(|s| {
                s.inline_subschemas = true;
            });
            let generator = settings.into_generator();
            let root = generator.into_root_schema_for::<StructuredSynthesisResponse>();
            serde_json::to_value(&root).unwrap_or_else(|_| serde_json::json!("json"))
        })
        .clone()
}

/// Parses raw Ollama structured output (either pure JSON or fenced ` ```json ... ``` `)
/// into a validated `StructuredSynthesisResponse`.
pub fn parse_structured_response(raw: &str) -> Option<StructuredSynthesisResponse> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate = if let Some(rest) = trimmed.strip_prefix("```json") {
        rest.trim().trim_end_matches("```").trim()
    } else if let Some(rest) = trimmed.strip_prefix("```") {
        rest.trim().trim_end_matches("```").trim()
    } else {
        trimmed
    };

    if let Ok(parsed) = serde_json::from_str::<StructuredSynthesisResponse>(candidate) {
        if !parsed.direct_answer.trim().is_empty() || !parsed.sections.is_empty() {
            return Some(parsed);
        }
    }

    // Tolerate leading/trailing chatter around the outermost JSON object
    if let (Some(start), Some(end)) = (candidate.find('{'), candidate.rfind('}')) {
        if end > start {
            if let Ok(parsed) =
                serde_json::from_str::<StructuredSynthesisResponse>(&candidate[start..=end])
            {
                if !parsed.direct_answer.trim().is_empty() || !parsed.sections.is_empty() {
                    return Some(parsed);
                }
            }
        }
    }

    None
}

/// Repairs unbalanced Markdown `**` bold delimiters line-by-line so a stray `**` from an
/// extracted document chunk never bleeds bold styling across paragraphs or citations (`[6]**`).
pub fn balance_markdown_emphasis(input: &str) -> String {
    let mut out_lines: Vec<String> = Vec::new();
    for line in input.lines() {
        let mut s = line.to_string();
        // Remove malformed trailing `**` immediately attached to citations like `[6]**` when unmatched
        let bold_count = s.matches("**").count();
        if bold_count % 2 != 0 {
            if let Some(pos) = s.rfind("**") {
                s.replace_range(pos..pos + 2, "");
            }
        }
        // Also collapse accidental empty `****` artifacts
        while s.contains("****") {
            s = s.replace("****", "");
        }
        out_lines.push(s);
    }
    out_lines.join("\n")
}

/// Strips raw Word/ODT `HYPERLINK "..."` field codes, `MERGEFORMAT` instructions, and decorative
/// underscore signature rules (`________`) even from previously indexed chunks.
pub fn strip_extraction_field_artifacts(input: &str) -> String {
    static HYPERLINK_RE: OnceLock<Regex> = OnceLock::new();
    static FIELD_RE: OnceLock<Regex> = OnceLock::new();
    static UNDERSCORE_RE: OnceLock<Regex> = OnceLock::new();
    static SPLIT_YEAR_RE: OnceLock<Regex> = OnceLock::new();
    static SPLIT_ORDINAL_RE: OnceLock<Regex> = OnceLock::new();

    let hyperlink_re = HYPERLINK_RE.get_or_init(|| {
        Regex::new(r#"(?i)\bHYPERLINK\s+"[^"]*"(?:\s+\\[a-z]\s+"[^"]*")*\s*"#)
            .expect("valid hyperlink regex")
    });
    let field_re = FIELD_RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:MERGEFORMAT|PAGEREF\s+\S+|REF\s+_Ref\S+)\b"#)
            .expect("valid field regex")
    });
    let underscore_re = UNDERSCORE_RE
        .get_or_init(|| Regex::new(r"_{4,}").expect("valid underscore regex"));
    let split_year_re = SPLIT_YEAR_RE
        .get_or_init(|| Regex::new(r"\b(19|20)(\d)\s+(\d)\b").expect("valid split year regex"));
    let split_ord_re = SPLIT_ORDINAL_RE
        .get_or_init(|| Regex::new(r"\b(\d+)\s+(st|nd|rd|th)\b").expect("valid split ordinal regex"));

    let s1 = hyperlink_re.replace_all(input, "");
    let s2 = field_re.replace_all(&s1, "");
    let s3 = underscore_re.replace_all(&s2, " ");
    let s4 = split_year_re.replace_all(&s3, "$1$2$3");
    let s5 = split_ord_re.replace_all(&s4, "$1$2");
    s5.into_owned()
}

/// Strips ChatGPT export conversational chrome (`You said:`, `Would you like this in Word or PDF format...`,
/// `Waiting for ppaper`, `Just let me know! Post here, please`) while preserving all real document content.
pub fn strip_chatgpt_export_chatter(input: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut prev_norm = String::new();
    for line in input.lines() {
        let t = line.trim();
        if t.is_empty() {
            if kept.last().map(|l| !l.is_empty()).unwrap_or(false) {
                kept.push("");
            }
            continue;
        }
        let tl = t.to_ascii_lowercase();
        let is_chrome = tl == "you said:"
            || tl == "chatgpt said:"
            || tl == "assistant:"
            || tl == "user:"
            || tl == "waiting for ppaper"
            || tl == "waiting for paper"
            || tl.starts_with("would you like this in word or pdf format")
            || tl.starts_with("just let me know! post here")
            || tl.starts_with("anything in this thread about")
            || tl.starts_with("no. this thread only contains")
            || tl.starts_with("here’s the plan:")
            || tl.starts_with("here's the plan:")
            || tl.starts_with("i am now ready to write your")
            || tl.starts_with("can you do this? no poetry or prose")
            || tl.starts_with("certainly, ")
            || tl.starts_with("absolutely, ")
            || tl.starts_with("thank you for your patience, ");
        if is_chrome {
            continue;
        }
        // Deduplicate immediately repeated identical lines (e.g. duplicated prompt drafts)
        let norm = tl.split_whitespace().collect::<Vec<_>>().join(" ");
        if norm.len() >= 24 && norm == prev_norm {
            continue;
        }
        prev_norm = norm;
        kept.push(t);
    }
    kept.join("\n").trim().to_string()
}

/// Heals broken mid-word or mid-number leading chunk stubs (such as `,000. Ventilation...`,
/// `bject lessons)`, `Gela Davis ...`, `Ant agrees ...`, `Er, and report ...`, `Rd will provide ...`,
/// `S to maintain ...`, `Om xylitol ...`) by advancing cleanly to the next complete sentence or clause.
pub fn heal_leading_fragment(input: &str) -> String {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return String::new();
    }

    let first_ch = trimmed.chars().next().unwrap_or(' ');
    let first_word = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| !c.is_alphanumeric());

    let looks_truncated_start =
        // Starts with comma/closing paren/semicolon/colon (e.g., `,000.`, `) and...`)
        matches!(first_ch, ',' | ';' | ':' | ')' | ']' | '}')
        // Starts with a lowercase fragment word like `bject lessons)` or `stitution of eviction`
        || (first_ch.is_ascii_lowercase() && !matches!(
            first_word,
            "a" | "an" | "the" | "in" | "on" | "at" | "to" | "for" | "with" | "by" | "of"
                | "and" | "or" | "but" | "if" | "is" | "was" | "are" | "were" | "this"
                | "that" | "these" | "those" | "she" | "he" | "they" | "we" | "you" | "it"
        ))
        // Starts with a 1-2 char uppercase fragment followed by lowercase/comma (`Er,`, `Rd `, `S `, `Le `, `Om `)
        || (first_word.len() <= 2
            && first_ch.is_ascii_uppercase()
            && !matches!(
                first_word,
                "A" | "I" | "Dr" | "Mr" | "Ms" | "No" | "In" | "On" | "At" | "To" | "By"
                    | "Of" | "An" | "As" | "If" | "It" | "We" | "He" | "My" | "Or" | "So"
                    | "Up" | "US" | "UK" | "LA" | "NC" | "TX" | "NY" | "AC" | "AI" | "IT"
            )
            && trimmed.len() > 25);

    if !looks_truncated_start {
        return trimmed.to_string();
    }

    // Try advancing to the next clean sentence start (`. `, `! `, `? `, or `\n`) within the first 180 chars
    let limit = trimmed.len().min(200);
    let mut safe_limit = limit;
    while safe_limit > 0 && !trimmed.is_char_boundary(safe_limit) {
        safe_limit -= 1;
    }
    let head = &trimmed[..safe_limit];
    for delim in ["\n", ". ", "! ", "? "] {
        if let Some(pos) = head.find(delim) {
            let after = trimmed[pos + delim.len()..].trim_start();
            if after.len() >= 24 {
                return after.to_string();
            }
        }
    }

    // Otherwise drop just the broken leading punctuation/stub token if substantial text remains
    if let Some(ws) = trimmed.find(char::is_whitespace) {
        let rest = trimmed[ws..].trim_start();
        if rest.len() >= 24 && !matches!(first_ch, 'A'..='Z') {
            return rest.to_string();
        }
    }

    trimmed.to_string()
}

/// Escapes Markdown table cell values and prevents empty cells.
fn clean_table_cell(raw: &str, fallback: &str) -> String {
    let cleaned = balance_markdown_emphasis(&strip_extraction_field_artifacts(raw))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|");
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/// Renders a validated `StructuredSynthesisResponse` into clean, exhaustive GFM Markdown
/// with zero content reduction:
/// 1. Direct overview answering every clause of the question
/// 2. Per-domain sections with structured key facts + exhaustive multi-paragraph prose
/// 3. Single unified `### Identity & Domain Cluster Summary` GFM table covering all cited docs
/// 4. Optional collapsible `<details>` Verified Document Excerpts drawer preserving full cleaned source text.
pub fn render_structured_response_markdown(
    resp: &StructuredSynthesisResponse,
    docs: &[&ScoredChunk],
    include_evidence_drawer: bool,
) -> String {
    let max_cite = docs.len().max(1);
    let mut md = String::new();

    // 1. Direct answer overview
    let direct = balance_markdown_emphasis(&strip_extraction_field_artifacts(resp.direct_answer.trim()));
    if !direct.is_empty() {
        md.push_str(&direct);
        md.push_str("\n\n");
    }

    // Track document summaries across sections so we emit one clean unified summary table (no 2x duplication)
    let mut table_rows: Vec<(usize, String, String, String)> = Vec::new();
    let mut seen_table_refs: BTreeSet<usize> = BTreeSet::new();

    // 2. Domain sections with exhaustive narrative prose + structured key facts
    for sec in &resp.sections {
        let title = balance_markdown_emphasis(sec.section_title.trim());
        if !title.is_empty() {
            md.push_str(&format!("### {}\n\n", title));
        }

        if !sec.key_facts.is_empty() {
            for fact in &sec.key_facts {
                let cat = fact.category.trim();
                let det = balance_markdown_emphasis(&strip_extraction_field_artifacts(fact.detail.trim()));
                if cat.is_empty() || det.is_empty() {
                    continue;
                }
                let valid_cites: Vec<String> = fact
                    .citations
                    .iter()
                    .copied()
                    .filter(|&n| n >= 1 && n <= max_cite)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|n| format!("[{n}]"))
                    .collect();
                if valid_cites.is_empty() {
                    md.push_str(&format!("- **{}:** {}\n", cat, det));
                } else {
                    md.push_str(&format!("- **{}:** {} {}\n", cat, det, valid_cites.join(", ")));
                }
            }
            md.push('\n');
        }

        for para in &sec.narrative_paragraphs {
            let clean_p = balance_markdown_emphasis(&strip_extraction_field_artifacts(para.trim()));
            if !clean_p.is_empty() {
                md.push_str(&clean_p);
                md.push_str("\n\n");
            }
        }

        for row in &sec.document_table {
            if row.ref_num >= 1 && row.ref_num <= max_cite && seen_table_refs.insert(row.ref_num) {
                let origin = docs
                    .get(row.ref_num - 1)
                    .map(|sc| {
                        if sc.is_remote
                            && !sc.source_peer.is_empty()
                            && !sc.source_peer.eq_ignore_ascii_case("local")
                        {
                            let short: String = sc.source_peer.chars().take(12).collect();
                            format!("Mesh Peer (`{short}`)")
                        } else {
                            "Local Host".to_string()
                        }
                    })
                    .unwrap_or_else(|| "Local Host".to_string());
                let doc_name = docs
                    .get(row.ref_num - 1)
                    .map(|sc| {
                        sc.chunk
                            .file_path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or(&sc.chunk.file_path)
                            .to_string()
                    })
                    .unwrap_or_else(|| row.document_name.clone());
                let summary = if title.is_empty() {
                    clean_table_cell(&row.summary, "Grounded source record")
                } else {
                    format!(
                        "*{}* — {}",
                        clean_table_cell(&title, "Document Context"),
                        clean_table_cell(&row.summary, "Grounded source record")
                    )
                };
                table_rows.push((row.ref_num, doc_name, origin, summary));
            }
        }
    }

    // 3. Single unified GFM summary matrix (no redundant back-to-back cluster + bottom duplicate tables)
    if !table_rows.is_empty() {
        table_rows.sort_by_key(|(r, _, _, _)| *r);
        let matrix_heading = if resp.sections.len() >= 2 {
            "### Identity & Domain Cluster Summary"
        } else {
            "### Grounded Source Summary"
        };
        md.push_str(matrix_heading);
        md.push_str("\n\n| Ref | Source Document | Origin Node | Grounded Context Summary |\n");
        md.push_str("|---|---|---|---|\n");
        for (ref_num, doc_name, origin, summary) in &table_rows {
            md.push_str(&format!(
                "| **[{}]** | `{}` | {} | {} |\n",
                ref_num,
                doc_name.replace('|', "\\|"),
                origin,
                summary
            ));
        }
        md.push('\n');
    }

    // 4. Collapsible Verified Document Excerpts drawer (preserves 100% of full cleaned source text without clutter)
    if include_evidence_drawer && !docs.is_empty() {
        md.push_str(&format!(
            "<details>\n<summary>Verified Document Excerpts ({} sources)</summary>\n\n",
            docs.len()
        ));
        for (idx, sc) in docs.iter().enumerate() {
            let doc_name = sc
                .chunk
                .file_path
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&sc.chunk.file_path);
            let cleaned = balance_markdown_emphasis(&heal_leading_fragment(
                &strip_chatgpt_export_chatter(&strip_extraction_field_artifacts(
                    &crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
                        &sc.chunk.text_content,
                    ),
                )),
            ));
            if cleaned.trim().is_empty() {
                continue;
            }
            md.push_str(&format!(
                "#### [{}] `{}`\n\n{}\n\n",
                idx + 1,
                doc_name,
                cleaned.trim()
            ));
        }
        md.push_str("</details>\n");
    }

    md.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_types::DocumentChunk;

    fn make_chunk(id: &str, path: &str, text: &str) -> ScoredChunk {
        ScoredChunk {
            chunk: DocumentChunk::new(id, id, path, 1, 10, 0, vec![0.0; 8], text, Some("{}".to_string()))
                .expect("test DocumentChunk"),
            score: 0.95,
            source_peer: "local".to_string(),
            is_remote: false,
        }
    }

    #[test]
    fn test_schemars_json_schema_generation_and_roundtrip() {
        let schema = ollama_response_json_schema();
        let schema_str = schema.to_string();
        assert!(schema_str.contains("direct_answer"));
        assert!(schema_str.contains("narrative_paragraphs"));
        assert!(schema_str.contains("key_facts"));
        assert!(schema_str.contains("document_table"));

        let sample = serde_json::json!({
            "direct_answer": "The corpus references multiple distinct Angela Davis records across academic scholarship and property leasing [1], [2].",
            "sections": [
                {
                    "section_title": "Academic Scholarship, Published Works & Critical Theory",
                    "narrative_paragraphs": [
                        "Women, Race & Class (1981) by Angela Davis analyzes the intersection of race, gender, slavery, abolition, suffrage, labor movements, and reproductive justice across American history [1]."
                    ],
                    "key_facts": [
                        {
                            "category": "Published Work",
                            "detail": "Women, Race & Class (1981) — intersectional analysis of race, gender, and class",
                            "citations": [1]
                        }
                    ],
                    "document_table": [
                        {
                            "ref_num": 1,
                            "document_name": "Women Race Class Summary.docx",
                            "summary": "Summarizes Angela Davis's 1981 critical theory work Women, Race & Class."
                        }
                    ]
                },
                {
                    "section_title": "Residential Property Leasing & Real Estate Management",
                    "narrative_paragraphs": [
                        "Firldeal (Angela Davis) Breure leased 2913 1/2 Castiglione St., New Orleans, LA 70119 with a $195.00 late fee after the third day of the month [2]."
                    ],
                    "key_facts": [
                        {
                            "category": "Address",
                            "detail": "2913 1/2 Castiglione St., New Orleans, LA 70119",
                            "citations": [2]
                        }
                    ],
                    "document_table": [
                        {
                            "ref_num": 2,
                            "document_name": "Aerial's LEase.odt",
                            "summary": "Residential lease agreement listing Angela Davis as landlord with $195.00 late fee."
                        }
                    ]
                }
            ],
            "cited_sources": [1, 2]
        });

        let parsed = parse_structured_response(&sample.to_string()).expect("must parse");
        let c1 = make_chunk("c1", "D:/Docs/Women Race Class Summary.docx", "Women, Race & Class (1981) examines race, gender, and class.");
        let c2 = make_chunk("c2", "D:/Docs/Aerial's LEase.odt", "HYPERLINK \"mailto:firldeal@gmail.com\" firldeal@gmail.com 2913 Castiglione St.");
        let refs = [&c1, &c2];
        let rendered = render_structured_response_markdown(&parsed, &refs, true);

        assert!(rendered.contains("### Academic Scholarship, Published Works & Critical Theory"));
        assert!(rendered.contains("### Identity & Domain Cluster Summary"));
        assert!(rendered.contains("| **[1]** | `Women Race Class Summary.docx` | Local Host |"));
        assert!(rendered.contains("<details>\n<summary>Verified Document Excerpts (2 sources)</summary>"));
        assert!(!rendered.contains("HYPERLINK"));
        assert!(rendered.contains("firldeal@gmail.com"));
    }

    #[test]
    fn test_strip_hyperlink_heal_fragments_and_balance_bold() {
        let raw = r#"Contact Angela Davis at HYPERLINK "mailto:firldeal@gmail.com" firldeal@gmail.com. ____(Initials) 201 9 1 st"#;
        let cleaned = strip_extraction_field_artifacts(raw);
        assert!(!cleaned.contains("HYPERLINK"));
        assert!(cleaned.contains("firldeal@gmail.com"));
        assert!(!cleaned.contains("____"));
        assert!(cleaned.contains("2019"));
        assert!(cleaned.contains("1st"));

        assert_eq!(
            heal_leading_fragment(",000. Ventilation cleaning expansion is under evaluation for increased profitability."),
            "Ventilation cleaning expansion is under evaluation for increased profitability."
        );
        assert_eq!(
            heal_leading_fragment("Er, and report any necessary repairs. Tenant agrees to maintain property cleanly."),
            "Tenant agrees to maintain property cleanly."
        );

        let unbalanced = "Proposal to form an official company board** within six months.";
        assert_eq!(
            balance_markdown_emphasis(unbalanced),
            "Proposal to form an official company board within six months."
        );
    }
}
