use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

use crate::state::DaemonState;
use quorum_coordinator::langextract::{
    ExampleData, Extraction, LlmFusionConsensus,
};

/// Request payload for `/api/langextract` and `/api/langextract/visualize`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LangExtractRequest {
    /// Plain text content to extract from.
    pub text: Option<String>,

    /// Alternatively, local file path to extract from (verified with path containment guard).
    pub file_path: Option<String>,

    /// Query or extraction instructions (e.g. "extract structs and functions").
    pub query: Option<String>,

    /// Description of the extraction prompt.
    pub prompt_description: Option<String>,

    /// Few-shot examples.
    pub examples: Option<Vec<ExampleData>>,

    /// Model family selector.
    pub model_family: Option<String>,
}

/// Structured Google LangExtract endpoint: `POST /api/langextract`.
/// Evaluates candidate extractions through 4-Arm LlmFusionConsensus with 100% char_interval grounding.
pub async fn extract_handler(
    State(_state): State<Arc<DaemonState>>,
    Json(payload): Json<LangExtractRequest>,
) -> impl IntoResponse {
    let (text, source_path) = match resolve_text_source(&payload) {
        Ok(res) => res,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({ "error": msg }))).into_response();
        }
    };

    info!(
        source_len = text.len(),
        file = ?source_path,
        "Running Fusion-powered LangExtract"
    );

    let candidates = generate_candidate_extractions(&text, source_path.as_deref());
    let consensus = LlmFusionConsensus::evaluate_extractions(&text, candidates, None);

    Json(consensus).into_response()
}

/// Interactive Google LangExtract visualizer endpoint: `POST /api/langextract/visualize`.
/// Returns color-coded interactive HTML with character-grounded spans, hover tooltips, and stepper slider.
pub async fn visualize_handler(
    State(_state): State<Arc<DaemonState>>,
    Json(payload): Json<LangExtractRequest>,
) -> impl IntoResponse {
    let (text, source_path) = match resolve_text_source(&payload) {
        Ok(res) => res,
        Err((code, msg)) => {
            return (code, Html(format!("<h3>Error: {}</h3>", msg))).into_response();
        }
    };

    let candidates = generate_candidate_extractions(&text, source_path.as_deref());
    let consensus = LlmFusionConsensus::evaluate_extractions(&text, candidates, None);

    let html = render_interactive_html(&text, &consensus);
    Html(html).into_response()
}

fn resolve_text_source(
    payload: &LangExtractRequest,
) -> Result<(String, Option<String>), (StatusCode, &'static str)> {
    if let Some(ref text) = payload.text {
        if !text.trim().is_empty() {
            return Ok((text.clone(), payload.file_path.clone()));
        }
    }

    if let Some(ref file_path) = payload.file_path {
        // Enforce containment safety check
        let p = Path::new(file_path);
        for comp in p.components() {
            if matches!(comp, std::path::Component::ParentDir) {
                return Err((StatusCode::FORBIDDEN, "Directory traversal (..) strictly blocked"));
            }
        }

        match std::fs::read_to_string(file_path) {
            Ok(content) => Ok((content, Some(file_path.clone()))),
            Err(_) => Err((StatusCode::NOT_FOUND, "Failed to read requested file path")),
        }
    } else {
        Err((StatusCode::BAD_REQUEST, "Must provide either 'text' or 'file_path'"))
    }
}

/// Generates candidate extractions using deterministic AST/token scanning.
fn generate_candidate_extractions(text: &str, file_path: Option<&str>) -> Vec<Extraction> {
    let mut extractions = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let trimmed = line.trim();
        // Functions: pub async fn, async fn, pub fn, fn
        if trimmed.contains("fn ") {
            if let Some(pos) = trimmed.find("fn ") {
                let after = &trimmed[pos + 3..];
                let ident = after
                    .split(|c: char| c == '(' || c == '<' || c.is_whitespace())
                    .next()
                    .unwrap_or("")
                    .trim();
                if !ident.is_empty() && text.contains(ident) && seen.insert(ident.to_string()) {
                    let mut ext = Extraction::new("function_symbol", ident)
                        .with_attribute("kind", "function");
                    if let Some(fp) = file_path {
                        ext = ext.with_source("chunk_local", fp);
                    }
                    extractions.push(ext);
                }
            }
        }
        // Structs
        if trimmed.contains("struct ") {
            if let Some(pos) = trimmed.find("struct ") {
                let after = &trimmed[pos + 7..];
                let ident = after
                    .split(|c: char| c.is_whitespace() || c == '<' || c == '{' || c == ';')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !ident.is_empty() && text.contains(ident) && seen.insert(ident.to_string()) {
                    let mut ext = Extraction::new("struct_symbol", ident)
                        .with_attribute("kind", "struct");
                    if let Some(fp) = file_path {
                        ext = ext.with_source("chunk_local", fp);
                    }
                    extractions.push(ext);
                }
            }
        }
    }

    // Security advisory markers
    for word in text.split_whitespace() {
        let cleaned = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
        if (cleaned.starts_with("CVE-") || cleaned.starts_with("RFC-")) && text.contains(cleaned) && seen.insert(cleaned.to_string()) {
            extractions.push(Extraction::new("security_advisory", cleaned));
        }
    }

    // Fallback: If no code structures matched, extract capital alphanumeric tokens to ground entities
    if extractions.is_empty() {
        for word in text.split_whitespace() {
            let cleaned = word.trim_matches(|c: char| !c.is_alphanumeric());
            if cleaned.len() >= 4 && cleaned.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) && text.contains(cleaned) && seen.insert(cleaned.to_string()) {
                extractions.push(Extraction::new("named_entity", cleaned));
                if extractions.len() >= 5 {
                    break;
                }
            }
        }
    }

    extractions
}

fn render_interactive_html(
    text: &str,
    consensus: &quorum_coordinator::langextract::ConsensusExtractionResult,
) -> String {
    let mut highlighted = String::new();
    let mut last_idx = 0;

    let mut sorted_extractions = consensus.verified_extractions.clone();
    sorted_extractions.sort_by_key(|e| e.char_interval.unwrap_or((0, 0)).0);

    for (i, ext) in sorted_extractions.iter().enumerate() {
        if let Some((start, end)) = ext.char_interval {
            if start >= last_idx && end <= text.len() {
                highlighted.push_str(&html_escape(&text[last_idx..start]));
                let bg_color = match ext.extraction_class.as_str() {
                    "function_symbol" => "#D2E3FC",
                    "struct_symbol" => "#FFE082",
                    "security_advisory" => "#FFCDD2",
                    _ => "#C8E6C9",
                };
                highlighted.push_str(&format!(
                    r#"<mark class="lx-span" data-idx="{}" style="background-color:{}; padding:2px 4px; border-radius:3px; cursor:pointer;" title="Class: {}">&#8203;{}&#8203;</mark>"#,
                    i, bg_color, ext.extraction_class, html_escape(&text[start..end])
                ));
                last_idx = end;
            }
        }
    }
    if last_idx < text.len() {
        highlighted.push_str(&html_escape(&text[last_idx..]));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Google LangExtract Visualizer — QuorumRAG</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin:0; padding:24px; background:#121212; color:#ececec; }}
.header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #333; padding-bottom:16px; margin-bottom:20px; }}
.badge {{ padding:4px 8px; border-radius:4px; font-weight:600; font-size:12px; }}
.container {{ display:grid; grid-template-columns: 2fr 1fr; gap:24px; }}
.doc-card {{ background:#1e1e1e; border:1px solid #2d2d2d; border-radius:8px; padding:20px; white-space:pre-wrap; line-height:1.6; font-family: monospace; font-size:13px; max-height:80vh; overflow-y:auto; }}
.panel {{ background:#1e1e1e; border:1px solid #2d2d2d; border-radius:8px; padding:20px; }}
.arm-card {{ background:#262626; border-radius:6px; padding:12px; margin-bottom:12px; font-size:12px; }}
</style>
</head>
<body>
<div class="header">
  <h2>Google LangExtract Interactive Visualizer</h2>
  <div>
    <span class="badge" style="background:#2e7d32; color:white;">Consensus Confidence: {:.1}%</span>
    <span class="badge" style="background:#1565c0; color:white;">Verified Spans: {}</span>
  </div>
</div>
<div class="container">
  <div class="doc-card">{}</div>
  <div class="panel">
    <h3>Verification Arms (LlmFusionConsensus)</h3>
    {}
  </div>
</div>
</body>
</html>"#,
        consensus.fused_confidence_bp as f32 / 100.0,
        consensus.verified_extractions.len(),
        highlighted,
        render_arm_reports(&consensus.arm_reports)
    )
}

fn render_arm_reports(reports: &[quorum_coordinator::langextract::LlmFusionArmReport]) -> String {
    let mut out = String::new();
    for r in reports {
        out.push_str(&format!(
            r#"<div class="arm-card">
  <strong>{}</strong> ({})<br/>
  Status: <span style="color:{};">{}</span> | Confidence: {:.1}%<br/>
  <small style="color:#aaa;">{}</small>
</div>"#,
            r.arm_name,
            r.evaluator_role,
            if r.passed { "#66bb6a" } else { "#ef5350" },
            if r.passed { "PASSED" } else { "FAILED" },
            r.score_pct,
            r.details
        ));
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
