use crate::offline_engine::DeterministicOfflineSynthesisEngine;
use crate::telemetry::AgenticTelemetryEvent;
use crate::types::AgenticGraphState;
use tokio::sync::mpsc::Sender;

pub struct SynthesizeWithCitationsNode;

impl SynthesizeWithCitationsNode {
    pub fn execute(
        state: &mut AgenticGraphState,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) {
        Self::execute_draft(state, telemetry_tx);
        Self::emit_final_answer(state, telemetry_tx);
    }

    /// Populates `state.synthesized_response` and `state.citations` without emitting
    /// `AgenticTelemetryEvent::FinalAnswer` yet, allowing Stage-3 `SelfRagCritique`
    /// verification and bounded corrective synthesis to run before finalizing telemetry.
    pub fn execute_draft(
        state: &mut AgenticGraphState,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) {
        Self::execute_draft_with_note(state, None, telemetry_tx);
    }

    /// Populates `state.synthesized_response` and `state.citations` with an optional
    /// bounded corrective grounding note appended to `kg_context`.
    pub fn execute_draft_with_note(
        state: &mut AgenticGraphState,
        corrective_note: Option<&str>,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) {
        let memo_ctx = crate::memo_protocol::format_memo_synthesis_context(state);
        let mut kg_parts: Vec<&str> = Vec::new();
        if !state.atlaskv_context.trim().is_empty() {
            kg_parts.push(state.atlaskv_context.trim());
        }
        if !memo_ctx.is_empty() {
            kg_parts.push(&memo_ctx);
        }
        if let Some(note) = corrective_note {
            if !note.trim().is_empty() {
                kg_parts.push(note.trim());
            }
        }
        let effective_kg_ctx = kg_parts.join("\n\n");
        let (resp, citations) = DeterministicOfflineSynthesisEngine::synthesize_with_history_and_kg(
            &state.original_prompt,
            &state.current_query,
            &state.conversation_history,
            &state.retrieved_chunks,
            &effective_kg_ctx,
            &state.selected_model_tag,
            telemetry_tx,
        );
        state.synthesized_response = Some(resp);
        state.citations = citations;
    }

    /// Deterministically repairs an ungrounded draft using `verify_post_synthesis_groundedness`,
    /// removing unsupported claims and appending verbatim grounded excerpts for missing
    /// 1-based `missing_document_refs` without fabricating unretrieved facts.
    pub fn repair_ungrounded_draft_deterministically(
        state: &mut AgenticGraphState,
        unsupported_claims: &[String],
        missing_document_refs: &[usize],
    ) {
        let chunk_refs: Vec<&quorum_types::ScoredChunk> = state.retrieved_chunks.iter().collect();
        let current = state.synthesized_response.as_deref().unwrap_or("");
        let groundedness =
            crate::answer_orchestrator::verify_post_synthesis_groundedness(current, &chunk_refs);
        let mut repaired = if !groundedness.is_grounded && groundedness.backfill_detected {
            groundedness.sanitized_answer
        } else {
            current.to_string()
        };

        if !unsupported_claims.is_empty() {
            let lowered_claims: Vec<String> = unsupported_claims
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .filter(|c| c.len() >= 4)
                .collect();
            if !lowered_claims.is_empty() {
                let kept_lines: Vec<&str> = repaired
                    .lines()
                    .filter(|line| {
                        let low = line.to_ascii_lowercase();
                        !lowered_claims.iter().any(|c| low.contains(c))
                    })
                    .collect();
                repaired = kept_lines.join("\n").trim().to_string();
            }
        }

        let mut appended_refs = Vec::new();
        for &doc_ref in missing_document_refs {
            if doc_ref >= 1 && doc_ref <= chunk_refs.len() {
                let sc = chunk_refs[doc_ref - 1];
                if crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
                    continue;
                }
                let cleaned = DeterministicOfflineSynthesisEngine::clean_chunk_text(&sc.chunk.text_content);
                let excerpt: String = cleaned.trim().chars().take(280).collect();
                if !excerpt.is_empty() {
                    let file_name = std::path::Path::new(&sc.chunk.file_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&sc.chunk.file_path);
                    appended_refs.push(format!("- [{}] ({}) {}", doc_ref, file_name, excerpt));
                }
            }
        }
        if !appended_refs.is_empty() {
            if !repaired.is_empty() {
                repaired.push_str("\n\n");
            }
            repaired.push_str("### Grounded Source Excerpts\n");
            repaired.push_str(&appended_refs.join("\n"));
        }

        if repaired.trim().is_empty() && !chunk_refs.is_empty() {
            let fallback: Vec<String> = chunk_refs
                .iter()
                .enumerate()
                .take(3)
                .filter_map(|(i, sc)| {
                    if crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
                        return None;
                    }
                    let excerpt: String = DeterministicOfflineSynthesisEngine::clean_chunk_text(&sc.chunk.text_content)
                        .trim()
                        .chars()
                        .take(280)
                        .collect();
                    if excerpt.is_empty() {
                        None
                    } else {
                        Some(format!("- [{}] {}", i + 1, excerpt))
                    }
                })
                .collect();
            if !fallback.is_empty() {
                repaired = fallback.join("\n");
            }
        }

        if !chunk_refs.is_empty() {
            crate::rlm_orchestrator::RlmOrchestrator::verify_and_attach_verbatim_grounding(
                &state.original_prompt,
                &repaired,
                &chunk_refs,
                &mut state.citations,
            );
        }
        state.synthesized_response = Some(repaired);
    }

    /// Emits `AgenticTelemetryEvent::FinalAnswer` once post-synthesis grounding checks settle.
    pub fn emit_final_answer(
        state: &AgenticGraphState,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) {
        if let (Some(tx), Some(ref resp)) = (telemetry_tx, &state.synthesized_response) {
            let _ = DeterministicOfflineSynthesisEngine::send_telemetry(
                tx,
                AgenticTelemetryEvent::FinalAnswer {
                    content: resp.clone(),
                },
            );
        }
    }
}
