use crate::hardware::HardwareTelemetry;
use crate::model_router::AutoFusionRouter;
use crate::types::{AgenticGraphState, QueryIntentType};

pub struct ClassifyIntentNode;

impl ClassifyIntentNode {
    pub fn execute(state: &mut AgenticGraphState, hw: &HardwareTelemetry) {
        let lower = state.original_prompt.to_lowercase();
        let is_continuation = crate::offline_engine::DeterministicOfflineSynthesisEngine::is_continuation_query(&lower);

        if is_continuation {
            // Locate the last non-continuation user query from history
            if let Some(last_user_turn) = state.conversation_history.iter().rev().find(|t| {
                t.role.eq_ignore_ascii_case("user")
                    && !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_continuation_query(&t.content.to_ascii_lowercase())
            }) {
                state.current_query = last_user_turn.content.clone();
            } else {
                // Extract key terms from prior history turns
                let mut terms = Vec::new();
                for turn in state.conversation_history.iter().rev() {
                    for word in turn.content.split(|c: char| !c.is_alphanumeric() && c != '_') {
                        let w = word.trim().to_ascii_lowercase();
                        if w.len() >= 4 && !crate::agentic::retrieve::GENERIC_ATTRIBUTE_TERMS.contains(&w.as_str()) && !terms.contains(&w) {
                            terms.push(w);
                            if terms.len() >= 6 {
                                break;
                            }
                        }
                    }
                    if !terms.is_empty() {
                        break;
                    }
                }
                if !terms.is_empty() {
                    state.current_query = terms.join(" ");
                }
            }
        }

        let is_multi_hop = lower.contains("compare")
            || lower.contains("difference")
            || lower.contains("versus")
            || lower.contains("vs ")
            || lower.contains("relationship");

        let is_mesh = lower.contains("mesh")
            || lower.contains("network")
            || lower.contains("federated")
            || lower.contains("all peers");

        let is_conversation = lower.starts_with("hello")
            || lower.starts_with("hi ")
            || lower == "hi"
            || lower.starts_with("who are you")
            || lower.starts_with("what can you do");

        let intent = if is_conversation {
            QueryIntentType::GeneralConversation
        } else if is_multi_hop {
            QueryIntentType::MultiHopReasoning
        } else if is_mesh {
            QueryIntentType::FederatedMeshSearch
        } else {
            QueryIntentType::LocalDocumentSearch
        };

        state.intent = Some(intent);

        // Feature 58: Google LangExtract Candidate Extraction & 4-Arm Consensus
        let text_for_extraction = if state.current_query != state.original_prompt {
            &state.current_query
        } else {
            &state.original_prompt
        };

        let candidates = crate::langextract::extraction::extract_chat_candidates(text_for_extraction);
        let consensus = crate::langextract::LlmFusionConsensus::evaluate_extractions(
            text_for_extraction,
            candidates,
            Some(state),
        );

        let mut verified_questions = Vec::new();
        let mut verified_entities = Vec::new();

        for ext in &consensus.verified_extractions {
            if ext.extraction_class == "question" {
                verified_questions.push(ext.extraction_text.clone());
            } else {
                verified_entities.push(ext.clone());
            }
        }

        if verified_questions.is_empty() && !state.original_prompt.trim().is_empty() {
            verified_questions.push(state.original_prompt.trim().to_string());
        }

        state.langextract_result = Some(consensus.clone());
        state.extracted_questions = verified_questions;
        state.extracted_entities = verified_entities;

        // Merge scalar metadata filters with LangExtract consensus attributes
        let mut combined_filters = crate::langextract::extract_query_metadata_filters(&state.original_prompt)
            .unwrap_or_default();
        for (k, v) in consensus.metadata_filters {
            combined_filters.insert(k, v);
        }
        if !combined_filters.is_empty() {
            state.query_metadata_filters = Some(combined_filters);
        }

        let requested_family = state.model_family;
        let (family, tag, rationale) = AutoFusionRouter::select_model(
            requested_family,
            &state.original_prompt,
            &state.retrieved_chunks,
            hw,
        );
        state.model_family = family;
        state.selected_model_tag = tag;
        state.routing_rationale = rationale;

        // Live daemon upgrade: when AutoFusion is active for prose/general synthesis and runtime free memory
        // satisfies the Gemma 4 26B gate, prefer `gemma4:26b` automatically if installed in local Ollama.
        if requested_family == crate::types::SynthesisModelFamily::AutoFusion
            && state.model_family != crate::types::SynthesisModelFamily::Qwen25Code
            && AutoFusionRouter::can_run_gemma4_26b(hw)
        {
            let daemon_active = crate::dlp_mesh::global_mesh_dlp_controller()
                .settings_file_path
                .read()
                .map(|p| p.is_some())
                .unwrap_or(false);
            if daemon_active {
                let installed = crate::offline_engine::DeterministicOfflineSynthesisEngine::probe_installed_ollama_models_default();
                if installed.iter().any(|m| {
                    let low = m.to_ascii_lowercase();
                    low == "gemma4:26b" || low.starts_with("gemma4:26b")
                }) {
                    state.model_family = crate::types::SynthesisModelFamily::Gemma4_26b;
                    state.selected_model_tag = "gemma4:26b".to_string();
                    state.routing_rationale = format!(
                        "AutoFusion: Gemma 4 26B installed with {:.1} GB free RAM -> gemma4:26b",
                        hw.free_ram_gb
                    );
                }
            }
        }
    }
}
