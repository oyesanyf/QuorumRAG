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
        let (resp, citations) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
            &state.original_prompt,
            &state.current_query,
            &state.conversation_history,
            &state.retrieved_chunks,
            &state.selected_model_tag,
            telemetry_tx,
        );
        if let Some(tx) = telemetry_tx {
            // Guards (repeat removal, meta stripping, grounding) run after token streaming; push the final text so
            // the UI shows exactly what the server returns.
            let _ = DeterministicOfflineSynthesisEngine::send_telemetry(
                tx,
                AgenticTelemetryEvent::FinalAnswer { content: resp.clone() },
            );
        }
        state.synthesized_response = Some(resp);
        state.citations = citations;
    }
}
