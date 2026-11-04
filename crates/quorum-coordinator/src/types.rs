use quorum_storage::SearchMode;
use quorum_types::{Citation, ScoredChunk, VolatileRemoteChunk};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

/// Unique identifiers for the agentic state machine nodes (LangGraph in Rust).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgenticStateName {
    ClassifyIntent,
    RetrieveMesh,
    GradeRelevance,
    RewriteQuery,
    SynthesizeWithCitations,
    Complete,
    Failed,
}

/// High-level classification of user query intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryIntentType {
    /// General knowledge or conversational QA (retrieval optional/empty)
    GeneralConversation,
    /// Targeted local file or code query
    LocalDocumentSearch,
    /// Cross-node federated mesh query
    FederatedMeshSearch,
    /// Complex multi-hop comparative reasoning across sources
    MultiHopReasoning,
}

/// Relevance assessment output from GradeRelevance node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelevanceGrade {
    pub is_relevant: bool,
    pub score: f32, // 0.0 .. 1.0
    pub reasoning: String,
    pub satisfactory: bool,
}

/// Synthesis model family options for GLM & ModelFusion routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisModelFamily {
    #[default]
    #[serde(alias = "Glm4Agentic", alias = "glm4", alias = "glm-4")]
    Glm4Agentic,
    #[serde(alias = "Qwen25Code", alias = "qwen", alias = "qwen2.5")]
    Qwen25Code,
    #[serde(alias = "GemmaProse", alias = "gemma", alias = "gemma3")]
    GemmaProse,
    #[serde(alias = "Gemma4_26b", alias = "gemma4:26b", alias = "gemma4")]
    Gemma4_26b,
    #[serde(alias = "AutoFusion")]
    AutoFusion,
}

/// A single turn in a multi-turn conversation (`role`: `"user"` or `"assistant"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatTurnMessage {
    pub role: String,
    pub content: String,
}

/// Full state context propagated through the agentic graph nodes.
#[derive(Debug)]
pub struct AgenticGraphState {
    pub session_id: Uuid,
    pub original_prompt: String,
    pub current_query: String,
    pub query_history: Vec<String>,
    pub conversation_history: Vec<ChatTurnMessage>,
    pub hop_count: usize,
    pub max_hops: usize, // default: 3
    pub intent: Option<QueryIntentType>,
    pub search_mode: SearchMode,
    pub model_family: SynthesisModelFamily,
    pub selected_model_tag: String,
    pub routing_rationale: String,
    pub retrieved_chunks: Vec<ScoredChunk>,
    pub volatile_chunks: Vec<VolatileRemoteChunk>,
    pub relevance_grade: Option<RelevanceGrade>,
    pub relevance_score: f32,
    pub start_time: Instant,
    pub synthesized_response: Option<String>,
    pub citations: Vec<Citation>,
    pub query_metadata_filters: Option<std::collections::BTreeMap<String, String>>,
    pub cached_vector_hits: Vec<ScoredChunk>,
    pub langextract_result: Option<crate::langextract::ConsensusExtractionResult>,
    pub extracted_questions: Vec<String>,
    pub extracted_entities: Vec<crate::langextract::Extraction>,
    pub seen_chunk_ids: std::collections::HashSet<String>,
}

impl AgenticGraphState {
    pub fn new(prompt: &str, model_family: SynthesisModelFamily, max_hops: usize) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            original_prompt: prompt.to_string(),
            current_query: prompt.to_string(),
            query_history: vec![prompt.to_string()],
            conversation_history: Vec::new(),
            hop_count: 0,
            max_hops,
            intent: None,
            search_mode: SearchMode::Hybrid,
            model_family,
            selected_model_tag: String::new(),
            routing_rationale: String::new(),
            retrieved_chunks: Vec::new(),
            volatile_chunks: Vec::new(),
            relevance_grade: None,
            relevance_score: 0.0,
            start_time: Instant::now(),
            synthesized_response: None,
            citations: Vec::new(),
            query_metadata_filters: None,
            cached_vector_hits: Vec::new(),
            langextract_result: None,
            extracted_questions: Vec::new(),
            extracted_entities: Vec::new(),
            seen_chunk_ids: std::collections::HashSet::new(),
        }
    }

    /// Attaches previously seen chunk IDs from prior conversation turns to filter out redundant passages.
    pub fn with_seen_chunks(mut self, seen: std::collections::HashSet<String>) -> Self {
        self.seen_chunk_ids = seen;
        self
    }

    /// Attaches prior multi-turn conversation messages and expands `current_query` for follow-up coreference resolution.
    pub fn with_conversation_history(mut self, history: Vec<ChatTurnMessage>) -> Self {
        if !history.is_empty() {
            let expanded = Self::expand_followup_query(&self.original_prompt, &history);
            if expanded != self.original_prompt {
                self.current_query = expanded.clone();
                self.query_history.push(expanded);
            }
        }
        self.conversation_history = history;
        self
    }

    /// Resolves pronouns and short follow-up questions by appending salient subject terms from prior user turns.
    pub fn expand_followup_query(prompt: &str, history: &[ChatTurnMessage]) -> String {
        if history.is_empty() {
            return prompt.to_string();
        }
        const PRONOUNS_AND_FOLLOWUPS: &[&str] = &[
            "he", "him", "his", "she", "her", "hers", "they", "them", "their", "theirs",
            "it", "its", "that", "this", "these", "those", "more", "else",
            "also", "elaborate", "expand", "further", "detail", "details", "continue",
        ];
        const STOPWORDS: &[&str] = &[
            "what", "does", "do", "did", "where", "when", "who", "how", "why",
            "is", "are", "was", "were", "the", "and", "for", "with", "from",
            "into", "about", "using", "have", "has", "had", "will", "would",
            "should", "could", "can", "you", "tell", "show", "please", "give",
            "me", "on", "in", "of", "to", "a", "an", "there", "file", "files",
            "document", "documents", "content", "contents", "folder", "folders",
        ];

        let words: Vec<String> = prompt
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_ascii_lowercase())
            .collect();

        let has_followup_marker = words
            .iter()
            .any(|w| PRONOUNS_AND_FOLLOWUPS.contains(&w.as_str()));
        let specific_entity_count = words
            .iter()
            .filter(|w| {
                w.len() >= 3
                    && !STOPWORDS.contains(&w.as_str())
                    && !PRONOUNS_AND_FOLLOWUPS.contains(&w.as_str())
                    && !crate::agentic::retrieve::GENERIC_ATTRIBUTE_TERMS.contains(&w.as_str())
            })
            .count();

        // If the query has no pronouns/follow-up markers and already names a specific entity (e.g. "WHAT REDACTX"),
        // treat it as a standalone topic query and do not pollute it with prior turns.
        if !has_followup_marker && specific_entity_count >= 1 {
            return prompt.to_string();
        }

        // Collect salient subject keywords from the most recent user turn in history that has specific entities
        let mut prior_terms: Vec<String> = Vec::new();
        for msg in history
            .iter()
            .rev()
            .filter(|m| m.role.eq_ignore_ascii_case("user"))
            .take(3)
        {
            for token in msg.content.split(|c: char| !c.is_alphanumeric()) {
                let low = token.trim().to_ascii_lowercase();
                if low.len() >= 3
                    && !STOPWORDS.contains(&low.as_str())
                    && !PRONOUNS_AND_FOLLOWUPS.contains(&low.as_str())
                    && !crate::agentic::retrieve::GENERIC_ATTRIBUTE_TERMS.contains(&low.as_str())
                    && !words.contains(&low)
                    && !prior_terms.contains(&low)
                {
                    prior_terms.push(low);
                }
            }
            if !prior_terms.is_empty() {
                break;
            }
        }

        if prior_terms.is_empty() {
            prompt.to_string()
        } else {
            let context_suffix = prior_terms.into_iter().take(6).collect::<Vec<_>>().join(" ");
            format!("{} ({})", prompt.trim(), context_suffix)
        }
    }
}
