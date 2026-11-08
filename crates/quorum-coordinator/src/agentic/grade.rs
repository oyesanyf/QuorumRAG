use crate::types::{AgenticGraphState, RelevanceGrade};
use std::collections::HashSet;

pub struct GradeRelevanceNode {
    pub relevance_threshold: f32,
}

impl Default for GradeRelevanceNode {
    fn default() -> Self {
        Self {
            relevance_threshold: 0.60,
        }
    }
}

impl GradeRelevanceNode {
    /// Determines whether any retrieved chunk contains significant query terms from the prompt.
    pub fn has_content_relevance(prompt: &str, chunks: &[quorum_types::ScoredChunk]) -> bool {
        let stop_words: HashSet<&'static str> = [
            "the", "and", "for", "with", "show", "that", "this", "from", "have",
            "what", "where", "when", "some", "into", "write", "about", "using",
            "are", "you", "can", "how", "why", "who", "all", "any", "will",
            "would", "should", "could", "did", "does", "been", "has", "had",
        ]
        .into_iter()
        .collect();

        let query_terms: Vec<String> = prompt
            .to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|w| w.len() >= 3 && !stop_words.contains(w))
            .map(|w| w.to_string())
            .collect();

        if query_terms.is_empty() {
            return false;
        }

        chunks.iter().any(|c| {
            let content_lower = c.chunk.text_content.to_ascii_lowercase();
            let path_lower = c.chunk.file_path.to_ascii_lowercase();
            query_terms
                .iter()
                .any(|term| content_lower.contains(term) || path_lower.contains(term))
        })
    }

    pub fn execute(&self, state: &mut AgenticGraphState) -> (RelevanceGrade, bool) {
        let is_empty = state.retrieved_chunks.is_empty();
        let max_score = if is_empty {
            0.0f32
        } else {
            state
                .retrieved_chunks
                .iter()
                .map(|c| c.score)
                .fold(0.0f32, f32::max)
        };

        state.relevance_score = max_score;

        let has_content_match =
            !is_empty && Self::has_content_relevance(&state.original_prompt, &state.retrieved_chunks);

        let effective_threshold = if max_score > 0.0 && has_content_match {
            self.relevance_threshold * (1.0 / 60.0)
        } else {
            self.relevance_threshold
        };

        let distinct_docs = state
            .retrieved_chunks
            .iter()
            .map(|c| c.chunk.file_path.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();

        let is_author_query = crate::offline_engine::DeterministicOfflineSynthesisEngine::is_authorship_query(&state.original_prompt);
        let satisfactory = !is_empty
            && max_score >= effective_threshold
            && (!is_author_query
                || distinct_docs >= 2
                || (distinct_docs >= 1 && (max_score >= 0.70 || has_content_match)));
        let will_rewrite = !satisfactory && state.hop_count < state.max_hops;

        let reasoning = if is_empty {
            "Empty chunks retrieved. Scheduling query rewrite or fallback.".to_string()
        } else if satisfactory {
            format!(
                "Top chunk score {:.3} meets threshold {:.3}{}",
                max_score,
                effective_threshold,
                if has_content_match && max_score <= 0.1 {
                    " (RRF content verified)"
                } else {
                    ""
                }
            )
        } else if max_score <= 0.1 && !has_content_match {
            format!(
                "Top chunk score {:.3} in RRF regime but failed content relevance check against query intent",
                max_score
            )
        } else {
            format!(
                "Top chunk score {:.3} below threshold {:.3}",
                max_score, effective_threshold
            )
        };

        let grade = RelevanceGrade {
            is_relevant: satisfactory,
            score: max_score,
            reasoning,
            satisfactory,
        };

        state.relevance_grade = Some(grade.clone());
        (grade, will_rewrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_types::{DocumentChunk, ScoredChunk};

    fn make_test_chunk(id: &str, path: &str, content: &str, score: f32) -> ScoredChunk {
        let doc = DocumentChunk::new(
            id,
            "test_doc",
            path,
            1,
            5,
            0,
            vec![0.0; 768],
            content,
            None,
        )
        .unwrap();
        ScoredChunk::new(doc, score, "local", false)
    }

    #[test]
    fn test_grade_relevance_empty_chunks_fails() {
        let grader = GradeRelevanceNode::default();
        let mut state =
            AgenticGraphState::new("Test query", crate::types::SynthesisModelFamily::AutoFusion, 3);
        let (grade, will_rewrite) = grader.execute(&mut state);
        assert!(!grade.satisfactory);
        assert!(!grade.is_relevant);
        assert!(will_rewrite);
    }

    #[test]
    fn test_grade_relevance_rrf_unrelated_content_fails_and_rewrites() {
        let grader = GradeRelevanceNode::default();
        let mut state = AgenticGraphState::new(
            "Adversarial query testing loop limit",
            crate::types::SynthesisModelFamily::AutoFusion,
            3,
        );
        state.retrieved_chunks = vec![make_test_chunk(
            "c1",
            "notes.txt",
            "Low relevance context",
            0.01639,
        )];
        let (grade, will_rewrite) = grader.execute(&mut state);
        assert!(!grade.satisfactory);
        assert!(will_rewrite);
    }

    #[test]
    fn test_grade_relevance_rrf_matching_content_passes() {
        let grader = GradeRelevanceNode::default();
        let mut state = AgenticGraphState::new(
            "Show me the RrfCombiner implementation in QuorumRAG",
            crate::types::SynthesisModelFamily::AutoFusion,
            3,
        );
        state.retrieved_chunks = vec![make_test_chunk(
            "c1",
            "fusion.rs",
            "pub struct RrfCombiner;",
            0.01639,
        )];
        let (grade, will_rewrite) = grader.execute(&mut state);
        assert!(grade.satisfactory);
        assert!(!will_rewrite);
    }

    #[test]
    fn test_grade_relevance_high_cosine_score_passes() {
        let grader = GradeRelevanceNode::default();
        let mut state =
            AgenticGraphState::new("Any query", crate::types::SynthesisModelFamily::AutoFusion, 3);
        state.retrieved_chunks = vec![make_test_chunk("c1", "doc.txt", "Arbitrary text", 0.85)];
        let (grade, will_rewrite) = grader.execute(&mut state);
        assert!(grade.satisfactory);
        assert!(!will_rewrite);
    }

    #[test]
    fn test_grade_relevance_max_hops_exhaustion_does_not_rewrite() {
        let grader = GradeRelevanceNode::default();
        let mut state = AgenticGraphState::new(
            "Unrelated query",
            crate::types::SynthesisModelFamily::AutoFusion,
            3,
        );
        state.hop_count = 3;
        state.retrieved_chunks = vec![make_test_chunk(
            "c1",
            "doc.txt",
            "Completely irrelevant",
            0.01639,
        )];
        let (grade, will_rewrite) = grader.execute(&mut state);
        assert!(!grade.satisfactory);
        assert!(
            !will_rewrite,
            "Must not rewrite when hop_count reached max_hops"
        );
    }

    #[test]
    fn test_grade_relevance_single_doc_author_query_passes_hop_0() {
        let grader = GradeRelevanceNode::default();
        let mut state = AgenticGraphState::new(
            "What did Femi Oyesanya write?",
            crate::types::SynthesisModelFamily::AutoFusion,
            3,
        );
        state.hop_count = 0;
        state.retrieved_chunks = vec![make_test_chunk(
            "c1",
            "African_Churches_and_Gang_Violence.docx",
            "African Churches and Gang Violence by Femi Oyesanya investigates youth intervention programs.",
            0.88,
        )];
        let (grade, will_rewrite) = grader.execute(&mut state);
        assert!(grade.satisfactory, "Single-document author query with verified content must be satisfactory");
        assert!(grade.is_relevant);
        assert!(!will_rewrite, "Hop 0 must not rewrite when author document is verified");
    }
}
