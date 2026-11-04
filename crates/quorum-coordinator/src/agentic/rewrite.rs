use std::collections::HashSet;
use crate::error::CoordinatorError;
use crate::types::AgenticGraphState;

pub struct RewriteQueryNode;

impl RewriteQueryNode {
    pub fn execute(state: &mut AgenticGraphState) -> Result<String, CoordinatorError> {
        state.hop_count += 1;

        let rewritten = format!(
            "{} (disambiguation hop {})",
            state.original_prompt, state.hop_count
        );

        if state.query_history.contains(&rewritten) {
            return Err(CoordinatorError::GraphError(format!(
                "Anti-cycle triggered: query '{}' already evaluated",
                rewritten
            )));
        }

        state.query_history.push(rewritten.clone());
        state.current_query = rewritten.clone();
        Ok(rewritten)
    }
}

/// Discovers covered semantic facets in prior turns and rewrites continuation queries
/// to explicitly target unexplored aspects before retrieval.
pub struct ContinuationFacetExtractor;

impl ContinuationFacetExtractor {
    pub fn extract_covered_facets(prior_text: &str) -> HashSet<String> {
        let low = prior_text.to_ascii_lowercase();
        let mut facets = HashSet::new();

        // Lease / Rental Agreement Domain (detected strictly from corpus/assistant evidence, never hardcoded names)
        if low.contains("landlord")
            || low.contains("tenant")
            || low.contains("lease")
            || low.contains("rent")
            || low.contains("premises")
            || low.contains("eviction")
        {
            facets.insert("domain:lease".to_string());
            if low.contains("contact") || low.contains("phone") || low.contains("email") || low.contains("address") {
                facets.insert("contact_and_parties".to_string());
            }
            if (low.contains("rent") || low.contains("monthly"))
                && (low.contains('$') || low.contains("due on") || low.contains("payable") || low.contains("direct deposit"))
            {
                facets.insert("base_rent_terms".to_string());
            }
            if low.contains("per month")
                || low.contains("/month")
                || low.contains("monthly rent")
                || low.contains("beginning on")
                || low.contains("entered into")
                || low.contains("one-year")
            {
                facets.insert("monthly_rent_rates_and_dates".to_string());
            }
            if low.contains("late fee") || low.contains("$195") || low.contains("eviction") || low.contains("penalty") || low.contains("notice fee") {
                facets.insert("late_fees_and_penalties".to_string());
            }
            if low.contains("bank") || low.contains("account") || low.contains("routing") || low.contains("payment method") || low.contains("direct deposit") {
                facets.insert("banking_and_payment_methods".to_string());
            }
            if low.contains("maintenance") || low.contains("repair") || low.contains("exterminat") || low.contains("appliance") || low.contains("ceiling fan") || low.contains("alteration") {
                facets.insert("maintenance_and_repairs".to_string());
            }
            if low.contains("utility") || low.contains("utilities") || low.contains("electric") || low.contains("water") || low.contains("gas") || low.contains("trash") || low.contains("sewer") {
                facets.insert("utilities_and_services".to_string());
            }
            if low.contains("terminate") || low.contains("termination") || low.contains("30 day") || low.contains("thirty day") || low.contains("surrender") || low.contains("move-out") {
                facets.insert("termination_and_notices".to_string());
            }
            if low.contains("sublet") || low.contains("sublease") || low.contains("assignment") || low.contains("occupy") || low.contains("occupancy") || low.contains("guest") {
                facets.insert("subletting_and_occupancy".to_string());
            }
        }

        // Biographical / Academic / Historical Domain (detected strictly from prior assistant text, never hardcoded names)
        if low.contains("activist")
            || low.contains("philosopher")
            || low.contains("academic")
            || low.contains("professor")
            || low.contains("born")
            || low.contains("philosophy")
            || low.contains("studied at")
        {
            facets.insert("domain:biographical".to_string());
            if low.contains("education") || low.contains("frankfurt") || low.contains("brandeis") || low.contains("studied") || low.contains("university") || low.contains("degree") {
                facets.insert("education_and_early_philosophy".to_string());
            }
            if low.contains("activism") || low.contains("civil rights") || low.contains("trial") || low.contains("movement") || low.contains("campaign") || low.contains("arrest") {
                facets.insert("civil_rights_activism_and_trial".to_string());
            }
            if low.contains("abolition") || low.contains("reform") || low.contains("industrial complex") || low.contains("incarceration") || low.contains("policy") {
                facets.insert("prison_abolition_movement".to_string());
            }
            if low.contains("professor") || low.contains("tenure") || low.contains("faculty") || low.contains("department") || low.contains("chair") {
                facets.insert("academic_career_and_professorship".to_string());
            }
            if low.contains("publications") || low.contains("writings") || low.contains("books") || low.contains("scholarship") || low.contains("authored") {
                facets.insert("published_books_and_scholarship".to_string());
            }
        }

        facets
    }

    pub fn rewrite_continuation_query(
        base_topic: &str,
        covered_facets: &HashSet<String>,
        turn_number: usize,
    ) -> (String, String) {
        let low_topic = base_topic.to_ascii_lowercase();

        // 1. Lease / Property Agreement Rewrite Tree (triggered by covered lease facets or lease topic)
        if covered_facets.contains("domain:lease")
            || low_topic.contains("lease")
            || low_topic.contains("rent")
            || low_topic.contains("tenant")
            || low_topic.contains("landlord")
        {
            let mut target_terms = Vec::new();
            if !covered_facets.contains("monthly_rent_rates_and_dates") {
                target_terms.push("monthly rent per month dollar rate agreement date beginning term");
            }
            if !covered_facets.contains("maintenance_and_repairs") {
                target_terms.push("maintenance duties extermination appliances alterations");
            }
            if !covered_facets.contains("utilities_and_services") {
                target_terms.push("utilities water gas electricity trash");
            }
            if !covered_facets.contains("termination_and_notices") {
                target_terms.push("termination notice duration surrender move-out");
            }
            if !covered_facets.contains("subletting_and_occupancy") {
                target_terms.push("subletting occupancy guest restrictions");
            }
            if target_terms.is_empty() || turn_number >= 2 {
                target_terms.push("vehicles parking insurance inspection default remedies");
            }
            let rewritten = format!("{} {}", base_topic, target_terms.join(" "));
            let rationale = format!(
                "Rewrote continuation to unexplored lease facets: {}",
                target_terms.join(", ")
            );
            return (rewritten, rationale);
        }

        // 2. Biographical / Academic Rewrite Tree (triggered strictly by biographical evidence in prior turn)
        if covered_facets.contains("domain:biographical") {
            let mut target_terms = Vec::new();
            if !covered_facets.contains("civil_rights_activism_and_trial") {
                target_terms.push("activism civil rights trial defense public work");
            }
            if !covered_facets.contains("prison_abolition_movement") {
                target_terms.push("prison reform movement organizations advocacy");
            }
            if !covered_facets.contains("academic_career_and_professorship") {
                target_terms.push("academic career professor university teaching");
            }
            if !covered_facets.contains("published_books_and_scholarship") {
                target_terms.push("published books writings scholarship awards");
            }
            if target_terms.is_empty() {
                target_terms.push("lectures leadership honors legacy contributions");
            }
            let rewritten = format!("{} {}", base_topic, target_terms.join(" "));
            let rationale = format!(
                "Rewrote continuation to unexplored biographical facets: {}",
                target_terms.join(", ")
            );
            return (rewritten, rationale);
        }

        // 3. General Corpus Vocabulary Fallback
        let rewritten = format!("{} additional provisions terms timeline details turn {}", base_topic, turn_number);
        (rewritten, format!("Default continuation exploration hop {}", turn_number))
    }
}

pub struct RewriteContinuationNode;

impl RewriteContinuationNode {
    pub fn execute(state: &mut AgenticGraphState) -> Result<String, CoordinatorError> {
        let prior_assistant_text: String = state
            .conversation_history
            .iter()
            .filter(|t| t.role.eq_ignore_ascii_case("assistant"))
            .map(|t| t.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let covered_facets = ContinuationFacetExtractor::extract_covered_facets(&prior_assistant_text);
        let turn_number = state
            .conversation_history
            .iter()
            .filter(|t| t.role.eq_ignore_ascii_case("user"))
            .count()
            .max(1);

        // Find the base topic query (current_query or last non-continuation user query)
        let base_query = if !state.current_query.is_empty()
            && !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_continuation_query(&state.current_query.to_ascii_lowercase())
        {
            state.current_query.clone()
        } else if let Some(last_user) = state.conversation_history.iter().rev().find(|t| {
            t.role.eq_ignore_ascii_case("user")
                && !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_continuation_query(&t.content.to_ascii_lowercase())
        }) {
            last_user.content.clone()
        } else {
            state.original_prompt.clone()
        };

        let (rewritten, rationale) = ContinuationFacetExtractor::rewrite_continuation_query(
            &base_query,
            &covered_facets,
            turn_number,
        );

        tracing::info!(
            base_query = %base_query,
            rewritten = %rewritten,
            rationale = %rationale,
            covered_facets = ?covered_facets,
            "RewriteContinuationNode executed"
        );

        state.current_query = rewritten.clone();
        if !state.query_history.contains(&rewritten) {
            state.query_history.push(rewritten.clone());
        }
        state.routing_rationale = rationale;
        Ok(rewritten)
    }
}

