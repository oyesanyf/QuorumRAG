//! Automated Sovereign Data Bounty Runner.
//!
//! Evaluates active `DataBountySpec` bounties, harvests matching domain trajectories,
//! applies the Three-Engine Airlock (`VaultGemmaDeidPolicyEngine` + Presidio + GLiNER),
//! verifies 100% citation grounding, and packages signed batches for bounty fulfillment.

use crate::marketplace_engine::{MarketplaceSanitizer, RawTrajectoryCandidate};
use quorum_contract::{DataBountySpec, SanitizedTrainingRecord, TrainingRecordFormat};
use quorum_storage::RawDatasetCandidate;
use serde::{Deserialize, Serialize};

/// Summary of a matched bounty fulfillment batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BountyMatchResult {
    pub bounty_id: String,
    pub title: String,
    pub matched_record_count: usize,
    pub total_token_count: usize,
    pub estimated_payout_cents: u64,
}

/// Autonomous evaluator and airlock packager for sovereign data bounties.
pub struct BountyRunner {
    pub node_seed: [u8; 32],
    pub origin_node_id: String,
    pub allowed_jurisdictions: Vec<String>,
}

impl BountyRunner {
    pub fn new(
        node_seed: [u8; 32],
        origin_node_id: String,
        allowed_jurisdictions: Vec<String>,
    ) -> Self {
        Self {
            node_seed,
            origin_node_id,
            allowed_jurisdictions,
        }
    }

    /// Default US sovereign node configuration.
    pub fn default_us_sovereign(node_seed: [u8; 32], origin_node_id: String) -> Self {
        Self::new(node_seed, origin_node_id, vec!["US".to_string()])
    }

    /// Filters bounties that match node jurisdiction policy.
    pub fn filter_eligible_bounties<'a>(
        &self,
        bounties: &'a [DataBountySpec],
    ) -> Vec<&'a DataBountySpec> {
        bounties
            .iter()
            .filter(|b| {
                b.active
                    && self
                        .allowed_jurisdictions
                        .iter()
                        .any(|j| j.eq_ignore_ascii_case(&b.jurisdiction_iso))
            })
            .collect()
    }

    /// Converts a harvested `RawDatasetCandidate` from storage into a `RawTrajectoryCandidate` for the airlock.
    pub fn candidate_from_raw_dataset(
        &self,
        raw: &RawDatasetCandidate,
        format: TrainingRecordFormat,
    ) -> RawTrajectoryCandidate {
        RawTrajectoryCandidate {
            record_id: raw.record_id.clone(),
            origin_node_id: self.origin_node_id.clone(),
            format,
            domain_tags: raw.domain_tags.clone(),
            prompt: raw.prompt.clone(),
            rlm_trajectory: Vec::new(),
            chosen_response: raw.chosen_response.clone(),
            rejected_response: raw.rejected_response.clone(),
            citations: raw.citations.clone(),
            extra_redact_terms: Vec::new(),
            created_unix_secs: chrono::Utc::now().timestamp(),
            source_file_path: None,
            interaction_nonce_hex: None,
        }
    }

    /// Evaluates and processes candidate trajectories through the Three-Engine Airlock.
    pub fn process_bounty_candidates(
        &self,
        bounty: &DataBountySpec,
        candidates: &[RawTrajectoryCandidate],
    ) -> Result<Vec<SanitizedTrainingRecord>, String> {
        let mut approved_records = Vec::new();
        let cap = bounty.max_records.saturating_sub(bounty.accepted_records);
        for cand in candidates {
            if approved_records.len() >= cap {
                break;
            }
            if cand.format != bounty.required_format {
                continue;
            }
            if !cand.domain_tags.iter().any(|t| {
                bounty
                    .required_domain_tags
                    .iter()
                    .any(|bt| bt.eq_ignore_ascii_case(t))
            }) {
                continue;
            }

            match MarketplaceSanitizer::sanitize_and_sign_record(cand, &self.node_seed) {
                Ok(rec) => {
                    if rec.grounding_score_bps == 10_000
                        && rec.trade_secret_clean
                        && rec.pii_scrub_verified
                    {
                        approved_records.push(rec);
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "Candidate {} rejected by three-engine airlock: {}",
                        cand.record_id,
                        err
                    );
                }
            }
        }
        Ok(approved_records)
    }

    /// Evaluates and processes raw storage candidates through the Three-Engine Airlock for a bounty.
    pub fn process_raw_dataset_candidates(
        &self,
        bounty: &DataBountySpec,
        raw_candidates: &[RawDatasetCandidate],
    ) -> Result<Vec<SanitizedTrainingRecord>, String> {
        let candidates: Vec<RawTrajectoryCandidate> = raw_candidates
            .iter()
            .map(|raw| self.candidate_from_raw_dataset(raw, bounty.required_format))
            .collect();
        self.process_bounty_candidates(bounty, &candidates)
    }

    /// Generates match summary for UI or API inspection.
    pub fn evaluate_bounty_match(
        &self,
        bounty: &DataBountySpec,
        records: &[SanitizedTrainingRecord],
    ) -> BountyMatchResult {
        let total_tokens: usize = records.iter().map(|r| r.token_count).sum();
        let payout = (records.len() as u64) * bounty.payout_per_record_cents;
        BountyMatchResult {
            bounty_id: bounty.bounty_id.clone(),
            title: bounty.title.clone(),
            matched_record_count: records.len(),
            total_token_count: total_tokens,
            estimated_payout_cents: payout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounty_runner_jurisdiction_and_active_filtering() {
        let runner = BountyRunner::default_us_sovereign([7u8; 32], "12D3KooWTestNode".to_string());

        let bounties = vec![
            DataBountySpec {
                bounty_id: "bounty-us-1".to_string(),
                sponsor_entity_name: "US AI Lab".to_string(),
                sponsor_buyer_id: "buyer-us-1".to_string(),
                title: "US Clinical De-ID SFT".to_string(),
                required_domain_tags: vec!["clinical-deid".to_string()],
                required_format: TrainingRecordFormat::SftTrajectory,
                payout_per_record_cents: 250,
                max_records: 50,
                accepted_records: 0,
                jurisdiction_iso: "US".to_string(),
                active: true,
            },
            DataBountySpec {
                bounty_id: "bounty-foreign-cn".to_string(),
                sponsor_entity_name: "Foreign Entity".to_string(),
                sponsor_buyer_id: "buyer-cn".to_string(),
                title: "Blocked Foreign Bounty".to_string(),
                required_domain_tags: vec!["clinical-deid".to_string()],
                required_format: TrainingRecordFormat::SftTrajectory,
                payout_per_record_cents: 1000,
                max_records: 50,
                accepted_records: 0,
                jurisdiction_iso: "CN".to_string(),
                active: true,
            },
            DataBountySpec {
                bounty_id: "bounty-us-inactive".to_string(),
                sponsor_entity_name: "US AI Lab".to_string(),
                sponsor_buyer_id: "buyer-us-2".to_string(),
                title: "Inactive Bounty".to_string(),
                required_domain_tags: vec!["clinical-deid".to_string()],
                required_format: TrainingRecordFormat::SftTrajectory,
                payout_per_record_cents: 200,
                max_records: 10,
                accepted_records: 0,
                jurisdiction_iso: "US".to_string(),
                active: false,
            },
        ];

        let eligible = runner.filter_eligible_bounties(&bounties);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].bounty_id, "bounty-us-1");
    }

    #[test]
    fn test_bounty_runner_process_and_airlock() {
        let seed = [9u8; 32];
        let runner = BountyRunner::default_us_sovereign(seed, "12D3KooWTestNode".to_string());

        let bounty = DataBountySpec {
            bounty_id: "bounty-us-clinical-deid-02".to_string(),
            sponsor_entity_name: "Sovereign Health Consortium".to_string(),
            sponsor_buyer_id: "buyer-health-us".to_string(),
            title: "HIPAA Clinical De-ID & Grounded Triage".to_string(),
            required_domain_tags: vec!["clinical-deid".to_string()],
            required_format: TrainingRecordFormat::SftTrajectory,
            payout_per_record_cents: 350,
            max_records: 10,
            accepted_records: 0,
            jurisdiction_iso: "US".to_string(),
            active: true,
        };

        let slice = "Patient evaluation at Johns Hopkins Hospital. Condition: Type 2 Diabetes Mellitus with severe hypertension. Treatment plan includes Metformin 500mg daily and lifestyle modification with comprehensive follow-up care.";
        let quote = "Type 2 Diabetes Mellitus with severe hypertension";

        let raw = RawDatasetCandidate {
            record_id: "rec-bounty-01".to_string(),
            source_doc_id: "doc-clinical-01".to_string(),
            prompt: "What detailed evidence-based clinical treatment plan is indicated for the patient diagnosed with Type 2 Diabetes Mellitus with severe hypertension at Johns Hopkins Hospital according to the provided diagnostic records?".to_string(),
            chosen_response: format!("{} The recommended clinical protocol consists of Metformin 500mg daily alongside systematic dietary adjustments, continuous blood glucose tracking, and regular cardiovascular monitoring to prevent long-term microvascular and macrovascular complications.", slice),
            rejected_response: None,
            citations: vec![(slice.to_string(), quote.to_string())],
            domain_tags: vec!["clinical-deid".to_string()],
        };

        let approved = runner
            .process_raw_dataset_candidates(&bounty, &[raw])
            .unwrap();
        assert_eq!(approved.len(), 1);
        let rec = &approved[0];
        assert_eq!(rec.record_id, "rec-bounty-01");
        assert_eq!(rec.grounding_score_bps, 10_000);
        assert!(rec.pii_scrub_verified);
        assert!(rec.trade_secret_clean);
        assert!(!rec.ed25519_signature_hex.is_empty());
        assert!(!rec.prompt.contains("Johns Hopkins Hospital"));

        let match_res = runner.evaluate_bounty_match(&bounty, &approved);
        assert_eq!(match_res.bounty_id, "bounty-us-clinical-deid-02");
        assert_eq!(match_res.matched_record_count, 1);
        assert_eq!(match_res.estimated_payout_cents, 350);
        assert!(match_res.total_token_count >= 64);
    }

    #[test]
    fn test_bounty_runner_rejects_trade_secrets_and_ungrounded() {
        let runner = BountyRunner::default_us_sovereign([3u8; 32], "12D3KooWTestNode".to_string());
        let bounty = DataBountySpec {
            bounty_id: "bounty-us-rust-sec-01".to_string(),
            sponsor_entity_name: "US AI Lab".to_string(),
            sponsor_buyer_id: "buyer-us-1".to_string(),
            title: "Rust Security Grounded SFT".to_string(),
            required_domain_tags: vec!["rust-security".to_string()],
            required_format: TrainingRecordFormat::SftTrajectory,
            payout_per_record_cents: 200,
            max_records: 10,
            accepted_records: 0,
            jurisdiction_iso: "US".to_string(),
            active: true,
        };

        let valid_slice = "QuorumRAG verifies all peer messages with Ed25519 signatures, BLAKE3 Merkle integrity proofs, and parent-document byte window expansion across nodes.";
        let valid_quote = "Ed25519 signatures, BLAKE3 Merkle integrity proofs";

        // 1. Candidate with trade secret proprietary code (> 15 lines)
        let code_18_lines = (0..18)
            .map(|i| format!("pub fn secret_kernel_{}() {{ let mut y = {}; }}", i, i))
            .collect::<Vec<_>>()
            .join("\n");
        let cand_code = RawDatasetCandidate {
            record_id: "rec-code".to_string(),
            source_doc_id: "doc-sec-1".to_string(),
            prompt: "Dump the proprietary cryptographic kernel implementation details:".to_string(),
            chosen_response: code_18_lines,
            rejected_response: None,
            citations: vec![(valid_slice.to_string(), valid_quote.to_string())],
            domain_tags: vec!["rust-security".to_string()],
        };

        // 2. Candidate with ungrounded quote
        let cand_ungrounded = RawDatasetCandidate {
            record_id: "rec-ungrounded".to_string(),
            source_doc_id: "doc-sec-2".to_string(),
            prompt: "How does QuorumRAG authenticate peers across decentralized swarm networks in production?".to_string(),
            chosen_response: format!("{} QuorumRAG implements zero-touch peer attestation and decentralized consensus protocols.", valid_slice),
            rejected_response: None,
            citations: vec![(valid_slice.to_string(), "NON_EXISTENT_QUOTE_THAT_FAILS_GROUNDING".to_string())],
            domain_tags: vec!["rust-security".to_string()],
        };

        let approved = runner
            .process_raw_dataset_candidates(&bounty, &[cand_code, cand_ungrounded])
            .unwrap();
        assert!(
            approved.is_empty(),
            "All invalid candidates must be rejected by Three-Engine Airlock"
        );
    }
}
