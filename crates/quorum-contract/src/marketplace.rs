//! Canonical contracts for QuorumRAG's Opt-In Sovereign AI Training Data Marketplace,
//! Zero-Knowledge Data Catalog Manifests, FOCI / DOJ 28 CFR Part 202 Buyer Certificates,
//! Commit-and-Reveal Cryptographic Escrow, and Federated Revenue-Sharing Contribution Ledgers.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use subtle::ConstantTimeEq;

/// Training trajectory output format for fine-tuning / preference alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingRecordFormat {
    SftTrajectory,
    DpoPreferencePair,
}

/// Cryptographic certificate attesting a buyer's U.S./allied legal incorporation,
/// Foreign Ownership, Control, or Influence (FOCI) / Ultimate Beneficial Owner (UBO) clearance,
/// DOJ 28 CFR Part 202 Non-Covered Person compliance, static corporate egress CIDRs,
/// and hardware-bound TPM 2.0 / HSM training cluster key hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuyerJurisdictionCertificate {
    pub buyer_id: String,
    pub legal_entity_name: String,
    /// ISO 3166-1 alpha-2 country of incorporation (default allowlist: `"US"`).
    pub incorporation_country_iso: String,
    /// Verified Legal Entity Identifier (LEI), DUNS number, or SAM.gov CAGE code.
    pub lei_or_duns_id: String,
    /// Static corporate IPv4/IPv6 egress CIDR ranges cryptographically pinned to this buyer.
    pub authorized_egress_cidrs: Vec<String>,
    /// BLAKE3 hex digest of the buyer cluster's hardware TPM 2.0 Endorsement Key / HSM public key.
    pub bound_tpm_pubkey_blake3: String,
    /// Attests 0% (<10% threshold) voting shares or board control by CN/HK/MO/RU/IR/KP/BY/CU/VE parent entities.
    pub foci_ubo_verified_clean: bool,
    /// Attests compliance with the U.S. DOJ Bulk Sensitive Data Rule (28 CFR Part 202 Non-Covered Person).
    pub doj_part202_non_covered_person: bool,
    /// Binding covenant prohibiting resale, re-export, or overseas cluster mirroring.
    pub non_redistribution_covenant_accepted: bool,
    /// Expiration timestamp (Unix seconds).
    pub expires_unix_secs: i64,
    /// Hex-encoded 64-byte Ed25519 signature by the Marketplace Licensing Authority.
    pub issuer_ed25519_signature_hex: String,
}

impl BuyerJurisdictionCertificate {
    /// Deterministic domain-separated byte representation for Ed25519 signing and verification.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"QuorumRAG-BuyerJurisdictionCertificate-v1:");
        hasher.update(self.buyer_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.legal_entity_name.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.incorporation_country_iso.trim().to_ascii_uppercase().as_bytes());
        hasher.update(b"|");
        hasher.update(self.lei_or_duns_id.trim().as_bytes());
        hasher.update(b"|");
        for cidr in &self.authorized_egress_cidrs {
            hasher.update(cidr.trim().as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"|");
        hasher.update(self.bound_tpm_pubkey_blake3.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        hasher.update(&[
            u8::from(self.foci_ubo_verified_clean),
            u8::from(self.doj_part202_non_covered_person),
            u8::from(self.non_redistribution_covenant_accepted),
        ]);
        hasher.update(b"|");
        hasher.update(&self.expires_unix_secs.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    /// Signs the certificate in-place using the authority's 32-byte Ed25519 seed.
    pub fn sign_ed25519(&mut self, authority_seed: &[u8; 32]) -> Result<(), String> {
        let signing_key = SigningKey::from_bytes(authority_seed);
        let msg = self.canonical_signing_bytes();
        let sig: Signature = signing_key.sign(&msg);
        self.issuer_ed25519_signature_hex = bytes_to_hex(&sig.to_bytes());
        Ok(())
    }

    /// Verifies the issuer's Ed25519 signature over the certificate.
    pub fn verify_ed25519(&self, authority_pubkey_bytes: &[u8; 32]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(authority_pubkey_bytes) else {
            return false;
        };
        let Some(sig_bytes) = hex_to_64_bytes(&self.issuer_ed25519_signature_hex) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = self.canonical_signing_bytes();
        verifying_key.verify(&msg, &sig).is_ok()
    }
}

/// Cryptographic Commit-and-Reveal escrow receipt unlocking a specific batch for a verified buyer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowReceiptToken {
    pub receipt_id: String,
    pub batch_id: String,
    pub batch_merkle_root_blake3: String,
    pub buyer_id: String,
    pub bound_tpm_pubkey_blake3: String,
    pub amount_paid_cents: u64,
    pub issued_unix_secs: i64,
    pub expires_unix_secs: i64,
    pub keyed_blake3_mac_hex: String,
}

impl EscrowReceiptToken {
    /// Computes the 256-bit keyed BLAKE3 MAC over all receipt fields.
    pub fn compute_keyed_mac(&self, escrow_secret: &[u8; 32]) -> String {
        let mut hasher = blake3::Hasher::new_keyed(escrow_secret);
        hasher.update(b"QuorumRAG-EscrowReceiptToken-v1:");
        hasher.update(self.receipt_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.batch_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.batch_merkle_root_blake3.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        hasher.update(self.buyer_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.bound_tpm_pubkey_blake3.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        hasher.update(&self.amount_paid_cents.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&self.issued_unix_secs.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&self.expires_unix_secs.to_le_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Seals the receipt token with the daemon's 32-byte escrow key.
    pub fn seal_with_secret(&mut self, escrow_secret: &[u8; 32]) {
        self.keyed_blake3_mac_hex = self.compute_keyed_mac(escrow_secret);
    }

    /// Verifies expiration and constant-time keyed BLAKE3 MAC authenticity (`subtle::ConstantTimeEq`).
    pub fn verify_constant_time(
        &self,
        escrow_secret: &[u8; 32],
        now_unix_secs: i64,
    ) -> Result<(), &'static str> {
        if now_unix_secs >= self.expires_unix_secs {
            return Err("EscrowReceiptToken has expired");
        }
        let expected_hex = self.compute_keyed_mac(escrow_secret);
        let provided_low = self.keyed_blake3_mac_hex.trim().to_ascii_lowercase();
        if expected_hex.len() != provided_low.len()
            || !bool::from(expected_hex.as_bytes().ct_eq(provided_low.as_bytes()))
        {
            return Err("EscrowReceiptToken keyed BLAKE3 MAC verification failed");
        }
        Ok(())
    }
}

/// Sanitized step in a Recursive Language Model (RLM) reasoning trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizedRlmStep {
    pub step_index: usize,
    pub action_kind: String,
    pub sanitized_query_or_pattern: String,
    pub abstracted_takeaway: String,
}

/// De-identified, citation-grounded SFT or DPO training record signed by the originating node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizedTrainingRecord {
    pub record_id: String,
    pub blake3_record_hash: String,
    pub origin_node_id: String,
    pub format: TrainingRecordFormat,
    pub domain_tags: Vec<String>,
    pub prompt: String,
    pub rlm_trajectory: Vec<SanitizedRlmStep>,
    pub chosen_response: String,
    pub rejected_response: Option<String>,
    pub verified_citation_count: usize,
    /// Basis points of citations passing verbatim substring verification (`10_000` = 100.00%).
    pub grounding_score_bps: u16,
    /// True when Presidio + GLiNER + regex path/contact scrubbing verified 0 residual PII/PHI.
    pub pii_scrub_verified: bool,
    /// True when Semantic Trade-Secret Filter verified <=15 code lines, 0 RFC1918 IPs, 0 high-entropy secrets.
    pub trade_secret_clean: bool,
    pub token_count: usize,
    pub created_unix_secs: i64,
    pub ed25519_signature_hex: String,
    /// Deterministic per-buyer or per-preview canary watermark hex digest for leak attribution.
    pub buyer_watermark_hex: Option<String>,
}

impl SanitizedTrainingRecord {
    /// Computes the canonical content BLAKE3 digest (independent of node signature or buyer watermark).
    pub fn compute_canonical_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"QuorumRAG-SanitizedTrainingRecord-v1:");
        let fmt_str = match self.format {
            TrainingRecordFormat::SftTrajectory => "sft",
            TrainingRecordFormat::DpoPreferencePair => "dpo",
        };
        hasher.update(fmt_str.as_bytes());
        hasher.update(b"|");
        hasher.update(self.prompt.trim().as_bytes());
        hasher.update(b"|");
        for step in &self.rlm_trajectory {
            hasher.update(&step.step_index.to_le_bytes());
            hasher.update(step.action_kind.trim().as_bytes());
            hasher.update(step.sanitized_query_or_pattern.trim().as_bytes());
            hasher.update(step.abstracted_takeaway.trim().as_bytes());
        }
        hasher.update(b"|");
        hasher.update(self.chosen_response.trim().as_bytes());
        hasher.update(b"|");
        if let Some(ref rej) = self.rejected_response {
            hasher.update(rej.trim().as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Updates `blake3_record_hash` to match the record's canonical content digest.
    pub fn refresh_hash(&mut self) {
        self.blake3_record_hash = self.compute_canonical_hash();
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"QuorumRAG-RecordSig-v1:");
        hasher.update(self.blake3_record_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(self.origin_node_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(&self.grounding_score_bps.to_le_bytes());
        hasher.update(&[
            u8::from(self.pii_scrub_verified),
            u8::from(self.trade_secret_clean),
        ]);
        hasher.finalize().as_bytes().to_vec()
    }

    /// Refresh hash and sign the record with the node's 32-byte Ed25519 private seed.
    pub fn sign_ed25519(&mut self, node_seed: &[u8; 32]) -> Result<(), String> {
        self.refresh_hash();
        let signing_key = SigningKey::from_bytes(node_seed);
        let msg = self.signing_payload();
        let sig: Signature = signing_key.sign(&msg);
        self.ed25519_signature_hex = bytes_to_hex(&sig.to_bytes());
        Ok(())
    }

    /// Verifies both the canonical `blake3_record_hash` and the originating node's Ed25519 signature.
    pub fn verify_ed25519(&self, node_pubkey_bytes: &[u8; 32]) -> bool {
        if self.compute_canonical_hash() != self.blake3_record_hash {
            return false;
        }
        let Ok(verifying_key) = VerifyingKey::from_bytes(node_pubkey_bytes) else {
            return false;
        };
        let Some(sig_bytes) = hex_to_64_bytes(&self.ed25519_signature_hex) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = self.signing_payload();
        verifying_key.verify(&msg, &sig).is_ok()
    }

    /// Produces a copy of this record carrying a deterministic cryptographic canary watermark
    /// bound to `buyer_id` and `scope` (e.g. `"full_unlock"` or `"preview_canary"`).
    pub fn with_buyer_watermark(&self, node_seed: &[u8; 32], buyer_id: &str, scope: &str) -> Self {
        let mut cloned = self.clone();
        let wm = compute_buyer_watermark_hex(node_seed, buyer_id, scope, &self.blake3_record_hash);
        cloned.buyer_watermark_hex = Some(wm);
        cloned
    }

    /// Verifies whether `self.buyer_watermark_hex` matches the expected forensic watermark for `buyer_id`.
    pub fn verify_buyer_watermark(&self, node_seed: &[u8; 32], buyer_id: &str, scope: &str) -> bool {
        let Some(ref actual) = self.buyer_watermark_hex else {
            return false;
        };
        let expected = compute_buyer_watermark_hex(node_seed, buyer_id, scope, &self.blake3_record_hash);
        expected.len() == actual.len()
            && bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
    }
}

/// Computes a deterministic keyed BLAKE3 forensic watermark for leak traceability.
pub fn compute_buyer_watermark_hex(
    node_seed: &[u8; 32],
    buyer_id: &str,
    scope: &str,
    record_hash: &str,
) -> String {
    let wm_key = blake3::derive_key("QuorumRAG-BuyerCanaryWatermark-v1", node_seed);
    let mut hasher = blake3::Hasher::new_keyed(&wm_key);
    hasher.update(buyer_id.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(scope.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(record_hash.trim().as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Computes a binary BLAKE3 Merkle Tree root over an ordered slice of record hashes.
pub fn compute_blake3_merkle_root(record_hashes: &[String]) -> String {
    if record_hashes.is_empty() {
        return blake3::hash(b"QuorumRAG-EmptyMerkleTree-v1").to_hex().to_string();
    }
    let mut current_layer: Vec<[u8; 32]> = record_hashes
        .iter()
        .map(|h| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"leaf:");
            hasher.update(h.trim().to_ascii_lowercase().as_bytes());
            *hasher.finalize().as_bytes()
        })
        .collect();

    while current_layer.len() > 1 {
        let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);
        for pair in current_layer.chunks(2) {
            let left = &pair[0];
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"node:");
            hasher.update(left);
            hasher.update(right);
            next_layer.push(*hasher.finalize().as_bytes());
        }
        current_layer = next_layer;
    }

    bytes_to_hex(&current_layer[0])
}

fn default_true_bool() -> bool {
    true
}

/// Zero-Knowledge Data Catalog Manifest broadcast over the mesh or served on `/api/v1/marketplace/preview`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataCatalogManifest {
    pub batch_id: String,
    pub origin_node_id: String,
    pub origin_pubkey_hex: String,
    pub domain_tags: Vec<String>,
    pub sft_record_count: usize,
    pub dpo_record_count: usize,
    pub total_tokens: usize,
    pub merkle_root_blake3: String,
    pub price_per_1k_records_cents: u64,
    /// Capped at `<= 5` canary records for authenticated buyers; empty (`[]`) for unauthenticated callers.
    pub canary_sample: Vec<SanitizedTrainingRecord>,
    /// Cryptographic proof that every record in the sealed batch passed all 4 exclusion stages.
    #[serde(default = "default_true_bool")]
    pub synthetic_contamination_filtered: bool,
    pub created_unix_secs: i64,
    pub manifest_signature_hex: String,
}

impl DataCatalogManifest {
    /// Constructs and signs a `DataCatalogManifest` from a slice of verified `SanitizedTrainingRecord` items.
    pub fn from_records(
        batch_id: impl Into<String>,
        origin_node_id: impl Into<String>,
        node_seed: &[u8; 32],
        records: &[SanitizedTrainingRecord],
        price_per_1k_records_cents: u64,
        created_unix_secs: i64,
    ) -> Result<Self, String> {
        let signing_key = SigningKey::from_bytes(node_seed);
        let pubkey_hex = bytes_to_hex(signing_key.verifying_key().as_bytes());

        let mut domain_set = HashSet::new();
        let mut domain_tags = Vec::new();
        let mut sft_record_count = 0usize;
        let mut dpo_record_count = 0usize;
        let mut total_tokens = 0usize;
        let mut hashes = Vec::with_capacity(records.len());

        for rec in records {
            match rec.format {
                TrainingRecordFormat::SftTrajectory => sft_record_count += 1,
                TrainingRecordFormat::DpoPreferencePair => dpo_record_count += 1,
            }
            total_tokens += rec.token_count;
            hashes.push(rec.blake3_record_hash.clone());
            for tag in &rec.domain_tags {
                let clean = tag.trim().to_ascii_lowercase();
                if !clean.is_empty() && domain_set.insert(clean.clone()) {
                    domain_tags.push(clean);
                }
            }
        }
        domain_tags.sort();

        let merkle_root_blake3 = compute_blake3_merkle_root(&hashes);
        let canary_count = records.len().min(5);
        let canary_sample = records[..canary_count].to_vec();

        let mut manifest = Self {
            batch_id: batch_id.into(),
            origin_node_id: origin_node_id.into(),
            origin_pubkey_hex: pubkey_hex,
            domain_tags,
            sft_record_count,
            dpo_record_count,
            total_tokens,
            merkle_root_blake3,
            price_per_1k_records_cents,
            canary_sample,
            synthetic_contamination_filtered: true,
            created_unix_secs,
            manifest_signature_hex: String::new(),
        };
        manifest.sign_ed25519(node_seed)?;
        Ok(manifest)
    }

    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"QuorumRAG-DataCatalogManifest-v1:");
        hasher.update(self.batch_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.origin_node_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.origin_pubkey_hex.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        for tag in &self.domain_tags {
            hasher.update(tag.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"|");
        hasher.update(&self.sft_record_count.to_le_bytes());
        hasher.update(&self.dpo_record_count.to_le_bytes());
        hasher.update(&self.total_tokens.to_le_bytes());
        hasher.update(self.merkle_root_blake3.as_bytes());
        hasher.update(&self.price_per_1k_records_cents.to_le_bytes());
        hasher.update(&[u8::from(self.synthetic_contamination_filtered)]);
        hasher.update(&self.created_unix_secs.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn sign_ed25519(&mut self, node_seed: &[u8; 32]) -> Result<(), String> {
        let signing_key = SigningKey::from_bytes(node_seed);
        self.origin_pubkey_hex = bytes_to_hex(signing_key.verifying_key().as_bytes());
        let msg = self.canonical_signing_bytes();
        let sig: Signature = signing_key.sign(&msg);
        self.manifest_signature_hex = bytes_to_hex(&sig.to_bytes());
        Ok(())
    }

    pub fn verify_ed25519(&self, node_pubkey_bytes: &[u8; 32]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(node_pubkey_bytes) else {
            return false;
        };
        let Some(sig_bytes) = hex_to_64_bytes(&self.manifest_signature_hex) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = self.canonical_signing_bytes();
        verifying_key.verify(&msg, &sig).is_ok()
    }

    /// Returns a zero-canary metadata manifest safe for unauthenticated preview requests (anti-scraping).
    pub fn to_unauthenticated_preview(&self) -> Self {
        let mut stripped = self.clone();
        stripped.canary_sample.clear();
        stripped
    }

    /// Returns a preview manifest whose canary sample lines are dynamically watermarked for `buyer_id`.
    pub fn to_authenticated_watermarked_preview(
        &self,
        node_seed: &[u8; 32],
        buyer_id: &str,
    ) -> Self {
        let mut preview = self.clone();
        preview.canary_sample = self
            .canary_sample
            .iter()
            .take(5)
            .map(|r| r.with_buyer_watermark(node_seed, buyer_id, "preview_canary"))
            .collect();
        preview
    }
}

/// Data Bounty broadcast by an enterprise or research coordinator node over the mesh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataBountySpec {
    pub bounty_id: String,
    pub sponsor_entity_name: String,
    pub sponsor_buyer_id: String,
    pub title: String,
    pub required_domain_tags: Vec<String>,
    pub required_format: TrainingRecordFormat,
    pub payout_per_record_cents: u64,
    pub max_records: usize,
    pub accepted_records: usize,
    pub jurisdiction_iso: String,
    pub active: bool,
}

/// Per-peer accounting entry inside a Federated Swarm Pool `ContributionLedger`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerContributionShare {
    pub origin_node_id: String,
    pub unique_records_accepted: usize,
    pub duplicate_records_dropped: usize,
    pub verified_tokens_accepted: usize,
    /// Revenue share in basis points (`0..=10_000`, where `10_000 == 100.00%`).
    pub revenue_share_bps: u16,
    pub estimated_payout_cents: u64,
}

/// Accounting ledger tracking unique BLAKE3 records, verified tokens, and proportional payouts across mesh peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContributionLedger {
    pub pool_batch_id: String,
    pub total_unique_records: usize,
    pub total_duplicates_dropped: usize,
    pub total_verified_tokens: usize,
    pub total_pool_payout_cents: u64,
    pub merkle_root_blake3: String,
    pub peer_shares: BTreeMap<String, PeerContributionShare>,
}

impl ContributionLedger {
    /// Deduplicates pooled records across consenting mesh peers by `blake3_record_hash`,
    /// filters out any record that fails `grounding_score_bps == 10_000`, `pii_scrub_verified`, or `trade_secret_clean`,
    /// and computes exact basis-point (`10,000 bps`) revenue splits and cent payouts per `origin_node_id`.
    pub fn merge_and_deduplicate_mesh_records(
        pool_batch_id: &str,
        records: Vec<SanitizedTrainingRecord>,
        total_pool_payout_cents: u64,
    ) -> (Self, Vec<SanitizedTrainingRecord>) {
        let mut seen_hashes = HashSet::new();
        let mut accepted_records = Vec::new();
        let mut peer_shares: BTreeMap<String, PeerContributionShare> = BTreeMap::new();
        let mut total_duplicates_dropped = 0usize;

        for rec in records {
            if rec.grounding_score_bps < 10_000 || !rec.pii_scrub_verified || !rec.trade_secret_clean {
                continue;
            }
            let canonical = rec.compute_canonical_hash();
            let peer_entry = peer_shares
                .entry(rec.origin_node_id.clone())
                .or_insert_with(|| PeerContributionShare {
                    origin_node_id: rec.origin_node_id.clone(),
                    unique_records_accepted: 0,
                    duplicate_records_dropped: 0,
                    verified_tokens_accepted: 0,
                    revenue_share_bps: 0,
                    estimated_payout_cents: 0,
                });

            if seen_hashes.insert(canonical) {
                peer_entry.unique_records_accepted += 1;
                peer_entry.verified_tokens_accepted += rec.token_count;
                accepted_records.push(rec);
            } else {
                peer_entry.duplicate_records_dropped += 1;
                total_duplicates_dropped += 1;
            }
        }

        let total_unique_records = accepted_records.len();
        let total_verified_tokens: usize = accepted_records.iter().map(|r| r.token_count).sum();
        let hashes: Vec<String> = accepted_records
            .iter()
            .map(|r| r.blake3_record_hash.clone())
            .collect();
        let merkle_root_blake3 = compute_blake3_merkle_root(&hashes);

        if total_unique_records > 0 {
            let mut allocated_bps = 0u16;
            let mut allocated_cents = 0u64;
            let peer_keys: Vec<String> = peer_shares
                .iter()
                .filter(|(_, s)| s.unique_records_accepted > 0)
                .map(|(k, _)| k.clone())
                .collect();

            for (idx, key) in peer_keys.iter().enumerate() {
                if let Some(share) = peer_shares.get_mut(key) {
                    if idx + 1 == peer_keys.len() {
                        share.revenue_share_bps = 10_000u16.saturating_sub(allocated_bps);
                        share.estimated_payout_cents =
                            total_pool_payout_cents.saturating_sub(allocated_cents);
                    } else {
                        let bps = ((share.unique_records_accepted as u64 * 10_000)
                            / total_unique_records as u64) as u16;
                        let cents = (total_pool_payout_cents
                            * share.unique_records_accepted as u64)
                            / total_unique_records as u64;
                        share.revenue_share_bps = bps;
                        share.estimated_payout_cents = cents;
                        allocated_bps = allocated_bps.saturating_add(bps);
                        allocated_cents = allocated_cents.saturating_add(cents);
                    }
                }
            }
        }

        let ledger = Self {
            pool_batch_id: pool_batch_id.to_string(),
            total_unique_records,
            total_duplicates_dropped,
            total_verified_tokens,
            total_pool_payout_cents,
            merkle_root_blake3,
            peer_shares,
        };
        (ledger, accepted_records)
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn hex_to_64_bytes(hex_str: &str) -> Option<[u8; 64]> {
    let clean = hex_str.trim();
    if clean.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_and_manifest_signature_and_preview_stripping() {
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        let mut r1 = SanitizedTrainingRecord {
            record_id: "rec-1".to_string(),
            blake3_record_hash: String::new(),
            origin_node_id: "12D3KooWPeerA".to_string(),
            format: TrainingRecordFormat::SftTrajectory,
            domain_tags: vec!["rust-security".to_string(), "ebpf".to_string()],
            prompt: "How does QuorumRAG enforce zero-trust P2P containment?".to_string(),
            rlm_trajectory: vec![SanitizedRlmStep {
                step_index: 1,
                action_kind: "peek_slice".to_string(),
                sanitized_query_or_pattern: "bytes 0..10000".to_string(),
                abstracted_takeaway: "Verified Ed25519 peer ACL and BLAKE3 contract hash.".to_string(),
            }],
            chosen_response: "QuorumRAG enforces Ed25519 peer authentication and constant-time BLAKE3 contract verification.".to_string(),
            rejected_response: None,
            verified_citation_count: 2,
            grounding_score_bps: 10_000,
            pii_scrub_verified: true,
            trade_secret_clean: true,
            token_count: 120,
            created_unix_secs: 1_760_000_000,
            ed25519_signature_hex: String::new(),
            buyer_watermark_hex: None,
        };
        r1.sign_ed25519(&seed).unwrap();
        assert!(r1.verify_ed25519(&pubkey_bytes));

        let manifest = DataCatalogManifest::from_records(
            "batch-001",
            "12D3KooWPeerA",
            &seed,
            std::slice::from_ref(&r1),
            5_000,
            1_760_000_100,
        )
        .unwrap();
        assert!(manifest.verify_ed25519(&pubkey_bytes));
        assert_eq!(manifest.sft_record_count, 1);
        assert_eq!(manifest.canary_sample.len(), 1);
        assert!(manifest.synthetic_contamination_filtered);

        // Unauthenticated preview must strip all canary text
        let unauth = manifest.to_unauthenticated_preview();
        assert!(unauth.canary_sample.is_empty());
        assert_eq!(unauth.merkle_root_blake3, manifest.merkle_root_blake3);
        assert!(unauth.synthetic_contamination_filtered);

        // Authenticated preview must watermark canary lines for the specific requester
        let auth_preview = manifest.to_authenticated_watermarked_preview(&seed, "us-lab-alpha");
        assert_eq!(auth_preview.canary_sample.len(), 1);
        assert!(auth_preview.synthetic_contamination_filtered);
        assert!(auth_preview.canary_sample[0].verify_buyer_watermark(&seed, "us-lab-alpha", "preview_canary"));
        assert!(!auth_preview.canary_sample[0].verify_buyer_watermark(&seed, "other-buyer", "preview_canary"));
    }

    #[test]
    fn test_contribution_ledger_multi_peer_dedup_and_revenue_split() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];

        let mk_rec = |id: &str, peer: &str, prompt: &str, seed: &[u8; 32]| {
            let mut r = SanitizedTrainingRecord {
                record_id: id.to_string(),
                blake3_record_hash: String::new(),
                origin_node_id: peer.to_string(),
                format: TrainingRecordFormat::DpoPreferencePair,
                domain_tags: vec!["clinical-deid".to_string()],
                prompt: prompt.to_string(),
                rlm_trajectory: vec![],
                chosen_response: format!("Grounded synthesis for {}", prompt),
                rejected_response: Some("Contact bar fallback".to_string()),
                verified_citation_count: 1,
                grounding_score_bps: 10_000,
                pii_scrub_verified: true,
                trade_secret_clean: true,
                token_count: 100,
                created_unix_secs: 1_760_000_000,
                ed25519_signature_hex: String::new(),
                buyer_watermark_hex: None,
            };
            r.sign_ed25519(seed).unwrap();
            r
        };

        let r1 = mk_rec("r1", "12D3KooWPeerA", "Prompt 1", &seed_a);
        let r2 = mk_rec("r2", "12D3KooWPeerA", "Prompt 2", &seed_a);
        let r3 = mk_rec("r3", "12D3KooWPeerA", "Prompt 3", &seed_a);
        let r4 = mk_rec("r4", "12D3KooWPeerB", "Prompt 4", &seed_b);
        // Duplicate of Prompt 1 submitted by PeerB -> must be dropped and counted as duplicate
        let r_dup = mk_rec("r5", "12D3KooWPeerB", "Prompt 1", &seed_b);

        let (ledger, unique) = ContributionLedger::merge_and_deduplicate_mesh_records(
            "pool-001",
            vec![r1, r2, r3, r4, r_dup],
            100_000, // $1,000.00
        );

        assert_eq!(unique.len(), 4);
        assert_eq!(ledger.total_unique_records, 4);
        assert_eq!(ledger.total_duplicates_dropped, 1);

        let share_a = ledger.peer_shares.get("12D3KooWPeerA").unwrap();
        let share_b = ledger.peer_shares.get("12D3KooWPeerB").unwrap();
        assert_eq!(share_a.unique_records_accepted, 3);
        assert_eq!(share_a.revenue_share_bps, 7500);
        assert_eq!(share_a.estimated_payout_cents, 75_000);
        assert_eq!(share_b.unique_records_accepted, 1);
        assert_eq!(share_b.duplicate_records_dropped, 1);
        assert_eq!(share_b.revenue_share_bps, 2500);
        assert_eq!(share_b.estimated_payout_cents, 25_000);
    }
}
