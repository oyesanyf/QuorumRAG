//! Access Control List (ACL) and Dynamic Attestation-Tier Gating for QuorumRAG Mesh Peers.
//!
//! Monotonically enforces access tier ceilings based on cryptographically verified
//! TPM 2.0 platform configuration and OEM Endorsement Key (EK) silicon provenance:
//! - Verified TPM 2.0 with Silicon EK -> Tier 3 (Restricted)
//! - Verified TPM 2.0 Hardware PCR -> Tier 2 (Confidential)
//! - Pure-Rust Simulated TPM -> Tier 1 (Internal)
//! - Unverified or Expired -> Tier 0 (Public)

use chrono::{DateTime, Utc};
use quorum_types::AccessTier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::tpm::TpmOemVendor;

/// Level of hardware or software platform attestation verified for a mesh peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum AttestationTier {
    /// No valid attestation evidence provided; unverified or failed challenge.
    #[default]
    Unverified = 0,
    /// Software-anchored or simulated TPM attestation (e.g. CI, VM, pure-Rust fallback).
    Simulated = 1,
    /// Verified physical hardware TPM 2.0 platform configuration (PCR 0, 7, 16 verified).
    VerifiedHardwareTpm = 2,
    /// Verified physical hardware TPM 2.0 with cryptographic OEM Silicon Endorsement Key (EK) certificate.
    VerifiedHardwareEk = 3,
}

impl AttestationTier {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns the maximum allowable AccessTier permitted under this attestation level.
    pub fn max_allowed_access_tier(&self) -> AccessTier {
        match self {
            Self::Unverified => AccessTier::Tier0Public,
            Self::Simulated => AccessTier::Tier1Internal,
            Self::VerifiedHardwareTpm => AccessTier::Tier2Confidential,
            Self::VerifiedHardwareEk => AccessTier::Tier3Restricted,
        }
    }
}

/// Detailed record of a verified hardware or simulated TPM attestation for a mesh peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAttestationRecord {
    pub peer_id: String,
    pub pubkey: Option<[u8; 32]>,
    pub attestation_tier: AttestationTier,
    pub vendor: Option<TpmOemVendor>,
    pub pcr_composite_digest: Option<String>,
    pub hardware_backed: bool,
    pub ek_fingerprint: Option<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PeerAttestationRecord {
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

/// Manages access-tier authorization policies and dynamic attestation-tier gating for mesh peers.
#[derive(Debug, Clone)]
pub struct PeerAclManager {
    peer_pubkey_tiers: HashMap<[u8; 32], AccessTier>,
    peer_id_tiers: HashMap<String, AccessTier>,
    peer_attestations: HashMap<String, PeerAttestationRecord>,
    pubkey_to_peer_id: HashMap<[u8; 32], String>,
    default_tier: AccessTier,
    attestation_ttl_seconds: i64,
}

pub type AccessTierPolicy = PeerAclManager;

impl Default for PeerAclManager {
    fn default() -> Self {
        Self {
            peer_pubkey_tiers: HashMap::new(),
            peer_id_tiers: HashMap::new(),
            peer_attestations: HashMap::new(),
            pubkey_to_peer_id: HashMap::new(),
            default_tier: AccessTier::Tier0Public,
            attestation_ttl_seconds: 300, // 5 minutes default TTL
        }
    }
}

impl PeerAclManager {
    pub fn new(default_tier: AccessTier) -> Self {
        Self {
            peer_pubkey_tiers: HashMap::new(),
            peer_id_tiers: HashMap::new(),
            peer_attestations: HashMap::new(),
            pubkey_to_peer_id: HashMap::new(),
            default_tier,
            attestation_ttl_seconds: 300,
        }
    }

    pub fn with_attestation_ttl(mut self, ttl_seconds: i64) -> Self {
        self.attestation_ttl_seconds = ttl_seconds;
        self
    }

    pub fn register_pubkey(&mut self, pubkey: [u8; 32], tier: AccessTier) {
        self.peer_pubkey_tiers.insert(pubkey, tier);
    }

    pub fn register_peer_id(&mut self, peer_id: String, tier: AccessTier) {
        self.peer_id_tiers.insert(peer_id, tier);
    }

    pub fn associate_pubkey_with_peer_id(&mut self, pubkey: [u8; 32], peer_id: String) {
        self.pubkey_to_peer_id.insert(pubkey, peer_id);
    }

    /// Record a verified hardware or simulated TPM attestation for a peer.
    pub fn record_peer_attestation(&mut self, record: PeerAttestationRecord) {
        if let Some(pk) = record.pubkey {
            self.pubkey_to_peer_id.insert(pk, record.peer_id.clone());
        }
        self.peer_attestations.insert(record.peer_id.clone(), record);
    }

    pub fn get_attestation_record(&self, peer_id: &str) -> Option<&PeerAttestationRecord> {
        self.peer_attestations.get(peer_id)
    }

    /// Retrieves the current attestation tier, downgrading to Unverified if expired.
    pub fn get_attestation_tier(&self, peer_id: &str) -> AttestationTier {
        match self.peer_attestations.get(peer_id) {
            Some(record) if record.is_valid() => record.attestation_tier,
            _ => AttestationTier::Unverified,
        }
    }

    /// Resolves the maximum access tier permitted by the peer's attestation state.
    pub fn get_max_allowed_tier_by_attestation(&self, peer_id: &str) -> AccessTier {
        self.get_attestation_tier(peer_id).max_allowed_access_tier()
    }

    /// Resolves effective tier by capping the registered tier at the attestation upper bound.
    pub fn get_effective_authorized_tier_for_peer_id(&self, peer_id: &str) -> AccessTier {
        let registered = self.get_authorized_tier_for_peer_id(peer_id);
        let max_allowed = self.get_max_allowed_tier_by_attestation(peer_id);
        registered.min(max_allowed)
    }

    pub fn get_effective_authorized_tier_for_pubkey(&self, pubkey: &[u8; 32]) -> AccessTier {
        let registered = self.get_authorized_tier_for_pubkey(pubkey);
        if let Some(peer_id) = self.pubkey_to_peer_id.get(pubkey) {
            let max_allowed = self.get_max_allowed_tier_by_attestation(peer_id);
            registered.min(max_allowed)
        } else {
            // Without attestation record, pubkey cannot exceed Tier0
            registered.min(AccessTier::Tier0Public)
        }
    }

    pub fn get_authorized_tier_for_pubkey(&self, pubkey: &[u8; 32]) -> AccessTier {
        self.peer_pubkey_tiers
            .get(pubkey)
            .copied()
            .unwrap_or(self.default_tier)
    }

    pub fn get_authorized_tier_for_peer_id(&self, peer_id: &str) -> AccessTier {
        self.peer_id_tiers
            .get(peer_id)
            .copied()
            .unwrap_or(self.default_tier)
    }

    /// Resolves the effective access tier by capping the requested tier at the peer's authorized upper bound.
    pub fn resolve_effective_tier(&self, requested_tier: u8, authorized_tier: AccessTier) -> u8 {
        requested_tier.min(authorized_tier.as_u8())
    }
}
