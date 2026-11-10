//! Forensic artifact classification, provenance attestation, and marketplace harvest allowlisting
//! for Artemis DFIR telemetry integration in QuorumRAG.
//!
//! # Architecture & Governance
//! Forensic telemetry ingestion from host OS artifacts (Windows Event Logs/Registry/Prefetch,
//! macOS Unified Logs/LaunchDaemons, Linux journald/auditd/proc) must adhere to strict zero-trust
//! boundaries:
//! 1. **Classification Schema**: Formal 10-type taxonomy of forensic telemetry.
//! 2. **Marketplace Harvest Allowlist**: Strictly allowlists defensive execution and telemetry
//!    categories (`ProcessExecution`, `NetworkConnection`, `RegistryPersistence`, `SystemEventLog`,
//!    `PrefetchAmcacheExecution`, `ServiceDaemon`) while unconditionally barring personal browsing,
//!    session tokens, raw shell history, and credential stores (`BrowserCookies`, `BrowserHistoryOAuth`,
//!    `CredentialStore`, `ShellHistoryRaw`).
//! 3. **Cryptographic Provenance**: Attestation data model tracking collector engine, timestamps,
//!    raw payload BLAKE3 digest, `Tier3Restricted` access tier, and node Ed25519 digital signatures.
//! 4. **Fail-Closed Airgap Invariants**: Enforces `access_tier: 3`, `artemis_dfir: true`, and
//!    `mesh_sharable: false` across all records.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Error contract for forensic artifact classification, provenance validation, and airgap gating.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ForensicContractError {
    #[error("Harvest category prohibited: category '{category}' is barred from marketplace harvest: {reason}")]
    HarvestCategoryProhibited { category: String, reason: String },

    #[error("Invalid access tier for forensic artifact: expected {expected} (Tier3Restricted), got {actual}")]
    InvalidAccessTier { expected: u8, actual: u8 },

    #[error("Airgap violation: forensic artifact '{artifact_id}' cannot have mesh_sharable = true")]
    MeshShareViolation { artifact_id: String },

    #[error("Airgap flag violation on artifact '{artifact_id}': field '{field}' expected {expected}, got {actual}")]
    AirgapFlagViolation {
        artifact_id: String,
        field: String,
        expected: bool,
        actual: bool,
    },

    #[error("Harvest eligibility flag mismatch for artifact '{artifact_id}': expected {expected}, got {actual}")]
    HarvestEligibilityMismatch {
        artifact_id: String,
        expected: bool,
        actual: bool,
    },

    #[error("Missing attestation signature for forensic artifact '{artifact_id}'")]
    MissingProvenanceSignature { artifact_id: String },

    #[error("Forensic provenance Ed25519 signature invalid for artifact '{artifact_id}'")]
    ProvenanceSignatureInvalid { artifact_id: String },

    #[error("Invalid Ed25519 public key bytes for artifact '{artifact_id}': {details}")]
    InvalidPublicKey { artifact_id: String, details: String },

    #[error("Invalid Ed25519 signature hex for artifact '{artifact_id}': {details}")]
    InvalidSignatureHex { artifact_id: String, details: String },

    #[error("Raw payload BLAKE3 digest mismatch for artifact '{artifact_id}': expected {expected}, actual {actual}")]
    PayloadDigestMismatch {
        artifact_id: String,
        expected: String,
        actual: String,
    },

    #[error("Unknown forensic telemetry type: '{raw}'")]
    UnknownTelemetryType { raw: String },
}

/// Canonical classification taxonomy for host forensic telemetry collected via Artemis DFIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicTelemetryType {
    /// Process creation, termination, command lines, parent PIDs, user tokens, binary hashes.
    ProcessExecution,
    /// Established/listening network sockets, IP endpoints, transport protocols, process bindings.
    NetworkConnection,
    /// Windows Run/RunOnce, ASEPs, ShellBags, UserAssist, ShimCache, scheduled persistence mechanisms.
    RegistryPersistence,
    /// Windows Event Logs (Security 4688/4624, Sysmon, System, Application), syslog, systemd journal.
    SystemEventLog,
    /// Windows Prefetch (.pf) execution evidence and Amcache.hve program execution records.
    PrefetchAmcacheExecution,
    /// Operating system services and background daemons (Windows Services, systemd units, LaunchDaemons).
    ServiceDaemon,
    /// Browser cookie databases and session tokens (STRICTLY PROHIBITED from marketplace harvest).
    BrowserCookies,
    /// Browser navigation history, OAuth redirect URLs, bearer query params (STRICTLY PROHIBITED).
    #[serde(rename = "browser_history_oauth", alias = "browser_history_o_auth")]
    BrowserHistoryOAuth,
    /// Local credential stores, SAM, SECURITY, DPAPI, Keychain, /etc/shadow (STRICTLY PROHIBITED).
    CredentialStore,
    /// Raw unparsed shell history files (.bash_history, ConsoleHost_history.txt) (STRICTLY PROHIBITED).
    ShellHistoryRaw,
}

impl ForensicTelemetryType {
    /// All 10 canonical forensic telemetry categories in canonical taxonomy order.
    pub const ALL_TYPES: [Self; 10] = [
        Self::ProcessExecution,
        Self::NetworkConnection,
        Self::RegistryPersistence,
        Self::SystemEventLog,
        Self::PrefetchAmcacheExecution,
        Self::ServiceDaemon,
        Self::BrowserCookies,
        Self::BrowserHistoryOAuth,
        Self::CredentialStore,
        Self::ShellHistoryRaw,
    ];

    /// Evaluates whether this telemetry category is strictly allowlisted for
    /// Opt-In Sovereign AI Training Data Marketplace harvesting and model fine-tuning.
    ///
    /// # Absolute Invariant:
    /// Only defensive execution and system telemetry categories are allowlisted:
    /// - `ProcessExecution`
    /// - `NetworkConnection`
    /// - `RegistryPersistence`
    /// - `SystemEventLog`
    /// - `PrefetchAmcacheExecution`
    /// - `ServiceDaemon`
    ///
    /// Personal browsing, session cookies, credential stores, and raw shell histories
    /// are strictly prohibited from marketplace harvest:
    /// - `BrowserCookies`
    /// - `BrowserHistoryOAuth`
    /// - `CredentialStore`
    /// - `ShellHistoryRaw`
    #[inline]
    pub const fn is_marketplace_harvest_allowed(&self) -> bool {
        match self {
            Self::ProcessExecution
            | Self::NetworkConnection
            | Self::RegistryPersistence
            | Self::SystemEventLog
            | Self::PrefetchAmcacheExecution
            | Self::ServiceDaemon => true,

            Self::BrowserCookies
            | Self::BrowserHistoryOAuth
            | Self::CredentialStore
            | Self::ShellHistoryRaw => false,
        }
    }

    /// Whether this telemetry type represents defensive system execution telemetry.
    #[inline]
    pub const fn is_defensive_telemetry(&self) -> bool {
        self.is_marketplace_harvest_allowed()
    }

    /// Canonical lowercase snake_case identifier string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessExecution => "process_execution",
            Self::NetworkConnection => "network_connection",
            Self::RegistryPersistence => "registry_persistence",
            Self::SystemEventLog => "system_event_log",
            Self::PrefetchAmcacheExecution => "prefetch_amcache_execution",
            Self::ServiceDaemon => "service_daemon",
            Self::BrowserCookies => "browser_cookies",
            Self::BrowserHistoryOAuth => "browser_history_oauth",
            Self::CredentialStore => "credential_store",
            Self::ShellHistoryRaw => "shell_history_raw",
        }
    }

    /// Human-readable explanation of why a category is prohibited from marketplace harvest,
    /// or `None` if the category is allowed.
    pub const fn harvest_prohibition_reason(&self) -> Option<&'static str> {
        match self {
            Self::BrowserCookies => Some(
                "Browser cookie jars and session tokens contain sensitive auth state and are strictly barred from sovereign AI training data harvest.",
            ),
            Self::BrowserHistoryOAuth => Some(
                "Browser history and OAuth redirect URLs with bearer parameters are strictly barred from marketplace harvest.",
            ),
            Self::CredentialStore => Some(
                "OS and application credential stores (SAM, DPAPI, Keychain, shadow) are strictly barred from marketplace harvest.",
            ),
            Self::ShellHistoryRaw => Some(
                "Raw shell history files containing commands and potential credentials are barred from marketplace harvest.",
            ),
            Self::ProcessExecution
            | Self::NetworkConnection
            | Self::RegistryPersistence
            | Self::SystemEventLog
            | Self::PrefetchAmcacheExecution
            | Self::ServiceDaemon => None,
        }
    }

    /// Asserts that this category is permitted for marketplace harvesting, returning a typed
    /// error if prohibited.
    pub fn assert_marketplace_harvest_allowed(&self) -> Result<(), ForensicContractError> {
        if self.is_marketplace_harvest_allowed() {
            Ok(())
        } else {
            let reason = self
                .harvest_prohibition_reason()
                .unwrap_or("Telemetry category prohibited from marketplace harvest")
                .to_string();
            Err(ForensicContractError::HarvestCategoryProhibited {
                category: self.as_str().to_string(),
                reason,
            })
        }
    }
}

impl fmt::Display for ForensicTelemetryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ForensicTelemetryType {
    type Err = ForensicContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "process_execution" | "processexecution" => Ok(Self::ProcessExecution),
            "network_connection" | "networkconnection" => Ok(Self::NetworkConnection),
            "registry_persistence" | "registrypersistence" => Ok(Self::RegistryPersistence),
            "system_event_log" | "systemeventlog" => Ok(Self::SystemEventLog),
            "prefetch_amcache_execution" | "prefetchamcacheexecution" | "prefetch_amcache" => {
                Ok(Self::PrefetchAmcacheExecution)
            }
            "service_daemon" | "servicedaemon" => Ok(Self::ServiceDaemon),
            "browser_cookies" | "browsercookies" => Ok(Self::BrowserCookies),
            "browser_history_oauth"
            | "browser_history_o_auth"
            | "browserhistoryoauth"
            | "browser_history" => {
                Ok(Self::BrowserHistoryOAuth)
            }
            "credential_store" | "credentialstore" => Ok(Self::CredentialStore),
            "shell_history_raw" | "shellhistoryraw" | "shell_history" => {
                Ok(Self::ShellHistoryRaw)
            }
            _ => Err(ForensicContractError::UnknownTelemetryType {
                raw: s.to_string(),
            }),
        }
    }
}

/// Cryptographic provenance attestation record bound to an Artemis DFIR telemetry artifact.
///
/// Guaranteed invariants:
/// 1. `access_tier` is strictly 3 (`Tier3Restricted`).
/// 2. `artemis_dfir` is strictly `true`.
/// 3. `mesh_sharable` is strictly `false`.
/// 4. `harvest_eligible` strictly mirrors `telemetry_type.is_marketplace_harvest_allowed()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicProvenance {
    /// Unique artifact identifier (UUID v4 or deterministic derivation).
    pub artifact_id: String,
    /// Forensic telemetry classification.
    pub telemetry_type: ForensicTelemetryType,
    /// Logical or physical source path (e.g. "artemis://windows/eventlog/Security.evtx").
    pub source_path: String,
    /// Origin host identifier (hostname, NetBIOS name, or machine GUID).
    pub host_identifier: String,
    /// Target operating system platform: "windows", "macos", "linux".
    pub os_platform: String,
    /// OS release, version, or kernel build.
    pub os_version: Option<String>,
    /// Collector engine identity (e.g. "artemis-core", "puffycid/artemis").
    pub collector_name: String,
    /// Collector engine version.
    pub collector_version: String,
    /// Timestamp in Unix seconds when artifact was captured from the OS.
    pub collected_unix_secs: i64,
    /// Timestamp in Unix seconds when artifact was ingested into QuorumRAG.
    pub ingested_unix_secs: i64,
    /// BLAKE3 hex digest of the raw artifact payload before chunking/scrubbing.
    pub raw_payload_blake3: String,
    /// Monotonically enforced access tier (invariant: always 3 = Tier3Restricted).
    pub access_tier: u8,
    /// Invariant flag indicating Artemis DFIR origin (always true).
    pub artemis_dfir: bool,
    /// Invariant flag barring P2P mesh sharing (always false).
    pub mesh_sharable: bool,
    /// Harvest eligibility flag: mirrors `telemetry_type.is_marketplace_harvest_allowed()`.
    pub harvest_eligible: bool,
    /// Optional Ed25519 signature hex string produced by the host node private key.
    pub attestation_signature_hex: Option<String>,
}

impl ForensicProvenance {
    /// Construct a new `ForensicProvenance` record enforcing default airgap invariants:
    /// - access_tier = 3 (Tier3Restricted)
    /// - artemis_dfir = true
    /// - mesh_sharable = false
    /// - harvest_eligible = telemetry_type.is_marketplace_harvest_allowed()
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_id: impl Into<String>,
        telemetry_type: ForensicTelemetryType,
        source_path: impl Into<String>,
        host_identifier: impl Into<String>,
        os_platform: impl Into<String>,
        os_version: Option<String>,
        collector_name: impl Into<String>,
        collector_version: impl Into<String>,
        collected_unix_secs: i64,
        raw_payload_blake3: impl Into<String>,
    ) -> Result<Self, ForensicContractError> {
        let prov = Self {
            artifact_id: artifact_id.into(),
            telemetry_type,
            source_path: source_path.into(),
            host_identifier: host_identifier.into(),
            os_platform: os_platform.into(),
            os_version,
            collector_name: collector_name.into(),
            collector_version: collector_version.into(),
            collected_unix_secs,
            ingested_unix_secs: chrono::Utc::now().timestamp(),
            raw_payload_blake3: raw_payload_blake3.into(),
            access_tier: 3,
            artemis_dfir: true,
            mesh_sharable: false,
            harvest_eligible: telemetry_type.is_marketplace_harvest_allowed(),
            attestation_signature_hex: None,
        };
        prov.validate_invariants()?;
        Ok(prov)
    }

    /// Construct provenance by directly hashing raw payload bytes with BLAKE3.
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_payload(
        artifact_id: impl Into<String>,
        telemetry_type: ForensicTelemetryType,
        source_path: impl Into<String>,
        host_identifier: impl Into<String>,
        os_platform: impl Into<String>,
        os_version: Option<String>,
        collector_name: impl Into<String>,
        collector_version: impl Into<String>,
        collected_unix_secs: i64,
        raw_payload: &[u8],
    ) -> Result<Self, ForensicContractError> {
        let digest_hex = blake3::hash(raw_payload).to_hex().to_string();
        Self::new(
            artifact_id,
            telemetry_type,
            source_path,
            host_identifier,
            os_platform,
            os_version,
            collector_name,
            collector_version,
            collected_unix_secs,
            digest_hex,
        )
    }

    /// Canonical domain-separated byte stream for Ed25519 node signing and verification.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"QuorumRAG-ForensicProvenance-v1:");
        hasher.update(self.artifact_id.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.telemetry_type.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(self.source_path.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.host_identifier.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        hasher.update(self.os_platform.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        hasher.update(self.os_version.as_deref().unwrap_or("").trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.collector_name.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(self.collector_version.trim().as_bytes());
        hasher.update(b"|");
        hasher.update(&self.collected_unix_secs.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&self.ingested_unix_secs.to_le_bytes());
        hasher.update(b"|");
        hasher.update(self.raw_payload_blake3.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"|");
        hasher.update(&[
            self.access_tier,
            u8::from(self.artemis_dfir),
            u8::from(self.mesh_sharable),
            u8::from(self.harvest_eligible),
        ]);
        hasher.finalize().as_bytes().to_vec()
    }

    /// Signs the provenance record in-place using a 32-byte Ed25519 node signing key seed.
    pub fn sign_ed25519(
        &mut self,
        node_signing_key_bytes: &[u8; 32],
    ) -> Result<(), ForensicContractError> {
        self.validate_invariants()?;
        let signing_key = SigningKey::from_bytes(node_signing_key_bytes);
        let msg = self.canonical_signing_bytes();
        let sig: Signature = signing_key.sign(&msg);
        self.attestation_signature_hex = Some(bytes_to_hex(&sig.to_bytes()));
        Ok(())
    }

    /// Verifies the provenance record's Ed25519 attestation signature against the given 32-byte public key.
    pub fn verify_ed25519(&self, node_pubkey_bytes: &[u8; 32]) -> Result<(), ForensicContractError> {
        self.validate_invariants()?;
        let verifying_key =
            VerifyingKey::from_bytes(node_pubkey_bytes).map_err(|e| {
                ForensicContractError::InvalidPublicKey {
                    artifact_id: self.artifact_id.clone(),
                    details: e.to_string(),
                }
            })?;

        let sig_hex = self
            .attestation_signature_hex
            .as_deref()
            .ok_or_else(|| ForensicContractError::MissingProvenanceSignature {
                artifact_id: self.artifact_id.clone(),
            })?;

        let sig_bytes = hex_to_64_bytes(sig_hex).ok_or_else(|| {
            ForensicContractError::InvalidSignatureHex {
                artifact_id: self.artifact_id.clone(),
                details: "Signature must be 128 hex characters (64 bytes)".to_string(),
            }
        })?;

        let sig = Signature::from_bytes(&sig_bytes);
        let msg = self.canonical_signing_bytes();
        verifying_key
            .verify(&msg, &sig)
            .map_err(|_| ForensicContractError::ProvenanceSignatureInvalid {
                artifact_id: self.artifact_id.clone(),
            })?;

        Ok(())
    }

    /// Verifies that the given raw payload bytes match the record's raw_payload_blake3 digest.
    pub fn verify_payload_bytes(&self, payload: &[u8]) -> Result<(), ForensicContractError> {
        let computed_digest = blake3::hash(payload).to_hex().to_string();
        let expected_clean = self.raw_payload_blake3.trim().to_ascii_lowercase();
        let matches = bool::from(
            expected_clean
                .as_bytes()
                .ct_eq(computed_digest.as_bytes()),
        );
        if !matches {
            return Err(ForensicContractError::PayloadDigestMismatch {
                artifact_id: self.artifact_id.clone(),
                expected: self.raw_payload_blake3.clone(),
                actual: computed_digest,
            });
        }
        Ok(())
    }

    /// Validates all forensic invariants:
    /// 1. access_tier == 3 (Tier3Restricted)
    /// 2. artemis_dfir == true
    /// 3. mesh_sharable == false
    /// 4. harvest_eligible == self.telemetry_type.is_marketplace_harvest_allowed()
    pub fn validate_invariants(&self) -> Result<(), ForensicContractError> {
        if self.access_tier != 3 {
            return Err(ForensicContractError::InvalidAccessTier {
                expected: 3,
                actual: self.access_tier,
            });
        }
        if !self.artemis_dfir {
            return Err(ForensicContractError::AirgapFlagViolation {
                artifact_id: self.artifact_id.clone(),
                field: "artemis_dfir".to_string(),
                expected: true,
                actual: self.artemis_dfir,
            });
        }
        if self.mesh_sharable {
            return Err(ForensicContractError::MeshShareViolation {
                artifact_id: self.artifact_id.clone(),
            });
        }
        let expected_harvest = self.telemetry_type.is_marketplace_harvest_allowed();
        if self.harvest_eligible != expected_harvest {
            return Err(ForensicContractError::HarvestEligibilityMismatch {
                artifact_id: self.artifact_id.clone(),
                expected: expected_harvest,
                actual: self.harvest_eligible,
            });
        }
        Ok(())
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
    let bytes = hex_str.trim().as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        let hi = match bytes[i * 2] {
            b'0'..=b'9' => bytes[i * 2] - b'0',
            b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
            _ => return None,
        };
        let lo = match bytes[i * 2 + 1] {
            b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
            b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
            _ => return None,
        };
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_10_telemetry_types_classification_and_allowlist() {
        assert_eq!(ForensicTelemetryType::ALL_TYPES.len(), 10);

        let allowed_types = [
            ForensicTelemetryType::ProcessExecution,
            ForensicTelemetryType::NetworkConnection,
            ForensicTelemetryType::RegistryPersistence,
            ForensicTelemetryType::SystemEventLog,
            ForensicTelemetryType::PrefetchAmcacheExecution,
            ForensicTelemetryType::ServiceDaemon,
        ];

        let prohibited_types = [
            ForensicTelemetryType::BrowserCookies,
            ForensicTelemetryType::BrowserHistoryOAuth,
            ForensicTelemetryType::CredentialStore,
            ForensicTelemetryType::ShellHistoryRaw,
        ];

        for t in &allowed_types {
            assert!(
                t.is_marketplace_harvest_allowed(),
                "Expected {:?} to be allowlisted",
                t
            );
            assert!(
                t.is_defensive_telemetry(),
                "Expected {:?} to be defensive telemetry",
                t
            );
            assert!(
                t.assert_marketplace_harvest_allowed().is_ok(),
                "Assertion should pass for allowlisted type {:?}",
                t
            );
            assert!(t.harvest_prohibition_reason().is_none());
        }

        for t in &prohibited_types {
            assert!(
                !t.is_marketplace_harvest_allowed(),
                "Expected {:?} to be prohibited",
                t
            );
            assert!(
                !t.is_defensive_telemetry(),
                "Expected {:?} to not be defensive telemetry",
                t
            );
            let res = t.assert_marketplace_harvest_allowed();
            assert!(
                matches!(
                    res,
                    Err(ForensicContractError::HarvestCategoryProhibited { .. })
                ),
                "Expected HarvestCategoryProhibited error for {:?}",
                t
            );
            assert!(t.harvest_prohibition_reason().is_some());
        }
    }

    #[test]
    fn test_telemetry_type_string_and_serde_roundtrip() {
        for t in &ForensicTelemetryType::ALL_TYPES {
            let s = t.as_str();
            assert_eq!(t.to_string(), s);

            let parsed: ForensicTelemetryType = s.parse().expect("Failed to parse from str");
            assert_eq!(*t, parsed);

            // Test JSON serde
            let json = serde_json::to_string(t).expect("Failed to serialize");
            let deserialized: ForensicTelemetryType =
                serde_json::from_str(&json).expect("Failed to deserialize");
            assert_eq!(*t, deserialized);
        }

        // Test unknown type rejection
        let unknown = "invalid_category_xyz".parse::<ForensicTelemetryType>();
        assert!(matches!(
            unknown,
            Err(ForensicContractError::UnknownTelemetryType { .. })
        ));

        // Explicitly assert BrowserHistoryOAuth alias and canonical serialization
        let oauth = ForensicTelemetryType::BrowserHistoryOAuth;
        assert_eq!(serde_json::to_string(&oauth).unwrap(), "\"browser_history_oauth\"");
        let de_canonical: ForensicTelemetryType = serde_json::from_str("\"browser_history_oauth\"").unwrap();
        assert_eq!(de_canonical, oauth);
        let de_alias: ForensicTelemetryType = serde_json::from_str("\"browser_history_o_auth\"").unwrap();
        assert_eq!(de_alias, oauth);
        let from_canonical: ForensicTelemetryType = "browser_history_oauth".parse().unwrap();
        assert_eq!(from_canonical, oauth);
        let from_alias: ForensicTelemetryType = "browser_history_o_auth".parse().unwrap();
        assert_eq!(from_alias, oauth);
    }

    #[test]
    fn test_forensic_provenance_construction_and_defaults() {
        let prov = ForensicProvenance::new(
            "artifact-001",
            ForensicTelemetryType::ProcessExecution,
            "artemis://windows/eventlog/Security.evtx",
            "SEC-DESKTOP-01",
            "windows",
            Some("10.0.19045".to_string()),
            "artemis-core",
            "0.1.0",
            1762736400,
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        )
        .expect("Failed to construct provenance");

        assert_eq!(prov.artifact_id, "artifact-001");
        assert_eq!(prov.access_tier, 3);
        assert!(prov.artemis_dfir);
        assert!(!prov.mesh_sharable);
        assert!(prov.harvest_eligible);
        assert!(prov.attestation_signature_hex.is_none());
        assert!(prov.validate_invariants().is_ok());

        // Prohibited type should have harvest_eligible = false
        let prohibited_prov = ForensicProvenance::new(
            "artifact-002",
            ForensicTelemetryType::CredentialStore,
            "artemis://windows/registry/SAM",
            "SEC-DESKTOP-01",
            "windows",
            None,
            "artemis-core",
            "0.1.0",
            1762736400,
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        )
        .expect("Failed to construct prohibited provenance");

        assert!(!prohibited_prov.harvest_eligible);
        assert!(prohibited_prov.validate_invariants().is_ok());
    }

    #[test]
    fn test_forensic_provenance_from_raw_payload_and_payload_digest_verification() {
        let payload = b"{\"event_id\": 4688, \"process\": \"powershell.exe\", \"parent\": \"explorer.exe\"}";
        let expected_hash = blake3::hash(payload).to_hex().to_string();

        let prov = ForensicProvenance::from_raw_payload(
            "art-jsonl-01",
            ForensicTelemetryType::ProcessExecution,
            "artemis://windows/eventlog/Security",
            "WIN-SRV01",
            "windows",
            None,
            "artemis-core",
            "0.1.0",
            1762736500,
            payload,
        )
        .expect("from_raw_payload should succeed");

        assert_eq!(prov.raw_payload_blake3, expected_hash);
        assert!(prov.verify_payload_bytes(payload).is_ok());

        // Tampered payload must fail verification
        let tampered = b"{\"event_id\": 4688, \"process\": \"cmd.exe\"}";
        let verify_res = prov.verify_payload_bytes(tampered);
        assert!(matches!(
            verify_res,
            Err(ForensicContractError::PayloadDigestMismatch { .. })
        ));
    }

    #[test]
    fn test_canonical_signing_bytes_determinism_and_domain_separation() {
        let mut prov1 = ForensicProvenance::new(
            "art-100",
            ForensicTelemetryType::SystemEventLog,
            "artemis://linux/journald",
            "LINUX-PROD-01",
            "linux",
            Some("6.5.0-generic".to_string()),
            "artemis-core",
            "0.1.0",
            1762736000,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        prov1.ingested_unix_secs = 1762736010;

        let mut prov2 = prov1.clone();
        assert_eq!(
            prov1.canonical_signing_bytes(),
            prov2.canonical_signing_bytes()
        );

        // Modifying any critical field must mutate the canonical signing bytes
        prov2.artifact_id = "art-101".to_string();
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov2.canonical_signing_bytes()
        );

        let mut prov3 = prov1.clone();
        prov3.telemetry_type = ForensicTelemetryType::NetworkConnection;
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov3.canonical_signing_bytes()
        );

        let mut prov4 = prov1.clone();
        prov4.source_path = "artemis://linux/auditd".to_string();
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov4.canonical_signing_bytes()
        );

        let mut prov5 = prov1.clone();
        prov5.host_identifier = "OTHER-HOST".to_string();
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov5.canonical_signing_bytes()
        );

        let mut prov6 = prov1.clone();
        prov6.os_version = Some("6.6.0-generic".to_string());
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov6.canonical_signing_bytes()
        );

        let mut prov7 = prov1.clone();
        prov7.collector_name = "artemis-custom".to_string();
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov7.canonical_signing_bytes()
        );

        let mut prov8 = prov1.clone();
        prov8.collector_version = "0.2.0".to_string();
        assert_ne!(
            prov1.canonical_signing_bytes(),
            prov8.canonical_signing_bytes()
        );
    }

    #[test]
    fn test_hex_to_64_bytes_multibyte_utf8_does_not_panic() {
        let cyrillic_pair = "ж"; // 2 bytes in UTF-8
        let mut multibyte_128_bytes = String::new();
        for _ in 0..64 {
            multibyte_128_bytes.push_str(cyrillic_pair);
        }
        assert_eq!(multibyte_128_bytes.len(), 128);

        // Must return None without panicking
        assert_eq!(hex_to_64_bytes(&multibyte_128_bytes), None);

        // Also test verify_ed25519 with this malformed signature hex returns error without panic
        let mut prov = ForensicProvenance::new(
            "art-utf8-panic-test",
            ForensicTelemetryType::ProcessExecution,
            "artemis://windows/eventlog/Security.evtx",
            "SEC-DESKTOP-01",
            "windows",
            None,
            "artemis-core",
            "0.1.0",
            1762736400,
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        )
        .unwrap();

        prov.attestation_signature_hex = Some(multibyte_128_bytes);
        let pubkey = [0u8; 32];
        let verify_res = prov.verify_ed25519(&pubkey);
        assert!(matches!(
            verify_res,
            Err(ForensicContractError::InvalidSignatureHex { .. })
        ));
    }

    #[test]
    fn test_ed25519_attestation_signing_and_verification() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        let mut prov = ForensicProvenance::new(
            "art-sign-01",
            ForensicTelemetryType::PrefetchAmcacheExecution,
            "artemis://windows/prefetch/CMD.EXE-12345678.pf",
            "WIN-HOST-42",
            "windows",
            None,
            "artemis-core",
            "0.1.0",
            1762736600,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .unwrap();

        // Before signing, verify should fail with MissingProvenanceSignature
        assert!(matches!(
            prov.verify_ed25519(&pubkey_bytes),
            Err(ForensicContractError::MissingProvenanceSignature { .. })
        ));

        // Sign in place
        prov.sign_ed25519(&seed).expect("Signing must succeed");
        assert!(prov.attestation_signature_hex.is_some());

        // Verification with matching pubkey must succeed
        assert!(prov.verify_ed25519(&pubkey_bytes).is_ok());

        // Verification with wrong pubkey must fail
        let wrong_seed = [99u8; 32];
        let wrong_pubkey = SigningKey::from_bytes(&wrong_seed).verifying_key().to_bytes();
        assert!(matches!(
            prov.verify_ed25519(&wrong_pubkey),
            Err(ForensicContractError::ProvenanceSignatureInvalid { .. })
        ));

        // Tampering with payload hash after signing must fail verification
        let mut tampered = prov.clone();
        tampered.raw_payload_blake3 =
            "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        assert!(matches!(
            tampered.verify_ed25519(&pubkey_bytes),
            Err(ForensicContractError::ProvenanceSignatureInvalid { .. })
        ));

        // Malformed signature hex must fail
        let mut malformed_hex = prov.clone();
        malformed_hex.attestation_signature_hex = Some("short_bad_hex".to_string());
        assert!(matches!(
            malformed_hex.verify_ed25519(&pubkey_bytes),
            Err(ForensicContractError::InvalidSignatureHex { .. })
        ));
    }

    #[test]
    fn test_fail_closed_validation_invariants() {
        let prov = ForensicProvenance::new(
            "art-inv-01",
            ForensicTelemetryType::ServiceDaemon,
            "artemis://windows/services",
            "WIN-SVC-01",
            "windows",
            None,
            "artemis-core",
            "0.1.0",
            1762736700,
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        )
        .unwrap();

        // Baseline must be valid
        assert!(prov.validate_invariants().is_ok());

        // 1. Invalid access tier (!= 3)
        for bad_tier in [0, 1, 2, 4, 255] {
            let mut bad = prov.clone();
            bad.access_tier = bad_tier;
            assert_eq!(
                bad.validate_invariants(),
                Err(ForensicContractError::InvalidAccessTier {
                    expected: 3,
                    actual: bad_tier,
                })
            );
        }

        // 2. Airgap violation: mesh_sharable = true
        let mut bad_mesh = prov.clone();
        bad_mesh.mesh_sharable = true;
        assert!(matches!(
            bad_mesh.validate_invariants(),
            Err(ForensicContractError::MeshShareViolation { .. })
        ));

        // 3. Airgap flag violation: artemis_dfir = false
        let mut bad_dfir = prov.clone();
        bad_dfir.artemis_dfir = false;
        assert!(matches!(
            bad_dfir.validate_invariants(),
            Err(ForensicContractError::AirgapFlagViolation { .. })
        ));

        // 4. Inconsistent harvest_eligible flag
        let mut bad_harvest = prov.clone();
        bad_harvest.harvest_eligible = false; // Expected true for ServiceDaemon
        assert!(matches!(
            bad_harvest.validate_invariants(),
            Err(ForensicContractError::HarvestEligibilityMismatch { .. })
        ));
    }
}
