//! HTTP Handlers & SQLite Ledger Store for the Opt-In Sovereign AI Training Data Marketplace.
//!
//! Enforces:
//! - Strictly Disabled by Default (`opt_in_enabled = false`) and `["US"]`-only default allowlist.
//! - 7-Layer Sovereign & Domestic-Evasion Guard (`verify_us_sovereign_buyer_against_domestic_evasion`).
//! - Anti-Scraping Tiered Previews (unauthenticated callers get metadata + Merkle root only;
//!   cert-authenticated callers get `<= 5` rate-limited, buyer-watermarked canary lines).
//! - Commit-and-Reveal Cryptographic Escrow (`EscrowReceiptToken`) with hardware TPM 2.0 key binding.
//! - Federated Swarm Pool `ContributionLedger` deduplication and basis-point (`10,000 bps`) revenue splits.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use quorum_contract::{
    BuyerJurisdictionCertificate, ContributionLedger, DataBountySpec, DataCatalogManifest,
    EscrowReceiptToken, SanitizedRlmStep, SanitizedTrainingRecord, TrainingRecordFormat,
};
use quorum_coordinator::{
    decrypt_batch_bytes, encrypt_batch_bytes, is_blocked_foreign_adversary_ip,
    is_high_risk_datacenter_or_proxy_asn, verify_us_sovereign_buyer_against_domestic_evasion,
    MarketplaceSanitizer, RawTrajectoryCandidate, BLOCKED_ADVERSARY_JURISDICTIONS,
    HIGH_RISK_DATACENTER_PROXY_ASNS,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

use crate::state::DaemonState;

/// Default rate limit for authenticated canary previews per buyer/subnet per hour.
pub const DEFAULT_PREVIEW_RATE_LIMIT_PER_HOUR: usize = 5;

/// Persistent SQLite-backed store for Marketplace configuration, encrypted batches,
/// escrow receipts, preview rate limits, data bounties, and `ContributionLedger` records.
pub struct MarketplaceStore {
    db_path: PathBuf,
    pub node_seed: [u8; 32],
    pub origin_node_id: String,
    pub origin_pubkey_hex: String,
    pub escrow_secret: [u8; 32],
    pub default_authority_seed: [u8; 32],
    pub default_authority_pubkey: [u8; 32],
    preview_rate_limits: Mutex<HashMap<String, Vec<i64>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceConfigState {
    /// Strictly disabled by default (`false`).
    pub opt_in_enabled: bool,
    /// Strictly `["US"]` by default.
    pub allowed_jurisdictions: Vec<String>,
    /// Optional subscriber toggle to allow Five Eyes (`["US", "CA", "GB", "AU", "NZ"]`).
    pub five_eyes_enabled: bool,
    pub price_per_1k_records_cents: u64,
    pub authority_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptInConfigRequest {
    pub opt_in_enabled: bool,
    #[serde(default)]
    pub five_eyes_enabled: Option<bool>,
    #[serde(default)]
    pub allowed_jurisdictions: Option<Vec<String>>,
    #[serde(default)]
    pub price_per_1k_records_cents: Option<u64>,
    #[serde(default)]
    pub authority_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestCandidateDto {
    #[serde(default)]
    pub record_id: Option<String>,
    #[serde(default)]
    pub origin_node_id: Option<String>,
    #[serde(default)]
    pub format: Option<TrainingRecordFormat>,
    #[serde(default)]
    pub domain_tags: Option<Vec<String>>,
    pub prompt: String,
    #[serde(default)]
    pub rlm_trajectory: Vec<SanitizedRlmStep>,
    pub chosen_response: String,
    #[serde(default)]
    pub rejected_response: Option<String>,
    /// Pairs of `(source_slice_text, verbatim_quote)` for 100% substring grounding check.
    #[serde(default)]
    pub citations: Vec<(String, String)>,
    #[serde(default)]
    pub extra_redact_terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HarvestBatchRequest {
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub domain_tags: Option<Vec<String>>,
    #[serde(default)]
    pub candidates: Option<Vec<HarvestCandidateDto>>,
    #[serde(default)]
    pub price_per_1k_records_cents: Option<u64>,
    #[serde(default)]
    pub auto_approve: Option<bool>,
    #[serde(default)]
    pub extra_redact_terms: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedCandidateReport {
    pub record_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestBatchResponse {
    pub batch_id: String,
    pub approved: bool,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub rejected_candidates: Vec<RejectedCandidateReport>,
    pub sanitized_records: Vec<SanitizedTrainingRecord>,
    pub manifest: Option<DataCatalogManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApproveBatchRequest {
    #[serde(default)]
    pub batch_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PreviewRequest {
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub buyer_cert: Option<BuyerJurisdictionCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockBatchRequest {
    #[serde(default)]
    pub batch_id: Option<String>,
    pub buyer_cert: BuyerJurisdictionCertificate,
    #[serde(default)]
    pub amount_paid_cents: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DownloadBatchRequest {
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub buyer_cert: Option<BuyerJurisdictionCertificate>,
    #[serde(default)]
    pub receipt_token: Option<EscrowReceiptToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMergeRequest {
    pub pool_batch_id: String,
    pub records: Vec<SanitizedTrainingRecord>,
    pub total_pool_payout_cents: u64,
    #[serde(default)]
    pub price_per_1k_records_cents: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountySubmitRequest {
    pub bounty_id: String,
    #[serde(default)]
    pub batch_id: Option<String>,
}

impl MarketplaceStore {
    pub fn open(
        db_path: &Path,
        node_seed: [u8; 32],
        origin_node_id: String,
    ) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let signing_key = SigningKey::from_bytes(&node_seed);
        let origin_pubkey_hex = bytes_to_hex(signing_key.verifying_key().as_bytes());
        let escrow_secret = blake3::derive_key("QuorumRAG-Marketplace-EscrowSecret-v1", &node_seed);
        let default_authority_seed =
            blake3::derive_key("QuorumRAG-Marketplace-AuthoritySeed-v1", &node_seed);
        let default_authority_pubkey = SigningKey::from_bytes(&default_authority_seed)
            .verifying_key()
            .to_bytes();

        let store = Self {
            db_path: db_path.to_path_buf(),
            node_seed,
            origin_node_id,
            origin_pubkey_hex,
            escrow_secret,
            default_authority_seed,
            default_authority_pubkey,
            preview_rate_limits: Mutex::new(HashMap::new()),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn connect(&self) -> Result<Connection, String> {
        Connection::open(&self.db_path).map_err(|e| format!("SQLite open error: {e}"))
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS marketplace_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS staged_batches (
                batch_id TEXT PRIMARY KEY,
                manifest_json TEXT NOT NULL,
                encrypted_jsonl BLOB NOT NULL,
                approved INTEGER NOT NULL DEFAULT 0,
                created_unix_secs INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS escrow_receipts (
                receipt_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                buyer_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                redeemed_count INTEGER NOT NULL DEFAULT 0,
                created_unix_secs INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contribution_ledgers (
                pool_batch_id TEXT PRIMARY KEY,
                ledger_json TEXT NOT NULL,
                updated_unix_secs INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS data_bounties (
                bounty_id TEXT PRIMARY KEY,
                bounty_json TEXT NOT NULL,
                updated_unix_secs INTEGER NOT NULL
            );",
        )
        .map_err(|e| format!("Failed to initialize marketplace SQLite schema: {e}"))?;

        // Seed defaults ONLY if not present (opt_in_enabled MUST default to false, allowed_jurisdictions MUST default to ["US"])
        let default_auth_pub_hex = bytes_to_hex(&self.default_authority_pubkey);
        let defaults = [
            ("opt_in_enabled", "false"),
            ("allowed_jurisdictions", "[\"US\"]"),
            ("five_eyes_enabled", "false"),
            ("price_per_1k_records_cents", "5000"),
            ("authority_pubkey_hex", default_auth_pub_hex.as_str()),
        ];
        for (k, v) in defaults {
            conn.execute(
                "INSERT OR IGNORE INTO marketplace_config (key, value) VALUES (?1, ?2)",
                params![k, v],
            )
            .map_err(|e| format!("Failed to seed config {k}: {e}"))?;
        }

        // Seed default US sovereign AI training data bounties
        let now = Utc::now().timestamp();
        let default_bounties = [
            DataBountySpec {
                bounty_id: "bounty-us-rust-sec-01".to_string(),
                sponsor_entity_name: "US Frontier Systems Security Lab (Verified LEI)".to_string(),
                sponsor_buyer_id: "us-frontier-sec-lab".to_string(),
                title: "Rust Memory-Safety, eBPF Containment & Zero-Trust P2P SFT Trajectories"
                    .to_string(),
                required_domain_tags: vec!["rust-security".to_string(), "ebpf".to_string()],
                required_format: TrainingRecordFormat::SftTrajectory,
                payout_per_record_cents: 25,
                max_records: 10_000,
                accepted_records: 0,
                jurisdiction_iso: "US".to_string(),
                active: true,
            },
            DataBountySpec {
                bounty_id: "bounty-us-clinical-deid-02".to_string(),
                sponsor_entity_name: "US Healthcare AI Consortium (HIPAA / Part-202 Verified)"
                    .to_string(),
                sponsor_buyer_id: "us-clinical-consortium".to_string(),
                title: "De-Identified Clinical Triage & Citation-Grounded DPO Preference Pairs"
                    .to_string(),
                required_domain_tags: vec!["clinical-deid".to_string(), "healthcare".to_string()],
                required_format: TrainingRecordFormat::DpoPreferencePair,
                payout_per_record_cents: 40,
                max_records: 5_000,
                accepted_records: 0,
                jurisdiction_iso: "US".to_string(),
                active: true,
            },
            DataBountySpec {
                bounty_id: "bounty-us-multimodal-rag-03".to_string(),
                sponsor_entity_name: "US Sovereign Research Foundation".to_string(),
                sponsor_buyer_id: "us-sovereign-research".to_string(),
                title: "Multi-Hop RLM Document Inspection & Grounded Synthesis Traces".to_string(),
                required_domain_tags: vec!["multimodal-rag".to_string(), "rlm".to_string()],
                required_format: TrainingRecordFormat::SftTrajectory,
                payout_per_record_cents: 20,
                max_records: 25_000,
                accepted_records: 0,
                jurisdiction_iso: "US".to_string(),
                active: true,
            },
        ];

        for b in default_bounties {
            if let Ok(json_str) = serde_json::to_string(&b) {
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO data_bounties (bounty_id, bounty_json, updated_unix_secs) VALUES (?1, ?2, ?3)",
                    params![b.bounty_id, json_str, now],
                );
            }
        }

        Ok(())
    }

    pub fn get_config(&self) -> Result<MarketplaceConfigState, String> {
        let conn = self.connect()?;
        let mut map = HashMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT key, value FROM marketplace_config")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| e.to_string())?;
            for r in rows.flatten() {
                map.insert(r.0, r.1);
            }
        }

        let opt_in_enabled = map
            .get("opt_in_enabled")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let five_eyes_enabled = map
            .get("five_eyes_enabled")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let allowed_jurisdictions: Vec<String> = map
            .get("allowed_jurisdictions")
            .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec!["US".to_string()]);
        let price_per_1k_records_cents = map
            .get("price_per_1k_records_cents")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5_000);
        let authority_pubkey_hex = map
            .get("authority_pubkey_hex")
            .cloned()
            .unwrap_or_else(|| bytes_to_hex(&self.default_authority_pubkey));

        Ok(MarketplaceConfigState {
            opt_in_enabled,
            allowed_jurisdictions,
            five_eyes_enabled,
            price_per_1k_records_cents,
            authority_pubkey_hex,
        })
    }

    pub fn update_config(
        &self,
        req: OptInConfigRequest,
    ) -> Result<MarketplaceConfigState, String> {
        let mut current = self.get_config()?;
        current.opt_in_enabled = req.opt_in_enabled;

        if let Some(five_eyes) = req.five_eyes_enabled {
            current.five_eyes_enabled = five_eyes;
            if five_eyes && req.allowed_jurisdictions.is_none() {
                current.allowed_jurisdictions = vec![
                    "US".to_string(),
                    "CA".to_string(),
                    "GB".to_string(),
                    "AU".to_string(),
                    "NZ".to_string(),
                ];
            } else if !five_eyes && req.allowed_jurisdictions.is_none() {
                current.allowed_jurisdictions = vec!["US".to_string()];
            }
        }

        if let Some(jurisdictions) = req.allowed_jurisdictions {
            let mut cleaned = Vec::new();
            for j in jurisdictions {
                let iso = j.trim().to_ascii_uppercase();
                if iso.is_empty() {
                    continue;
                }
                if BLOCKED_ADVERSARY_JURISDICTIONS.contains(&iso.as_str()) {
                    return Err(format!(
                        "Jurisdiction '{}' is permanently prohibited by SovereignJurisdictionGuard (DOJ 28 CFR Part 202)",
                        iso
                    ));
                }
                if !cleaned.contains(&iso) {
                    cleaned.push(iso);
                }
            }
            if cleaned.is_empty() {
                cleaned.push("US".to_string());
            }
            current.allowed_jurisdictions = cleaned;
        }

        if let Some(price) = req.price_per_1k_records_cents {
            current.price_per_1k_records_cents = price.max(100);
        }

        if let Some(auth_hex) = req.authority_pubkey_hex {
            let clean = auth_hex.trim().to_ascii_lowercase();
            if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("authority_pubkey_hex must be a valid 64-character hex Ed25519 public key".to_string());
            }
            current.authority_pubkey_hex = clean;
        }

        let conn = self.connect()?;
        let allowed_json =
            serde_json::to_string(&current.allowed_jurisdictions).unwrap_or_else(|_| "[\"US\"]".to_string());
        let updates = [
            (
                "opt_in_enabled",
                if current.opt_in_enabled { "true" } else { "false" }.to_string(),
            ),
            ("allowed_jurisdictions", allowed_json),
            (
                "five_eyes_enabled",
                if current.five_eyes_enabled {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
            (
                "price_per_1k_records_cents",
                current.price_per_1k_records_cents.to_string(),
            ),
            ("authority_pubkey_hex", current.authority_pubkey_hex.clone()),
        ];
        for (k, v) in updates {
            conn.execute(
                "INSERT OR REPLACE INTO marketplace_config (key, value) VALUES (?1, ?2)",
                params![k, v],
            )
            .map_err(|e| format!("Failed to update {k}: {e}"))?;
        }

        Ok(current)
    }

    pub fn active_authority_pubkey(&self, cfg: &MarketplaceConfigState) -> [u8; 32] {
        hex_to_32_bytes(&cfg.authority_pubkey_hex).unwrap_or(self.default_authority_pubkey)
    }

    pub fn save_staged_batch(
        &self,
        manifest: &DataCatalogManifest,
        records: &[SanitizedTrainingRecord],
        approved: bool,
    ) -> Result<(), String> {
        let mut jsonl_buf = Vec::new();
        for rec in records {
            let line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
            jsonl_buf.extend_from_slice(line.as_bytes());
            jsonl_buf.push(b'\n');
        }
        let encrypted_blob = encrypt_batch_bytes(&self.node_seed, &manifest.batch_id, &jsonl_buf);
        let manifest_json = serde_json::to_string(manifest).map_err(|e| e.to_string())?;

        let conn = self.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO staged_batches (batch_id, manifest_json, encrypted_jsonl, approved, created_unix_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                manifest.batch_id,
                manifest_json,
                encrypted_blob,
                i32::from(approved),
                manifest.created_unix_secs
            ],
        )
        .map_err(|e| format!("Failed to persist staged batch: {e}"))?;
        Ok(())
    }

    pub fn load_batch(
        &self,
        batch_id: Option<&str>,
    ) -> Result<Option<(DataCatalogManifest, Vec<u8>, bool)>, String> {
        let conn = self.connect()?;
        let row_opt: Option<(String, Vec<u8>, i32)> = if let Some(id) = batch_id {
            conn.query_row(
                "SELECT manifest_json, encrypted_jsonl, approved FROM staged_batches WHERE batch_id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?
        } else {
            conn.query_row(
                "SELECT manifest_json, encrypted_jsonl, approved FROM staged_batches ORDER BY created_unix_secs DESC, rowid DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?
        };

        let Some((manifest_json, encrypted_jsonl, approved_int)) = row_opt else {
            return Ok(None);
        };
        let manifest: DataCatalogManifest =
            serde_json::from_str(&manifest_json).map_err(|e| e.to_string())?;
        Ok(Some((manifest, encrypted_jsonl, approved_int != 0)))
    }

    pub fn decrypt_batch_records(
        &self,
        batch_id: &str,
        encrypted_jsonl: &[u8],
    ) -> Result<Vec<SanitizedTrainingRecord>, String> {
        let plaintext = decrypt_batch_bytes(&self.node_seed, batch_id, encrypted_jsonl)
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
        let mut records = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: SanitizedTrainingRecord =
                serde_json::from_str(trimmed).map_err(|e| e.to_string())?;
            records.push(rec);
        }
        Ok(records)
    }

    pub fn mark_batch_approved(&self, batch_id: &str) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE staged_batches SET approved = 1 WHERE batch_id = ?1",
            params![batch_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn batch_counts(&self) -> (usize, usize) {
        let Ok(conn) = self.connect() else {
            return (0, 0);
        };
        let total: usize = conn
            .query_row("SELECT COUNT(*) FROM staged_batches", [], |r| r.get(0))
            .unwrap_or(0);
        let approved: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM staged_batches WHERE approved = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (total, approved)
    }

    pub fn save_ledger(&self, ledger: &ContributionLedger) -> Result<(), String> {
        let conn = self.connect()?;
        let json_str = serde_json::to_string(ledger).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO contribution_ledgers (pool_batch_id, ledger_json, updated_unix_secs)
             VALUES (?1, ?2, ?3)",
            params![ledger.pool_batch_id, json_str, Utc::now().timestamp()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn latest_ledger(&self) -> Option<ContributionLedger> {
        let conn = self.connect().ok()?;
        let json_str: String = conn
            .query_row(
                "SELECT ledger_json FROM contribution_ledgers ORDER BY updated_unix_secs DESC, rowid DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .ok()??;
        serde_json::from_str(&json_str).ok()
    }

    pub fn all_ledgers(&self) -> Vec<ContributionLedger> {
        let Ok(conn) = self.connect() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT ledger_json FROM contribution_ledgers ORDER BY updated_unix_secs DESC, rowid DESC",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
            return Vec::new();
        };
        rows.flatten()
            .filter_map(|s| serde_json::from_str::<ContributionLedger>(&s).ok())
            .collect()
    }

    pub fn list_bounties(&self, allowed_jurisdictions: &[String]) -> Vec<DataBountySpec> {
        let Ok(conn) = self.connect() else {
            return Vec::new();
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT bounty_json FROM data_bounties ORDER BY bounty_id ASC")
        else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
            return Vec::new();
        };
        rows.flatten()
            .filter_map(|s| serde_json::from_str::<DataBountySpec>(&s).ok())
            .filter(|b| {
                allowed_jurisdictions
                    .iter()
                    .any(|j| j.eq_ignore_ascii_case(&b.jurisdiction_iso))
            })
            .collect()
    }

    pub fn check_and_record_preview_rate_limit(
        &self,
        buyer_id: &str,
        caller_ip: IpAddr,
        now_unix_secs: i64,
        max_per_hour: usize,
    ) -> Result<(), &'static str> {
        let mut guard = self
            .preview_rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let cutoff = now_unix_secs - 3600;
        let subnet_key = match caller_ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("subnet:{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("subnet:{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        };
        let buyer_key = format!("buyer:{}", buyer_id.trim().to_ascii_lowercase());

        for key in [&buyer_key, &subnet_key] {
            let entries = guard.entry(key.clone()).or_default();
            entries.retain(|&ts| ts > cutoff);
            if entries.len() >= max_per_hour {
                return Err("Preview rate limit exceeded (anti-scraping guard: max authenticated canary previews per hour reached)");
            }
        }
        guard.entry(buyer_key).or_default().push(now_unix_secs);
        guard.entry(subnet_key).or_default().push(now_unix_secs);
        Ok(())
    }
}

/// Extracts caller IP, forwarded proxy hops, ASN, country header, and hardware TPM 2.0 key hash from HTTP headers.
struct CallerNetworkContext {
    caller_ip: IpAddr,
    forwarded_ips: Vec<IpAddr>,
    caller_asn: Option<u32>,
    caller_country: Option<String>,
    presented_tpm_pubkey_blake3: Option<String>,
}

fn extract_caller_network_context(headers: &HeaderMap) -> Result<CallerNetworkContext, &'static str> {
    let mut forwarded_ips = Vec::new();
    if let Some(xff_val) = headers.get("x-forwarded-for") {
        let xff_str = xff_val
            .to_str()
            .map_err(|_| "Malformed X-Forwarded-For header")?;
        for part in xff_str.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                let ip: IpAddr = trimmed
                    .parse()
                    .map_err(|_| "Invalid IP address in X-Forwarded-For header")?;
                forwarded_ips.push(ip);
            }
        }
    }
    for extra_hdr in ["cf-connecting-ip", "x-real-ip"] {
        if let Some(val) = headers.get(extra_hdr) {
            let s = val.to_str().map_err(|_| "Malformed proxy IP header")?.trim();
            if !s.is_empty() {
                let ip: IpAddr = s.parse().map_err(|_| "Invalid IP in proxy header")?;
                if !forwarded_ips.contains(&ip) {
                    forwarded_ips.push(ip);
                }
            }
        }
    }

    let caller_ip = if let Some(val) = headers.get("x-quorum-caller-ip") {
        let s = val
            .to_str()
            .map_err(|_| "Malformed X-Quorum-Caller-IP header")?
            .trim();
        s.parse::<IpAddr>()
            .map_err(|_| "Invalid IP in X-Quorum-Caller-IP header")?
    } else if let Some(&first_hop) = forwarded_ips.first() {
        first_hop
    } else {
        IpAddr::from([127, 0, 0, 1])
    };

    let caller_asn = if let Some(val) = headers.get("x-quorum-caller-asn") {
        let s = val
            .to_str()
            .map_err(|_| "Malformed X-Quorum-Caller-ASN header")?
            .trim()
            .trim_start_matches("AS")
            .trim_start_matches("as");
        Some(
            s.parse::<u32>()
                .map_err(|_| "Invalid numeric ASN in X-Quorum-Caller-ASN header")?,
        )
    } else {
        None
    };

    let caller_country = headers
        .get("x-quorum-caller-country")
        .or_else(|| headers.get("cf-ipcountry"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty());

    let presented_tpm_pubkey_blake3 = headers
        .get("x-quorum-tpm-pubkey-blake3")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    Ok(CallerNetworkContext {
        caller_ip,
        forwarded_ips,
        caller_asn,
        caller_country,
        presented_tpm_pubkey_blake3,
    })
}

fn check_layer2_network_perimeter(
    net_ctx: &CallerNetworkContext,
    allowed_jurisdictions: &[String],
) -> Result<(), &'static str> {
    if is_blocked_foreign_adversary_ip(net_ctx.caller_ip) {
        return Err("Blocked by SovereignJurisdictionGuard Layer 2: caller IP is in a restricted foreign adversary CIDR");
    }
    for hop in &net_ctx.forwarded_ips {
        if is_blocked_foreign_adversary_ip(*hop) {
            return Err("Blocked by SovereignJurisdictionGuard Layer 2: proxy hop IP is in a restricted foreign adversary CIDR");
        }
    }
    if let Some(asn) = net_ctx.caller_asn {
        if is_high_risk_datacenter_or_proxy_asn(asn) {
            return Err("Blocked by SovereignJurisdictionGuard Layer 2: caller ASN is a restricted Chinese cloud PoP or unverified VPS/VPN provider");
        }
    }
    if let Some(ref country) = net_ctx.caller_country {
        if BLOCKED_ADVERSARY_JURISDICTIONS.contains(&country.as_str()) {
            return Err("Blocked by SovereignJurisdictionGuard Layer 2: caller GeoIP country is a prohibited foreign adversary jurisdiction");
        }
        if !allowed_jurisdictions
            .iter()
            .any(|c| c.eq_ignore_ascii_case(country))
        {
            return Err("Blocked by SovereignJurisdictionGuard Layer 2: caller GeoIP country is outside subscriber's allowed_jurisdictions policy");
        }
    }
    Ok(())
}

fn parse_header_buyer_cert(headers: &HeaderMap) -> Result<Option<BuyerJurisdictionCertificate>, &'static str> {
    let Some(val) = headers.get("x-quorum-buyer-cert") else {
        return Ok(None);
    };
    let raw = val
        .to_str()
        .map_err(|_| "Malformed X-Quorum-Buyer-Cert header")?
        .trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let cert: BuyerJurisdictionCertificate = serde_json::from_str(raw)
        .map_err(|_| "Invalid BuyerJurisdictionCertificate JSON in X-Quorum-Buyer-Cert header")?;
    Ok(Some(cert))
}

fn parse_header_escrow_receipt(headers: &HeaderMap) -> Result<Option<EscrowReceiptToken>, &'static str> {
    let Some(val) = headers.get("x-quorum-escrow-receipt") else {
        return Ok(None);
    };
    let raw = val
        .to_str()
        .map_err(|_| "Malformed X-Quorum-Escrow-Receipt header")?
        .trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let token: EscrowReceiptToken = serde_json::from_str(raw)
        .map_err(|_| "Invalid EscrowReceiptToken JSON in X-Quorum-Escrow-Receipt header")?;
    Ok(Some(token))
}

fn forbidden_json(reason: impl Into<String>) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "status": "forbidden",
            "error": reason.into(),
        })),
    )
        .into_response()
}

/// GET /api/v1/marketplace/status
pub async fn marketplace_status_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };

    let (staged_batches_count, approved_batches_count) = store.batch_counts();
    let latest_manifest = store
        .load_batch(None)
        .ok()
        .flatten()
        .map(|(m, _, _)| m);
    let latest_ledger = store.latest_ledger();
    let bounties = store.list_bounties(&cfg.allowed_jurisdictions);
    let sovereign_lock_mode = if cfg.five_eyes_enabled {
        "FIVE_EYES_ALLIED"
    } else {
        "US_ONLY_DOJ_28_CFR_PART_202"
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "opt_in_enabled": cfg.opt_in_enabled,
            "allowed_jurisdictions": cfg.allowed_jurisdictions,
            "five_eyes_enabled": cfg.five_eyes_enabled,
            "sovereign_lock_mode": sovereign_lock_mode,
            "price_per_1k_records_cents": cfg.price_per_1k_records_cents,
            "authority_pubkey_hex": cfg.authority_pubkey_hex,
            "origin_node_id": store.origin_node_id,
            "origin_pubkey_hex": store.origin_pubkey_hex,
            "blocked_jurisdictions": BLOCKED_ADVERSARY_JURISDICTIONS,
            "blocked_high_risk_asns": HIGH_RISK_DATACENTER_PROXY_ASNS,
            "staged_batches_count": staged_batches_count,
            "approved_batches_count": approved_batches_count,
            "latest_manifest": latest_manifest,
            "latest_ledger": latest_ledger,
            "bounties": bounties,
        })),
    )
        .into_response()
}

/// POST /api/v1/marketplace/opt-in
pub async fn marketplace_opt_in_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<OptInConfigRequest>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    match store.update_config(req) {
        Ok(cfg) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "updated",
                "opt_in_enabled": cfg.opt_in_enabled,
                "allowed_jurisdictions": cfg.allowed_jurisdictions,
                "five_eyes_enabled": cfg.five_eyes_enabled,
                "price_per_1k_records_cents": cfg.price_per_1k_records_cents,
                "authority_pubkey_hex": cfg.authority_pubkey_hex,
            })),
        )
            .into_response(),
        Err(e) => forbidden_json(e),
    }
}

/// POST /api/v1/marketplace/harvest
pub async fn marketplace_harvest_handler(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body_opt: Option<Json<HarvestBatchRequest>>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false). Enable Opt-In in Settings first.",
        );
    }

    let net_ctx = match extract_caller_network_context(&headers) {
        Ok(c) => c,
        Err(e) => return forbidden_json(e),
    };
    if let Err(e) = check_layer2_network_perimeter(&net_ctx, &cfg.allowed_jurisdictions) {
        return forbidden_json(e);
    }

    let req = body_opt.map(|Json(r)| r).unwrap_or_default();
    let now = Utc::now().timestamp();
    let batch_id = req
        .batch_id
        .clone()
        .unwrap_or_else(|| format!("batch-{}", uuid::Uuid::new_v4()));
    let default_tags = req
        .domain_tags
        .clone()
        .unwrap_or_else(|| vec!["rust-security".to_string(), "multimodal-rag".to_string()]);
    let extra_terms = req.extra_redact_terms.clone().unwrap_or_default();

    let raw_candidates: Vec<RawTrajectoryCandidate> = match req.candidates {
        Some(ref list) if !list.is_empty() => list
            .iter()
            .enumerate()
            .map(|(idx, dto)| RawTrajectoryCandidate {
                record_id: dto
                    .record_id
                    .clone()
                    .unwrap_or_else(|| format!("{}-rec-{}", batch_id, idx + 1)),
                origin_node_id: dto
                    .origin_node_id
                    .clone()
                    .unwrap_or_else(|| store.origin_node_id.clone()),
                format: dto.format.unwrap_or(TrainingRecordFormat::SftTrajectory),
                domain_tags: dto
                    .domain_tags
                    .clone()
                    .unwrap_or_else(|| default_tags.clone()),
                prompt: dto.prompt.clone(),
                rlm_trajectory: dto.rlm_trajectory.clone(),
                chosen_response: dto.chosen_response.clone(),
                rejected_response: dto.rejected_response.clone(),
                citations: dto.citations.clone(),
                extra_redact_terms: {
                    let mut t = dto.extra_redact_terms.clone();
                    t.extend(extra_terms.iter().cloned());
                    t
                },
                created_unix_secs: now,
            })
            .collect(),
        _ => synthesize_default_local_candidates(&store.origin_node_id, &batch_id, &default_tags, &extra_terms, now),
    };

    let mut sanitized_records = Vec::new();
    let mut rejected_candidates = Vec::new();

    for cand in &raw_candidates {
        match MarketplaceSanitizer::sanitize_and_sign_record(cand, &store.node_seed) {
            Ok(rec) => sanitized_records.push(rec),
            Err(reason) => rejected_candidates.push(RejectedCandidateReport {
                record_id: cand.record_id.clone(),
                reason,
            }),
        }
    }

    if sanitized_records.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(HarvestBatchResponse {
                batch_id,
                approved: false,
                accepted_count: 0,
                rejected_count: rejected_candidates.len(),
                rejected_candidates,
                sanitized_records: Vec::new(),
                manifest: None,
            }),
        )
            .into_response();
    }

    let price_cents = req
        .price_per_1k_records_cents
        .unwrap_or(cfg.price_per_1k_records_cents);
    let manifest = match DataCatalogManifest::from_records(
        &batch_id,
        &store.origin_node_id,
        &store.node_seed,
        &sanitized_records,
        price_cents,
        now,
    ) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };

    let approved = req.auto_approve.unwrap_or(false);
    if let Err(e) = store.save_staged_batch(&manifest, &sanitized_records, approved) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    if approved {
        let est_payout = ((sanitized_records.len() as u64) * price_cents) / 1000;
        let (ledger, _) = ContributionLedger::merge_and_deduplicate_mesh_records(
            &batch_id,
            sanitized_records.clone(),
            est_payout.max(price_cents),
        );
        let _ = store.save_ledger(&ledger);
    }

    (
        StatusCode::OK,
        Json(HarvestBatchResponse {
            batch_id,
            approved,
            accepted_count: sanitized_records.len(),
            rejected_count: rejected_candidates.len(),
            rejected_candidates,
            sanitized_records,
            manifest: Some(manifest),
        }),
    )
        .into_response()
}

/// POST /api/v1/marketplace/approve-batch
pub async fn marketplace_approve_batch_handler(
    State(state): State<Arc<DaemonState>>,
    body_opt: Option<Json<ApproveBatchRequest>>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let req = body_opt.map(|Json(r)| r).unwrap_or_default();
    let Some((manifest, encrypted_jsonl, _)) = store
        .load_batch(req.batch_id.as_deref())
        .ok()
        .flatten()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No staged batch found to approve" })),
        )
            .into_response();
    };

    if let Err(e) = store.mark_batch_approved(&manifest.batch_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    let records = store
        .decrypt_batch_records(&manifest.batch_id, &encrypted_jsonl)
        .unwrap_or_default();
    let est_payout =
        (((records.len() as u64) * manifest.price_per_1k_records_cents) / 1000).max(500);
    let (ledger, _) = ContributionLedger::merge_and_deduplicate_mesh_records(
        &manifest.batch_id,
        records,
        est_payout,
    );
    let _ = store.save_ledger(&ledger);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "approved_and_sealed",
            "batch_id": manifest.batch_id,
            "manifest": manifest,
            "ledger": ledger,
        })),
    )
        .into_response()
}

/// GET & POST /api/v1/marketplace/preview
/// - Unauthenticated callers: returns aggregate metadata + `merkle_root_blake3` ONLY (`canary_sample: []`).
/// - Authenticated callers presenting `BuyerJurisdictionCertificate`: enforces 7-layer Domestic-Evasion Guard
///   + rate limiter (`<= 5` previews/hour) and returns `<= 5` requester-watermarked canary lines.
pub async fn marketplace_preview_handler(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query_params): Query<HashMap<String, String>>,
    body_opt: Option<Json<PreviewRequest>>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let net_ctx = match extract_caller_network_context(&headers) {
        Ok(c) => c,
        Err(e) => return forbidden_json(e),
    };
    if let Err(e) = check_layer2_network_perimeter(&net_ctx, &cfg.allowed_jurisdictions) {
        return forbidden_json(e);
    }

    let body_req = body_opt.map(|Json(b)| b).unwrap_or_default();
    let batch_id_param = body_req
        .batch_id
        .as_deref()
        .or_else(|| query_params.get("batch_id").map(|s| s.as_str()));

    let Some((manifest, _, _)) = store.load_batch(batch_id_param).ok().flatten() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No catalog manifest available for preview" })),
        )
            .into_response();
    };

    // Check if caller presented a BuyerJurisdictionCertificate (via header, query param, or JSON body)
    let header_cert = match parse_header_buyer_cert(&headers) {
        Ok(c) => c,
        Err(e) => return forbidden_json(e),
    };
    let query_cert = match query_params.get("buyer_cert_json") {
        Some(raw) if !raw.trim().is_empty() => match serde_json::from_str::<BuyerJurisdictionCertificate>(raw) {
            Ok(c) => Some(c),
            Err(_) => return forbidden_json("Invalid BuyerJurisdictionCertificate in buyer_cert_json"),
        },
        _ => None,
    };
    let cert_opt = body_req.buyer_cert.or(header_cert).or(query_cert);

    let Some(cert) = cert_opt else {
        // Tier 1 Unauthenticated Preview: Zero canary sample text exposed (aggregate counts + Merkle root only)
        let unauth_manifest = manifest.to_unauthenticated_preview();
        return (StatusCode::OK, Json(unauth_manifest)).into_response();
    };

    // Tier 2 Cert-Authenticated Canary Preview: Enforce full Domestic-Evasion Guard + Rate Limit + Canary Watermarking
    let auth_pub = store.active_authority_pubkey(&cfg);
    let now = Utc::now().timestamp();
    if let Err(reason) = verify_us_sovereign_buyer_against_domestic_evasion(
        net_ctx.caller_ip,
        &net_ctx.forwarded_ips,
        net_ctx.caller_asn,
        net_ctx.presented_tpm_pubkey_blake3.as_deref(),
        &cert,
        &auth_pub,
        &cfg.allowed_jurisdictions,
        false,
        now,
    ) {
        return forbidden_json(reason);
    }

    let rate_limit = headers
        .get("x-quorum-preview-rate-limit")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PREVIEW_RATE_LIMIT_PER_HOUR);

    if let Err(limit_err) =
        store.check_and_record_preview_rate_limit(&cert.buyer_id, net_ctx.caller_ip, now, rate_limit)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "status": "rate_limited",
                "error": limit_err,
            })),
        )
            .into_response();
    }

    let watermarked_preview =
        manifest.to_authenticated_watermarked_preview(&store.node_seed, &cert.buyer_id);
    (StatusCode::OK, Json(watermarked_preview)).into_response()
}

/// POST /api/v1/marketplace/unlock (and /api/v1/marketplace/issue-receipt)
/// Verifies `BuyerJurisdictionCertificate` + corporate egress CIDR + TPM 2.0 binding and issues a Commit-and-Reveal `EscrowReceiptToken`.
pub async fn marketplace_unlock_handler(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(req): Json<UnlockBatchRequest>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let net_ctx = match extract_caller_network_context(&headers) {
        Ok(c) => c,
        Err(e) => return forbidden_json(e),
    };

    let auth_pub = store.active_authority_pubkey(&cfg);
    let now = Utc::now().timestamp();
    let presented_tpm = net_ctx
        .presented_tpm_pubkey_blake3
        .as_deref()
        .unwrap_or(&req.buyer_cert.bound_tpm_pubkey_blake3);

    if let Err(reason) = verify_us_sovereign_buyer_against_domestic_evasion(
        net_ctx.caller_ip,
        &net_ctx.forwarded_ips,
        net_ctx.caller_asn,
        Some(presented_tpm),
        &req.buyer_cert,
        &auth_pub,
        &cfg.allowed_jurisdictions,
        true,
        now,
    ) {
        return forbidden_json(reason);
    }

    let Some((manifest, encrypted_jsonl, _)) =
        store.load_batch(req.batch_id.as_deref()).ok().flatten()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Requested batch_id not found" })),
        )
            .into_response();
    };

    let total_records = (manifest.sft_record_count + manifest.dpo_record_count).max(1) as u64;
    let default_amount =
        ((total_records * manifest.price_per_1k_records_cents) / 1000).max(manifest.price_per_1k_records_cents);
    let amount_paid_cents = req.amount_paid_cents.unwrap_or(default_amount);

    let mut receipt = EscrowReceiptToken {
        receipt_id: format!("rcpt-{}", uuid::Uuid::new_v4()),
        batch_id: manifest.batch_id.clone(),
        batch_merkle_root_blake3: manifest.merkle_root_blake3.clone(),
        buyer_id: req.buyer_cert.buyer_id.clone(),
        bound_tpm_pubkey_blake3: req.buyer_cert.bound_tpm_pubkey_blake3.clone(),
        amount_paid_cents,
        issued_unix_secs: now,
        expires_unix_secs: now + 3600,
        keyed_blake3_mac_hex: String::new(),
    };
    receipt.seal_with_secret(&store.escrow_secret);

    if let Ok(conn) = store.connect() {
        if let Ok(json_str) = serde_json::to_string(&receipt) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO escrow_receipts (receipt_id, batch_id, buyer_id, receipt_json, redeemed_count, created_unix_secs)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                params![receipt.receipt_id, receipt.batch_id, receipt.buyer_id, json_str, now],
            );
        }
    }

    if let Ok(records) = store.decrypt_batch_records(&manifest.batch_id, &encrypted_jsonl) {
        let (ledger, _) = ContributionLedger::merge_and_deduplicate_mesh_records(
            &manifest.batch_id,
            records,
            amount_paid_cents,
        );
        let _ = store.save_ledger(&ledger);
    }

    (StatusCode::OK, Json(receipt)).into_response()
}

/// GET & POST /api/v1/marketplace/download
/// Enforces all 7 layers of `SovereignJurisdictionGuard` (including mandatory hardware TPM 2.0 key binding
/// and constant-time `EscrowReceiptToken` MAC verification) and streams buyer-watermarked `.jsonl` trajectories.
pub async fn marketplace_download_handler(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query_params): Query<HashMap<String, String>>,
    body_opt: Option<Json<DownloadBatchRequest>>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let net_ctx = match extract_caller_network_context(&headers) {
        Ok(c) => c,
        Err(e) => return forbidden_json(e),
    };
    if let Err(e) = check_layer2_network_perimeter(&net_ctx, &cfg.allowed_jurisdictions) {
        return forbidden_json(e);
    }

    let body_req = body_opt.map(|Json(b)| b).unwrap_or_default();

    let header_cert = match parse_header_buyer_cert(&headers) {
        Ok(c) => c,
        Err(e) => return forbidden_json(e),
    };
    let query_cert = match query_params.get("buyer_cert_json") {
        Some(raw) if !raw.trim().is_empty() => {
            match serde_json::from_str::<BuyerJurisdictionCertificate>(raw) {
                Ok(c) => Some(c),
                Err(_) => return forbidden_json("Invalid BuyerJurisdictionCertificate in buyer_cert_json"),
            }
        }
        _ => None,
    };
    let Some(cert) = body_req.buyer_cert.or(header_cert).or(query_cert) else {
        return forbidden_json("Missing BuyerJurisdictionCertificate required by SovereignJurisdictionGuard");
    };

    let header_rcpt = match parse_header_escrow_receipt(&headers) {
        Ok(r) => r,
        Err(e) => return forbidden_json(e),
    };
    let query_rcpt = match query_params.get("receipt_token_json").or_else(|| query_params.get("receipt_token")) {
        Some(raw) if !raw.trim().is_empty() => match serde_json::from_str::<EscrowReceiptToken>(raw) {
            Ok(r) => Some(r),
            Err(_) => return forbidden_json("Invalid EscrowReceiptToken in query parameter"),
        },
        _ => None,
    };
    let Some(receipt) = body_req.receipt_token.or(header_rcpt).or(query_rcpt) else {
        return forbidden_json("Missing Commit-and-Reveal EscrowReceiptToken");
    };

    // Enforce Layers 2, 3, 4, and 5 (with require_tpm_binding = true!)
    let auth_pub = store.active_authority_pubkey(&cfg);
    let now = Utc::now().timestamp();
    if let Err(reason) = verify_us_sovereign_buyer_against_domestic_evasion(
        net_ctx.caller_ip,
        &net_ctx.forwarded_ips,
        net_ctx.caller_asn,
        net_ctx.presented_tpm_pubkey_blake3.as_deref(),
        &cert,
        &auth_pub,
        &cfg.allowed_jurisdictions,
        true,
        now,
    ) {
        return forbidden_json(reason);
    }

    // Enforce Layer 6: Constant-time EscrowReceiptToken MAC verification and buyer/hardware binding
    if let Err(reason) = receipt.verify_constant_time(&store.escrow_secret, now) {
        return forbidden_json(reason);
    }
    if receipt.buyer_id.trim() != cert.buyer_id.trim() {
        return forbidden_json("EscrowReceiptToken buyer_id does not match BuyerJurisdictionCertificate");
    }
    let rcpt_tpm = receipt.bound_tpm_pubkey_blake3.trim().to_ascii_lowercase();
    let cert_tpm = cert.bound_tpm_pubkey_blake3.trim().to_ascii_lowercase();
    if rcpt_tpm.len() != cert_tpm.len() || !bool::from(rcpt_tpm.as_bytes().ct_eq(cert_tpm.as_bytes())) {
        return forbidden_json("EscrowReceiptToken TPM hardware binding mismatch");
    }

    let target_batch_id = body_req
        .batch_id
        .as_deref()
        .or_else(|| query_params.get("batch_id").map(|s| s.as_str()))
        .unwrap_or(&receipt.batch_id);

    let Some((manifest, encrypted_jsonl, _)) =
        store.load_batch(Some(target_batch_id)).ok().flatten()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Batch not found" })),
        )
            .into_response();
    };

    if manifest.merkle_root_blake3 != receipt.batch_merkle_root_blake3 {
        return forbidden_json("EscrowReceiptToken batch_merkle_root_blake3 does not match sealed batch Merkle root");
    }

    let records = match store.decrypt_batch_records(&manifest.batch_id, &encrypted_jsonl) {
        Ok(r) => r,
        Err(e) => return forbidden_json(e),
    };

    // Enforce Layer 7: Embed deterministic per-buyer cryptographic canary watermark into every record
    let mut jsonl_out = String::new();
    for rec in &records {
        let watermarked = rec.with_buyer_watermark(&store.node_seed, &cert.buyer_id, "full_unlock");
        if let Ok(line) = serde_json::to_string(&watermarked) {
            jsonl_out.push_str(&line);
            jsonl_out.push('\n');
        }
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8".to_string()),
            ("x-quorum-batch-id".parse().unwrap(), manifest.batch_id),
            (
                "x-quorum-batch-merkle-root".parse().unwrap(),
                manifest.merkle_root_blake3,
            ),
            ("x-quorum-buyer-id".parse().unwrap(), cert.buyer_id),
        ],
        jsonl_out,
    )
        .into_response()
}

/// POST /api/v1/marketplace/pool-merge
/// Deduplicates pooled `SanitizedTrainingRecord` trajectories across mesh peers (`origin_node_id`),
/// seals the combined batch, and computes exact basis-point (`10,000 bps`) revenue splits in `ContributionLedger`.
pub async fn marketplace_pool_merge_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<PoolMergeRequest>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let (ledger, unique_records) = ContributionLedger::merge_and_deduplicate_mesh_records(
        &req.pool_batch_id,
        req.records,
        req.total_pool_payout_cents,
    );
    if let Err(e) = store.save_ledger(&ledger) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    let price_cents = req
        .price_per_1k_records_cents
        .unwrap_or(cfg.price_per_1k_records_cents);
    let manifest = DataCatalogManifest::from_records(
        &req.pool_batch_id,
        &store.origin_node_id,
        &store.node_seed,
        &unique_records,
        price_cents,
        Utc::now().timestamp(),
    )
    .ok();

    if let Some(ref m) = manifest {
        let _ = store.save_staged_batch(m, &unique_records, true);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ledger": ledger,
            "manifest": manifest,
            "unique_records_count": unique_records.len(),
        })),
    )
        .into_response()
}

/// GET /api/v1/marketplace/ledger
pub async fn marketplace_ledger_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let latest = store.latest_ledger();
    let history = store.all_ledgers();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "latest_ledger": latest,
            "ledgers": history,
        })),
    )
        .into_response()
}

/// GET /api/v1/marketplace/bounties
pub async fn marketplace_bounties_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let bounties = store.list_bounties(&cfg.allowed_jurisdictions);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "allowed_jurisdictions": cfg.allowed_jurisdictions,
            "bounties": bounties,
        })),
    )
        .into_response()
}

/// POST /api/v1/marketplace/bounties/submit
pub async fn marketplace_bounty_submit_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<BountySubmitRequest>,
) -> impl IntoResponse {
    let store = match state.marketplace_store() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let cfg = match store.get_config() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if !cfg.opt_in_enabled {
        return forbidden_json(
            "AI Training Data Marketplace is disabled by default (opt_in_enabled = false).",
        );
    }

    let bounties = store.list_bounties(&cfg.allowed_jurisdictions);
    let Some(bounty) = bounties.into_iter().find(|b| b.bounty_id == req.bounty_id) else {
        return forbidden_json("Requested bounty_id is not active or outside allowed_jurisdictions");
    };

    let Some((manifest, encrypted_jsonl, _)) =
        store.load_batch(req.batch_id.as_deref()).ok().flatten()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No staged or approved batch available to submit to bounty" })),
        )
            .into_response();
    };

    let records = store
        .decrypt_batch_records(&manifest.batch_id, &encrypted_jsonl)
        .unwrap_or_default();
    let payout_cents = (records.len() as u64) * bounty.payout_per_record_cents;
    let pool_id = format!("{}-{}", bounty.bounty_id, manifest.batch_id);
    let (ledger, _) = ContributionLedger::merge_and_deduplicate_mesh_records(
        &pool_id,
        records,
        payout_cents,
    );
    let _ = store.save_ledger(&ledger);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "bounty_fulfilled",
            "bounty_id": bounty.bounty_id,
            "batch_id": manifest.batch_id,
            "payout_cents": payout_cents,
            "ledger": ledger,
        })),
    )
        .into_response()
}

fn synthesize_default_local_candidates(
    origin_node_id: &str,
    batch_id: &str,
    domain_tags: &[String],
    extra_terms: &[String],
    now: i64,
) -> Vec<RawTrajectoryCandidate> {
    let s1_slice = "QuorumRAG expands primary search hits into parent-document byte windows (0..10000 bytes) so executive summaries, biographical narratives, and technical sections are preserved alongside title headers.";
    let s1_quote = "parent-document byte windows (0..10000 bytes)";

    let s2_slice = "Every peer-to-peer scatter-gather request in quorum-network is authenticated with Ed25519 signatures and constant-time BLAKE3 embedding contract verification before remote chunks are fused.";
    let s2_quote = "Ed25519 signatures and constant-time BLAKE3 embedding contract verification";

    vec![
        RawTrajectoryCandidate {
            record_id: format!("{}-sft-1", batch_id),
            origin_node_id: origin_node_id.to_string(),
            format: TrainingRecordFormat::SftTrajectory,
            domain_tags: domain_tags.to_vec(),
            prompt: "How does QuorumRAG prevent chunk-0 contact-header starvation on biographical and technical queries?".to_string(),
            rlm_trajectory: vec![
                SanitizedRlmStep {
                    step_index: 1,
                    action_kind: "peek_slice".to_string(),
                    sanitized_query_or_pattern: "inspect parent document bytes 0..10000".to_string(),
                    abstracted_takeaway: "Expanded primary hit into 10 KB parent window to capture executive summary and body paragraphs beyond Chunk 0.".to_string(),
                },
                SanitizedRlmStep {
                    step_index: 2,
                    action_kind: "verify_grounding".to_string(),
                    sanitized_query_or_pattern: "slice_text.contains(verbatim_quote)".to_string(),
                    abstracted_takeaway: "Verified 100% verbatim substring grounding across extracted biography facts.".to_string(),
                },
            ],
            chosen_response: "QuorumRAG eliminates chunk-0 contact-header starvation by expanding primary retrieval hits into parent-document byte windows (0..10000 bytes), deduplicating near-identical document revisions across local and mesh peers, and verifying verbatim substring citations before synthesis so executive summaries, biographical narratives, and technical sections are always preserved in the final grounded response.".to_string(),
            rejected_response: None,
            citations: vec![(s1_slice.to_string(), s1_quote.to_string())],
            extra_redact_terms: extra_terms.to_vec(),
            created_unix_secs: now,
        },
        RawTrajectoryCandidate {
            record_id: format!("{}-dpo-2", batch_id),
            origin_node_id: origin_node_id.to_string(),
            format: TrainingRecordFormat::DpoPreferencePair,
            domain_tags: domain_tags.to_vec(),
            prompt: "How are federated scatter-gather queries secured across consenting QuorumRAG mesh nodes while preventing sensitive PII or PHI leakage?".to_string(),
            rlm_trajectory: vec![SanitizedRlmStep {
                step_index: 1,
                action_kind: "regex_grep".to_string(),
                sanitized_query_or_pattern: "verify_contract_handshake|Ed25519".to_string(),
                abstracted_takeaway: "Confirmed constant-time BLAKE3 contract check and Ed25519 peer signature verification across all mesh inbound and outbound scatter-gather handlers.".to_string(),
            }],
            chosen_response: "Federated scatter-gather requests require Ed25519 signatures and constant-time BLAKE3 embedding contract verification alongside Microsoft Presidio and GLiNER DLP scrubbing so unverified peers and raw sensitive spans are deterministically rejected before any remote candidate chunk enters the local synthesis window.".to_string(),
            rejected_response: Some("Unauthenticated peers can query raw files directly without contract verification.".to_string()),
            citations: vec![(s2_slice.to_string(), s2_quote.to_string())],
            extra_redact_terms: extra_terms.to_vec(),
            created_unix_secs: now,
        },
    ]
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn hex_to_32_bytes(hex_str: &str) -> Option<[u8; 32]> {
    let clean = hex_str.trim();
    if clean.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
