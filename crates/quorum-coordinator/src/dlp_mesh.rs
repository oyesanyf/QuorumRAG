//! OshoosiClaw-Adapted P2P Mesh Governance, Shared Folder Access Control,
//! and Two-Tier HIPAA PHI / PII Data Loss Prevention (DLP) Gate.
//!
//! Enforces two absolute security invariants across all Mesh nodes:
//! 1. **Explicit Folder Sharing Control**: Local files and chunks are NEVER shared with remote
//!    Mesh peers unless their parent directory is explicitly enabled in the user's `shared_folders` list.
//! 2. **Zero-PHI Leakage Between Nodes (Block or Redact)**: Every outbound and inbound Mesh chunk
//!    or query is inspected for Protected Health Information (HIPAA 18 identifiers), PII, Financial/Tax
//!    data, and Crown-Jewel secrets, and is deterministically **Blocked** or **Redacted** before leaving
//!    or entering the node.

use chrono::Utc;
use quorum_types::{CandidateChunkDto, VolatileRemoteChunk};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use subtle::ConstantTimeEq;

/// DLP enforcement action when PHI/PII is detected in a chunk or query crossing a Mesh boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DlpEnforcementMode {
    /// Scrub all detected PHI/PII spans in-place with `[REDACTED:PHI_<CATEGORY>]` before sharing.
    #[default]
    Redact,
    /// Completely drop/block any chunk or message containing PHI/PII from being shared across the Mesh.
    Block,
}

impl DlpEnforcementMode {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "block" | "strict_lockdown" | "quarantine" | "zero_leakage" => Self::Block,
            _ => Self::Redact,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Redact => "Redact",
            Self::Block => "Block",
        }
    }
}

/// Configurable HIPAA PHI / PII / Crown-Jewel protection policy for Mesh node communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDlpPolicy {
    /// Whether the Mesh DLP gate is active (always true by default; fail-closed).
    pub enabled: bool,
    /// Action taken when PHI/PII is detected (`Redact` or `Block`).
    pub mode: DlpEnforcementMode,
    /// Scrub/block US Social Security Numbers (`XXX-XX-XXXX`).
    pub protect_ssn: bool,
    /// Scrub/block Medical Record Numbers (`MRN`), ICD-10, CPT, Rx/Pharmacy, Hospital/Clinical notes.
    pub protect_medical_records: bool,
    /// Scrub/block Health Plan Beneficiary IDs, Medicare/Medicaid IDs, and NPI numbers.
    pub protect_health_plan: bool,
    /// Scrub/block Dates of Birth (`DOB`), admission/discharge dates.
    pub protect_dob_dates: bool,
    /// Scrub/block Academic/Student IDs and federal loan deferment identifiers.
    pub protect_academic_student_id: bool,
    /// Scrub/block Email addresses, Phone numbers, Fax numbers, and street addresses.
    pub protect_contact_pii: bool,
    /// Scrub/block Luhn-validated Credit Cards, Bank Account/Routing numbers, and IRS Tax/W-2/1040 data.
    pub protect_financial_tax: bool,
    /// Scrub/block API keys, AWS/GitHub tokens, PEM private keys, and Crown Jewel secrets.
    pub protect_secrets_crown_jewels: bool,
    /// Also scrub/block PHI/PII in outbound search queries before broadcasting to remote Mesh peers.
    pub scrub_outbound_queries: bool,
}

impl Default for MeshDlpPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: DlpEnforcementMode::Redact,
            protect_ssn: true,
            protect_medical_records: true,
            protect_health_plan: true,
            protect_dob_dates: true,
            protect_academic_student_id: true,
            protect_contact_pii: true,
            protect_financial_tax: true,
            protect_secrets_crown_jewels: true,
            scrub_outbound_queries: true,
        }
    }
}

/// A single detected PHI/PII span inside inspected text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPhiSpan {
    pub category: String,
    pub start: usize,
    pub end: usize,
    pub replacement: String,
    pub confidence: f32,
}

/// Result of inspecting and enforcing DLP on a text payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpInspectionResult {
    pub allowed_to_share: bool,
    pub action_taken: String,
    pub scrubbed_text: String,
    pub detected_categories: Vec<String>,
    pub detected_spans: Vec<DetectedPhiSpan>,
    pub redacted_span_count: usize,
    pub sensitivity_phi_score: f64,
    pub zk_commitment_hex: String,
}

/// Audit log record for a Mesh DLP inspection/interception event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpAuditEvent {
    pub id: String,
    pub timestamp: String,
    pub direction: String,
    pub peer_id: String,
    pub file_path: String,
    pub action_taken: String,
    pub mode: String,
    pub detected_categories: Vec<String>,
    pub redacted_span_count: usize,
    pub zk_commitment_hex: String,
    pub scrubbed_preview: String,
}

/// A folder explicitly configured by the user for Mesh sharing (or paused).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFolderEntry {
    pub path: String,
    pub label: String,
    pub enabled: bool,
    pub access_tier: u8,
    pub dlp_mode_override: Option<DlpEnforcementMode>,
    pub shared_at: String,
}

/// OshoosiClaw-adapted P2P Mesh & Shared Folders configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsoosiMeshSettings {
    pub p2p_enabled: bool,
    pub node_alias: String,
    pub zone: String,
    pub mesh_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub duckdns_domain: Option<String>,
    pub auto_bootstrap_duckdns: bool,
    pub hmac_epoch: u64,
    pub join_gate_mode: String,
    pub require_explicit_folder_share: bool,
    pub shared_folders: Vec<SharedFolderEntry>,
    pub quarantined_peers: Vec<String>,
    pub trusted_peers: Vec<String>,
    #[serde(default = "default_8")]
    pub max_peer_responses: usize,
}

fn default_8() -> usize {
    8
}

impl Default for OsoosiMeshSettings {
    fn default() -> Self {
        Self {
            p2p_enabled: true,
            node_alias: "QuorumRAG-Master-Core".to_string(),
            zone: "quorum-lan-mesh".to_string(),
            mesh_port: 3032,
            bootstrap_peers: Vec::new(),
            duckdns_domain: Some("oshoosi".to_string()),
            auto_bootstrap_duckdns: true,
            hmac_epoch: 1,
            join_gate_mode: "MutualContractAndHmac".to_string(),
            require_explicit_folder_share: true,
            shared_folders: vec![SharedFolderEntry {
                path: r"D:\harfile\QuorumRAG\docs".to_string(),
                label: "QuorumRAG Documentation".to_string(),
                enabled: true,
                access_tier: 0,
                dlp_mode_override: None,
                shared_at: Utc::now().to_rfc3339(),
            }],
            quarantined_peers: Vec::new(),
            trusted_peers: Vec::new(),
            max_peer_responses: 8,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_4096() -> usize {
    4096
}

/// Type alias for ChatGPT UI preferences configuration.
pub type UiPreferencesConfig = ChatGptUiSettings;

/// Personal & Application Settings persisted in `settings.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatGptUiSettings {
    // General
    pub theme: String,
    pub language: String,
    pub default_model_family: String,
    pub default_search_mode: String,
    pub auto_reindex_enabled: bool,
    // Appearance
    pub font_size: String,
    pub message_density: String,
    pub show_telemetry_bar: bool,
    pub show_citation_previews: bool,
    // Notifications
    pub notify_drift_remediation: bool,
    pub notify_mesh_peer_events: bool,
    pub notify_dlp_interceptions: bool,
    // Profile
    pub display_name: String,
    pub profile_role: String,
    pub organization: String,
    // Security & Login
    pub default_peer_access_tier: u8,
    pub lan_remote_access_enabled: bool,
    pub strict_wire_frame_validation: bool,
    // Parental Controls
    pub safe_synthesis_filter: bool,
    pub lock_tier3_restricted_folders: bool,
    // Trusted Contact
    pub emergency_recovery_peer: String,
    pub trusted_contact_email: String,
    // Voice
    pub voice_input_enabled: bool,
    pub voice_output_tts_enabled: bool,
    pub preferred_voice: String,
    // Personalization
    pub custom_instructions: String,
    pub response_style: String,
    // Pets
    pub mesh_pet_enabled: bool,
    pub mesh_pet_name: String,
    pub mesh_pet_species: String,
    // Data Controls
    pub retain_chat_history: bool,
    pub anonymize_mesh_queries: bool,
    pub archived_chats: Vec<ArchivedChatEntry>,
    // IDE General & AI Models / Endpoints Settings
    pub enable_streaming: bool,
    pub auto_scroll: bool,
    pub sizing_strategy: String,
    pub ollama_url: String,
    pub ipc_url: String,
    pub cdp_port: u16,
    pub primary_workhorse_model: String,
    pub fusion_panel_size: usize,
    pub vision_specialist_model: String,
    pub audio_specialist_model: String,
    pub multimodal_auto_routing: bool,
    pub natural_human_voice: bool,
    pub sampling_temperature: f32,
    pub max_output_tokens: usize,
    #[serde(default = "default_true", alias = "agentic_loop_chaining")]
    pub agentic_loop_enabled: bool,
    #[serde(default = "default_4096", alias = "agentic_loop_chunk_size")]
    pub agentic_chunk_size: usize,
    pub agentic_strategy: String,
    #[serde(default = "default_true", alias = "deep_research")]
    pub deep_research_iterative_rag: bool,
    #[serde(default = "default_true", alias = "parent_doc_retrieval")]
    pub parent_document_retrieval: bool,
    #[serde(default = "default_true", alias = "map_reduce")]
    pub map_reduce_fact_extraction: bool,
    pub restrl_daemon_running: bool,
    pub restrl_processed_tasks: u64,
    // Dynamic key-value settings for all interactive controls (Appearance, Personalization, Family, Contacts, Voice, etc.)
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedChatEntry {
    pub id: String,
    pub title: String,
    pub archived_at: String,
    pub message_count: usize,
}

impl Default for ChatGptUiSettings {
    fn default() -> Self {
        Self {
            theme: "theme-obsidian".to_string(),
            language: "en-US".to_string(),
            default_model_family: "AutoFusion".to_string(),
            default_search_mode: "Hybrid".to_string(),
            auto_reindex_enabled: true,
            font_size: "medium".to_string(),
            message_density: "comfortable".to_string(),
            show_telemetry_bar: true,
            show_citation_previews: true,
            notify_drift_remediation: true,
            notify_mesh_peer_events: true,
            notify_dlp_interceptions: true,
            display_name: "Femi Oyesanya".to_string(),
            profile_role: "Principal AI & Application Security Architect".to_string(),
            organization: "QuorumRAG Local Sovereign Node".to_string(),
            default_peer_access_tier: 0,
            lan_remote_access_enabled: true,
            strict_wire_frame_validation: true,
            safe_synthesis_filter: false,
            lock_tier3_restricted_folders: true,
            emergency_recovery_peer: String::new(),
            trusted_contact_email: String::new(),
            voice_input_enabled: true,
            voice_output_tts_enabled: false,
            preferred_voice: "System Default (Local Neural)".to_string(),
            custom_instructions: "Answer directly and conversationally from indexed local drives with clean Markdown formatting and citations grouped at the end.".to_string(),
            response_style: "Concise & Grounded".to_string(),
            mesh_pet_enabled: true,
            mesh_pet_name: "Oshoosi Sentinel".to_string(),
            mesh_pet_species: "Cyber Owl 🦉".to_string(),
            retain_chat_history: true,
            anonymize_mesh_queries: true,
            archived_chats: Vec::new(),
            enable_streaming: true,
            auto_scroll: true,
            sizing_strategy: "runtime_ram".to_string(),
            ollama_url: "http://127.0.0.1:11434".to_string(),
            ipc_url: "http://127.0.0.1:3031".to_string(),
            cdp_port: 9222,
            primary_workhorse_model: "qwen2.5:1.5b".to_string(),
            fusion_panel_size: 0,
            vision_specialist_model: "qwen2.5-vl".to_string(),
            audio_specialist_model: "whisper-base".to_string(),
            multimodal_auto_routing: true,
            natural_human_voice: true,
            sampling_temperature: 0.20,
            max_output_tokens: 262144,
            agentic_loop_enabled: true,
            agentic_chunk_size: 4096,
            agentic_strategy: "auto_continuation".to_string(),
            deep_research_iterative_rag: true,
            parent_document_retrieval: true,
            map_reduce_fact_extraction: true,
            restrl_daemon_running: true,
            restrl_processed_tasks: 14,
            extra: std::collections::HashMap::new(),
        }
    }
}

/// Combined persisted state saved to `<data_dir>/settings.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedDaemonSettings {
    pub ui: ChatGptUiSettings,
    pub mesh: OsoosiMeshSettings,
    pub dlp: MeshDlpPolicy,
}

/// Live runtime telemetry for the DLP & Mesh Governance controller.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DlpTelemetryStats {
    pub total_inspected_chunks: u64,
    pub total_redacted_chunks: u64,
    pub total_blocked_chunks: u64,
    pub total_redacted_spans: u64,
    pub total_blocked_unshared_folder_chunks: u64,
    pub zk_commitments_verified: u64,
    pub recent_events: Vec<DlpAuditEvent>,
}

/// Global/shared controller enforcing OshoosiClaw Mesh folder sharing and PHI/PII DLP.
pub struct OsoosiMeshDlpController {
    pub settings: RwLock<PersistedDaemonSettings>,
    pub stats: RwLock<DlpTelemetryStats>,
    pub settings_file_path: RwLock<Option<PathBuf>>,
    pub hmac_secret: [u8; 32],
}

static GLOBAL_CONTROLLER: OnceLock<Arc<OsoosiMeshDlpController>> = OnceLock::new();

pub fn global_mesh_dlp_controller() -> Arc<OsoosiMeshDlpController> {
    GLOBAL_CONTROLLER
        .get_or_init(|| Arc::new(OsoosiMeshDlpController::new()))
        .clone()
}

impl Default for OsoosiMeshDlpController {
    fn default() -> Self {
        Self::new()
    }
}

impl OsoosiMeshDlpController {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (0xA5u8).wrapping_add((i as u8).wrapping_mul(17));
        }
        Self {
            settings: RwLock::new(PersistedDaemonSettings::default()),
            stats: RwLock::new(DlpTelemetryStats::default()),
            settings_file_path: RwLock::new(None),
            hmac_secret: secret,
        }
    }

    /// Loads persisted settings from `<data_dir>/settings.json` if present, or writes defaults.
    pub fn init_persistence(&self, data_dir: &Path) {
        let path = data_dir.join("settings.json");
        {
            let mut p = self
                .settings_file_path
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *p = Some(path.clone());
        }
        if path.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(parsed) = serde_json::from_str::<PersistedDaemonSettings>(&raw) {
                    let mut guard = self.settings.write().unwrap_or_else(|e| e.into_inner());
                    *guard = parsed;
                    return;
                }
            }
        }
        self.save_to_disk();
    }

    /// Saves current settings to `<data_dir>/settings.json`.
    pub fn save_to_disk(&self) {
        let path_opt = self
            .settings_file_path
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(path) = path_opt {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let guard = self.settings.read().unwrap_or_else(|e| e.into_inner());
            if let Ok(json) = serde_json::to_string_pretty(&*guard) {
                let _ = std::fs::write(path, json);
            }
        }
    }

    /// Computes OshoosiClaw-compatible keyed BLAKE3/MAC generation epoch signature over `(peer_id, epoch, role)`.
    pub fn sign_epoch_token(&self, peer_id: &str, epoch: u64, role: &str) -> String {
        let canonical = format!(
            "osoosi-mesh:{}:{}:{}",
            peer_id.trim().to_ascii_lowercase(),
            epoch,
            role.trim().to_ascii_lowercase()
        );
        blake3::keyed_hash(&self.hmac_secret, canonical.as_bytes())
            .to_hex()
            .to_string()
    }

    /// Verifies a keyed generation epoch token in constant time (`subtle::ConstantTimeEq`).
    pub fn verify_epoch_token(
        &self,
        peer_id: &str,
        epoch: u64,
        role: &str,
        signature_hex: &str,
    ) -> bool {
        let active_epoch = self
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .mesh
            .hmac_epoch;
        if epoch < active_epoch {
            return false;
        }
        let expected = self.sign_epoch_token(peer_id, epoch, role);
        signature_hex.len() == expected.len()
            && bool::from(signature_hex.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// Monotonically advances the Mesh generation epoch (`N -> N + 1`) to invalidate stale peer handles.
    pub fn rotate_hmac_epoch(&self) -> u64 {
        let next = {
            let mut guard = self.settings.write().unwrap_or_else(|e| e.into_inner());
            guard.mesh.hmac_epoch = guard.mesh.hmac_epoch.saturating_add(1);
            guard.mesh.hmac_epoch
        };
        self.save_to_disk();
        next
    }

    /// Normalizes a filesystem path for safe, case-insensitive prefix comparison on Windows/Unix.
    pub fn normalize_folder_path(raw: &str) -> Option<String> {
        let trimmed = raw.trim().replace('/', "\\");
        if trimmed.is_empty()
            || trimmed.contains("..")
            || trimmed.contains("%2e")
            || trimmed.contains("%2E")
            || trimmed.starts_with("\\\\")
        {
            return None;
        }
        let path = Path::new(&trimmed);
        for comp in path.components() {
            if matches!(comp, Component::ParentDir) {
                return None;
            }
        }
        let clean = trimmed.trim_end_matches('\\').to_ascii_lowercase();
        if clean.is_empty() {
            None
        } else {
            Some(clean)
        }
    }

    /// Checks whether a local file path is inside one of the user's explicitly enabled `shared_folders`.
    /// Returns the matching `SharedFolderEntry` if sharing is permitted, or `None` if local-only.
    pub fn check_file_shared_with_mesh(&self, file_path: &str) -> Option<SharedFolderEntry> {
        let guard = self.settings.read().unwrap_or_else(|e| e.into_inner());
        if !guard.mesh.p2p_enabled {
            return None;
        }
        let norm_file = Self::normalize_folder_path(file_path)?;

        for folder in &guard.mesh.shared_folders {
            if !folder.enabled {
                continue;
            }
            if let Some(norm_folder) = Self::normalize_folder_path(&folder.path) {
                if norm_file == norm_folder
                    || norm_file.starts_with(&format!("{}\\", norm_folder))
                {
                    return Some(folder.clone());
                }
            }
        }

        if !guard.mesh.require_explicit_folder_share {
            return Some(SharedFolderEntry {
                path: "*".to_string(),
                label: "All Indexed Folders".to_string(),
                enabled: true,
                access_tier: 0,
                dlp_mode_override: None,
                shared_at: String::new(),
            });
        }

        None
    }

    /// Filters and scrubs/blocks candidate chunks before returning them to a remote Mesh peer.
    /// Enforces BOTH:
    /// 1. User Shared Folders allowlist (`shared_folders`)
    /// 2. HIPAA PHI / PII Data Loss Prevention (`Redact` or `Block`)
    pub fn filter_and_enforce_outbound_mesh_chunks(
        &self,
        chunks: Vec<CandidateChunkDto>,
        requester_peer_id: &str,
    ) -> Vec<CandidateChunkDto> {
        let mut allowed_chunks = Vec::new();

        for mut chunk in chunks {
            let shared_entry = match self.check_file_shared_with_mesh(&chunk.file_path) {
                Some(entry) => entry,
                None => {
                    let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
                    stats.total_blocked_unshared_folder_chunks += 1;
                    continue;
                }
            };

            let res = self.inspect_and_enforce_text(
                &chunk.content,
                &chunk.file_path,
                requester_peer_id,
                "OutboundMesh",
                shared_entry.dlp_mode_override,
                false,
            );

            if res.allowed_to_share {
                chunk.content = res.scrubbed_text;
                allowed_chunks.push(chunk);
            }
        }

        allowed_chunks
    }

    /// Enforces PHI/PII DLP on inbound remote chunks received from other Mesh nodes before synthesis.
    pub fn enforce_inbound_remote_chunks(
        &self,
        chunks: Vec<VolatileRemoteChunk>,
    ) -> Vec<VolatileRemoteChunk> {
        let mut clean = Vec::new();
        for mut chunk in chunks {
            let res = self.inspect_and_enforce_text(
                &chunk.content,
                &chunk.file_path,
                &chunk.peer_id,
                "InboundMesh",
                None,
                false,
            );
            if res.allowed_to_share {
                chunk.content = res.scrubbed_text;
                clean.push(chunk);
            }
        }
        clean
    }

    /// Scrubs or blocks PHI/PII in an outbound search query before sending to remote Mesh peers.
    pub fn sanitize_outbound_query(&self, query_text: &str) -> Option<String> {
        let scrub_queries = self
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .dlp
            .scrub_outbound_queries;
        if !scrub_queries {
            return Some(query_text.to_string());
        }
        let res = self.inspect_and_enforce_text(
            query_text,
            "<outbound_mesh_query>",
            "mesh_broadcast",
            "OutboundQuery",
            None,
            true,
        );
        if res.allowed_to_share {
            Some(res.scrubbed_text)
        } else {
            None
        }
    }

    /// Core Two-Tier HIPAA PHI / PII / Secret detector & deterministic redactor/blocker.
    pub fn inspect_and_enforce_text(
        &self,
        text: &str,
        file_path: &str,
        peer_id: &str,
        direction: &str,
        mode_override: Option<DlpEnforcementMode>,
        skip_clean_audit_log: bool,
    ) -> DlpInspectionResult {
        let policy = self
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .dlp
            .clone();

        let effective_mode = mode_override.unwrap_or(policy.mode);

        if !policy.enabled || text.is_empty() {
            return DlpInspectionResult {
                allowed_to_share: true,
                action_taken: "Allowed".to_string(),
                scrubbed_text: text.to_string(),
                detected_categories: Vec::new(),
                detected_spans: Vec::new(),
                redacted_span_count: 0,
                sensitivity_phi_score: 0.0,
                zk_commitment_hex: Self::sha256_hex(text),
            };
        }

        let mut spans: Vec<DetectedPhiSpan> = Vec::new();
        let mut categories: Vec<String> = Vec::new();

        fn add_matches(
            text: &str,
            spans: &mut Vec<DetectedPhiSpan>,
            categories: &mut Vec<String>,
            re_str: &str,
            category: &str,
            replacement: &str,
            conf: f32,
        ) {
            static REGEX_CACHE: OnceLock<RwLock<std::collections::HashMap<String, Regex>>> =
                OnceLock::new();
            let cache = REGEX_CACHE.get_or_init(|| RwLock::new(std::collections::HashMap::new()));
            let re_opt = {
                let guard = cache.read().unwrap_or_else(|e| e.into_inner());
                guard.get(re_str).cloned()
            }
            .or_else(|| {
                let compiled = Regex::new(re_str).ok()?;
                let mut guard = cache.write().unwrap_or_else(|e| e.into_inner());
                guard.insert(re_str.to_string(), compiled.clone());
                Some(compiled)
            });

            if let Some(re) = re_opt {
                for mat in re.find_iter(text) {
                    spans.push(DetectedPhiSpan {
                        category: category.to_string(),
                        start: mat.start(),
                        end: mat.end(),
                        replacement: replacement.to_string(),
                        confidence: conf,
                    });
                    if !categories.contains(&category.to_string()) {
                        categories.push(category.to_string());
                    }
                }
            }
        }

        // 1. US Social Security Numbers (HIPAA Identifier #7)
        if policy.protect_ssn {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"\b\d{3}-\d{2}-\d{4}\b",
                "PHI_SSN",
                "[REDACTED:PHI_SSN]",
                0.98,
            );
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\bSSN\s*[:#]?\s*[X*\d]{3}[-\s]?[X*\d]{2}[-\s]?\d{4}\b",
                "PHI_SSN",
                "[REDACTED:PHI_SSN]",
                0.99,
            );
        }

        // 2. Medical Record Numbers (MRN), ICD-10, CPT, Rx/Pharmacy, Clinical/Hospital PHI (HIPAA #8)
        if policy.protect_medical_records {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\b(?:MRN|Medical\s+Record(?:\s+Number|\s+No\.?)?|Patient\s+ID|Pharmacy\s+ID|Rx\s*#?)\s*[:#-]?\s*[A-Z0-9-]{4,20}\b",
                "PHI_MEDICAL_RECORD",
                "[REDACTED:PHI_MEDICAL_RECORD]",
                0.97,
            );
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\b(?:ICD-?10|Diagnosis(?:\s+Code)?|Clinical\s+Diagnosis|Discharge\s+Summary|Patient\s+Name|Attending\s+Physician|MedicalPharmacy)\s*[:#-]?\s*[^\n|,;]{2,45}",
                "PHI_MEDICAL_RECORD",
                "[REDACTED:PHI_MEDICAL_RECORD]",
                0.94,
            );
            // Check if the file path itself is a medical/pharmacy card or clinical record
            let path_l = file_path.to_ascii_lowercase();
            if path_l.contains("medical")
                || path_l.contains("pharmacy")
                || path_l.contains("patient")
                || path_l.contains("hipaa")
                || path_l.contains("clinical")
            {
                if !categories.contains(&"PHI_MEDICAL_DOCUMENT".to_string()) {
                    categories.push("PHI_MEDICAL_DOCUMENT".to_string());
                }
                if spans.is_empty() && !text.is_empty() {
                    spans.push(DetectedPhiSpan {
                        category: "PHI_MEDICAL_DOCUMENT".to_string(),
                        start: 0,
                        end: text.len(),
                        replacement: "[REDACTED:PHI_MEDICAL_DOCUMENT]".to_string(),
                        confidence: 0.96,
                    });
                }
            }
        }

        // 3. Health Plan Beneficiary Numbers, Medicare/Medicaid, NPI (HIPAA #9)
        if policy.protect_health_plan {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\b(?:Health\s+Plan(?:\s+ID)?|Beneficiary\s+ID|Member\s+ID|Policy\s*#|Group\s*#|Medicare\s+ID|Medicaid\s+ID|NPI)\s*[:#-]?\s*[A-Z0-9-]{5,20}\b",
                "PHI_HEALTH_PLAN_ID",
                "[REDACTED:PHI_HEALTH_PLAN_ID]",
                0.95,
            );
        }

        // 4. Dates of Birth & Clinical Admission/Discharge Dates (HIPAA #3)
        if policy.protect_dob_dates {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\b(?:DOB|Date\s+of\s+Birth|Birth\s*Date|Admission\s+Date|Discharge\s+Date)\s*[:#-]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}|[A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})\b",
                "PHI_DOB",
                "[REDACTED:PHI_DOB]",
                0.96,
            );
        }

        // 5. Student / Academic / Federal Loan IDs
        if policy.protect_academic_student_id {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\b(?:Student\s+ID|University\s+ID|FERPA\s+ID)\s*[:#-]?\s*\d{5,12}\b",
                "PHI_STUDENT_ID",
                "[REDACTED:PHI_STUDENT_ID]",
                0.92,
            );
        }

        // 6. Contact PII: Email, Phone, Fax (HIPAA #4, #5, #6)
        if policy.protect_contact_pii {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                "PHI_CONTACT_EMAIL",
                "[REDACTED:PHI_EMAIL]",
                0.95,
            );
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
                "PHI_CONTACT_PHONE",
                "[REDACTED:PHI_PHONE]",
                0.90,
            );
        }

        // 7. Financial / Tax / Credit Card PANs (HIPAA #10)
        if policy.protect_financial_tax {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"(?i)\b(?:EIN|Tax\s+ID|Employer\s+Identification\s+Number|Routing\s+Number|Bank\s+Account)\s*[:#-]?\s*[\d-]{7,18}\b",
                "PHI_FINANCIAL_TAX",
                "[REDACTED:PHI_FINANCIAL]",
                0.95,
            );
            if let Ok(cc_re) = Regex::new(r"\b(?:\d[ -]*?){13,19}\b") {
                for mat in cc_re.find_iter(text) {
                    let digits: String = mat.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                    if Self::luhn_valid(&digits) {
                        spans.push(DetectedPhiSpan {
                            category: "PHI_PAYMENT_CARD".to_string(),
                            start: mat.start(),
                            end: mat.end(),
                            replacement: "[REDACTED:PHI_PAYMENT_CARD]".to_string(),
                            confidence: 0.97,
                        });
                        if !categories.contains(&"PHI_PAYMENT_CARD".to_string()) {
                            categories.push("PHI_PAYMENT_CARD".to_string());
                        }
                    }
                }
            }
        }

        // 8. Secrets & Crown Jewels
        if policy.protect_secrets_crown_jewels {
            add_matches(
                text,
                &mut spans,
                &mut categories,
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|\bsk-(?:proj-|live-)?[A-Za-z0-9_\-]{16,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----",
                "CROWN_JEWEL_SECRET",
                "[REDACTED:CROWN_JEWEL_SECRET]",
                0.99,
            );
        }

        // Sort and deduplicate overlapping spans
        spans.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));
        let mut merged_spans: Vec<DetectedPhiSpan> = Vec::new();
        for sp in spans {
            if let Some(last) = merged_spans.last_mut() {
                if sp.start < last.end {
                    if sp.end > last.end {
                        last.end = sp.end;
                    }
                    continue;
                }
            }
            merged_spans.push(sp);
        }

        let redacted_span_count = merged_spans.len();
        let sensitivity_phi_score = if merged_spans.is_empty() {
            0.0
        } else {
            merged_spans
                .iter()
                .map(|s| s.confidence as f64)
                .fold(0.0_f64, f64::max)
        };

        // Construct scrubbed string by replacing spans from right to left (preserving UTF-8 boundaries)
        let mut scrubbed_text = text.to_string();
        for sp in merged_spans.iter().rev() {
            if sp.start <= sp.end
                && sp.end <= scrubbed_text.len()
                && scrubbed_text.is_char_boundary(sp.start)
                && scrubbed_text.is_char_boundary(sp.end)
            {
                scrubbed_text.replace_range(sp.start..sp.end, &sp.replacement);
            }
        }

        let zk_commitment_hex = Self::sha256_hex(&scrubbed_text);

        let (allowed_to_share, action_taken) = if redacted_span_count == 0 {
            (true, "Allowed".to_string())
        } else {
            match effective_mode {
                DlpEnforcementMode::Block => (false, "Blocked".to_string()),
                DlpEnforcementMode::Redact => (true, "Redacted".to_string()),
            }
        };

        // Update live telemetry counters and audit log
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.total_inspected_chunks += 1;
            if redacted_span_count > 0 {
                stats.zk_commitments_verified += 1;
                if allowed_to_share {
                    stats.total_redacted_chunks += 1;
                    stats.total_redacted_spans += redacted_span_count as u64;
                } else {
                    stats.total_blocked_chunks += 1;
                }
            }

            if redacted_span_count > 0 || !skip_clean_audit_log {
                let preview: String = scrubbed_text.chars().take(180).collect();
                let event = DlpAuditEvent {
                    id: format!("dlp-{}", stats.total_inspected_chunks),
                    timestamp: Utc::now().to_rfc3339(),
                    direction: direction.to_string(),
                    peer_id: peer_id.to_string(),
                    file_path: file_path.to_string(),
                    action_taken: action_taken.clone(),
                    mode: effective_mode.as_str().to_string(),
                    detected_categories: categories.clone(),
                    redacted_span_count,
                    zk_commitment_hex: zk_commitment_hex.clone(),
                    scrubbed_preview: preview,
                };
                stats.recent_events.insert(0, event);
                if stats.recent_events.len() > 50 {
                    stats.recent_events.truncate(50);
                }
            }
        }

        DlpInspectionResult {
            allowed_to_share,
            action_taken,
            scrubbed_text,
            detected_categories: categories,
            detected_spans: merged_spans,
            redacted_span_count,
            sensitivity_phi_score,
            zk_commitment_hex,
        }
    }

    fn sha256_hex(input: &str) -> String {
        blake3::hash(input.as_bytes()).to_hex().to_string()
    }

    fn luhn_valid(digits: &str) -> bool {
        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }
        let mut sum = 0u32;
        let mut alt = false;
        for ch in digits.chars().rev() {
            let mut n = match ch.to_digit(10) {
                Some(d) => d,
                None => return false,
            };
            if alt {
                n *= 2;
                if n > 9 {
                    n -= 9;
                }
            }
            sum += n;
            alt = !alt;
        }
        sum % 10 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phi_redaction_and_blocking_modes() {
        let controller = OsoosiMeshDlpController::new();
        let sample_phi = "Patient Name: John Doe | MRN: MRN-994821 | SSN: 123-45-6789 | DOB: 04/15/1982 | Diagnosis: ICD-10 J45.909 | Email: john.doe@hospital.org";

        // 1. Default Redact mode scrubs all PHI spans and permits sharing the scrubbed text
        let res_redact = controller.inspect_and_enforce_text(
            sample_phi,
            r"D:\harfile\QuorumRAG\docs\clinical_note.txt",
            "peer_remote_1",
            "OutboundMesh",
            Some(DlpEnforcementMode::Redact),
            false,
        );
        assert!(res_redact.allowed_to_share);
        assert_eq!(res_redact.action_taken, "Redacted");
        assert!(!res_redact.scrubbed_text.contains("123-45-6789"));
        assert!(!res_redact.scrubbed_text.contains("MRN-994821"));
        assert!(!res_redact.scrubbed_text.contains("04/15/1982"));
        assert!(!res_redact.scrubbed_text.contains("john.doe@hospital.org"));
        assert!(res_redact.scrubbed_text.contains("[REDACTED:PHI_SSN]"));
        assert!(res_redact.scrubbed_text.contains("[REDACTED:PHI_MEDICAL_RECORD]"));

        // 2. Block mode completely blocks sharing any chunk containing PHI
        let res_block = controller.inspect_and_enforce_text(
            sample_phi,
            r"D:\harfile\QuorumRAG\docs\clinical_note.txt",
            "peer_remote_1",
            "OutboundMesh",
            Some(DlpEnforcementMode::Block),
            false,
        );
        assert!(!res_block.allowed_to_share);
        assert_eq!(res_block.action_taken, "Blocked");
    }

    #[test]
    fn test_mesh_shared_folder_enforcement() {
        let controller = OsoosiMeshDlpController::new();
        // Default shared folder is D:\harfile\QuorumRAG\docs
        assert!(controller
            .check_file_shared_with_mesh(r"D:\harfile\QuorumRAG\docs\architecture.md")
            .is_some());
        // Unshared personal folder D:\femi\tax or D:\femi\school is strictly blocked from Mesh sharing
        assert!(controller
            .check_file_shared_with_mesh(r"D:\femi\tax\1040_return.pdf")
            .is_none());
        assert!(controller
            .check_file_shared_with_mesh(r"D:\femi\school\Femi-MedicalPharmacy-idcard.png")
            .is_none());
    }

    #[test]
    fn test_ui_preferences_config_defaults() {
        let cfg = UiPreferencesConfig::default();
        assert_eq!(cfg.max_output_tokens, 262144);
        assert!(cfg.agentic_loop_enabled);
        assert_eq!(cfg.agentic_chunk_size, 4096);
        assert_eq!(cfg.agentic_strategy, "auto_continuation");
        assert!(cfg.deep_research_iterative_rag);
        assert!(cfg.parent_document_retrieval);
        assert!(cfg.map_reduce_fact_extraction);
    }

    #[test]
    fn test_ui_preferences_config_serde_aliases() {
        let json_data = serde_json::json!({
            "deep_research": false,
            "parent_doc_retrieval": false,
            "map_reduce": false,
            "agentic_loop_chaining": false,
            "agentic_loop_chunk_size": 2048,
            "max_output_tokens": 8192
        });

        let parsed: UiPreferencesConfig = serde_json::from_value(json_data).expect("Failed to deserialize with aliases");
        assert!(!parsed.deep_research_iterative_rag);
        assert!(!parsed.parent_document_retrieval);
        assert!(!parsed.map_reduce_fact_extraction);
        assert!(!parsed.agentic_loop_enabled);
        assert_eq!(parsed.agentic_chunk_size, 2048);
        assert_eq!(parsed.max_output_tokens, 8192);
    }

    #[test]
    fn test_ui_preferences_config_serde_canonical_and_defaults() {
        // Deserializing empty JSON should populate all defaults correctly
        let empty_json = serde_json::json!({});
        let from_empty: UiPreferencesConfig = serde_json::from_value(empty_json).expect("Failed to deserialize empty");
        assert!(from_empty.deep_research_iterative_rag);
        assert!(from_empty.parent_document_retrieval);
        assert!(from_empty.map_reduce_fact_extraction);
        assert!(from_empty.agentic_loop_enabled);
        assert_eq!(from_empty.agentic_chunk_size, 4096);
        assert_eq!(from_empty.max_output_tokens, 262144);

        // Deserializing explicit canonical names
        let canonical_json = serde_json::json!({
            "deep_research_iterative_rag": false,
            "parent_document_retrieval": false,
            "map_reduce_fact_extraction": false,
            "agentic_loop_enabled": false,
            "agentic_chunk_size": 8192,
            "max_output_tokens": 16384
        });
        let parsed_canonical: UiPreferencesConfig = serde_json::from_value(canonical_json).expect("Failed to deserialize canonical");
        assert!(!parsed_canonical.deep_research_iterative_rag);
        assert!(!parsed_canonical.parent_document_retrieval);
        assert!(!parsed_canonical.map_reduce_fact_extraction);
        assert!(!parsed_canonical.agentic_loop_enabled);
        assert_eq!(parsed_canonical.agentic_chunk_size, 8192);
        assert_eq!(parsed_canonical.max_output_tokens, 16384);

        // Serialization round-trip
        let serialized = serde_json::to_string(&parsed_canonical).expect("Serialization failed");
        let round_trip: UiPreferencesConfig = serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(round_trip.deep_research_iterative_rag, parsed_canonical.deep_research_iterative_rag);
        assert_eq!(round_trip.parent_document_retrieval, parsed_canonical.parent_document_retrieval);
        assert_eq!(round_trip.map_reduce_fact_extraction, parsed_canonical.map_reduce_fact_extraction);
        assert_eq!(round_trip.agentic_loop_enabled, parsed_canonical.agentic_loop_enabled);
        assert_eq!(round_trip.agentic_chunk_size, parsed_canonical.agentic_chunk_size);
        assert_eq!(round_trip.max_output_tokens, parsed_canonical.max_output_tokens);
    }
}
