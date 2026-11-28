//! MeMo (`arXiv:2605.15156`) 3-Stage Decoupled Inference Protocol & Grounded Reflection.
//!
//! Translates MeMo's 3-stage executive/memory protocol into QuorumRAG's grounded, ACL-enforced
//! hybrid retrieval stack (`StorageSearcher` + `AtlasKvStore` + `ScatterGatherEngine` +
//! `RlmOrchestrator`):
//! - **Stage 1 (Stateless Atomic Clue Grounding)**: Decomposes complex queries into independent
//!   clue-probing sub-questions executed without cross-turn context contamination.
//! - **Stage 2 (Entity Identification + Deterministic Uncertain Answer Streak Tracker)**: Tracks
//!   consecutive uncorroborated probes per `(normalized_entity, domain_cluster)` candidate,
//!   pruning distractors at `streak_limit` while strictly preserving all distinct grounded
//!   homonym clusters in `pinned_entities: Vec<String>`.
//! - **Stage 3 (Entity-Pinned Answer Seeking & Grounded Synthesis)**: Feeds pinned entities
//!   and Stage-1 clues into RLM parent-window seeking and citation-grounded synthesis.

use crate::adaptive_rag::{extract_clean_primary_subject, AdaptiveQueryPlan, RetrievalDepth};
use crate::answer_orchestrator::classify_entity_domain_cluster;
use crate::types::{AgenticGraphState, QueryIntentType};
use quorum_atlaskv::{
    audit_chunk_self_containment, infer_chunk_subject_anchor, ScoredKgTriple, SelfContainmentAudit,
};
use quorum_types::ScoredChunk;
use schemars::schema::{InstanceType, Schema, SchemaObject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Configuration for QuorumRAG's MeMo (`arXiv:2605.15156`) 3-stage inference protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoProtocolConfig {
    pub enabled: bool,
    pub stage1_max_subqueries: usize,
    pub stage2_max_turns: usize,
    pub stage2_uncertain_streak_limit: usize,
    pub stage3_max_seek_queries: usize,
    pub use_live_llm_probes: bool,
}

impl Default for MemoProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stage1_max_subqueries: 4,
            stage2_max_turns: 3,
            stage2_uncertain_streak_limit: 2,
            stage3_max_seek_queries: 3,
            use_live_llm_probes: true,
        }
    }
}

/// Active stage of the MeMo 3-stage decoupled inference state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoStage {
    #[default]
    Bypassed,
    Stage1Grounding,
    Stage2EntityIdentification,
    Stage3AnswerSeeking,
    Complete,
}

/// Stateless Stage-1 atomic clue probe result.
///
/// Security invariant: `grounded_clue` NEVER stores raw remote chunk prose (`is_remote == true`),
/// and all sensitive string fields are zeroized on drop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AtomicClueProbe {
    pub sub_question: String,
    pub retrieved_chunk_ids: Vec<String>,
    pub grounded_clue: Option<String>,
    pub candidate_entities: Vec<String>,
    #[zeroize(skip)]
    pub is_uncertain: bool,
    #[zeroize(skip)]
    pub confidence: f32,
}

/// Typed structured extraction schema for optional live Ollama Stage-1 clue probing
/// via `TypedStructuredExtractor<Stage1ClueProbeOutput>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Stage1ClueProbeOutput {
    pub answer: String,
    #[serde(default)]
    pub entity_candidates: Vec<String>,
    #[zeroize(skip)]
    pub is_uncertain: bool,
    pub verbatim_evidence: String,
}

impl JsonSchema for Stage1ClueProbeOutput {
    fn schema_name() -> String {
        "Stage1ClueProbeOutput".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> Schema {
        let mut obj = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let props = obj.object();
        props
            .properties
            .insert("answer".to_string(), gen.subschema_for::<String>());
        props.properties.insert(
            "entity_candidates".to_string(),
            gen.subschema_for::<Vec<String>>(),
        );
        props
            .properties
            .insert("is_uncertain".to_string(), gen.subschema_for::<bool>());
        props.properties.insert(
            "verbatim_evidence".to_string(),
            gen.subschema_for::<String>(),
        );
        for req in [
            "answer",
            "entity_candidates",
            "is_uncertain",
            "verbatim_evidence",
        ] {
            props.required.insert(req.to_string());
        }
        props.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(obj)
    }
}

/// Typed structured extraction schema for optional live Ollama Stage-2 entity pinning
/// via `TypedStructuredExtractor<Stage2EntityPinDecision>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Stage2EntityPinDecision {
    #[serde(default)]
    pub selected_entities: Vec<String>,
    #[serde(default)]
    pub next_probe_question: Option<String>,
    #[zeroize(skip)]
    pub ready_for_stage3: bool,
}

impl JsonSchema for Stage2EntityPinDecision {
    fn schema_name() -> String {
        "Stage2EntityPinDecision".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> Schema {
        let mut obj = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let props = obj.object();
        props.properties.insert(
            "selected_entities".to_string(),
            gen.subschema_for::<Vec<String>>(),
        );
        props.properties.insert(
            "next_probe_question".to_string(),
            gen.subschema_for::<Option<String>>(),
        );
        props
            .properties
            .insert("ready_for_stage3".to_string(), gen.subschema_for::<bool>());
        for req in [
            "selected_entities",
            "next_probe_question",
            "ready_for_stage3",
        ] {
            props.required.insert(req.to_string());
        }
        props.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(obj)
    }
}

/// Per-`(normalized_entity, domain_cluster)` candidate state tracked across Stage-2 turns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CandidateEntityState {
    pub canonical_name: String,
    pub normalized_key: String,
    pub domain_cluster: Option<String>,
    pub corroborating_chunk_ids: Vec<String>,
    #[zeroize(skip)]
    pub corroborating_triple_ids: Vec<u64>,
    #[zeroize(skip)]
    pub consecutive_uncertain_streak: usize,
    #[zeroize(skip)]
    pub total_probes: usize,
    #[zeroize(skip)]
    pub confirmed_hits: usize,
    #[zeroize(skip)]
    pub pruned: bool,
    #[zeroize(skip)]
    pub confidence: f32,
}

/// Deterministic directive emitted at the start of every Stage-2 turn (MeMo §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage2TurnDirective {
    ContinueProbe {
        target_key: String,
        target_entity: String,
        domain_cluster: Option<String>,
        probe_query: String,
        streak_prompt_signal: String,
    },
    SkipToStage3 {
        reason: String,
    },
}

/// Deterministic Stage-2 Uncertain Answer Streak Tracker (MeMo §3.2) with Homonym Preservation Guard.
///
/// Candidates are keyed by `(normalized_entity, domain_cluster)` so distinct grounded homonym
/// identities (e.g. Academic vs. Property Leasing vs. Ministry) are preserved in `pinned_entities`
/// while uncorroborated distractors are pruned once `consecutive_uncertain_streak >= streak_limit`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UncertainAnswerStreakTracker {
    pub turn: usize,
    pub max_turns: usize,
    pub streak_limit: usize,
    pub candidates: BTreeMap<String, CandidateEntityState>,
    pub pinned_entities: Vec<String>,
}

impl Zeroize for UncertainAnswerStreakTracker {
    fn zeroize(&mut self) {
        for cand in self.candidates.values_mut() {
            cand.zeroize();
        }
        self.candidates.clear();
        self.pinned_entities.zeroize();
        self.turn = 0;
    }
}

impl Drop for UncertainAnswerStreakTracker {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for UncertainAnswerStreakTracker {}

impl UncertainAnswerStreakTracker {
    pub fn new(max_turns: usize, streak_limit: usize) -> Self {
        Self {
            turn: 0,
            max_turns: max_turns.max(1),
            streak_limit: streak_limit.max(1),
            candidates: BTreeMap::new(),
            pinned_entities: Vec::new(),
        }
    }

    /// Normalizes an entity name for case-insensitive candidate keying.
    pub fn normalize_entity_name(raw: &str) -> String {
        let trimmed = raw
            .trim()
            .trim_matches(|c: char| matches!(c, '?' | '!' | '.' | ',' | ';' | '"' | '\''))
            .trim();
        let without_possessive = trimmed
            .strip_suffix("'s")
            .or_else(|| trimmed.strip_suffix("\u{2019}s"))
            .or_else(|| trimmed.strip_suffix('\''))
            .unwrap_or(trimmed);
        without_possessive
            .split_whitespace()
            .map(|w| w.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Canonical map key `(normalized_entity, domain_cluster)` for homonym-safe tracking.
    pub fn candidate_key(normalized_entity: &str, domain_cluster: Option<&str>) -> String {
        let cluster = domain_cluster
            .map(str::trim)
            .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("General Document Context"))
            .map(|c| c.to_ascii_lowercase())
            .unwrap_or_else(|| "general".to_string());
        format!("{normalized_entity}::{cluster}")
    }

    /// Strips any disambiguating `" (<Cluster>)"` suffix from a `pinned_entities` entry
    /// so downstream lookup APIs (`AtlasKvStore::query_entity_surface`, RLM grep) receive
    /// the clean entity name.
    pub fn entity_lookup_name(pinned_entry: &str) -> &str {
        if let Some((base, _)) = pinned_entry.rsplit_once(" (") {
            let trimmed = base.trim();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        pinned_entry.trim()
    }

    /// Seeds candidates and initial grounded corroboration from Stage-1 clues, retrieved chunks,
    /// and AtlasKV triples. Never stores raw chunk prose inside candidate state.
    pub fn seed_from_stage1(
        &mut self,
        clues: &[AtomicClueProbe],
        chunks: &[ScoredChunk],
        triples: &[ScoredKgTriple],
    ) {
        // 1. Register candidates surfaced by Stage-1 clue probes
        for clue in clues {
            for ent in &clue.candidate_entities {
                let clean = ent.trim();
                let norm = Self::normalize_entity_name(clean);
                if norm.len() < 2 {
                    continue;
                }

                // Check which retrieved chunks matching this clue actually corroborate this entity
                let mut matched_clusters: Vec<(Option<String>, String)> = Vec::new();
                for sc in chunks {
                    if crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
                        continue;
                    }
                    if !clue.retrieved_chunk_ids.is_empty()
                        && !clue
                            .retrieved_chunk_ids
                            .iter()
                            .any(|cid| cid == &sc.chunk.chunk_id)
                    {
                        continue;
                    }
                    if chunk_corroborates_entity(sc, &norm) {
                        let cluster = classify_specific_cluster(&sc.chunk.file_path, &sc.chunk.text_content);
                        matched_clusters.push((cluster, sc.chunk.chunk_id.clone()));
                    }
                }

                if matched_clusters.is_empty() || clue.is_uncertain {
                    let key = Self::candidate_key(&norm, None);
                    let entry = self.candidates.entry(key.clone()).or_insert_with(|| {
                        CandidateEntityState {
                            canonical_name: clean.to_string(),
                            normalized_key: key.clone(),
                            domain_cluster: None,
                            corroborating_chunk_ids: Vec::new(),
                            corroborating_triple_ids: Vec::new(),
                            consecutive_uncertain_streak: 0,
                            total_probes: 0,
                            confirmed_hits: 0,
                            pruned: false,
                            confidence: 0.25,
                        }
                    });
                    entry.total_probes += 1;
                    if matched_clusters.is_empty() || clue.is_uncertain {
                        entry.consecutive_uncertain_streak += 1;
                        entry.confidence = (entry.confidence * 0.75).max(0.05);
                        if entry.consecutive_uncertain_streak >= self.streak_limit
                            && entry.confirmed_hits == 0
                        {
                            entry.pruned = true;
                        }
                    }
                } else {
                    for (cluster_opt, chunk_id) in matched_clusters {
                        let key = Self::candidate_key(&norm, cluster_opt.as_deref());
                        let entry = self.candidates.entry(key.clone()).or_insert_with(|| {
                            CandidateEntityState {
                                canonical_name: clean.to_string(),
                                normalized_key: key.clone(),
                                domain_cluster: cluster_opt.clone(),
                                corroborating_chunk_ids: Vec::new(),
                                corroborating_triple_ids: Vec::new(),
                                consecutive_uncertain_streak: 0,
                                total_probes: 0,
                                confirmed_hits: 0,
                                pruned: false,
                                confidence: 0.50,
                            }
                        });
                        entry.total_probes += 1;
                        entry.confirmed_hits += 1;
                        entry.consecutive_uncertain_streak = 0;
                        entry.pruned = false;
                        if !entry.corroborating_chunk_ids.contains(&chunk_id) {
                            entry.corroborating_chunk_ids.push(chunk_id);
                        }
                        entry.confidence = (entry.confidence + 0.25 * clue.confidence.max(0.4)).min(1.0);
                    }
                }
            }
        }

        // 2. Register strong subject anchors directly from grounded retrieved chunks
        for sc in chunks {
            if crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
                continue;
            }
            if let Some(anchor) = extract_chunk_anchor(sc) {
                let norm = Self::normalize_entity_name(&anchor);
                if norm.len() < 2 {
                    continue;
                }
                let cluster = classify_specific_cluster(&sc.chunk.file_path, &sc.chunk.text_content);
                let key = Self::candidate_key(&norm, cluster.as_deref());
                let entry = self.candidates.entry(key.clone()).or_insert_with(|| {
                    CandidateEntityState {
                        canonical_name: anchor.clone(),
                        normalized_key: key.clone(),
                        domain_cluster: cluster.clone(),
                        corroborating_chunk_ids: Vec::new(),
                        corroborating_triple_ids: Vec::new(),
                        consecutive_uncertain_streak: 0,
                        total_probes: 0,
                        confirmed_hits: 0,
                        pruned: false,
                        confidence: 0.55,
                    }
                });
                entry.total_probes += 1;
                entry.confirmed_hits += 1;
                entry.consecutive_uncertain_streak = 0;
                entry.pruned = false;
                if !entry.corroborating_chunk_ids.contains(&sc.chunk.chunk_id) {
                    entry.corroborating_chunk_ids.push(sc.chunk.chunk_id.clone());
                }
                entry.confidence = (entry.confidence + 0.20).min(1.0);
            }
        }

        // 3. Register/corroborate entities from AtlasKV triples (respecting work_cluster_id)
        for t in triples {
            let ent = t.triple.entity.trim();
            let norm = Self::normalize_entity_name(ent);
            if norm.len() < 2 {
                continue;
            }
            let cluster = normalize_work_cluster(&t.triple.work_cluster_id);
            let key = Self::candidate_key(&norm, cluster.as_deref());
            let entry = self.candidates.entry(key.clone()).or_insert_with(|| {
                CandidateEntityState {
                    canonical_name: ent.to_string(),
                    normalized_key: key.clone(),
                    domain_cluster: cluster.clone(),
                    corroborating_chunk_ids: Vec::new(),
                    corroborating_triple_ids: Vec::new(),
                    consecutive_uncertain_streak: 0,
                    total_probes: 0,
                    confirmed_hits: 0,
                    pruned: false,
                    confidence: 0.60,
                }
            });
            entry.total_probes += 1;
            entry.confirmed_hits += 1;
            entry.consecutive_uncertain_streak = 0;
            entry.pruned = false;
            if !entry.corroborating_triple_ids.contains(&t.triple.triple_id) {
                entry.corroborating_triple_ids.push(t.triple.triple_id);
            }
            if !t.triple.chunk_id.is_empty()
                && !entry.corroborating_chunk_ids.contains(&t.triple.chunk_id)
            {
                entry.corroborating_chunk_ids.push(t.triple.chunk_id.clone());
            }
            entry.confidence = (entry.confidence + 0.25).min(1.0);
        }

        // Collapse generic unclustered placeholder if the exact same normalized entity already
        // has a confirmed specific cluster (avoids redundant unverified general duplicates).
        let confirmed_specific_norms: BTreeSet<String> = self
            .candidates
            .values()
            .filter(|c| !c.pruned && c.confirmed_hits > 0 && c.domain_cluster.is_some())
            .map(|c| Self::normalize_entity_name(&c.canonical_name))
            .collect();
        let to_remove: Vec<String> = self
            .candidates
            .iter()
            .filter(|(_, c)| {
                c.domain_cluster.is_none()
                    && c.confirmed_hits == 0
                    && confirmed_specific_norms.contains(&Self::normalize_entity_name(&c.canonical_name))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in to_remove {
            self.candidates.remove(&k);
        }

        self.rebuild_pinned_entities();
    }

    /// Deterministically evaluates the start of a Stage-2 turn (MeMo §3.2) and emits either
    /// a targeted `ContinueProbe` directive (with live uncertain-streak signal) or `SkipToStage3`.
    pub fn begin_stage2_turn(&mut self) -> Stage2TurnDirective {
        self.turn += 1;

        if self.turn > self.max_turns {
            return Stage2TurnDirective::SkipToStage3 {
                reason: format!(
                    "Stage-2 turn budget ({}) reached; proceeding to Stage-3 synthesis",
                    self.max_turns
                ),
            };
        }

        if self.all_candidates_pruned() {
            return Stage2TurnDirective::SkipToStage3 {
                reason: "All Stage-2 candidate entities pruned after exceeding uncertain streak limit"
                    .to_string(),
            };
        }

        if self.candidates.is_empty() {
            return Stage2TurnDirective::SkipToStage3 {
                reason: "No ambiguous Stage-2 entity candidates require pinning".to_string(),
            };
        }

        let active_unpinned: Vec<&CandidateEntityState> = self
            .candidates
            .values()
            .filter(|c| !c.pruned && c.confirmed_hits == 0)
            .collect();

        if !self.pinned_entities.is_empty() && active_unpinned.is_empty() {
            return Stage2TurnDirective::SkipToStage3 {
                reason: format!(
                    "Pinned {} grounded entity cluster(s) with zero remaining unverified candidates",
                    self.pinned_entities.len()
                ),
            };
        }

        let mut pool: Vec<&CandidateEntityState> = if !active_unpinned.is_empty() {
            active_unpinned
        } else {
            self.candidates.values().filter(|c| !c.pruned).collect()
        };

        pool.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.consecutive_uncertain_streak.cmp(&b.consecutive_uncertain_streak))
                .then_with(|| a.normalized_key.cmp(&b.normalized_key))
        });

        let Some(target) = pool.first().copied() else {
            return Stage2TurnDirective::SkipToStage3 {
                reason: "No active candidates remaining".to_string(),
            };
        };

        let streak_prompt_signal = self
            .candidates
            .values()
            .map(|c| {
                format!(
                    "{}[cluster={}, streak={}/{}, hits={}, pruned={}]",
                    c.canonical_name,
                    c.domain_cluster.as_deref().unwrap_or("general"),
                    c.consecutive_uncertain_streak,
                    self.streak_limit,
                    c.confirmed_hits,
                    c.pruned
                )
            })
            .collect::<Vec<_>>()
            .join("; ");

        let probe_query = if let Some(ref cluster) = target.domain_cluster {
            format!("{} {}", target.canonical_name, cluster)
        } else {
            target.canonical_name.clone()
        };

        Stage2TurnDirective::ContinueProbe {
            target_key: target.normalized_key.clone(),
            target_entity: target.canonical_name.clone(),
            domain_cluster: target.domain_cluster.clone(),
            probe_query,
            streak_prompt_signal,
        }
    }

    /// Records the outcome of a Stage-2 entity probe (`is_uncertain == true` increments the
    /// consecutive uncertain streak and prunes uncorroborated distractors at `streak_limit`;
    /// grounded hits reset the streak to `0` and promote the entity cluster to `pinned_entities`).
    pub fn record_probe_outcome(
        &mut self,
        entity_key: &str,
        is_uncertain: bool,
        chunk_ids: &[String],
        triple_ids: &[u64],
    ) {
        let mut matched_keys: Vec<String> = Vec::new();
        if self.candidates.contains_key(entity_key) {
            matched_keys.push(entity_key.to_string());
        } else {
            let norm = Self::normalize_entity_name(entity_key);
            if norm.is_empty() {
                return;
            }
            for (k, cand) in &self.candidates {
                if k == &norm || Self::normalize_entity_name(&cand.canonical_name) == norm {
                    matched_keys.push(k.clone());
                }
            }
            if matched_keys.is_empty() {
                let default_key = Self::candidate_key(&norm, None);
                self.candidates.insert(
                    default_key.clone(),
                    CandidateEntityState {
                        canonical_name: entity_key.trim().to_string(),
                        normalized_key: default_key.clone(),
                        domain_cluster: None,
                        corroborating_chunk_ids: Vec::new(),
                        corroborating_triple_ids: Vec::new(),
                        consecutive_uncertain_streak: 0,
                        total_probes: 0,
                        confirmed_hits: 0,
                        pruned: false,
                        confidence: 0.40,
                    },
                );
                matched_keys.push(default_key);
            }
        }

        let effective_uncertain = is_uncertain || (chunk_ids.is_empty() && triple_ids.is_empty());

        for key in matched_keys {
            if let Some(cand) = self.candidates.get_mut(&key) {
                cand.total_probes += 1;
                if effective_uncertain {
                    cand.consecutive_uncertain_streak += 1;
                    cand.confidence = (cand.confidence * 0.5).max(0.01);
                    if cand.consecutive_uncertain_streak >= self.streak_limit
                        && cand.confirmed_hits == 0
                    {
                        cand.pruned = true;
                    }
                } else {
                    cand.consecutive_uncertain_streak = 0;
                    cand.confirmed_hits += 1;
                    cand.pruned = false;
                    for cid in chunk_ids {
                        if !cid.is_empty() && !cand.corroborating_chunk_ids.contains(cid) {
                            cand.corroborating_chunk_ids.push(cid.clone());
                        }
                    }
                    for &tid in triple_ids {
                        if !cand.corroborating_triple_ids.contains(&tid) {
                            cand.corroborating_triple_ids.push(tid);
                        }
                    }
                    cand.confidence = (cand.confidence + 0.35).min(1.0);
                }
            }
        }

        self.rebuild_pinned_entities();
    }

    /// Returns `true` when at least one candidate was tracked and every tracked candidate has been pruned.
    pub fn all_candidates_pruned(&self) -> bool {
        !self.candidates.is_empty() && self.candidates.values().all(|c| c.pruned)
    }

    pub fn active_candidate_count(&self) -> usize {
        self.candidates.values().filter(|c| !c.pruned).count()
    }

    pub fn pruned_candidate_count(&self) -> usize {
        self.candidates.values().filter(|c| c.pruned).count()
    }

    /// Rebuilds `pinned_entities: Vec<String>` from all non-pruned candidates with `confirmed_hits >= 1`,
    /// preserving distinct labels when a single entity name spans multiple domain clusters (homonyms).
    fn rebuild_pinned_entities(&mut self) {
        let mut cluster_counts: HashMap<String, usize> = HashMap::new();
        for cand in self.candidates.values() {
            if !cand.pruned && cand.confirmed_hits > 0 {
                let norm = Self::normalize_entity_name(&cand.canonical_name);
                *cluster_counts.entry(norm).or_insert(0) += 1;
            }
        }

        let mut confirmed: Vec<&CandidateEntityState> = self
            .candidates
            .values()
            .filter(|c| !c.pruned && c.confirmed_hits > 0)
            .collect();

        confirmed.sort_by(|a, b| {
            b.confirmed_hits
                .cmp(&a.confirmed_hits)
                .then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.normalized_key.cmp(&b.normalized_key))
        });

        let mut pinned = Vec::new();
        for cand in confirmed {
            let norm = Self::normalize_entity_name(&cand.canonical_name);
            let is_homonym_multi_cluster = cluster_counts.get(&norm).copied().unwrap_or(0) >= 2;
            let label = match (&cand.domain_cluster, is_homonym_multi_cluster) {
                (Some(cluster), true) => format!("{} ({})", cand.canonical_name, cluster),
                _ => cand.canonical_name.clone(),
            };
            if !pinned.contains(&label) {
                pinned.push(label);
            }
        }
        self.pinned_entities = pinned;
    }
}

/// Fast-path gate deciding whether MeMo Stage 1–3 should engage for the query.
///
/// Bypasses MeMo for disabled configs, `ForensicQueryIntent`, continuation turns,
/// `GeneralConversation`, and trivial `SingleHop` queries without `primary_subject` or
/// multiple sub-questions.
pub fn should_engage_memo_protocol(
    config: &MemoProtocolConfig,
    intent: Option<QueryIntentType>,
    plan: &AdaptiveQueryPlan,
    is_forensic: bool,
    is_continuation: bool,
) -> bool {
    if !config.enabled || is_forensic || is_continuation {
        return false;
    }
    if intent == Some(QueryIntentType::GeneralConversation) {
        return false;
    }
    if intent == Some(QueryIntentType::MultiHopReasoning) {
        return true;
    }
    match plan.depth {
        RetrievalDepth::DeepGraph
        | RetrievalDepth::DecomposedMultiQuery
        | RetrievalDepth::ConceptualHyde => true,
        RetrievalDepth::SingleHop => {
            plan.primary_subject.is_some() || plan.sub_questions.len() >= 2
        }
    }
}

/// Delegates to `quorum_atlaskv::audit_chunk_self_containment` and annotates `metadata_json`
/// ONLY for local chunks (`!chunk.is_remote`), NEVER mutating `chunk.chunk.text_content` and
/// NEVER persisting remote chunk prose or annotations into `metadata_json` / caches.
pub fn verify_and_annotate_chunk_self_containment(
    chunk: &mut ScoredChunk,
    parent_subject: Option<&str>,
) -> SelfContainmentAudit {
    let audit = audit_chunk_self_containment(&chunk.chunk.text_content, parent_subject);

    let is_remote_chunk = chunk.is_remote
        || (!chunk.source_peer.is_empty() && !chunk.source_peer.eq_ignore_ascii_case("local"));
    if is_remote_chunk || crate::artemis_airgap::is_artemis_dfir_chunk(&chunk.chunk) {
        return audit;
    }

    let mut meta: serde_json::Value = serde_json::from_str(&chunk.chunk.metadata_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = meta.as_object_mut() {
        obj.insert(
            "self_contained".to_string(),
            serde_json::json!(audit.is_self_contained),
        );
        if let Some(ref subj) = audit.resolved_subject {
            obj.insert(
                "resolved_entity_anchor".to_string(),
                serde_json::json!(subj),
            );
        }
        if let Ok(serialized) = serde_json::to_string(&meta) {
            chunk.chunk.metadata_json = serialized;
        }
    }

    audit
}

/// Batch self-containment annotator that propagates strong document-level subject anchors
/// across sibling local chunks sharing `document_id`, without touching `text_content` or remote chunks.
///
/// Only same-`document_id` antecedent anchors (`doc_fallback`) are propagated so unrelated
/// pronoun-initial distractor documents are never stamped with the query's `primary_subject`.
pub fn annotate_chunks_self_containment(
    chunks: &mut [ScoredChunk],
    _parent_subject: Option<&str>,
) {
    let mut doc_anchors: HashMap<String, String> = HashMap::new();
    for sc in chunks.iter() {
        let is_remote_chunk = sc.is_remote
            || (!sc.source_peer.is_empty() && !sc.source_peer.eq_ignore_ascii_case("local"));
        if is_remote_chunk || crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
            continue;
        }
        if !sc.chunk.document_id.is_empty() && !doc_anchors.contains_key(&sc.chunk.document_id) {
            if let Some(anchor) = infer_chunk_subject_anchor(
                &sc.chunk.text_content,
                &sc.chunk.metadata_json,
                &sc.chunk.file_path,
            ) {
                doc_anchors.insert(sc.chunk.document_id.clone(), anchor);
            }
        }
    }

    for sc in chunks.iter_mut() {
        let doc_fallback = if !sc.chunk.document_id.is_empty() {
            doc_anchors.get(&sc.chunk.document_id).map(String::as_str)
        } else {
            None
        };
        let _ = verify_and_annotate_chunk_self_containment(sc, doc_fallback);
    }
}

/// Builds stateless Stage-1 `AtomicClueProbe`s for each decomposed sub-question in isolation.
/// Never copies raw remote chunk prose (`is_remote == true`) into `grounded_clue`.
pub fn build_stage1_clue_probes(
    sub_questions: &[String],
    chunks: &[ScoredChunk],
    triples: &[ScoredKgTriple],
    max_subqueries: usize,
) -> Vec<AtomicClueProbe> {
    let cap = max_subqueries.max(1);
    let mut probes = Vec::new();

    for sq in sub_questions.iter().take(cap) {
        let sq_terms = meaningful_query_terms(sq);
        let subj = extract_clean_primary_subject(sq);

        let mut matched_chunk_ids = Vec::new();
        let mut candidate_entities = Vec::new();
        let mut best_local_clue: Option<String> = None;

        if let Some(ref s) = subj {
            candidate_entities.push(s.clone());
        }

        for sc in chunks {
            if crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
                continue;
            }
            let hay_path = sc.chunk.file_path.to_ascii_lowercase();
            let hay_text = sc.chunk.text_content.to_ascii_lowercase();
            let term_hits = sq_terms
                .iter()
                .filter(|t| hay_text.contains(t.as_str()) || hay_path.contains(t.as_str()))
                .count();
            let req_hits = if sq_terms.len() <= 1 { 1 } else { 2.min(sq_terms.len()) };

            if term_hits >= req_hits || (sq_terms.is_empty() && !sc.chunk.text_content.trim().is_empty()) {
                if !matched_chunk_ids.contains(&sc.chunk.chunk_id) {
                    matched_chunk_ids.push(sc.chunk.chunk_id.clone());
                }
                if let Some(anchor) = extract_chunk_anchor(sc) {
                    if !candidate_entities
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(&anchor))
                    {
                        candidate_entities.push(anchor);
                    }
                }
                if best_local_clue.is_none()
                    && !sc.is_remote
                    && (sc.source_peer.is_empty() || sc.source_peer.eq_ignore_ascii_case("local"))
                {
                    let snippet = extract_concise_local_clue(&sc.chunk.text_content, &sq_terms);
                    if !snippet.is_empty() {
                        best_local_clue = Some(snippet);
                    }
                }
            }
        }

        let mut triple_hits = 0usize;
        for t in triples {
            let t_hay = format!(
                "{} {} {}",
                t.triple.entity, t.triple.relation, t.triple.value
            )
            .to_ascii_lowercase();
            if sq_terms.iter().any(|qt| t_hay.contains(qt.as_str())) {
                triple_hits += 1;
                let ent = t.triple.entity.trim();
                if ent.len() >= 2
                    && !candidate_entities.iter().any(|e| e.eq_ignore_ascii_case(ent))
                {
                    candidate_entities.push(ent.to_string());
                }
            }
        }

        let is_uncertain = matched_chunk_ids.is_empty() && triple_hits == 0;
        let confidence = if is_uncertain {
            0.15
        } else {
            (0.45 + 0.15 * (matched_chunk_ids.len() + triple_hits).min(3) as f32).min(0.98)
        };

        probes.push(AtomicClueProbe {
            sub_question: sq.clone(),
            retrieved_chunk_ids: matched_chunk_ids,
            grounded_clue: best_local_clue,
            candidate_entities,
            is_uncertain,
            confidence,
        });
    }

    probes
}

/// Applies an optional live `Stage1ClueProbeOutput` from `TypedStructuredExtractor` while
/// strictly enforcing the remote prose isolation invariant (`is_remote_only` drops `verbatim_evidence`).
pub fn apply_live_stage1_probe_output(
    probe: &mut AtomicClueProbe,
    out: Stage1ClueProbeOutput,
    is_remote_only: bool,
) {
    for cand in &out.entity_candidates {
        let clean = cand.trim();
        if clean.len() >= 2
            && !probe
                .candidate_entities
                .iter()
                .any(|e| e.eq_ignore_ascii_case(clean))
        {
            probe.candidate_entities.push(clean.to_string());
        }
    }
    probe.is_uncertain = out.is_uncertain;
    if !is_remote_only {
        let ev = out.verbatim_evidence.trim();
        let ans = out.answer.trim();
        if !ev.is_empty() {
            probe.grounded_clue = Some(ev.chars().take(240).collect());
        } else if !ans.is_empty() && !out.is_uncertain {
            probe.grounded_clue = Some(ans.chars().take(240).collect());
        }
    }
    probe.confidence = if out.is_uncertain {
        probe.confidence.min(0.30)
    } else {
        probe.confidence.max(0.85)
    };
}

/// Applies an optional live `Stage2EntityPinDecision` from `TypedStructuredExtractor`
/// to `UncertainAnswerStreakTracker`. Boosts or registers LLM-selected candidate entities
/// for deterministic chunk/KG verification without fabricating `confirmed_hits`, and returns
/// any sanitized `next_probe_question` hint when `!decision.ready_for_stage3`.
pub fn apply_live_stage2_pin_decision(
    tracker: &mut UncertainAnswerStreakTracker,
    decision: Stage2EntityPinDecision,
) -> Option<String> {
    for ent in &decision.selected_entities {
        let clean = ent.trim();
        let norm = UncertainAnswerStreakTracker::normalize_entity_name(clean);
        if norm.len() < 2 {
            continue;
        }
        let mut matched = false;
        for cand in tracker.candidates.values_mut() {
            if !cand.pruned
                && UncertainAnswerStreakTracker::normalize_entity_name(&cand.canonical_name) == norm
            {
                cand.confidence = (cand.confidence + 0.15).min(1.0);
                matched = true;
            }
        }
        if !matched {
            let key = UncertainAnswerStreakTracker::candidate_key(&norm, None);
            tracker.candidates.entry(key.clone()).or_insert_with(|| {
                CandidateEntityState {
                    canonical_name: clean.to_string(),
                    normalized_key: key,
                    domain_cluster: None,
                    corroborating_chunk_ids: Vec::new(),
                    corroborating_triple_ids: Vec::new(),
                    consecutive_uncertain_streak: 0,
                    total_probes: 0,
                    confirmed_hits: 0,
                    pruned: false,
                    confidence: 0.65,
                }
            });
        }
    }

    if decision.ready_for_stage3 {
        None
    } else {
        decision
            .next_probe_question
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .map(|q| q.chars().take(160).collect())
    }
}

/// Prunes retrieved chunks that mention ONLY Stage-2 pruned distractor entities and mention
/// NONE of `pinned_entities`, `adaptive_plan.primary_subject`, or confirmed non-pruned
/// document anchors before Stage-3 synthesis. Guarantees at least 1 chunk remains and
/// preserves all multi-cluster homonym chunks.
pub fn prune_distractor_chunks_for_stage3(state: &mut AgenticGraphState) {
    if state.memo_stage == MemoStage::Bypassed || state.retrieved_chunks.len() <= 1 {
        return;
    }
    let Some(ref tracker) = state.entity_streak_tracker else {
        return;
    };
    if tracker.pinned_entities.is_empty() || tracker.pruned_candidate_count() == 0 {
        return;
    }

    let mut keep_terms: Vec<String> = Vec::new();
    for pinned in &tracker.pinned_entities {
        let norm = UncertainAnswerStreakTracker::normalize_entity_name(
            UncertainAnswerStreakTracker::entity_lookup_name(pinned),
        );
        if norm.len() >= 2 && !keep_terms.contains(&norm) {
            keep_terms.push(norm);
        }
    }
    if let Some(ref subj) = state
        .adaptive_plan
        .as_ref()
        .and_then(|p| p.primary_subject.as_ref())
    {
        let norm = UncertainAnswerStreakTracker::normalize_entity_name(subj);
        if norm.len() >= 2 && !keep_terms.contains(&norm) {
            keep_terms.push(norm);
        }
    }
    for cand in tracker.candidates.values() {
        if !cand.pruned && cand.confirmed_hits > 0 {
            let norm = UncertainAnswerStreakTracker::normalize_entity_name(&cand.canonical_name);
            if norm.len() >= 2 && !keep_terms.contains(&norm) {
                keep_terms.push(norm);
            }
        }
    }
    if keep_terms.is_empty() {
        return;
    }

    let mut pruned_only_terms: Vec<String> = Vec::new();
    for cand in tracker.candidates.values() {
        if cand.pruned {
            let norm = UncertainAnswerStreakTracker::normalize_entity_name(&cand.canonical_name);
            if norm.len() >= 2
                && !keep_terms.contains(&norm)
                && !pruned_only_terms.contains(&norm)
            {
                pruned_only_terms.push(norm);
            }
        }
    }
    if pruned_only_terms.is_empty() {
        return;
    }

    let retained: Vec<ScoredChunk> = state
        .retrieved_chunks
        .iter()
        .filter(|sc| {
            if crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk) {
                return true;
            }
            let hay = format!(
                "{} {}",
                sc.chunk.file_path.to_ascii_lowercase(),
                sc.chunk.text_content.to_ascii_lowercase()
            );
            let anchor_norm = if !sc.is_remote {
                serde_json::from_str::<serde_json::Value>(&sc.chunk.metadata_json)
                    .ok()
                    .and_then(|meta| {
                        meta.get("resolved_entity_anchor")
                            .and_then(|v| v.as_str())
                            .map(UncertainAnswerStreakTracker::normalize_entity_name)
                    })
            } else {
                None
            };
            let mentions_keep = keep_terms.iter().any(|k| entity_text_matches(&hay, k))
                || anchor_norm
                    .as_deref()
                    .is_some_and(|a| keep_terms.iter().any(|k| entity_text_matches(a, k) || a == k));
            if mentions_keep {
                return true;
            }
            let mentions_pruned = pruned_only_terms
                .iter()
                .any(|p| entity_text_matches(&hay, p))
                || anchor_norm
                    .as_deref()
                    .is_some_and(|a| pruned_only_terms.iter().any(|p| entity_text_matches(a, p) || a == p));
            !mentions_pruned
        })
        .cloned()
        .collect();

    if !retained.is_empty() && retained.len() < state.retrieved_chunks.len() {
        state.retrieved_chunks = retained;
    }
}

/// Formats Stage-1 grounded clues, Stage-2 pinned entities, and local `resolved_entity_anchor`
/// metadata for Stage-3 synthesis framing (strictly omitting remote chunk prose).
pub fn format_memo_synthesis_context(state: &AgenticGraphState) -> String {
    if state.memo_stage == MemoStage::Bypassed {
        return String::new();
    }

    let mut lines: Vec<String> = Vec::new();
    if !state.pinned_entities.is_empty() {
        lines.push(format!(
            "Pinned Entity Clusters: {}",
            state.pinned_entities.join(" | ")
        ));
    }

    for clue in state.stage1_clues.iter().take(4) {
        if let Some(ref grounded) = clue.grounded_clue {
            if !clue.is_uncertain && !grounded.trim().is_empty() {
                lines.push(format!(
                    "- Sub-question `{}` -> Grounded Clue: {}",
                    clue.sub_question.trim(),
                    grounded.trim()
                ));
            }
        }
    }

    let mut anchor_notes: Vec<String> = Vec::new();
    for sc in &state.retrieved_chunks {
        let is_remote = sc.is_remote
            || (!sc.source_peer.is_empty() && !sc.source_peer.eq_ignore_ascii_case("local"));
        if is_remote {
            continue;
        }
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&sc.chunk.metadata_json) {
            if let Some(anchor) = meta.get("resolved_entity_anchor").and_then(|v| v.as_str()) {
                let file_name = std::path::Path::new(&sc.chunk.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&sc.chunk.file_path);
                let note = format!("{file_name} -> resolved_entity_anchor={anchor}");
                if !anchor_notes.contains(&note) {
                    anchor_notes.push(note);
                }
            }
        }
    }
    if !anchor_notes.is_empty() {
        lines.push(format!(
            "Self-Containment Anchors: {}",
            anchor_notes.into_iter().take(6).collect::<Vec<_>>().join("; ")
        ));
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!(
            "[MeMo Grounded Clues & Pinned Entities]\n{}",
            lines.join("\n")
        )
    }
}

fn classify_specific_cluster(file_path: &str, text: &str) -> Option<String> {
    let label = classify_entity_domain_cluster(file_path, text);
    if label == "General Document Context" {
        None
    } else {
        Some(label.to_string())
    }
}

fn normalize_work_cluster(work_cluster_id: &str) -> Option<String> {
    let trimmed = work_cluster_id.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("general") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn extract_chunk_anchor(sc: &ScoredChunk) -> Option<String> {
    if !sc.is_remote {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&sc.chunk.metadata_json) {
            if let Some(anchor) = meta.get("resolved_entity_anchor").and_then(|v| v.as_str()) {
                let clean = anchor.trim();
                if clean.len() >= 2 {
                    return Some(clean.to_string());
                }
            }
        }
    }
    infer_chunk_subject_anchor(
        &sc.chunk.text_content,
        &sc.chunk.metadata_json,
        &sc.chunk.file_path,
    )
}

fn contains_word_boundary(hay: &str, tok: &str) -> bool {
    if tok.is_empty() {
        return false;
    }
    for (idx, _) in hay.match_indices(tok) {
        let before_alnum = hay[..idx]
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric);
        let after_alnum = hay[idx + tok.len()..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric);
        if !before_alnum && !after_alnum {
            return true;
        }
    }
    false
}

/// Matches a normalized candidate entity name against lowercased text, handling middle initials
/// (e.g. `"alice m. vance"` matching `"alice vance"`) and honorifics without false substring hits.
pub fn entity_text_matches(hay_lower: &str, norm_entity: &str) -> bool {
    if norm_entity.is_empty() {
        return false;
    }
    if (norm_entity.len() >= 4 && hay_lower.contains(norm_entity))
        || (norm_entity.len() >= 2
            && norm_entity.len() < 4
            && contains_word_boundary(hay_lower, norm_entity))
    {
        return true;
    }
    const HONORIFICS: &[&str] = &["dr", "mr", "ms", "mrs", "prof", "rev"];
    let mut significant_tokens: Vec<String> = Vec::new();
    for raw in norm_entity.split_whitespace() {
        let clean: String = raw
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if clean.len() <= 1 || HONORIFICS.contains(&clean.as_str()) {
            continue;
        }
        significant_tokens.push(clean);
    }
    if significant_tokens.len() >= 2 {
        significant_tokens
            .iter()
            .all(|tok| contains_word_boundary(hay_lower, tok))
    } else if significant_tokens.len() == 1 {
        significant_tokens[0].len() >= 4
            && contains_word_boundary(hay_lower, &significant_tokens[0])
    } else {
        false
    }
}

/// Checks whether a retrieved chunk corroborates a normalized entity name (excluding DFIR chunks
/// when callers filter them, and handling middle-initial variations).
pub fn chunk_matches_entity_name(sc: &ScoredChunk, norm_entity: &str) -> bool {
    if norm_entity.is_empty() {
        return false;
    }
    let hay = format!(
        "{} {}",
        sc.chunk.file_path.to_ascii_lowercase(),
        sc.chunk.text_content.to_ascii_lowercase()
    );
    entity_text_matches(&hay, norm_entity)
}

fn chunk_corroborates_entity(sc: &ScoredChunk, norm_entity: &str) -> bool {
    chunk_matches_entity_name(sc, norm_entity)
}

fn meaningful_query_terms(q: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "what", "who", "where", "when", "why", "how", "which", "whose", "whom", "the", "and",
        "for", "with", "from", "into", "about", "are", "was", "were", "have", "has", "had",
        "does", "did", "can", "could", "should", "would", "her", "his", "their", "she", "they",
        "this", "that", "these", "those", "tell", "show", "give", "find",
    ];
    q.to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3 && !STOP.contains(w))
        .fold(Vec::new(), |mut acc, w| {
            let s = w.to_string();
            if !acc.contains(&s) {
                acc.push(s);
            }
            acc
        })
}

fn extract_concise_local_clue(text: &str, terms: &[String]) -> String {
    let cleaned = crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(text);
    for line in cleaned.lines() {
        let t = line.trim();
        if t.len() < 12 {
            continue;
        }
        let tl = t.to_ascii_lowercase();
        if terms.is_empty() || terms.iter().any(|qt| tl.contains(qt.as_str())) {
            return t.chars().take(240).collect();
        }
    }
    cleaned.trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_extractor::{
        compile_json_schema_to_gbnf, generate_inlined_draft07_schema, TypedStructuredExtractor,
    };
    use quorum_atlaskv::KgTripleRecord;
    use quorum_types::DocumentChunk;

    fn make_chunk(id: &str, path: &str, text: &str, is_remote: bool) -> ScoredChunk {
        let peer = if is_remote { "12D3KooWRemotePeer" } else { "local" };
        let doc = DocumentChunk::new(
            id,
            "doc_1",
            path,
            1,
            10,
            0,
            vec![0.1; 8],
            text,
            None,
        )
        .unwrap();
        ScoredChunk::new(doc, 0.9, peer, is_remote)
    }

    #[test]
    fn test_manual_json_schemas_compile_to_gbnf_and_parse() {
        let s1 = generate_inlined_draft07_schema::<Stage1ClueProbeOutput>();
        let g1 = compile_json_schema_to_gbnf(&s1);
        assert!(g1.contains("entity_candidates"));
        assert!(g1.contains("verbatim_evidence"));

        let s2 = generate_inlined_draft07_schema::<Stage2EntityPinDecision>();
        let g2 = compile_json_schema_to_gbnf(&s2);
        assert!(g2.contains("selected_entities"));
        assert!(g2.contains("ready_for_stage3"));

        let raw1 = r#"{"answer":"Angela Davis published Women, Race & Class in 1981.","entity_candidates":["Angela Davis"],"is_uncertain":false,"verbatim_evidence":"Women, Race & Class in 1981"}"#;
        let parsed1 = TypedStructuredExtractor::<Stage1ClueProbeOutput>::parse_raw_json(raw1)
            .expect("parse Stage1ClueProbeOutput");
        assert!(!parsed1.is_uncertain);
        assert_eq!(parsed1.entity_candidates, vec!["Angela Davis"]);

        let raw2 = r#"{"selected_entities":["Angela Davis"],"next_probe_question":null,"ready_for_stage3":true}"#;
        let parsed2 = TypedStructuredExtractor::<Stage2EntityPinDecision>::parse_raw_json(raw2)
            .expect("parse Stage2EntityPinDecision");
        assert!(parsed2.ready_for_stage3);
        assert!(parsed2.next_probe_question.is_none());
    }

    #[test]
    fn test_uncertain_answer_streak_tracker_prunes_distractor_and_resets_on_corroboration() {
        let mut tracker = UncertainAnswerStreakTracker::new(4, 2);

        // Uncertain probe 1 on distractor -> streak 1, not pruned yet
        tracker.record_probe_outcome("Phantom Distractor", true, &[], &[]);
        let d_key = UncertainAnswerStreakTracker::candidate_key("phantom distractor", None);
        assert_eq!(tracker.candidates[&d_key].consecutive_uncertain_streak, 1);
        assert!(!tracker.candidates[&d_key].pruned);

        // Uncertain probe 2 on distractor -> streak hits limit 2 -> pruned!
        tracker.record_probe_outcome("Phantom Distractor", true, &[], &[]);
        assert_eq!(tracker.candidates[&d_key].consecutive_uncertain_streak, 2);
        assert!(tracker.candidates[&d_key].pruned);

        // Corroborated candidate resets streak to 0 and enters pinned_entities
        tracker.record_probe_outcome("Real Entity", true, &[], &[]);
        let r_key = UncertainAnswerStreakTracker::candidate_key("real entity", None);
        assert_eq!(tracker.candidates[&r_key].consecutive_uncertain_streak, 1);
        tracker.record_probe_outcome("Real Entity", false, &["c_real:0".to_string()], &[42]);
        assert_eq!(tracker.candidates[&r_key].consecutive_uncertain_streak, 0);
        assert!(!tracker.candidates[&r_key].pruned);
        assert_eq!(tracker.candidates[&r_key].confirmed_hits, 1);
        assert_eq!(tracker.pinned_entities, vec!["Real Entity".to_string()]);
    }

    #[test]
    fn test_homonym_preservation_across_distinct_domain_clusters() {
        let mut tracker = UncertainAnswerStreakTracker::new(3, 2);

        let c_acad = make_chunk(
            "acad:0",
            "C:/Library/Women_Race_Class_Summary.docx",
            "Angela Davis is a scholar whose landmark work Women, Race & Class explores critical theory.",
            false,
        );
        let c_lease = make_chunk(
            "lease:0",
            "C:/Leases/Susan_LEASE_AGREEMENT.doc",
            "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) in New Orleans.",
            false,
        );
        let c_min = make_chunk(
            "min:0",
            "C:/Ministry/Sermon.docx",
            "Reverend Angela Davis serves as a Unity minister exploring divine presence and stewardship.",
            false,
        );

        let clues = vec![AtomicClueProbe {
            sub_question: "Who is Angela Davis?".to_string(),
            retrieved_chunk_ids: vec![
                "acad:0".to_string(),
                "lease:0".to_string(),
                "min:0".to_string(),
            ],
            grounded_clue: Some("Angela Davis appears across 3 domains.".to_string()),
            candidate_entities: vec!["Angela Davis".to_string()],
            is_uncertain: false,
            confidence: 0.9,
        }];

        tracker.seed_from_stage1(&clues, &[c_acad, c_lease, c_min], &[]);

        assert_eq!(
            tracker.pinned_entities.len(),
            3,
            "All 3 grounded Angela Davis domain clusters must remain pinned without collapsing: {:?}",
            tracker.pinned_entities
        );
        for p in &tracker.pinned_entities {
            assert_eq!(
                UncertainAnswerStreakTracker::entity_lookup_name(p),
                "Angela Davis"
            );
        }
    }

    #[test]
    fn test_self_containment_annotation_preserves_text_and_isolates_remote() {
        let original_text = "She later published Women, Race & Class in 1981.";
        let mut local = make_chunk("loc:1", "C:/Library/Bio.docx", original_text, false);
        let original_hash = local.chunk.blake3_hash.clone();

        let audit = verify_and_annotate_chunk_self_containment(&mut local, Some("Angela Davis"));
        assert!(!audit.is_self_contained);
        assert_eq!(audit.resolved_subject.as_deref(), Some("Angela Davis"));
        // Text content and BLAKE3 hash MUST remain untouched
        assert_eq!(local.chunk.text_content, original_text);
        assert!(local.chunk.verify_hash());
        assert_eq!(local.chunk.blake3_hash, original_hash);
        // Metadata JSON carries the MeMo self-containment annotations
        let meta: serde_json::Value = serde_json::from_str(&local.chunk.metadata_json).unwrap();
        assert_eq!(meta["self_contained"], serde_json::json!(false));
        assert_eq!(
            meta["resolved_entity_anchor"],
            serde_json::json!("Angela Davis")
        );

        // Remote chunk metadata_json must NEVER be mutated
        let mut remote = make_chunk("rem:1", "D:/Remote/Bio.docx", original_text, true);
        let rem_meta_before = remote.chunk.metadata_json.clone();
        let _ = verify_and_annotate_chunk_self_containment(&mut remote, Some("Angela Davis"));
        assert_eq!(remote.chunk.metadata_json, rem_meta_before);
        assert_eq!(remote.chunk.text_content, original_text);
    }

    #[test]
    fn test_stage1_clue_probe_never_stores_remote_prose() {
        let remote = make_chunk(
            "rem:0",
            "D:/Remote/SecretMemo.docx",
            "Alice Vance led Project Horizon in 2024 using confidential telemetry.",
            true,
        );
        let probes = build_stage1_clue_probes(
            &["Which project did Alice Vance lead in 2024?".to_string()],
            &[remote],
            &[],
            4,
        );
        assert_eq!(probes.len(), 1);
        assert!(
            probes[0].grounded_clue.is_none(),
            "Remote chunk prose must NEVER be copied into AtomicClueProbe::grounded_clue"
        );
        assert_eq!(probes[0].retrieved_chunk_ids, vec!["rem:0".to_string()]);
    }

    #[test]
    fn test_should_engage_memo_protocol_gating() {
        let cfg = MemoProtocolConfig::default();
        let simple_plan = AdaptiveQueryPlan {
            depth: RetrievalDepth::SingleHop,
            primary_subject: None,
            sub_questions: vec!["what is the weather".to_string()],
            query_variants: vec!["what is the weather".to_string()],
            hyde_passage: None,
        };
        assert!(!should_engage_memo_protocol(
            &cfg,
            Some(QueryIntentType::LocalDocumentSearch),
            &simple_plan,
            false,
            false
        ));
        assert!(!should_engage_memo_protocol(
            &cfg,
            Some(QueryIntentType::MultiHopReasoning),
            &simple_plan,
            true, // forensic bypass
            false
        ));
        assert!(!should_engage_memo_protocol(
            &cfg,
            Some(QueryIntentType::GeneralConversation),
            &simple_plan,
            false,
            false
        ));

        let multi_plan = AdaptiveQueryPlan {
            depth: RetrievalDepth::DecomposedMultiQuery,
            primary_subject: Some("Angela Davis".to_string()),
            sub_questions: vec![
                "Who is Angela Davis?".to_string(),
                "What is Angela Davis's research?".to_string(),
            ],
            query_variants: vec!["Angela Davis".to_string()],
            hyde_passage: None,
        };
        assert!(should_engage_memo_protocol(
            &cfg,
            Some(QueryIntentType::LocalDocumentSearch),
            &multi_plan,
            false,
            false
        ));
    }

    #[test]
    fn test_1xn_distractor_noise_robustness_via_tracker() {
        let mut tracker = UncertainAnswerStreakTracker::new(3, 2);

        let local_target = make_chunk(
            "target:0",
            "C:/Projects/Horizon_Report.docx",
            "Alice Vance directed Project Horizon in 2024 with full budget sign-off.",
            false,
        );
        let triple = ScoredKgTriple {
            triple: KgTripleRecord {
                triple_id: 101,
                blake3_hash: "h101".to_string(),
                entity: "Alice Vance".to_string(),
                relation: "directed".to_string(),
                key_string: "Alice Vance directed Project Horizon".to_string(),
                value: "Project Horizon".to_string(),
                document_id: "doc_1".to_string(),
                chunk_id: "target:0".to_string(),
                file_path: "C:/Projects/Horizon_Report.docx".to_string(),
                line_start: 1,
                line_end: 5,
                work_cluster_id: String::new(),
                access_tier: 0,
                source_peer: "local".to_string(),
            },
            score: 0.95,
        };

        // 1 corroborated candidate + 4 high-noise distractor candidates
        let mut clues = vec![AtomicClueProbe {
            sub_question: "Who directed Project Horizon?".to_string(),
            retrieved_chunk_ids: vec!["target:0".to_string()],
            grounded_clue: Some("Alice Vance directed Project Horizon in 2024.".to_string()),
            candidate_entities: vec!["Alice Vance".to_string()],
            is_uncertain: false,
            confidence: 0.9,
        }];
        for idx in 1..=4 {
            clues.push(AtomicClueProbe {
                sub_question: format!("Noise distractor probe {idx}"),
                retrieved_chunk_ids: Vec::new(),
                grounded_clue: None,
                candidate_entities: vec![format!("Distractor Noise {idx}")],
                is_uncertain: true,
                confidence: 0.2,
            });
        }

        tracker.seed_from_stage1(&clues, &[local_target], &[triple]);
        for idx in 1..=4 {
            tracker.record_probe_outcome(&format!("Distractor Noise {idx}"), true, &[], &[]);
        }

        assert_eq!(tracker.pinned_entities, vec!["Alice Vance".to_string()]);
        assert_eq!(tracker.pruned_candidate_count(), 4);
        assert_eq!(tracker.active_candidate_count(), 1);
    }

    #[test]
    fn test_annotate_chunks_self_containment_does_not_leak_parent_subject_cross_doc() {
        let mut elena_header = ScoredChunk::new(
            DocumentChunk::new(
                "doc_elena:0",
                "doc_elena",
                "C:/Bio/Elena.docx",
                1,
                10,
                0,
                vec![0.1; 8],
                "Elena Rostova is a computational linguist at Zurich Institute.",
                None,
            )
            .unwrap(),
            0.9,
            "local",
            false,
        );
        let mut elena_pronoun = ScoredChunk::new(
            DocumentChunk::new(
                "doc_elena:5",
                "doc_elena",
                "C:/Bio/Elena.docx",
                50,
                60,
                0,
                vec![0.1; 8],
                "She published Sparse Graph Attention in 2023.",
                None,
            )
            .unwrap(),
            0.85,
            "local",
            false,
        );
        let mut unrelated_pronoun = ScoredChunk::new(
            DocumentChunk::new(
                "doc_other:5",
                "doc_other",
                "C:/Noise/Parking_Notice.docx",
                50,
                60,
                0,
                vec![0.1; 8],
                "He later parked in Lot B near Gate 3.",
                None,
            )
            .unwrap(),
            0.75,
            "local",
            false,
        );

        let mut chunks = vec![
            elena_header.clone(),
            elena_pronoun.clone(),
            unrelated_pronoun.clone(),
        ];
        annotate_chunks_self_containment(&mut chunks, Some("Elena Rostova"));

        elena_header = chunks[0].clone();
        elena_pronoun = chunks[1].clone();
        unrelated_pronoun = chunks[2].clone();
        assert!(elena_header.chunk.verify_hash());
        assert!(elena_pronoun.chunk.verify_hash());
        assert!(unrelated_pronoun.chunk.verify_hash());

        let elena_meta: serde_json::Value =
            serde_json::from_str(&elena_pronoun.chunk.metadata_json).unwrap();
        assert_eq!(
            elena_meta["resolved_entity_anchor"],
            serde_json::json!("Elena Rostova")
        );

        let unrelated_meta: serde_json::Value =
            serde_json::from_str(&unrelated_pronoun.chunk.metadata_json).unwrap();
        assert!(
            unrelated_meta.get("resolved_entity_anchor").is_none(),
            "Unrelated distractor document must NOT receive parent_subject as resolved_entity_anchor: {:?}",
            unrelated_meta
        );
    }

    #[test]
    fn test_apply_live_stage2_pin_decision_and_middle_initial_matching() {
        let mut tracker = UncertainAnswerStreakTracker::new(3, 2);
        tracker.record_probe_outcome("Alice M. Vance", true, &[], &[]);
        let decision = Stage2EntityPinDecision {
            selected_entities: vec!["Alice M. Vance".to_string(), "Zurich Institute".to_string()],
            next_probe_question: Some("Alice M. Vance Horizon budget".to_string()),
            ready_for_stage3: false,
        };
        let hint = apply_live_stage2_pin_decision(&mut tracker, decision);
        assert_eq!(hint.as_deref(), Some("Alice M. Vance Horizon budget"));
        // Must not fabricate confirmed_hits before real chunk/KG corroboration
        let alice_key = UncertainAnswerStreakTracker::candidate_key("alice m. vance", None);
        assert_eq!(tracker.candidates[&alice_key].confirmed_hits, 0);
        assert!(tracker.pinned_entities.is_empty());

        // Middle-initial matching must corroborate "Alice M. Vance" against "Alice Vance"
        let sc = make_chunk(
            "c_alice:0",
            "C:/Projects/Charter.docx",
            "Alice Vance directed Project Horizon in 2024.",
            false,
        );
        assert!(chunk_matches_entity_name(&sc, "alice m. vance"));
        assert!(!chunk_matches_entity_name(&sc, "bob distractor"));
    }

    #[test]
    fn test_prune_distractor_chunks_for_stage3_preserves_homonyms_and_drops_pruned_only() {
        let mut state = AgenticGraphState::new(
            "Who is Angela Davis?",
            crate::types::SynthesisModelFamily::AutoFusion,
            3,
        );
        state.memo_stage = MemoStage::Stage3AnswerSeeking;
        let mut tracker = UncertainAnswerStreakTracker::new(3, 2);
        let c_acad = make_chunk(
            "acad:0",
            "C:/Library/Women_Race_Class_Summary.docx",
            "Angela Davis is a scholar whose landmark work Women, Race & Class explores critical theory.",
            false,
        );
        let c_lease = make_chunk(
            "lease:0",
            "C:/Leases/Susan_LEASE_AGREEMENT.doc",
            "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant).",
            false,
        );
        let c_pruned = make_chunk(
            "noise:0",
            "C:/Noise/Parking.docx",
            "Bob Distractor requested quarterly parking pass renewal.",
            false,
        );

        let clues = vec![AtomicClueProbe {
            sub_question: "Who is Angela Davis?".to_string(),
            retrieved_chunk_ids: vec!["acad:0".to_string(), "lease:0".to_string()],
            grounded_clue: Some("Angela Davis appears in academic and leasing records.".to_string()),
            candidate_entities: vec!["Angela Davis".to_string()],
            is_uncertain: false,
            confidence: 0.9,
        }];
        tracker.seed_from_stage1(&clues, &[c_acad.clone(), c_lease.clone()], &[]);
        tracker.record_probe_outcome("Bob Distractor", true, &[], &[]);
        tracker.record_probe_outcome("Bob Distractor", true, &[], &[]);
        assert_eq!(tracker.pruned_candidate_count(), 1);
        assert_eq!(tracker.pinned_entities.len(), 2);

        state.entity_streak_tracker = Some(tracker);
        state.retrieved_chunks = vec![c_acad, c_lease, c_pruned];

        prune_distractor_chunks_for_stage3(&mut state);
        assert_eq!(state.retrieved_chunks.len(), 2);
        assert!(state
            .retrieved_chunks
            .iter()
            .all(|c| c.chunk.chunk_id != "noise:0"));
    }

    #[test]
    fn test_entity_text_matches_short_entities_require_word_boundaries() {
        let ann_norm = UncertainAnswerStreakTracker::normalize_entity_name("Ann");
        assert_eq!(ann_norm, "ann");
        assert!(!entity_text_matches("annual budget report", &ann_norm));
        assert!(entity_text_matches("ann smith led the review", &ann_norm));
        assert!(!entity_text_matches("she said hello", "ai"));
        assert!(entity_text_matches("ai safety guidelines", "ai"));
        assert!(!entity_text_matches("deep sleep study", "lee"));
        assert!(entity_text_matches("lee signed the charter", "lee"));
    }
}
