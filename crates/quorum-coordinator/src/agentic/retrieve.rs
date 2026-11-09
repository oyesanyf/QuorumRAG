use crate::scatter_gather::ScatterGatherEngine;
use crate::types::AgenticGraphState;
use quorum_contract::EmbeddingGenerator;
use quorum_types::ScoredChunk;

/// Pre-computed scoring criteria evaluated once per chunk before sorting,
/// eliminating repetitive lowercase allocations and substring scans inside the comparator.
#[derive(Debug, Clone, Copy)]
pub struct ChunkScoreCriteria {
    pub weighted_hits: usize,
    pub content_matched_terms: usize,
    pub entity_hits: usize,
    pub prompt_entity_hits: usize,
    pub intent_bonus: i32,
    pub total_score: i32,
    pub is_relevant: bool,
    /// True when every user-capitalised proper-noun anchor (or all but one when 3+) appears in the chunk.
    pub proper_ok: bool,
}

pub const QUERY_META_INTENT_TERMS: &[&str] = &[
    "article", "articles", "paper", "papers", "research",
    "written", "writing", "writings", "write", "writes", "wrote",
    "authored", "author", "authors",
    "publication", "publications", "published", "publish",
    "done", "he", "him", "his", "she", "her", "they", "them",
    "tell", "show", "give", "list", "find", "describe", "explain",
    "all", "any", "other", "more", "another", "besides",
    "according", "based", "within", "listed", "documented", "provided", "explicitly",
    "formal", "official", "mentioned", "stated", "shown", "included",
];

pub const GENERIC_ATTRIBUTE_TERMS: &[&str] = &[
    "school", "schools", "university", "universities", "college", "colleges",
    "degree", "degrees", "education", "academic", "transcript", "transcripts",
    "gpa", "study", "studied", "major", "course", "courses", "work", "worked",
    "job", "jobs", "role", "roles", "skill", "skills", "profession", "professional",
    "experience", "experiences", "career", "background", "profile", "resume",
    "resumes", "summary", "summaries", "history", "company", "companies",
    "held", "hold", "holds", "holding", "timeline", "chronology", "chronological",
    "position", "positions", "title", "titles", "capacity", "capacities",
    "responsibility", "responsibilities", "duty", "duties", "employer", "employers",
    "employment", "organization", "organizations", "past", "previous", "current", "recent",
    "project", "projects", "certification", "certifications", "went", "attend",
    "attended", "graduated", "year", "years", "detail", "details", "information",
    "income", "tax", "taxes", "statement", "statements", "plan", "plans",
    "payment", "payments", "credit", "credits", "account", "accounts",
    "amount", "amounts", "rate", "rates", "form", "forms", "section",
    "sections", "page", "pages", "total", "day", "days", "heart", "soul",
    "life", "time", "world", "reading", "book", "books", "universal", "system", "systems",
    "model", "models", "data", "report", "reports", "policy", "policies",
    "pay", "pays", "paid", "paying", "cost", "costs", "price", "prices", "fee", "fees",
    "start", "started", "starts", "begin", "began", "end", "ended", "ends", "date", "dates",
    "important", "importance", "result", "results", "respond", "responds", "response",
];

pub const STOPWORDS: &[&str] = &[
    "what", "does", "do", "did", "where", "when", "who", "how", "why",
    "is", "are", "was", "were", "the", "and", "for", "with", "from",
    "into", "about", "using", "have", "has", "had", "will", "would",
    "should", "could", "can", "you", "tell", "show", "went", "attend", "attended",
    "disambiguation", "hop", "more", "else", "also", "his", "her", "hers", "him",
    "she", "they", "them", "their", "theirs", "there", "that", "this", "these", "those",
    "file", "files", "document", "documents", "doc", "docs", "docx", "pdf", "txt",
    "folder", "folders", "content", "contents", "text", "exist", "exists", "existing",
    "find", "check", "list", "located", "location", "explain", "describe", "give", "please",
    "know", "knows", "knew", "known", "think", "thinks", "thought", "mean", "means", "meant",
    "say", "says", "said", "talk", "talks", "talked", "need", "needs", "want", "wants",
    "like", "likes", "make", "makes", "made", "take", "takes", "took", "come", "comes",
    "came", "look", "looks", "looked", "summarize", "detail", "details", "info", "information",
    "anything", "everything", "something", "nothing", "someone", "anyone", "all", "any", "some",
    "much", "many", "often", "long", "kind", "type", "sort", "way", "get", "gets", "got", "use",
    "uses", "used", "which", "whose", "whom", "its", "our", "your", "my", "me", "one", "ones",
    "not", "than", "then", "very", "just", "only", "each", "every", "both", "either", "other",
    "others", "own", "same", "such", "been", "being", "off", "out", "over", "under", "again",
    "here", "now", "still", "yet", "ever", "even", "continue", "continued", "elaborate",
];

pub struct RetrieveMeshNode;

impl RetrieveMeshNode {
    /// Capping helper: Caps excerpts per document stem per peer across the federation (max 2 per document family per peer),
    /// keying on (source_peer, stem) so local document families do not evict remote peer chunks from the same document family.
    pub fn cap_document_families_federated(
        chunks: Vec<quorum_types::ScoredChunk>,
        max_per_family: usize,
    ) -> Vec<quorum_types::ScoredChunk> {
        let mut stem_counts: std::collections::HashMap<(String, String), usize> =
            std::collections::HashMap::new();
        let mut stem_deduped: Vec<quorum_types::ScoredChunk> = Vec::with_capacity(chunks.len());
        for c in chunks {
            let stem = crate::offline_engine::DeterministicOfflineSynthesisEngine::normalize_file_stem(
                &c.chunk.file_path,
            );
            let key = (c.source_peer.to_ascii_lowercase(), stem);
            let count = stem_counts.entry(key).or_insert(0);
            if *count < max_per_family {
                *count += 1;
                stem_deduped.push(c);
            }
        }
        stem_deduped
    }

    pub async fn execute(
        state: &mut AgenticGraphState,
        engine: &ScatterGatherEngine,
        vector: &[f32],
        access_tier: u8,
        top_k: usize,
    ) {
        let candidate_k = top_k.max(48);

        // Feature 48: Reuse cached vector hits across rewrite hops to avoid redundant LanceDB scans
        let cached_hits_opt = if state.hop_count > 0 && !state.cached_vector_hits.is_empty() {
            Some(state.cached_vector_hits.as_slice())
        } else {
            None
        };

        let (corrected_q, _) = crate::offline_engine::DeterministicOfflineSynthesisEngine::correct_query_spelling(
            &state.current_query,
            false,
        );
        if !corrected_q.trim().is_empty() {
            state.current_query = corrected_q;
        }
        let q_low = state.current_query.to_ascii_lowercase();
        let search_query = if q_low.contains("school")
            || q_low.contains("college")
            || q_low.contains("university")
            || q_low.contains("education")
            || q_low.contains("degree")
            || q_low.contains("graduated")
        {
            format!(
                "{} education university college master bachelor degree certifications",
                state.current_query
            )
        } else if (q_low.contains("resume")
            || q_low.contains("cv")
            || q_low.contains("curriculum vitae")
            || q_low.contains("roles")
            || q_low.contains("role ")
            || q_low.contains("positions")
            || q_low.contains("career")
            || q_low.contains("timeline")
            || q_low.contains("work history"))
            && !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_authorship_query(&q_low)
        {
            format!(
                "{} professional summary experience work history engineer architect analyst lead consultant manager",
                state.current_query
            )
        } else {
            state.current_query.clone()
        };

        // Align dense vector with primary extracted question if cleaner than noisy raw prompt
        let aligned_vec_storage;
        let effective_vector = if let Some(primary_q) = state.extracted_questions.first() {
            if primary_q != &state.current_query && !primary_q.trim().is_empty() {
                let embedder = quorum_contract::DeterministicOfflineEngine::new();
                if let Ok(fresh) = embedder.embed_text(primary_q) {
                    aligned_vec_storage = fresh;
                    aligned_vec_storage.as_slice()
                } else {
                    vector
                }
            } else {
                vector
            }
        } else {
            vector
        };

        let exclude_chunk_ids: Vec<String> = state.seen_chunk_ids.iter().cloned().collect();
        tracing::info!(query = %search_query, exclude_count = exclude_chunk_ids.len(), "Calling execute_query_with_cached_vector_and_exclusion");

        // When running in the live daemon (or when non-code user documents exist), filter out source code,
        // lock files, raw .dat blobs, and monolithic chat dumps so they never crowd out user PDF/DOCX documents.
        let daemon_active = crate::dlp_mesh::global_mesh_dlp_controller()
            .settings_file_path
            .read()
            .map(|p| p.is_some())
            .unwrap_or(false);

        let orig_low = state.original_prompt.to_ascii_lowercase();
        let is_continuation_turn =
            crate::offline_engine::DeterministicOfflineSynthesisEngine::is_continuation_query(&orig_low);
        let base_subject_prompt: String = if is_continuation_turn {
            state
                .conversation_history
                .iter()
                .rev()
                .find(|t| {
                    t.role.eq_ignore_ascii_case("user")
                        && !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_continuation_query(
                            &t.content.to_ascii_lowercase(),
                        )
                })
                .map(|t| t.content.clone())
                .unwrap_or_else(|| state.current_query.clone())
        } else {
            state.current_query.clone()
        };
        let subject_low = base_subject_prompt.to_ascii_lowercase();

        // Supplement candidate pool with direct entity-term keyword hits so large corpora
        // never drown out specific entity documents (e.g. "Femi_Oyesanya_CV_2026.pdf") when generic
        // education/profile expansion terms ("school", "university", "experience") are present.
        let mut prelim_entities: Vec<String> = subject_low
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|w| {
                w.len() >= 3
                    && !STOPWORDS.contains(w)
                    && !GENERIC_ATTRIBUTE_TERMS.contains(w)
            })
            .map(|w| w.to_string())
            .collect();

        // Augment with LangExtract verified entities and document targets
        for ext in &state.extracted_entities {
            let t = ext.extraction_text.trim();
            if !t.is_empty() && !prelim_entities.iter().any(|e| e.eq_ignore_ascii_case(t)) {
                prelim_entities.push(t.to_string());
            }
        }

        let prompt_only_entities: Vec<String> = if is_continuation_turn {
            Vec::new()
        } else {
            orig_low
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|w| {
                    w.len() >= 3
                        && !STOPWORDS.contains(w)
                        && !GENERIC_ATTRIBUTE_TERMS.contains(w)
                        && !QUERY_META_INTENT_TERMS.contains(w)
                })
                .fold(Vec::new(), |mut acc, w| {
                    let s = w.to_string();
                    if !acc.contains(&s) {
                        acc.push(s);
                    }
                    acc
                })
        };

        // Proper-noun anchors: words the user capitalised mid-sentence ("how much rent does Casey Ringgold pay").
        // When present, a chunk must contain them, so generic words ("rent", "pay") can never outvote the named subject.
        let proper_source = if is_continuation_turn {
            base_subject_prompt.as_str()
        } else {
            state.original_prompt.as_str()
        };
        let proper_terms: Vec<String> = proper_source
            .split_whitespace()
            .enumerate()
            .filter_map(|(i, raw)| {
                if i == 0 {
                    return None;
                }
                let w = raw
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '\'')
                    .trim_end_matches("'s")
                    .trim_end_matches("\u{2019}s")
                    .trim_matches(|c: char| !c.is_alphanumeric());
                let first_upper = w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                let lw = w.to_ascii_lowercase();
                if first_upper
                    && lw.len() >= 3
                    && !STOPWORDS.contains(&lw.as_str())
                    && !GENERIC_ATTRIBUTE_TERMS.contains(&lw.as_str())
                {
                    Some(lw)
                } else {
                    None
                }
            })
            .fold(Vec::new(), |mut acc, w| {
                if !acc.contains(&w) {
                    acc.push(w);
                }
                acc
            });

        // Precompute supplemental search queries upfront so they can execute concurrently with the primary search
        let should_run_supplemental = (daemon_active || !state.extracted_entities.is_empty()) && !prelim_entities.is_empty();
        let entity_kw_query_opt = if should_run_supplemental {
            Some(prelim_entities.join(" "))
        } else {
            None
        };
        let prompt_kw_query_opt = if should_run_supplemental && !prompt_only_entities.is_empty() && prompt_only_entities != prelim_entities {
            Some(prompt_only_entities.join(" "))
        } else {
            None
        };
        let cue_terms = crate::offline_engine::DeterministicOfflineSynthesisEngine::answer_type_cue_terms(&state.original_prompt);
        let cue_query_opt = if should_run_supplemental && !cue_terms.is_empty() && !prompt_only_entities.is_empty() {
            Some(format!("{} {}", prompt_only_entities.join(" "), cue_terms.join(" ")))
        } else {
            None
        };

        // Dispatch primary query + supplemental queries concurrently via tokio::join!
        // Send the unbloated query (`state.current_query`) to remote P2P peers so 1.5M+ chunk remote corpora
        // are not diluted by 7 generic BM25 expansion words, while keeping `search_query` for local storage.
        let primary_fut = engine.execute_query_with_p2p_query_and_exclusion(
            &search_query,
            &state.current_query,
            effective_vector,
            cached_hits_opt,
            access_tier,
            candidate_k,
            &exclude_chunk_ids,
        );
        let entity_fut = async {
            if let Some(ref q) = entity_kw_query_opt {
                engine.local_storage.search_text(q, access_tier, 96).await
            } else {
                Vec::new()
            }
        };
        let prompt_fut = async {
            if let Some(ref q) = prompt_kw_query_opt {
                engine.local_storage.search_text(q, access_tier, 64).await
            } else {
                Vec::new()
            }
        };
        let cue_fut = async {
            if let Some(ref q) = cue_query_opt {
                engine.local_storage.search_text(q, access_tier, 48).await
            } else {
                Vec::new()
            }
        };

        let (
            (mut chunks, mut volatile, _duration, new_vector_hits),
            entity_hits,
            prompt_hits,
            cue_hits,
        ) = tokio::join!(primary_fut, entity_fut, prompt_fut, cue_fut);

        let has_entity_matched_remote = !volatile.is_empty()
            && (prelim_entities.is_empty()
                || chunks.iter().any(|c| {
                    c.is_remote && {
                        let hay = format!(
                            "{} {}",
                            c.chunk.file_path.to_ascii_lowercase(),
                            c.chunk.text_content.to_ascii_lowercase()
                        );
                        prelim_entities
                            .iter()
                            .any(|e| hay.contains(&e.to_ascii_lowercase()))
                    }
                }));

        let local_chunks_satisfy_query = {
            let local_chunks: Vec<&ScoredChunk> = chunks.iter().filter(|c| !c.is_remote).collect();
            if local_chunks.is_empty() {
                false
            } else {
                let max_score = local_chunks.iter().map(|c| c.score).fold(0.0f32, f32::max);
                let has_match = prelim_entities.is_empty() || local_chunks.iter().any(|c| {
                    let hay = format!(
                        "{} {}",
                        c.chunk.file_path.to_ascii_lowercase(),
                        c.chunk.text_content.to_ascii_lowercase()
                    );
                    prelim_entities.iter().any(|e| hay.contains(&e.to_ascii_lowercase()))
                });
                (local_chunks.len() >= 3 && has_match) || max_score >= 0.70 || (max_score >= 0.015 && has_match)
            }
        };

        let peer_count = engine.mesh_dispatcher.peer_count();
        if !local_chunks_satisfy_query && !has_entity_matched_remote && peer_count > 0 {
            if let Some(ref entity_q) = entity_kw_query_opt {
                if !entity_q.eq_ignore_ascii_case(&state.current_query) {
                    let (fb_hits, fb_vol) = engine
                        .search_federated_text_with_volatile(entity_q, access_tier, 48)
                        .await;
                    if !fb_vol.is_empty() {
                        volatile.extend(fb_vol);
                        let mut existing_remote: std::collections::HashSet<(String, String)> = chunks
                            .iter()
                            .filter(|c| c.is_remote)
                            .map(|c| (c.source_peer.clone(), c.chunk.chunk_id.clone()))
                            .collect();
                        for hit in fb_hits.into_iter().filter(|h| h.is_remote) {
                            if existing_remote.insert((hit.source_peer.clone(), hit.chunk.chunk_id.clone())) {
                                chunks.push(hit);
                            }
                        }
                    }
                }
            }
        }
        tracing::info!(chunks = chunks.len(), volatile = volatile.len(), "Finished concurrent execute_query and supplemental federated queries");
        state.peer_diagnostics = engine.last_diagnostics().await;

        if !new_vector_hits.is_empty() && state.cached_vector_hits.is_empty() {
            state.cached_vector_hits = new_vector_hits;
        }

        // Merge supplemental results in exact deterministic order (primary -> entity -> prompt -> cue)
        // preserving exact deduplication and RRF scoring
        if should_run_supplemental {
            let mut seen_ids: std::collections::HashSet<(String, String)> = chunks
                .iter()
                .map(|c| (c.source_peer.clone(), c.chunk.chunk_id.clone()))
                .collect();

            for (idx, mut hit) in entity_hits.into_iter().enumerate() {
                // Normalize supplemental BM25 scores to [0.0, 1.0] RRF scale (1.0 / (60.0 + rank))
                hit.score = 1.0 / (60.0 + idx as f32);
                if seen_ids.insert((hit.source_peer.clone(), hit.chunk.chunk_id.clone())) {
                    chunks.push(hit);
                }
            }

            for (idx, mut hit) in prompt_hits.into_iter().enumerate() {
                hit.score = 1.0 / (60.0 + idx as f32);
                if seen_ids.insert((hit.source_peer.clone(), hit.chunk.chunk_id.clone())) {
                    chunks.push(hit);
                }
            }

            for (idx, mut hit) in cue_hits.into_iter().enumerate() {
                hit.score = 1.0 / (60.0 + idx as f32);
                if seen_ids.insert((hit.source_peer.clone(), hit.chunk.chunk_id.clone())) {
                    chunks.push(hit);
                }
            }
        }

        if let Some(ref filters) = state.query_metadata_filters {
            if let Some(ext) = filters.get("filetype") {
                let target_ext = format!(".{}", ext.trim_start_matches('.'));
                chunks.retain(|c| c.chunk.file_path.ends_with(&target_ext));
            }
        }

        // Extract meaningful query content terms from current_query
        let query_lower = state.current_query.to_ascii_lowercase();
        let requests_code = query_lower.contains("code")
            || query_lower.contains("unit test")
            || query_lower.contains("implement")
            || query_lower.contains("rrfcombiner")
            || query_lower.contains("struct ")
            || query_lower.contains("fn ");

        if (daemon_active || engine.config.exclude_source_code) && !requests_code {
            const EXCLUDED_EXTS: &[&str] = &[
                ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".hpp",
                ".cc", ".cs", ".java", ".go", ".kt", ".rb", ".php", ".swift", ".scala",
                ".sh", ".bash", ".ps1", ".bat", ".cmd", ".sql", ".css", ".scss", ".less",
                ".vue", ".svelte", ".toml", ".yaml", ".yml", ".lock", ".dat", ".log",
                ".tmp", ".bak", ".wbk",
            ];
            chunks.retain(|c| {
                let path_l = c.chunk.file_path.to_ascii_lowercase();
                let text_l = c.chunk.text_content.to_ascii_lowercase();
                let file_l = std::path::Path::new(&c.chunk.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if file_l.starts_with('~')
                    || file_l.starts_with(".~lock")
                    || file_l == "chat.html"
                    || (file_l.starts_with("conversations-") && file_l.ends_with(".json"))
                {
                    return false;
                }
                // Repo trees are excluded as code, except indexed media, user office/PDF documents, and remote peer files.
                let is_media = text_l.contains("[audio document:")
                    || text_l.contains("[image document:")
                    || text_l.contains("[video document:")
                    || text_l.contains("[ocr text]");
                let is_user_doc = file_l.ends_with(".pdf")
                    || file_l.ends_with(".docx")
                    || file_l.ends_with(".doc")
                    || file_l.ends_with(".pptx")
                    || file_l.ends_with(".xlsx")
                    || file_l.ends_with(".rtf")
                    || file_l.ends_with(".odt");
                if !c.is_remote
                    && !is_media
                    && !is_user_doc
                    && (path_l.contains("\\harfile\\") || path_l.contains("/harfile/"))
                {
                    return false;
                }
                // Exclude coding tutorials / Google Colab notebooks / fenced code dumps when user did not ask for code
                if text_l.contains("```python")
                    || text_l.contains("```javascript")
                    || text_l.contains("```js")
                    || text_l.contains("```rust")
                    || text_l.contains("```bash")
                    || text_l.contains("```cpp")
                    || text_l.contains("from google.colab import")
                    || text_l.contains("drive.mount(")
                    || text_l.contains("np.loadtxt(")
                    || text_l.contains("import numpy as np")
                {
                    return false;
                }
                if crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
                    &c.chunk.text_content,
                ) {
                    return false;
                }
                !EXCLUDED_EXTS.iter().any(|ext| file_l.ends_with(ext))
            });
        }

        // Uniformly filter blacklisted session chunks BEFORE entity-coverage and scoring criteria
        if is_continuation_turn || crate::offline_engine::DeterministicOfflineSynthesisEngine::is_exclusion_query(&orig_low) {
            if !state.seen_chunk_ids.is_empty() {
                chunks.retain(|c| !state.seen_chunk_ids.contains(&c.chunk.chunk_id));
            }
        }
        let query_terms: Vec<String> = query_lower
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|w| w.len() >= 3 && !STOPWORDS.contains(w))
            .fold(Vec::new(), |mut acc, w| {
                let s = w.to_string();
                if !acc.contains(&s) {
                    acc.push(s);
                }
                acc
            });

        let mut entity_terms: Vec<String> = if is_continuation_turn {
            subject_low
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|w| {
                    w.len() >= 3
                        && !STOPWORDS.contains(w)
                        && !GENERIC_ATTRIBUTE_TERMS.contains(w)
                })
                .fold(Vec::new(), |mut acc, w| {
                    let s = w.to_string();
                    if !acc.contains(&s) {
                        acc.push(s);
                    }
                    acc
                })
        } else {
            query_terms
                .iter()
                .filter(|t| !GENERIC_ATTRIBUTE_TERMS.contains(&t.as_str()))
                .cloned()
                .collect()
        };

        // Extract document targets from LangExtract verified entities
        let doc_targets: Vec<String> = state
            .extracted_entities
            .iter()
            .filter(|e| e.extraction_class == "document_reference")
            .map(|e| e.extraction_text.to_ascii_lowercase())
            .collect();

        // Incorporate LangExtract named entities into entity_terms
        for ext in &state.extracted_entities {
            if ext.extraction_class == "named_entity" || ext.extraction_class == "technical_term" {
                let lower_term = ext.extraction_text.to_ascii_lowercase();
                for sub in lower_term.split(|c: char| !c.is_alphanumeric()) {
                    let s = sub.trim();
                    if s.len() >= 3 && !entity_terms.iter().any(|e| e == s) {
                        entity_terms.push(s.to_string());
                    }
                }
            }
        }

        if !query_terms.is_empty() && !chunks.is_empty() {
            let asks_education = query_lower.contains("university")
                || query_lower.contains("college")
                || query_lower.contains("school")
                || query_lower.contains("degree")
                || query_lower.contains("education")
                || query_lower.contains("transcript")
                || query_lower.contains("study")
                || query_lower.contains("studied")
                || query_lower.contains("gpa");

            let asks_profile_or_role = query_lower.contains("what does")
                || query_lower.contains("who is")
                || query_lower.contains("resume")
                || query_lower.contains("work")
                || query_lower.contains("job")
                || query_lower.contains("role")
                || query_lower.contains("skill")
                || query_lower.contains("profession")
                || query_lower.contains("experience")
                || query_lower.contains("career")
                || query_lower.contains("background")
                || query_lower.contains("about");

            let asks_image = query_lower.contains("image")
                || query_lower.contains("photo")
                || query_lower.contains("picture")
                || query_lower.contains("screenshot");

            let has_resume_or_bio = chunks.iter().any(|c| {
                let path_l = c.chunk.file_path.to_ascii_lowercase();
                let text_l = c.chunk.text_content.to_ascii_lowercase();
                path_l.contains("resume") || path_l.contains("cv") || path_l.contains("bio")
                    || text_l.contains("professional summary") || text_l.contains("work experience")
                    || text_l.contains("career summary") || text_l.contains("curriculum vitae")
                    || text_l.contains("cissp-certified") || text_l.contains("employment history")
            });

            // Precompute query term forms and proper term forms once upfront to eliminate inner-loop format! allocations
            struct QueryTermInfo {
                term: String,
                plural_s: Option<String>,
                plural_es: Option<String>,
                stem: Option<String>,
                is_entity: bool,
                is_prompt_entity: bool,
            }

            let query_term_info: Vec<QueryTermInfo> = query_terms
                .iter()
                .map(|t| {
                    let (plural_s, plural_es, stem) = if t.len() >= 4 {
                        let p_s = format!("{}s", t);
                        let p_es = format!("{}es", t);
                        let st = t
                            .strip_suffix("es")
                            .or_else(|| t.strip_suffix('s'))
                            .filter(|s| s.len() >= 4)
                            .map(|s| s.to_string());
                        (Some(p_s), Some(p_es), st)
                    } else {
                        (None, None, None)
                    };
                    let is_entity = entity_terms.contains(t);
                    let is_prompt_entity = prompt_only_entities.contains(t);
                    QueryTermInfo {
                        term: t.clone(),
                        plural_s,
                        plural_es,
                        stem,
                        is_entity,
                        is_prompt_entity,
                    }
                })
                .collect();

            struct ProperTermInfo {
                term: String,
                plural_s: Option<String>,
                plural_es: Option<String>,
                stem: Option<String>,
            }

            let proper_term_info: Vec<ProperTermInfo> = proper_terms
                .iter()
                .map(|t| {
                    let (plural_s, plural_es, stem) = if t.len() >= 4 {
                        let p_s = format!("{}s", t);
                        let p_es = format!("{}es", t);
                        let st = t
                            .strip_suffix("es")
                            .or_else(|| t.strip_suffix('s'))
                            .filter(|s| s.len() >= 4)
                            .map(|s| s.to_string());
                        (Some(p_s), Some(p_es), st)
                    } else {
                        (None, None, None)
                    };
                    ProperTermInfo {
                        term: t.clone(),
                        plural_s,
                        plural_es,
                        stem,
                    }
                })
                .collect();

            // Compute score criteria once upfront per chunk
            let precompute_criteria = |c: &ScoredChunk| -> ChunkScoreCriteria {
                let text_l = c.chunk.text_content.to_ascii_lowercase();
                let path_l = c.chunk.file_path.to_ascii_lowercase();
                let file_name_l = std::path::Path::new(&c.chunk.file_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();

                let doc_tokens: std::collections::HashSet<&str> = text_l
                    .split(|ch: char| !ch.is_alphanumeric())
                    .chain(file_name_l.split(|ch: char| !ch.is_alphanumeric()))
                    .filter(|w| !w.is_empty())
                    .collect();

                let check_match = |term: &str, p_s: Option<&str>, p_es: Option<&str>, stem: Option<&str>| -> bool {
                    if doc_tokens.contains(term) {
                        return true;
                    }
                    // OCR left-edge clipping tolerance: "cve" -> "ve" when a 4-digit year token is present
                    if term == "cve"
                        && doc_tokens.contains("ve")
                        && doc_tokens.iter().any(|t| t.len() == 4 && t.chars().all(|ch| ch.is_ascii_digit()))
                    {
                        return true;
                    }
                    // Allow simple plural/singular inflection using pre-formatted string references
                    if let Some(ps) = p_s {
                        if doc_tokens.contains(ps) {
                            return true;
                        }
                    }
                    if let Some(pes) = p_es {
                        if doc_tokens.contains(pes) {
                            return true;
                        }
                    }
                    if let Some(st) = stem {
                        if doc_tokens.contains(st) {
                            return true;
                        }
                    }
                    false
                };

                let mut weighted_hits = 0usize;
                let mut content_matched_terms = 0usize;
                let mut entity_hits = 0usize;
                let mut prompt_entity_hits = 0usize;

                for qt in &query_term_info {
                    let matches_text_or_name = check_match(
                        qt.term.as_str(),
                        qt.plural_s.as_deref(),
                        qt.plural_es.as_deref(),
                        qt.stem.as_deref(),
                    );

                    if matches_text_or_name {
                        weighted_hits += 12;
                        content_matched_terms += 1;
                        if qt.is_entity {
                            entity_hits += 1;
                        }
                        if qt.is_prompt_entity {
                            prompt_entity_hits += 1;
                        }
                    } else if path_l.contains(qt.term.as_str()) {
                        weighted_hits += 1;
                    }
                }
                if content_matched_terms >= 2 {
                    weighted_hits += content_matched_terms * 8;
                }

                let proper_hits = proper_term_info
                    .iter()
                    .filter(|pt| {
                        check_match(
                            pt.term.as_str(),
                            pt.plural_s.as_deref(),
                            pt.plural_es.as_deref(),
                            pt.stem.as_deref(),
                        )
                    })
                    .count();

                let mut intent_bonus = (prompt_entity_hits as i32) * 320;

                // Boost chunks whose filename directly matches query terms (e.g. "African Churches and Gang Violence.docx")
                let file_tokens: std::collections::HashSet<&str> = file_name_l
                    .split(|ch: char| !ch.is_alphanumeric())
                    .filter(|w| !w.is_empty())
                    .collect();
                let file_term_hits = query_term_info
                    .iter()
                    .filter(|qt| {
                        file_tokens.contains(qt.term.as_str())
                            || qt.plural_s.as_ref().map_or(false, |s| file_tokens.contains(s.as_str()))
                            || qt.plural_es.as_ref().map_or(false, |s| file_tokens.contains(s.as_str()))
                    })
                    .count();
                if file_term_hits > 0 {
                    intent_bonus += (file_term_hits as i32) * 180;
                    weighted_hits += file_term_hits * 25;
                }

                // Google LangExtract: Boost document reference targets +200
                let matches_target_doc = !doc_targets.is_empty()
                    && doc_targets.iter().any(|target| {
                        file_name_l.contains(target.as_str()) || path_l.contains(target.as_str())
                    });

                if matches_target_doc {
                    intent_bonus += 200;
                    weighted_hits += 40;
                    content_matched_terms += 1;
                }

                // Filter out ChatGPT export artifacts from dominating profile queries
                if text_l.contains("fileciteturn0file0") || text_l.contains("sandbox:/mnt/data") {
                    intent_bonus -= 300;
                }

                let has_ocr_text = text_l.contains("[ocr text]");
                if !asks_image
                    && !has_ocr_text
                    && content_matched_terms == 0
                    && (text_l.contains("[image document:")
                        || file_name_l.ends_with(".gif")
                        || file_name_l.ends_with(".jpg")
                        || file_name_l.ends_with(".jpeg")
                        || file_name_l.ends_with(".png")
                        || file_name_l.ends_with(".heic"))
                {
                    intent_bonus -= 150;
                }

                if file_name_l == "stuff.txt" || file_name_l.contains("1095-c") {
                    intent_bonus -= 120;
                }

                if asks_education {
                    if text_l.contains("university")
                        || text_l.contains("college")
                        || text_l.contains("transcript")
                        || text_l.contains("master of")
                        || text_l.contains("bachelor of")
                        || text_l.contains("education")
                    {
                        intent_bonus += 90;
                    }
                    if text_l.contains("gpa")
                        || text_l.contains("degree")
                        || text_l.contains("curriculum")
                    {
                        intent_bonus += 40;
                    }
                }

                let asks_author_works = crate::offline_engine::DeterministicOfflineSynthesisEngine::is_authorship_query(&state.original_prompt);
                if asks_profile_or_role && !asks_author_works {
                    if file_name_l.contains("resume")
                        || path_l.contains("resume")
                        || file_name_l.contains("cv")
                    {
                        intent_bonus += 180;
                    }
                    if text_l.contains("professional summary")
                        || text_l.contains("cissp-certified")
                        || text_l.contains("summary")
                        || text_l.contains("experience")
                        || text_l.contains("competencies")
                        || text_l.contains("skills")
                        || text_l.contains("certification")
                        || text_l.contains("education")
                    {
                        intent_bonus += 90;
                    }
                }

                // Authorship / Profile Intent: heavily penalize government legal forms and boilerplate
                let is_g28 = crate::offline_engine::DeterministicOfflineSynthesisEngine::is_g28_or_administrative_boilerplate(
                    &c.chunk.file_path,
                    &c.chunk.text_content,
                );
                if (asks_author_works || (asks_profile_or_role && has_resume_or_bio)) && is_g28 {
                    intent_bonus -= 500;
                }
                if asks_author_works {
                    if file_name_l.contains("paper") || file_name_l.contains("article") || file_name_l.contains("manuscript") || text_l.contains("abstract") || text_l.contains("introduction") || text_l.contains("methodology") || text_l.contains("references") {
                        intent_bonus += 120;
                    }
                }

                // Boost opening / Abstract / Introduction / Overview sections for definitional and entity queries,
                // and deprioritize raw chart axis chunks ("0 20 40 60 80 100") so answers are orchestrated from core prose.
                if c.chunk.line_start <= 45
                    || text_l.contains("abstract")
                    || text_l.contains("introduction")
                    || text_l.contains("professional summary")
                    || text_l.contains("executive summary")
                    || text_l.contains("overview")
                {
                    intent_bonus += 95;
                }
                if text_l.contains("0 20 40 60 80 100") {
                    intent_bonus -= 75;
                }

                if c.chunk.text_content.trim().len() >= 180 {
                    intent_bonus += 20;
                }
                if file_name_l.ends_with(".docx")
                    || file_name_l.ends_with(".pdf")
                    || file_name_l.ends_with(".doc")
                {
                    intent_bonus += 35;
                }
                if !file_name_l.starts_with("recovered_file_") && !file_name_l.starts_with("file_") {
                    intent_bonus += 15;
                }

                // Strictly enforce multi-term entity matching:
                // When 2 specific entity terms are present (e.g. "cover letter", "universal mineral"), require both.
                // When only 1 entity term is paired with a generic attribute term (e.g. "cigna policy"),
                // require the entity term and rank higher if the attribute term also matches.
                let required_entity_hits = if entity_terms.len() == 2 {
                    2
                } else if entity_terms.len() > 2 {
                    ((entity_terms.len() + 1) / 2).max(2).min(entity_terms.len())
                } else if entity_terms.len() == 1 {
                    1
                } else {
                    0
                };
                let required_query_hits = if is_continuation_turn {
                    required_entity_hits.max(1)
                } else if query_terms.len() >= 2 {
                    ((query_terms.len() + 1) / 2).max(2).min(query_terms.len())
                } else {
                    1
                };

                let required_proper_hits = if proper_terms.len() > 2 {
                    proper_terms.len() - 1
                } else {
                    proper_terms.len()
                };
                let proper_ok = proper_hits >= required_proper_hits;
                let is_relevant = ((content_matched_terms >= required_query_hits
                    && entity_hits >= required_entity_hits)
                    || (proper_ok && !proper_terms.is_empty() && content_matched_terms >= proper_terms.len()))
                    || matches_target_doc;

                intent_bonus += crate::offline_engine::DeterministicOfflineSynthesisEngine::answer_type_cue_score(
                    &state.original_prompt,
                    &text_l,
                );
                let total_score = (weighted_hits as i32) * 5 + intent_bonus;

                ChunkScoreCriteria {
                    weighted_hits,
                    content_matched_terms,
                    entity_hits,
                    prompt_entity_hits,
                    intent_bonus,
                    total_score,
                    is_relevant,
                    proper_ok,
                }
            };

            // Stitch multi-chunk remote peer documents BEFORE term-quorum filtering (`paired.retain`)
            // so a remote resume whose header chunk has the person's name and whose body chunk has Education
            // merges into a single complete section instead of losing half its terms!
            if chunks.iter().any(|c| c.is_remote) {
                let (remote_candidates, mut local_candidates): (Vec<ScoredChunk>, Vec<ScoredChunk>) =
                    chunks.into_iter().partition(|c| c.is_remote);
                let stitched_remote =
                    crate::offline_engine::DeterministicOfflineSynthesisEngine::stitch_parent_document_chunks(
                        remote_candidates,
                    );
                local_candidates.extend(stitched_remote);
                chunks = local_candidates;
            }

            // Precompute criteria upfront into static structs for all candidates
            let mut paired: Vec<(ScoredChunk, ChunkScoreCriteria)> = Vec::with_capacity(chunks.len());
            for c in chunks {
                let crit = precompute_criteria(&c);
                paired.push((c, crit));
            }

            let any_lexical_match = paired.iter().any(|(_, crit)| crit.weighted_hits > 0);
            let any_proper_match = !proper_terms.is_empty()
                && paired.iter().any(|(_, crit)| crit.is_relevant && crit.proper_ok);
            let required_prompt_hits = if prompt_only_entities.len() == 2 {
                2
            } else if prompt_only_entities.len() > 2 {
                ((prompt_only_entities.len() + 1) / 2).max(2)
            } else {
                prompt_only_entities.len()
            };
            let any_prompt_entity_match = !prompt_only_entities.is_empty()
                && paired
                    .iter()
                    .any(|(_, crit)| crit.is_relevant && crit.prompt_entity_hits >= required_prompt_hits);
            // A question that asks for a modality ("the song ...", "pictures of ...") keeps that media's
            // chunks whenever they lexically match, even if a text document scores higher on entities.
            let media_prefix = quorum_storage::query_framing::media_content_prefix(
                quorum_storage::query_framing::detect_media_intent(&state.original_prompt),
            );
            if any_lexical_match {
                paired.retain(|(c, crit)| {
                    let wanted_media = media_prefix
                        .map_or(false, |p| c.chunk.text_content.trim_start().starts_with(p) && crit.weighted_hits > 0);
                    c.is_remote
                        || wanted_media
                        || (crit.is_relevant
                            && crit.weighted_hits > 0
                            && crit.intent_bonus > -100
                            && (!any_prompt_entity_match || crit.prompt_entity_hits >= required_prompt_hits)
                            && (!any_proper_match || crit.proper_ok))
                });

                // Zero string allocation comparator: sorts using precomputed total_score
                paired.sort_by(|(chunk_a, crit_a), (chunk_b, crit_b)| {
                    crit_b
                        .total_score
                        .cmp(&crit_a.total_score)
                        .then_with(|| {
                            chunk_b
                                .score
                                .partial_cmp(&chunk_a.score)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                });
            }

            chunks = paired.into_iter().map(|(c, _)| c).collect();
        }

        // Expand adjacent/body chunks (`{doc_id}:0..=4`) for the top matched local multi-chunk documents
        // BEFORE parent-document stitching so multi-page resumes and timelines merge their full career body
        // even when Chunk 0 initially scored highest via its header/title banner.
        {
            let mut seen_local_ids: std::collections::HashSet<String> = chunks
                .iter()
                .filter(|c| c.source_peer == "local")
                .map(|c| c.chunk.chunk_id.clone())
                .collect();
            let mut top_local_docs: Vec<(String, f32)> = Vec::new();
            for item in chunks.iter().filter(|c| c.source_peer == "local") {
                let doc_prefix = if !item.chunk.document_id.is_empty() {
                    item.chunk.document_id.clone()
                } else if let Some((prefix, _)) = item.chunk.chunk_id.rsplit_once(':') {
                    prefix.to_string()
                } else {
                    continue;
                };
                if !top_local_docs.iter().any(|(d, _)| d == &doc_prefix) {
                    top_local_docs.push((doc_prefix, item.score));
                    if top_local_docs.len() >= 4 {
                        break;
                    }
                }
            }
            if !top_local_docs.is_empty() {
                let mut sibling_ids: Vec<String> = Vec::new();
                let mut base_scores: std::collections::HashMap<String, f32> =
                    std::collections::HashMap::new();
                for (doc_id, base_score) in top_local_docs {
                    base_scores.insert(doc_id.clone(), base_score);
                    for idx in 0..=4 {
                        let cid = format!("{}:{}", doc_id, idx);
                        if !seen_local_ids.contains(&cid)
                            && !state.seen_chunk_ids.contains(&cid)
                        {
                            sibling_ids.push(cid);
                        }
                    }
                }
                if !sibling_ids.is_empty() {
                    let extras = engine
                        .local_storage
                        .get_chunks_by_ids(&sibling_ids, access_tier)
                        .await;
                    for extra in extras {
                        if !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
                            &extra.text_content,
                        ) && seen_local_ids.insert(extra.chunk_id.clone())
                        {
                            let base = base_scores
                                .get(&extra.document_id)
                                .copied()
                                .unwrap_or(0.014);
                            chunks.push(quorum_types::ScoredChunk::new(
                                extra,
                                (base * 0.94).max(0.012),
                                "local",
                                false,
                            ));
                        }
                    }
                }
            }
        }

        let ui = crate::dlp_mesh::global_mesh_dlp_controller()
            .settings
            .read()
            .map(|g| g.ui.clone())
            .unwrap_or_default();

        // Stitch adjacent chunks (`0..N`) of each matched file BEFORE per-stem capping so multi-chunk
        // resumes and timelines merge their header + body sections into complete passages first!
        if ui.parent_document_retrieval {
            chunks = crate::offline_engine::DeterministicOfflineSynthesisEngine::stitch_parent_document_chunks(chunks);
        }

        // Cap stitched sections per document family stem across the entire federation (max 2 per stem)
        // so redundant revisions (e.g. Resume_v1.pdf, Resume_v2.pdf, Resume_Final.docx) across local and mesh nodes
        // do not starve search context diversity.
        chunks = Self::cap_document_families_federated(chunks, 2);

        // Snapshot top remote peer chunks (`source_peer != "local"`), prioritizing distinct connected peers first,
        // so federated stitched results from connected computers are interleaved near the top alongside local results.
        let mut preserved_remote: Vec<ScoredChunk> = Vec::new();
        let mut seen_remote_peers: std::collections::HashSet<String> = std::collections::HashSet::new();
        for rc in chunks.iter().filter(|c| c.source_peer != "local") {
            if seen_remote_peers.insert(rc.source_peer.clone()) {
                preserved_remote.push(rc.clone());
                if preserved_remote.len() >= 8 {
                    break;
                }
            }
        }
        if preserved_remote.len() < 8 {
            for rc in chunks.iter().filter(|c| c.source_peer != "local") {
                if !preserved_remote
                    .iter()
                    .any(|p| p.source_peer == rc.source_peer && p.chunk.chunk_id == rc.chunk.chunk_id)
                {
                    preserved_remote.push(rc.clone());
                    if preserved_remote.len() >= 8 {
                        break;
                    }
                }
            }
        }

        // Apply Maximal Marginal Relevance (MMR) candidate diversity selection (default lambda = 0.70)
        chunks = apply_mmr_selection(chunks, effective_vector, top_k, 0.70);

        // Requested modality first (stable; other chunks are kept to ground the answer).
        if let Some(prefix) = quorum_storage::query_framing::media_content_prefix(
            quorum_storage::query_framing::detect_media_intent(&state.original_prompt),
        ) {
            let (mut media, rest): (Vec<ScoredChunk>, Vec<ScoredChunk>) = chunks
                .into_iter()
                .partition(|c| c.chunk.text_content.trim_start().starts_with(prefix));
            media.extend(rest);
            chunks = media;
        }

        chunks.truncate(top_k);

        // Dedicated quota for remote volatile mesh chunks so local sibling expansion
        // and supplemental text queries cannot crowd out remote peer chunks in top-K context packing.
        let remote_quota = preserved_remote.len().min((top_k / 3).max(2));

        // Interleave preserved remote peer chunks right after the #1 local chunk (slots 1..=4) rather than
        // burying them at the tail behind 6+ local files so synthesis and `SOURCES` surface `(mesh)` peers prominently.
        let mut insert_cursor = 1usize.min(chunks.len());
        for rem in preserved_remote.into_iter().take(remote_quota.max(4)) {
            if let Some(existing_idx) = chunks
                .iter()
                .position(|c| c.source_peer == rem.source_peer && c.chunk.chunk_id == rem.chunk.chunk_id)
            {
                if existing_idx <= insert_cursor {
                    insert_cursor = (existing_idx + 1).min(chunks.len());
                    continue;
                }
                chunks.remove(existing_idx);
            } else if chunks.len() >= top_k {
                if let Some(pos) = chunks.iter().rposition(|c| c.source_peer == "local") {
                    chunks.remove(pos);
                } else if !chunks.is_empty() {
                    chunks.pop();
                }
            }
            let target_idx = insert_cursor.min(chunks.len());
            chunks.insert(target_idx, rem);
            insert_cursor = (target_idx + 1).min(chunks.len());
        }
        state.retrieved_chunks = chunks;
        state.volatile_chunks = volatile;
    }
}

/// Maximal Marginal Relevance (MMR) selection algorithm to penalize redundant candidate chunks
/// and maximize topical coverage diversity across the candidate pool.
/// Operates in O(K * M * D) using unit-L2 pre-normalization and incremental max-similarity tracking.
pub fn apply_mmr_selection(
    candidates: Vec<ScoredChunk>,
    _query_vector: &[f32],
    top_k: usize,
    lambda: f32, // default 0.70
) -> Vec<ScoredChunk> {
    if candidates.len() <= top_k {
        return candidates;
    }

    let embedder = quorum_contract::DeterministicOfflineEngine::new();
    let num_candidates = candidates.len();

    // 1. Pre-normalize candidate vectors to unit L2 norm once upfront.
    // If norm is 0.0 or vector is empty, normalized vector is kept empty and has_valid_norm is false.
    let mut norm_vectors: Vec<Vec<f32>> = Vec::with_capacity(num_candidates);
    let mut has_valid_norm: Vec<bool> = Vec::with_capacity(num_candidates);

    for c in &candidates {
        let raw_vec = if !c.chunk.vector.is_empty() {
            c.chunk.vector.clone()
        } else {
            embedder.embed_text(&c.chunk.text_content).unwrap_or_default()
        };
        let norm_sq: f32 = raw_vec.iter().map(|&x| x * x).sum();
        if norm_sq > 0.0 {
            let inv_norm = 1.0 / norm_sq.sqrt();
            norm_vectors.push(raw_vec.into_iter().map(|x| x * inv_norm).collect());
            has_valid_norm.push(true);
        } else {
            norm_vectors.push(raw_vec);
            has_valid_norm.push(false);
        }
    }

    let fast_sim = |idx_a: usize, idx_b: usize| -> f32 {
        if !has_valid_norm[idx_a] || !has_valid_norm[idx_b] {
            return 0.0;
        }
        let a = &norm_vectors[idx_a];
        let b = &norm_vectors[idx_b];
        if a.len() != b.len() {
            return 0.0;
        }
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        dot.clamp(-1.0, 1.0)
    };

    let max_score = candidates.iter().map(|c| c.score).fold(0.001f32, f32::max);
    let mut remaining_indices: Vec<usize> = (0..candidates.len()).collect();
    let mut selected_indices: Vec<usize> = Vec::with_capacity(top_k);

    // 2. Seed selected with the highest relevance candidate
    let first_pos = remaining_indices
        .iter()
        .enumerate()
        .max_by(|(_, &a), (_, &b)| {
            candidates[a]
                .score
                .partial_cmp(&candidates[b].score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(pos, _)| pos)
        .unwrap_or(0);

    let first_selected = remaining_indices.remove(first_pos);
    selected_indices.push(first_selected);

    // 3. Maintain incremental max similarity to any selected candidate for all remaining candidates
    let mut max_sim_to_selected: Vec<f32> = vec![0.0; num_candidates];
    for &cand_idx in &remaining_indices {
        max_sim_to_selected[cand_idx] = fast_sim(cand_idx, first_selected).max(0.0);
    }

    // 4. Greedily select top_k items with O(M) evaluations per step
    while selected_indices.len() < top_k && !remaining_indices.is_empty() {
        let mut best_pos = 0;
        let mut best_mmr = f32::NEG_INFINITY;

        for (pos, &cand_idx) in remaining_indices.iter().enumerate() {
            let cand_score = candidates[cand_idx].score;
            let norm_rel = cand_score / max_score;
            let max_sim = max_sim_to_selected[cand_idx];

            let mmr_score = lambda * norm_rel - (1.0 - lambda) * max_sim;
            if mmr_score > best_mmr {
                best_mmr = mmr_score;
                best_pos = pos;
            }
        }

        let newly_selected = remaining_indices.remove(best_pos);
        selected_indices.push(newly_selected);

        // Incremental update: update max_sim_to_selected ONLY against the newly chosen candidate
        for &cand_idx in &remaining_indices {
            let sim = fast_sim(cand_idx, newly_selected);
            if sim > max_sim_to_selected[cand_idx] {
                max_sim_to_selected[cand_idx] = sim;
            }
        }
    }

    let mut selected_chunks = Vec::with_capacity(selected_indices.len());
    let mut cand_opt: Vec<Option<ScoredChunk>> = candidates.into_iter().map(Some).collect();
    for idx in selected_indices {
        if let Some(chunk) = cand_opt[idx].take() {
            selected_chunks.push(chunk);
        }
    }

    selected_chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::PeerAclManager;
    use crate::config::CoordinatorConfig;
    use crate::mesh::{MockMeshDispatcher, MockRemotePeer};
    use crate::offline_engine::DeterministicOfflineSynthesisEngine;
    use crate::scatter_gather::StorageSearcher;
    use crate::types::SynthesisModelFamily;
    use quorum_types::{CandidateChunkDto, DocumentChunk};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    struct InMemoryLocalResumeStorage {
        chunks: Vec<DocumentChunk>,
    }

    #[async_trait::async_trait]
    impl StorageSearcher for InMemoryLocalResumeStorage {
        async fn search_hybrid(
            &self,
            _query_text: &str,
            _query_vec: &[f32],
            max_tier: u8,
            _top_k: usize,
        ) -> Vec<ScoredChunk> {
            self.chunks
                .iter()
                .filter(|c| c.access_tier <= max_tier)
                .map(|c| ScoredChunk::new(c.clone(), 0.89, "local", false))
                .collect()
        }

        async fn get_chunks_by_ids(
            &self,
            chunk_ids: &[String],
            max_tier: u8,
        ) -> Vec<DocumentChunk> {
            self.chunks
                .iter()
                .filter(|c| c.access_tier <= max_tier && chunk_ids.contains(&c.chunk_id))
                .cloned()
                .collect()
        }
    }

    #[tokio::test]
    async fn test_resume_timeline_roles_query_stitches_remote_timeline_and_preserves_local_resumes() {
        let embedder = quorum_contract::DeterministicOfflineEngine::new();
        let vec768 = embedder.embed_text("Femi Oyesanya AI Security Resume Timeline").unwrap();

        let local_resume = DocumentChunk::new(
            "local_cv_doc:0",
            "local_cv_doc",
            r"C:\Users\oyesanyf\Documents\Femi_Oyesanya_Enhanced_Resume_v3.docx",
            1,
            40,
            0,
            vec768.clone(),
            "Femi Oyesanya, CISSP | Principal Application & AI Security Engineer (2020–2026) | Senior Cloud Security Architect (2015–2020).",
            None,
        )
        .unwrap();

        let local_paper = DocumentChunk::new(
            "local_paper_doc:0",
            "local_paper_doc",
            r"C:\Users\oyesanyf\Documents\RedactX_v3_arXiv_Femi_Oyesanya.pdf",
            1,
            25,
            0,
            vec768.clone(),
            "RedactX-v3: Clinical De-Identification System. Femi Oyesanya, Independent Researcher, October 2026.",
            None,
        )
        .unwrap();

        let local_storage = Arc::new(InMemoryLocalResumeStorage {
            chunks: vec![local_resume, local_paper],
        });

        let remote_peer_id = "12D3KooWEcNhbaJtvJCF6QqvWwzxWTXBMfMqvxrRbxKbAZ2ZvKR5";
        let remote_chunks = vec![
            CandidateChunkDto {
                chunk_id: "remote_pdf_doc:0".to_string(),
                file_path: r"D:\Shared\Femi_Oyesanya_AI_Security_Resume_Timeline_Fixed.pdf".to_string(),
                line_start: 1,
                line_end: 18,
                content: "Femi Oyesanya — AI Security Resume Timeline | LinkedIn: linkedin.com/in/femioyesanya | GitHub: github.com/oyesanyf".to_string(),
                score: 0.96,
                access_tier: 0,
            },
            CandidateChunkDto {
                chunk_id: "remote_pdf_doc:1".to_string(),
                file_path: r"D:\Shared\Femi_Oyesanya_AI_Security_Resume_Timeline_Fixed.pdf".to_string(),
                line_start: 19,
                line_end: 65,
                content: "Career Timeline: 2022–Present: Principal AI Security Architect — Led LLM & Agentic RAG containment. 2018–2022: Lead Application Security Engineer — Directed SDLC threat modeling and cloud security.".to_string(),
                score: 0.91,
                access_tier: 0,
            },
            CandidateChunkDto {
                chunk_id: "remote_docx_doc:0".to_string(),
                file_path: r"D:\Shared\Femi_Oyesanya_AI_Security_Resume_Timeline_Fixed.docx".to_string(),
                line_start: 1,
                line_end: 18,
                content: "Femi Oyesanya — AI Security Resume Timeline | LinkedIn: linkedin.com/in/femioyesanya | GitHub: github.com/oyesanyf".to_string(),
                score: 0.93,
                access_tier: 0,
            },
            CandidateChunkDto {
                chunk_id: "remote_docx_doc:1".to_string(),
                file_path: r"D:\Shared\Femi_Oyesanya_AI_Security_Resume_Timeline_Fixed.docx".to_string(),
                line_start: 19,
                line_end: 65,
                content: "Career Timeline: 2022–Present: Principal AI Security Architect | 2014–2018: Senior Information Security Consultant.".to_string(),
                score: 0.89,
                access_tier: 0,
            },
        ];

        let mesh = MockMeshDispatcher::new();
        mesh.add_peer(MockRemotePeer {
            peer_id: remote_peer_id.to_string(),
            latency: Duration::from_millis(5),
            max_access_tier: 0,
            candidate_chunks: remote_chunks,
        })
        .await;

        let engine = ScatterGatherEngine::new(
            local_storage,
            Arc::new(mesh),
            Arc::new(RwLock::new(PeerAclManager::default())),
            CoordinatorConfig::default(),
            [7u8; 32],
            "12D3KooWDRDLdpC9DeyiHMfpTMUVrDz73vgYXKjQPJKWgtiaqtrL".to_string(),
        );

        let prompt = "What roles has Femi Oyesanya held according to the resume timeline?";
        let mut state = AgenticGraphState::new(prompt, SynthesisModelFamily::AutoFusion, 3);
        let q_vec = embedder.embed_text(prompt).unwrap();

        RetrieveMeshNode::execute(&mut state, &engine, &q_vec, 0, 12).await;

        assert!(
            !state.retrieved_chunks.is_empty(),
            "Expected fused local + mesh resume chunks"
        );

        // 1. Remote timeline body chunk (`Principal AI Security Architect`) MUST be stitched and retained
        //    even when both `.pdf` and `.docx` share the same stem and have Chunk 0 headers!
        let has_remote_timeline_roles = state.retrieved_chunks.iter().any(|c| {
            c.is_remote
                && c.source_peer == remote_peer_id
                && c.chunk.text_content.contains("Principal AI Security Architect")
                && c.chunk.text_content.contains("Lead Application Security Engineer")
        });
        assert!(
            has_remote_timeline_roles,
            "Remote timeline body roles must be stitched into retrieved chunks without header starvation: {:?}",
            state
                .retrieved_chunks
                .iter()
                .map(|c| (&c.source_peer, &c.chunk.file_path, &c.chunk.text_content))
                .collect::<Vec<_>>()
        );

        // 2. Local resume (`Femi_Oyesanya_Enhanced_Resume_v3.docx`) MUST NOT be filtered out by
        //    query-framing words (`according`, `held`, `timeline`)
        let has_local_resume = state.retrieved_chunks.iter().any(|c| {
            !c.is_remote
                && c.chunk
                    .file_path
                    .contains("Femi_Oyesanya_Enhanced_Resume_v3.docx")
        });
        assert!(
            has_local_resume,
            "Local resume must remain in retrieved chunks despite framing words 'according'/'held'/'timeline'"
        );

        // 3. Per-source citation attribution must preserve remote PeerId on mesh chunks and None/local on local chunks
        let remote_cit = state
            .retrieved_chunks
            .iter()
            .find(|c| c.is_remote)
            .unwrap()
            .to_citation();
        assert!(remote_cit.is_external_node);
        assert_eq!(remote_cit.node_id.as_deref(), Some(remote_peer_id));

        let local_cit = state
            .retrieved_chunks
            .iter()
            .find(|c| !c.is_remote)
            .unwrap()
            .to_citation();
        assert!(!local_cit.is_external_node);
        assert!(local_cit.node_id.is_none());

        // 4. Deterministic synthesis produces concrete role titles
        let (answer, _) = DeterministicOfflineSynthesisEngine::synthesize(
            prompt,
            &state.retrieved_chunks,
            "AutoFusion",
        );
        assert!(
            answer.contains("Principal AI Security Architect"),
            "Synthesized answer should cite concrete roles from timeline: {answer}"
        );
    }
}
