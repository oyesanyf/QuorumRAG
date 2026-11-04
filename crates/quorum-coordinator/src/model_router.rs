use crate::hardware::HardwareTelemetry;
use crate::types::SynthesisModelFamily;
use quorum_types::ScoredChunk;

pub struct AutoFusionRouter;

impl AutoFusionRouter {
    /// Minimum runtime free RAM (GB) required to run Gemma 4 26B on CPU/hybrid without OOM.
    pub const GEMMA4_26B_MIN_FREE_RAM_GB: f64 = 18.0;
    /// Minimum runtime free VRAM (MB) required to run Gemma 4 26B on GPU without host RAM spill.
    pub const GEMMA4_26B_MIN_FREE_VRAM_MB: u64 = 16_384;

    /// Evaluates strictly runtime free/available memory (never total physical RAM) for `gemma4:26b`.
    pub fn can_run_gemma4_26b(hw: &HardwareTelemetry) -> bool {
        hw.free_ram_gb >= Self::GEMMA4_26B_MIN_FREE_RAM_GB
            || hw.free_vram_mb >= Self::GEMMA4_26B_MIN_FREE_VRAM_MB
    }

    /// Selects model family, tag, and rationale based on intent, retrieved chunks, and hardware telemetry.
    pub fn select_model(
        requested_family: SynthesisModelFamily,
        prompt: &str,
        chunks: &[ScoredChunk],
        hw: &HardwareTelemetry,
    ) -> (SynthesisModelFamily, String, String) {
        Self::select_model_calibrated(requested_family, prompt, chunks, hw, &[])
    }

    /// Selects model family, tag, and rationale calibrated against the host's actual installed models.
    /// Strictly prevents routing to uninstalled models (e.g. `gemma2:2b`) or memory-ineligible models.
    pub fn select_model_calibrated(
        requested_family: SynthesisModelFamily,
        prompt: &str,
        chunks: &[ScoredChunk],
        hw: &HardwareTelemetry,
        installed_models: &[String],
    ) -> (SynthesisModelFamily, String, String) {
        match requested_family {
            SynthesisModelFamily::Glm4Agentic => {
                if installed_models.is_empty() {
                    (
                        SynthesisModelFamily::Glm4Agentic,
                        "glm4:9b".to_string(),
                        "GLM-4-9B explicitly selected (128K context window)".to_string(),
                    )
                } else if let Some(matched) = Self::find_best_installed_chat_model(Some("glm4:9b"), hw, installed_models) {
                    if matched.to_ascii_lowercase().starts_with("glm4") {
                        (
                            SynthesisModelFamily::Glm4Agentic,
                            matched,
                            "GLM-4-9B explicitly selected and confirmed installed".to_string(),
                        )
                    } else {
                        (
                            SynthesisModelFamily::Glm4Agentic,
                            matched.clone(),
                            format!("GLM-4-9B requested but not installed -> calibrated to installed chat model {}", matched),
                        )
                    }
                } else {
                    let fallback = Self::size_qwen_by_hardware(hw);
                    (
                        SynthesisModelFamily::Glm4Agentic,
                        fallback.clone(),
                        format!("GLM-4-9B requested but not installed; recommended tier: {}", fallback),
                    )
                }
            }
            SynthesisModelFamily::Qwen25Code => {
                let ideal_tag = Self::size_qwen_by_hardware(hw);
                if installed_models.is_empty() {
                    (
                        SynthesisModelFamily::Qwen25Code,
                        ideal_tag,
                        "Qwen 2.5 Code selected with hardware-sized parameter tier".to_string(),
                    )
                } else if let Some(matched) = Self::find_best_installed_chat_model(Some(&ideal_tag), hw, installed_models) {
                    (
                        SynthesisModelFamily::Qwen25Code,
                        matched.clone(),
                        format!("Qwen 2.5 Code calibrated to installed {}", matched),
                    )
                } else {
                    (
                        SynthesisModelFamily::Qwen25Code,
                        ideal_tag.clone(),
                        format!("Qwen 2.5 Code recommended tier: {}", ideal_tag),
                    )
                }
            }
            SynthesisModelFamily::GemmaProse => {
                let ideal_tag = Self::size_gemma_by_hardware(hw);
                if installed_models.is_empty() {
                    (
                        SynthesisModelFamily::GemmaProse,
                        ideal_tag,
                        "Gemma Prose selected for natural language synthesis".to_string(),
                    )
                } else if let Some(matched) = Self::find_best_installed_chat_model(Some(&ideal_tag), hw, installed_models) {
                    (
                        SynthesisModelFamily::GemmaProse,
                        matched.clone(),
                        format!("Gemma Prose calibrated to installed {}", matched),
                    )
                } else {
                    (
                        SynthesisModelFamily::GemmaProse,
                        ideal_tag.clone(),
                        format!("Gemma Prose recommended tier: {}", ideal_tag),
                    )
                }
            }
            SynthesisModelFamily::Gemma4_26b => {
                if Self::can_run_gemma4_26b(hw) {
                    if installed_models.is_empty() {
                        (
                            SynthesisModelFamily::Gemma4_26b,
                            "gemma4:26b".to_string(),
                            format!(
                                "Gemma 4 26B selected (runtime free RAM {:.1} GB, free VRAM {} MB satisfies memory gate)",
                                hw.free_ram_gb, hw.free_vram_mb
                            ),
                        )
                    } else if let Some(matched) = Self::find_best_installed_chat_model(Some("gemma4:26b"), hw, installed_models) {
                        (
                            SynthesisModelFamily::Gemma4_26b,
                            matched.clone(),
                            format!("Gemma 4 26B calibrated to installed {}", matched),
                        )
                    } else {
                        let fallback = Self::size_qwen_by_hardware(hw);
                        (
                            SynthesisModelFamily::Gemma4_26b,
                            fallback.clone(),
                            format!("Gemma 4 26B not installed; fallback to {}", fallback),
                        )
                    }
                } else {
                    let fallback_ideal = Self::size_gemma_by_hardware(hw);
                    if installed_models.is_empty() {
                        (
                            SynthesisModelFamily::GemmaProse,
                            fallback_ideal.clone(),
                            format!(
                                "Gemma 4 26B gated by runtime free memory ({:.1} GB free RAM, {} MB free VRAM < 18 GB / 16 GB) -> {}",
                                hw.free_ram_gb, hw.free_vram_mb, fallback_ideal
                            ),
                        )
                    } else if let Some(matched) = Self::find_best_installed_chat_model(Some(&fallback_ideal), hw, installed_models) {
                        (
                            SynthesisModelFamily::GemmaProse,
                            matched.clone(),
                            format!("Gemma 4 26B gated by memory -> calibrated to installed {}", matched),
                        )
                    } else {
                        (
                            SynthesisModelFamily::GemmaProse,
                            fallback_ideal.clone(),
                            format!("Gemma 4 26B gated by memory -> {}", fallback_ideal),
                        )
                    }
                }
            }
            SynthesisModelFamily::AutoFusion => {
                let lower = prompt.to_lowercase();
                let has_code_keywords = lower.contains("fn ")
                    || lower.contains("def ")
                    || lower.contains("impl ")
                    || lower.contains("struct ")
                    || lower.contains("rust")
                    || lower.contains("python")
                    || lower.contains("typescript")
                    || lower.contains("code");

                let code_chunks_count = chunks
                    .iter()
                    .filter(|c| {
                        let p = c.chunk.file_path.to_lowercase();
                        p.ends_with(".rs")
                            || p.ends_with(".py")
                            || p.ends_with(".ts")
                            || p.ends_with(".js")
                            || p.ends_with(".go")
                            || p.ends_with(".cpp")
                    })
                    .count();

                if has_code_keywords || (!chunks.is_empty() && code_chunks_count * 2 >= chunks.len()) {
                    let ideal_tag = Self::size_qwen_by_hardware(hw);
                    if installed_models.is_empty() {
                        return (
                            SynthesisModelFamily::Qwen25Code,
                            ideal_tag,
                            format!(
                                "AutoFusion: query/chunks dominated by code ({}/{} chunks) -> Qwen 2.5 Code",
                                code_chunks_count,
                                chunks.len()
                            ),
                        );
                    }
                    let chosen_tag = Self::find_best_installed_chat_model(Some(&ideal_tag), hw, installed_models)
                        .unwrap_or(ideal_tag);
                    return (
                        SynthesisModelFamily::Qwen25Code,
                        chosen_tag.clone(),
                        format!(
                            "AutoFusion: code-dominated ({}/{} chunks) -> calibrated to installed {}",
                            code_chunks_count,
                            chunks.len(),
                            chosen_tag
                        ),
                    );
                }

                // If multi-document context > 16KB or multi-hop (> 6 chunks) -> GLM-4-9B or Gemma 4 26B
                let total_chars: usize = chunks.iter().map(|c| c.chunk.text_content.len()).sum();
                if total_chars > 16_000 || chunks.len() > 6 {
                    if installed_models.is_empty() {
                        return (
                            SynthesisModelFamily::Glm4Agentic,
                            "glm4:9b".to_string(),
                            format!(
                                "AutoFusion: heavy multi-document context ({} chars across {} chunks) -> GLM-4-9B (128K context)",
                                total_chars,
                                chunks.len()
                            ),
                        );
                    }
                    let pref = if Self::can_run_gemma4_26b(hw) { "gemma4:26b" } else { "glm4:9b" };
                    let chosen_tag = Self::find_best_installed_chat_model(Some(pref), hw, installed_models)
                        .unwrap_or_else(|| "glm4:9b".to_string());
                    return (
                        SynthesisModelFamily::Glm4Agentic,
                        chosen_tag.clone(),
                        format!(
                            "AutoFusion: heavy multi-doc context ({} chars) -> calibrated to installed {}",
                            total_chars,
                            chosen_tag
                        ),
                    );
                }

                // Default general QA / prose
                if installed_models.is_empty() {
                    if hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4500 {
                        (
                            SynthesisModelFamily::Glm4Agentic,
                            "glm4:9b".to_string(),
                            "AutoFusion: high hardware headroom -> GLM-4-9B default reasoning".to_string(),
                        )
                    } else {
                        (
                            SynthesisModelFamily::GemmaProse,
                            "gemma2:2b".to_string(),
                            "AutoFusion: constrained hardware -> lightweight Gemma 2B".to_string(),
                        )
                    }
                } else {
                    let preferred_target = if Self::can_run_gemma4_26b(hw) {
                        "gemma4:26b"
                    } else if hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4500 {
                        "glm4:9b"
                    } else {
                        let qwen_sz = Self::size_qwen_by_hardware(hw);
                        if qwen_sz == "qwen2.5:1.5b" {
                            "qwen2.5:1.5b"
                        } else {
                            "qwen2.5:3b"
                        }
                    };

                    if let Some(matched) = Self::find_best_installed_chat_model(Some(preferred_target), hw, installed_models) {
                        let fam = if matched.to_ascii_lowercase().starts_with("gemma4") {
                            SynthesisModelFamily::Gemma4_26b
                        } else if matched.to_ascii_lowercase().starts_with("glm") {
                            SynthesisModelFamily::Glm4Agentic
                        } else if matched.to_ascii_lowercase().starts_with("qwen") {
                            SynthesisModelFamily::Qwen25Code
                        } else {
                            SynthesisModelFamily::GemmaProse
                        };
                        (
                            fam,
                            matched.clone(),
                            format!("AutoFusion: host-calibrated -> installed model {}", matched),
                        )
                    } else {
                        let fallback = Self::size_qwen_by_hardware(hw);
                        (
                            SynthesisModelFamily::Qwen25Code,
                            fallback.clone(),
                            format!("AutoFusion: no installed models fit; recommended tier {}", fallback),
                        )
                    }
                }
            }
        }
    }

    /// Evaluates whether a model tag represents an embedding-only model.
    pub fn is_embedding_model(tag: &str) -> bool {
        let low = tag.to_ascii_lowercase();
        low.contains("embed")
            || low.starts_with("bge-")
            || low.contains("nomic-embed")
            || low.contains("minilm")
    }

    /// Evaluates whether a model tag represents a vision/multimodal specialist model.
    pub fn is_vision_model(tag: &str) -> bool {
        let low = tag.to_ascii_lowercase();
        low.starts_with("moondream")
            || low.starts_with("llava")
            || low.starts_with("minicpm-v")
            || low.starts_with("qwen2.5-vl")
            || low.contains("-vl")
    }

    /// Evaluates whether a model is eligible for general text chat synthesis.
    pub fn is_synthesis_chat_model(tag: &str) -> bool {
        !Self::is_embedding_model(tag) && !Self::is_vision_model(tag)
    }

    /// Capability score for model ranking (higher parameter tiers prioritized).
    pub fn model_capability_score(tag: &str) -> u32 {
        let low = tag.to_ascii_lowercase();
        if low.contains("70b") {
            700
        } else if low.contains("32b") {
            320
        } else if low.contains("26b") || low.contains("27b") {
            260
        } else if low.contains("14b") || low.contains("13b") || low.contains("12b") {
            140
        } else if low.contains("9b") || low.contains("8b") || low.contains("7b") {
            80
        } else if low.contains("4b") || low.contains("3b") {
            35
        } else if low.contains("1.5b") || low.contains("2b") {
            20
        } else if low.contains("0.5b") {
            10
        } else {
            15
        }
    }

    /// Finds the best installed chat model matching the hardware tier and fitting free memory.
    pub fn find_best_installed_chat_model(
        preferred_tag: Option<&str>,
        hw: &HardwareTelemetry,
        installed_models: &[String],
    ) -> Option<String> {
        if installed_models.is_empty() {
            return None;
        }

        let mut eligible: Vec<&String> = installed_models
            .iter()
            .filter(|m| Self::is_synthesis_chat_model(m) && Self::model_fits_free_memory(m, hw))
            .collect();

        if eligible.is_empty() {
            return None;
        }

        // 1. If preferred_tag is specified, check for exact match or model:tag match
        if let Some(pref) = preferred_tag {
            let pref_low = pref.trim().to_ascii_lowercase();
            let pref_latest = format!("{}:latest", pref_low);
            if let Some(found) = eligible.iter().find(|m| {
                let ml = m.to_ascii_lowercase();
                ml == pref_low || ml == pref_latest || ml.starts_with(&format!("{}:", pref_low))
            }) {
                return Some((*found).clone());
            }
        }

        // 2. Sort eligible models by capability score descending
        eligible.sort_by(|a, b| {
            let score_b = Self::model_capability_score(b);
            let score_a = Self::model_capability_score(a);
            score_b.cmp(&score_a)
        });

        Some(eligible[0].clone())
    }

    /// Evaluates strictly runtime free RAM / free VRAM against model parameter size.
    pub fn model_fits_free_memory(tag: &str, hw: &HardwareTelemetry) -> bool {
        let low = tag.trim().to_ascii_lowercase();
        if low.contains("32b") || low.contains("70b") {
            hw.free_ram_gb >= 48.0 || hw.free_vram_mb >= 24_000
        } else if low.contains("26b") || low.contains("27b") || low.starts_with("glm-4.7") {
            Self::can_run_gemma4_26b(hw)
        } else if low.contains("14b") || low.contains("12b") || low.contains("13b") {
            hw.free_ram_gb >= 24.0 || hw.free_vram_mb >= 14_000
        } else if low.contains("9b") || low.contains("8b") || low.contains("7b") {
            hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4_500
        } else if low.contains("4b") || low.contains("3b") {
            hw.free_ram_gb >= 6.0 || hw.free_vram_mb >= 2_000
        } else {
            true
        }
    }

    /// Ollama Dynamic Memory Law: Size Qwen strictly by runtime free RAM/VRAM.
    /// Never appends `-coder` suffixes.
    pub fn size_qwen_by_hardware(hw: &HardwareTelemetry) -> String {
        if hw.free_ram_gb >= 48.0 || hw.free_vram_mb >= 24_000 {
            "qwen2.5:32b".to_string()
        } else if hw.free_ram_gb >= 24.0 || hw.free_vram_mb >= 14_000 {
            "qwen2.5:14b".to_string()
        } else if hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4_500 {
            "qwen2.5:7b".to_string()
        } else if hw.free_ram_gb >= 6.0 || hw.free_vram_mb >= 2_000 {
            "qwen2.5:3b".to_string()
        } else {
            "qwen2.5:1.5b".to_string()
        }
    }

    pub fn size_gemma_by_hardware(hw: &HardwareTelemetry) -> String {
        if Self::can_run_gemma4_26b(hw) {
            "gemma4:26b".to_string()
        } else if hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 6_000 {
            "gemma2:9b".to_string()
        } else if hw.free_ram_gb >= 6.0 || hw.free_vram_mb >= 3_000 {
            "gemma3:4b".to_string()
        } else {
            "gemma2:2b".to_string()
        }
    }
}
