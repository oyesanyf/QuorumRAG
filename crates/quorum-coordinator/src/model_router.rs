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
        match requested_family {
            SynthesisModelFamily::Glm4Agentic => (
                SynthesisModelFamily::Glm4Agentic,
                "glm4:9b".to_string(),
                "GLM-4-9B explicitly selected (128K context window)".to_string(),
            ),
            SynthesisModelFamily::Qwen25Code => {
                let tag = Self::size_qwen_by_hardware(hw);
                (
                    SynthesisModelFamily::Qwen25Code,
                    tag,
                    "Qwen 2.5 Code selected with hardware-sized parameter tier".to_string(),
                )
            }
            SynthesisModelFamily::GemmaProse => {
                let tag = Self::size_gemma_by_hardware(hw);
                (
                    SynthesisModelFamily::GemmaProse,
                    tag,
                    "Gemma Prose selected for natural language synthesis".to_string(),
                )
            }
            SynthesisModelFamily::Gemma4_26b => {
                if Self::can_run_gemma4_26b(hw) {
                    (
                        SynthesisModelFamily::Gemma4_26b,
                        "gemma4:26b".to_string(),
                        format!(
                            "Gemma 4 26B selected (runtime free RAM {:.1} GB, free VRAM {} MB satisfies memory gate)",
                            hw.free_ram_gb, hw.free_vram_mb
                        ),
                    )
                } else {
                    let fallback = Self::size_gemma_by_hardware(hw);
                    (
                        SynthesisModelFamily::GemmaProse,
                        fallback.clone(),
                        format!(
                            "Gemma 4 26B gated by runtime free memory ({:.1} GB free RAM, {} MB free VRAM < 18 GB / 16 GB) -> {}",
                            hw.free_ram_gb, hw.free_vram_mb, fallback
                        ),
                    )
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
                    let tag = Self::size_qwen_by_hardware(hw);
                    return (
                        SynthesisModelFamily::Qwen25Code,
                        tag,
                        format!(
                            "AutoFusion: query/chunks dominated by code ({}/{} chunks) -> Qwen 2.5 Code",
                            code_chunks_count,
                            chunks.len()
                        ),
                    );
                }

                // If multi-document context > 16KB or multi-hop (> 6 chunks) -> GLM-4-9B (128K context)
                let total_chars: usize = chunks.iter().map(|c| c.chunk.text_content.len()).sum();
                if total_chars > 16_000 || chunks.len() > 6 {
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

                // Default general QA / prose -> GLM-4-9B or Gemma
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
            }
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
