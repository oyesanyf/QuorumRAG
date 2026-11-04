#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    pub timeout_ms: u64,
    pub max_drift_secs: i64,
    pub rrf_k: f32,
    pub default_top_k: usize,
    pub candidate_multiplier: usize,
    pub default_peer_access_tier: u8,
    pub exclude_source_code: bool,
    pub max_peer_responses: usize,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 400,
            max_drift_secs: 60,
            rrf_k: 60.0,
            default_top_k: 10,
            candidate_multiplier: 2,
            default_peer_access_tier: 0,
            exclude_source_code: true,
            max_peer_responses: 8,
        }
    }
}
