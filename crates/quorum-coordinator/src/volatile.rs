pub use quorum_types::VolatileRemoteChunk;
use quorum_types::CandidateChunkDto;
use zeroize::Zeroize;

/// Ingests remote candidate chunk DTOs into volatile memory protected structs.
pub fn wrap_candidates(
    peer_id: &str,
    dtos: Vec<CandidateChunkDto>,
) -> Vec<VolatileRemoteChunk> {
    dtos.into_iter()
        .map(|dto| dto.into_volatile_remote_chunk(peer_id))
        .collect()
}

/// Explicitly zeroizes volatile remote chunk memory buffers.
pub fn scrub_volatile(chunks: &mut [VolatileRemoteChunk]) {
    for chunk in chunks.iter_mut() {
        chunk.content.zeroize();
    }
}
