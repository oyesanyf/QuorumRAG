use crate::error::CoordinatorError;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use quorum_types::{AccessTier, FederatedQueryRequest};
use uuid::Uuid;

/// Produces canonical byte representation for Ed25519 query signature.
pub fn canonical_query_bytes(
    query_id: Uuid,
    sender_peer_id: &str,
    timestamp: i64,
    access_tier: AccessTier,
    top_k: usize,
    embedding: &[f32],
    query_text: &str,
) -> Vec<u8> {
    let mut emb_hasher = blake3::Hasher::new();
    for &val in embedding {
        emb_hasher.update(&val.to_le_bytes());
    }
    let embedding_hash = emb_hasher.finalize();

    let mut bytes = Vec::with_capacity(64 + sender_peer_id.len() + query_text.len());
    bytes.extend_from_slice(b"QUORUM_QUERY_V2\n");
    bytes.extend_from_slice(query_id.as_bytes());
    bytes.extend_from_slice(sender_peer_id.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.push(access_tier.as_u8());
    bytes.extend_from_slice(&(top_k as u32).to_le_bytes());
    bytes.extend_from_slice(embedding_hash.as_bytes());
    bytes.extend_from_slice(query_text.as_bytes());
    bytes
}

/// Computes an authentic Ed25519 signature over canonical query payload using a 32-byte secret seed.
#[allow(clippy::too_many_arguments)]
pub fn sign_query(
    secret_seed: &[u8; 32],
    query_id: Uuid,
    sender_peer_id: &str,
    timestamp: i64,
    access_tier: AccessTier,
    top_k: usize,
    embedding: &[f32],
    query_text: &str,
) -> (VerifyingKey, [u8; 64]) {
    let signing_key = SigningKey::from_bytes(secret_seed);
    let verifying_key = signing_key.verifying_key();
    let bytes = canonical_query_bytes(
        query_id,
        sender_peer_id,
        timestamp,
        access_tier,
        top_k,
        embedding,
        query_text,
    );
    let signature = signing_key.sign(&bytes);
    (verifying_key, signature.to_bytes())
}

/// Verifies an Ed25519 signature and enforces anti-replay timestamp freshness (< max_drift_secs).
#[allow(clippy::too_many_arguments)]
pub fn verify_query(
    verifying_key: &VerifyingKey,
    signature_bytes: &[u8; 64],
    query_id: Uuid,
    sender_peer_id: &str,
    timestamp: i64,
    access_tier: AccessTier,
    top_k: usize,
    embedding: &[f32],
    query_text: &str,
    max_drift_secs: i64,
) -> Result<(), CoordinatorError> {
    let now = Utc::now().timestamp();
    let drift = (now - timestamp).abs();
    if drift > max_drift_secs {
        return Err(CoordinatorError::StaleTimestamp {
            server_time: now,
            query_time: timestamp,
            drift_secs: drift,
            limit: max_drift_secs,
        });
    }

    let bytes = canonical_query_bytes(
        query_id,
        sender_peer_id,
        timestamp,
        access_tier,
        top_k,
        embedding,
        query_text,
    );
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(&bytes, &signature)
        .map_err(|e| CoordinatorError::InvalidSignature(e.to_string()))?;

    Ok(())
}

/// Sign full `FederatedQueryRequest` in-place.
pub fn sign_request(
    secret_seed: &[u8; 32],
    request: &mut FederatedQueryRequest,
    access_tier: AccessTier,
) {
    let signing_key = SigningKey::from_bytes(secret_seed);
    request.sender_pubkey = signing_key.verifying_key().to_bytes();
    let bytes = canonical_query_bytes(
        request.query_id,
        &request.sender_peer_id,
        request.timestamp,
        access_tier,
        request.top_k,
        &request.embedding,
        &request.query_text,
    );
    let signature = signing_key.sign(&bytes);
    request.signature = signature.to_bytes();
}

/// Verify full `FederatedQueryRequest` against its public key and timestamp freshness.
pub fn verify_request(
    request: &FederatedQueryRequest,
    access_tier: AccessTier,
    max_drift_secs: i64,
) -> Result<(), CoordinatorError> {
    let verifying_key = VerifyingKey::from_bytes(&request.sender_pubkey)
        .map_err(|e| CoordinatorError::InvalidPublicKey(e.to_string()))?;
    verify_query(
        &verifying_key,
        &request.signature,
        request.query_id,
        &request.sender_peer_id,
        request.timestamp,
        access_tier,
        request.top_k,
        &request.embedding,
        &request.query_text,
        max_drift_secs,
    )
}

// Aliases matching E2E test oracle naming conventions
pub use sign_query as oracle_sign_query;
pub use verify_query as oracle_verify_query;
