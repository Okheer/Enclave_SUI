use crate::error::Result;
use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sui_sdk_types::{Address, Digest, Mutability, ObjectReference, SharedInput, TypeTag};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;

/// HTTP API for TEE Solver Engine (Sui).
/// Solvers submit quotes here during the sealed auction.
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<crate::TeeSolverEngine>,
    pub attestation_token: Arc<tokio::sync::RwLock<crate::gcp_attestation::AttestationToken>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteSubmissionRequest {
    pub solver_id: String,
    /// Output amount as decimal string (u64).
    pub output_amount: String,
    /// DeepBook pool ID (0x-prefixed 64-char hex).
    pub deepbook_pool_id: String,
    /// Gas estimate in MIST as decimal string.
    pub gas_estimate: String,
    /// Intent hash (0x-prefixed 64-char hex).
    pub intent_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteSubmissionResponse {
    pub success: bool,
    pub message: String,
    pub quote_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub version: String,
    pub public_key: String,
    pub tee_sui_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/pubkey", get(get_public_key))
        .route("/attestation", get(get_attestation))
        .route("/start", post(start_auction))
        .route("/quote", post(submit_quote))
        .route("/status", get(auction_status))
        .route("/finalize", post(finalize_competition))
        .route("/settle", post(build_settlement_tx))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

/// Health check endpoint — verify TEE is operational
async fn health_check(State(state): State<ApiState>) -> impl IntoResponse {
    match state.engine.get_public_key() {
        Ok(pubkey) => {
            let sui_addr = state
                .engine
                .get_sui_address()
                .map(|a| hex::encode(a))
                .unwrap_or_else(|_| "unknown".into());
            let response = HealthCheckResponse {
                status: "ok".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                public_key: hex::encode(&pubkey),
                tee_sui_address: sui_addr,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Health check failed: {}", e),
                code: 500,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// Get TEE's public key and Sui address for onchain registration
async fn get_public_key(State(state): State<ApiState>) -> impl IntoResponse {
    match state.engine.get_public_key() {
        Ok(pubkey) => {
            let pubkey_uncompressed = state
                .engine
                .get_public_key_uncompressed()
                .map(|k| hex::encode(&k))
                .unwrap_or_default();
            let sui_addr = state
                .engine
                .get_sui_address()
                .map(|a| hex::encode(a))
                .unwrap_or_else(|_| "unknown".into());
            #[derive(Serialize)]
            struct Response {
                public_key_compressed: String,
                public_key_uncompressed: String,
                /// Register THIS address in SolverRegistry.
                tee_sui_address: String,
            }
            (
                StatusCode::OK,
                Json(Response {
                    public_key_compressed: hex::encode(&pubkey),
                    public_key_uncompressed: pubkey_uncompressed,
                    tee_sui_address: sui_addr,
                }),
            )
                .into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Failed to get public key: {}", e),
                code: 500,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// GET /attestation — returns the full GCP attestation token
async fn get_attestation(State(state): State<ApiState>) -> impl IntoResponse {
    let token = state.attestation_token.read().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "mode": if token.is_simulation { "simulation" } else { "hardware" },
            "image_digest": token.image_digest,
            "tee_pubkey": token.tee_pubkey,
            "jwt_preview": token.jwt_preview(),
            "jwt": token.jwt,
            "gcp_verification_note": "In production: verify JWT at https://www.googleapis.com/oauth2/v3/certs",
        }))
    )
}

/// Submit a quote during sealed auction
async fn submit_quote(
    State(state): State<ApiState>,
    Json(payload): Json<QuoteSubmissionRequest>,
) -> impl IntoResponse {
    info!(
        "Quote submission from solver: {} for amount: {}",
        payload.solver_id, payload.output_amount
    );

    let quote = match parse_quote_request(&payload) {
        Ok(q) => q,
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Invalid quote format: {}", e),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    match state.engine.submit_quote(payload.solver_id.clone(), quote) {
        Ok(_) => {
            let response = QuoteSubmissionResponse {
                success: true,
                message: "Quote received and sealed".to_string(),
                quote_id: Some(format!("q_{}", chrono::Utc::now().timestamp_millis())),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Quote submission failed: {}", e),
                code: 400,
            };
            (StatusCode::BAD_REQUEST, Json(error)).into_response()
        }
    }
}

/// Get current auction status
async fn auction_status(State(state): State<ApiState>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Status {
        is_active: bool,
        intent_hash: Option<String>,
        solver_count: usize,
        quote_count: usize,
        message: String,
    }

    let (is_active, intent_hash, message) = state.engine.competition_status();

    let solver_count = state.engine.solver_count();
    let quote_count = state.engine.quote_count();

    let status = Status {
        is_active,
        intent_hash: intent_hash.map(|h| format!("0x{}", hex::encode(h))),
        solver_count,
        quote_count,
        message,
    };

    (StatusCode::OK, Json(status)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /start — open a new sealed auction for a given intent hash
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuctionRequest {
    /// 0x-prefixed 32-byte intent hash
    pub intent_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuctionResponse {
    pub success: bool,
    pub intent_hash: String,
    pub message: String,
    pub tee_public_key: String,
}

/// Open a new sealed auction for the given intent hash.
async fn start_auction(
    State(state): State<ApiState>,
    Json(payload): Json<StartAuctionRequest>,
) -> impl IntoResponse {
    info!("Starting new sealed auction for intent: {}", payload.intent_hash);

    let intent_hash_bytes = match hex::decode(payload.intent_hash.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            let error = ErrorResponse {
                error: "Invalid intent_hash: must be a 0x-prefixed 32-byte hex string".to_string(),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    match state.engine.start_competition(intent_hash_bytes) {
        Ok(_) => {
            let pubkey = state
                .engine
                .get_public_key()
                .map(|k| hex::encode(&k))
                .unwrap_or_default();

            let response = StartAuctionResponse {
                success: true,
                intent_hash: payload.intent_hash,
                message: "Sealed auction opened — solvers may now POST to /quote".to_string(),
                tee_public_key: pubkey,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Failed to start auction: {}", e),
                code: 409,
            };
            (StatusCode::CONFLICT, Json(error)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /finalize — select winner and produce signed attestation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeRequest {
    /// Intent object ID (0x-prefixed 64-char hex).
    pub intent_id: String,
    /// Optional Walrus blob ID for the quote log. If empty, a default is used.
    pub walrus_blob_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponseJson {
    pub intent_id: String,
    pub winner_solver: String,
    pub output_amount: u64,
    pub deepbook_pool_id: String,
    pub prev_attestation_hash: String,
    pub walrus_blob_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeResponse {
    pub success: bool,
    pub winner_solver: String,
    pub output_amount: u64,
    pub attestation_hash: String,
    pub error: Option<String>,
    pub attestation: Option<AttestationResponseJson>,
    pub attestation_sig: Option<String>,
}

/// Finalize competition and produce signed TEE attestation.
async fn finalize_competition(
    State(state): State<ApiState>,
    Json(payload): Json<FinalizeRequest>,
) -> impl IntoResponse {
    info!("Finalizing competition");

    let intent_id = match hex::decode(payload.intent_id.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            let error = ErrorResponse {
                error: "Invalid intent_id format".to_string(),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    let walrus_blob_id = payload
        .walrus_blob_id
        .unwrap_or_else(|| "0x".to_string())
        .trim_start_matches("0x")
        .as_bytes()
        .to_vec();

    match state
        .engine
        .finalize_competition_with_intent_hash(&intent_id, walrus_blob_id)
    {
        Ok(attestation) => {
            let hash = attestation.hash().unwrap_or_default();
            let att_json = AttestationResponseJson {
                intent_id: format!("0x{}", hex::encode(&attestation.intent_id)),
                winner_solver: format!("0x{}", hex::encode(&attestation.winner_solver)),
                output_amount: attestation.output_amount,
                deepbook_pool_id: format!("0x{}", hex::encode(&attestation.deepbook_pool_id)),
                prev_attestation_hash: format!("0x{}", hex::encode(&attestation.prev_attestation_hash)),
                walrus_blob_id: format!("0x{}", hex::encode(&attestation.walrus_blob_id)),
            };

            let response = FinalizeResponse {
                success: true,
                winner_solver: format!("0x{}", hex::encode(&attestation.winner_solver)),
                output_amount: attestation.output_amount,
                attestation_hash: format!("0x{}", hex::encode(hash)),
                error: None,
                attestation: Some(att_json),
                attestation_sig: Some(format!("0x{}", hex::encode(&attestation.signature))),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let response = FinalizeResponse {
                success: false,
                winner_solver: String::new(),
                output_amount: 0,
                attestation_hash: String::new(),
                error: Some(e.to_string()),
                attestation: None,
                attestation_sig: None,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settle — build settlement PTB from a finalized attestation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SettleRequest {
    /// 0x-prefixed 32-byte intent object ID.
    pub intent_id: String,
    /// 0x-prefixed 32-byte SettlementConfig object ID.
    pub config_id: String,
    /// 0x-prefixed 32-byte SolverRegistry object ID.
    pub registry_id: String,
    /// 0x-prefixed 32-byte Pool object ID.
    pub pool_id: String,
    /// 0x-prefixed 32-byte Clock object ID.
    pub clock_id: String,
    /// 0x-prefixed 32-byte DEEP coin object ID.
    pub deep_fee_id: String,
    /// Object version of the DEEP coin.
    pub deep_fee_version: u64,
    /// 0x-prefixed 32-byte digest of the DEEP coin (hex).
    pub deep_fee_digest: String,
    /// Object version of the Intent.
    pub intent_version: u64,
    /// 0x-prefixed 32-byte digest of the Intent (hex).
    pub intent_digest: String,
    /// Full type tag for `In` (e.g. `0x2::sui::SUI`).
    pub type_in: String,
    /// Full type tag for `Out` (e.g. `0x2::sui::SUI`).
    pub type_out: String,
    /// 64-byte TEE signature hex string (from /finalize response).
    pub tee_sig_hex: String,
}

#[derive(Debug, Serialize)]
pub struct SettleResponse {
    pub success: bool,
    /// Base64-encoded BCS bytes of the `ProgrammableTransaction`.
    pub ptb_base64: Option<String>,
    pub error: Option<String>,
}

type ParseResult<T> = std::result::Result<T, (StatusCode, Json<ErrorResponse>)>;

fn bad_request(msg: String) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg, code: 400 }))
}

fn parse_hex_32(hex_str: &str, field: &str) -> ParseResult<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|_| bad_request(format!("Invalid hex for {field}")))?;
    if bytes.len() != 32 {
        return Err(bad_request(format!("{field} must be 32 bytes")));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_digest(hex_str: &str, field: &str) -> ParseResult<Digest> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|_| bad_request(format!("Invalid hex digest for {field}")))?;
    if bytes.len() != 32 {
        return Err(bad_request(format!("Digest {field} must be 32 bytes")));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Digest::new(arr))
}

struct SettleParsed {
    intent_id: [u8; 32],
    config_id: [u8; 32],
    registry_id: [u8; 32],
    pool_id: [u8; 32],
    clock_id: [u8; 32],
    deep_fee_id: [u8; 32],
    deep_fee_digest: Digest,
    intent_digest: Digest,
    deep_fee_version: u64,
    intent_version: u64,
    type_in: TypeTag,
    type_out: TypeTag,
    tee_sig: Vec<u8>,
}

fn parse_settle_request(payload: &SettleRequest) -> ParseResult<SettleParsed> {
    Ok(SettleParsed {
        intent_id: parse_hex_32(&payload.intent_id, "intent_id")?,
        config_id: parse_hex_32(&payload.config_id, "config_id")?,
        registry_id: parse_hex_32(&payload.registry_id, "registry_id")?,
        pool_id: parse_hex_32(&payload.pool_id, "pool_id")?,
        clock_id: parse_hex_32(&payload.clock_id, "clock_id")?,
        deep_fee_id: parse_hex_32(&payload.deep_fee_id, "deep_fee_id")?,
        deep_fee_digest: parse_digest(&payload.deep_fee_digest, "deep_fee_digest")?,
        intent_digest: parse_digest(&payload.intent_digest, "intent_digest")?,
        deep_fee_version: payload.deep_fee_version,
        intent_version: payload.intent_version,
        type_in: payload.type_in.parse().map_err(|_| bad_request(format!("Invalid type tag for 'in': {}", payload.type_in)))?,
        type_out: payload.type_out.parse().map_err(|_| bad_request(format!("Invalid type tag for 'out': {}", payload.type_out)))?,
        tee_sig: {
            let b = hex::decode(payload.tee_sig_hex.trim_start_matches("0x"))
                .map_err(|_| bad_request("Invalid tee_sig_hex".into()))?;
            if b.len() != 64 {
                return Err(bad_request("tee_sig_hex must be a 64-byte hex string".into()));
            }
            b
        },
    })
}

/// Build a settlement PTB for an external relayer to sign and submit.
async fn build_settlement_tx(
    State(state): State<ApiState>,
    Json(payload): Json<SettleRequest>,
) -> impl IntoResponse {
    info!("Building settlement PTB for intent: {}", payload.intent_id);

    let parsed = match parse_settle_request(&payload) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    // ── build object references / shared inputs ──────────────────────────
    let config_obj = SharedInput::new(
        Address::new(parsed.config_id),
        0,
        Mutability::Mutable,
    );
    let registry_obj = SharedInput::new(
        Address::new(parsed.registry_id),
        0,
        Mutability::Mutable,
    );
    let pool_obj = SharedInput::new(
        Address::new(parsed.pool_id),
        0,
        Mutability::Mutable,
    );
    let clock_obj = SharedInput::new(
        Address::new(parsed.clock_id),
        0,
        Mutability::Immutable,
    );
    let intent_ref = ObjectReference::new(
        Address::new(parsed.intent_id),
        parsed.intent_version,
        parsed.intent_digest,
    );
    let deep_fee_ref = ObjectReference::new(
        Address::new(parsed.deep_fee_id),
        parsed.deep_fee_version,
        parsed.deep_fee_digest,
    );

    // ── reconstruct Attestation from parsed data ─────────────────────────
    // We need a minimal Attestation with the correct fields for PTB building.
    // The signature and pool_id are the key fields used.
    let attestation = crate::attestation::Attestation {
        intent_id: parsed.intent_id,
        winner_solver: [0u8; 32],
        output_amount: 0,
        deepbook_pool_id: parsed.pool_id,
        prev_attestation_hash: Vec::new(),
        walrus_blob_id: Vec::new(),
        timestamp: chrono::Utc::now(),
        signature: parsed.tee_sig.clone(),
    };

    // ── build PTB ────────────────────────────────────────────────────────
    match state.engine.build_settlement_payload(
        &attestation,
        config_obj,
        registry_obj,
        intent_ref,
        pool_obj,
        deep_fee_ref,
        clock_obj,
        vec![parsed.type_in, parsed.type_out],
    ) {
        Ok(ptb_bytes) => {
            let ptb_base64 = base64::engine::general_purpose::STANDARD.encode(&ptb_bytes);
            let response = SettleResponse {
                success: true,
                ptb_base64: Some(ptb_base64),
                error: None,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let response = SettleResponse {
                success: false,
                ptb_base64: None,
                error: Some(e.to_string()),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a quote submission request into QuoteData
fn parse_quote_request(req: &QuoteSubmissionRequest) -> Result<crate::types::QuoteData> {
    let output_amount: u64 = req
        .output_amount
        .parse()
        .map_err(|e| crate::error::TeeError::InvalidQuote(format!("Invalid output_amount: {}", e)))?;

    let hex = req.deepbook_pool_id.trim_start_matches("0x");
    let bytes = hex::decode(hex)
        .map_err(|e| crate::error::TeeError::InvalidQuote(format!("Invalid deepbook_pool_id: {}", e)))?;
    if bytes.len() != 32 {
        return Err(crate::error::TeeError::InvalidQuote(
            "deepbook_pool_id must be 32 bytes (64 hex chars)".to_string(),
        ));
    }
    let mut deepbook_pool_id = [0u8; 32];
    deepbook_pool_id.copy_from_slice(&bytes);

    let gas_estimate: u64 = req
        .gas_estimate
        .parse()
        .map_err(|e| crate::error::TeeError::InvalidQuote(format!("Invalid gas_estimate: {}", e)))?;

    Ok(crate::types::QuoteData {
        output_amount,
        deepbook_pool_id,
        gas_estimate,
        timestamp: chrono::Utc::now(),
        solver_id: req.solver_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_quote() {
        let req = QuoteSubmissionRequest {
            solver_id: "solver1".to_string(),
            output_amount: "1000".to_string(),
            deepbook_pool_id: format!("0x{}", hex::encode([0u8; 32])),
            gas_estimate: "100000".to_string(),
            intent_hash: format!("0x{}", hex::encode([0u8; 32])),
        };

        let result = parse_quote_request(&req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_quote_amount() {
        let req = QuoteSubmissionRequest {
            solver_id: "solver1".to_string(),
            output_amount: "invalid".to_string(),
            deepbook_pool_id: format!("0x{}", hex::encode([0u8; 32])),
            gas_estimate: "100000".to_string(),
            intent_hash: format!("0x{}", hex::encode([0u8; 32])),
        };

        let result = parse_quote_request(&req);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_pool_id() {
        let req = QuoteSubmissionRequest {
            solver_id: "solver1".to_string(),
            output_amount: "1000".to_string(),
            deepbook_pool_id: "0xdeadbeef".to_string(),
            gas_estimate: "100000".to_string(),
            intent_hash: format!("0x{}", hex::encode([0u8; 32])),
        };

        let result = parse_quote_request(&req);
        assert!(result.is_err());
    }
}
