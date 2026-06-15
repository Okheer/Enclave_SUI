use std::sync::Arc;
use tokio::signal;
use tracing::info;
use tee_solver::{
    api::{create_router, ApiState},
    TeeSolverEngine,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting ENCLAVE TEE Solver Engine (Sui)");

    // Initialize TEE Solver Engine
    let engine = Arc::new(TeeSolverEngine::new()?);
    let pubkey = engine.get_public_key()?;
    let sui_addr = engine.get_sui_address()?;

    // ── read config from env ─────────────────────────────────────────────
    let package_id_hex = std::env::var("PACKAGE_ID").unwrap_or_else(|_| {
        "0x5bf4bb326f548f2982106241691e07889bedde189d2fa0ec1116d9b54a83e02c".into()
    });
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| {
        "https://fullnode.testnet.sui.io:443".into()
    });

    let package_id = {
        let hex = package_id_hex.trim_start_matches("0x");
        let bytes = hex::decode(hex).expect("Invalid PACKAGE_ID hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    engine.configure_tx_builder(package_id)?;
    engine.configure_rpc(rpc_url.clone());
    info!("Settlement PTB builder configured for package: {}", package_id_hex);
    info!("Sui RPC endpoint: {}", rpc_url);

    // ── log key info ─────────────────────────────────────────────────────
    info!("TEE Solver Engine initialized");
    let tee_pubkey_hex = hex::encode(&pubkey);
    info!("Public Key (compressed): 0x{}", tee_pubkey_hex);
    info!("TEE Sui Address:         0x{}", hex::encode(sui_addr));

    // At startup, fetch attestation token and print it
    let attest_token =
        tee_solver::gcp_attestation::AttestationToken::fetch(&tee_pubkey_hex).await?;

    if attest_token.is_simulation {
        tracing::warn!("ATTESTATION MODE: {}", attest_token.mode_str());
        tracing::warn!("Image digest (simulated PCR0): {}", attest_token.image_digest);
    } else {
        tracing::info!("ATTESTATION MODE: {}", attest_token.mode_str());
        tracing::info!("Image digest (real PCR0): {}", attest_token.image_digest);
        tracing::info!("GCP attestation JWT: {}", attest_token.jwt_preview());
    }
    info!(">>> Register this pubkey in SolverRegistry: 0x{}", tee_pubkey_hex);
    info!(">>> TEE Sui address: 0x{}", hex::encode(sui_addr));

    // Create API server
    let api_state = ApiState {
        engine: engine.clone(),
        attestation_token: Arc::new(tokio::sync::RwLock::new(attest_token)),
    };

    let app = create_router(api_state);

    // Start listener
    let addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("TEE Solver Engine listening on http://{}", addr);
    info!("  POST /start     — open a new sealed auction");
    info!("  POST /quote     — solver quote submission");
    info!("  GET  /pubkey    — TEE public key + Sui address");
    info!("  POST /finalize  — finalize competition, get attestation");
    info!("  POST /settle    — build BCS-encoded settlement PTB from attestation");
    info!("  GET  /attestation — GCP hardware attestation info");
    info!("  GET  /health    — health check");

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("TEE Solver Engine shutdown complete");
    Ok(())
}

/// Listen for shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received CTRL+C, initiating shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating shutdown");
        }
    }
}
