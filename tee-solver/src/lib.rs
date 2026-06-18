pub mod api;
pub mod attestation;
pub mod competition;
pub mod deepbook;
pub mod error;
pub mod gcp_attestation;
pub mod merkle;
pub mod ptb;
pub mod simulation;
pub mod sui_client;
pub mod types;
pub mod walrus;

pub use attestation::{Attestation, AttestationSigner};
pub use competition::SolverCompetition;
pub use error::{Result, TeeError};
pub use ptb::SettlementTxBuilder;
pub use types::{Intent, ObjectID, Solver, SuiAddress};

/// TEE Solver Engine - Main orchestrator for sealed solver competition on Sui.
pub struct TeeSolverEngine {
    signer: AttestationSigner,
    competition: SolverCompetition,
    merkle_chain: merkle::MerkleChain,
    registered_solvers: dashmap::DashMap<String, Solver>,
    walrus_client: parking_lot::RwLock<walrus::WalrusClient>,
    deepbook_client: parking_lot::RwLock<deepbook::DeepBookClient>,
    tx_builder: parking_lot::RwLock<Option<SettlementTxBuilder>>,
    rpc_client: parking_lot::RwLock<Option<sui_client::SuiRpcClient>>,
}

impl TeeSolverEngine {
    /// Initialize the TEE Solver Engine with a new signing key
    pub fn new() -> Result<Self> {
        Ok(Self {
            signer: AttestationSigner::new()?,
            competition: SolverCompetition::new(),
            merkle_chain: merkle::MerkleChain::new(),
            registered_solvers: dashmap::DashMap::new(),
            walrus_client: parking_lot::RwLock::new(walrus::WalrusClient::new()),
            deepbook_client: parking_lot::RwLock::new(deepbook::DeepBookClient::new()),
            tx_builder: parking_lot::RwLock::new(None),
            rpc_client: parking_lot::RwLock::new(None),
        })
    }

    /// Register a solver with their TEE public key
    pub fn register_solver(&self, solver_id: String, pubkey: Vec<u8>) -> Result<()> {
        let solver = Solver {
            id: solver_id.clone(),
            pubkey,
            registered_at: chrono::Utc::now(),
        };
        self.registered_solvers.insert(solver_id, solver);
        Ok(())
    }

    /// Start a new sealed auction for a specific intent
    pub fn start_competition(&self, intent_hash: [u8; 32]) -> Result<()> {
        self.competition.start_competition(intent_hash)?;
        Ok(())
    }

    /// Collect a quote from a solver during sealed auction
    pub fn submit_quote(&self, solver_id: String, quote: types::QuoteData) -> Result<()> {
        self.competition.add_quote(solver_id, quote)?;
        Ok(())
    }

    /// Run the sealed solver competition - selects winner by argmax(output_amount)
    pub fn finalize_competition(
        &self,
        intent: &Intent,
        walrus_blob_id: Vec<u8>,
    ) -> Result<Attestation> {
        let winning_quote = self.competition.select_winner()?;

        // The Merkle chain now uses BCS-based hash — compat with Move
        let attestation = self.signer.create_attestation(
            intent,
            &winning_quote,
            0, // block_number unused on Sui; timestamp is offchain metadata
            self.merkle_chain.get_latest_hash_vec(),
            walrus_blob_id,
        )?;

        // Add to Merkle chain for continuity verification
        self.merkle_chain.append(&attestation)?;

        // Reset competition for next auction
        self.competition.reset()?;

        Ok(attestation)
    }

    /// Get the TEE's compressed secp256k1 public key
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        self.signer.get_public_key()
    }

    /// Get the TEE's uncompressed secp256k1 public key
    pub fn get_public_key_uncompressed(&self) -> Result<Vec<u8>> {
        self.signer.get_public_key_uncompressed()
    }

    /// Get the TEE's Sui address (blake2b-256 of compressed pubkey || 0x00).
    pub fn get_sui_address(&self) -> Result<SuiAddress> {
        self.signer.sui_address()
    }

    /// Configure the Walrus publisher URL.
    pub fn configure_walrus(&self, publisher_url: String) {
        *self.walrus_client.write() = walrus::WalrusClient::with_publisher(publisher_url);
    }

    /// Configure the DeepBook RPC endpoint.
    pub fn configure_deepbook(&self, rpc_endpoint: String) {
        *self.deepbook_client.write() = deepbook::DeepBookClient::with_rpc(rpc_endpoint);
    }

    /// Seed a pool in the DeepBook cache.
    pub fn register_deepbook_pool(
        &self,
        pool_id: ObjectID,
        token_in: String,
        token_out: String,
    ) {
        self.deepbook_client
            .read()
            .register_pool(pool_id, token_in, token_out);
    }

    /// Finalize competition and upload quote log to Walrus, then produce attestation.
    pub async fn finalize_and_upload(
        &self,
        intent: &Intent,
    ) -> Result<Attestation> {
        // Upload quote log to Walrus
        let quote_log = self.competition.get_all_quotes();
        let walrus_blob_id = self
            .walrus_client
            .read()
            .upload_json(&quote_log)
            .await?;

        // Convert Walrus blob ID hex string to bytes for the attestation
        let blob_id_bytes = hex::decode(walrus_blob_id.trim_start_matches("0x"))
            .unwrap_or_else(|_| walrus_blob_id.as_bytes().to_vec());

        self.finalize_competition(intent, blob_id_bytes)
    }

    /// Finalize competition with just intent hash (for API endpoint).
    pub fn finalize_competition_with_intent_hash(
        &self,
        intent_id: &ObjectID,
        walrus_blob_id: Vec<u8>,
    ) -> Result<Attestation> {
        let winning_quote = self.competition.select_winner()?;

        let attestation = self.signer.create_attestation_with_hash(
            intent_id,
            &winning_quote,
            0,
            self.merkle_chain.get_latest_hash_vec(),
            walrus_blob_id,
        )?;

        self.merkle_chain.append(&attestation)?;
        self.competition.reset()?;

        Ok(attestation)
    }

    /// Configure the settlement PTB builder (package address for `settle_intent`).
    pub fn configure_tx_builder(&self, package_id: [u8; 32]) -> Result<()> {
        let builder = SettlementTxBuilder::new(package_id)
            .map_err(|e| TeeError::InternalError(e))?;
        *self.tx_builder.write() = Some(builder);
        Ok(())
    }

    /// Configure the Sui JSON-RPC client.
    pub fn configure_rpc(&self, rpc_url: String) {
        *self.rpc_client.write() = Some(sui_client::SuiRpcClient::new(rpc_url));
    }

    /// Build a settlement PTB from a finalized `Attestation`.
    ///
    /// Requires that `configure_tx_builder` was called first.
    /// The PTB is returned as BCS-encoded bytes for an external relayer to wrap
    /// in a `Transaction`, sign, and submit.
    pub fn build_settlement_payload(
        &self,
        attestation: &Attestation,
        config_obj: sui_sdk_types::SharedInput,
        registry_obj: sui_sdk_types::SharedInput,
        intent_ref: sui_sdk_types::ObjectReference,
        pool_obj: sui_sdk_types::SharedInput,
        deep_fee_ref: sui_sdk_types::ObjectReference,
        clock_obj: sui_sdk_types::SharedInput,
        type_arguments: Vec<sui_sdk_types::TypeTag>,
    ) -> Result<Vec<u8>> {
        let tee_sig = attestation.signature.clone();

        let builder = self
            .tx_builder
            .read()
            .as_ref()
            .ok_or_else(|| TeeError::InternalError(
                "SettlementTxBuilder not configured, call configure_tx_builder first".into()
            ))?
            .clone();

        let ptb = builder.build_programmable_tx(
            config_obj,
            registry_obj,
            intent_ref,
            pool_obj,
            attestation,
            &tee_sig,
            deep_fee_ref,
            clock_obj,
            type_arguments,
        );

        bcs::to_bytes(&ptb)
            .map_err(|e| TeeError::SerializationError(format!("BCS encoding failed: {e}")))
    }

    /// Get competition status for the API.
    pub fn competition_status(&self) -> (bool, Option<[u8; 32]>, String) {
        self.competition.status()
    }

    /// Count of registered solvers.
    pub fn solver_count(&self) -> usize {
        self.registered_solvers.len()
    }

    /// Total submitted quotes.
    pub fn quote_count(&self) -> usize {
        self.competition.total_quotes()
    }

    /// Dry-run a BCS-encoded PTB via Sui RPC.
    pub async fn dry_run_ptb(&self, tx_bytes: &[u8]) -> Result<serde_json::Value> {
        let client = self
            .rpc_client
            .read()
            .as_ref()
            .ok_or_else(|| TeeError::InternalError("SuiRpcClient not configured, call configure_rpc first".into()))?
            .clone();
        client.dry_run_tx(tx_bytes).await
    }
}

impl Default for TeeSolverEngine {
    fn default() -> Self {
        Self::new().expect("Failed to initialize TEE Solver Engine")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_initialization() {
        let engine = TeeSolverEngine::new().unwrap();
        let pubkey = engine.get_public_key().unwrap();
        assert!(!pubkey.is_empty());
    }

    #[test]
    fn test_sui_address_non_zero() {
        let engine = TeeSolverEngine::new().unwrap();
        let addr = engine.get_sui_address().unwrap();
        assert_ne!(addr, [0u8; 32]);
    }
}
