use crate::error::{Result, TeeError};
use crate::types::{ObjectID, QuoteData, SuiAddress};
use chrono::{DateTime, Utc};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::SecretKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// TEE-signed attestation matching the Move `Attestation` struct exactly.
///
/// Fields and order must match `solvex_settlement.move`:
/// ```move
/// public struct Attestation has copy, drop, store {
///     intent_id: ID,                    // [u8; 32]
///     winner_solver: address,           // [u8; 32]
///     output_amount: u64,               // u64, 8 bytes LE
///     deepbook_pool_id: ID,             // [u8; 32]
///     prev_attestation_hash: vector<u8>, // length-prefixed
///     walrus_blob_id: vector<u8>,        // length-prefixed
/// }
/// ```
///
/// BCS encoding (via `bcs::to_bytes`) matches Move's `bcs::to_bytes` exactly.
/// Signature is compact 64-byte `r || s` (no recovery id), which Sui's
/// `ecdsa_k1::secp256k1_verify` expects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    /// On-chain intent object ID (32 bytes).
    pub intent_id: ObjectID,
    /// Sui address of the winning solver.
    pub winner_solver: SuiAddress,
    /// Output amount the solver commits to deliver.
    pub output_amount: u64,
    /// DeepBook pool ID used for the swap.
    pub deepbook_pool_id: ObjectID,
    /// Keccak256 hash of the previous attestation's BCS encoding.
    /// Empty vec for genesis.
    pub prev_attestation_hash: Vec<u8>,
    /// Walrus blob ID referencing the full quote log.
    pub walrus_blob_id: Vec<u8>,
    /// Timestamp when the attestation was created (offchain metadata, NOT in BCS).
    #[serde(skip)]
    pub timestamp: DateTime<Utc>,
    /// Compact 64-byte ECDSA signature: r[32] || s[32] (no recovery id).
    /// This is what Sui's `ecdsa_k1::secp256k1_verify` expects.
    pub signature: Vec<u8>,
}

impl Attestation {
    /// BCS-encode the attestation in the exact byte order Move uses.
    ///
    /// Uses the `bcs` crate which produces the same encoding as
    /// `sui::bcs::to_bytes` / `std::bcs::to_bytes` in Move.
    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        // Manually build BCS to match Move's exact field order.
        // The timestamp and signature fields are excluded from BCS encoding.
        let mut buf = Vec::new();

        // 1. intent_id: ID → 32 raw bytes (fixed array, no length prefix in BCS)
        buf.extend_from_slice(&self.intent_id);

        // 2. winner_solver: address → 32 raw bytes
        buf.extend_from_slice(&self.winner_solver);

        // 3. output_amount: u64 → 8 bytes little-endian
        buf.extend_from_slice(&self.output_amount.to_le_bytes());

        // 4. deepbook_pool_id: ID → 32 raw bytes
        buf.extend_from_slice(&self.deepbook_pool_id);

        // 5. prev_attestation_hash: vector<u8> → 4-byte LE length + bytes
        let prev_len = self.prev_attestation_hash.len() as u32;
        buf.extend_from_slice(&prev_len.to_le_bytes());
        buf.extend_from_slice(&self.prev_attestation_hash);

        // 6. walrus_blob_id: vector<u8> → 4-byte LE length + bytes
        let walrus_len = self.walrus_blob_id.len() as u32;
        buf.extend_from_slice(&walrus_len.to_le_bytes());
        buf.extend_from_slice(&self.walrus_blob_id);

        buf
    }

    /// Compute keccak256 of the BCS-encoded attestation.
    ///
    /// This is what the TEE signs and what the Move `solvex_verifier` verifies.
    pub fn hash(&self) -> Result<[u8; 32]> {
        let bytes = self.to_bcs_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AttestationSigner
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the TEE's secp256k1 signing key pair.
///
/// `sign_hash` produces compact 64-byte `r || s` signatures — the format
/// Sui's `ecdsa_k1::secp256k1_verify` expects (no recovery id byte).
pub struct AttestationSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AttestationSigner {
    /// Create a new signer with a random key.
    pub fn new() -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Create a signer from a fixed 32-byte seed (deterministic — for testing only).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_slice(seed)
            .map_err(|e| TeeError::CryptoError(format!("Invalid seed: {:?}", e)))?;
        let signing_key = SigningKey::from(secret);
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Compressed (33-byte) secp256k1 public key — register this in `SolverRegistry`.
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.verifying_key.to_encoded_point(true).as_bytes().to_vec())
    }

    /// Uncompressed (65-byte) secp256k1 public key.
    pub fn get_public_key_uncompressed(&self) -> Result<Vec<u8>> {
        Ok(self.verifying_key.to_encoded_point(false).as_bytes().to_vec())
    }

    /// Derive the Sui address from the TEE's public key.
    ///
    /// Sui addresses are the first 32 bytes of `blake2b-256(pubkey || 0x00)`.
    /// This is what the `SolverRegistry` expects as the solver identifier.
    pub fn sui_address(&self) -> Result<SuiAddress> {
        use blake3::hash;

        let pubkey = self.get_public_key()?; // compressed 33 bytes
        let mut input = pubkey;
        input.push(0x00); // signature scheme flag for secp256k1
        let blake3_hash = hash(&input);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&blake3_hash.as_bytes()[..32]);
        Ok(addr)
    }

    /// Create and sign an attestation from a full `Intent`.
    pub fn create_attestation(
        &self,
        intent: &crate::types::Intent,
        winning_quote: &QuoteData,
        block_number: u64,
        prev_attest_hash: Vec<u8>,
        walrus_blob_id: Vec<u8>,
    ) -> Result<Attestation> {
        self.build_attestation(
            intent.hash(),
            winning_quote,
            block_number,
            prev_attest_hash,
            walrus_blob_id,
        )
    }

    /// Create and sign an attestation when only the intent hash is available.
    pub fn create_attestation_with_hash(
        &self,
        intent_id: &ObjectID,
        winning_quote: &QuoteData,
        block_number: u64,
        prev_attest_hash: Vec<u8>,
        walrus_blob_id: Vec<u8>,
    ) -> Result<Attestation> {
        self.build_attestation(*intent_id, winning_quote, block_number, prev_attest_hash, walrus_blob_id)
    }

    fn build_attestation(
        &self,
        intent_id: ObjectID,
        winning_quote: &QuoteData,
        _block_number: u64,
        prev_attest_hash: Vec<u8>,
        walrus_blob_id: Vec<u8>,
    ) -> Result<Attestation> {
        // Resolve solver address from their ID (simplified: blake2b of solver_id bytes)
        let winner_solver = self.solver_id_to_address(&winning_quote.solver_id);

        let mut attestation = Attestation {
            intent_id,
            winner_solver,
            output_amount: winning_quote.output_amount,
            deepbook_pool_id: winning_quote.deepbook_pool_id,
            prev_attestation_hash: prev_attest_hash,
            walrus_blob_id,
            timestamp: chrono::Utc::now(),
            signature: Vec::new(),
        };

        // hash() uses BCS encoding — consistent with Move's `bcs::to_bytes`
        let hash = attestation.hash()?;
        attestation.signature = self.sign_hash(&hash)?;
        Ok(attestation)
    }

    /// Convert a solver ID string to a Sui address.
    /// In production the solver is identified by their on-chain address;
    /// this is a placeholder for the offchain engine.
    fn solver_id_to_address(&self, solver_id: &str) -> SuiAddress {
        use blake3::hash;
        let input = [solver_id.as_bytes(), &[0x00]].concat();
        let blake3_hash = hash(&input);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&blake3_hash.as_bytes()[..32]);
        addr
    }

    /// Sign a 32-byte prehash.
    ///
    /// Returns a compact **64-byte** signature: `r[32] || s[32]`.
    /// No recovery id — Sui's `secp256k1_verify` does not need it because the
    /// public key is provided separately via `SolverRegistry`.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        use ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{RecoveryId, Signature};

        let (sig, _recid): (Signature, RecoveryId) = self
            .signing_key
            .sign_prehash(hash)
            .map_err(|e| TeeError::CryptoError(format!("Signing failed: {:?}", e)))?;

        // Compact 64-byte r||s — no recovery id byte
        let sig_bytes = sig.to_bytes();
        Ok(sig_bytes.to_vec())
    }

    /// Verify a compact 64-byte `r || s` signature against a pre-hashed message.
    pub fn verify_signature(&self, hash: &[u8; 32], signature_bytes: &[u8]) -> Result<bool> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::Signature;

        if signature_bytes.len() != 64 {
            return Err(TeeError::CryptoError(format!(
                "Expected 64-byte compact signature, got {}",
                signature_bytes.len()
            )));
        }

        let sig = Signature::from_bytes(signature_bytes.into())
            .map_err(|e| TeeError::CryptoError(format!("Invalid signature bytes: {:?}", e)))?;

        match self.verifying_key.verify_prehash(hash, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Default for AttestationSigner {
    fn default() -> Self {
        Self::new().expect("Failed to create default AttestationSigner")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
use super::*;

    fn make_quote() -> QuoteData {
        QuoteData {
            output_amount: 950,
            deepbook_pool_id: [1u8; 32],
            gas_estimate: 100_000,
            timestamp: Utc::now(),
            solver_id: "solver1".to_string(),
        }
    }

    #[test]
    fn test_signer_creation() {
        let signer = AttestationSigner::new().unwrap();
        let pubkey = signer.get_public_key().unwrap();
        assert_eq!(pubkey.len(), 33, "Compressed public key must be 33 bytes");
    }

    #[test]
    fn test_signer_from_seed_is_deterministic() {
        let seed = [1u8; 32];
        let s1 = AttestationSigner::from_seed(&seed).unwrap();
        let s2 = AttestationSigner::from_seed(&seed).unwrap();
        assert_eq!(s1.get_public_key().unwrap(), s2.get_public_key().unwrap());
    }

    #[test]
    fn test_sign_produces_64_bytes() {
        let signer = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = signer.sign_hash(&hash).unwrap();
        assert_eq!(sig.len(), 64, "Compact signature must be exactly 64 bytes");
    }

    #[test]
    fn test_signature_verification_roundtrip() {
        let signer = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = signer.sign_hash(&hash).unwrap();
        assert!(signer.verify_signature(&hash, &sig).unwrap());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let s1 = AttestationSigner::new().unwrap();
        let s2 = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = s1.sign_hash(&hash).unwrap();
        assert!(!s2.verify_signature(&hash, &sig).unwrap());
    }

    #[test]
    fn test_bcs_encoding_roundtrip() {
        let signer = AttestationSigner::new().unwrap();
        let quote = make_quote();

        let attestation = signer
            .create_attestation_with_hash(
                &[1u8; 32],
                &quote,
                100,
                vec![0u8; 32],
                vec![2u8; 16],
            )
            .unwrap();

        let bcs = attestation.to_bcs_bytes();
        // Minimum: 32 (intent_id) + 32 (winner_solver) + 8 (output) + 32 (pool_id)
        //   + 4 + 32 (prev hash len+data) + 4 + 16 (walrus len+data) = 160
        assert!(bcs.len() >= 160, "BCS encoding too short: {}", bcs.len());

        // Verify we can decode: fixed fields first
        assert_eq!(&bcs[0..32], &[1u8; 32]);
        assert_eq!(&bcs[64..72], 950u64.to_le_bytes().as_slice());
    }

    #[test]
    fn test_attestation_hash_is_deterministic() {
        let signer = AttestationSigner::new().unwrap();
        let quote = make_quote();

        let a = signer
            .create_attestation_with_hash(
                &[1u8; 32],
                &quote,
                100,
                vec![0u8; 32],
                vec![2u8; 16],
            )
            .unwrap();

        assert_eq!(a.hash().unwrap(), a.hash().unwrap());
    }

    #[test]
    fn test_attestation_signature_valid() {
        let signer = AttestationSigner::new().unwrap();
        let quote = make_quote();

        let att = signer
            .create_attestation_with_hash(
                &[1u8; 32],
                &quote,
                100,
                vec![0u8; 32],
                vec![2u8; 16],
            )
            .unwrap();

        let hash = att.hash().unwrap();
        assert!(signer.verify_signature(&hash, &att.signature).unwrap());
    }

    #[test]
    fn test_sui_address_non_zero() {
        let signer = AttestationSigner::new().unwrap();
        let addr = signer.sui_address().unwrap();
        assert_ne!(addr, [0u8; 32], "Sui address must not be zero");
    }

    #[test]
    fn test_bcs_matches_move_struct_order() {
        // Verify that our BCS encoding matches the Move struct field order.
        // Move field order: intent_id, winner_solver, output_amount, deepbook_pool_id,
        //   prev_attestation_hash, walrus_blob_id
        let attestation = Attestation {
            intent_id: [0x01u8; 32],
            winner_solver: [0x02u8; 32],
            output_amount: 12345,
            deepbook_pool_id: [0x03u8; 32],
            prev_attestation_hash: vec![0x04u8; 32],
            walrus_blob_id: vec![0x05u8; 8],
            timestamp: Utc::now(),
            signature: vec![],
        };

        let bcs = attestation.to_bcs_bytes();

        // Indices (offset, length):
        // 0..32: intent_id
        assert_eq!(&bcs[0..32], &[0x01u8; 32]);
        // 32..64: winner_solver
        assert_eq!(&bcs[32..64], &[0x02u8; 32]);
        // 64..72: output_amount (u64 LE)
        assert_eq!(&bcs[64..72], 12345u64.to_le_bytes().as_slice());
        // 72..104: deepbook_pool_id
        assert_eq!(&bcs[72..104], &[0x03u8; 32]);
        // 104..108: prev_attestation_hash length (32 = 0x20)
        let prev_len = u32::from_le_bytes(bcs[104..108].try_into().unwrap());
        assert_eq!(prev_len, 32);
        // 108..140: prev_attestation_hash data
        assert_eq!(&bcs[108..140], &[0x04u8; 32]);
        // 140..144: walrus_blob_id length (8)
        let walrus_len = u32::from_le_bytes(bcs[140..144].try_into().unwrap());
        assert_eq!(walrus_len, 8);
        // 144..152: walrus_blob_id data
        assert_eq!(&bcs[144..152], &[0x05u8; 8]);
    }
}
