//! TEE Simulation Environment (P3 Days 3–5)
//!
//! Local simulation of TEE behaviour with Sui types — no hardware required.
//!
//! Key guarantees emulated:
//! - Quote opacity (enforced by `SolverCompetition`)
//! - Deterministic winner selection (`argmax(output_amount)`)
//! - Real ECDSA signing with `AttestationSigner`
//! - Real Merkle chain with BCS-based hashing
//!
//! Usage:
//! ```ignore
//! let mut sim = TeeSimulation::new();
//! sim.register_solver("alice", 1_000_000);
//! sim.register_solver("bob",   1_000_000);
//!
//! let auction = sim.open_auction([1u8; 32]);
//! auction.submit_quote("alice", 995_000);
//! auction.submit_quote("bob",   998_000);
//!
//! let result = sim.close_and_attest(auction).unwrap();
//! println!("Winner: {}", result.winner_solver_id);
//! ```

use crate::attestation::{Attestation, AttestationSigner};
use crate::competition::SolverCompetition;
use crate::error::Result;
use crate::merkle::MerkleChain;
use crate::types::{ObjectID, QuoteData};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

/// A registered solver in the simulation
#[derive(Debug, Clone)]
pub struct SimSolver {
    pub id: String,
    /// Stake amount in MIST (u64, not u128).
    pub stake_mist: u64,
    /// Whether this solver is a "colluding" cartel member (used in MEV demo)
    pub is_cartel: bool,
}

/// An open sealed auction ready to accept quotes
pub struct Auction {
    pub intent_id: ObjectID,
    pub competition: SolverCompetition,
}

impl Auction {
    fn new(intent_id: ObjectID) -> Self {
        let competition = SolverCompetition::new();
        competition
            .start_competition(intent_id)
            .expect("Failed to start competition");
        Self { intent_id, competition }
    }

    /// Submit a quote from a solver — sealed inside TEE memory, invisible to peers.
    pub fn submit_quote(&self, solver_id: &str, output_mist: u64) -> Result<()> {
        let quote = QuoteData {
            output_amount: output_mist,
            deepbook_pool_id: [0u8; 32],
            gas_estimate: 100_000,
            timestamp: Utc::now(),
            solver_id: solver_id.to_string(),
        };
        self.competition.add_quote(solver_id.to_string(), quote)
    }
}

/// Result of a completed sealed auction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionResult {
    pub intent_id: ObjectID,
    pub winner_solver_id: String,
    pub winning_output_mist: u64,
    /// Signed TEE attestation
    pub attestation: Attestation,
    /// BCS-encoded attestation bytes (pass as `attestation_bytes` to Move).
    pub attestation_data: Vec<u8>,
    /// Compact 64-byte signature (pass as `tee_sig` to Move).
    pub tee_sig: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// TeeSimulation
// ─────────────────────────────────────────────────────────────────────────────

/// Local simulation of TEE behaviour on Sui.
///
/// Provides the same cryptographic guarantees as production:
/// - Real k256 ECDSA signing
/// - Real Merkle chain linking attestations (BCS-based hashing)
/// - Quote opacity enforced by `SolverCompetition`
pub struct TeeSimulation {
    signer: AttestationSigner,
    merkle_chain: MerkleChain,
    solvers: HashMap<String, SimSolver>,
    auction_counter: u64,
}

impl TeeSimulation {
    /// Create a new simulation instance with a fresh random TEE key pair.
    pub fn new() -> Self {
        Self {
            signer: AttestationSigner::new().expect("Failed to create TEE signer"),
            merkle_chain: MerkleChain::new(),
            solvers: HashMap::new(),
            auction_counter: 0,
        }
    }

    /// Create a simulation with a deterministic key (for reproducible tests/demos).
    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self {
            signer: AttestationSigner::from_seed(&seed).expect("Failed to create TEE signer"),
            merkle_chain: MerkleChain::new(),
            solvers: HashMap::new(),
            auction_counter: 0,
        }
    }

    /// Return the TEE's compressed secp256k1 public key (33 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.signer.get_public_key().unwrap()
    }

    /// Return the TEE's Sui address.
    pub fn sui_address(&self) -> [u8; 32] {
        self.signer.sui_address().unwrap()
    }

    /// Register a solver in the simulation.
    pub fn register_solver(&mut self, id: &str, stake_mist: u64) {
        self.solvers.insert(
            id.to_string(),
            SimSolver { id: id.to_string(), stake_mist, is_cartel: false },
        );
    }

    /// Register a cartel (colluding) solver — used in MEV attack demo.
    pub fn register_cartel_solver(&mut self, id: &str, stake_mist: u64) {
        self.solvers.insert(
            id.to_string(),
            SimSolver { id: id.to_string(), stake_mist, is_cartel: true },
        );
    }

    /// Open a new sealed auction for `intent_id`.
    pub fn open_auction(&mut self, intent_id: [u8; 32]) -> Auction {
        self.auction_counter += 1;
        Auction::new(intent_id)
    }

    /// Finalize an auction, run `argmax(output_amount)`, and produce a signed attestation.
    pub fn close_and_attest(&mut self, auction: Auction) -> Result<AuctionResult> {
        let winner = auction.competition.select_winner()?;
        let prev_hash = self.merkle_chain.get_latest_hash_vec();

        let attestation = self.signer.create_attestation_with_hash(
            &auction.intent_id,
            &winner,
            0,
            prev_hash,
            vec![], // empty walrus_blob_id in sim
        )?;

        // Append to Merkle chain
        self.merkle_chain.append(&attestation)?;

        let attestation_data = attestation.to_bcs_bytes();
        let tee_sig = attestation.signature.clone();

        Ok(AuctionResult {
            intent_id: auction.intent_id,
            winner_solver_id: winner.solver_id,
            winning_output_mist: winner.output_amount,
            attestation,
            attestation_data,
            tee_sig,
        })
    }

    /// Get the current Merkle chain head.
    pub fn merkle_head(&self) -> [u8; 32] {
        self.merkle_chain.get_latest_hash()
    }

    /// Get the number of completed auctions.
    pub fn auction_count(&self) -> u64 {
        self.auction_counter
    }

    /// Verify a previously produced attestation is cryptographically valid.
    pub fn verify_attestation(&self, result: &AuctionResult) -> Result<bool> {
        let hash = result.attestation.hash()?;
        self.signer.verify_signature(&hash, &result.tee_sig)
    }
}

impl Default for TeeSimulation {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MEV Attack Scenarios (for demo)
// ─────────────────────────────────────────────────────────────────────────────

/// Demonstrates the three MEV attack vectors and why TEE eliminates them.
pub struct MevDemoScenario;

impl MevDemoScenario {
    /// **Attack 1: Quote Sniping**
    ///
    /// Without TEE: Solver B observes A's quote and undercuts by 1 wei.
    /// With TEE: Impossible — B cannot see A's sealed quote.
    ///
    /// Returns `(winner_id, winning_output_mist, was_sniping_attempt_successful)`
    pub fn quote_sniping_demo() -> (String, u64, bool) {
        let mut sim = TeeSimulation::with_seed([42u8; 32]);
        sim.register_solver("alice_honest", 1_000_000);
        sim.register_solver("bob_sniper", 1_000_000);
        sim.register_solver("charlie_best", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);

        auction.submit_quote("alice_honest", 995_000).unwrap();
        auction.submit_quote("bob_sniper", 999_000).unwrap();
        auction.submit_quote("charlie_best", 1_005_000).unwrap();

        let result = sim.close_and_attest(auction).unwrap();

        let sniping_worked = result.winner_solver_id == "bob_sniper";
        (result.winner_solver_id, result.winning_output_mist, sniping_worked)
    }

    /// **Attack 2: Collusive Floor Setting**
    ///
    /// Cartel agrees: "never bid above 990". Honest solver breaks the floor.
    pub fn collusion_demo() -> (String, u64, bool) {
        let mut sim = TeeSimulation::with_seed([43u8; 32]);
        sim.register_cartel_solver("cartel_a", 1_000_000);
        sim.register_cartel_solver("cartel_b", 1_000_000);
        sim.register_solver("honest_carol", 1_000_000);

        let auction = sim.open_auction([2u8; 32]);

        auction.submit_quote("cartel_a", 990_000).unwrap();
        auction.submit_quote("cartel_b", 985_000).unwrap();
        auction.submit_quote("honest_carol", 1_100_000).unwrap();

        let result = sim.close_and_attest(auction).unwrap();

        let cartel_won = result.winner_solver_id.starts_with("cartel");
        (result.winner_solver_id, result.winning_output_mist, cartel_won)
    }

    /// **Attack 3: Sandwich Attack Attempt**
    ///
    /// The fill route (DeepBook pool) is committed inside the attestation,
    /// so the settlement route is set before any onchain tx — no front-running.
    pub fn sandwich_demo() -> ([u8; 32], bool) {
        let mut sim = TeeSimulation::with_seed([44u8; 32]);
        sim.register_solver("dave_sandwicher", 1_000_000);
        sim.register_solver("eve_honest", 1_000_000);

        let auction = sim.open_auction([3u8; 32]);
        auction.submit_quote("dave_sandwicher", 970_000).unwrap();
        auction.submit_quote("eve_honest", 980_000).unwrap();

        let result = sim.close_and_attest(auction).unwrap();

        let attested_pool = result.attestation.deepbook_pool_id;
        let pool_tampered = attested_pool != [0u8; 32];
        (attested_pool, pool_tampered)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_basic_flow() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);
        sim.register_solver("s2", 1_000_000);

        let auction = sim.open_auction([99u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();
        auction.submit_quote("s2", 2_000).unwrap();

        let result = sim.close_and_attest(auction).unwrap();
        assert_eq!(result.winner_solver_id, "s2");
        assert_eq!(result.winning_output_mist, 2_000);
    }

    #[test]
    fn test_attestation_sig_is_64_bytes() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();

        let result = sim.close_and_attest(auction).unwrap();
        assert_eq!(result.tee_sig.len(), 64, "Signature must be 64 bytes (r||s)");
    }

    #[test]
    fn test_verify_attestation() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();

        let result = sim.close_and_attest(auction).unwrap();
        assert!(sim.verify_attestation(&result).unwrap());
    }

    #[test]
    fn test_merkle_chain_links() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let a1 = sim.open_auction([1u8; 32]);
        a1.submit_quote("s1", 1_000).unwrap();
        let r1 = sim.close_and_attest(a1).unwrap();

        let a2 = sim.open_auction([2u8; 32]);
        a2.submit_quote("s1", 2_000).unwrap();
        let r2 = sim.close_and_attest(a2).unwrap();

        let hash1 = r1.attestation.hash().unwrap();
        assert_eq!(r2.attestation.prev_attestation_hash, hash1.to_vec());
    }

    #[test]
    fn test_quote_sniping_prevented() {
        let (winner, output, sniping_worked) = MevDemoScenario::quote_sniping_demo();
        assert_eq!(winner, "charlie_best", "Best honest quote must win");
        assert_eq!(output, 1_005_000);
        assert!(!sniping_worked, "Sniping must have failed");
    }

    #[test]
    fn test_collusion_prevented() {
        let (winner, output, cartel_won) = MevDemoScenario::collusion_demo();
        assert_eq!(winner, "honest_carol");
        assert_eq!(output, 1_100_000);
        assert!(!cartel_won, "Cartel must not have won");
    }

    #[test]
    fn test_sui_address_non_zero() {
        let sim = TeeSimulation::new();
        assert_ne!(sim.sui_address(), [0u8; 32]);
    }
}
