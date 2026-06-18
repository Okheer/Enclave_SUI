use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Sui type aliases – lightweight, avoiding sui-types crate dependency
// ─────────────────────────────────────────────────────────────────────────────

/// 32-byte Sui address.
pub type SuiAddress = [u8; 32];

/// 32-byte Sui object ID (matches `sui::object::ID` / `UID`).
pub type ObjectID = [u8; 32];

/// 33-byte compressed secp256k1 public key (as stored in `SolverRegistry`).
pub type CompressedPubKey = [u8; 33];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn parse_sui_address(hex_str: &str) -> Result<SuiAddress, String> {
    let hex = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

pub fn parse_object_id(hex_str: &str) -> Result<ObjectID, String> {
    parse_sui_address(hex_str)
}

// ─────────────────────────────────────────────────────────────────────────────
// Types aligned with Move structs (intent_pool.move / solvex_settlement.move)
// ─────────────────────────────────────────────────────────────────────────────

/// User intent — offchain representation (mirrors `Intent<In, Out>`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Intent {
    /// Sui address of the user who submitted the intent.
    pub user: SuiAddress,
    /// Amount of input tokens (u64 on Sui, unlike EVM U256).
    pub amount_in: u64,
    /// Minimum output amount the user will accept.
    pub min_amount_out: u64,
    /// Deadline in milliseconds (unix epoch).
    pub deadline_ms: u64,
    /// User-provided nonce for intent uniqueness.
    pub nonce: u64,
    /// 32-byte intent hash (computed on-chain by `intent_pool`).
    pub intent_hash: [u8; 32],
}

impl Intent {
    /// The offchain engine does not compute the hash locally — it receives it
    /// from the on-chain `intent_pool` event. This is a no-op placeholder.
    pub fn hash(&self) -> [u8; 32] {
        self.intent_hash
    }
}

/// Registered solver information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solver {
    pub id: String,
    /// 33-byte compressed secp256k1 public key (matches `SolverRecord.tee_pubkey`).
    pub pubkey: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

/// Quote submitted by a solver during sealed auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteData {
    pub solver_id: String,
    /// Output amount the solver commits to return (u64 on Sui).
    pub output_amount: u64,
    /// DeepBook pool ID — replaces EVM `fill_route`.
    pub deepbook_pool_id: ObjectID,
    /// Gas estimate in MIST (u64, not U256).
    pub gas_estimate: u64,
    #[serde(default = "chrono::Utc::now")]
    pub timestamp: DateTime<Utc>,
}

/// Sealed solver registration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverRegistration {
    pub solver_id: String,
    pub tee_pubkey: Vec<u8>,
    /// Stake in MIST (u64, not U256).
    pub stake_amount: u64,
}

/// Result of sealed competition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitionResult {
    pub winner_solver_id: String,
    pub winning_output: u64,
    pub deepbook_pool_id: ObjectID,
    pub all_quotes_count: u32,
}

/// Configuration for intent conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentConditions {
    pub allows_partial_fill: bool,
    pub requires_single_solver: bool,
    pub max_return_value_loss_bps: u16,
}

impl Default for IntentConditions {
    fn default() -> Self {
        Self {
            allows_partial_fill: false,
            requires_single_solver: true,
            max_return_value_loss_bps: 50,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sui_address() {
        let hex = "0x".to_owned() + &"aa".repeat(32);
        let addr = parse_sui_address(&hex).unwrap();
        assert_eq!(addr.len(), 32);
        assert_eq!(addr[0], 0xaa);
    }

    #[test]
    fn test_parse_sui_address_no_prefix() {
        let hex = "bb".repeat(32);
        let addr = parse_sui_address(&hex).unwrap();
        assert_eq!(addr[0], 0xbb);
    }

    #[test]
    fn test_parse_sui_address_wrong_length() {
        let result = parse_sui_address("0xabcd");
        assert!(result.is_err());
    }
}
