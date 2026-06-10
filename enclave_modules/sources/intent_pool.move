module enclave_modules::intent_pool;

use sui::balance::Balance;
use sui::coin::{Self, Coin};
use sui::clock::{Self, Clock};
use std::type_name::{Self, TypeName};


// === Objects ===
/// @notice The on-chain escrow vault representing a user's pending trade request.
/// @dev    Structurally replaces the EVM `escrows` mapping. The object's existence implies a PENDING state.
///         Double-settlement is prevented natively by consuming (deleting) this object upon settlement.
///         The `<phantom CoinIn>` type parameter allows this single struct to handle any native Sui asset.
/// @param  id              The globally unique identifier for this Move object.
/// @param  user            Address of the original depositor who created the intent.
/// @param  coin_in         The physical `Balance` vault holding the escrowed input tokens.
/// @param  amount_in       The exact quantity of the input coin deposited.
/// @param  token_in        Type identifier for the input token (for off-chain solver routing).
/// @param  token_out       Type identifier for the desired output token.
/// @param  min_amount_out  The minimum amount of `token_out` the solver must deliver off-chain.
/// @param  deadline_ms     Unix timestamp (in ms) when this order expires and becomes refundable.
/// @param  nonce           Advisory only. Kept for EVM UI/indexer parity. Unneeded for on-chain replay protection.
/// @param  intent_hash     The canonical, UID-seeded digest that the TEE solver signs to authorize settlement.
public struct Intent<phantom CoinIn> has key {
    id: UID,
    user: address,
    coin_in: Balance<CoinIn>,
    amount_in: u64,
    token_in: TypeName,
    token_out: TypeName,
    min_amount_out: u64,
    deadline_ms: u64,
    nonce: u64,
    intent_hash: vector<u8>,
}


/// @notice Creates a new intent escrow vault and shares it on-chain for solvers to fulfill.
/// @dev    Direct submission path. The user's transaction signature natively replaces EVM EIP-712 authorization.
///         Reverts if the deposit is zero, the deadline has already passed, or input/output tokens are identical.
///         Shares the resulting `Intent` object globally so anyone (settlement module or user) can reference it.
/// @param  coin_in         The physical `Coin` object deposited by the user to be escrowed.
/// @param  min_amount_out  The minimum amount of `CoinOut` the user requires from the solver.
/// @param  deadline_ms     Unix timestamp (in milliseconds) after which the intent can be refunded.
/// @param  nonce           Advisory only. Preserved for UI/indexer parity with the EVM version.
/// @param  clock           Shared Sui `Clock` object used to validate the current time against the deadline.
/// @param  ctx             Transaction context, used to fetch the sender address and generate a unique `UID`.
public fun submit_intent<CoinIn, CoinOut>(
    coin_in: Coin<CoinIn>,
    min_amount_out: u64,
    deadline_ms: u64,
    nonce: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {

}

//Refund
public fun refund_expired<CoinIn>(
    intent: Intent<CoinIn>,
    clock: &Clock,
    ctx: &mut TxContext,
) {

}

