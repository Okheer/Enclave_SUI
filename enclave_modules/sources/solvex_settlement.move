/// Atomic settlement pipeline: validate intent -> verify TEE attestation ->
/// min-output check -> CEI state writes -> consume the escrow -> distribute
/// fees -> update solver reputation -> emit events. All sibling modules
/// (`intent_pool`, `solver_registry`, `solvex_verifier`) live in the same
/// package and are called directly — no interface dispatch needed.
module enclave_modules::solvex_settlement;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::clock::{Self, Clock};
use sui::table::{Self, Table};
use sui::event;
use std::bcs;

use enclave_modules::intent_pool::{Self, Intent};
use enclave_modules::solver_registry::{Self, SolverRegistry};
use enclave_modules::solvex_verifier;

// === Constants ===
const PROTOCOL_FEE_BPS: u64 = 10; // 0.1%
const BPS_DENOM: u64 = 10_000;
const MAX_ACCURACY: u64 = 1_000_000_000;

// === Errors ===
const EAlreadySettled: u64 = 0;
const EInvalidSolver: u64 = 1;
const EOutputBelowMinimum: u64 = 2;
const EMerkleChainBroken: u64 = 3;
const EZeroOutput: u64 = 4;
const EAttestationVerificationFailed: u64 = 5;
const ESlashAmountZero: u64 = 6;
const EIntentNotExpired: u64 = 7;
const EWrongSolver: u64 = 8;
const ENoAuctionResult: u64 = 9;

// === Objects ===

public struct AdminCap has key, store { id: UID }

public struct SettlementConfig has key {
    id: UID,
    fee_recipient: address,
    /// Tracks settled intent hashes. Belt-and-suspenders guard: the real
    /// replay protection comes from consuming the `Intent` object itself.
    settled: Table<vector<u8>, bool>,
    /// Maps intent hash to winning solver for Phase-2 slashing.
    /// Written by `record_auction_result` and read by `slash_non_fill`.
    auction_results: Table<vector<u8>, address>,
    /// Head of the attestation chain. Empty `vector<u8>` is the genesis
    /// sentinel (analogous to the zero-hash default on account-based chains).
    last_attestation_hash: vector<u8>,
}

/// Attestation signed by the TEE proving the sealed auction result.
/// `fill_route` is a `vector<u8>` referencing a DeepBook pool object id
/// or a Walrus blob id with the off-chain route/quote record.
/// `checkpoint` is Sui's epoch-level freshness marker (analogous to block
/// number on account-based chains).
public struct Attestation has drop {
    intent_hash: vector<u8>,
    winner_solver: address,
    fill_route: vector<u8>,
    output_amount: u64,
    checkpoint: u64,
    prev_attestation_hash: vector<u8>,
}

// === Events ===

public struct IntentSettled has copy, drop {
    intent_hash: vector<u8>,
    winner_solver: address,
    fill_route: vector<u8>,
    output_amount: u64,
    fee_paid: u64,
    checkpoint: u64,
}

public struct AttestationVerified has copy, drop {
    intent_hash: vector<u8>,
    attestation_hash: vector<u8>,
    winner_solver: address,
}

public struct RewardDistributed has copy, drop {
    solver: address,
    solver_amount: u64,
    protocol_fee: u64,
}

public struct SolverSlashedForNonFill has copy, drop {
    solver: address,
    amount: u64,
}

// === Init / setup ===

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
}

public fun create_settlement_config(_: &AdminCap, fee_recipient: address, ctx: &mut TxContext) {
    transfer::share_object(SettlementConfig {
        id: object::new(ctx),
        fee_recipient,
        settled: table::new(ctx),
        auction_results: table::new(ctx),
        last_attestation_hash: vector[],
    });
}

// === Core settlement ===

/// Core settlement entrypoint. Takes the `Intent` shared object by value
/// (consuming/deleting it on success). Object consumption is the structural
/// replay guard — the intent object cannot be passed twice. The `settled`
/// table provides a secondary check and a public `is_settled` view.
public fun settle_intent<CoinIn>(
    config: &mut SettlementConfig,
    registry: &mut SolverRegistry,
    intent: Intent<CoinIn>,
    winner_solver: address,
    fill_route: vector<u8>,
    output_amount: u64,
    checkpoint: u64,
    prev_attestation_hash: vector<u8>,
    tee_sig: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let intent_hash = intent_pool::intent_hash(&intent);

    // 1. Not already settled.
    assert!(!table::contains(&config.settled, intent_hash), EAlreadySettled);

    // 2. Solver validity: active, not slashed, TEE key unexpired.
    assert!(solver_registry::is_valid_solver(registry, winner_solver, clock), EInvalidSolver);

    // 4. Zero-output guard.
    assert!(output_amount > 0, EZeroOutput);

    // 5. Merkle chain pre-check.
    assert!(prev_attestation_hash == config.last_attestation_hash, EMerkleChainBroken);

    // 3 (folded in) + 6. Build the canonical attestation message and verify
    // the TEE signature against it directly via `solvex_verifier`.
    let attestation = Attestation {
        intent_hash, winner_solver, fill_route, output_amount, checkpoint, prev_attestation_hash,
    };
    let attestation_bytes = bcs::to_bytes(&attestation);
    let tee_pubkey = solver_registry::get_tee_public_key(registry, winner_solver);
    let verified = solvex_verifier::verify_attestation(attestation_bytes, tee_sig, tee_pubkey);
    assert!(verified, EAttestationVerificationFailed);

    // 7. Min-output check against the escrow's own min_amount_out.
    let min_amount_out = intent_pool::min_amount_out(&intent);
    assert!(output_amount >= min_amount_out, EOutputBelowMinimum);

    // 8. State writes before anything else (CEI).
    table::add(&mut config.settled, intent_hash, true);
    let attest_hash = solvex_verifier::attestation_hash(&attestation_bytes);
    config.last_attestation_hash = attest_hash;

    // 9. Release the escrow. The escrowed deposit goes to the solver (not
    // back to the depositor) — delivering token_out to the user is trusted
    // to have happened off-chain as part of the attested fill.
    let (_user, coin_in, amount_in, _min_out, _hash) =
        intent_pool::consume_intent(intent, winner_solver, ctx);

    // 10. Fee distribution.
    let fee = distribute_rewards(config, coin_in, amount_in, winner_solver, ctx);

    // 11. Reputation update. accuracy = output/min_amount_out scaled by
    // REP_SCALE (1e9) and capped — a 2x fill scores the same as an
    // exact-floor fill in Phase 1 (fine for MVP; Phase 2 will use actual
    // quoted vs delivered for precision).
    let mut accuracy = (((output_amount as u128) * (MAX_ACCURACY as u128)) / (min_amount_out as u128)) as u64;
    if (accuracy > MAX_ACCURACY) { accuracy = MAX_ACCURACY };
    solver_registry::update_reputation(registry, winner_solver, accuracy);

    // 12. Events.
    event::emit(AttestationVerified { intent_hash, attestation_hash: attest_hash, winner_solver });
    event::emit(IntentSettled {
        intent_hash, winner_solver, fill_route, output_amount, fee_paid: fee, checkpoint,
    });
}

fun distribute_rewards<CoinIn>(
    config: &SettlementConfig,
    coin_in: Coin<CoinIn>,
    amount_in: u64,
    winner_solver: address,
    ctx: &mut TxContext,
): u64 {
    let fee = amount_in * PROTOCOL_FEE_BPS / BPS_DENOM;
    let mut balance_in: Balance<CoinIn> = coin::into_balance(coin_in);
    let fee_balance = balance::split(&mut balance_in, fee);

    transfer::public_transfer(coin::from_balance(balance_in, ctx), winner_solver);
    transfer::public_transfer(coin::from_balance(fee_balance, ctx), config.fee_recipient);

    event::emit(RewardDistributed { solver: winner_solver, solver_amount: amount_in - fee, protocol_fee: fee });
    fee
}

// === Phase-2 slash trigger ===

/// Phase-2 stub for posting an auction result before a fill window closes.
/// Gated by `AdminCap` for now; in production this should be triggered by
/// a TEE on-chain event or a governance oracle.
public fun record_auction_result(
    _: &AdminCap,
    config: &mut SettlementConfig,
    intent_hash: vector<u8>,
    winner_solver: address,
) {
    table::add(&mut config.auction_results, intent_hash, winner_solver);
}

/// Slashes a solver for failing to fill a won auction. Takes the `Intent` by
/// reference (not by value) so the escrow remains intact for the user to
/// call `intent_pool::refund_expired` separately after the deadline.
public fun slash_non_fill<CoinIn>(
    config: &mut SettlementConfig,
    registry: &mut SolverRegistry,
    intent: &Intent<CoinIn>,
    winner_solver: address,
    slash_amount: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(slash_amount > 0, ESlashAmountZero);
    assert!(clock::timestamp_ms(clock) > intent_pool::deadline_ms(intent), EIntentNotExpired);

    let intent_hash = intent_pool::intent_hash(intent);
    assert!(table::contains(&config.auction_results, intent_hash), ENoAuctionResult);
    let recorded = table::borrow(&config.auction_results, intent_hash);
    assert!(*recorded == winner_solver, EWrongSolver);

    let slashed_coin = solver_registry::slash_solver(registry, winner_solver, slash_amount, b"non-fill", ctx);
    transfer::public_transfer(slashed_coin, solver_registry::fee_recipient(registry));

    event::emit(SolverSlashedForNonFill { solver: winner_solver, amount: slash_amount });
}

// === Views ===

public fun is_settled(config: &SettlementConfig, intent_hash: vector<u8>): bool {
    table::contains(&config.settled, intent_hash) && *table::borrow(&config.settled, intent_hash)
}

public fun get_chain_head(config: &SettlementConfig): vector<u8> {
    config.last_attestation_hash
}

public fun compute_fee(amount: u64): (u64, u64) {
    let fee = amount * PROTOCOL_FEE_BPS / BPS_DENOM;
    (fee, amount - fee)
}
