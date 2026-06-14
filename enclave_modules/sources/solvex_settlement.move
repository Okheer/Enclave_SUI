/// Atomic settlement pipeline: validate intent -> verify TEE attestation ->
/// swap escrowed Coin<In> through DeepBook -> deliver Coin<Out> to user ->
/// update attestation chain + solver reputation. All sibling modules live
/// in the same package and are called directly.
#[allow(lint(self_transfer))]
module enclave_modules::solvex_settlement;

use sui::coin::{Self, Coin};
use sui::clock::{Self, Clock};
use sui::hash;
use sui::table::{Self, Table};
use sui::event;
use std::bcs;

use enclave_modules::intent_pool::{Self, Intent};
use enclave_modules::solver_registry::{Self, SolverRegistry};
use enclave_modules::solvex_verifier;
use enclave_modules::deepbook_router;

use deepbook::pool::Pool;
use token::deep::DEEP;

// === Constants ===
const MAX_ACCURACY: u64 = 1_000_000_000;

// === Errors ===
const EAlreadySettled: u64 = 0;
const EInvalidSolver: u64 = 1;
const EOutputBelowMinimum: u64 = 2;
const EChainBroken: u64 = 3;
const EZeroOutput: u64 = 4;
const EAttestationVerificationFailed: u64 = 5;
const EIntentExpired: u64 = 6;
const ESlashAmountZero: u64 = 7;
const EIntentNotExpired: u64 = 8;
const EWrongSolver: u64 = 9;
const ENoAuctionResult: u64 = 10;

// === Objects ===

public struct AdminCap has key, store { id: UID }

public struct SettlementConfig has key {
    id: UID,
    fee_recipient: address,
    /// Belt-and-suspenders replay guard — the real protection is structural
    /// (Intent object consumed at settlement).
    settled: Table<ID, bool>,
    /// Maps intent ID to winning solver for Phase-2 slashing.
    auction_results: Table<ID, address>,
    /// Head of the attestation hash chain. Empty vector = genesis sentinel.
    last_attestation_hash: vector<u8>,
}

/// TEE-signed proof that a sealed auction completed fairly.
/// Matches the ENCLAVE spec exactly.
#[allow(unused_field)]
public struct Attestation has copy, drop, store {
    intent_id: ID,
    winner_solver: address,
    output_amount: u64,
    deepbook_pool_id: ID,
    prev_attestation_hash: vector<u8>,
    walrus_blob_id: vector<u8>,
}

// === Events ===

public struct IntentSettled has copy, drop {
    intent_id: ID,
    solver: address,
    output_amount: u64,
    walrus_blob_id: vector<u8>,
}

public struct AttestationVerified has copy, drop {
    intent_id: ID,
    attestation_hash: vector<u8>,
    winner_solver: address,
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

/// Single-entry settlement point. Inside one PTB:
///   1. Verify the TEE attestation (signature + hash-chain continuity)
///   2. Consume (delete) the Intent object — replay is structurally impossible
///   3. Swap Coin<In> → Coin<Out> via DeepBook
///   4. Enforce min_amount_out slippage floor
///   5. Update attestation chain head
///   6. Update solver reputation
///   7. Emit events and transfer Coin<Out> to the user
///
/// If any step aborts the entire PTB reverts — escrow is never partially released.
public fun settle_intent<In, Out>(
    config: &mut SettlementConfig,
    registry: &mut SolverRegistry,
    intent: Intent<In, Out>,
    pool: &mut Pool<In, Out>,
    attestation: Attestation,
    tee_sig: vector<u8>,
    deep_fee: Coin<DEEP>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    // 1. Not already settled (belt-and-suspenders).
    assert!(!table::contains(&config.settled, attestation.intent_id), EAlreadySettled);

    // 2. Solver validity.
    assert!(solver_registry::is_valid_solver(registry, attestation.winner_solver, clock), EInvalidSolver);

    // 3. Zero-output guard.
    assert!(attestation.output_amount > 0, EZeroOutput);

    // 4. Hash-chain continuity.
    assert!(attestation.prev_attestation_hash == config.last_attestation_hash, EChainBroken);

    // 5. Build canonical attestation message and verify the TEE signature.
    let attestation_bytes = bcs::to_bytes(&attestation);
    let tee_pubkey = solver_registry::get_tee_public_key(registry, attestation.winner_solver);
    assert!(solvex_verifier::verify_attestation(attestation_bytes, tee_sig, tee_pubkey), EAttestationVerificationFailed);

    // 6. Check intent deadline.
    let dline = intent_pool::deadline_ms(&intent);
    assert!(clock::timestamp_ms(clock) <= dline, EIntentExpired);

    // 7. Consume the intent — structural replay guard.
    let (intent_id, user, coin_in, _amount_in, min_amount_out, _hash) =
        intent_pool::consume_intent(intent, attestation.winner_solver, ctx);
    assert!(intent_id == attestation.intent_id, EAlreadySettled);

    // 8. Swap the escrowed coin through DeepBook.
    let (coin_out, leftover, deep_remainder) =
        deepbook_router::execute_fill(pool, coin_in, deep_fee, min_amount_out, clock, ctx);

    // 9. Slippage enforcement.
    assert!(coin::value(&coin_out) >= min_amount_out, EOutputBelowMinimum);

    // 10. Mark settled.
    table::add(&mut config.settled, attestation.intent_id, true);

    // 11. Update attestation chain.
    let att_hash = hash::keccak256(&attestation_bytes);
    config.last_attestation_hash = att_hash;

    // 12. Update solver reputation.
    let mut accuracy = (((attestation.output_amount as u128) * (MAX_ACCURACY as u128)) / (min_amount_out as u128)) as u64;
    if (accuracy > MAX_ACCURACY) { accuracy = MAX_ACCURACY };
    solver_registry::update_reputation(registry, attestation.winner_solver, accuracy);

    // 13. Events.
    event::emit(AttestationVerified {
        intent_id: attestation.intent_id,
        attestation_hash: att_hash,
        winner_solver: attestation.winner_solver,
    });
    event::emit(IntentSettled {
        intent_id: attestation.intent_id,
        solver: attestation.winner_solver,
        output_amount: coin::value(&coin_out),
        walrus_blob_id: attestation.walrus_blob_id,
    });

    // 14. Deliver output to user. Return leftover base + unused DEEP to caller.
    transfer::public_transfer(coin_out, user);
    transfer::public_transfer(leftover, tx_context::sender(ctx));
    transfer::public_transfer(deep_remainder, tx_context::sender(ctx));
}

// === Phase-2 slash trigger ===

public fun record_auction_result(
    _: &AdminCap,
    config: &mut SettlementConfig,
    intent_id: ID,
    winner_solver: address,
) {
    table::add(&mut config.auction_results, intent_id, winner_solver);
}

public fun slash_non_fill<In, Out>(
    config: &mut SettlementConfig,
    registry: &mut SolverRegistry,
    intent: &Intent<In, Out>,
    winner_solver: address,
    slash_amount: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(slash_amount > 0, ESlashAmountZero);
    assert!(clock::timestamp_ms(clock) > intent_pool::deadline_ms(intent), EIntentNotExpired);

    let intent_id = intent_pool::intent_id(intent);
    assert!(table::contains(&config.auction_results, intent_id), ENoAuctionResult);
    let recorded = table::borrow(&config.auction_results, intent_id);
    assert!(*recorded == winner_solver, EWrongSolver);

    let slashed_coin = solver_registry::slash_solver(registry, winner_solver, slash_amount, b"non-fill", ctx);
    transfer::public_transfer(slashed_coin, solver_registry::fee_recipient(registry));

    event::emit(SolverSlashedForNonFill { solver: winner_solver, amount: slash_amount });
}

// === Test-only helpers ===

#[test_only]
public fun create_attestation(
    intent_id: ID,
    winner_solver: address,
    output_amount: u64,
    deepbook_pool_id: ID,
    prev_attestation_hash: vector<u8>,
    walrus_blob_id: vector<u8>,
): Attestation {
    Attestation { intent_id, winner_solver, output_amount, deepbook_pool_id, prev_attestation_hash, walrus_blob_id }
}

#[test_only]
public fun create_config_for_testing(fee_recipient: address, ctx: &mut TxContext) {
    transfer::share_object(SettlementConfig {
        id: object::new(ctx),
        fee_recipient,
        settled: table::new(ctx),
        auction_results: table::new(ctx),
        last_attestation_hash: vector[],
    });
}

#[test_only]
public fun settle_intent_with_output<In, Out>(
    config: &mut SettlementConfig,
    registry: &mut SolverRegistry,
    intent: Intent<In, Out>,
    attestation: Attestation,
    tee_sig: vector<u8>,
    coin_out: Coin<Out>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!table::contains(&config.settled, attestation.intent_id), EAlreadySettled);

    assert!(solver_registry::is_valid_solver(registry, attestation.winner_solver, clock), EInvalidSolver);

    assert!(attestation.output_amount > 0, EZeroOutput);

    assert!(attestation.prev_attestation_hash == config.last_attestation_hash, EChainBroken);

    let attestation_bytes = bcs::to_bytes(&attestation);
    let tee_pubkey = solver_registry::get_tee_public_key(registry, attestation.winner_solver);
    assert!(solvex_verifier::verify_attestation(attestation_bytes, tee_sig, tee_pubkey), EAttestationVerificationFailed);

    let dline = intent_pool::deadline_ms(&intent);
    assert!(clock::timestamp_ms(clock) <= dline, EIntentExpired);

    let (intent_id, user, coin_in, _amount_in, min_amount_out, _hash) =
        intent_pool::consume_intent(intent, attestation.winner_solver, ctx);
    assert!(intent_id == attestation.intent_id, EAlreadySettled);
    coin::burn_for_testing(coin_in);

    let coin_out_value = coin::value(&coin_out);
    assert!(coin_out_value >= min_amount_out, EOutputBelowMinimum);

    table::add(&mut config.settled, attestation.intent_id, true);

    let att_hash = hash::keccak256(&attestation_bytes);
    config.last_attestation_hash = att_hash;

    let mut accuracy = (((attestation.output_amount as u128) * (MAX_ACCURACY as u128)) / (min_amount_out as u128)) as u64;
    if (accuracy > MAX_ACCURACY) { accuracy = MAX_ACCURACY };
    solver_registry::update_reputation(registry, attestation.winner_solver, accuracy);

    event::emit(AttestationVerified {
        intent_id: attestation.intent_id,
        attestation_hash: att_hash,
        winner_solver: attestation.winner_solver,
    });
    event::emit(IntentSettled {
        intent_id: attestation.intent_id,
        solver: attestation.winner_solver,
        output_amount: coin_out_value,
        walrus_blob_id: attestation.walrus_blob_id,
    });

    transfer::public_transfer(coin_out, user);
}

// === Views ===

public fun is_settled(config: &SettlementConfig, intent_id: ID): bool {
    table::contains(&config.settled, intent_id) && *table::borrow(&config.settled, intent_id)
}

public fun get_chain_head(config: &SettlementConfig): vector<u8> {
    config.last_attestation_hash
}
