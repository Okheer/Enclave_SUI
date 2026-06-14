#[allow(unused_const)]
module enclave_modules::solver_registry;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::clock::{Self, Clock};
use sui::table::{Self, Table};
use sui::event;

// === Constants ===
const MIN_STAKE: u64 = 0;
const KEY_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 days
const ALPHA_NUM: u128 = 5;
const ALPHA_DEN: u128 = 100;
const REP_SCALE: u64 = 1_000_000_000;
const REP_SUSPEND_THRESHOLD: u64 = 300_000_000; // R < 0.30
const REP_PREMIUM_THRESHOLD: u64 = 850_000_000; // R > 0.85 — reserved for Phase-2 fee-tier gating.
const REP_DEFAULT: u64 = 500_000_000;

// === Errors ===
const EAlreadyRegistered: u64 = 0;
const ESolverSlashedOut: u64 = 1;
const EInvalidPubkey: u64 = 2;
const ESolverNotActive: u64 = 3;
const ESlashExceedsStake: u64 = 4;
const EInsufficientStake: u64 = 5;

// === Objects ===
public struct AdminCap has key, store { id: UID }

public struct SolverRecord has store {
    /// 33-byte compressed secp256k1 public key. Sui's `ecdsa_k1::secp256k1_verify`
    /// expects compressed keys, so the TEE enclave must emit compressed pubkeys
    /// when targeting this module. See `solvex_verifier`.
    tee_pubkey: vector<u8>,
    key_registered_at_ms: u64,
    stake: Balance<SUI>,
    reputation: u64,
    slashed: bool,
    active: bool,
}

public struct SolverRegistry has key {
    id: UID,
    solvers: Table<address, SolverRecord>,
    /// Parallel vector for paginated iteration. `Table` has no Move-native
    /// iteration, so a side vector of solver addresses enables paginated reads
    /// via `get_solvers`.
    solver_list: vector<address>,
    fee_recipient: address,
}
// === Events ===

public struct SolverRegistered has copy, drop { solver: address, tee_pubkey: vector<u8>, stake: u64 }
public struct SolverKeyRotated has copy, drop { solver: address, new_pubkey: vector<u8> }
public struct SolverSlashed has copy, drop { solver: address, amount: u64, reason: vector<u8> }
public struct SolverSuspended has copy, drop { solver: address }
public struct ReputationUpdated has copy, drop { solver: address, old_rep: u64, new_rep: u64 }
public struct StakeWithdrawn has copy, drop { solver: address, amount: u64 }


// === Init / setup ===
fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
}

public fun create_registry(_: &AdminCap, fee_recipient: address, ctx: &mut TxContext) {
    transfer::share_object(SolverRegistry {
        id: object::new(ctx),
        solvers: table::new(ctx),
        solver_list: vector[],
        fee_recipient,
    });
}


// === Registration & key management ===

/// @notice Registers a new solver by locking their SUI stake and recording their TEE public key.
/// @dev    Reverts if the stake is below `MIN_STAKE` or if the pubkey is not exactly 33 bytes (compressed).
///         Note: Voluntary re-registration after `withdraw_stake` is not supported in this version,
///         as the inactive record remains in the Table.
/// @param  registry    The shared `SolverRegistry` state object.
/// @param  stake       The physical `Coin<SUI>` object representing the solver's initial locked stake.
/// @param  tee_pubkey  The 33-byte compressed secp256k1 public key of the solver's TEE enclave.
/// @param  clock       Shared Sui `Clock` object to timestamp when the key was registered.
/// @param  ctx         Transaction context, used to identify the calling solver.
public fun register_solver(
    registry: &mut SolverRegistry,
    stake: Coin<SUI>,
    tee_pubkey: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
     let solver = tx_context::sender(ctx);
    let stake_value = coin::value(&stake);
    assert!(stake_value >= MIN_STAKE, EInsufficientStake);
    assert!(!table::contains(&registry.solvers, solver), EAlreadyRegistered);
    assert!(vector::length(&tee_pubkey) == 33, EInvalidPubkey);

    table::add(&mut registry.solvers, solver, SolverRecord {
        tee_pubkey,
        key_registered_at_ms: clock::timestamp_ms(clock),
        stake: coin::into_balance(stake),
        reputation: REP_DEFAULT,
        slashed: false,
        active: true,
    });
    vector::push_back(&mut registry.solver_list, solver);

    event::emit(SolverRegistered { solver, tee_pubkey, stake: stake_value });

}

public fun rotate_tee_key(
    registry: &mut SolverRegistry,
    new_pubkey: vector<u8>,
    clock: &Clock,
    ctx: &TxContext,
) {
    let solver = tx_context::sender(ctx);
    assert!(table::contains(&registry.solvers, solver), ESolverNotActive);
    let rec = table::borrow_mut(&mut registry.solvers, solver);
    assert!(rec.active && !rec.slashed, ESolverNotActive);
    assert!(vector::length(&new_pubkey) == 33, EInvalidPubkey);
    rec.tee_pubkey = new_pubkey;
    rec.key_registered_at_ms = clock::timestamp_ms(clock);
    event::emit(SolverKeyRotated { solver, new_pubkey: rec.tee_pubkey });
}

public fun add_stake(registry: &mut SolverRegistry, stake: Coin<SUI>, ctx: &TxContext) {
    let solver = tx_context::sender(ctx);
    let rec = table::borrow_mut(&mut registry.solvers, solver);
    assert!(rec.active && !rec.slashed, ESolverNotActive);
    balance::join(&mut rec.stake, coin::into_balance(stake));
}

public fun withdraw_stake(registry: &mut SolverRegistry, ctx: &mut TxContext): Coin<SUI> {
    let solver = tx_context::sender(ctx);
    let rec = table::borrow_mut(&mut registry.solvers, solver);
    assert!(rec.active && !rec.slashed, ESolverNotActive);
    let amount = balance::value(&rec.stake);
    let withdrawn = balance::split(&mut rec.stake, amount);
    rec.active = false;
    event::emit(StakeWithdrawn { solver, amount });
    coin::from_balance(withdrawn, ctx)
}

// === Slashing & reputation (package-only — the SETTLER_ROLE equivalent) ===
public(package) fun slash_solver(
    registry: &mut SolverRegistry,
    solver: address,
    amount: u64,
    reason: vector<u8>,
    ctx: &mut TxContext,
): Coin<SUI> {
    assert!(table::contains(&registry.solvers, solver), ESolverNotActive);
    let rec = table::borrow_mut(&mut registry.solvers, solver);
    assert!(rec.active, ESolverNotActive);
    assert!(!rec.slashed, ESolverSlashedOut);
    assert!(amount <= balance::value(&rec.stake), ESlashExceedsStake);

    let slashed_balance = balance::split(&mut rec.stake, amount);
    event::emit(SolverSlashed { solver, amount, reason });

    if (balance::value(&rec.stake) < MIN_STAKE) {
        rec.active = false;
        event::emit(SolverSuspended { solver });
    };
    if (balance::value(&rec.stake) == 0) {
        rec.slashed = true;
    };

    coin::from_balance(slashed_balance, ctx)
}

/// R_new = (alpha * accuracy + (1 - alpha) * R_old), exponential moving
/// average computed in u128 to avoid overflow before the final division.
public(package) fun update_reputation(registry: &mut SolverRegistry, solver: address, accuracy: u64) {
    assert!(table::contains(&registry.solvers, solver), ESolverNotActive);
    let rec = table::borrow_mut(&mut registry.solvers, solver);
    assert!(rec.active, ESolverNotActive);

    let old_rep = rec.reputation;
    let weighted = (ALPHA_NUM * (accuracy as u128)) + ((ALPHA_DEN - ALPHA_NUM) * (old_rep as u128));
    let new_rep = (weighted / ALPHA_DEN) as u64;

    rec.reputation = new_rep;
    event::emit(ReputationUpdated { solver, old_rep, new_rep });

    if (new_rep < REP_SUSPEND_THRESHOLD) {
        rec.active = false;
        event::emit(SolverSuspended { solver });
    };
}

// === Views ===

public fun is_valid_solver(registry: &SolverRegistry, solver: address, clock: &Clock): bool {
    if (!table::contains(&registry.solvers, solver)) { return false };
    let rec = table::borrow(&registry.solvers, solver);
    rec.active && !rec.slashed && (clock::timestamp_ms(clock) - rec.key_registered_at_ms < KEY_TTL_MS)
}

public fun get_tee_public_key(registry: &SolverRegistry, solver: address): vector<u8> {
    table::borrow(&registry.solvers, solver).tee_pubkey
}

public fun get_reputation(registry: &SolverRegistry, solver: address): u64 {
    table::borrow(&registry.solvers, solver).reputation
}

public fun get_stake(registry: &SolverRegistry, solver: address): u64 {
    balance::value(&table::borrow(&registry.solvers, solver).stake)
}

public fun fee_recipient(registry: &SolverRegistry): address {
    registry.fee_recipient
}

public fun solver_count(registry: &SolverRegistry): u64 {
    vector::length(&registry.solver_list)
}

public fun get_solvers(registry: &SolverRegistry, offset: u64, limit: u64): vector<address> {
    let total = vector::length(&registry.solver_list);
    let mut result = vector[];
    if (offset >= total || limit == 0) { return result };

    let mut end = offset + limit;
    if (end > total) { end = total };

    let mut i = offset;
    while (i < end) {
        vector::push_back(&mut result, *vector::borrow(&registry.solver_list, i));
        i = i + 1;
    };
    result
}

#[test_only]
public fun rep_premium_threshold(): u64 { REP_PREMIUM_THRESHOLD }

#[test_only]
public fun create_registry_for_testing(fee_recipient: address, ctx: &mut TxContext) {
    transfer::share_object(SolverRegistry {
        id: object::new(ctx),
        solvers: table::new(ctx),
        solver_list: vector[],
        fee_recipient,
    });
}
