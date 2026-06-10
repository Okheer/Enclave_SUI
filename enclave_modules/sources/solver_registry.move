module enclave_module::solver_registry;

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
const REP_SUSPEND_THRESHOLD: u64 = 300; // R < 0.30
const REP_PREMIUM_THRESHOLD: u64 = 850; // R > 0.85 — defined for parity with
                                         // the Solidity constant; like the
                                         // original, nothing gates on it yet.
const REP_DEFAULT: u64 = 500;

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
    /// 33-byte COMPRESSED secp256k1 public key. This is the one genuine
    /// format change from the EVM version, which stored 65-byte
    /// *uncompressed* keys: Sui's `ecdsa_k1::secp256k1_verify` expects the
    /// compressed form, so the TEE enclave should emit compressed pubkeys
    /// when targeting this contract. See `solvex_verifier`.
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
    /// Mirrors `solverList` — Table can't be iterated directly in Move, so
    /// we keep a parallel vector for pagination, same as the Solidity
    /// version kept an array alongside its mapping for the same reason.
    solver_list: vector<address>,
    fee_recipient: address,
}
// === Events ===

public struct SolverRegistered has copy, drop { solver: address, tee_pubkey: vector<u8>, stake: u64 }
public struct SolverKeyRotated has copy, drop { solver: address, new_pubkey: vector<u8> }


// === Init / setup ===
fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
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

/// @notice Updates the TEE public key for an actively registered solver.
/// @dev    Reverts if the solver is inactive, slashed, or if the key is not 33 bytes.
///         Updates the `key_registered_at_ms` timer, which is typically used to enforce grace periods.
/// @param  registry    The shared `SolverRegistry` state object.
/// @param  new_pubkey  The new 33-byte compressed secp256k1 public key.
/// @param  clock       Shared Sui `Clock` object to record the rotation timestamp.
/// @param  ctx         Transaction context to identify the calling solver.
public fun rotate_tee_key(
    registry: &mut SolverRegistry,
    new_pubkey: vector<u8>,
    clock: &Clock,
    ctx: &TxContext,
){

}

/// @notice Allows an active, unslashed solver to increase their locked stake.
/// @dev    Uses `balance::join` to merge the new deposit directly into the solver's existing stake balance.
/// @param  registry    The shared `SolverRegistry` state object.
/// @param  stake       The additional `Coin<SUI>` to add to the locked stake.
/// @param  ctx         Transaction context to identify the calling solver.
public fun add_stake(registry: &mut SolverRegistry, stake: Coin<SUI>, ctx: &TxContext){

}

public fun withdraw_stake(registry: &mut SolverRegistry, ctx: &mut TxContext): Coin<SUI>{

}

// === Slashing & reputation (package-only — the SETTLER_ROLE equivalent) ===