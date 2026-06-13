module enclave_modules::intent_pool;

use sui::balance::Balance;
use sui::coin::{Self, Coin};
use sui::clock::{Self, Clock};
use sui::hash;
use sui::event;
use std::bcs;
use std::type_name;

// === Objects ===
public struct Intent<phantom In, phantom Out> has key, store {
    id: UID,
    user: address,
    coin_in: Balance<In>,
    amount_in: u64,
    min_amount_out: u64,
    deadline_ms: u64,
    nonce: u64,
    intent_hash: vector<u8>,
}

// === Events ===

public struct IntentSubmitted has copy, drop {
    intent_hash: vector<u8>,
    user: address,
    amount_in: u64,
    min_amount_out: u64,
    deadline_ms: u64,
}

public struct IntentFilled has copy, drop {
    intent_hash: vector<u8>,
    winner_solver: address,
}

public struct IntentRefunded has copy, drop {
    intent_hash: vector<u8>,
    user: address,
    amount_in: u64,
}

// Error
const EZeroAmount: u64 = 0;
const EDeadlinePassed: u64 = 1;
const EDeadlineNotReached: u64 = 2;
const ESameToken: u64 = 3;

/// Creates a new intent escrow vault and shares it on-chain for solvers to fulfill.
/// Reverts if the deposit is zero, the deadline has passed, or In == Out.
public fun submit_intent<In, Out>(
    coin_in: Coin<In>,
    min_amount_out: u64,
    deadline_ms: u64,
    nonce: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let amount_in = coin::value(&coin_in);
    assert!(amount_in > 0, EZeroAmount);
    assert!(clock::timestamp_ms(clock) <= deadline_ms, EDeadlinePassed);
    assert!(type_name::with_defining_ids<In>() != type_name::with_defining_ids<Out>(), ESameToken);

    let user = tx_context::sender(ctx);
    let uid = object::new(ctx);

    let mut buf = object::uid_to_bytes(&uid);
    vector::append(&mut buf, bcs::to_bytes(&user));
    vector::append(&mut buf, bcs::to_bytes(&amount_in));
    vector::append(&mut buf, bcs::to_bytes(&min_amount_out));
    vector::append(&mut buf, bcs::to_bytes(&deadline_ms));
    vector::append(&mut buf, bcs::to_bytes(&nonce));
    let intent_hash = hash::keccak256(&buf);

    event::emit(IntentSubmitted {
        intent_hash, user, amount_in, min_amount_out, deadline_ms,
    });

    transfer::share_object(Intent<In, Out> {
        id: uid,
        user,
        coin_in: coin::into_balance(coin_in),
        amount_in,
        min_amount_out,
        deadline_ms,
        nonce,
        intent_hash,
    });
}

// Refund
public fun refund_expired<In, Out>(
    intent: Intent<In, Out>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(clock::timestamp_ms(clock) > intent.deadline_ms, EDeadlineNotReached);

    let Intent {
        id, user, coin_in, amount_in,
        min_amount_out: _, deadline_ms: _, nonce: _, intent_hash,
    } = intent;

    object::delete(id);
    event::emit(IntentRefunded { intent_hash, user, amount_in });
    transfer::public_transfer(coin::from_balance(coin_in, ctx), user);
}

/// Consumes the intent for settlement. Returns (intent_id, user, coin_in, amount_in, min_amount_out, intent_hash).
public(package) fun consume_intent<In, Out>(
    intent: Intent<In, Out>,
    winner_solver: address,
    ctx: &mut TxContext,
): (ID, address, Coin<In>, u64, u64, vector<u8>) {
    let intent_id = *object::uid_as_inner(&intent.id);
    let Intent {
        id, user, coin_in, amount_in,
        min_amount_out, deadline_ms: _, nonce: _, intent_hash,
    } = intent;

    object::delete(id);
    event::emit(IntentFilled { intent_hash, winner_solver });

    (intent_id, user, coin::from_balance(coin_in, ctx), amount_in, min_amount_out, intent_hash)
}

/// Returns the object ID of the intent.
public fun intent_id<In, Out>(intent: &Intent<In, Out>): ID {
    *object::uid_as_inner(&intent.id)
}

// === Read-only accessors ===

public fun user<In, Out>(intent: &Intent<In, Out>): address { intent.user }
public fun amount_in<In, Out>(intent: &Intent<In, Out>): u64 { intent.amount_in }
public fun min_amount_out<In, Out>(intent: &Intent<In, Out>): u64 { intent.min_amount_out }
public fun deadline_ms<In, Out>(intent: &Intent<In, Out>): u64 { intent.deadline_ms }
public fun nonce<In, Out>(intent: &Intent<In, Out>): u64 { intent.nonce }
public fun intent_hash<In, Out>(intent: &Intent<In, Out>): vector<u8> { intent.intent_hash }
