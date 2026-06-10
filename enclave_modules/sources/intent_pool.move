module enclave_modules::intent_pool;

use sui::balance::Balance;
use sui::coin::{Self, Coin};
use sui::clock::{Self, Clock};
use sui::hash;
use sui::event;
use std::bcs;
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

// === Events ===

public struct IntentSubmitted has copy, drop {
    intent_hash: vector<u8>,
    user: address,
    token_in: TypeName,
    token_out: TypeName,
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
     let amount_in = coin::value(&coin_in);
    assert!(amount_in > 0, EZeroAmount);
    assert!(clock::timestamp_ms(clock) <= deadline_ms, EDeadlinePassed);

    let token_in = type_name::get<CoinIn>();
    let token_out = type_name::get<CoinOut>();
    assert!(token_in != token_out, ESameToken);

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
        intent_hash, user, token_in, token_out, amount_in, min_amount_out, deadline_ms,
    });


    transfer::share_object(Intent<CoinIn> {
        id: uid,
        user,
        coin_in: coin::into_balance(coin_in),
        amount_in,
        token_in,
        token_out,
        min_amount_out,
        deadline_ms,
        nonce,
        intent_hash,
    });
}

//Refund
public fun refund_expired<CoinIn>(
    intent: Intent<CoinIn>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
  assert!(clock::timestamp_ms(clock) > intent.deadline_ms, EDeadlineNotReached);

    let Intent {
        id, user, coin_in, amount_in, token_in: _, token_out: _,
        min_amount_out: _, deadline_ms: _, nonce: _, intent_hash,
    } = intent;

    object::delete(id);
    event::emit(IntentRefunded { intent_hash, user, amount_in });
    transfer::public_transfer(coin::from_balance(coin_in, ctx), user);
}

public(package) fun consume_intent<CoinIn>(
    intent: Intent<CoinIn>,
    winner_solver: address,
    ctx: &mut TxContext,
): (address, Coin<CoinIn>, u64, u64, vector<u8>) {
    let Intent {
        id, user, coin_in, amount_in, token_in: _, token_out: _,
        min_amount_out, deadline_ms: _, nonce: _, intent_hash,
    } = intent;

    object::delete(id);
    event::emit(IntentFilled { intent_hash, winner_solver });

    (user, coin::from_balance(coin_in, ctx), amount_in, min_amount_out, intent_hash)
}

// === Read-only accessors (replace getEscrowRecord) ===

public fun user<CoinIn>(intent: &Intent<CoinIn>): address { intent.user }
public fun amount_in<CoinIn>(intent: &Intent<CoinIn>): u64 { intent.amount_in }
public fun min_amount_out<CoinIn>(intent: &Intent<CoinIn>): u64 { intent.min_amount_out }
public fun deadline_ms<CoinIn>(intent: &Intent<CoinIn>): u64 { intent.deadline_ms }
public fun nonce<CoinIn>(intent: &Intent<CoinIn>): u64 { intent.nonce }
public fun intent_hash<CoinIn>(intent: &Intent<CoinIn>): vector<u8> { intent.intent_hash }
public fun token_out<CoinIn>(intent: &Intent<CoinIn>): TypeName { intent.token_out }
