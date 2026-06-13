/// Thin wrapper around DeepBook v3's `Pool<Base, Quote>` swap entrypoints.
/// Provides a unified `execute_fill` interface that the settlement module
/// calls to route the escrowed input coin through DeepBook and obtain the
/// output coin. Handles DEEP fee payment and returns unused DEEP + leftover
/// base back to the caller.
module enclave_modules::deepbook_router;

use sui::coin::{Self, Coin};
use sui::clock::Clock;

use deepbook::pool::{Self, Pool};
use token::deep::DEEP;

/// Minimum output not met after swap.
const EMinOutputNotMet: u64 = 0;

/// Swaps `coin_in` for the paired asset through the given DeepBook `pool`.
///
/// # Direction
/// Assumes `Pool<In, Out>` is ordered such that `In` = base asset, `Out` =
/// quote asset. The swap always executes as base → quote via
/// `swap_exact_base_for_quote`.
///
/// # DEEP Fees
/// DeepBook charges fees in DEEP tokens. The caller must supply a `deep_fee`
/// coin with sufficient DEEP to cover the taker fee. Any unused DEEP is
/// returned so it can be reused for subsequent intents.
///
/// # Returns
/// - `Coin<Out>` — the output asset received from DeepBook (the fill).
/// - `Coin<In>`  — any leftover base that could not be swapped (lot-size
///    remainder).
/// - `Coin<DEEP>` — the unused portion of the `deep_fee` deposit.
public fun execute_fill<In, Out>(
    pool: &mut Pool<In, Out>,
    coin_in: Coin<In>,
    deep_fee: Coin<DEEP>,
    min_out: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): (Coin<Out>, Coin<In>, Coin<DEEP>) {
    let (base_leftover, quote_out, deep_remainder) =
        pool::swap_exact_base_for_quote(pool, coin_in, deep_fee, min_out, clock, ctx);

    assert!(coin::value(&quote_out) >= min_out, EMinOutputNotMet);

    (quote_out, base_leftover, deep_remainder)
}

/// Returns the expected output amount for a given input amount, without
/// executing a swap. Useful for the TEE solver engine to price intents.
public fun quote_fill<In, Out>(
    pool: &Pool<In, Out>,
    amount_in: u64,
    clock: &Clock,
): (u64, u64, u64) {
    pool::get_quote_quantity_out(pool, amount_in, clock)
}
