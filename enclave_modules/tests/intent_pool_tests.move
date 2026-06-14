#[test_only]
module enclave_modules::intent_pool_tests;

use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::clock::{Self, Clock};
use sui::test_scenario::{Self, Scenario};

use enclave_modules::intent_pool::{Self, Intent};

public struct USDC has copy, drop {}

const USER: address = @0xA;
const SOLVER: address = @0xB;

fun setup_clock(scenario: &mut Scenario) {
    test_scenario::next_tx(scenario, USER);
    {
        let clock = clock::create_for_testing(test_scenario::ctx(scenario));
        clock::share_for_testing(clock);
    };
}

#[test]
fun test_submit_intent_success() {
    let mut scenario = test_scenario::begin(USER);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, USER);
    {
        let intent = test_scenario::take_shared<Intent<SUI, USDC>>(&scenario);
        assert!(intent_pool::user(&intent) == USER, 0);
        assert!(intent_pool::amount_in(&intent) == 1_000_000, 1);
        assert!(intent_pool::min_amount_out(&intent) == 100_000, 2);
        assert!(intent_pool::nonce(&intent) == 42, 3);
        test_scenario::return_shared(intent);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 0)]
fun test_zero_amount_fails() {
    let mut scenario = test_scenario::begin(USER);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(0, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 3)]
fun test_same_coin_type_fails() {
    let mut scenario = test_scenario::begin(USER);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, SUI>(coin_in, 100, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
fun test_consume_intent() {
    let mut scenario = test_scenario::begin(USER);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let intent = test_scenario::take_shared<Intent<SUI, USDC>>(&scenario);
        let (_id, user, coin_in, amount_in, min_out, _hash) =
            intent_pool::consume_intent(intent, SOLVER, test_scenario::ctx(&mut scenario));
        assert!(user == USER, 0);
        assert!(coin::value(&coin_in) == 1_000_000, 1);
        assert!(amount_in == 1_000_000, 2);
        assert!(min_out == 100_000, 3);
        coin::burn_for_testing(coin_in);
    };

    test_scenario::end(scenario);
}
