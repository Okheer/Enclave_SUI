#[test_only]
module enclave_modules::settlement_tests;

use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::clock::{Self, Clock};
use sui::test_scenario::{Self, Scenario};
use sui::ecdsa_k1;
use sui::object;

use std::bcs;

use enclave_modules::intent_pool::{Self, Intent};
use enclave_modules::solver_registry::{Self, SolverRegistry};
use enclave_modules::solvex_settlement::{Self, SettlementConfig, Attestation};

public struct USDC has copy, drop {}

const ADMIN: address = @0xA;
const SOLVER: address = @0xB;
const USER: address = @0xC;
const FEE_RECIPIENT: address = @0xD;
const TEE_SEED: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000001";

fun setup_env(scenario: &mut Scenario) {
    test_scenario::next_tx(scenario, ADMIN);
    {
        solver_registry::create_registry_for_testing(FEE_RECIPIENT, test_scenario::ctx(scenario));
    };

    test_scenario::next_tx(scenario, ADMIN);
    {
        solvex_settlement::create_config_for_testing(FEE_RECIPIENT, test_scenario::ctx(scenario));
    };

    test_scenario::next_tx(scenario, ADMIN);
    {
        let clock = clock::create_for_testing(test_scenario::ctx(scenario));
        clock::share_for_testing(clock);
    };
}

#[test]
fun test_settle_success() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_env(&mut scenario);

    let tee_seed = TEE_SEED;
    let kp = ecdsa_k1::secp256k1_keypair_from_seed(&tee_seed);
    let tee_pk = *ecdsa_k1::public_key(&kp);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(10_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, tee_pk, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let mut config = test_scenario::take_shared<SettlementConfig>(&scenario);
        let intent = test_scenario::take_shared<Intent<SUI, USDC>>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);

        let intent_id = intent_pool::intent_id(&intent);

        let attestation = solvex_settlement::create_attestation(
            intent_id,
            SOLVER,
            200_000,
            object::id_from_address(@0x0),
            vector[],
            x"deadbeef",
        );

        let attestation_bytes = bcs::to_bytes(&attestation);
        let tee_sig = ecdsa_k1::secp256k1_sign(
            ecdsa_k1::private_key(&kp),
            &attestation_bytes,
            0,
            false,
        );

        let coin_out = coin::mint_for_testing<USDC>(200_000, test_scenario::ctx(&mut scenario));

        solvex_settlement::settle_intent_with_output(
            &mut config, &mut registry,
            intent, attestation, tee_sig,
            coin_out,
            &clock, test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(registry);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let config = test_scenario::take_shared<SettlementConfig>(&scenario);
        let chain_head = solvex_settlement::get_chain_head(&config);
        assert!(vector::length(&chain_head) == 32, 0);
        test_scenario::return_shared(config);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 4)]
fun test_zero_output_amount_rejected() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_env(&mut scenario);

    let tee_seed = TEE_SEED;
    let kp = ecdsa_k1::secp256k1_keypair_from_seed(&tee_seed);
    let tee_pk = *ecdsa_k1::public_key(&kp);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(10_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, tee_pk, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let mut config = test_scenario::take_shared<SettlementConfig>(&scenario);
        let intent = test_scenario::take_shared<Intent<SUI, USDC>>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);

        let intent_id = intent_pool::intent_id(&intent);

        let attestation = solvex_settlement::create_attestation(
            intent_id,
            SOLVER,
            0,
            object::id_from_address(@0x0),
            vector[],
            x"",
        );

        let attestation_bytes = bcs::to_bytes(&attestation);
        let tee_sig = ecdsa_k1::secp256k1_sign(
            ecdsa_k1::private_key(&kp),
            &attestation_bytes,
            0,
            false,
        );

        let coin_out = coin::mint_for_testing<USDC>(0, test_scenario::ctx(&mut scenario));

        solvex_settlement::settle_intent_with_output(
            &mut config, &mut registry,
            intent, attestation, tee_sig,
            coin_out,
            &clock, test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(registry);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 3)]
fun test_chain_continuity_enforced() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_env(&mut scenario);

    let tee_seed = TEE_SEED;
    let kp = ecdsa_k1::secp256k1_keypair_from_seed(&tee_seed);
    let tee_pk = *ecdsa_k1::public_key(&kp);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(10_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, tee_pk, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let mut config = test_scenario::take_shared<SettlementConfig>(&scenario);
        let intent = test_scenario::take_shared<Intent<SUI, USDC>>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);

        let intent_id = intent_pool::intent_id(&intent);

        let attestation = solvex_settlement::create_attestation(
            intent_id,
            SOLVER,
            200_000,
            object::id_from_address(@0x0),
            x"deadbeef",
            x"",
        );

        let attestation_bytes = bcs::to_bytes(&attestation);
        let tee_sig = ecdsa_k1::secp256k1_sign(
            ecdsa_k1::private_key(&kp),
            &attestation_bytes,
            0,
            false,
        );

        let coin_out = coin::mint_for_testing<USDC>(200_000, test_scenario::ctx(&mut scenario));

        solvex_settlement::settle_intent_with_output(
            &mut config, &mut registry,
            intent, attestation, tee_sig,
            coin_out,
            &clock, test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(registry);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 2)]
fun test_min_amount_out_enforced() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_env(&mut scenario);

    let tee_seed = TEE_SEED;
    let kp = ecdsa_k1::secp256k1_keypair_from_seed(&tee_seed);
    let tee_pk = *ecdsa_k1::public_key(&kp);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(10_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, tee_pk, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, USER);
    {
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let coin_in = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        intent_pool::submit_intent<SUI, USDC>(coin_in, 100_000, 9999999999999, 42, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let mut config = test_scenario::take_shared<SettlementConfig>(&scenario);
        let intent = test_scenario::take_shared<Intent<SUI, USDC>>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);

        let intent_id = intent_pool::intent_id(&intent);

        let attestation = solvex_settlement::create_attestation(
            intent_id,
            SOLVER,
            50_000,
            object::id_from_address(@0x0),
            vector[],
            x"",
        );

        let attestation_bytes = bcs::to_bytes(&attestation);
        let tee_sig = ecdsa_k1::secp256k1_sign(
            ecdsa_k1::private_key(&kp),
            &attestation_bytes,
            0,
            false,
        );

        let coin_out = coin::mint_for_testing<USDC>(50_000, test_scenario::ctx(&mut scenario));

        solvex_settlement::settle_intent_with_output(
            &mut config, &mut registry,
            intent, attestation, tee_sig,
            coin_out,
            &clock, test_scenario::ctx(&mut scenario),
        );

        test_scenario::return_shared(registry);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}
