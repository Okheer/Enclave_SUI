#[test_only]
module enclave_modules::solver_registry_tests;

use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::clock::{Self, Clock};
use sui::test_scenario::{Self, Scenario};

use enclave_modules::solver_registry::{Self, SolverRegistry};

const ADMIN: address = @0xA;
const SOLVER: address = @0xB;
const FEE_RECIPIENT: address = @0xC;
const TEE_PK: vector<u8> = x"0263456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01";

fun setup_registry(scenario: &mut Scenario) {
    test_scenario::next_tx(scenario, ADMIN);
    {
        solver_registry::create_registry_for_testing(FEE_RECIPIENT, test_scenario::ctx(scenario));
    };
}

fun setup_clock(scenario: &mut Scenario) {
    test_scenario::next_tx(scenario, ADMIN);
    {
        let clock = clock::create_for_testing(test_scenario::ctx(scenario));
        clock::share_for_testing(clock);
    };
}

#[test]
fun test_init_and_create_registry() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_registry(&mut scenario);

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        assert!(solver_registry::solver_count(&registry) == 0, 0);
        assert!(solver_registry::fee_recipient(&registry) == FEE_RECIPIENT, 1);
        test_scenario::return_shared(registry);
    };

    test_scenario::end(scenario);
}

#[test]
fun test_register_solver_success() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_registry(&mut scenario);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, TEE_PK, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        assert!(solver_registry::solver_count(&registry) == 1, 0);
        assert!(solver_registry::is_valid_solver(&registry, SOLVER, &clock), 1);
        assert!(solver_registry::get_stake(&registry, SOLVER) == 1_000_000, 2);
        assert!(solver_registry::get_reputation(&registry, SOLVER) == 500_000_000, 3);
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 0)]
fun test_duplicate_registration_fails() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_registry(&mut scenario);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, TEE_PK, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, TEE_PK, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 2)]
fun test_invalid_pubkey_fails() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_registry(&mut scenario);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(
            &mut registry, stake,
            x"0263456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            &clock, test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}

#[test]
fun test_add_and_withdraw_stake() {
    let mut scenario = test_scenario::begin(ADMIN);
    setup_registry(&mut scenario);
    setup_clock(&mut scenario);

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let stake = coin::mint_for_testing<SUI>(1_000_000, test_scenario::ctx(&mut scenario));
        let clock = test_scenario::take_shared<Clock>(&scenario);
        solver_registry::register_solver(&mut registry, stake, TEE_PK, &clock, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let extra = coin::mint_for_testing<SUI>(500_000, test_scenario::ctx(&mut scenario));
        solver_registry::add_stake(&mut registry, extra, test_scenario::ctx(&mut scenario));
        test_scenario::return_shared(registry);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        assert!(solver_registry::get_stake(&registry, SOLVER) == 1_500_000, 0);
        test_scenario::return_shared(registry);
    };

    test_scenario::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let withdrawn = solver_registry::withdraw_stake(&mut registry, test_scenario::ctx(&mut scenario));
        coin::burn_for_testing(withdrawn);
        test_scenario::return_shared(registry);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let registry = test_scenario::take_shared<SolverRegistry>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        assert!(!solver_registry::is_valid_solver(&registry, SOLVER, &clock), 0);
        test_scenario::return_shared(registry);
        test_scenario::return_shared(clock);
    };

    test_scenario::end(scenario);
}
