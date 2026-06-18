use crate::attestation::Attestation;
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ObjectReference,
    ProgrammableTransaction, SharedInput, TypeTag,
};

/// Builds `ProgrammableTransaction` values for the `settle_intent` Move call.
///
/// Each `build_*` method creates a complete PTB with all object inputs and
/// a single `Command::MoveCall` that matches the on-chain function signature:
///
/// ```move
/// public fun settle_intent<In, Out>(
///     config: &mut SettlementConfig,
///     registry: &mut SolverRegistry,
///     intent: Intent<In, Out>,
///     pool: &mut Pool<In, Out>,
///     attestation: Attestation,
///     tee_sig: vector<u8>,
///     deep_fee: Coin<DEEP>,
///     clock: &Clock,
///     ctx: &mut TxContext,
/// )
/// ```
#[derive(Clone)]
pub struct SettlementTxBuilder {
    package: Address,
    module: Identifier,
    function: Identifier,
}

impl SettlementTxBuilder {
    /// Create a new builder targeting `{package}::solvex_settlement::settle_intent`.
    pub fn new(package_id: [u8; 32]) -> Result<Self, String> {
        let package = Address::new(package_id);
        let module = Identifier::new("solvex_settlement")
            .map_err(|e| format!("Invalid module identifier: {:?}", e))?;
        let function = Identifier::new("settle_intent")
            .map_err(|e| format!("Invalid function identifier: {:?}", e))?;
        Ok(Self { package, module, function })
    }

    /// Build the full `ProgrammableTransaction` for `settle_intent`.
    ///
    /// # Arguments
    ///
    /// * `config`       — `SharedInput` for the shared `SettlementConfig` object (mut).
    /// * `registry`     — `SharedInput` for the shared `SolverRegistry` object (mut).
    /// * `intent`       — `ObjectReference` for the owned `Intent<In, Out>` (consumed).
    /// * `pool`         — `SharedInput` for the shared `Pool<In, Out>` object (mut).
    /// * `attestation`  — The `Attestation` to encode as BCS pure input.
    /// * `tee_sig`      — 64-byte compact secp256k1 signature (pure input).
    /// * `deep_fee`     — `ObjectReference` for the owned `Coin<DEEP>` (consumed).
    /// * `clock`        — `SharedInput` for the shared `Clock` object (immutable).
    /// * `type_arguments` — Type tags for `In` and `Out`.
    pub fn build_programmable_tx(
        &self,
        config: SharedInput,
        registry: SharedInput,
        intent: ObjectReference,
        pool: SharedInput,
        attestation: &Attestation,
        tee_sig: &[u8],
        deep_fee: ObjectReference,
        clock: SharedInput,
        type_arguments: Vec<TypeTag>,
    ) -> ProgrammableTransaction {
        let attestation_bcs = attestation.to_bcs_bytes();

        let inputs = vec![
            Input::Shared(config),
            Input::Shared(registry),
            Input::ImmutableOrOwned(intent),
            Input::Shared(pool),
            Input::Pure(attestation_bcs),
            Input::Pure(tee_sig.to_vec()),
            Input::ImmutableOrOwned(deep_fee),
            Input::Shared(clock),
        ];

        let arguments = (0u16..8).map(Argument::Input).collect();

        let command = Command::MoveCall(MoveCall {
            package: self.package,
            module: self.module.clone(),
            function: self.function.clone(),
            type_arguments,
            arguments,
        });

        ProgrammableTransaction {
            inputs,
            commands: vec![command],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationSigner;
    use crate::types::QuoteData;
    use sui_sdk_types::{Digest, Mutability};

    fn make_attestation() -> (Attestation, Vec<u8>) {
        let signer = AttestationSigner::new().unwrap();
        let quote = QuoteData {
            solver_id: "solver1".into(),
            output_amount: 950,
            deepbook_pool_id: [1u8; 32],
            gas_estimate: 100_000,
            timestamp: chrono::Utc::now(),
        };
        let attestation = signer
            .create_attestation_with_hash(
                &[1u8; 32],
                &quote,
                0,
                vec![0u8; 32],
                vec![2u8; 16],
            )
            .unwrap();
        let tee_sig = attestation.signature.clone();
        (attestation, tee_sig)
    }

    fn make_shared_input(id: [u8; 32], mutable: bool) -> SharedInput {
        SharedInput::new(
            Address::new(id),
            0,
            if mutable { Mutability::Mutable } else { Mutability::Immutable },
        )
    }

    fn make_obj_ref(id: [u8; 32]) -> ObjectReference {
        ObjectReference::new(Address::new(id), 1, Digest::new([0u8; 32]))
    }

    #[test]
    fn test_builder_creation() {
        let builder = SettlementTxBuilder::new([0x42u8; 32]).unwrap();
        assert_eq!(
            format!("{:?}", builder.package),
            format!("{:?}", Address::new([0x42u8; 32]))
        );
    }

    #[test]
    fn test_build_programmable_tx() {
        let builder = SettlementTxBuilder::new([0x42u8; 32]).unwrap();
        let (attestation, tee_sig) = make_attestation();

        let config = make_shared_input([0x10u8; 32], true);
        let registry = make_shared_input([0x11u8; 32], true);
        let intent = make_obj_ref([0x12u8; 32]);
        let pool = make_shared_input([0x13u8; 32], true);
        let deep_fee = make_obj_ref([0x14u8; 32]);
        let clock = make_shared_input([0x15u8; 32], false);

        let type_args = vec![
            "0x2::sui::SUI".parse::<TypeTag>().unwrap(),
            "0x2::sui::SUI".parse::<TypeTag>().unwrap(),
        ];

        let ptb = builder.build_programmable_tx(
            config, registry, intent, pool,
            &attestation, &tee_sig, deep_fee, clock, type_args,
        );

        assert_eq!(ptb.inputs.len(), 8);
        assert_eq!(ptb.commands.len(), 1);

        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.type_arguments.len(), 2);
                assert_eq!(mc.arguments.len(), 8);
            }
            _ => panic!("Expected MoveCall command"),
        }
    }

    #[test]
    fn test_ptb_bcs_roundtrip() {
        let builder = SettlementTxBuilder::new([0x42u8; 32]).unwrap();
        let (attestation, tee_sig) = make_attestation();

        let config = make_shared_input([0x10u8; 32], true);
        let registry = make_shared_input([0x11u8; 32], true);
        let intent = make_obj_ref([0x12u8; 32]);
        let pool = make_shared_input([0x13u8; 32], true);
        let deep_fee = make_obj_ref([0x14u8; 32]);
        let clock = make_shared_input([0x15u8; 32], false);

        let type_args = vec![
            "0x2::sui::SUI".parse::<TypeTag>().unwrap(),
            "0x2::sui::SUI".parse::<TypeTag>().unwrap(),
        ];

        let ptb = builder.build_programmable_tx(
            config, registry, intent, pool,
            &attestation, &tee_sig, deep_fee, clock, type_args,
        );

        let encoded = bcs::to_bytes(&ptb).expect("BCS encoding failed");
        assert!(!encoded.is_empty());

        let decoded: ProgrammableTransaction =
            bcs::from_bytes(&encoded).expect("BCS decoding failed");
        assert_eq!(decoded.inputs.len(), 8);
        assert_eq!(decoded.commands.len(), 1);
    }
}
