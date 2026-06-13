module enclave_modules::solvex_verifier;

use sui::ecdsa_k1;
use sui::hash;

/// Verifies that `tee_sig` is a valid secp256k1 signature by `tee_pubkey`
/// (33-byte compressed) over `attestation_bytes`. Uses Sui's native
/// `ecdsa_k1::secp256k1_verify` — no external verifier needed.
public fun verify_attestation(
    attestation_bytes: vector<u8>,
    tee_sig: vector<u8>,
    tee_pubkey: vector<u8>,
): bool {
    ecdsa_k1::secp256k1_verify(&tee_sig, &tee_pubkey, &attestation_bytes, 0)
}


/// `keccak256` of the encoded attestation — used by settlement both as the
/// new Merkle-chain head and as the event payload.
public fun attestation_hash(attestation_bytes: &vector<u8>): vector<u8> {
    hash::keccak256(attestation_bytes)
}
