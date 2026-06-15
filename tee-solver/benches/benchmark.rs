/// Criterion benchmarks for TEE Solver Engine cryptographic operations (Sui).
/// Run with:  cargo bench
use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tee_solver::{
    attestation::AttestationSigner,
    types::QuoteData,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_quote(output: u64) -> QuoteData {
    QuoteData {
        output_amount: output,
        deepbook_pool_id: [0u8; 32],
        gas_estimate: 100_000,
        timestamp: Utc::now(),
        solver_id: "solver_bench".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Bench: compact 64-byte ECDSA signature generation (prehash, no recovery id)
fn bench_sign(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let hash = [42u8; 32];

    c.bench_function("sign_hash (compact 64-byte)", |b| {
        b.iter(|| signer.sign_hash(black_box(&hash)).unwrap())
    });
}

/// Bench: compact 64-byte ECDSA signature verification (prehash)
fn bench_verify(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let hash = [42u8; 32];
    let signature = signer.sign_hash(&hash).unwrap();

    c.bench_function("verify_signature (compact 64-byte)", |b| {
        b.iter(|| {
            signer
                .verify_signature(black_box(&hash), black_box(&signature))
                .unwrap()
        })
    });
}

/// Bench: batch verification of 50 signatures
fn bench_batch_verify(c: &mut Criterion) {
    let signers: Vec<_> = (0u8..50)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i + 1;
            AttestationSigner::from_seed(&seed).unwrap()
        })
        .collect();
    let hash = [42u8; 32];
    let sigs: Vec<_> = signers
        .iter()
        .map(|s| s.sign_hash(&hash).unwrap())
        .collect();

    c.bench_function("batch_verify x50", |b| {
        b.iter(|| {
            for (s, sig) in signers.iter().zip(sigs.iter()) {
                black_box(s.verify_signature(&hash, sig).unwrap());
            }
        })
    });
}

/// Bench: full attestation creation (BCS encode + prehash sign)
fn bench_attestation_create(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let quote = make_quote(950);

    c.bench_function("create_attestation (BCS-encoded)", |b| {
        b.iter(|| {
            signer
                .create_attestation_with_hash(
                    black_box(&[1u8; 32]),
                    black_box(&quote),
                    black_box(0u64),
                    black_box(vec![0u8; 32]),
                    black_box(vec![]),
                )
                .unwrap()
        })
    });
}

/// Bench: BCS encoding of attestation
fn bench_bcs_encode(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let att = signer
        .create_attestation_with_hash(&[1u8; 32], &make_quote(950), 0, vec![0u8; 32], vec![])
        .unwrap();

    c.bench_function("attestation.to_bcs_bytes", |b| {
        b.iter(|| black_box(att.to_bcs_bytes()))
    });
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_batch_verify,
    bench_attestation_create,
    bench_bcs_encode,
);
criterion_main!(benches);
