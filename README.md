# 🔒 ENCLAVE

### Private Routing & Intent Settlement Mechanism — SUI Network

**Sealed by GCP Confidential Space · Verified by Native Move Cryptography · Settled on DeepBook v3 · Anchored on Walrus**

[![Built with Move](https://img.shields.io/badge/Built%20with-Move-000000?style=for-the-badge&logo=sui&logoColor=white)](https://move-book.com) [![SUI Network](https://img.shields.io/badge/SUI-Network-6FBCF0?style=for-the-badge&logo=sui&logoColor=white)](https://sui.io) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](#11-project-license) [![Network: Testnet](https://img.shields.io/badge/Network-Testnet-3380C4?style=for-the-badge)](https://docs.sui.io/guides/developer/getting-started/connect)

[![TEE](https://img.shields.io/badge/TEE-GCP%20Confidential%20Space-4285F4?style=flat-square&logo=googlecloud&logoColor=white)](#23-sealed-tee-solver-competition) [![Settlement](https://img.shields.io/badge/Settlement-DeepBook%20v3-00C2A8?style=flat-square)](#25-deepbook-routed-settlement-atomic-ptb) [![Audit Trail](https://img.shields.io/badge/Audit%20Trail-Walrus-00ADB5?style=flat-square)](#26-walrus-anchored-audit-trail) [![Off-chain](https://img.shields.io/badge/Off--chain-Rust-CE422B?style=flat-square&logo=rust&logoColor=white)](#94-running-the-solver-engine)

**ENCLAVE** eliminates solver-level MEV from intent-based DEX routing on SUI by sealing the entire solver competition inside a Trusted Execution Environment (TEE), proving the correct solver won using SUI's **native** Move cryptographic primitives, settling the winning fill directly against **DeepBook v3**'s on-chain order book, and anchoring the complete auction record on **Walrus** for independent verification.

> **"Prove your solver won fairly — without trusting anyone, including us."**

Unlike intent protocols that bolt a verifier contract onto an existing chain, ENCLAVE verifies TEE attestations with a single stdlib call — `sui::ecdsa_k1::secp256k1_ecrecover` — inside the settlement module itself. There is no separate verifier package to compile, deploy, or maintain. Combined with SUI's object model and atomic Programmable Transaction Blocks (PTBs), **verification, settlement, and fund release happen as one indivisible step** — no transaction can be interleaved between "attestation verified" and "funds released."

---

## Deployed Package & Object IDs (SUI Testnet)

> Pending Testnet publish — see [10. Deployment](#10-deployment) for the publish flow, and [Day 1 of the roadmap](./ENCLAVE_SUI_SPEC.md#deployment-roadmap) in the full spec for the schedule. Fill in the table below once `sui client publish` returns real IDs.

`Package ID:` `TBD`

`SolverRegistry (shared object):` `TBD`

`AttestationChain (shared object):` `TBD`

`DeepBook Pool<In, Out> referenced:` `TBD`

---

## Table of Contents

- [1. Overview](#1-overview)
  * [1.1 Introduction](#11-introduction)
  * [1.2 The Solver MEV Problem](#12-the-solver-mev-problem)
  * [1.3 The ENCLAVE Solution](#13-the-enclave-solution)
  * [1.4 Why Native SUI Primitives Solve It](#14-why-native-sui-primitives-solve-it)
  * [1.5 Protocol Comparison](#15-protocol-comparison)
  * [1.6 Conclusion](#16-conclusion)
- [2. Architecture](#2-architecture)
  * [2.1 High-Level Workflow](#21-high-level-workflow)
  * [2.2 Intent Escrow: Object-Native Model](#22-intent-escrow-object-native-model)
  * [2.3 Sealed TEE Solver Competition](#23-sealed-tee-solver-competition)
  * [2.4 Native Attestation Verification](#24-native-attestation-verification)
  * [2.5 DeepBook-Routed Settlement (Atomic PTB)](#25-deepbook-routed-settlement-atomic-ptb)
  * [2.6 Walrus-Anchored Audit Trail](#26-walrus-anchored-audit-trail)
- [3. Features](#3-features)
- [4. Technical Overview](#4-technical-overview)
- **[Spec & deep dive → ENCLAVE_SUI_SPEC.md](./ENCLAVE_SUI_SPEC.md)**
  * [5. Phase 2: Extended Vision](./ENCLAVE_SUI_SPEC.md#phase-2-extended-vision)
  * [6. Component Specifications](./ENCLAVE_SUI_SPEC.md#component-specifications)
  * [7. Security Model & Transaction Cost Analysis](./ENCLAVE_SUI_SPEC.md#security-model)
  * [8. Testing Strategy & Deployment Roadmap](./ENCLAVE_SUI_SPEC.md#testing-strategy)
- [9. Getting Started](#9-getting-started)
  * [9.1 Prerequisites](#91-prerequisites)
  * [9.2 Installation](#92-installation)
  * [9.3 Building the Move Package](#93-building-the-move-package)
  * [9.4 Running the Solver Engine](#94-running-the-solver-engine)
- [10. Deployment](#10-deployment)
- [11. Project License](#11-project-license)
- [12. References](#12-references)

---

## 1. Overview

ENCLAVE is a private intent-settlement protocol for the SUI network. Instead of trusting a relayer, a leaderboard, or an opaque off-chain router to run a solver competition fairly, ENCLAVE seals the entire competition inside hardware — a TEE — and then *proves* that the result is genuine, using SUI's own cryptographic stdlib rather than a bolted-on verifier contract, before a single coin moves.

User funds are escrowed as `Coin<T>` living inside an owned `Intent` object. The winning route settles against DeepBook v3's real on-chain order book. A full, independently-recomputable audit trail of every solver's quote — not only the winner's — is anchored on Walrus.

### 1.1 Introduction

#### What led to this project?

Intent-based trading promises better prices through solver competition, but most implementations leak the one thing they need to hide: the quotes. Once a solver can see a competitor's near-winning bid, three predictable attacks follow — quote sniping, collusive floor-setting, and settlement-time reordering. On account-based chains, closing this gap usually means a separate verifier contract, a nonce table to block replay, and hoping nothing gets wedged between "verified" and "paid."

SUI's object model removes structural categories of this problem rather than merely mitigating them: an object consumed at settlement cannot be replayed, because the runtime forbids referencing a deleted object as a transaction input, and a PTB executes as one atomic unit, so there is no transaction boundary between verification and payout to exploit in the first place.

#### The problem we solve

In intent-based DEX protocols, solver competition is typically observable in some form, enabling three attack vectors:

- **Quote Sniping** — a solver observes a competitor's near-winning quote and undercuts by a negligible amount, claiming the reward while providing no real improvement to the user.
- **Collusive Floor Setting** — colluding solvers agree to never bid above a minimum threshold, suppressing genuine price competition.
- **Settlement-Time Extraction** — a solver who controls the settlement transaction can reorder or front-run the user's fill at the venue level.

### 1.2 The Solver MEV Problem

A subtler gap is specific to object-based chains: even a well-designed sealed auction can still be vulnerable if verification and fund release are split across separate transactions, because a shared object's state is readable by anyone between calls. ENCLAVE closes this by collapsing **verify → route → settle** into a single PTB — there is no gap left for an attacker to wedge into.

### 1.3 The ENCLAVE Solution

Four layers form the complete intent-execution pipeline:

```
┌──────────────────────────────────────────────────────────┐
│ Layer 1: User Intent Submission                          │
│ └─ User signs intent, funds escrowed inside an owned      │
│    Intent<In, Out> object (coin lives in the object)      │
└────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Layer 2: Sealed TEE Solver Competition                     │
│ └─ GCP Confidential Space: collect quotes → argmax          │
│    └─ No solver sees peers' bids                            │
│    └─ Full quote log streamed to Walrus                     │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Layer 3: Native Move Attestation Verification               │
│ └─ sui::ecdsa_k1::secp256k1_ecrecover against registered     │
│    TEE pubkey — no separate verifier package, no nonce       │
│    table (object linearity makes replay structurally          │
│    impossible)                                                │
└─────────────────────┬─────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────┐
│ Layer 4: DeepBook Settlement (single atomic PTB)             │
│ └─ Route fill through DeepBook Pool, release Coin<Out>         │
│    to user, anchor Walrus blob ID, delete Intent object        │
└────────────────────────────────────────────────────────────┘
```

![High-Level Architecture](./images/HighLevelArchitecture.png)

1. **User Intent Submission** — funds are escrowed structurally inside an owned `Intent<In, Out>` object.
2. **Sealed TEE Solver Competition** — GCP Confidential Space runs the auction; no solver sees a peer's quote.
3. **Native Attestation Verification** — `sui::ecdsa_k1::secp256k1_ecrecover` recovers and checks the TEE's signing key inside the settlement module itself.
4. **DeepBook-Settled Fills** — the winning route executes against DeepBook v3's real order book, anchored by a Walrus-committed audit trail.

### 1.4 Why Native SUI Primitives Solve It

1. **TEE Seals Competition** — a hardware-attested enclave prevents all three attack vectors; deterministic argmax selection and isolated memory prevent manipulation and operator observation alike.
2. **Object Linearity Replaces Replay Guards** — a consumed `Intent` can never be settled twice; there's no nonce table, no Bloom filter, no replay-window edge case to get wrong.
3. **Atomicity Is Free** — a PTB either commits every step or none; verification, routing, transfer, reputation update, and Walrus-anchor commitment happen inside one transaction.
4. **Settlement Is Real Liquidity** — the winning fill executes against DeepBook v3's actual `Pool<Base, Quote>`, not an opaque router address you have to trust.
5. **The Audit Trail Is Independently Verifiable** — Walrus stores every solver's quote, not only the winner's, so anyone can recompute `argmax(output_amount)` themselves.

### 1.5 Protocol Comparison

| Protocol Pattern | Transparency | Settlement Atomicity | Solver Trust |
|---|---|---|---|
| Off-chain RFQ aggregators | Quotes visible to relayer | Multi-step, interruptible | Trusted relayer |
| On-chain solver auctions | Bids visible pre-settlement | Multi-step, interruptible | Partially trusted solver pool |
| **ENCLAVE** | **TEE-sealed competition** | **Single atomic PTB** | **Hardware-attested enclave** |

![Protocol Comparison](./images/ProtocolComparison.png)

### 1.6 Conclusion

ENCLAVE's core bet is that MEV resistance and trustlessness aren't in tension if the right primitive sits in the right layer: a TEE for sealing, SUI's native crypto stdlib for verification, DeepBook for real settlement liquidity, and Walrus for an audit trail anyone can recompute. None of these pieces require trusting ENCLAVE's own operators — only the hardware vendor's attestation chain and SUI's runtime guarantees.

---

## 2. Architecture

ENCLAVE follows a four-layer pipeline with a clear separation between escrow (`intent_pool`), sealed competition (the off-chain TEE), verification + settlement (`settlement`), and the DeepBook adapter (`deepbook_router`).

### 2.1 High-Level Workflow

![Intent Lifecycle — Happy Path](./images/IntentLifecycle.png)

**Happy path, step by step:**

1. The user calls `intent_pool::submit_intent()` directly from their wallet — `Coin<In>` moves into a new shared `Intent<In, Out>` object.
2. `enclave-solver-engine` observes the new intent and runs a sealed auction: quotes are collected from registered, staked solvers inside the TEE, with no quote visible to any other participant.
3. The TEE selects the winner via `argmax(output_amount)`, uploads the full quote log to Walrus, and signs an `Attestation` covering the winning fill plus the resulting `walrus_blob_id`.
4. The solver submits `settle_intent()` as a single PTB: verify attestation → consume the `Intent` → route the fill through DeepBook → enforce the slippage floor → pay the user → update reputation → emit `IntentSettled`.

If a user's intent times out, `refund_intent()` returns `coin_in` and deletes the `Intent` object — no separate cancellation flow is needed.

### 2.2 Intent Escrow: Object-Native Model

| Property | Value |
|---|---|
| **Module** | `intent_pool` |
| **Key Object** | `Intent<In, Out> { id, user, coin_in: Coin<In>, min_amount_out, deadline_ms, nonce }` |
| **Key Functions** | `submit_intent()`, `refund_intent()` |

```move
public struct Intent<phantom In, phantom Out> has key, store {
    id: UID,
    user: address,
    coin_in: Coin<In>,       // escrow lives inside the object itself
    min_amount_out: u64,
    deadline_ms: u64,
    nonce: u64,
}
```

Escrow is structural — there is no separate balance ledger to keep in sync with the locked amount, and only the address named as `user` inside the object can trigger a refund.

### 2.3 Sealed TEE Solver Competition

![Sealed Solver Auction Flow](./images/SolverAuctionFlow.png)

- **Platform**: GCP Confidential Space (hardware-attested enclave)
- Solvers register stake + a secp256k1 TEE public key on-chain before competing
- Quotes are collected inside sealed enclave memory — no solver, including the TEE operator, can observe a peer's bid
- The winner is selected deterministically via `argmax(output_amount)`
- The complete quote log (every bid, not only the winner's) streams to Walrus before the attestation is signed

```rust
pub fn run_auction(intent: Intent, quotes: Vec<Quote>) -> Result<Quote> {
    // quotes is sealed - no individual quote observable
    let winner = quotes.iter().max_by_key(|q| q.output_amount).ok_or(AuctionError::NoQuotes)?;
    Ok(winner.clone())
}
```

### 2.4 Native Attestation Verification

Verification is a private function inside `settlement` — not a separately deployed package:

```move
fun verify_attestation(
    registry: &SolverRegistry,
    chain: &AttestationChain,
    attestation: &Attestation,
    tee_sig: vector<u8>,
): bool {
    let msg = bcs::to_bytes(attestation);
    let recovered = ecdsa_k1::secp256k1_ecrecover(&tee_sig, &msg, HASH_KECCAK256);
    let registered = solver_registry::tee_pubkey(registry, attestation.winner_solver);
    assert!(recovered == registered, EInvalidAttestation);
    assert!(attestation.prev_attest_hash == chain.last_hash, EChainBroken);
    true
}
```

Replay protection is structural, not a nonce table — see the [Security Model](./ENCLAVE_SUI_SPEC.md#security-model) in the full spec for the complete threat-model breakdown.

### 2.5 DeepBook-Routed Settlement (Atomic PTB)

![Atomic Settlement PTB](./images/AtomicSettlementPTB.png)

`settle_intent()` is the single entry point a relayer calls. Inside one PTB: verify attestation → consume the `Intent` → route the fill through DeepBook's `Pool<In, Out>` → enforce `min_amount_out` → pay the user → update reputation → commit the Walrus anchor. If any step aborts, the whole PTB reverts — escrowed funds are never partially released.

### 2.6 Walrus-Anchored Audit Trail

The TEE doesn't just *attest* that it ran fairly — it proves it. Every quote collected during the sealed auction, not only the winner's, is uploaded to Walrus and certified before the attestation is signed. Anyone can fetch the blob and independently recompute `argmax(output_amount)` rather than take the enclave's word for it.

---

## 3. Features

- **TEE-Sealed Solver Competition** — no solver, including the operator, observes a peer's quote before selection.
- **Stdlib Attestation Verification** — `sui::ecdsa_k1::secp256k1_ecrecover` runs inside `settlement` itself; no separate verifier package to deploy or maintain.
- **Object-Native Escrow** — user funds live inside an owned `Intent` object; there's no balance ledger to desync from the locked amount.
- **Single Atomic PTB Settlement** — verification, DeepBook routing, fund release, reputation update, and Walrus-anchor commitment happen as one indivisible transaction.
- **Structural Replay Protection** — a consumed `Intent` cannot be referenced again; SUI's runtime forbids it by construction, no nonce table required.
- **Real DeepBook v3 Liquidity** — winning fills route through an actual on-chain CLOB `Pool<Base, Quote>`, not an opaque router address.
- **Independently Recomputable Audit Trail** — Walrus stores every quote from the sealed auction, letting anyone verify the TEE didn't cherry-pick the winner.
- **Storage-Rebate-Aware Settlement** — deleting the `Intent` object on settlement recovers roughly 99% of its original storage deposit, partially self-funding the escrow.
- **Fixed-Point Solver Reputation** *(Phase 2)* — an EMA-based reputation score gates fee tiers and suspends underperforming solvers.
- **Multi-Venue Routing** *(Phase 2)* — the TEE's quote-collection step can query liquidity across multiple SUI-native venues, still settling in one atomic PTB.

---

## 4. Technical Overview

| Layer | Technology |
|---|---|
| Smart Contracts | SUI Move, published via `sui client publish` |
| Settlement Venue | DeepBook v3 (`deepbook::pool`, `deepbook::balance_manager`) |
| Audit Trail | Walrus (`walrus::system`, `walrus::blob`) |
| TEE Runtime | GCP Confidential Space (hardware-attested) |
| Off-Chain Services | Rust workspace — `tokio`, `axum`, `sui-sdk`, `fastcrypto`, `bcs` |
| Indexing | SUI event subscription via `sui-sdk` or a custom indexer |
| Network | SUI Testnet (MVP) |

## Deep dive: full spec, internals & roadmap

The in-depth material — Phase 2's reputation system and multi-venue routing, the contract-by-contract component specifications, the full threat model and transaction cost analysis, the testing strategy, and the day-by-day deployment roadmap — lives in **[ENCLAVE_SUI_SPEC.md](./ENCLAVE_SUI_SPEC.md)**:

- [5. Phase 2: Extended Vision](./ENCLAVE_SUI_SPEC.md#phase-2-extended-vision)
- [6. Component Specifications](./ENCLAVE_SUI_SPEC.md#component-specifications)
- [7. Security Model & Transaction Cost Analysis](./ENCLAVE_SUI_SPEC.md#security-model)
- [8. Testing Strategy & Deployment Roadmap](./ENCLAVE_SUI_SPEC.md#testing-strategy)
- [Glossary](./ENCLAVE_SUI_SPEC.md#glossary)

---

## 9. Getting Started

Follow these instructions to set up the project locally for development and testing.

### 9.1 Prerequisites

- **SUI CLI** (latest stable) with a configured Testnet environment
- **Rust** (1.75+) for the off-chain solver engine and indexer
- **GCP account** with Confidential Space access, for TEE deployment
- **Move** toolchain (bundled with the SUI CLI)

### 9.2 Installation

Clone the repository and install dependencies:

```bash
git clone <repository_url>
cd enclave-sui
```

### 9.3 Building the Move Package

```bash
# Build the Move package
sui move build

# Run Move unit tests
sui move test
# Tests: ecdsa_k1 recovery against known signature fixtures, hash-chain
# continuity, reputation EMA fixed-point math, slippage enforcement
```

### 9.4 Running the Solver Engine

```bash
# Build the Rust workspace
cargo build --workspace --release

# Start a local SUI test validator
sui start --with-faucet

# Run the solver engine against it
cargo run --bin enclave-solver-engine
```

---

## 10. Deployment

```bash
# Publish the Move package to SUI Testnet
sui client publish --gas-budget 200000000

# Deploy the solver engine to GCP Confidential Space
gcloud compute instances create-with-container enclave-solver-1 \
  --container-image us-central1-docker.pkg.dev/.../solver-engine:latest \
  --confidential-compute \
  --maintenance-policy TERMINATE

# Call settle_intent manually (debugging)
sui client call \
  --package $ENCLAVE_PKG \
  --module settlement \
  --function settle_intent \
  --args $INTENT_ID $REGISTRY_ID $CHAIN_ID $POOL_ID ... \
  --gas-budget 50000000
```

### Deployed Addresses (SUI Testnet)

| Object | ID |
|---|---|
| Package | `TBD` |
| `SolverRegistry` | `TBD` |
| `AttestationChain` | `TBD` |
| DeepBook `Pool<In, Out>` | `TBD` |

---

## 11. Project License

This project is licensed under the **MIT License**.

---

## 12. References

- **SUI Move Book** — [move-book.com](https://move-book.com)
- **`sui::ecdsa_k1` module reference** — SUI Framework documentation
- **DeepBook v3 Documentation** — [docs.sui.io/standards/deepbook](https://docs.sui.io/standards/deepbook)
- **Walrus Documentation** — [docs.walrus.site](https://docs.walrus.site)
- **GCP Confidential Space** — [cloud.google.com/confidential-computing/confidential-space](https://cloud.google.com/confidential-computing/confidential-space/docs)
