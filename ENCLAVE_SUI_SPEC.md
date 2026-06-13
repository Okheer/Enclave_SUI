# ENCLAVE Protocol Specification — SUI Network

## Private Routing & Intent Settlement Mechanism
### A TEE-Sealed Solver Competition with Native Move Attestation, DeepBook Settlement, and Walrus-Anchored Audit Trails

**Date:** 2026-06-21
**Status:** MVP Specification (Phase 1 Core + Phase 2 Extended Vision)
**Platform:** SUI Network (L1) + GCP Confidential Space (TEE) + DeepBook v3 + Walrus

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [Phase 1: Core MVP](#phase-1-core-mvp)
5. [Phase 2: Extended Vision](#phase-2-extended-vision)
6. [Component Specifications](#component-specifications)
7. [Data Flow & Protocol](#data-flow--protocol)
8. [Security Model](#security-model)
9. [Transaction Cost Analysis](#transaction-cost-analysis)
10. [Development Architecture](#development-architecture)
11. [Key Dependencies](#key-dependencies)
12. [Testing Strategy](#testing-strategy)
13. [Deployment Roadmap](#deployment-roadmap)
14. [Glossary](#glossary)

---

## Executive Summary

ENCLAVE eliminates solver-level MEV from intent-based DEX routing by sealing the entire solver competition inside a Trusted Execution Environment (TEE), then proving the correct solver won using native Move cryptographic primitives on SUI — settling the winning fill directly against DeepBook's on-chain order book and anchoring the full auction record on Walrus for independent verification.

### The 14-Word Pitch
> **"Prove your solver won fairly — without trusting anyone, including us."**

### Key Differentiator
ENCLAVE verifies TEE attestations using SUI's native `ecdsa_k1` module rather than a deployed verifier contract. There is no separate verification contract to compile, deploy, or maintain — signature recovery is a stdlib call inside the settlement module itself. Combined with SUI's object model, this means **verification, settlement, and fund release happen inside a single atomic Programmable Transaction Block (PTB)** — no other transaction can be interleaved between "attestation verified" and "funds released," a property that requires careful multi-call sequencing to achieve on account-based chains.

### Core Innovation Stack
- **TEE Solver Pool**: GCP Confidential Space runs a sealed auction where no solver sees competitors' quotes
- **Native Attestation Verification**: `sui::ecdsa_k1::secp256k1_ecrecover` validates TEE signatures directly inside the settlement module — no separate verifier package
- **Object-Native Escrow**: User funds are escrowed as `Coin<T>` held inside an owned `Intent` object — escrow is structural, not a balance entry
- **DeepBook-Settled Fills**: Winning solver routes execute against DeepBook v3's on-chain central limit order book, not an opaque external router
- **Walrus-Anchored Audit Trail**: The full sealed-auction log (every quote, not just the winner) is committed to Walrus, letting anyone independently recompute the argmax and confirm the TEE didn't cherry-pick

---

## Problem Statement

### The Solver MEV Problem

In intent-based DEX protocols, solver competition is typically observable in some form — enabling three attack vectors:

1. **Quote Sniping**: A solver observes a competitor's near-winning quote and undercuts by a negligible amount, claiming the reward while providing no real improvement to the user.
2. **Collusive Floor Setting**: Colluding solvers agree to never bid above a minimum threshold, suppressing genuine price competition.
3. **Settlement-Time Extraction**: A solver who controls the settlement transaction can reorder or front-run the user's fill at the venue level.

### Current Protocol Gaps on SUI

| Protocol Pattern | Transparency | Settlement Atomicity | Solver Trust |
|---|---|---|---|
| Off-chain RFQ aggregators | Quotes visible to relayer | Multi-step, interruptible | Trusted relayer |
| On-chain solver auctions | Bids visible pre-settlement | Multi-step, interruptible | Partially trusted solver pool |
| **ENCLAVE** | **TEE-sealed competition** | **Single atomic PTB** | **Hardware-attested enclave** |

A subtler gap is specific to object-based chains: even a well-designed solver auction can still be vulnerable if verification and fund release are split across separate transactions, because a shared object's state can be read by an attacker between calls. ENCLAVE closes this by collapsing verify → route → settle into one PTB.

---

## Solution Overview

### Architecture Stack (4 Layers)

```
┌──────────────────────────────────────────────────────────┐
│ Layer 1: User Intent Submission                          │
│ └─ User signs intent, funds escrowed inside an owned      │
│    Intent<In, Out> object (coin lives in the object)      │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│ Layer 2: Sealed TEE Solver Competition                   │
│ └─ GCP Confidential Space: collect quotes → argmax         │
│    └─ No solver sees peers' bids                          │
│    └─ Full quote log streamed to Walrus                   │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│ Layer 3: Native Move Attestation Verification              │
│ └─ sui::ecdsa_k1::secp256k1_ecrecover against registered    │
│    TEE pubkey — no separate verifier package, no nonce      │
│    table (object linearity makes replay structurally        │
│    impossible)                                              │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│ Layer 4: DeepBook Settlement (single atomic PTB)            │
│ └─ Route fill through DeepBook Pool, release Coin<Out>       │
│    to user, anchor Walrus blob ID, delete Intent object      │
└──────────────────────────────────────────────────────────┘
```

### Why Native SUI Primitives Solve the Problem

1. **TEE Seals Competition**: Identical security property to any TEE-based design — hardware-attested enclave prevents all three attack vectors. No solver sees peer quotes; deterministic argmax selection prevents manipulation; isolated memory prevents operator observation.

2. **Object Linearity Replaces Replay Guards**: Because an `Intent` is a SUI object consumed (deleted) at settlement, the same intent can never be settled twice — there is no code path that lets a deleted object's ID be reused as a transaction input. This removes an entire class of bugs (nonce management, Bloom filter sizing, replay-window edge cases) that exist on account-based chains by construction.

3. **Atomicity Is Free**: A SUI Programmable Transaction Block executes as a single unit — either every step commits or none does. Verification, DeepBook routing, fund transfer, reputation update, and Walrus-anchor commitment all happen inside one PTB, so there is no transaction boundary for an attacker to wedge into.

4. **Settlement Is Real Liquidity, Not an Opaque Router**: The winning solver's fill executes against DeepBook v3's actual on-chain order book (`Pool<Base, Quote>`), so "fill_route" isn't an address you have to trust — it's a verifiable trade against a shared, auditable CLOB.

5. **The Audit Trail Is Independently Verifiable**: Walrus stores the complete sealed-auction record — every solver's quote, not only the winner's — content-addressed and erasure-coded. Anyone can fetch the blob and recompute `argmax(output_amount)` themselves rather than trusting the TEE's word that it ran fairly.

---

## Phase 1: Core MVP

### What is Being Built

Four tightly integrated primitives form the complete intent-execution pipeline:

#### 1. Sealed TEE Solver Pool
- **Platform**: GCP Confidential Space (hardware-attested enclave)
- **Functionality**:
  - Solvers register stake + secp256k1 TEE public key on-chain
  - Sealed auction logic: collect quotes from registered solvers
  - Deterministic winner selection via `argmax(output_amount)`
  - Sign attestation covering the winning fill
  - Stream the complete quote log (all bids) to Walrus and embed the resulting blob ID inside the signed attestation
- **Security Property**: No solver — including the TEE operator — can observe peer quotes during the auction

#### 2. Native Attestation Verification (Move stdlib)
- **Location**: A private function inside the `settlement` module — not a separately deployed package
- **Purpose**: Verify the TEE's secp256k1 signature over the attestation
- **Operations** (in sequence):
  1. **Recover signer**: `ecdsa_k1::secp256k1_ecrecover(&tee_sig, &bcs::to_bytes(&attestation), 0)` (hash mode `0` = Keccak-256)
  2. **Match registered key**: compare the recovered 65-byte uncompressed public key against the TEE pubkey stored for `winner_solver` in `SolverRegistry`
  3. **Hash-chain continuity**: confirm `attestation.prev_attest_hash` matches the last committed hash in the shared `AttestationChain` object
- **Replay protection**: structural — handled by object consumption, not a nonce table (see Security Model)

#### 3. Intent Escrow (Move object model)
- **Module**: `intent_pool`
- **Functionality**:
  - `submit_intent<In, Out>()`: wraps the user's `Coin<In>` inside a new `Intent<In, Out>` object and shares it
  - Funds are escrowed *structurally* — there is no separate balance ledger to keep in sync with the locked amount
  - `refund_intent()`: after `deadline_ms` passes, the original `Intent` owner can reclaim `coin_in` and the object is deleted
- **Security Property**: Only the address named as `user` inside the `Intent` object can trigger a refund

#### 4. DeepBook-Routed Settlement
- **Module**: `settlement`
- **Functionality**:
  - `settle_intent<In, Out>()` is the single entry point a relayer calls
  - Inside one PTB: verify attestation → execute fill against the DeepBook `Pool<In, Out>` → enforce `min_amount_out` slippage floor → transfer `Coin<Out>` to user → update solver reputation → commit Walrus blob ID → delete the `Intent` object
  - If any step aborts, the entire PTB reverts — escrowed funds are never partially released

### Intent Schema (Move struct)

```move
public struct Intent<phantom In, phantom Out> has key, store {
    id: UID,
    user: address,
    coin_in: Coin<In>,       // escrow lives inside the object itself
    min_amount_out: u64,
    deadline_ms: u64,
    nonce: u64,               // monotonic per-user counter, used for UX/indexing only
}
```

There is no EIP-712-style typed-data signature step on the intent itself in the MVP: intent creation is a direct transaction signed by the user's SUI wallet, and the resulting `Intent` object's existence on-chain *is* the proof of submission. (An optional off-chain-signed-intent flow, for gasless submission via a relayer, is scoped for Phase 2.)

### Attestation Schema (TEE-Signed)

```move
public struct Attestation has copy, drop, store {
    intent_id: ID,             // SUI object ID of the settled Intent
    winner_solver: address,
    output_amount: u64,
    deepbook_pool_id: ID,       // which DeepBook Pool the fill executed against
    prev_attest_hash: vector<u8>, // hash-chain continuity
    walrus_blob_id: vector<u8>,   // commitment to the full sealed-auction log
}

// tee_sig = secp256k1_sign(tee_private_key, keccak256(bcs::to_bytes(attestation)))
```

### Attestation Verification (Move, Phase 1)

```move
const HASH_KECCAK256: u8 = 0;

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

No separate Bloom filter or nonce store is required here — see [Security Model](#security-model) for why SUI's object model makes this unnecessary rather than merely cheaper.

### Phase 1 Deliverables

- [ ] `solver_registry` module: staking, TEE pubkey registration, slashing
- [ ] `intent_pool` module: `Intent<In, Out>` object creation, refund path
- [ ] `settlement` module: native attestation verification + DeepBook routing + fund release in one PTB
- [ ] `enclave-solver-engine` (Rust, unchanged TEE logic) wired to a SUI RPC client instead of an EVM RPC client
- [ ] Walrus upload integration in the solver engine: full quote log pushed and certified before the attestation is signed
- [ ] End-to-end integration tests on a local SUI test validator + SUI Testnet
- [ ] Demo UI showing the MEV attack comparison and a Walrus-backed "recompute the auction yourself" verifier

---

## Phase 2: Extended Vision

### What is Being Built

A solver reputation system and multi-venue liquidity routing across SUI-native DEXs.

#### 1. Solver Reputation System

**Reputation Score**: Stored as a fixed-point integer (scaled by 10⁹, since Move has no native floating-point arithmetic) in a `Table<address, u64>` inside `SolverRegistry`. Based on:
- Fill accuracy: `actual_output / quoted_output`
- Slash-free history

**Update Mechanism** (Exponential Moving Average, fixed-point):

$$R_{\text{new}}(s) = \alpha \cdot \text{accuracy} + (1 - \alpha) \cdot R_{\text{prev}}(s)$$

```move
const SCALE: u64 = 1_000_000_000;
const ALPHA_NUM: u64 = 5;      // α = 0.05, expressed as 5 / 100
const ALPHA_DEN: u64 = 100;

fun update_reputation(registry: &mut SolverRegistry, solver: address, actual: u64, quoted: u64) {
    let accuracy = (actual as u128) * (SCALE as u128) / (quoted as u128); // fixed-point
    let prev_r = *table::borrow(&registry.reputation, solver);
    let new_r = ((ALPHA_NUM as u128) * accuracy
                + ((ALPHA_DEN - ALPHA_NUM) as u128) * (prev_r as u128))
                / (ALPHA_DEN as u128);
    *table::borrow_mut(&mut registry.reputation, solver) = (new_r as u64);
}
```

Where $\alpha = 0.05$ means reputation responds to recent performance over roughly 20 fills, preventing single-event manipulation.

**Fee-Tier Gating**:
- $R(s) > 0.85 \times 10^9$: lower fee cap
- $0.3 \times 10^9 \leq R(s) \leq 0.85 \times 10^9$: standard fee cap
- $R(s) < 0.3 \times 10^9$: temporary suspension from auctions, enforced as an `assert!` guard in `settle_intent`

#### 2. Multi-Venue Liquidity Routing

Rather than bridging to other chains, Phase 2 extends the TEE's quote-collection step to query liquidity across multiple SUI-native venues simultaneously — DeepBook, and optionally other on-chain CLOBs or AMMs — and lets the solver competition select the best fill *across venues*, still settled inside a single atomic PTB on SUI. Because everything stays on one chain, this avoids bridge risk and atomic cross-chain message-passing entirely; the only thing that changes is which `Pool` (or AMM object) the winning fill routes through.

**Data Flow**:
1. User submits intent without specifying a venue
2. TEE queries on-chain liquidity across registered venues
3. TEE selects the best fill (highest output) and records `deepbook_pool_id` (or the equivalent venue object ID)
4. `settle_intent` routes to whichever venue the attestation names

#### 3. On-Chain Walrus Certification Check

Phase 1 stores `walrus_blob_id` as an opaque commitment. Phase 2 adds an on-chain read of the Walrus `Blob` shared object to confirm `certified_epoch` is set (i.e., the blob is actually retrievable) before `settle_intent` will finalize — turning the audit-trail commitment from "TEE claims it uploaded this" into "the chain confirms the data is live on Walrus."

### Phase 2 Deliverables

- [ ] Fixed-point reputation table and EMA update logic in `solver_registry`
- [ ] Fee-tier gating enforced in `settlement`
- [ ] Multi-venue routing support in the solver engine and `settlement` module
- [ ] On-chain Walrus `Blob` certification check before settlement finalizes
- [ ] Solver performance dashboard backed by a SUI indexing service

---

## Component Specifications

### Move Modules

#### `solver_registry`

| Property | Value |
|---|---|
| **Purpose** | Solver onboarding, staking, TEE key management, slashing, reputation |
| **File** | `sources/solver_registry.move` |
| **Key Object** | Shared `SolverRegistry { id: UID, solvers: Table<address, SolverInfo>, reputation: Table<address, u64> }` |
| **Key Functions** | `register_solver()`, `slash_solver()`, `tee_pubkey()`, `update_reputation()` |

```move
public fun register_solver(
    registry: &mut SolverRegistry,
    stake: Coin<SUI>,
    tee_pubkey: vector<u8>,   // 65-byte uncompressed secp256k1 pubkey
    ctx: &mut TxContext,
);

public(package) fun slash_solver(registry: &mut SolverRegistry, solver: address, amount: u64);

public fun tee_pubkey(registry: &SolverRegistry, solver: address): vector<u8>;
```

#### `intent_pool`

| Property | Value |
|---|---|
| **Purpose** | Receive and escrow user intents as shared objects |
| **File** | `sources/intent_pool.move` |
| **Key Object** | `Intent<In, Out> { id, user, coin_in: Coin<In>, min_amount_out, deadline_ms, nonce }` |
| **Key Functions** | `submit_intent()`, `refund_intent()` |

```move
public fun submit_intent<In, Out>(
    coin_in: Coin<In>,
    min_amount_out: u64,
    deadline_ms: u64,
    ctx: &mut TxContext,
): ID;  // returns the new Intent's object ID for the solver pool to pick up

public fun refund_intent<In, Out>(
    intent: Intent<In, Out>,
    clock: &Clock,
    ctx: &mut TxContext,
);
```

#### `settlement`

| Property | Value |
|---|---|
| **Purpose** | Verify attestation, route fill via DeepBook, release funds, anchor Walrus commitment — all in one PTB |
| **File** | `sources/settlement.move` |
| **Key Object** | Shared `AttestationChain { id: UID, last_hash: vector<u8> }` |
| **Key Functions** | `settle_intent()` |

```move
public fun settle_intent<In, Out>(
    intent: Intent<In, Out>,
    registry: &mut SolverRegistry,
    chain: &mut AttestationChain,
    pool: &mut Pool<In, Out>,          // DeepBook shared Pool object
    attestation: Attestation,
    tee_sig: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
);
```

**Settlement logic**:
```move
public fun settle_intent<In, Out>(
    intent: Intent<In, Out>,
    registry: &mut SolverRegistry,
    chain: &mut AttestationChain,
    pool: &mut Pool<In, Out>,
    attestation: Attestation,
    tee_sig: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(verify_attestation(registry, chain, &attestation, tee_sig), EInvalidAttestation);
    assert!(clock::timestamp_ms(clock) <= intent.deadline_ms, EIntentExpired);

    let Intent { id, user, coin_in, min_amount_out, nonce: _ } = intent;
    object::delete(id); // consumed — cannot be replayed

    let coin_out = deepbook_router::execute_fill(pool, coin_in, ctx);
    assert!(coin::value(&coin_out) >= min_amount_out, ESlippageViolation);

    chain.last_hash = hash::keccak256(&bcs::to_bytes(&attestation));
    solver_registry::update_reputation(registry, attestation.winner_solver, coin::value(&coin_out), min_amount_out);

    event::emit(IntentSettled {
        intent_id: attestation.intent_id,
        solver: attestation.winner_solver,
        output_amount: coin::value(&coin_out),
        walrus_blob_id: attestation.walrus_blob_id,
    });

    transfer::public_transfer(coin_out, user);
}
```

#### `deepbook_router` (internal adapter)

| Property | Value |
|---|---|
| **Purpose** | Thin wrapper around DeepBook v3's `Pool<Base, Quote>` swap entrypoints |
| **File** | `sources/deepbook_router.move` |
| **Note** | DeepBook v3's exact swap/order interface (limit vs. market, `BalanceManager` requirements, `pay_with_deep` fee flag) should be confirmed against the currently deployed package ID at build time, since DeepBook is actively versioned |

### Off-Chain Services (Rust — largely unchanged from the original TEE design)

#### `enclave-solver-engine`

| Property | Value |
|---|---|
| **Purpose** | Sealed TEE solver competition logic |
| **Platform** | GCP Confidential Space |
| **Language** | Rust |
| **Change from prior design** | Submits settlement via the SUI Rust SDK instead of an EVM RPC client; pushes the full quote log to Walrus before signing the attestation |

**Entry Point** (`main.rs`):
1. Generate ephemeral secp256k1 signing key
2. Request GCP Confidential Space attestation token
3. Register TEE public key via `solver_registry::register_solver`
4. Start HTTP API server to receive quote submissions
5. Run sealed auction loop; on completion, upload the full quote log to Walrus, then sign the `Attestation` (including the resulting `walrus_blob_id`)

**Competition Logic** (unchanged in spirit):
```rust
pub fn run_auction(intent: Intent, quotes: Vec<Quote>) -> Result<Quote> {
    // quotes is sealed - no individual quote observable
    let winner = quotes.iter().max_by_key(|q| q.output_amount).ok_or(AuctionError::NoQuotes)?;
    Ok(winner.clone())
}
```

#### `enclave-bootstrap`

| Property | Value |
|---|---|
| **Purpose** | TEE key generation and registration against `solver_registry` |
| **Key Function** | Submit TEE public key + stake via a SUI transaction |

#### `enclave-shared`

| Property | Value |
|---|---|
| **Purpose** | Shared types and BCS (de)serialization utilities |
| **Key Modules** | `types::intent`, `types::attestation`, `bcs_codec`, `config` |
| **Change from prior design** | Uses the `bcs` crate for serialization instead of ABI encoding |

#### `enclave-walrus-client`

| Property | Value |
|---|---|
| **Purpose** | Upload the sealed-auction quote log to Walrus and poll for certification |
| **Key Function** | Returns a `blob_id` once the blob is certified, for embedding in the `Attestation` |

---

## Data Flow & Protocol

### Complete User Journey (Happy Path)

**Step 1: User Intent Submission**
```
User calls intent_pool::submit_intent() directly from their wallet
├─ Coin<In> moves into the new Intent<In, Out> object
├─ Intent is shared so the solver pool can read it
└─ Emit IntentSubmitted event → solver engine picks it up
```

**Step 2: Sealed TEE Solver Competition**
```
enclave-solver-engine observes the new Intent → Run auction
├─ Accept quotes from registered solvers (timeout: T seconds)
│  ├─ Validator: solver has valid registration + stake
│  ├─ Validator: min_amount_out ≤ quoted output
│  └─ Sealed memory: no quote observable to other solvers
├─ Select winner: argmax(output_amount)
├─ Upload full quote log to Walrus → get walrus_blob_id
├─ Sign Attestation (now including walrus_blob_id) with TEE key
└─ Submit settle_intent() PTB to SUI
```

**Step 3 + 4: Atomic Verification & Settlement (single PTB)**
```
settle_intent() executes as one atomic transaction
├─ Native ecdsa_k1::secp256k1_ecrecover verifies tee_sig
├─ Hash-chain continuity check against AttestationChain
├─ Intent object deleted (consumed — cannot be replayed)
├─ Fill routed through DeepBook Pool<In, Out>
├─ min_amount_out slippage check
├─ Coin<Out> transferred to user
├─ Solver reputation updated
├─ AttestationChain.last_hash updated
└─ IntentSettled event emitted
```

Because Steps 3 and 4 are one PTB, there is no transaction boundary between "attestation confirmed valid" and "funds released" — nothing can be interleaved between them.

### Timeout & Refund Path

```
User calls intent_pool::refund_intent() after deadline_ms passes
├─ Clock object confirms deadline has passed
├─ coin_in returned to user
├─ Intent object deleted
└─ Emit IntentRefunded event
```

### Multi-Venue Settlement (Phase 2)

```
User intent specifies no particular venue → Multi-venue execution
├─ TEE queries liquidity across DeepBook + other registered SUI venues
├─ Selects best fill (any venue)
├─ Attestation records which Pool/venue object ID was used
├─ settle_intent routes to the named venue
└─ Still one atomic PTB — no cross-chain bridging, no atomicity risk
```

---

## Security Model

### Threat Model & Mitigations

| Threat | Attack Vector | ENCLAVE Mitigation |
|---|---|---|
| **Quote Sniping** | Solver sees competitor bid, undercuts marginally | TEE seals quotes; no solver sees bids until after selection |
| **Collusive Floor Setting** | Multiple solvers agree to a bid floor | TEE seals bids; deterministic argmax prevents negotiation |
| **Settlement Reordering** | Attacker tries to insert a transaction between verification and fund release | Verification, routing, and release occur in a single atomic PTB — no transaction boundary exists to exploit |
| **Replay of a Settled Intent** | Resubmitting the same intent for double settlement | Structurally impossible: the `Intent` object is deleted on settlement, and SUI's object model forbids referencing a deleted object as a transaction input |
| **Solver Equivocation** | Solver signs conflicting attestations for the same intent | Hash-chain (`prev_attest_hash`) continuity check in `AttestationChain` |
| **TEE Compromise** | Attacker gains TEE memory access | GCP Confidential Space hardware attestation; no operator access to memory |
| **Fabricated Audit Trail** | TEE claims a fair auction without proof | Full quote log (not just the winner) committed to Walrus; Phase 2 verifies on-chain that the blob is actually certified before settlement |

### Security Assumptions

| Component | Assumption | Basis |
|---|---|---|
| **TEE** | GCP Confidential Space prevents unauthorized memory access | Hardware attestation (Intel TDX / AMD SEV) |
| **Solver signature** | Recovered pubkey from `secp256k1_ecrecover` cannot be forged | SUI native `ecdsa_k1` cryptographic guarantees |
| **Attestation chain** | Hash continuity cannot be falsified | `keccak256` hash chaining verified inside `settlement` |
| **Replay protection** | Settled intents cannot be reused | SUI object linearity — a structural guarantee of the runtime, not a probabilistic guard like a Bloom filter |
| **Walrus availability** | Blob remains retrievable for the audit window | Walrus's erasure-coded storage with on-chain certification (Phase 2 enforces this on-chain) |

### Slashing & Accountability

**Automatic Slashing**:
- Solver submits two conflicting attestations for the same intent → slash a fixed percentage of stake
- Solver's delivered output falls materially below quoted output → reputation penalty (Phase 2)

**Manual Slashing**:
- Protocol governance (a designated multisig `address` or `Cap`-gated function) can slash a solver for protocol violations

**Key Expiration**:
- TEE keys must be re-attested and re-registered periodically (e.g., every 30 days)
- Expired keys fail the `tee_pubkey` lookup and cannot sign new attestations

---

## Transaction Cost Analysis

SUI's fee model differs structurally from gas-per-opcode chains: every transaction pays a **computation cost** (bucketed by complexity, priced in MIST per computation unit) plus a **storage cost** (charged per byte of on-chain object data, priced per storage unit), minus a **storage rebate** for any storage freed by deleting objects. Net cost is:

```
net_gas_fee = computation_cost + storage_cost − storage_rebate
```

### Why This Matters for ENCLAVE's Design

Because `settle_intent` **deletes** the `Intent` object as part of settlement, the transaction recovers most of the storage deposit that was paid when the `Intent` was created — a rebate currently set at roughly 99% of the original storage fee. This is a cost property with no equivalent in account-based gas models: locking funds in an object you intend to consume is partially self-funding from a storage-fee perspective.

### Estimated Cost Breakdown (illustrative, epoch-dependent)

```
Component                                  | Computation | Storage
────────────────────────────────────────────────────────────────────
submit_intent (creates Intent object)      | bucketed CU | + storage fee (deposit)
settle_intent:
  ├─ ecdsa_k1::secp256k1_ecrecover          | bucketed CU | —
  ├─ hash::keccak256 (chain continuity)      | bucketed CU | —
  ├─ DeepBook fill execution                 | bucketed CU | mutates Pool object
  ├─ Intent object deletion                  | —           | − storage rebate (~99%)
  └─ event emission                          | bucketed CU | minor
────────────────────────────────────────────────────────────────────
Net cost per settled intent: well under 0.01 SUI at typical reference
gas prices, with the Intent-deletion rebate substantially offsetting
the escrow object's own storage cost.
```

Exact figures depend on the network's reference gas price at the time of execution (set by validator consensus each epoch) and the precise byte size of the objects involved; this should be benchmarked against SUI Testnet during development rather than hardcoded, since SUI's computation-unit bucketing and reference price both shift over time. As a rough anchor, recent network-wide average transaction fees on SUI have sat in the neighborhood of 0.0028 SUI — ENCLAVE's settlement transaction is expected to land in a comparable or lower range given its native crypto calls replace what would otherwise require a separate contract call.

### Why No Separate Verifier Deployment Cost Exists

Because attestation verification is a Move stdlib call rather than a deployed contract, there's no separate deployment, no separate per-call dispatch overhead to a verifier address, and no WASM compilation step to budget for. The cost surface is simpler to reason about than a multi-contract pipeline because there are fewer cross-contract calls to account for in the first place.

---

## Development Architecture

### File Structure

```
enclave-sui/
│
├── README.md
├── SPEC.md (this file)
├── Move.toml                        # Move package manifest
│
├── sources/                         # ── MOVE PACKAGE ──
│   ├── solver_registry.move
│   ├── intent_pool.move
│   ├── settlement.move
│   ├── deepbook_router.move
│   ├── attestation.move             # shared Attestation struct + hash-chain logic
│   └── errors.move
│
├── tests/                           # ── MOVE UNIT/INTEGRATION TESTS ──
│   ├── solver_registry_tests.move
│   ├── intent_pool_tests.move
│   ├── settlement_tests.move
│   └── integration_tests.move
│
├── crates/                          # ── RUST OFF-CHAIN SERVICES ──
│   ├── enclave-shared/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types/
│   │       │   ├── intent.rs
│   │       │   └── attestation.rs
│   │       ├── bcs_codec.rs
│   │       └── config.rs
│   │
│   ├── enclave-solver-engine/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── config.rs
│   │       ├── competition.rs
│   │       ├── attestation.rs
│   │       ├── http_api.rs
│   │       └── registry.rs
│   │
│   ├── enclave-bootstrap/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs
│   │       └── submitter.rs
│   │
│   ├── enclave-walrus-client/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── upload.rs
│   │
│   ├── gcp-attestation/
│   │   └── (TEE attestation token handling)
│   │
│   └── enclave-intent-indexer/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── config.rs
│           ├── monitor.rs           # subscribes to SUI events
│           └── handlers.rs
│
├── docker/
│   ├── solver-engine.Dockerfile
│   └── bootstrap.Dockerfile
│
├── deploy/
│   └── terraform/                   # GCP Confidential Space IaC
│       ├── main.tf
│       └── variables.tf
│
└── demo/                            # ── HACKATHON DEMO ──
    ├── index.html                   # Attestation Explorer UI
    ├── walrus-verifier.html         # "recompute the auction yourself" tool
    └── mev-comparison.html          # MEV attack demo
```

### Build & Deployment Commands

```bash
# Build the Move package
sui move build

# Run Move unit tests
sui move test

# Publish to SUI Testnet
sui client publish --gas-budget 200000000

# Build Rust services
cargo build --workspace --release

# Deploy to GCP Confidential Space
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

---

## Key Dependencies

### Move

| Package | Purpose |
|---|---|
| `sui::ecdsa_k1` | secp256k1 signature recovery for attestation verification |
| `sui::hash` | Keccak-256 hashing for attestation digests and chain continuity |
| `sui::coin` / `sui::balance` | `Coin<T>` escrow and stake management |
| `sui::table` | Solver registry and reputation storage |
| `sui::clock` | Deadline enforcement |
| `sui::event` | `IntentSubmitted`, `IntentSettled`, `IntentRefunded` events |
| DeepBook v3 (`deepbook::pool`, `deepbook::balance_manager`) | Settlement venue for winning fills |
| Walrus Move package (`walrus::system`, `walrus::blob`) | On-chain Blob certification checks (Phase 2) |

### Rust — Workspace

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `axum` | HTTP framework for the solver engine's quote API |
| `sui-sdk` | SUI Rust SDK — transaction building, RPC client |
| `fastcrypto` | secp256k1 signing (TEE attestation key) |
| `bcs` | Binary Canonical Serialization, matching Move's native encoding |
| `serde` | Serialization |
| `tracing` | Structured logging |
| `thiserror` / `anyhow` | Error handling |

### GCP Integration

| Tool | Purpose |
|---|---|
| GCP Confidential Space attestation verifier | Verify TEE execution proofs |
| `tonic` | gRPC client for GCP services |

### Walrus Integration

| Tool | Purpose |
|---|---|
| Walrus SDK / publisher HTTP API | Upload and certify the sealed-auction quote log |
| Walrus aggregator | Retrieve blobs for the audit-trail verifier UI |

### Indexing

| Tool | Purpose |
|---|---|
| SUI event subscription (via `sui-sdk` or a custom indexer) | Track `IntentSubmitted → IntentSettled` state machine |

---

## Testing Strategy

### Unit Tests (Per Module)

**Move modules**:
```bash
sui move test
# Tests: ecdsa_k1 recovery against known signature fixtures, hash-chain
# continuity, reputation EMA fixed-point math, slippage enforcement
```

**Rust services**:
```bash
cargo test --workspace --lib
# Tests: config parsing, HTTP endpoints, quote aggregation, BCS encoding,
# attestation signing
```

### Integration Tests

**Local SUI test validator**:
```bash
# 1. Start a local validator
sui start --with-faucet

# 2. Publish the package locally
sui client publish --gas-budget 200000000

# 3. Run integration tests against it
cargo test --test integration --features integration-tests
```

**SUI Testnet**:
```bash
sui client publish --gas-budget 200000000 --skip-dependency-verification
cargo test --test e2e_sui_testnet -- --nocapture
```

### Property-Based Testing

**Fuzzing (Solver Competition)**:
```bash
cargo +nightly fuzz run solver_competition_fuzz
# Property: for any set of quotes, argmax selection is deterministic
```

### Performance Testing

**Transaction cost benchmarking**:
```bash
sui client call ... --dry-run
# Track computation_cost / storage_cost / storage_rebate for settle_intent
# over time as the module evolves
```

**Throughput Testing**:
```bash
cargo bench --bench solver_throughput
# Property: solver can process N quotes/second
```

---

## Deployment Roadmap

### Day 1: Foundation
- [ ] Write and test `solver_registry.move` (registration, staking, slashing)
- [ ] Write and test `attestation.move` (struct + hash-chain helpers)
- [ ] Publish to SUI Testnet
- **Deliverable**: Solver registration working end-to-end on Testnet

### Day 2: Escrow Layer
- [ ] Write and test `intent_pool.move` (`submit_intent`, `refund_intent`)
- [ ] Full Move unit test suite passing
- **Deliverable**: Intents can be submitted and refunded on Testnet

### Day 3: Settlement Integration
- [ ] Write `deepbook_router.move` against the deployed DeepBook Testnet package
- [ ] Write `settlement.move` with native `ecdsa_k1` verification
- [ ] End-to-end Move integration tests
- **Deliverable**: Complete settlement flow working atomically on Testnet

### Day 4: Off-Chain Services
- [ ] Port `enclave-solver-engine` to submit via `sui-sdk`
- [ ] Build `enclave-walrus-client` and wire quote-log upload into the attestation-signing flow
- [ ] Test TEE bootstrap on GCP Confidential Space (staging)
- **Deliverable**: Solver can register, compete, and settle through the full pipeline

### Day 5: Demo & Polish
- [ ] Build Attestation Explorer UI
- [ ] Build the Walrus-backed "recompute the auction" verifier tool
- [ ] Build MEV comparison demo
- [ ] Transaction cost benchmark demo (with the Intent-deletion rebate highlighted)
- [ ] Final integration tests
- **Deliverable**: Hackathon-ready demo + documentation

---

## Glossary

| Term | Definition |
|---|---|
| **Attestation** | secp256k1-signed proof from the TEE of a sealed auction result, including a Walrus blob commitment |
| **BCS** | Binary Canonical Serialization — Move's native (de)serialization format |
| **Blob** | A Walrus-stored unit of data, represented on SUI as an object with a content-addressed blob ID |
| **Filled Intent** | A completed trade where the winning solver delivered at least `min_amount_out` |
| **Intent** | A SUI object representing a user's trade request, with the input `Coin` escrowed inside it |
| **Object Linearity** | The Move/SUI property that an object can be consumed (deleted) at most once, preventing replay structurally |
| **PTB (Programmable Transaction Block)** | SUI's atomic multi-step transaction format; all steps commit or none do |
| **Quote** | A solver's proposed output amount for the user's input amount |
| **Sealed Auction** | A solver competition where no quote is visible until after selection |
| **Settlement** | Release of escrowed funds and routing of the fill through DeepBook |
| **Shared Object** | A SUI object accessible by any transaction (requires consensus ordering) |
| **Slashing** | Stake penalty applied to a solver for protocol violations |
| **Solver** | An entity competing to fulfill a user's intent |
| **Storage Rebate** | Partial refund of an object's storage deposit upon deletion |
| **TEE** | Trusted Execution Environment (GCP Confidential Space) |

---

**Document Version**: 1.0
**Last Updated**: 2026-06-21
**Status**: Ready for Development
