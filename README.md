# FortiBlox Router

Non-custodial, atomic, multi-hop **route executor** for [X1](https://x1.xyz) (a Solana-compatible SVM), with an **unbypassable in-program protocol fee**.

- **Program ID:** `3geAsZiNaWDuTVtTbdWVQRitd55jY4UoWeeBmJFTJZmE`
- **Network:** X1 mainnet (`https://rpc.mainnet.x1.xyz`)
- **Language:** Rust / [Anchor](https://www.anchor-lang.com)
- **License:** Apache-2.0
- **Live version:** `0.4.3` — confirmed on-chain via the program's own `version()` instruction (`simulateTransaction` returns the return-data string `"0.4.3"`; see the account-less, zero-cost `version` handler in `lib.rs`).

## What it does

Off-chain routing (FortiSwap's own `/api/tx/build`) finds the best path across
[XDEX](https://xdex.fortiblox.com) cp-swap pools and Degen bonding-curve legs; this
program **executes that path in one atomic instruction** by CPI-ing each hop in
order, then takes the protocol fee on the output **before** the user can receive
it. Running the hops inside a single program call keeps the outer transaction
small (so deeper routes fit in one transaction) and makes the fee impossible to
omit.

The primary entrypoint is `route_v2`. `route_v3` is the same engine plus a
second, integrator-owned fee sink (for third parties building on top of
FortiSwap). `route_v2_snipe` and `route_v2_delegated` are fixed-shape variants
for same-slot races and SPL-delegate-signed automation. All four charge the
identical, unbypassable 25 bps protocol fee. See [`DESIGN.md`](./DESIGN.md) for
the full interface, invariants, and threat model.

## Design principles

- **Non-custodial by construction.** Every token account is one of the user's own
  ATAs; each hop's output ATA is the next hop's input ATA (funds sit in user
  accounts between hops); the swap authority for every leg is the user (a signer
  of the outer transaction, or an SPL delegate on `route_v2_delegated`). The
  program takes no delegation on the user's behalf and holds no vault between
  transactions — its only persistent state is a governance-owned `fee_config` PDA
  (pause switch + rate ladder, holds no user funds).
- **Unbypassable fee.** The fee is computed and moved **inside** the route
  instruction, atomically with the swap, to the pinned fee wallet's canonical
  ATA. There is no code path that returns output to the user without the fee
  being taken (Jupiter's platform-fee model). The rate is a compile-time
  constant (`PROTOCOL_FEE_BPS = 25`), not a caller argument, so it cannot be
  zeroed to dodge the fee.
- **Kill-switch, not a backdoor.** A `fee_config` PDA carries a `paused` flag a
  guardian key can set in an incident (any live route entrypoint then reverts);
  only the upgrade authority can unpause. The switch cannot redirect funds,
  change the fee rate, or bypass non-custodial execution — it can only halt it.
- **All-or-nothing atomicity** from a single SVM transaction.

## Build

Requires the Solana/Anchor toolchain (`cargo-build-sbf` / `anchor`).

```bash
# Standard SBF build
cargo build-sbf

# Reproducible / verifiable build (recommended — matches the on-chain hash)
solana-verify build --library-name fortiblox_router
solana-verify get-executable-hash target/deploy/fortiblox_router.so
```

## Repository layout

```
Cargo.toml, Cargo.lock, Anchor.toml   workspace + toolchain config
programs/fortiblox-router/            the on-chain program (Cargo.toml + src/lib.rs)
idl/fortiblox_router.json             the Anchor IDL
keys/PROGRAM_ID.txt                   the canonical program ID
tests/                                a representative slice of the test suite (mock AMM + two integration tests)
DESIGN.md                             design, invariants, and threat model
```

This is a **curated snapshot**, not a 1:1 mirror of the private development repo —
deployment tooling, internal upgrade runbooks, and audit-in-progress scratch work
are intentionally excluded. What's here is the complete, real on-chain program
source plus enough of the test harness to read how it's exercised.

## Security

The program embeds an on-chain `security.txt`. To report a vulnerability, contact
`security@fortiblox.com` — see the policy at <https://fortiblox.com/security>.

Internal contract audits (multiple rounds, including a deep audit that produced
the v0.4.2 pause-bypass fix) have been completed; an external audit is pending.
Do not rely on this program for material value until the external audit and bug
bounty are complete.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
