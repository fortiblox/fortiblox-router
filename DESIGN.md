# fortiblox-router — design & threat model (condensed)

Program id: `3geAsZiNaWDuTVtTbdWVQRitd55jY4UoWeeBmJFTJZmE`
Status: **LIVE on X1 mainnet, version `0.4.3`** — confirmed via the program's own
`version()` instruction (a `simulateTransaction` call against the real deployed
program returns the return-data string `"0.4.3"`; last-deploy slot observed
77065693). This is a condensed version of the private repo's full design
document, trimmed to what's relevant to reading and auditing this source.

## What it is

A non-custodial, atomic, multi-hop **route executor** for X1 (a Solana-compatible
SVM). Off-chain routing (FortiSwap's own `/api/tx/build`) finds the best path
across [XDEX](https://xdex.fortiblox.com) cp-swap pools and Degen bonding-curve
legs; the program executes that path in **one atomic instruction** by CPI-ing
each hop in order, then takes the protocol fee on the output before the user can
receive it. Modeled on Raydium's routing program over Raydium cp-swap — XDEX is
a cp-swap fork, so this is the same shape repointed to XDEX plus Degen legs.

Why on-chain: running the hops inside one program call keeps the outer
transaction small (deep routes fit where an Address-Lookup-Table-composed
client-side path alone couldn't), and it makes the fee impossible to omit.

## Entrypoints

| Instruction | Purpose | Fixed accounts |
|---|---|---|
| `route_v2` | Primary swap path (XDEX + Degen legs) | 9 (incl. mandatory `fee_config` pause account) |
| `route_v3` | `route_v2`'s engine + a second, integrator-owned fee sink | 11 (`route_v2`'s 9 + integrator destination/wallet) |
| `route_v2_snipe` | Fixed-account single-XDEX-hop variant for same-slot races | 19 |
| `route_v2_delegated` | An SPL delegate signs on the user's behalf (copy-trade automation); output routes through a transient, always-drained vault PDA | 12 |
| `version` | Read-only, account-less; returns the semantic version as return data | 0 |
| `set_paused` / `set_guardian` | Governance: pause switch and guardian key management | — |

All four route variants CPI only into the pinned `xdex::ID` (cp-swap AMM) and
`degen::ID` (bonding-curve launchpad) programs, never a caller-supplied program.
Hop data arrives as `remaining_accounts`, partitioned per leg kind, and must
match the instruction's declared route exactly.

## `route_v2` — the primary interface

`route_v2(legs: Vec<u8>, initial_amount_in: u64, minimum_amount_out: u64)`

Fixed accounts, in order: `user` (signer, rent payer), `fee_destination` (mut,
validated), `fee_wallet` (pinned constant), `system_program`,
`associated_token_program`, `xdex_program` (pinned), `degen_program` (pinned),
`token_program` (pinned, for WXNT wrap/unwrap), `fee_config` (pinned PDA,
mandatory pause-switch account).

Hop 0 swaps `initial_amount_in`; each later hop swaps the exact balance its
input ATA received from the previous hop (an explicit input-debit invariant is
asserted around every CPI, so a hop can never be induced to spend more than the
route says). `minimum_amount_out` is a floor on what the user keeps **after**
the protocol fee.

## Invariants (what an audit should verify)

1. **Non-custodial.** Every token account is one of the user's own ATAs; each
   hop's output ATA is the next hop's input ATA; the swap authority for every
   leg is the user (a signer) or, on `route_v2_delegated`, an asserted SPL
   delegate. The program holds no vault and takes no delegation of its own —
   its only persistent state is the governance-owned `fee_config` PDA (pause
   flag + rate ladder), which holds no user funds.
2. **CPI targets pinned.** Swaps are `invoke`d against the constants `xdex::ID`
   / `degen::ID`, never a caller-supplied program; every AMM/pool account is
   checked to be owned by the expected program before use.
3. **Fee is unbypassable.** `PROTOCOL_FEE_BPS = 25` (0.25%) is a compile-time
   constant, not a caller argument — no input sets it to 0. The fee is
   `ceil(gross_out * 25 / 10_000)`, rounded **up**, so any positive output pays
   at least 1 unit (no sub-unit dust-farming). It's transferred, atomically with
   the swap, to `fee_destination`, which must equal
   `ATA(output_mint, FEE_WALLET, output_token_program)` — a caller cannot
   redirect it. There is no code path that returns output to the user without
   the fee being taken. `route_v3` additionally splits off an integrator fee
   (`1..=300` bps, hard-capped at compile time) from the same gross, never
   carved out of the protocol fee.
4. **On-chain slippage.** The user's net receipt (after all fees) must meet
   `minimum_amount_out` or the whole transaction reverts.
5. **Pausable, not redirectable.** A guardian or the upgrade authority can set
   `fee_config.paused`, which every route entrypoint checks as a **mandatory**
   fixed account before running the engine — a caller cannot omit it to bypass
   an active pause (Anchor's `AccountNotEnoughKeys` if they try). Only the
   upgrade authority can unpause. The switch has no path to move funds or
   change the fee rate; it can only halt execution.
6. **Checked math only**, Token-2022 aware (amounts read from live token-account
   balances post-transfer-fee; decimals read from the mint for
   `TransferChecked`). Bounded: `1 <= num_hops <= 6`.

## Fee rounding — worked example

`gross_out = 1_000_000`, `bps = 25` → `ceil(1_000_000 × 25 / 10_000) = 2_500`.
`gross_out = 1` → `ceil(25 / 10_000) = 1` (dust still pays 1 unit). Fee is 0
only when `gross_out` is 0, which cannot pass a positive `minimum_amount_out`.

## Version history (condensed — see `lib.rs`'s module doc for full detail)

- **v0.2.0** — the original XDEX-only `route` instruction (which traded a
  hop's *full* input-ATA balance rather than an exact carried amount) was
  deleted; `route_v2`'s exact-carry engine became the sole audited path. Added
  the governance `fee_config` PDA (dormant at this point).
- **v0.3.0** — added `route_v2_delegated` (SPL-delegate automation, via a
  transient always-drained vault PDA) and `route_v2_snipe` (fixed-account
  single-hop race variant).
- **v0.3.1** — audit patch set: an exact input-debit invariant on every hop
  (bounds what a rogue/upgraded AMM can ever take to precisely the route's
  declared amount), a `TransferHook`-output rejection before any CPI, a guard
  against a Borsh length-prefix heap-OOM panic, and the `fee_config`
  pause/guardian switch (initially optional on `route_v2` for backward
  compatibility — see v0.4.2 below).
- **v0.4.0** — added `route_v3`: the `route_v2` engine plus a second,
  integrator-owned fee sink, for third parties building on top of FortiSwap.
  `route_v2` itself is byte-identical on the wire.
- **v0.4.1** — repointed the protocol fee wallet from a cold hardware wallet to
  a hot, program-signable intake key, so fee sweeps can be automated. No
  behavioural or wire change; only the pinned pubkey constant changed (deployed
  to X1 mainnet 2026-09-03).
- **v0.4.2** — closed a pause-bypass gap: `route_v2`'s `fee_config` account had
  been *optional* since v0.3.1 (for backward compatibility), meaning a caller
  could omit it and keep trading through a route a guardian had just paused.
  Fixed by making `fee_config` a mandatory fixed account on `route_v2`, matching
  every other entrypoint — a deliberate, audited wire break affecting only
  external/stale callers, not FortiBlox's own client (which already sent the
  account on every call).
- **v0.4.3** (current live version) — combines v0.4.1 + v0.4.2 into a single
  mainnet upgrade transaction, plus an independent fix: a missing address check
  on the fee-recipient slot read during Degen bonding-curve "graduation"
  accounting could, for a compromised Degen program, redirect the real
  (governance-set, non-attacker-arbitrary) creation fee to an arbitrary wallet.
  A targeted proof-of-concept first confirmed the *theorized* larger exploit
  (an attacker forging an unbounded fee ceiling) is **not possible** — it's
  blocked at the Solana runtime level, not by router logic — before the actual,
  smaller, real gap was found and fixed by validating the fee recipient against
  the same account bytes already being read for the fee amount.

## Test status

The full private test suite (`cargo test -p fortiblox-router` + a LiteSVM
integration suite exercising real, captured on-chain XDEX/Degen bytes) is
green. This mirror includes a representative slice — a minimal mock AMM crate
and two integration tests — as a readable sample of the harness shape, not the
complete suite (which also depends on archived historical program binaries and
a larger fixture set kept in the private repo for exact A/B wire-compatibility
checks across every shipped version).

## Security

The program embeds an on-chain `security.txt` (see `lib.rs`). Internal contract
audits (multiple rounds, including a deep round that produced the v0.4.2 fix)
are complete; an external audit is pending. Report vulnerabilities to
`security@fortiblox.com`.
