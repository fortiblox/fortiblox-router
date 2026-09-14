//! FortiBlox Router — non-custodial atomic multi-hop route executor for X1
//! (Solana-compatible SVM) with an UNBYPASSABLE in-program protocol fee.
//!
//! Off-chain routing (our `/api/tx/build`) finds the best path across XDEX
//! cp-swap pools and Degen bonding curves; this program EXECUTES that path in
//! ONE atomic instruction (`route_v2`) by CPI-ing each leg in order, then takes
//! the protocol fee on the output BEFORE the user can receive it. Doing the hops
//! inside one program call keeps the OUTER transaction small (the deep-route
//! win an ALT alone can't fully deliver); a single SVM transaction gives
//! all-or-nothing atomicity.
//!
//! NON-CUSTODIAL BY CONSTRUCTION. The router never owns or holds funds:
//!   * every token account is one of the USER's own ATAs,
//!   * each hop's output ATA is the next hop's input ATA (funds sit in user
//!     accounts between hops),
//!   * the swap authority for every leg is the USER (a signer of the outer tx),
//!   * the program holds no vault and takes no delegation. Its ONLY state is the
//!     governance-owned `fee_config` PDA (v0.2.0, WP #6707 B2), which holds no
//!     user funds and which `route_v2` does not even read (dormant until the
//!     future `route_tiered` upgrade).
//!
//! UNBYPASSABLE FEE. Unlike a client-appended fee transfer (which any custom
//! client can simply omit), the fee here is computed and moved INSIDE
//! `route_v2`, atomically with the swap, to the pinned fee wallet's canonical
//! ATA. There is no code path that returns output to the user without the fee
//! being taken — this is Jupiter's platform-fee model. See DESIGN.md "Fee
//! invariant".
//!
//! v0.2.0 (WP #6707 bundle): the v1 `route` instruction (XDEX-only, discriminator
//! `e517cb977ae3ad2a`) was DELETED — its mid-route hops traded the full input-ATA
//! balance (the "sweep" class, WP #6704/6705); `route_v2`'s exact carry is the
//! sole audited engine. That discriminator is RETIRED and must never be reused
//! for different semantics: a stale client hitting it gets Anchor's
//! `InstructionFallbackNotFound` (error 101) before any account is touched.
//!
//! v0.3.0 (Forgejo fortiblox-app #450): two ADDITIVE entrypoints for the
//! Honeybadger automation surfaces, `route_v2` untouched on the wire:
//!   * `route_v2_delegated` — an SPL DELEGATE signs on the user's behalf
//!     (copy-trade). Because a delegate has authority over the user's INPUT
//!     ATA only, the route's output lands in a router-controlled transient
//!     vault ATA (owner = the `["vault_authority"]` PDA), the PDA signs the fee
//!     `TransferChecked` to the pinned fee sink and forwards the net to the
//!     USER's canonical output ATA, and the instruction asserts the vault is
//!     EMPTY at exit (`VaultNotDrained`). The router still holds no value
//!     between transactions; XDEX legs only (see the instruction docs).
//!   * `route_v2_snipe` — a fixed-account single-XDEX-hop variant (no leg
//!     partitioning, no Degen/WXNT plumbing) for same-slot races; identical fee
//!     path to `route_v2`.
//!
//! v0.3.1 (audit patch set A/B/C, 2026-08-23) — ADDITIVE, `route_v2` wire
//! unchanged:
//!   * C-1 INPUT-DEBIT INVARIANT: every XDEX hop (all three entrypoints) asserts
//!     `input_ata.amount(before) − amount(after) == amount_in` around the CPI
//!     (`InputDebitMismatch` 6040); a Degen SELL asserts the exact meme debit;
//!     a Degen BUY bounds the signer's native debit to
//!     `amount + ceil(amount × 1 %) + rent of the ATAs the buy created`
//!     (measured on the live Degen bytes, `tests/degen-live.test.ts`). A rogue
//!     / upgraded AMM can therefore take EXACTLY what the route says, never the
//!     whole balance the signer's authority would otherwise expose.
//!   * A-5: the delegated hop loop rejects `TransferHook` output mints BEFORE
//!     any CPI (next to the `TransferFeeConfig` check).
//!   * A-7: a guarded entrypoint validates the `legs` Borsh length prefix
//!     against the instruction data before Anchor deserialises it
//!     (`BadLegsLength` 6041 instead of a heap-OOM panic).
//!   * B-M2 PAUSE SWITCH (superseded by v0.4.2 below — see there for the FINAL
//!     `route_v2` shape): `FeeConfig.paused` (byte 225) + `guardian` (bytes
//!     226..258) carved from the front of `reserved`; `route_v2_snipe` and
//!     `route_v2_delegated` take the `fee_config` PDA as a trailing FIXED
//!     account; `route_v2` originally accepted it as an OPTIONAL trailing
//!     remaining account so legacy/cached clients kept working while updated
//!     clients opted into pause coverage; `set_paused` (guardian or authority
//!     may pause, ONLY the authority may unpause), `set_guardian` (authority).
//!     Paused → 6042.
//!
//! v0.4.0 (OpenProject #7264, public FortiSwap API) — INTEGRATOR FEE, ADDITIVE,
//! `route_v2` byte-identical on the wire and in behaviour:
//!   * `route_v3` = the `route_v2` engine (same leg kinds, windows, carry,
//!     C-1 bounds, WXNT bridging) + a SECOND, integrator-owned fee sink taken
//!     atomically in the SAME instruction: `integrator_fee_bps: u16` (arg,
//!     `1..=MAX_INTEGRATOR_FEE_BPS`) and two fixed accounts
//!     `integrator_fee_destination` (== `ATA(out_mint, integrator_wallet,
//!     out_token_program)`, derived + asserted, MUST pre-exist — the
//!     integrator creates its own fee account, never the user) and
//!     `integrator_wallet`. The protocol fee is UNCHANGED and UNTOUCHABLE:
//!     `ceil(gross × 25 bps)` on the GROSS output, computed first, to the
//!     pinned `EeWE…` sink; the integrator fee is `floor(gross × bps)` on the
//!     same gross — never carved out of the protocol fee — and the user's
//!     `minimum_amount_out` is enforced on `gross − protocol − integrator`.
//!     `fee_config` is a MANDATORY fixed account (pause-covered from the first
//!     tx, like snipe/delegated). Emits the unchanged `RouteExecuted` (`fee` =
//!     the protocol fee, `user_receives` = net after BOTH fees) plus
//!     `IntegratorFeePaid`. A new instruction rather than a new `route_v2`
//!     arg because Anchor/Borsh args are positional with no defaults: any
//!     appended arg (even `Option<u16>`, which needs its tag byte) would make
//!     every un-upgraded client fail with Anchor 102 — see DESIGN.md v0.4.0.
//!
//! v0.4.1 (OpenProject #7386) — PROTOCOL FEE WALLET REPOINT, additive, no
//! behavioural or wire change: `fee_wallet::ID` moves from a cold hardware
//! wallet (`EeWE…`) to a hot fee-intake key (`FdQ2…`) the app box can sign for,
//! so `/api/cron/fee-sweep` + `fee-forward` can consolidate the 25 bps take
//! automatically instead of requiring a physical hardware tap. The pin stays
//! a compile-time constant, not a `fee_config`-driven field, to avoid adding
//! a live fee-redirection surface. Only the 32-byte pubkey constant changes
//! (12 copies in the ELF: 1 contiguous `.rodata` literal + 11 inlined `lddw`
//! immediates); all 12 instructions, 47 errors, wire formats, `FeeConfig`
//! layout, the 25 bps rate, and the pause/guardian surface are byte-identical
//! otherwise. Deployed to X1 mainnet 2026-09-03; see UPGRADE_PLAN_FEE_WALLET.md.
//!
//! v0.4.2 (security audit, Medium finding — the B-M2 pause bypass) — WIRE
//! BREAK, on `route_v2` ONLY, by design:
//!   * `route_v2`'s optional trailing `fee_config` account (B-M2, v0.3.1) was
//!     the router's PRIMARY/highest-volume entrypoint and the pause switch was
//!     the guardian incident kill-switch — an attacker (or any legacy/cached
//!     client) could simply omit the tail and keep trading through a route the
//!     guardian had just paused, exactly the scenario the switch exists for.
//!     `route_v2_snipe` / `route_v2_delegated` / `route_v3` were never exposed
//!     to this because their `fee_config` was already a mandatory FIXED
//!     account from the day each shipped.
//!   * FIX: `fee_config` is now a MANDATORY, FIXED 9th account on `route_v2`
//!     (`route_v2`'s existing 8, same order, then `fee_config` — the identical
//!     append pattern `route_v3` already used relative to `route_v2`), gated
//!     BEFORE the engine runs, matching every other entrypoint. A caller that
//!     omits it now gets Anchor `AccountNotEnoughKeys` (3005), never a silent
//!     uncovered swap. `execute_route`'s optional-tail parsing branch (the
//!     bypass surface itself) is removed — remaining_accounts must now
//!     partition EXACTLY for BOTH `route_v2` and `route_v3`.
//!   * This is an intentional, audited wire break: FortiBlox's own BFF
//!     (`/api/tx/build`, `packages/onchain-client/src/txBuilder.ts`
//!     `planSwapInstructions`) already appended the tail on every `route_v2`
//!     it built (`ROUTER_PAUSE_GUARD` defaults to enabled; unset in every
//!     deployed env) — the fix has ZERO effect on FortiBlox's own users and
//!     closes the loophole for any external/malicious/stale caller.
//!
//! Model: Raydium's routing program (`routeUGW…`) over Raydium cp-swap — XDEX
//! is a cp-swap fork, so this is the same shape repointed to XDEX + our routes.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
};
use anchor_lang::system_program::System;
use anchor_spl::associated_token::{
    get_associated_token_address_with_program_id, AssociatedToken,
};

declare_id!("3geAsZiNaWDuTVtTbdWVQRitd55jY4UoWeeBmJFTJZmE");

#[cfg(all(feature = "guarded-entrypoint", not(feature = "cpi")))]
use solana_security_txt::security_txt;
#[cfg(all(feature = "guarded-entrypoint", not(feature = "cpi")))]
security_txt! {
    name: "FortiSwap Router",
    project_url: "https://app.fortiblox.com",
    contacts: "email:security@fortiblox.com,link:https://fortiblox.com",
    policy: "https://fortiblox.com/security",
    preferred_languages: "en",
    source_code: "https://github.com/fortiblox/fortiblox-router",
    auditors: "Internal contract-audit (rounds 1-2 + deep); external audit pending"
}

// ---------------------------------------------------------------------------
// v0.3.1 (audit A-7) — GUARDED ENTRYPOINT.
//
// Anchor deserialises instruction args with Borsh BEFORE any handler code runs.
// borsh 1.8 `Vec<u8>` (`de/mod.rs::vec_from_reader`) pre-allocates
// `min(len_prefix, 1 MiB)` bytes, and the SBF heap is 32 KiB — so a `legs`
// length prefix above ~30 KiB aborts with an UNTYPED heap-OOM panic instead of
// Anchor's `InstructionDidNotDeserialize` (102). The Anchor-generated
// `entrypoint!` is disabled (feature `guarded-entrypoint` implies
// `no-entrypoint`) and replaced by one that bounds the prefix against the bytes
// actually present, then delegates to the generated `entry` unchanged. No IDL /
// wire change: `legs` stays `Vec<u8>`; only the failure mode of malformed data
// changes (panic → typed 6041).
// ---------------------------------------------------------------------------
/// Pure A-7 guard (unit-tested): true unless `data` is a `route_v2` /
/// `route_v2_delegated` call whose `legs` u32 length prefix exceeds the bytes
/// that follow it. Anything else (other discriminators, truncated data) is left
/// to Anchor, which answers 101 / 102 exactly as before.
pub fn legs_prefix_ok(data: &[u8]) -> bool {
    if data.len() < 8 {
        return true;
    }
    let is_legs_ix = data[..8] == *instruction::RouteV2::DISCRIMINATOR
        || data[..8] == *instruction::RouteV2Delegated::DISCRIMINATOR
        || data[..8] == *instruction::RouteV3::DISCRIMINATOR; // v0.4.0: first arg is `legs` too
    if !is_legs_ix || data.len() < 12 {
        return true;
    }
    let len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    len <= data.len() - 12
}

#[cfg(all(feature = "guarded-entrypoint", not(feature = "cpi")))]
mod guarded_entrypoint {
    use super::*;
    use anchor_lang::solana_program::entrypoint::ProgramResult;

    fn guarded_entry<'info>(
        program_id: &'info Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &'info [u8],
    ) -> ProgramResult {
        if !legs_prefix_ok(data) {
            let e: anchor_lang::error::Error = RouterError::BadLegsLength.into();
            e.log();
            return Err(e.into());
        }
        entry(program_id, accounts, data)
    }

    anchor_lang::solana_program::entrypoint!(guarded_entry);
}

/// XDEX AMM (Raydium cp-swap fork) — the ONLY program this router CPIs into.
pub mod xdex {
    use anchor_lang::prelude::*;
    declare_id!("sEsYH97wqmfnkzHedjNcw3zyJdPvUmsa9AixhS4b4fN");
}
/// FortiBlox protocol fee wallet — pinned; the fee ATA is derived from this.
pub mod fee_wallet {
    use anchor_lang::prelude::*;
    declare_id!("FdQ2FmAydXBe87Nm7w4MjksRqTUjahPaqjj7mVshKvNa");
}
/// Degen (degen.fyi) bonding-curve launchpad ("pump") on X1 — v2's second, and
/// only other, CPI target. Live-verified `degenDXVP…`.
pub mod degen {
    use anchor_lang::prelude::*;
    declare_id!("degenDXVPhS7vgu3hcdzGA7T6dfCe6qTYyVM7npP3pc");
}
/// Wrapped-XNT mint (classic SPL). The XNT hub between a Degen leg (native) and
/// an XDEX leg (WXNT) is normalized to WXNT by the router's wrap/unwrap.
pub mod wxnt {
    use anchor_lang::prelude::*;
    declare_id!("So11111111111111111111111111111111111111112");
}

/// Anchor discriminator for cp-swap `swap_base_input` = sha256("global:swap_base_input")[..8].
/// Confirmed byte-for-byte against a live XDEX SwapBaseInput (8f be 5a da c4 1e 33 de).
const SWAP_BASE_INPUT_DISC: [u8; 8] = [143, 190, 90, 218, 196, 30, 51, 222];

/// Protocol fee, in basis points of the route's net output. CONSTANT (not a
/// caller argument) so it can never be set to 0 to dodge the fee. `MAX_FEE_BPS`
/// is the compile-time sanity cap governance may not exceed if this is ever
/// made config-driven.
const PROTOCOL_FEE_BPS: u64 = 25; // 0.25%, matching today's client fee
const MAX_FEE_BPS: u64 = 100; // 1.00% hard cap (invariant: PROTOCOL_FEE_BPS <= MAX_FEE_BPS)
const BPS_DENOM: u64 = 10_000;

/// v0.4.0 — HARD CAP on the integrator (third-party dApp) fee a `route_v3`
/// caller may charge, in bps of the route's gross output. COMPILE-TIME, no
/// governance surface: the cap is a user-protection invariant (a malicious
/// or compromised integrator frontend cannot turn the router into a drain),
/// not a tunable. 300 bps = 3 %: above every live integrator programme we
/// verified (Jupiter referral `platformFeeBps` is a u8, ≤ 255 bps in
/// practice; 1inch Fusion / 0x affiliate fees run 10–100 bps), so no honest
/// integrator is constrained, while 3 % keeps the worst case bounded and
/// visible next to the 25 bps protocol fee it can never touch. Floor is 1
/// (a zero integrator fee is what `route_v2` is for — one code path per
/// intent, nothing "ignored").
pub const MAX_INTEGRATOR_FEE_BPS: u16 = 300;

const ACCOUNTS_PER_HOP: usize = 13;
const IDX_PAYER: usize = 0;
const IDX_POOL_STATE: usize = 3;
const IDX_INPUT_ATA: usize = 4;
const IDX_OUTPUT_ATA: usize = 5;
const IDX_INPUT_TOKEN_PROGRAM: usize = 8;
const IDX_OUTPUT_TOKEN_PROGRAM: usize = 9;
const IDX_INPUT_MINT: usize = 10;
const IDX_OUTPUT_MINT: usize = 11;

const MAX_HOPS: usize = 6;

/// v0.3.0 — seed of the router's transient-vault authority PDA. Vault token
/// accounts are the PDA's canonical ATAs (`ATA(mint, vault_authority,
/// token_program)`): one per mint, idempotently created (the `payer` funds the
/// one-time rent), standard for indexers, Token-2022-extension-aware
/// (ImmutableOwner) — no custom token-account init path to audit. Funds only
/// ever transit them INSIDE `route_v2_delegated`; the final vault is asserted
/// EMPTY at exit.
pub const VAULT_AUTHORITY_SEED: &[u8] = b"vault_authority";

/// v0.3.1 (audit B-M2) — PAUSE SWITCH. `FeeConfig.paused` lives at absolute
/// byte 225 (the first byte carved from the former `reserved` region; the
/// layout table on `FeeConfig` is the authority). Route entrypoints read ONE
/// byte of the `fee_config` PDA, which is pinned by CONSTANT address (no
/// `find_program_address` on the hot path) and by owner — no Anchor account
/// deserialisation. `set_paused` / `set_guardian` are the only writers.
pub const FEE_CONFIG_PAUSED_OFF: usize = 225;
/// The single global `fee_config` PDA = `find_program_address(["fee_config"], ID)`
/// (unit-asserted). Initialised on X1 mainnet 2026-08-22 (v0.2.0 runbook §2b).
pub mod fee_config_pda {
    use anchor_lang::prelude::*;
    declare_id!("6kfdAmUEPCQbRWpVchV6wS3K8wtd6vKgSEYvkKPAUoHC");
}
/// The pause gate shared by every route entrypoint. Fail-closed: the account
/// must BE the fee_config PDA (else `ConstraintAddress` 2012, like the other
/// pinned fixed accounts), be owned by this program (`ConstraintOwner` 2004 —
/// i.e. the PDA must exist), be the full 512-byte account, and have
/// `paused == 0` (else `Paused` 6042).
fn require_not_paused(ai: &AccountInfo) -> Result<()> {
    require_keys_eq!(ai.key(), fee_config_pda::ID, anchor_lang::error::ErrorCode::ConstraintAddress);
    require_keys_eq!(*ai.owner, crate::ID, anchor_lang::error::ErrorCode::ConstraintOwner);
    let d = ai.try_borrow_data()?;
    require!(d.len() == FEE_CONFIG_SPACE, anchor_lang::error::ErrorCode::ConstraintOwner);
    require!(d[FEE_CONFIG_PAUSED_OFF] == 0, RouterError::Paused);
    Ok(())
}

/// On-chain ground truth for explorers/auditors (B3). Bumped with every
/// upgrade; mirrors the crate/IDL version. Read via the `version` instruction.
pub const ROUTER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// SPL / Token-2022 token-account offsets: mint[0..32], owner[32..64], amount[64..72].
const TA_MINT_OFF: usize = 0;
const TA_OWNER_OFF: usize = 32;
const TA_AMOUNT_OFF: usize = 64;
/// SPL / Token-2022 token-account `delegate: COption<Pubkey>` (u32 tag at 72,
/// key at 76..108) and `delegated_amount: u64` at 121..129 (base layout; the
/// Token-2022 base account is byte-identical for these fields).
const TA_DELEGATE_TAG_OFF: usize = 72;
const TA_DELEGATE_KEY_OFF: usize = 76;
const TA_DELEGATED_AMOUNT_OFF: usize = 121;
/// SPL / Token-2022 token-account `state` byte (AccountState: 0 Uninitialized,
/// 1 Initialized, 2 Frozen). S3 (round-3 audit L-2): only an INITIALIZED account
/// classifies as a token account — a token-program-owned buffer that merely has
/// the right length/type byte no longer passes structurally. Frozen is rejected
/// too (fail-closed: no transfer into/out of a frozen account can succeed).
const TA_STATE_OFF: usize = 108;
const TA_STATE_INITIALIZED: u8 = 1;
/// Mint `decimals` byte offset (SPL + Token-2022 base layout).
const MINT_DECIMALS_OFF: usize = 44;
/// Token-2022 base sizes / TLV layout. A base Mint is 82 bytes; a base token
/// Account is 165. Extended accounts carry an account-type discriminator at
/// offset 165 (1 = Mint, 2 = Account), then TLV extensions from 166.
const SPL_MINT_LEN: usize = 82;
const TA_LEN: usize = 165;
const ACCOUNT_TYPE_OFF: usize = 165;
const ACCOUNT_TYPE_MINT: u8 = 1;
const ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const TLV_START: usize = 166;
/// spl-token-2022 ExtensionType::TransferHook = 14.
const EXT_TRANSFER_HOOK: u16 = 14;
/// spl-token-2022 ExtensionType::TransferFeeConfig = 1. v0.3.0 review M-1: the
/// delegated path FORWARDS the net output vault -> user in a second transfer,
/// on which Token-2022 withholds the mint's transfer fee AFTER the min-out was
/// enforced — so fee-config mints are rejected fail-closed on that path only
/// (`route_v2` / `route_v2_snipe` measure gross in the user's ATA and stay correct).
const EXT_TRANSFER_FEE_CONFIG: u16 = 1;

// ---------------------------------------------------------------------------
// v2 — Degen bonding-curve leg support.
//
// v2 adds a SECOND CPI target (Degen) and a per-hop LEG-TYPE scheme so a single
// atomic route can mix XDEX cp-swap hops and Degen buy/sell hops. Since v0.2.0
// `route_v2` is the ONLY swap entrypoint (v1 `route` deleted — see the crate
// docs). All v1 invariants (unbypassable fee before min-out, pinned fee sink,
// non-custodial, token/mint validation) are preserved and the fee is still
// taken EXACTLY ONCE on the route's final net output.
//
// Degen legs use NATIVE XNT as their quote medium (live-verified, lamport-exact):
//   * BUY  debits NATIVE from the signer (amount into curve + 1% fee ON TOP +
//     ATA rents); ignores the signer's WXNT balance; outputs meme Token-2022.
//     Idempotently (re)creates the signer's meme + WXNT ATAs (safe to pre-exist).
//   * SELL inputs meme Token-2022; outputs NATIVE to the signer (the program
//     wraps the curve payout into the signer WXNT ATA then CLOSES it — the WXNT
//     ATA MUST pre-exist and is GONE afterwards, its rent reclaimed to signer).
// Neither has an on-chain min-out — so the ROUTER enforces the net min-out on the
// final output itself (the key safety point), exactly as it already does for XDEX.
// ---------------------------------------------------------------------------

/// Anchor discriminators for Degen `buy`/`sell` (sha256("global:<name>")[..8]),
/// live-verified byte-for-byte against real X1 txs.
const DEGEN_BUY_DISC: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];
const DEGEN_SELL_DISC: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];

/// Degen buy fee (parts-per-million of the amount-into-curve), charged ON TOP.
/// Used ONLY to conservatively reserve native when the router derives a
/// mid-route buy's `amount` — under-reserving reverts the tx (safe), over-
/// reserving just buys fewer tokens (the net min-out still binds). Correctness
/// never depends on this being exactly Degen's live fee.
const DEGEN_BUY_FEE_PPM: u64 = 10_000; // 1.0%
const PPM_DENOM: u64 = 1_000_000;
/// Conservative native reserve (lamports) for a mid-route buy: up to two ATA
/// rents (meme Token-2022 + WXNT) the buy may (re)create. Generous on purpose.
const DEGEN_BUY_RENT_RESERVE: u64 = 5_000_000;

/// Per-hop leg kinds (u8, wire-encoded in `route_v2`'s `legs` vector).
const LEG_XDEX: u8 = 0;
const LEG_DEGEN_BUY: u8 = 1;
const LEG_DEGEN_SELL: u8 = 2;

/// Account-window sizes per leg kind (consumed in order from remaining_accounts).
const XDEX_ACCTS: usize = ACCOUNTS_PER_HOP; // 13
const DEGEN_BUY_ACCTS: usize = 28;
const DEGEN_SELL_ACCTS: usize = 16;

// Degen BUY window indices (per degen-pump-idl.json `buy`, 28 accounts).
const DB_TOKEN_STATE: usize = 0;
const DB_SIGNER: usize = 3;
const DB_MINT: usize = 5;
const DB_SIGNER_TOKEN: usize = 7; // signer meme Token-2022 ATA (OUTPUT)
const DB_SIGNER_WSOL: usize = 8; // signer WXNT ATA (touched, not a funding source)
const DB_TOKEN_2022_PROG: usize = 25;
/// Writable indices for the buy CPI metas (per IDL isMut); signer = DB_SIGNER.
const DB_WRITABLE: [usize; 19] = [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21];

// R-1 (v0.3.1): graduation-cost accounts. A buy with `amount == remaining`
// fills the curve and Degen's `buy` ALSO performs the XDEX pool-creation CPI
// in the same instruction, charging the signer `amm_config.create_pool_fee`
// plus the rent of every account the migration creates. These indices let
// `degen_graduation_allowance` detect that and widen the exact-debit bound
// by EXACTLY that cost — see the LEG_DEGEN_BUY arm and
// `tests/degen-live.test.ts` DL5.
const DB_AMM_CONFIG: usize = 11;
const DB_POOL_STATE: usize = 13;
/// First of the two token-vault slots (pool's traded-mint token accounts,
/// always SPL-Token-owned — classic or Token-2022 — never `xdex::ID`; see
/// the owner-gate special case in `degen_graduation_allowance`).
const DB_VAULT0: usize = 19;
/// Last of the 8 "newly created on graduation" rent-bearing slots
/// (pool_state, observation, lp_mint, 3 LP ATAs, vault0, vault1 = 13..=20).
const DB_VAULT1: usize = 20;
const DB_CREATE_POOL_FEE: usize = 21;

/// R-1 fix (v0.3.1-R1 review, Finding 1 MUST-FIX): FIXED, hardcoded expected
/// sizes for the 8 "newly created on graduation" accounts, live-measured on
/// the REAL Degen+XDEX bytes (`tests/degen-live.test.ts` DL5; re-confirmed
/// this session against `tests/fixtures/xdex-live.json`'s already-graduated
/// live pool, address `CAJeVEoSm1QQZccnCqYu9cnNF7TTD2fcUA3E5HQoxRvR`, and a
/// fresh LiteSVM graduation on the DL5 fixture). These are NOT read off the
/// CPI-created account at runtime (`degen_graduation_allowance` used to do
/// exactly that, which is Finding 1: any CPI-calling program can stamp
/// `owner == xdex::ID` on an account IT creates at whatever size it likes, up
/// to the SVM's own `MAX_PERMITTED_DATA_INCREASE` ceiling of 10,240 B — no
/// cooperation from the real XDEX program required — so trusting post-CPI
/// `data_len` let a compromised Degen inflate the graduation rent credit
/// ~24.6x, confirmed by the `tests/rogue-amm.test.ts` "R7" PoC).
///
/// pool_state (637 B) and observation_state (4075 B) are fixed-layout Anchor
/// accounts holding only config/pubkeys/a ring buffer — no field's size
/// depends on the traded pair, so every XDEX pool's pool_state/observation is
/// exactly this size (live-verified on the fixture pool above). lp_mint is
/// always a classic SPL Token mint (XDEX never uses Token-2022 for the LP
/// token), so it is always `spl_token::state::Mint::LEN` (82); the 3 LP-ATAs
/// are ATAs of that same fixed-format mint, always classic
/// `spl_token::state::Account::LEN` (165). vault0/vault1 hold the traded
/// mints themselves (WXNT is always the classic, extension-free native mint;
/// the meme side is whatever Degen's own bonding-curve factory mints, which
/// the DL5 live graduation measures at the base Token-2022 account size with
/// no account-mirrored extensions) — 165 is the smallest defensible value
/// per REVIEW-v0.3.1-R1.md's remediation and matches DL5 exactly.
///
/// Used as a CEILING via `data_len().min(expected)` (see
/// `degen_graduation_allowance`): an honest graduation's real `data_len`
/// equals this exactly, so honest rent is still credited in full; a
/// fabricated oversized fake account is capped at the honest size regardless
/// of how large the CPI target claims it made it; a fake account SMALLER
/// than the real size is credited at its own (smaller, non-exploitable) size.
const XDEX_POOL_STATE_LEN: usize = 637;
const XDEX_OBSERVATION_LEN: usize = 4_075;
const XDEX_LP_MINT_LEN: usize = 82;
const XDEX_LP_ATA_LEN: usize = 165;
const XDEX_VAULT_LEN: usize = 165;
/// Per-slot expected size, indexed by `i - DB_POOL_STATE` for `i` in
/// `DB_POOL_STATE..=DB_VAULT1` — order matches the DB_VAULT1 doc comment
/// above (pool_state, observation, lp_mint, 3 LP-ATAs, vault0, vault1).
const XDEX_GRAD_SLOT_LEN: [usize; 8] = [
    XDEX_POOL_STATE_LEN,
    XDEX_OBSERVATION_LEN,
    XDEX_LP_MINT_LEN,
    XDEX_LP_ATA_LEN,
    XDEX_LP_ATA_LEN,
    XDEX_LP_ATA_LEN,
    XDEX_VAULT_LEN,
    XDEX_VAULT_LEN,
];
/// R-1-R1 Finding 2 fix (v0.3.1-R1 verify2 review, "phantom-slot" / R7b):
/// `before[idx] == 0` only proves a slot was ABSENT before the CPI — it does
/// NOT prove the CPI actually created it. An account the CPI never touches
/// at all is *still* absent after the CPI too (0 lamports, 0 bytes, owner
/// still the System Program), so `XDEX_GRAD_SLOT_LEN`'s size cap alone lets
/// `data_len().min(cap)` collapse to 0 for a genuinely-untouched slot, and
/// `Rent::minimum_balance(0)` is a real, nonzero ≈890,880-lamport figure —
/// crediting 7 phantom accounts that were never created (`tests/rogue-amm.
/// test.ts` "R7b", ~6,236,160 lamports/graduation-labeled buy). The size cap
/// (ceiling) and this owner gate (floor/existence) are independent checks
/// that BOTH must pass before a slot's rent is credited — neither replaces
/// the other. Real XDEX graduation accounts are owned by `xdex::ID`
/// (pool_state/observation only) or the classic SPL Token program (lp_mint +
/// the 3 LP-ATAs — XDEX never uses Token-2022 for the LP token, see the doc
/// comment above). vault0/vault1 are NOT covered by this table — see
/// `is_token_program`-based check at the vault0/vault1 arm in
/// `degen_graduation_allowance`'s loop (R-1-R1 verify3 Finding 3 fix): a
/// real XDEX pool's token vaults are always SPL Token *accounts* (the Token
/// program must own them to move balances), classic Token or Token-2022
/// depending on which of the two traded mints' pubkeys sorts first — NEVER
/// `xdex::ID` (a pool vault's address happens to be a PDA derived under the
/// AMM program's seeds, which is a different concept from Solana account
/// *ownership*). Pinning vault0/vault1 to `xdex::ID` here previously meant
/// those two slots NEVER matched real bytes and silently contributed ZERO
/// credit on every honest graduation (non-exploitable — see R7c/R7d — but
/// semantically wrong and a latent false-negative risk if a future XDEX
/// version ever charges vault-creation rent to the signer). An untouched
/// slot stays System-Program-owned and fails either check, contributing
/// ZERO to the credit (skipped, not `Rent::minimum_balance(0)`). Order
/// matches `XDEX_GRAD_SLOT_LEN` above.
const XDEX_GRAD_SLOT_OWNER: [Pubkey; 6] = [
    xdex::ID,             // pool_state
    xdex::ID,              // observation_state
    anchor_spl::token::ID, // lp_mint
    anchor_spl::token::ID, // lp ATA 0
    anchor_spl::token::ID, // lp ATA 1
    anchor_spl::token::ID, // lp ATA 2
    // vault0 / vault1 intentionally NOT in this table — see doc comment
    // above and `is_token_program` check in `degen_graduation_allowance`.
];
/// Offset of cp-swap `AmmConfig.create_pool_fee` (u64 LE): 8 disc + bump(1) +
/// disable_create_pool(1) + index(u16=2) + trade_fee(8) + protocol_fee(8) +
/// fund_fee(8) = 36. Live-verified: `tests/degen-live.test.ts` DL5 /
/// `v0.3.1-review` RV-C2a (`amm_config.create_pool_fee(field @36)=100000000`).
const AMM_CONFIG_CREATE_POOL_FEE_OFF: usize = 36;
/// WP #7421 fix: `AmmConfig.protocol_owner` — the REAL recipient of the
/// pool-creation fee (`8` disc + `bump`(1) + `disable_create_pool`(1) +
/// `index`(u16=2) + `trade_fee`(8) + `protocol_fee`(8) + `fund_fee`(8) +
/// `create_pool_fee`(8) = 44; live-verified against
/// `tests/fixtures/degen-live.json`'s `curve.ammConfig` bytes, offset 44..76
/// decodes to EXACTLY `curve.createPoolFee` = `SKc6b6zAv2kkB9EtitjppbzPVR48bCMfRtE5B8KDuF1`,
/// the live account that actually receives the fee). `win[DB_CREATE_POOL_FEE]`
/// had NO address/ownership pin at all pre-fix — any account could occupy
/// that slot and its lamport delta would still be credited (capped only by
/// `create_pool_fee`, itself un-forgeable per the WP #7421 PoC's R8 result,
/// but the RECIPIENT was never checked — WP #7421's R8b PoC: a REAL,
/// unforged `amm_config` still let the full real `create_pool_fee` land in
/// an attacker-chosen wallet instead of `protocol_owner`, CONFIRMED
/// exploitable). Fix: only credit the fee term when
/// `win[DB_CREATE_POOL_FEE].key() == protocol_owner`; otherwise it
/// contributes ZERO (same graceful "skip, don't credit" pattern as the
/// owner gate on the other 8 graduation slots — an honest graduation always
/// pays the real `protocol_owner`, so this never under-credits real traffic).
const AMM_CONFIG_PROTOCOL_OWNER_OFF: usize = 44;

// Degen SELL window indices (per degen-pump-idl.json `sell`, 16 accounts).
const DS_SIGNER: usize = 0;
const DS_MINT: usize = 4;
const DS_WSOL_MINT: usize = 5;
const DS_TOKEN_STATE: usize = 6;
const DS_SIGNER_TOKEN: usize = 7; // signer meme Token-2022 ATA (INPUT)
const DS_SIGNER_WSOL: usize = 8; // signer WXNT ATA (unwrap conduit; CLOSED by sell)
const DS_TOKEN_PROG: usize = 12; // classic SPL token program
/// Writable indices for the sell CPI metas (per IDL isMut); signer = DS_SIGNER.
const DS_WRITABLE: [usize; 9] = [0, 1, 2, 3, 6, 7, 8, 9, 10];

/// SPL Token (classic) instruction tags used by the router's own wrap/unwrap.
const SPL_IX_CLOSE_ACCOUNT: u8 = 9;
const SPL_IX_SYNC_NATIVE: u8 = 17;

// `legacy_idl` opts back into Anchor's `anchor:idl` instruction so the on-chain
// IDL can be published (`anchor idl init`) after the v2 upgrade. Anchor 1.x made
// this opt-in; v1 shipped without it, which is why the deployed program has no
// on-chain IDL. This attribute is the only reason v2 can publish one.
#[program(legacy_idl)]
pub mod fortiblox_router {
    use super::*;

    /// v2 — execute a mixed route of XDEX cp-swap and Degen bonding-curve legs
    /// in ONE atomic instruction, then take the unbypassable protocol fee and
    /// enforce the user's net minimum receipt.
    ///
    /// `legs[i]` is the kind of hop i: `0`=XDEX, `1`=Degen buy, `2`=Degen sell.
    /// `remaining_accounts` is the concatenation of each leg's account window in
    /// order (XDEX=13, Degen buy=28, Degen sell=16). Hop 0 trades
    /// `initial_amount_in`; every later hop trades the full value it received.
    /// The XNT hub between a Degen leg (native) and an XDEX leg (WXNT) is bridged
    /// by the router itself (wrap/unwrap); a route that ends in native (Degen
    /// sell) is normalized to WXNT so the fee + min-out use the same proven path.
    /// `minimum_amount_out` is the floor on what the user keeps AFTER the fee —
    /// the ONLY slippage protection Degen legs have (they carry no pool min-out).
    ///
    /// v0.4.2 pause coverage (fixes the B-M2 bypass, security audit Medium
    /// finding): `fee_config` is a MANDATORY, FIXED 9th account (see
    /// `RouteV2`) — the pause gate (`require_not_paused`, `Paused` 6042) runs
    /// BEFORE the engine, unconditionally, for every caller. There is no wire
    /// shape that reaches the engine without it; a caller on the old 8-account
    /// wire gets Anchor `AccountNotEnoughKeys` (3005), never a silent
    /// uncovered swap. (v0.3.1 originally made this account an OPTIONAL
    /// trailing `remaining_account` for backward compatibility — that was the
    /// bypass: any caller that simply omitted it kept trading through a
    /// guardian pause. `route_v2_snipe` / `route_v2_delegated` / `route_v3`
    /// were unaffected — their `fee_config` was already mandatory.)
    pub fn route_v2<'info>(
        ctx: Context<'info, RouteV2<'info>>,
        legs: Vec<u8>,
        initial_amount_in: u64,
        minimum_amount_out: u64,
    ) -> Result<()> {
        require!(PROTOCOL_FEE_BPS <= MAX_FEE_BPS, RouterError::FeeConfig);
        require_not_paused(&ctx.accounts.fee_config.to_account_info())?; // v0.4.2 fix, mandatory here (was B-M2 optional tail)
        let rc = RouteCtx {
            user: ctx.accounts.user.to_account_info(),
            fee_destination: ctx.accounts.fee_destination.to_account_info(),
            fee_wallet: ctx.accounts.fee_wallet.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            token_program: ctx.accounts.token_program.to_account_info(),
        };
        let split = execute_route(&rc, ctx.remaining_accounts, &legs, initial_amount_in, minimum_amount_out, None)?;
        emit!(RouteExecuted {
            user: ctx.accounts.user.key(),
            hops: legs.len() as u8,
            amount_in: initial_amount_in,
            gross_out: split.gross,
            fee: split.fee,
            user_receives: split.user_receives,
        });
        Ok(())
    }

    /// v0.4.0 (OpenProject #7264) — `route_v2` + an INTEGRATOR FEE: the same
    /// engine (leg kinds, windows, exact carry, C-1 bounds, WXNT bridging),
    /// then TWO fee transfers out of the final output ATA, both signed by the
    /// user, atomically in this instruction:
    ///   1. the protocol fee — UNCHANGED: `ceil(gross × 25 bps)` on the GROSS
    ///      output to `ATA(out_mint, EeWE…)`; computed first and never reduced
    ///      by the integrator fee (the integrator fee is never carved out of it);
    ///   2. the integrator fee — `floor(gross × integrator_fee_bps)` on the same
    ///      gross, to `integrator_fee_destination`, which MUST equal
    ///      `ATA(out_mint, integrator_wallet, out_token_program)` (derived and
    ///      asserted — a caller cannot redirect it to a non-canonical account)
    ///      and MUST ALREADY EXIST (6046 `IntegratorFeeDestinationMissing`,
    ///      checked BEFORE any CPI): the integrator creates its own fee account
    ///      per mint (Jupiter standard); the router never creates it and the
    ///      user never pays a partner's rent. Owner + mint are read and pinned.
    /// `minimum_amount_out` is the floor on what the user keeps AFTER BOTH fees.
    /// `integrator_fee_bps` is `1..=MAX_INTEGRATOR_FEE_BPS` (300) — a
    /// compile-time cap, no governance surface; `0` is rejected (use `route_v2`).
    /// `integrator_wallet` may be any pubkey except the zero key (its ATA would
    /// be an unrecoverable sink); it may be the user or even the protocol fee
    /// wallet (harmless: the amount lands in that owner's own ATA).
    ///
    /// Fixed accounts: `route_v2`'s 8 + `fee_config` (MANDATORY pause coverage
    /// from the first tx — no optional tail on this ix) + the two integrator
    /// accounts; `remaining_accounts` = the leg windows EXACTLY (any trailing
    /// account is `BadAccountCount`). Gate order: pause → args → engine.
    /// Emits `RouteExecuted` (unchanged shape: `fee` = the protocol fee,
    /// `user_receives` = net after both fees, `gross_out − fee − integrator ==
    /// user_receives`) and `IntegratorFeePaid`.
    pub fn route_v3<'info>(
        ctx: Context<'info, RouteV3<'info>>,
        legs: Vec<u8>,
        initial_amount_in: u64,
        minimum_amount_out: u64,
        integrator_fee_bps: u16,
    ) -> Result<()> {
        require!(PROTOCOL_FEE_BPS <= MAX_FEE_BPS, RouterError::FeeConfig);
        require_not_paused(&ctx.accounts.fee_config.to_account_info())?; // B-M2, mandatory here
        require!(
            integrator_fee_bps >= 1 && integrator_fee_bps <= MAX_INTEGRATOR_FEE_BPS,
            RouterError::BadIntegratorFeeBps
        );
        require!(ctx.accounts.integrator_wallet.key() != Pubkey::default(), RouterError::InvalidIntegratorWallet);

        let rc = RouteCtx {
            user: ctx.accounts.user.to_account_info(),
            fee_destination: ctx.accounts.fee_destination.to_account_info(),
            fee_wallet: ctx.accounts.fee_wallet.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            token_program: ctx.accounts.token_program.to_account_info(),
        };
        let dest = ctx.accounts.integrator_fee_destination.to_account_info();
        let wallet = ctx.accounts.integrator_wallet.to_account_info();
        let sink = IntegratorSink { bps: integrator_fee_bps, destination: &dest, wallet: &wallet };
        let split = execute_route(&rc, ctx.remaining_accounts, &legs, initial_amount_in, minimum_amount_out, Some(&sink))?;
        emit!(RouteExecuted {
            user: ctx.accounts.user.key(),
            hops: legs.len() as u8,
            amount_in: initial_amount_in,
            gross_out: split.gross,
            fee: split.fee,
            user_receives: split.user_receives,
        });
        emit!(IntegratorFeePaid {
            user: ctx.accounts.user.key(),
            integrator_wallet: ctx.accounts.integrator_wallet.key(),
            integrator_fee_destination: ctx.accounts.integrator_fee_destination.key(),
            bps: integrator_fee_bps,
            amount: split.integrator_fee,
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // v0.3.0 — delegated + snipe variants (Forgejo fortiblox-app #450).
    // Both are ADDITIVE: `route_v2` (wire, accounts, fee path, event) is
    // untouched. Fee model identical: ceil(gross * 25 bps) taken BEFORE the
    // user's net min-out, to ATA(out_mint, FEE_WALLET) — unbypassable.
    // -----------------------------------------------------------------------

    /// v0.3.0 — execute an XDEX-only route ON BEHALF of `user`, signed by an
    /// SPL DELEGATE (`delegate_authority`) instead of the user — the
    /// copy-trade / automation surface (Honeybadger CopyTradeService).
    ///
    /// Why a vault (the fee-authority catch, #450 comment 2): a delegate only
    /// has authority over the user's INPUT ATA, never over the OUTPUT ATA, so
    /// the manual fee `TransferChecked` `route_v2` makes out of the user's
    /// output ATA cannot be signed by anyone in a delegated tx. Instead every
    /// hop's OUTPUT is the router's transient vault ATA for that mint
    /// (`ATA(mint, vault_authority)`); hop 0 is paid from `user_input_ata` with
    /// the delegate as the XDEX `payer` (live-verified: XDEX `swap_base_input`
    /// moves the input with `transfer_checked(authority = payer)` and has NO
    /// owner constraint on either token account — the SPL program accepts the
    /// delegate and debits `delegated_amount`); every later hop is paid from
    /// the previous hop's vault ATA with the PDA signing. At the end the PDA
    /// signs `fee` → pinned fee sink and `gross − fee` → the USER's canonical
    /// output ATA (`user_output_ata`, derived and asserted — the delegate
    /// cannot redirect proceeds), then the final vault MUST read 0
    /// (`VaultNotDrained`). Any balance that already sat in the final vault
    /// before the route (only possible via a third-party donation — the router
    /// never leaves value behind) is swept to the fee sink first, so a griefer
    /// cannot brick a mint by dusting its vault.
    ///
    /// Delegation proof (asserted BEFORE any CPI): `user_input_ata.owner ==
    /// user`, `user_input_ata.delegate == Some(delegate_authority)`,
    /// `delegated_amount >= initial_amount_in`. The delegate can therefore move
    /// at most what the user explicitly approved, and only INTO a swap whose
    /// output goes to the user; it can never receive value itself.
    ///
    /// Transfer-fee mints (Token-2022 `TransferFeeConfig`) are rejected as an
    /// output of ANY hop (`TransferFeeUnsupported`): the vault -> user forward
    /// would pay the mint's fee after the min-out check, crediting the user
    /// less than `user_receives` — use `route_v2` / `route_v2_snipe` for those.
    ///
    /// Scope: `legs` must be all-XDEX (`0`); Degen legs revert
    /// `DelegatedLegUnsupported` (a Degen leg debits NATIVE from its signer,
    /// which an SPL delegate cannot supply — supporting it would mean native
    /// custody in the PDA, a separate design). `legs` is kept on the wire so a
    /// future widening is wire-compatible. `remaining_accounts` = n × the
    /// 13-account XDEX window, with: slot 0 (payer) = `delegate_authority` for
    /// hop 0 / `vault_authority` for later hops; slot 4 (input) =
    /// `user_input_ata` for hop 0 / the previous hop's vault ATA; slot 5
    /// (output) = `ATA(out_mint, vault_authority, out_token_program)` — all
    /// derived and asserted by the router, and vault ATAs are created
    /// idempotently (`payer` funds rent) before the hop runs.
    ///
    /// `RouteExecuted.user` is the token-account OWNER (the follower), not the
    /// delegate; `DelegatedRouteExecuted` additionally records the delegate and
    /// payer.
    pub fn route_v2_delegated<'info>(
        ctx: Context<'info, RouteV2Delegated<'info>>,
        legs: Vec<u8>,
        initial_amount_in: u64,
        minimum_amount_out: u64,
    ) -> Result<()> {
        require!(PROTOCOL_FEE_BPS <= MAX_FEE_BPS, RouterError::FeeConfig);
        require_not_paused(&ctx.accounts.fee_config.to_account_info())?; // B-M2

        let user = ctx.accounts.user.key();
        let delegate = ctx.accounts.delegate_authority.key();
        let vault_auth = ctx.accounts.vault_authority.key();
        let n = legs.len();
        require!(n >= 1 && n <= MAX_HOPS, RouterError::BadHopCount);
        require!(initial_amount_in > 0, RouterError::ZeroAmountIn);
        require!(legs.iter().all(|&k| k == LEG_XDEX), RouterError::DelegatedLegUnsupported);

        let accs = ctx.remaining_accounts;
        let expected_len = n.checked_mul(XDEX_ACCTS).ok_or(RouterError::MathOverflow)?;
        require!(accs.len() == expected_len, RouterError::BadAccountCount);

        // --- Delegation proof on the user's input ATA (the fixed account; hop 0
        //     is required to spend exactly this account). ---------------------
        let user_input_ata = ctx.accounts.user_input_ata.to_account_info();
        require_keys_eq!(read_token_owner(&user_input_ata)?, user, RouterError::AtaNotUser);
        check_delegation(read_token_delegate(&user_input_ata)?, &delegate, initial_amount_in)?;

        let bump = ctx.bumps.vault_authority;
        let vault_seeds: &[&[u8]] = &[VAULT_AUTHORITY_SEED, &[bump]];
        let vault_auth_ai = ctx.accounts.vault_authority.to_account_info();
        let payer_ai = ctx.accounts.payer.to_account_info();
        let system_ai = ctx.accounts.system_program.to_account_info();

        // Final output = the last hop's vault ATA. Snapshot its pre-route
        // balance (0 if it does not exist yet) so `gross` is the route's own
        // delta and any pre-existing (donated) balance is identified for sweep.
        let last = (n - 1) * XDEX_ACCTS;
        let final_vault = &accs[last + IDX_OUTPUT_ATA];
        let before_final: u64 = read_token_amount_or_zero(final_vault)?;

        // Carry between hops: (vault ATA key, EXACT amount the hop produced).
        let mut carry: Option<(Pubkey, u64)> = None;
        for i in 0..n {
            let win = &accs[i * XDEX_ACCTS..(i + 1) * XDEX_ACCTS];
            let payer = &win[IDX_PAYER];
            let pool_state = &win[IDX_POOL_STATE];
            let input_ata = &win[IDX_INPUT_ATA];
            let output_ata = &win[IDX_OUTPUT_ATA];
            let input_mint = &win[IDX_INPUT_MINT];
            let output_mint = &win[IDX_OUTPUT_MINT];
            let in_tp = &win[IDX_INPUT_TOKEN_PROGRAM];
            let out_tp = &win[IDX_OUTPUT_TOKEN_PROGRAM];

            require_keys_eq!(*pool_state.owner, xdex::ID, RouterError::PoolNotXdex);
            require!(is_token_program(&in_tp.key()), RouterError::BadTokenProgram);
            require!(is_token_program(&out_tp.key()), RouterError::BadTokenProgram);
            require!(is_mint_account(input_mint)?, RouterError::NotAMint);
            require!(is_mint_account(output_mint)?, RouterError::NotAMint);
            // M-1 (v0.3.0 review): every hop's output transits a vault and is
            // forwarded by a SECOND Token-2022 transfer (vault -> next hop, or
            // vault -> user). A TransferFeeConfig mint withholds its fee on that
            // leg after our accounting, so the user would be credited less than
            // `user_receives` / `minimum_amount_out`. Fail closed on this path.
            require!(
                !mint_has_extension(output_mint, EXT_TRANSFER_FEE_CONFIG)?,
                RouterError::TransferFeeUnsupported
            );
            // A-5 (v0.3.1): a TransferHook output mint is rejected BEFORE any
            // CPI on every hop (v0.3.0 checked only the final mint, after the
            // swaps had run — fail-closed either way, but wasted CU).
            require!(
                !mint_has_extension(output_mint, EXT_TRANSFER_HOOK)?,
                RouterError::TransferHookUnsupported
            );

            // Hop authority + input: hop 0 = delegate over the user's input ATA;
            // later hops = the vault PDA over the previous hop's vault ATA.
            let amount_in = match &carry {
                None => {
                    require_keys_eq!(payer.key(), delegate, RouterError::BadHopAuthority);
                    require_keys_eq!(input_ata.key(), user_input_ata.key(), RouterError::BrokenRoute);
                    initial_amount_in
                }
                Some((prev_vault, produced)) => {
                    require_keys_eq!(payer.key(), vault_auth, RouterError::BadHopAuthority);
                    require_keys_eq!(input_ata.key(), *prev_vault, RouterError::BrokenRoute);
                    *produced // exact prior-hop output; any idle vault balance is untouched
                }
            };
            require!(amount_in > 0, RouterError::ZeroAmountIn);
            require_keys_eq!(read_token_mint(input_ata)?, input_mint.key(), RouterError::MintMismatch);

            // Output MUST be the router's vault ATA for this hop's output mint
            // (derived, never trusted) — created idempotently, payer funds rent.
            let expected_vault = get_associated_token_address_with_program_id(
                &vault_auth, &output_mint.key(), &out_tp.key(),
            );
            require_keys_eq!(output_ata.key(), expected_vault, RouterError::WrongVaultAta);
            create_ata_idempotent(&payer_ai, output_ata, &vault_auth_ai, output_mint, &system_ai, out_tp)?;
            require_keys_eq!(read_token_owner(output_ata)?, vault_auth, RouterError::WrongVaultAta);
            require_keys_eq!(read_token_mint(output_ata)?, output_mint.key(), RouterError::MintMismatch);

            let before_out = read_token_amount(output_ata)?;
            let before_in = read_token_amount(input_ata)?;
            if i == 0 {
                exec_xdex_swap_signed(win, amount_in, &[])?; // delegate is an outer-tx signer
            } else {
                exec_xdex_swap_signed(win, amount_in, &[vault_seeds])?; // PDA signs
            }
            require_exact_debit(input_ata, before_in, amount_in)?; // C-1
            let after_out = read_token_amount(output_ata)?;
            let produced = after_out.checked_sub(before_out).ok_or(RouterError::NoNetOutput)?;
            carry = Some((output_ata.key(), produced));
        }

        let out_mint = &accs[last + IDX_OUTPUT_MINT];
        let out_tp = &accs[last + IDX_OUTPUT_TOKEN_PROGRAM];
        let gross = read_token_amount(final_vault)?
            .checked_sub(before_final)
            .ok_or(RouterError::NoNetOutput)?;

        let (fee, user_receives) = take_fee_from_vault_and_forward(
            VaultSink {
                vault: final_vault,
                vault_authority: &vault_auth_ai,
                vault_seeds,
                payer: &payer_ai,
                user: &ctx.accounts.user.to_account_info(),
                user_output_ata: &ctx.accounts.user_output_ata.to_account_info(),
                fee_destination: &ctx.accounts.fee_destination.to_account_info(),
                fee_wallet: &ctx.accounts.fee_wallet.to_account_info(),
                system_program: &system_ai,
            },
            out_mint,
            out_tp,
            gross,
            minimum_amount_out,
            before_final,
        )?;

        emit!(RouteExecuted {
            user,
            hops: n as u8,
            amount_in: initial_amount_in,
            gross_out: gross,
            fee,
            user_receives,
        });
        emit!(DelegatedRouteExecuted {
            user,
            delegate,
            payer: ctx.accounts.payer.key(),
            input_mint: accs[IDX_INPUT_MINT].key(),
            output_mint: out_mint.key(),
        });
        Ok(())
    }

    /// v0.3.0 — ONE XDEX `swap_base_input` hop with a FIXED account list (no
    /// leg partition, no Degen / WXNT plumbing, no `remaining_accounts`), for
    /// same-slot sniper races where every account and CU counts. The user is
    /// the signer and swap authority exactly as in `route_v2`; the fee path is
    /// `route_v2`'s shared helper byte-for-byte (fee BEFORE min-out, pinned
    /// sink, hook-reject, idempotent fee-ATA create — the user funds it,
    /// which a fresh-launch sniper needs since the fee ATA for a new mint will
    /// not exist yet). `user_output_ata` must pre-exist (no create here).
    /// XDEX requires `observation_state` (live-verified: omitting it is Anchor
    /// 3005, substituting it is 2012), so the 13-account cp-swap window is the
    /// floor; this variant removes only the router's own overhead (18 accounts
    /// vs `route_v2`'s 21 metas for one hop). Emits `RouteExecuted{hops:1}`.
    pub fn route_v2_snipe(
        ctx: Context<RouteV2Snipe>,
        amount_in: u64,
        minimum_amount_out: u64,
    ) -> Result<()> {
        require!(PROTOCOL_FEE_BPS <= MAX_FEE_BPS, RouterError::FeeConfig);
        require_not_paused(&ctx.accounts.fee_config.to_account_info())?; // B-M2
        require!(amount_in > 0, RouterError::ZeroAmountIn);
        let a = &ctx.accounts;
        let user = a.user.key();

        require_keys_eq!(*a.pool_state.owner, xdex::ID, RouterError::PoolNotXdex);
        require!(is_token_program(&a.input_token_program.key()), RouterError::BadTokenProgram);
        require!(is_token_program(&a.output_token_program.key()), RouterError::BadTokenProgram);
        require!(is_mint_account(&a.input_mint)?, RouterError::NotAMint);
        require!(is_mint_account(&a.output_mint)?, RouterError::NotAMint);
        require_keys_eq!(read_token_owner(&a.user_input_ata)?, user, RouterError::AtaNotUser);
        require_keys_eq!(read_token_owner(&a.user_output_ata)?, user, RouterError::AtaNotUser);
        require_keys_eq!(read_token_mint(&a.user_input_ata)?, a.input_mint.key(), RouterError::MintMismatch);
        require_keys_eq!(read_token_mint(&a.user_output_ata)?, a.output_mint.key(), RouterError::MintMismatch);

        // The 13-account cp-swap window in XDEX's exact order (same table as a
        // `route_v2` XDEX leg; user = payer at index 0).
        let win: [AccountInfo<'_>; ACCOUNTS_PER_HOP] = [
            a.user.to_account_info(),
            a.authority.to_account_info(),
            a.amm_config.to_account_info(),
            a.pool_state.to_account_info(),
            a.user_input_ata.to_account_info(),
            a.user_output_ata.to_account_info(),
            a.input_vault.to_account_info(),
            a.output_vault.to_account_info(),
            a.input_token_program.to_account_info(),
            a.output_token_program.to_account_info(),
            a.input_mint.to_account_info(),
            a.output_mint.to_account_info(),
            a.observation_state.to_account_info(),
        ];
        let before = read_token_amount(&win[IDX_OUTPUT_ATA])?;
        let before_in = read_token_amount(&win[IDX_INPUT_ATA])?;
        exec_xdex_swap_signed(&win, amount_in, &[])?;
        require_exact_debit(&win[IDX_INPUT_ATA], before_in, amount_in)?; // C-1
        let gross = read_token_amount(&win[IDX_OUTPUT_ATA])?
            .checked_sub(before)
            .ok_or(RouterError::NoNetOutput)?;

        let user_ai = a.user.to_account_info();
        let split = take_fee_and_enforce_min_out(
            FeeSink {
                user: &user_ai,
                fee_destination: &a.fee_destination.to_account_info(),
                fee_wallet: &a.fee_wallet.to_account_info(),
                system_program: &a.system_program.to_account_info(),
            },
            &win[IDX_OUTPUT_ATA],
            &win[IDX_OUTPUT_MINT],
            &win[IDX_OUTPUT_TOKEN_PROGRAM],
            gross,
            minimum_amount_out,
            None,
        )?;

        emit!(RouteExecuted { user, hops: 1, amount_in, gross_out: gross, fee: split.fee, user_receives: split.user_receives });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // B3 — on-chain version marker.
    // -----------------------------------------------------------------------

    /// Read-only, account-less no-op that logs and returns (as return data)
    /// the program's semantic version — ground truth for explorers, auditors and
    /// the keeper's "program version changed" hook. Zero cost on the hot path.
    pub fn version(_ctx: Context<Version>) -> Result<()> {
        msg!("fortiblox-router v{}", ROUTER_VERSION);
        anchor_lang::solana_program::program::set_return_data(ROUTER_VERSION.as_bytes());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // B2 — FeeConfig v1 (tier-ladder forward-compatible, DORMANT).
    //
    // The ratified FORTI fee ladder is 25 bps base / 15 bps sFORTI-holder /
    // 5 bps veFORTI-locked. Tier ENFORCEMENT is a future upgrade (`route_tiered`
    // — the sFORTI/veFORTI programs it must read do not exist yet); this bundle
    // ships the config account so that upgrade is code-only — never a config
    // migration. `route_v2` does NOT read this account; `PROTOCOL_FEE_BPS` (25)
    // stays the live rate and must equal `tier_bps[0]` (unit-asserted).
    // -----------------------------------------------------------------------

    /// One-time creation of the single global `fee_config` PDA.
    ///
    /// GATED to the program's UPGRADE AUTHORITY (CC-1 pattern): `program` pins
    /// this program, `program_data` must be its ProgramData and its
    /// `upgrade_authority_address` must be the `payer` signer — so nobody can
    /// front-run the deploy-to-init window and squat the PDA / set a rogue
    /// `authority`. Re-init is impossible (Anchor `init` reverts if the PDA
    /// exists). Writes the IMMUTABLE ladder `tier_bps = [25,15,5]` (asserted,
    /// never a parameter; NO instruction can ever mutate it), `streak_n`, the
    /// floored thresholds, the governance `authority` (the multisig), and
    /// `version = 1`. The writer-side identity (`forti_mint`/`sforti_mint`/
    /// `sforti_program`/`ve_program`) is left ZERO: those programs are not
    /// deployed yet and are written once, later, by `finalize_tier_writers`.
    pub fn init_fee_config(
        ctx: Context<InitFeeConfig>,
        authority: Pubkey,
        holder_threshold: u64,
        locker_threshold: u64,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let cfg = &mut ctx.accounts.fee_config;

        // The ratified, immutable ladder — asserted at init, never a param.
        let tier_bps = RATIFIED_TIER_BPS;
        require!(FeeConfig::tier_bps_ok(&tier_bps), RouterError::InvalidTierBps);
        // Code/config drift guard: the live const IS the base tier.
        require!(PROTOCOL_FEE_BPS == tier_bps[0] as u64, RouterError::InvalidTierBps);
        // Thresholds start at/above the compile-time floors (spec §4.3).
        require!(holder_threshold >= MIN_HOLDER_THRESHOLD, RouterError::ThresholdTooLow);
        require!(locker_threshold >= MIN_LOCKER_THRESHOLD, RouterError::ThresholdTooLow);
        require!(authority != Pubkey::default(), RouterError::InvalidAuthority);

        cfg.version = FEE_CONFIG_VERSION_INIT;
        cfg.bump = ctx.bumps.fee_config;
        cfg.forti_mint = Pubkey::default();
        cfg.sforti_mint = Pubkey::default();
        cfg.sforti_program = Pubkey::default();
        cfg.ve_program = Pubkey::default();
        cfg.tier_bps = tier_bps;
        cfg.streak_n = STREAK_N;
        cfg.holder_threshold = holder_threshold;
        cfg.locker_threshold = locker_threshold;
        cfg.authority = authority;
        cfg.last_change_ts = now;
        cfg.pending_holder = 0;
        cfg.pending_locker = 0;
        cfg.pending_effective_ts = 0;
        cfg.paused = 0;
        cfg.guardian = Pubkey::default();
        cfg.reserved = [0u8; FEE_CONFIG_RESERVED];

        emit!(FeeConfigInitialized { authority, holder_threshold, locker_threshold, tier_bps });
        Ok(())
    }

    /// Deferred WRITE-ONCE of the tier writer-side identity. Authority-gated and
    /// valid ONLY while `version == 1` AND all four identity fields are zero;
    /// writes them and bumps `version = 2`, after which NO mutation path exists
    /// (spec R4: a repointable mint/program under a captured authority would pass
    /// every downstream holder/locker check — so this is one-shot by design).
    pub fn finalize_tier_writers(
        ctx: Context<FinalizeTierWriters>,
        forti_mint: Pubkey,
        sforti_mint: Pubkey,
        sforti_program: Pubkey,
        ve_program: Pubkey,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.fee_config;
        require_keys_eq!(ctx.accounts.authority.key(), cfg.authority, RouterError::Unauthorized);
        require!(cfg.version == FEE_CONFIG_VERSION_INIT, RouterError::AlreadyFinalized);
        require!(
            cfg.forti_mint == Pubkey::default()
                && cfg.sforti_mint == Pubkey::default()
                && cfg.sforti_program == Pubkey::default()
                && cfg.ve_program == Pubkey::default(),
            RouterError::AlreadyFinalized
        );
        // Sanity on the write-once values: all non-zero, mints distinct, programs
        // distinct (cheap guards against an obviously mis-built finalize tx; the
        // real proof-layout pinning is the tier upgrade's job).
        require!(
            forti_mint != Pubkey::default()
                && sforti_mint != Pubkey::default()
                && sforti_program != Pubkey::default()
                && ve_program != Pubkey::default(),
            RouterError::InvalidIdentity
        );
        require!(forti_mint != sforti_mint, RouterError::InvalidIdentity);
        require!(sforti_program != ve_program, RouterError::InvalidIdentity);

        cfg.forti_mint = forti_mint;
        cfg.sforti_mint = sforti_mint;
        cfg.sforti_program = sforti_program;
        cfg.ve_program = ve_program;
        cfg.version = FEE_CONFIG_VERSION_FINAL;

        emit!(TierWritersFinalized { forti_mint, sforti_mint, sforti_program, ve_program });
        Ok(())
    }

    /// Step 1 of the bounded threshold tuning (spec §4.3, Surface 6.3). Only the
    /// governance `authority` may propose; new values must clear the compile-time
    /// FLOORS (governance can never dust the thresholds to make 15/5 universal);
    /// a RATE-LIMIT (since the last committed change) bounds frequency; the
    /// staged change carries a TIMELOCK the commit must wait out. `tier_bps` and
    /// the identity block have NO propose/commit path.
    pub fn propose_threshold_change(
        ctx: Context<ProposeThresholdChange>,
        new_holder: u64,
        new_locker: u64,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let cfg = &mut ctx.accounts.fee_config;
        require_keys_eq!(ctx.accounts.authority.key(), cfg.authority, RouterError::Unauthorized);
        require!(new_holder >= MIN_HOLDER_THRESHOLD, RouterError::ThresholdTooLow);
        require!(new_locker >= MIN_LOCKER_THRESHOLD, RouterError::ThresholdTooLow);
        require!(
            now.checked_sub(cfg.last_change_ts).ok_or(RouterError::MathOverflow)?
                >= MIN_CHANGE_INTERVAL_SECS,
            RouterError::RateLimited
        );
        cfg.pending_holder = new_holder;
        cfg.pending_locker = new_locker;
        cfg.pending_effective_ts =
            now.checked_add(THRESHOLD_TIMELOCK_SECS).ok_or(RouterError::MathOverflow)?;
        emit!(ThresholdChangeProposed {
            new_holder,
            new_locker,
            effective_ts: cfg.pending_effective_ts,
        });
        Ok(())
    }

    /// Step 2 of the bounded threshold tuning. PERMISSIONLESS crank once the
    /// timelock has elapsed — it can only apply an already-staged, already-
    /// floored, already-rate-limited change.
    pub fn commit_threshold_change(ctx: Context<CommitThresholdChange>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let cfg = &mut ctx.accounts.fee_config;
        require!(cfg.pending_effective_ts != 0, RouterError::NoPendingChange);
        require!(now >= cfg.pending_effective_ts, RouterError::TimelockNotElapsed);
        let (holder_threshold, locker_threshold) = (cfg.pending_holder, cfg.pending_locker);
        cfg.holder_threshold = holder_threshold;
        cfg.locker_threshold = locker_threshold;
        cfg.last_change_ts = now;
        cfg.pending_holder = 0;
        cfg.pending_locker = 0;
        cfg.pending_effective_ts = 0;
        emit!(ThresholdChangeCommitted { holder_threshold, locker_threshold });
        Ok(())
    }

    /// Hand the `fee_config` governance `authority` to a new key (e.g. multisig →
    /// governance-execute PDA at activation). CURRENT-authority-gated; the sole
    /// mutator of `authority`. Plain reassignment (no timelock): the tunable
    /// thresholds stay floored + rate-limited + timelocked regardless of who
    /// holds the keys, and the immutable block is untouched.
    pub fn migrate_fee_authority(
        ctx: Context<MigrateFeeAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.fee_config;
        require_keys_eq!(ctx.accounts.authority.key(), cfg.authority, RouterError::Unauthorized);
        require!(new_authority != Pubkey::default(), RouterError::InvalidAuthority);
        let old_authority = cfg.authority;
        cfg.authority = new_authority;
        emit!(FeeAuthorityMigrated { old_authority, new_authority });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // v0.3.1 (audit B-M2) — pause switch governance.
    // -----------------------------------------------------------------------

    /// Flip `FeeConfig.paused`. PAUSE (`true`) may be signed by the `guardian`
    /// (a low-privilege incident key — fast, no multisig round-trip) OR by the
    /// governance `authority`; UNPAUSE (`false`) ONLY by the `authority`.
    /// Anyone else → `Unauthorized` (6022). While paused, every route entrypoint
    /// that carries the `fee_config` account reverts `Paused` (6042) before any
    /// CPI; governance writes are never blocked by the pause. A pause does NOT
    /// protect against a compromised UPGRADE authority (it can upgrade the flag
    /// away) — that threat is only closed by moving the upgrade authority to
    /// the multisig (plan §5).
    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        let cfg = &mut ctx.accounts.fee_config;
        let by = ctx.accounts.signer.key();
        let is_authority = by == cfg.authority;
        let is_guardian = cfg.guardian != Pubkey::default() && by == cfg.guardian;
        if paused {
            require!(is_authority || is_guardian, RouterError::Unauthorized);
        } else {
            require!(is_authority, RouterError::Unauthorized);
        }
        cfg.paused = paused as u8;
        emit!(PauseSet { paused, by });
        Ok(())
    }

    /// Set (or clear, with `Pubkey::default()`) the `guardian` that may PAUSE.
    /// Authority-gated; the guardian can never unpause, migrate the authority,
    /// or touch any other field.
    pub fn set_guardian(ctx: Context<SetGuardian>, guardian: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.fee_config;
        require_keys_eq!(ctx.accounts.authority.key(), cfg.authority, RouterError::Unauthorized);
        let old_guardian = cfg.guardian;
        cfg.guardian = guardian;
        emit!(GuardianSet { old_guardian, new_guardian: guardian });
        Ok(())
    }
}

/// Value carried from one hop to the next.
enum Carry {
    /// A token account (XDEX/Degen-buy output, or wrapped WXNT). `amount` is the
    /// EXACT value this hop produced (measured as the output-ATA delta), so the
    /// next hop chains only the route's value — never a pre-existing idle balance
    /// the user left in the ATA (M1). `mint` enforces the WXNT medium at a
    /// Degen-buy boundary.
    Token { key: Pubkey, mint: Pubkey, amount: u64 },
    /// Native XNT lamports (a Degen sell's net proceeds), measured exactly.
    Native(u64),
}
/// Which remaining-account slots describe the route's final token output.
struct FinalOut {
    ata_ix: usize,
    mint_ix: usize,
    tp_ix: usize,
    gross: u64,
}

/// The accounts every user-signed route engine call needs (v0.4.0: lifted out
/// of `Context<RouteV2>` so `route_v2` and `route_v3` share ONE engine — the
/// same partition, carry, C-1 bounds and WXNT bridging code, byte-for-byte).
struct RouteCtx<'info> {
    /// Route authority + rent payer; signs every fee `TransferChecked`.
    user: AccountInfo<'info>,
    fee_destination: AccountInfo<'info>,
    fee_wallet: AccountInfo<'info>,
    system_program: AccountInfo<'info>,
    /// Classic SPL Token (WXNT wrap/unwrap/sync/close).
    token_program: AccountInfo<'info>,
}

/// v0.4.0 — the integrator (third-party dApp) fee sink of `route_v3`.
struct IntegratorSink<'a, 'info> {
    /// `1..=MAX_INTEGRATOR_FEE_BPS`, asserted by the handler before the engine runs.
    bps: u16,
    /// Must equal `ATA(out_mint, wallet, out_token_program)` (asserted in the fee path).
    destination: &'a AccountInfo<'info>,
    /// The integrator's wallet (any pubkey but the zero key); the ATA owner.
    wallet: &'a AccountInfo<'info>,
}

/// All three fee-path amounts of one route (v0.4.0). `integrator_fee` is 0 for
/// `route_v2` / `route_v2_snipe` (no integrator sink).
struct FeeSplit {
    gross: u64,
    fee: u64,
    integrator_fee: u64,
    user_receives: u64,
}

/// THE route engine shared by `route_v2` and `route_v3` (v0.4.0). Executes the
/// leg list against `accs` (the instruction's remaining accounts), then runs
/// the fee + net min-out path with an optional integrator sink, and returns
/// the amounts for the caller's event. As of v0.4.2 `fee_config` is a
/// mandatory FIXED account on BOTH callers (gated by each caller before this
/// runs), so `remaining_accounts` must partition EXACTLY for both — there is
/// no optional trailing account any more (removed: the v0.3.1 B-M2 bypass).
fn execute_route<'info>(
    rc: &RouteCtx<'info>,
    accs: &[AccountInfo<'info>],
    legs: &[u8],
    initial_amount_in: u64,
    minimum_amount_out: u64,
    integrator: Option<&IntegratorSink<'_, 'info>>,
) -> Result<FeeSplit> {
    let user = rc.user.key();
    let n = legs.len();
    require!(n >= 1 && n <= MAX_HOPS, RouterError::BadHopCount);
    require!(initial_amount_in > 0, RouterError::ZeroAmountIn);

    
    // --- Partition remaining_accounts into per-leg windows by declared kind.
    //     A mismatch (wrong total, unknown kind) reverts before any CPI, so a
    //     caller can never smuggle a Degen window into an XDEX slot or vice
    //     versa — the kind drives BOTH the window size AND the dispatch. -----
    let mut spans: Vec<(u8, usize, usize)> = Vec::with_capacity(n);
    let mut off: usize = 0;
    for &kind in legs.iter() {
        let len = match kind {
            LEG_XDEX => XDEX_ACCTS,
            LEG_DEGEN_BUY => DEGEN_BUY_ACCTS,
            LEG_DEGEN_SELL => DEGEN_SELL_ACCTS,
            _ => return err!(RouterError::BadLegKind),
        };
        let end = off.checked_add(len).ok_or(RouterError::MathOverflow)?;
        require!(end <= accs.len(), RouterError::BadAccountCount);
        spans.push((kind, off, len));
        off = end;
    }
    // v0.4.2: `fee_config` is a mandatory FIXED account on both `route_v2`
    // and `route_v3` (each caller gates it BEFORE calling in), so
    // `remaining_accounts` must partition EXACTLY — no trailing account of
    // any kind (this removes the v0.3.1 B-M2 optional-tail bypass surface).
    require!(accs.len() == off, RouterError::BadAccountCount);

    // v0.4.0 (review follow-up): the integrator sink must ALREADY EXIST as the
    // canonical ATA of the final output mint BEFORE any CPI — the standard
    // (Jupiter: the referral/platform-fee token account is created by the
    // integrator; end users never pay rent for a partner's fee account).
    // The final mint / token program are known from the last leg's window.
    if let Some(i) = integrator {
        let (last_kind, last_start, _) = spans[n - 1];
        let (mint_ix, tp_ix) = match last_kind {
            LEG_XDEX => (last_start + IDX_OUTPUT_MINT, last_start + IDX_OUTPUT_TOKEN_PROGRAM),
            LEG_DEGEN_BUY => (last_start + DB_MINT, last_start + DB_TOKEN_2022_PROG),
            _ => (last_start + DS_WSOL_MINT, last_start + DS_TOKEN_PROG),
        };
        require_integrator_destination(i, &accs[mint_ix], &accs[tp_ix])?;
    }

    // Capture the whole-route "before" balance of the FINAL output token
    // account (XDEX/buy terminal) so a round trip measures the NET delta
    // (v1's M1 semantics). A sell-terminal route ends in native and is
    // measured locally (net_refund) then normalized to WXNT.
    let (last_kind, last_start, _last_len) = spans[n - 1];
    let before_final_token: u64 = match last_kind {
        LEG_XDEX => read_token_amount(&accs[last_start + IDX_OUTPUT_ATA])?,
        LEG_DEGEN_BUY => read_token_amount_or_zero(&accs[last_start + DB_SIGNER_TOKEN])?,
        _ => 0,
    };

    // Carry medium threaded between hops.
    let mut carry: Option<Carry> = None;
    // Final descriptor (filled by the last leg): the token account/mint/prog
    // whose delta is the route's gross output, plus the gross itself.
    let mut fin: Option<FinalOut> = None;

    for (i, &(kind, start, len)) in spans.iter().enumerate() {
        let win = &accs[start..start + len];
        let is_last = i == n - 1;

        match kind {
            LEG_XDEX => {
                let payer = &win[IDX_PAYER];
                let pool_state = &win[IDX_POOL_STATE];
                let input_ata = &win[IDX_INPUT_ATA];
                let output_ata = &win[IDX_OUTPUT_ATA];
                let input_mint = &win[IDX_INPUT_MINT];
                let output_mint = &win[IDX_OUTPUT_MINT];
                let in_tp = &win[IDX_INPUT_TOKEN_PROGRAM];
                let out_tp = &win[IDX_OUTPUT_TOKEN_PROGRAM];

                require_keys_eq!(payer.key(), user, RouterError::AuthorityNotUser);
                require!(payer.is_signer, RouterError::AuthorityNotSigner);
                require_keys_eq!(*pool_state.owner, xdex::ID, RouterError::PoolNotXdex);
                require_keys_eq!(read_token_owner(input_ata)?, user, RouterError::AtaNotUser);
                require_keys_eq!(read_token_owner(output_ata)?, user, RouterError::AtaNotUser);
                require!(is_token_program(&in_tp.key()), RouterError::BadTokenProgram);
                require!(is_token_program(&out_tp.key()), RouterError::BadTokenProgram);
                require!(is_mint_account(input_mint)?, RouterError::NotAMint);
                require!(is_mint_account(output_mint)?, RouterError::NotAMint);
                require_keys_eq!(read_token_mint(input_ata)?, input_mint.key(), RouterError::MintMismatch);
                require_keys_eq!(read_token_mint(output_ata)?, output_mint.key(), RouterError::MintMismatch);

                // Snapshot the output ATA so we chain the EXACT value this hop
                // produces, not any idle balance the user already left there.
                let before_out = read_token_amount(output_ata)?;

                // Establish this hop's input amount from the carried medium.
                let amount_in = match &carry {
                    None => initial_amount_in, // hop 0: client pre-funded input_ata
                    Some(Carry::Token { key, amount, .. }) => {
                        require_keys_eq!(input_ata.key(), *key, RouterError::BrokenRoute);
                        *amount // exact prior-hop output; leaves any idle balance untouched
                    }
                    Some(Carry::Native(nr)) => {
                        // Native (from a Degen sell) → this XDEX hop needs WXNT.
                        // Wrap exactly `nr` into input_ata (must be the user's
                        // WXNT ATA), which the sell closed → recreate first.
                        require_keys_eq!(input_mint.key(), wxnt::ID, RouterError::ExpectedWxntInput);
                        require!(in_tp.key() == anchor_spl::token::ID, RouterError::BadTokenProgram);
                        ensure_wxnt_ata(rc, input_ata, input_mint)?;
                        wrap_native_to_wxnt(rc, input_ata, *nr)?;
                        *nr
                    }
                };
                require!(amount_in > 0, RouterError::ZeroAmountIn);

                let before_in = read_token_amount(input_ata)?;
                exec_xdex_swap(win, amount_in)?;
                require_exact_debit(input_ata, before_in, amount_in)?; // C-1
                let after_out = read_token_amount(output_ata)?;
                let produced = after_out.checked_sub(before_out).ok_or(RouterError::NoNetOutput)?;
                carry = Some(Carry::Token {
                    key: output_ata.key(),
                    mint: output_mint.key(),
                    amount: produced,
                });
                if is_last {
                    let gross = after_out.checked_sub(before_final_token).ok_or(RouterError::NoNetOutput)?;
                    fin = Some(FinalOut { ata_ix: last_start + IDX_OUTPUT_ATA, mint_ix: last_start + IDX_OUTPUT_MINT, tp_ix: last_start + IDX_OUTPUT_TOKEN_PROGRAM, gross });
                }
            }

            LEG_DEGEN_BUY => {
                let signer = &win[DB_SIGNER];
                let token_state = &win[DB_TOKEN_STATE];
                let out_meme = &win[DB_SIGNER_TOKEN];
                let wsol_ata = &win[DB_SIGNER_WSOL];
                require_keys_eq!(signer.key(), user, RouterError::AuthorityNotUser);
                require!(signer.is_signer, RouterError::AuthorityNotSigner);
                require_keys_eq!(*token_state.owner, degen::ID, RouterError::NotDegenAccount);

                // Native amount into the curve, from the carried medium.
                let amount = match &carry {
                    None => initial_amount_in, // hop 0: user pays native (amount + 1% + rents)
                    Some(Carry::Native(nr)) => derive_buy_amount(*nr)?,
                    Some(Carry::Token { key, mint, amount }) => {
                        // WXNT (from an XDEX hop) → unwrap to native, then buy.
                        // Budget is the EXACT carried amount (not the ATA's full
                        // balance) so idle WXNT isn't swept into the buy (M1).
                        require_keys_eq!(*mint, wxnt::ID, RouterError::ExpectedWxntInput);
                        require_keys_eq!(wsol_ata.key(), *key, RouterError::BrokenRoute);
                        unwrap_wxnt_to_native(rc, wsol_ata)?;
                        derive_buy_amount(*amount)?
                    }
                };
                require!(amount > 0, RouterError::ZeroAmountIn);

                let before_meme = read_token_amount_or_zero(out_meme)?;
                // C-1 (buy): snapshot the signer's native balance and the
                // lamports of the two ATAs the buy may (re)create, so the
                // debit can be bounded to amount + fee + rent actually paid.
                let l0 = rc.user.lamports();
                let meme_l0 = out_meme.lamports();
                let wsol_l0 = wsol_ata.lamports();
                // R-1 (v0.3.1): snapshot the graduation-cost accounts
                // BEFORE the CPI too — a buy that fills the curve creates
                // the XDEX pool inside this same call, and the allowance
                // below needs "did this account exist before" to tell a
                // real graduation from a pre-existing pool.
                let pool_existed_before = win[DB_POOL_STATE].lamports() > 0;
                let grad_lamports_before: Vec<u64> = (DB_POOL_STATE..=DB_CREATE_POOL_FEE)
                    .map(|i| win[i].lamports())
                    .collect();
                exec_degen(win, &DEGEN_BUY_DISC, amount, &DB_WRITABLE, DB_SIGNER)?;
                let rent_paid = out_meme
                    .lamports()
                    .saturating_sub(meme_l0)
                    .checked_add(wsol_ata.lamports().saturating_sub(wsol_l0))
                    .ok_or(RouterError::MathOverflow)?;
                let grad =
                    degen_graduation_allowance(win, pool_existed_before, &grad_lamports_before)?;
                let debit = l0.saturating_sub(rc.user.lamports());
                require!(
                    debit
                        <= degen_buy_max_debit(amount, rent_paid)?
                            .checked_add(grad)
                            .ok_or(RouterError::MathOverflow)?,
                    RouterError::InputDebitMismatch
                );

                // The buy (re)created the meme ATA as the user's — verify + measure.
                // Defense-in-depth (v1 H1 parity): DB_MINT is a real mint and is
                // the meme ATA's mint — it drives the fee-destination derivation.
                require_keys_eq!(read_token_owner(out_meme)?, user, RouterError::AtaNotUser);
                require!(is_mint_account(&win[DB_MINT])?, RouterError::NotAMint);
                require_keys_eq!(read_token_mint(out_meme)?, win[DB_MINT].key(), RouterError::MintMismatch);
                let after_meme = read_token_amount(out_meme)?;
                let produced = after_meme.checked_sub(before_meme).ok_or(RouterError::NoNetOutput)?;
                carry = Some(Carry::Token {
                    key: out_meme.key(),
                    mint: win[DB_MINT].key(),
                    amount: produced,
                });
                if is_last {
                    let gross = after_meme.checked_sub(before_final_token).ok_or(RouterError::NoNetOutput)?;
                    fin = Some(FinalOut { ata_ix: last_start + DB_SIGNER_TOKEN, mint_ix: last_start + DB_MINT, tp_ix: last_start + DB_TOKEN_2022_PROG, gross });
                }
            }

            LEG_DEGEN_SELL => {
                let signer = &win[DS_SIGNER];
                let token_state = &win[DS_TOKEN_STATE];
                let in_meme = &win[DS_SIGNER_TOKEN];
                let wsol_ata = &win[DS_SIGNER_WSOL];
                let wsol_mint = &win[DS_WSOL_MINT];
                require_keys_eq!(signer.key(), user, RouterError::AuthorityNotUser);
                require!(signer.is_signer, RouterError::AuthorityNotSigner);
                require_keys_eq!(*token_state.owner, degen::ID, RouterError::NotDegenAccount);
                require_keys_eq!(read_token_owner(in_meme)?, user, RouterError::AtaNotUser);
                require_keys_eq!(wsol_mint.key(), wxnt::ID, RouterError::ExpectedWxntInput);
                // Defense-in-depth (v1 H1 parity): the input meme ATA's mint
                // matches the hop's declared mint account, which is a real mint.
                require!(is_mint_account(&win[DS_MINT])?, RouterError::NotAMint);
                require_keys_eq!(read_token_mint(in_meme)?, win[DS_MINT].key(), RouterError::MintMismatch);

                // Token amount to sell.
                let amount = match &carry {
                    None => initial_amount_in,
                    Some(Carry::Token { key, amount, .. }) => {
                        require_keys_eq!(in_meme.key(), *key, RouterError::BrokenRoute);
                        *amount // exact carried meme amount; leaves idle balance untouched
                    }
                    // native -> sell needs meme tokens: unsupported adjacency.
                    Some(Carry::Native(_)) => return err!(RouterError::UnsupportedLegSequence),
                };
                require!(amount > 0, RouterError::ZeroAmountIn);

                // The sell REQUIRES the signer WXNT ATA to pre-exist and CLOSES
                // it (reclaiming its rent + ANY balance). Rent-wash: ensure it
                // exists, snap lamports, sell, re-open (recreate rent cancels
                // close rent), snap again → the lamport delta is the sell payout
                // free of rent noise. Subtract any WXNT already parked in the
                // hub ATA (the close reclaims it too) so the route's proceeds are
                // ONLY this sell's payout — never an over-fee on the user's idle
                // WXNT nor a silent sweep of it (M1).
                ensure_wxnt_ata(rc, wsol_ata, wsol_mint)?;
                let pre_wxnt = read_token_amount(wsol_ata)?;
                let l0 = rc.user.lamports();
                let before_meme = read_token_amount(in_meme)?;
                exec_degen(win, &DEGEN_SELL_DISC, amount, &DS_WRITABLE, DS_SIGNER)?;
                require_exact_debit(in_meme, before_meme, amount)?; // C-1
                ensure_wxnt_ata(rc, wsol_ata, wsol_mint)?;
                let l1 = rc.user.lamports();
                let net_refund = l1
                    .checked_sub(l0)
                    .ok_or(RouterError::NoNetOutput)?
                    .checked_sub(pre_wxnt)
                    .ok_or(RouterError::NoNetOutput)?;

                if is_last {
                    // Normalize native → WXNT so fee + min-out use the proven
                    // token path. Wrap exactly net_refund into the (re-opened,
                    // empty) WXNT ATA.
                    require!(net_refund > 0, RouterError::NoNetOutput);
                    wrap_native_to_wxnt(rc, wsol_ata, net_refund)?;
                    // gross = the WXNT just wrapped (ATA was empty post-reopen).
                    fin = Some(FinalOut { ata_ix: last_start + DS_SIGNER_WSOL, mint_ix: last_start + DS_WSOL_MINT, tp_ix: last_start + DS_TOKEN_PROG, gross: net_refund });
                } else {
                    // Mid-route: hand native to the next leg (Degen buy = native
                    // passthrough; XDEX = wrapped at that leg from Carry::Native).
                    carry = Some(Carry::Native(net_refund));
                }
            }

            _ => return err!(RouterError::BadLegKind),
        }
    }

    // --- Fee + net min-out on the final (token) output: fee taken BEFORE the
    //     user's min-out, pinned sink, hook-reject, idempotent fee-ATA create,
    //     manual TransferChecked (the single shared helper); v0.4.0: then the
    //     integrator fee (if any) from the same output ATA, same signer. ----
    let f = fin.ok_or(RouterError::NoNetOutput)?;
    let final_out = accs[f.ata_ix].clone();
    let out_mint = accs[f.mint_ix].clone();
    let out_token_program = accs[f.tp_ix].clone();
    take_fee_and_enforce_min_out(
        FeeSink {
            user: &rc.user,
            fee_destination: &rc.fee_destination,
            fee_wallet: &rc.fee_wallet,
            system_program: &rc.system_program,
        },
        &final_out, &out_mint, &out_token_program, f.gross, minimum_amount_out, integrator,
    )
}

/// ceil(amount * bps / 10_000) in u128 to avoid overflow, capped at `amount`.
fn ceil_fee(amount: u64, bps: u64) -> Result<u64> {
    if amount == 0 || bps == 0 {
        return Ok(0);
    }
    let num = (amount as u128)
        .checked_mul(bps as u128)
        .ok_or(RouterError::MathOverflow)?
        .checked_add((BPS_DENOM - 1) as u128)
        .ok_or(RouterError::MathOverflow)?;
    let fee = (num / BPS_DENOM as u128) as u64;
    Ok(fee.min(amount))
}

/// C-1 (v0.3.1): the hop's input token account must have been debited by
/// EXACTLY `amount_in` by the CPI that just ran. Both SPL Token and Token-2022
/// debit the SOURCE by the full `amount` of a `transfer_checked` (a transfer-fee
/// mint withholds on the DESTINATION side), so equality is exact for every mint
/// the router accepts. A rogue / upgraded AMM that uses the signer's authority
/// to take more (or less) than the route states reverts here, atomically.
fn require_exact_debit(input: &AccountInfo, before: u64, amount_in: u64) -> Result<()> {
    let after = read_token_amount(input)?;
    let debited = before.checked_sub(after).ok_or(RouterError::InputDebitMismatch)?;
    require!(debited == amount_in, RouterError::InputDebitMismatch);
    Ok(())
}

/// C-1 (v0.3.1), Degen BUY: the most native the signer may be debited for a buy
/// of `amount` into the curve. Measured on the LIVE Degen bytes
/// (`tests/degen-live.test.ts`): the wallet pays exactly
/// `amount + amount × 1 % (fee ON TOP) + rent of every ATA the buy created`.
/// The fee term is bounded with a ceiling so an implementation that rounds its
/// three fee shares (0.5 % creator / 0.4 % platform / 0.1 % router) upward can
/// never trip the guard; `rent_paid` is the MEASURED lamport increase of the
/// signer's meme + WXNT ATAs (value that stays the user's — recoverable by
/// closing the ATA), so no rent constant is assumed.
fn degen_buy_max_debit(amount: u64, rent_paid: u64) -> Result<u64> {
    let fee = (amount as u128)
        .checked_mul(DEGEN_BUY_FEE_PPM as u128)
        .ok_or(RouterError::MathOverflow)?
        .checked_add((PPM_DENOM - 1) as u128)
        .ok_or(RouterError::MathOverflow)?
        / PPM_DENOM as u128;
    let fee = u64::try_from(fee).map_err(|_| RouterError::MathOverflow)?;
    amount
        .checked_add(fee)
        .and_then(|x| x.checked_add(rent_paid))
        .ok_or_else(|| RouterError::MathOverflow.into())
}

/// R-1 (v0.3.1): allowance for the extra native a GRADUATING Degen buy costs
/// the signer beyond `degen_buy_max_debit` — the XDEX pool-creation fee plus
/// the rent of every account the migration creates (measured on the live
/// bytes, `tests/degen-live.test.ts` DL5: `amm_config.create_pool_fee` +
/// rent of pool_state/observation/lp_mint/3 LP-ATAs/vault0/vault1).
///
/// Zero unless the buy ACTUALLY graduated the curve in THIS CPI (`pool_state`
/// went from absent to XDEX-owned). R-1 fix (v0.3.1-R1 review, Finding 1) +
/// R-1-R1 fix (v0.3.1-R1 verify2 review, Finding 2): a rogue/compromised
/// Degen CANNOT inflate this — each of the 8 "newly created" slots must pass
/// BOTH an owner gate AND a size ceiling before contributing anything:
///   1. Owner gate (Finding 2 / `XDEX_GRAD_SLOT_OWNER`, widened for
///      vault0/vault1 in Finding 3 / R-1-R1 verify3): the slot's post-CPI
///      `owner` must equal the program that's actually supposed to own it
///      (`xdex::ID` for pool_state/observation, the classic SPL Token
///      program for lp_mint + the 3 LP-ATAs, EITHER SPL Token program —
///      classic or Token-2022, via `is_token_program` — for vault0/vault1,
///      since a pool's vaults are Token *accounts* by protocol necessity and
///      which token program owns each one depends on which of the two
///      traded mints' pubkeys sorts first). `before[idx] == 0`
///      (absent pre-CPI) alone is NOT proof the CPI created the slot — an
///      account the CPI never touches at all is still absent afterwards
///      too, and previously got credited `Rent::minimum_balance(0)` (a
///      real, nonzero ≈890,880-lamport figure) for doing nothing; see
///      `tests/rogue-amm.test.ts` "R7b". A slot that fails the owner gate
///      contributes ZERO — skipped entirely, not `minimum_balance(0)`.
///   2. Size ceiling (Finding 1 / `XDEX_GRAD_SLOT_LEN`): `Rent::minimum_balance`
///      of the SMALLER of the slot's own post-CPI `data_len` and the FIXED,
///      hardcoded expected size for that slot (live-measured on real XDEX
///      bytes), never the raw CPI-target-claimed size on its own.
/// `owner == xdex::ID` (or the Token program) is necessary but NOT
/// sufficient proof of real XDEX involvement on its own (any CPI-calling
/// program can stamp any owner on an account it creates itself, no
/// cooperation from XDEX or the Token program required) — that's why the
/// owner gate is combined with, not a substitute for, the size ceiling: a
/// compromised Degen could still self-fund a genuinely owned but near-empty
/// account to pass the owner gate, but that only recovers what it actually
/// paid to create it (no free credit), since the ceiling never lets the
/// credited size exceed the account's own real `data_len`; see
/// `tests/rogue-amm.test.ts` "R7" (oversized fake, Finding 1) and "R7b"
/// (untouched phantom slot, Finding 2). The pool-fee term is capped by
/// `min(observed delta, amm_config.create_pool_fee)` and `amm_config` itself
/// must be owned by the real XDEX program.
///
/// `before[i]` is `win[DB_POOL_STATE + i].lamports()` snapshotted
/// immediately BEFORE the buy CPI, for `i` in `0..=(DB_CREATE_POOL_FEE -
/// DB_POOL_STATE)` (9 entries: pool_state, observation, lp_mint, the 3 LP
/// ATAs, vault0, vault1, create_pool_fee).
fn degen_graduation_allowance(
    win: &[AccountInfo],
    pool_existed_before: bool,
    before: &[u64],
) -> Result<u64> {
    let pool_state = &win[DB_POOL_STATE];
    let graduated =
        !pool_existed_before && pool_state.lamports() > 0 && *pool_state.owner == xdex::ID;
    if !graduated {
        return Ok(0);
    }

    // Pin amm_config to the real XDEX program before trusting its bytes —
    // a rogue caller cannot substitute a foreign account to inflate the
    // fee term this way (§2 of the review's fix).
    let amm_config = &win[DB_AMM_CONFIG];
    require_keys_eq!(*amm_config.owner, xdex::ID, RouterError::PoolNotXdex);
    let (create_pool_fee, protocol_owner): (u64, Option<Pubkey>) = {
        let data = amm_config.try_borrow_data()?;
        let fee_bytes = data
            .get(AMM_CONFIG_CREATE_POOL_FEE_OFF..AMM_CONFIG_CREATE_POOL_FEE_OFF + 8)
            .ok_or(RouterError::PoolNotXdex)?;
        let mut fee_buf = [0u8; 8];
        fee_buf.copy_from_slice(fee_bytes);
        // `protocol_owner` is read best-effort, NOT `?`-propagated: a real
        // live AmmConfig is always 236 B (well past offset 44..76), but a
        // shorter, legacy/atypical-shaped `amm_config` must not turn into a
        // hard, whole-instruction error here — it just can't prove a
        // recipient, so the fee term below is skipped (credited ZERO, same
        // graceful degradation as every owner/size gate elsewhere in this
        // function), while the size/owner-gated rent credits for the other
        // 8 slots are UNAFFECTED and still apply normally.
        let owner = data
            .get(AMM_CONFIG_PROTOCOL_OWNER_OFF..AMM_CONFIG_PROTOCOL_OWNER_OFF + 32)
            .map(|b| Pubkey::new_from_array(b.try_into().unwrap()));
        (u64::from_le_bytes(fee_buf), owner)
    };
    // WP #7421 fix: `win[DB_CREATE_POOL_FEE]` had no address pin at all — any
    // account could occupy that slot and its lamport delta was still
    // credited. Only credit the fee term when this slot IS the real
    // `amm_config.protocol_owner`; a mismatch (or an amm_config too short to
    // even contain the field) contributes ZERO (same graceful skip as the
    // owner gate on the other 8 slots below), so an honest graduation
    // (which always pays the real `protocol_owner`) is never under-credited,
    // while a compromised Degen routing the fee to an arbitrary wallet gets
    // no credit for it at all.
    let fee_recipient_ok = protocol_owner == Some(win[DB_CREATE_POOL_FEE].key());

    // Rent::get() is a syscall, unavailable outside the SBF runtime — kept
    // here at the edge; the summation itself is pure and unit-tested
    // (`graduation_grad_sum`).
    let rent = Rent::get()?;
    let mut created_rent_minimums: Vec<u64> = Vec::with_capacity(8);
    for i in DB_POOL_STATE..=DB_VAULT1 {
        let idx = i - DB_POOL_STATE;
        if before[idx] == 0 {
            // Account did not exist pre-CPI → CANDIDATE for "this graduation
            // created it" — but `before[idx] == 0` alone is NOT proof; an
            // account the CPI never touches at all is still absent
            // afterwards too. R-1-R1 Finding 2 fix: require the slot to
            // ACTUALLY be owned by the program that's supposed to own it
            // post-creation before crediting anything. A slot still owned by
            // the System Program (genuinely untouched) fails this and
            // contributes ZERO — skipped entirely, never
            // `Rent::minimum_balance(0)`.
            //
            // R-1-R1 verify3 Finding 3 fix: vault0/vault1 (i ==
            // DB_VAULT0/DB_VAULT1) are NOT in `XDEX_GRAD_SLOT_OWNER` — a
            // real pool's token vaults are SPL Token *accounts* (the Token
            // program must own them to move balances) and are NEVER
            // `xdex::ID`, so they're checked against EITHER SPL Token
            // program via `is_token_program` instead of a single fixed
            // expected owner (which token program owns a given vault flips
            // depending on which of the two traded mints' pubkeys sorts
            // first — not predictable as a single constant per slot).
            let owner_ok = if i == DB_VAULT0 || i == DB_VAULT1 {
                is_token_program(win[i].owner)
            } else {
                *win[i].owner == XDEX_GRAD_SLOT_OWNER[idx]
            };
            if !owner_ok {
                continue;
            }
            // R-1 fix (Finding 1): NEVER trust the CPI target's claimed
            // post-CPI `data_len` on its own as the rent basis — a
            // malicious/compromised Degen can fabricate an oversized fake
            // account here (see the module doc above). Cap the credited
            // size at the REAL, fixed size XDEX actually allocates for this
            // slot (`XDEX_GRAD_SLOT_LEN`): an honest graduation's account is
            // exactly that size, so honest rent is still covered in full; a
            // fabricated oversized account is capped at the honest size no
            // matter how large the CPI target claims it made it; a
            // smaller-than-real fake account is credited at its own
            // (smaller, non-exploitable) size. This composes with, and does
            // NOT replace, the owner gate above — both must pass.
            let capped_len = win[i].data_len().min(XDEX_GRAD_SLOT_LEN[idx]);
            created_rent_minimums.push(rent.minimum_balance(capped_len));
        }
    }
    let fee_idx = DB_CREATE_POOL_FEE - DB_POOL_STATE;
    let fee_delta = if fee_recipient_ok {
        win[DB_CREATE_POOL_FEE]
            .lamports()
            .saturating_sub(before[fee_idx])
    } else {
        0
    };
    graduation_grad_sum(&created_rent_minimums, fee_delta, create_pool_fee)
}

/// Pure arithmetic (unit-tested): sum the rent-exempt minimums of the
/// accounts a graduation actually created, plus the pool-creation fee delta
/// CAPPED at `amm_config.create_pool_fee` — a rogue AMM raising the observed
/// delta beyond the real configured fee cannot inflate the allowance. Split
/// out of `degen_graduation_allowance` because `Rent::minimum_balance` is a
/// syscall only available under the SBF runtime; this half has no such
/// dependency and runs under plain `cargo test`.
fn graduation_grad_sum(
    created_rent_minimums: &[u64],
    fee_delta: u64,
    create_pool_fee: u64,
) -> Result<u64> {
    let mut grad: u64 = 0;
    for &m in created_rent_minimums {
        grad = grad.checked_add(m).ok_or(RouterError::MathOverflow)?;
    }
    grad
        .checked_add(fee_delta.min(create_pool_fee))
        .ok_or_else(|| RouterError::MathOverflow.into())
}

fn read_token_amount(ai: &AccountInfo) -> Result<u64> {
    require!(is_token_account(ai)?, RouterError::NotATokenAccount);
    let data = ai.try_borrow_data()?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[TA_AMOUNT_OFF..TA_AMOUNT_OFF + 8]);
    Ok(u64::from_le_bytes(buf))
}
fn read_token_owner(ai: &AccountInfo) -> Result<Pubkey> {
    require!(is_token_account(ai)?, RouterError::NotATokenAccount);
    let data = ai.try_borrow_data()?;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[TA_OWNER_OFF..TA_OWNER_OFF + 32]);
    Ok(Pubkey::new_from_array(buf))
}
fn read_token_mint(ai: &AccountInfo) -> Result<Pubkey> {
    require!(is_token_account(ai)?, RouterError::NotATokenAccount);
    let data = ai.try_borrow_data()?;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[TA_MINT_OFF..TA_MINT_OFF + 32]);
    Ok(Pubkey::new_from_array(buf))
}
fn read_mint_decimals(ai: &AccountInfo) -> Result<u8> {
    require!(is_mint_account(ai)?, RouterError::NotAMint);
    // is_mint_account guarantees len >= SPL_MINT_LEN (82) > MINT_DECIMALS_OFF.
    let data = ai.try_borrow_data()?;
    Ok(data[MINT_DECIMALS_OFF])
}
fn is_token_program(pk: &Pubkey) -> bool {
    *pk == anchor_spl::token::ID || *pk == anchor_spl::token_2022::ID
}
/// Token-2022 account-type byte (offset 165), present only on EXTENDED accounts.
fn account_type_byte(ai: &AccountInfo) -> Result<Option<u8>> {
    if ai.data_len() > ACCOUNT_TYPE_OFF {
        let data = ai.try_borrow_data()?;
        Ok(Some(data[ACCOUNT_TYPE_OFF]))
    } else {
        Ok(None)
    }
}
/// SPL `AccountState` byte (offset 108), present on every >=165-byte account.
fn token_state_byte(ai: &AccountInfo) -> Result<Option<u8>> {
    if ai.data_len() > TA_STATE_OFF {
        let data = ai.try_borrow_data()?;
        Ok(Some(data[TA_STATE_OFF]))
    } else {
        Ok(None)
    }
}
/// Pure length/type/state classification — a base token account is 165 bytes;
/// an extended one is >165 with account-type byte == 2 (Account). An 82-byte
/// MINT must NOT qualify (the round-2 Low fix). S3: the account must also be
/// INITIALIZED (state byte == 1) — an allocated-but-uninitialized or frozen
/// token-program-owned account is NOT a usable token account (round-3 L-2).
/// Unit-tested without an AccountInfo.
fn looks_like_token_account(len: usize, type_byte: Option<u8>, state_byte: Option<u8>) -> bool {
    let shape_ok = if len == TA_LEN {
        true
    } else if len > ACCOUNT_TYPE_OFF {
        type_byte == Some(ACCOUNT_TYPE_ACCOUNT)
    } else {
        false
    };
    shape_ok && state_byte == Some(TA_STATE_INITIALIZED)
}
/// A base mint is 82 bytes; a base account is 165; an extended mint is >165 with
/// account-type byte == 1 (Mint). Rejects token accounts posing as mints.
fn looks_like_mint(len: usize, type_byte: Option<u8>) -> bool {
    if len == SPL_MINT_LEN {
        return true;
    }
    if len == TA_LEN {
        return false;
    }
    if len > ACCOUNT_TYPE_OFF {
        return type_byte == Some(ACCOUNT_TYPE_MINT);
    }
    false
}
fn is_token_account(ai: &AccountInfo) -> Result<bool> {
    Ok(is_token_program(ai.owner)
        && looks_like_token_account(ai.data_len(), account_type_byte(ai)?, token_state_byte(ai)?))
}
fn is_mint_account(ai: &AccountInfo) -> Result<bool> {
    Ok(is_token_program(ai.owner) && looks_like_mint(ai.data_len(), account_type_byte(ai)?))
}
/// True iff `ai` is a Token-2022 mint carrying the TransferHook extension.
fn mint_has_transfer_hook(ai: &AccountInfo) -> Result<bool> {
    mint_has_extension(ai, EXT_TRANSFER_HOOK)
}
/// True iff `ai` is a Token-2022 mint whose TLV carries extension `ext`
/// (v0.3.0: generalised from the hook check; same walk, same semantics).
fn mint_has_extension(ai: &AccountInfo, ext: u16) -> Result<bool> {
    if *ai.owner != anchor_spl::token_2022::ID {
        return Ok(false); // legacy SPL mints have no extensions
    }
    let data = ai.try_borrow_data()?;
    tlv_has_extension(&data, ext)
}
/// Pure TLV walk over a Token-2022 mint's bytes (unit-tested).
fn tlv_has_extension(data: &[u8], ext: u16) -> Result<bool> {
    if data.len() <= ACCOUNT_TYPE_OFF || data[ACCOUNT_TYPE_OFF] != ACCOUNT_TYPE_MINT {
        return Ok(false); // base mint (no extensions) or not an extended mint
    }
    let mut off = TLV_START;
    while off + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[off], data[off + 1]]);
        if ext_type == ext {
            return Ok(true);
        }
        if ext_type == 0 {
            break; // uninitialized TLV terminator
        }
        let ext_len = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
        off = off
            .checked_add(4)
            .and_then(|o| o.checked_add(ext_len))
            .ok_or(RouterError::MathOverflow)?;
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// v2 — fixed accounts, CPI helpers, and the fee/min-out path shared by route_v2.
// ---------------------------------------------------------------------------

/// Fixed accounts for `route_v2` (WIRE: 9 accounts, this order — v0.4.2: the
/// first 8 are frozen since v0.2.0, `fee_config` is a NEW mandatory 9th,
/// appended exactly like `route_v3` appends it relative to these same 8 —
/// security audit fix, was the v0.3.1 B-M2 optional-tail bypass). Two pinned
/// CPI targets (Degen + classic SPL Token for WXNT wrap/unwrap) beyond the
/// fee/XDEX set. All hop accounts arrive as `remaining_accounts`; the route
/// holds no vault.
#[derive(Accounts)]
pub struct RouteV2<'info> {
    /// Route authority + rent payer (fee-ATA + WXNT-ATA idempotent creates).
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: validated in-instruction to equal ATA(final_out_mint, FEE_WALLET,
    /// final_out_token_program); the mandatory fee is transferred here.
    #[account(mut)]
    pub fee_destination: UncheckedAccount<'info>,
    /// CHECK: pinned to `fee_wallet::ID`.
    #[account(address = fee_wallet::ID)]
    pub fee_wallet: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// CHECK: pinned XDEX cp-swap program (CPI target for XDEX legs).
    #[account(address = xdex::ID)]
    pub xdex_program: UncheckedAccount<'info>,
    /// CHECK: pinned Degen launchpad program (CPI target for Degen legs).
    #[account(address = degen::ID)]
    pub degen_program: UncheckedAccount<'info>,
    /// CHECK: pinned classic SPL Token program (WXNT wrap/unwrap/sync/close).
    #[account(address = anchor_spl::token::ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: v0.4.2 pause switch (security audit fix) — the `fee_config` PDA
    /// pinned by constant address (Anchor 2012 for anything else);
    /// `require_not_paused` re-checks address, then owner (2004), then reads
    /// only the `paused` byte (225). MANDATORY: a caller that omits this
    /// account gets Anchor `AccountNotEnoughKeys` (3005), never a swap that
    /// silently bypasses the guardian's pause switch.
    #[account(address = fee_config_pda::ID)]
    pub fee_config: UncheckedAccount<'info>,
}

/// v0.4.0 — fixed accounts for `route_v3` (WIRE: 11 accounts, this order):
/// `route_v2`'s 8 in the same order, then `fee_config` (MANDATORY, pinned by
/// constant address — Anchor 2012 for anything else; `require_not_paused`
/// re-checks owner + reads the `paused` byte), then the integrator pair. Leg
/// windows arrive as `remaining_accounts` and must partition EXACTLY.
#[derive(Accounts)]
pub struct RouteV3<'info> {
    /// Route authority + rent payer (protocol fee-ATA / WXNT-ATA idempotent creates; never the integrator's).
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: validated in-instruction to equal ATA(final_out_mint, FEE_WALLET,
    /// final_out_token_program); the mandatory protocol fee is transferred here.
    #[account(mut)]
    pub fee_destination: UncheckedAccount<'info>,
    /// CHECK: pinned to `fee_wallet::ID`.
    #[account(address = fee_wallet::ID)]
    pub fee_wallet: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// CHECK: pinned XDEX cp-swap program (CPI target for XDEX legs).
    #[account(address = xdex::ID)]
    pub xdex_program: UncheckedAccount<'info>,
    /// CHECK: pinned Degen launchpad program (CPI target for Degen legs).
    #[account(address = degen::ID)]
    pub degen_program: UncheckedAccount<'info>,
    /// CHECK: pinned classic SPL Token program (WXNT wrap/unwrap/sync/close).
    #[account(address = anchor_spl::token::ID)]
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: v0.3.1 pause switch — the `fee_config` PDA pinned by constant
    /// address (Anchor 2012); `require_not_paused` re-checks address, then owner
    /// (2004), then reads only the `paused` byte (225). Mandatory on this ix.
    #[account(address = fee_config_pda::ID)]
    pub fee_config: UncheckedAccount<'info>,
    /// CHECK: validated in-instruction (before any CPI) to equal ATA(final_out_mint,
    /// integrator_wallet, final_out_token_program) (`WrongIntegratorFeeDestination`)
    /// AND to already exist as that token account (`IntegratorFeeDestinationMissing`);
    /// never created by the router; the integrator fee is transferred here.
    #[account(mut)]
    pub integrator_fee_destination: UncheckedAccount<'info>,
    /// CHECK: the integrator's wallet — the ATA owner above. Any pubkey except
    /// the zero key (`InvalidIntegratorWallet`); need not exist or sign.
    pub integrator_wallet: UncheckedAccount<'info>,
}

/// v0.3.0 — fixed accounts for `route_v2_delegated` (WIRE: 12 accounts since
/// v0.3.1 — the trailing `fee_config` pause account was appended while no
/// client was live on this ix; 11 in v0.3.0). The delegate + payer sign; the
/// user does NOT. Hop windows arrive as `remaining_accounts` (13 per XDEX leg,
/// see the instruction docs).
#[derive(Accounts)]
pub struct RouteV2Delegated<'info> {
    /// CHECK: the token-account OWNER the route acts for (owner of
    /// `user_input_ata`, recipient at `user_output_ata`). Not a signer; its
    /// ownership of the input ATA + the SPL delegation are asserted in-instruction.
    pub user: UncheckedAccount<'info>,
    /// The SPL delegate on `user_input_ata` (asserted); XDEX `payer` of hop 0.
    pub delegate_authority: Signer<'info>,
    /// Funds idempotent ATA creates (vault / user output / fee) — may equal the delegate.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: the router's transient-vault authority PDA; signs the later hops
    /// and the fee/forward transfers out of the vault ATAs.
    #[account(seeds = [VAULT_AUTHORITY_SEED], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    /// CHECK: validated in-instruction (owner == user, delegate == delegate_authority,
    /// delegated_amount >= initial_amount_in); hop 0 must spend exactly this account.
    #[account(mut)]
    pub user_input_ata: UncheckedAccount<'info>,
    /// CHECK: validated in-instruction to equal ATA(final_out_mint, user,
    /// final_out_token_program); created idempotently; receives gross − fee.
    #[account(mut)]
    pub user_output_ata: UncheckedAccount<'info>,
    /// CHECK: validated in-instruction to equal ATA(final_out_mint, FEE_WALLET,
    /// final_out_token_program); the mandatory fee is transferred here.
    #[account(mut)]
    pub fee_destination: UncheckedAccount<'info>,
    /// CHECK: pinned to `fee_wallet::ID`.
    #[account(address = fee_wallet::ID)]
    pub fee_wallet: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// CHECK: pinned XDEX cp-swap program (the only CPI target of this ix).
    #[account(address = xdex::ID)]
    pub xdex_program: UncheckedAccount<'info>,
    /// CHECK: v0.3.1 pause switch — the `fee_config` PDA pinned by constant
    /// address (Anchor 2012); `require_not_paused` re-checks address, then owner
    /// (2004), then reads only the `paused` byte (225).
    #[account(address = fee_config_pda::ID)]
    pub fee_config: UncheckedAccount<'info>,
}

/// v0.3.0 — fixed accounts for `route_v2_snipe` (WIRE: 19 accounts since
/// v0.3.1 — trailing `fee_config` appended while no client was live; 18 in
/// v0.3.0; this order = the 13-account XDEX `swap_base_input` window with the
/// user as payer, then the router's fee set, then the pause account). All token/mint/pool accounts are validated
/// in-instruction exactly like a `route_v2` XDEX leg; XDEX itself pins
/// authority / amm_config / vaults / observation to the pool.
#[derive(Accounts)]
pub struct RouteV2Snipe<'info> {
    /// Swap authority, fee signer, fee-ATA rent payer.
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: XDEX vault/LP authority PDA (XDEX validates).
    pub authority: UncheckedAccount<'info>,
    /// CHECK: XDEX AmmConfig (XDEX validates against the pool).
    pub amm_config: UncheckedAccount<'info>,
    /// CHECK: must be owned by the XDEX program (PoolNotXdex).
    #[account(mut)]
    pub pool_state: UncheckedAccount<'info>,
    /// CHECK: the user's input token account (owner/mint asserted).
    #[account(mut)]
    pub user_input_ata: UncheckedAccount<'info>,
    /// CHECK: the user's output token account — must PRE-EXIST (owner/mint asserted).
    #[account(mut)]
    pub user_output_ata: UncheckedAccount<'info>,
    /// CHECK: XDEX input vault (XDEX validates against the pool).
    #[account(mut)]
    pub input_vault: UncheckedAccount<'info>,
    /// CHECK: XDEX output vault (XDEX validates against the pool).
    #[account(mut)]
    pub output_vault: UncheckedAccount<'info>,
    /// CHECK: SPL Token or Token-2022 (asserted).
    pub input_token_program: UncheckedAccount<'info>,
    /// CHECK: SPL Token or Token-2022 (asserted).
    pub output_token_program: UncheckedAccount<'info>,
    /// CHECK: real mint (asserted) == user_input_ata.mint.
    pub input_mint: UncheckedAccount<'info>,
    /// CHECK: real mint (asserted) == user_output_ata.mint; drives the fee sink.
    pub output_mint: UncheckedAccount<'info>,
    /// CHECK: XDEX pins it to `pool_state.observation_key` (required by XDEX).
    #[account(mut)]
    pub observation_state: UncheckedAccount<'info>,
    /// CHECK: validated in-instruction to equal ATA(output_mint, FEE_WALLET,
    /// output_token_program); the mandatory fee is transferred here.
    #[account(mut)]
    pub fee_destination: UncheckedAccount<'info>,
    /// CHECK: pinned to `fee_wallet::ID`.
    #[account(address = fee_wallet::ID)]
    pub fee_wallet: UncheckedAccount<'info>,
    /// CHECK: pinned XDEX cp-swap program (CPI target).
    #[account(address = xdex::ID)]
    pub xdex_program: UncheckedAccount<'info>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: v0.3.1 pause switch — the `fee_config` PDA pinned by constant
    /// address (Anchor 2012); `require_not_paused` re-checks address, then owner
    /// (2004), then reads only the `paused` byte (225).
    #[account(address = fee_config_pda::ID)]
    pub fee_config: UncheckedAccount<'info>,
}

/// Reads a token account's amount, or 0 if the account isn't (yet) an
/// initialized token account (e.g. a meme ATA the Degen buy is about to create).
fn read_token_amount_or_zero(ai: &AccountInfo) -> Result<u64> {
    if is_token_account(ai)? {
        read_token_amount(ai)
    } else {
        Ok(0)
    }
}

/// Reconstruct + invoke one XDEX `swap_base_input` (identical shape to v1's
/// per-hop CPI: index 0 signer, `matches!(i,3|4|5|6|7|12)` writable, per-hop
/// min set to 0 — the route's net min-out is the real floor).
fn exec_xdex_swap<'info>(win: &[AccountInfo<'info>], amount_in: u64) -> Result<()> {
    exec_xdex_swap_signed(win, amount_in, &[])
}

/// Same CPI, optionally PDA-signed (`signer_seeds` empty == plain `invoke`).
/// v0.3.0: the delegated route's later hops are paid from vault ATAs whose
/// authority is the `vault_authority` PDA, which signs via these seeds.
fn exec_xdex_swap_signed<'info>(
    win: &[AccountInfo<'info>],
    amount_in: u64,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&SWAP_BASE_INPUT_DISC);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    let metas: Vec<AccountMeta> = win
        .iter()
        .enumerate()
        .map(|(i, ai)| {
            let writable = matches!(i, 3 | 4 | 5 | 6 | 7 | 12);
            if i == IDX_PAYER {
                AccountMeta::new_readonly(ai.key(), true)
            } else if writable {
                AccountMeta::new(ai.key(), false)
            } else {
                AccountMeta::new_readonly(ai.key(), false)
            }
        })
        .collect();
    invoke_signed(&Instruction { program_id: xdex::ID, accounts: metas, data }, win, signer_seeds)?;
    Ok(())
}

/// Reconstruct + invoke a Degen `buy`/`sell` from its account window. The signer
/// index (the user) is emitted as writable+signer; the rest use the IDL isMut
/// table. `amount` is injected by the router (never a raw caller field), so a
/// mid-route hop trades exactly the value the router derived.
fn exec_degen<'info>(
    win: &[AccountInfo<'info>],
    disc: &[u8; 8],
    amount: u64,
    writable: &[usize],
    signer_idx: usize,
) -> Result<()> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(disc);
    data.extend_from_slice(&amount.to_le_bytes());
    let metas: Vec<AccountMeta> = win
        .iter()
        .enumerate()
        .map(|(i, ai)| {
            if i == signer_idx {
                AccountMeta::new(ai.key(), true)
            } else if writable.contains(&i) {
                AccountMeta::new(ai.key(), false)
            } else {
                AccountMeta::new_readonly(ai.key(), false)
            }
        })
        .collect();
    invoke(&Instruction { program_id: degen::ID, accounts: metas, data }, win)?;
    Ok(())
}

/// Idempotently create the USER's WXNT ATA (classic SPL). No-op if it exists;
/// used to guarantee the sell's precondition and to wash the close-rent so the
/// sell's net proceeds can be measured exactly.
fn ensure_wxnt_ata<'info>(
    rc: &RouteCtx<'info>,
    ata: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
) -> Result<()> {
    let ix = Instruction {
        program_id: anchor_spl::associated_token::ID,
        accounts: vec![
            AccountMeta::new(rc.user.key(), true),
            AccountMeta::new(ata.key(), false),
            AccountMeta::new_readonly(rc.user.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
            AccountMeta::new_readonly(rc.token_program.key(), false),
        ],
        data: vec![1u8], // CreateIdempotent
    };
    invoke(
        &ix,
        &[
            rc.user.clone(),
            ata.clone(),
            rc.user.clone(),
            mint.clone(),
            rc.system_program.clone(),
            rc.token_program.clone(),
        ],
    )?;
    Ok(())
}

/// Move `amount` native lamports from the user into their (existing, classic)
/// WXNT ATA and SyncNative so it registers as WXNT. Bridges a Degen sell's
/// native proceeds onto the WXNT medium (for an XDEX leg or the final fee path).
fn wrap_native_to_wxnt<'info>(
    rc: &RouteCtx<'info>,
    wxnt_ata: &AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    let mut td = Vec::with_capacity(12);
    td.extend_from_slice(&2u32.to_le_bytes()); // System `Transfer`
    td.extend_from_slice(&amount.to_le_bytes());
    invoke(
        &Instruction {
            program_id: anchor_lang::system_program::ID,
            accounts: vec![
                AccountMeta::new(rc.user.key(), true),
                AccountMeta::new(wxnt_ata.key(), false),
            ],
            data: td,
        },
        &[
            rc.user.clone(),
            wxnt_ata.clone(),
            rc.system_program.clone(),
        ],
    )?;
    invoke(
        &Instruction {
            program_id: rc.token_program.key(),
            accounts: vec![AccountMeta::new(wxnt_ata.key(), false)],
            data: vec![SPL_IX_SYNC_NATIVE],
        },
        &[wxnt_ata.clone(), rc.token_program.clone()],
    )?;
    Ok(())
}

/// CloseAccount the user's WXNT ATA, sending all WXNT (as native) + rent to the
/// user. Converts a WXNT carry to native ahead of a Degen buy (which debits
/// native). The buy re-creates the WXNT ATA idempotently afterwards.
fn unwrap_wxnt_to_native<'info>(
    rc: &RouteCtx<'info>,
    wxnt_ata: &AccountInfo<'info>,
) -> Result<()> {
    invoke(
        &Instruction {
            program_id: rc.token_program.key(),
            accounts: vec![
                AccountMeta::new(wxnt_ata.key(), false),
                AccountMeta::new(rc.user.key(), false),
                AccountMeta::new_readonly(rc.user.key(), true),
            ],
            data: vec![SPL_IX_CLOSE_ACCOUNT],
        },
        &[
            wxnt_ata.clone(),
            rc.user.clone(),
            rc.user.clone(),
            rc.token_program.clone(),
        ],
    )?;
    Ok(())
}

/// Native amount to feed a MID-route Degen buy: reserve up to two ATA rents and
/// the (fee-on-top) buy fee, so `amount + degen_fee(amount) + rents <= available`.
/// Conservative by design — under-buying is bounded by the net min-out, and an
/// over-estimate simply reverts the tx.
fn derive_buy_amount(available_native: u64) -> Result<u64> {
    let spendable = available_native.saturating_sub(DEGEN_BUY_RENT_RESERVE);
    let amount = (spendable as u128)
        .checked_mul(PPM_DENOM as u128)
        .ok_or(RouterError::MathOverflow)?
        / (PPM_DENOM as u128 + DEGEN_BUY_FEE_PPM as u128);
    let amount = amount as u64;
    require!(amount > 0, RouterError::ZeroAmountIn);
    Ok(amount)
}

/// THE fee + min-out policy (the single shared helper since v0.2.0 — v1's
/// inline copy died with the v1 `route` deletion, WP #6707 B1): fee =
/// ceil(gross*PROTOCOL_FEE_BPS/1e4) taken BEFORE the user's min-out; pinned sink
/// = ATA(out_mint, FEE_WALLET); L-3 fail-fast owner/program checks; hook-reject
/// (M2); idempotent fee-ATA create (M4, user pays rent); manual TransferChecked
/// (tag 12) by the user (signer). The 25 bps const is the ratified base tier
/// (== `FeeConfig.tier_bps[0]`, asserted in unit tests); `route_v2` does NOT
/// read the config — the rate stays compile-time until the tier upgrade.
/// The accounts the user-signed fee path needs (v0.3.0: lifted out of
/// `Context<RouteV2>` so `route_v2_snipe` shares the helper byte-for-byte).
struct FeeSink<'a, 'info> {
    /// The route authority: signs the fee `TransferChecked`, funds the fee-ATA rent.
    user: &'a AccountInfo<'info>,
    fee_destination: &'a AccountInfo<'info>,
    fee_wallet: &'a AccountInfo<'info>,
    system_program: &'a AccountInfo<'info>,
}

fn take_fee_and_enforce_min_out<'info>(
    sink: FeeSink<'_, 'info>,
    final_out: &AccountInfo<'info>,
    out_mint: &AccountInfo<'info>,
    out_token_program: &AccountInfo<'info>,
    gross_out: u64,
    minimum_amount_out: u64,
    integrator: Option<&IntegratorSink<'_, 'info>>,
) -> Result<FeeSplit> {
    let split = split_fees(gross_out, integrator.map(|i| i.bps))?;
    let fee = split.fee;
    require!(split.user_receives >= minimum_amount_out, RouterError::SlippageExceeded);

    if fee > 0 {
        require!(is_token_program(&out_token_program.key()), RouterError::BadTokenProgram);
        require_keys_eq!(*final_out.owner, out_token_program.key(), RouterError::BadTokenProgram);
        require_keys_eq!(*out_mint.owner, out_token_program.key(), RouterError::BadTokenProgram);

        let expected = get_associated_token_address_with_program_id(
            &fee_wallet::ID,
            &out_mint.key(),
            &out_token_program.key(),
        );
        require_keys_eq!(sink.fee_destination.key(), expected, RouterError::WrongFeeDestination);

        require!(!mint_has_transfer_hook(out_mint)?, RouterError::TransferHookUnsupported);

        let create_ix = Instruction {
            program_id: anchor_spl::associated_token::ID,
            accounts: vec![
                AccountMeta::new(sink.user.key(), true),
                AccountMeta::new(sink.fee_destination.key(), false),
                AccountMeta::new_readonly(fee_wallet::ID, false),
                AccountMeta::new_readonly(out_mint.key(), false),
                AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
                AccountMeta::new_readonly(out_token_program.key(), false),
            ],
            data: vec![1u8],
        };
        invoke(
            &create_ix,
            &[
                sink.user.clone(),
                sink.fee_destination.clone(),
                sink.fee_wallet.clone(),
                out_mint.clone(),
                sink.system_program.clone(),
                out_token_program.clone(),
            ],
        )?;

        let decimals = read_mint_decimals(out_mint)?;
        let mut fdata = Vec::with_capacity(10);
        fdata.push(12u8);
        fdata.extend_from_slice(&fee.to_le_bytes());
        fdata.push(decimals);
        let fee_dest = sink.fee_destination.clone();
        let fmetas = vec![
            AccountMeta::new(final_out.key(), false),
            AccountMeta::new_readonly(out_mint.key(), false),
            AccountMeta::new(fee_dest.key(), false),
            AccountMeta::new_readonly(sink.user.key(), true),
        ];
        invoke(
            &Instruction { program_id: out_token_program.key(), accounts: fmetas, data: fdata },
            &[
                final_out.clone(),
                out_mint.clone(),
                fee_dest.clone(),
                sink.user.clone(),
                out_token_program.clone(),
            ],
        )?;
    }

    // v0.4.0 — the integrator sink (route_v3 only). Runs AFTER the protocol
    // fee has left the output ATA; it can only ever move `integrator_fee`,
    // which `split_fees` derived from the gross INDEPENDENTLY of the protocol
    // fee. The destination was already required to EXIST as the canonical ATA
    // before any CPI (`require_integrator_destination` in the engine); it is
    // re-validated here (defense in depth — this helper is safe on its own)
    // and NEVER created by the router: the integrator creates its own fee
    // account (Jupiter standard), the user pays no partner rent. The transfer
    // is skipped for a zero (dust) amount.
    if let Some(i) = integrator {
        require!(is_token_program(&out_token_program.key()), RouterError::BadTokenProgram);
        require_integrator_destination(i, out_mint, out_token_program)?;
        require!(!mint_has_transfer_hook(out_mint)?, RouterError::TransferHookUnsupported);
        if split.integrator_fee > 0 {
            let decimals = read_mint_decimals(out_mint)?;
            transfer_checked_signed(out_token_program, final_out, out_mint, i.destination, sink.user, split.integrator_fee, decimals, &[])?;
        }
    }
    Ok(split)
}

/// v0.4.0 — the integrator sink MUST be the integrator wallet's canonical ATA
/// for the route's final output mint AND must already exist as an initialised
/// token account of that mint owned by that wallet. Order of checks:
///   1. wallet != zero key (6045);
///   2. `destination == ATA(out_mint, wallet, out_token_program)` (6044 — a
///      caller cannot name a non-canonical account);
///   3. the account exists and is an initialised token account (else 6046
///      `IntegratorFeeDestinationMissing` — the integrator has not created its
///      fee account for this mint yet; the router never creates it);
///   4. its owner is `wallet` and its mint is `out_mint` (6044 — belt and
///      braces: an account at the canonical address can only be created by the
///      ATA program with exactly these fields, but the router reads them anyway).
/// Called once BEFORE any CPI (the final mint is known from the last leg's
/// window) and again in the fee path.
fn require_integrator_destination(
    i: &IntegratorSink<'_, '_>,
    out_mint: &AccountInfo,
    out_token_program: &AccountInfo,
) -> Result<()> {
    require!(i.wallet.key() != Pubkey::default(), RouterError::InvalidIntegratorWallet);
    let expected = get_associated_token_address_with_program_id(
        &i.wallet.key(),
        &out_mint.key(),
        &out_token_program.key(),
    );
    require_keys_eq!(i.destination.key(), expected, RouterError::WrongIntegratorFeeDestination);
    require!(is_token_account(i.destination)?, RouterError::IntegratorFeeDestinationMissing);
    require_keys_eq!(read_token_owner(i.destination)?, i.wallet.key(), RouterError::WrongIntegratorFeeDestination);
    require_keys_eq!(read_token_mint(i.destination)?, out_mint.key(), RouterError::WrongIntegratorFeeDestination);
    Ok(())
}

/// v0.4.0 — the ONE fee formula for the user-signed paths. Protocol fee =
/// `ceil(gross × PROTOCOL_FEE_BPS)` (unchanged, ≥ 1 for any positive gross);
/// integrator fee = `floor(gross × bps)` on the SAME gross (0 when absent);
/// net = gross − protocol − integrator. Both fees are functions of `gross`
/// alone — the integrator fee can never reduce the protocol fee, and vice
/// versa. With `bps ≤ MAX_INTEGRATOR_FEE_BPS` the two never exceed `gross`
/// (unit-tested across the dust range); the subtraction is still checked.
fn split_fees(gross_out: u64, integrator_bps: Option<u16>) -> Result<FeeSplit> {
    require!(gross_out > 0, RouterError::NoNetOutput);
    let fee = ceil_fee(gross_out, PROTOCOL_FEE_BPS)?;
    let integrator_fee = match integrator_bps {
        None => 0,
        Some(bps) => {
            require!(bps >= 1 && bps <= MAX_INTEGRATOR_FEE_BPS, RouterError::BadIntegratorFeeBps);
            floor_fee(gross_out, bps as u64)?
        }
    };
    let user_receives = gross_out
        .checked_sub(fee)
        .and_then(|x| x.checked_sub(integrator_fee))
        .ok_or(RouterError::MathOverflow)?;
    Ok(FeeSplit { gross: gross_out, fee, integrator_fee, user_receives })
}

/// floor(amount * bps / 10_000) in u128 (v0.4.0, integrator fee).
fn floor_fee(amount: u64, bps: u64) -> Result<u64> {
    let num = (amount as u128).checked_mul(bps as u128).ok_or(RouterError::MathOverflow)?;
    let fee = num / BPS_DENOM as u128;
    u64::try_from(fee).map_err(|_| RouterError::MathOverflow.into())
}

// ---------------------------------------------------------------------------
// v0.3.0 — delegated-route helpers: delegation proof, vault-signed fee path.
// ---------------------------------------------------------------------------

/// Pure parse of the SPL `delegate` / `delegated_amount` fields out of a token
/// account's raw bytes: `None` when no delegate is set (COption tag 0).
/// Unit-tested; `read_token_delegate` wraps it with the token-account classifier.
fn parse_token_delegate(data: &[u8]) -> Option<(Pubkey, u64)> {
    if data.len() < TA_DELEGATED_AMOUNT_OFF + 8 {
        return None;
    }
    let tag = u32::from_le_bytes([
        data[TA_DELEGATE_TAG_OFF],
        data[TA_DELEGATE_TAG_OFF + 1],
        data[TA_DELEGATE_TAG_OFF + 2],
        data[TA_DELEGATE_TAG_OFF + 3],
    ]);
    if tag != 1 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[TA_DELEGATE_KEY_OFF..TA_DELEGATE_KEY_OFF + 32]);
    let mut amt = [0u8; 8];
    amt.copy_from_slice(&data[TA_DELEGATED_AMOUNT_OFF..TA_DELEGATED_AMOUNT_OFF + 8]);
    Some((Pubkey::new_from_array(key), u64::from_le_bytes(amt)))
}
fn read_token_delegate(ai: &AccountInfo) -> Result<Option<(Pubkey, u64)>> {
    require!(is_token_account(ai)?, RouterError::NotATokenAccount);
    let data = ai.try_borrow_data()?;
    Ok(parse_token_delegate(&data))
}
/// The delegation invariant: the signer IS the account's SPL delegate and was
/// approved for at least the amount hop 0 will spend. (The SPL program would
/// also refuse, but asserting it here fails fast with a typed error before any
/// CPI or rent is spent.)
fn check_delegation(delegate: Option<(Pubkey, u64)>, signer: &Pubkey, needed: u64) -> Result<()> {
    let (key, amount) = delegate.ok_or(RouterError::NotDelegate)?;
    require_keys_eq!(key, *signer, RouterError::NotDelegate);
    require!(amount >= needed, RouterError::InsufficientDelegation);
    Ok(())
}

/// Associated-token `CreateIdempotent` (data `[1]`): no-op if `ata` exists,
/// otherwise `payer` funds the rent. Generic over the ATA owner (vault PDA,
/// user, fee wallet) — the owner need not be a signer nor exist as an account.
fn create_ata_idempotent<'info>(
    payer: &AccountInfo<'info>,
    ata: &AccountInfo<'info>,
    owner: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    token_program: &AccountInfo<'info>,
) -> Result<()> {
    let ix = Instruction {
        program_id: anchor_spl::associated_token::ID,
        accounts: vec![
            AccountMeta::new(payer.key(), true),
            AccountMeta::new(ata.key(), false),
            AccountMeta::new_readonly(owner.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
            AccountMeta::new_readonly(token_program.key(), false),
        ],
        data: vec![1u8],
    };
    invoke(
        &ix,
        &[payer.clone(), ata.clone(), owner.clone(), mint.clone(), system_program.clone(), token_program.clone()],
    )?;
    Ok(())
}

/// SPL / Token-2022 `TransferChecked` (tag 12) with an optionally PDA-signed
/// authority (`signer_seeds` empty == plain invoke).
fn transfer_checked_signed<'info>(
    token_program: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let metas = vec![
        AccountMeta::new(from.key(), false),
        AccountMeta::new_readonly(mint.key(), false),
        AccountMeta::new(to.key(), false),
        AccountMeta::new_readonly(authority.key(), true),
    ];
    invoke_signed(
        &Instruction { program_id: token_program.key(), accounts: metas, data },
        &[from.clone(), mint.clone(), to.clone(), authority.clone(), token_program.clone()],
        signer_seeds,
    )?;
    Ok(())
}

/// Accounts for the vault-signed fee + forward path of `route_v2_delegated`.
struct VaultSink<'a, 'info> {
    /// The final hop's vault ATA (owner = `vault_authority`), holds `gross`
    /// (+ any pre-route residual) on entry and MUST hold 0 on exit.
    vault: &'a AccountInfo<'info>,
    vault_authority: &'a AccountInfo<'info>,
    vault_seeds: &'a [&'a [u8]],
    /// Funds the idempotent fee-ATA / user-ATA creates.
    payer: &'a AccountInfo<'info>,
    /// The token-account owner the net output is forwarded to (NOT a signer).
    user: &'a AccountInfo<'info>,
    /// Must equal `ATA(out_mint, user, out_token_program)` (asserted).
    user_output_ata: &'a AccountInfo<'info>,
    fee_destination: &'a AccountInfo<'info>,
    fee_wallet: &'a AccountInfo<'info>,
    system_program: &'a AccountInfo<'info>,
}

/// The delegated-route fee policy — the SAME numbers as `take_fee_and_enforce_min_out`
/// (fee = ceil(gross × PROTOCOL_FEE_BPS / 1e4) BEFORE the user's net min-out,
/// pinned sink = ATA(out_mint, FEE_WALLET), L-3 owner/program checks, M2 hook
/// reject, M4 idempotent fee-ATA create) with two differences forced by
/// delegation: the transfers are signed by the vault PDA (the user never
/// signs), and the net output is FORWARDED to the user's canonical output ATA
/// (derived + asserted: the delegate cannot name an arbitrary destination),
/// created idempotently by `payer`. Any pre-route `residual` in the vault
/// (third-party donation) is swept to the fee sink and the vault is asserted
/// EMPTY at exit — the router holds nothing between transactions, and a
/// donation can never turn that assertion into a DoS.
fn take_fee_from_vault_and_forward<'info>(
    sink: VaultSink<'_, 'info>,
    out_mint: &AccountInfo<'info>,
    out_token_program: &AccountInfo<'info>,
    gross_out: u64,
    minimum_amount_out: u64,
    residual: u64,
) -> Result<(u64, u64)> {
    let (fee, user_receives) = split_fee(gross_out)?;
    require!(user_receives >= minimum_amount_out, RouterError::SlippageExceeded);

    require!(is_token_program(&out_token_program.key()), RouterError::BadTokenProgram);
    require_keys_eq!(*sink.vault.owner, out_token_program.key(), RouterError::BadTokenProgram);
    require_keys_eq!(*out_mint.owner, out_token_program.key(), RouterError::BadTokenProgram);

    let expected_fee = get_associated_token_address_with_program_id(
        &fee_wallet::ID, &out_mint.key(), &out_token_program.key(),
    );
    require_keys_eq!(sink.fee_destination.key(), expected_fee, RouterError::WrongFeeDestination);
    let expected_user = get_associated_token_address_with_program_id(
        &sink.user.key(), &out_mint.key(), &out_token_program.key(),
    );
    require_keys_eq!(sink.user_output_ata.key(), expected_user, RouterError::WrongUserDestination);

    require!(!mint_has_transfer_hook(out_mint)?, RouterError::TransferHookUnsupported);
    // M-1: the forward leg below would pay the mint's transfer fee AFTER the
    // min-out check — re-asserted here (defense in depth; the hop loop already
    // rejects it) so this helper is safe on its own.
    require!(!mint_has_extension(out_mint, EXT_TRANSFER_FEE_CONFIG)?, RouterError::TransferFeeUnsupported);

    create_ata_idempotent(sink.payer, sink.fee_destination, sink.fee_wallet, out_mint, sink.system_program, out_token_program)?;
    create_ata_idempotent(sink.payer, sink.user_output_ata, sink.user, out_mint, sink.system_program, out_token_program)?;
    // Defense-in-depth after the creates: both destinations are real token
    // accounts of this mint owned by exactly whom the derivation says.
    require_keys_eq!(read_token_owner(sink.user_output_ata)?, sink.user.key(), RouterError::WrongUserDestination);
    require_keys_eq!(read_token_mint(sink.user_output_ata)?, out_mint.key(), RouterError::MintMismatch);
    require_keys_eq!(read_token_owner(sink.fee_destination)?, fee_wallet::ID, RouterError::WrongFeeDestination);
    require_keys_eq!(read_token_mint(sink.fee_destination)?, out_mint.key(), RouterError::MintMismatch);

    let decimals = read_mint_decimals(out_mint)?;
    let seeds: &[&[&[u8]]] = &[sink.vault_seeds];
    if fee > 0 {
        transfer_checked_signed(out_token_program, sink.vault, out_mint, sink.fee_destination, sink.vault_authority, fee, decimals, seeds)?;
    }
    if user_receives > 0 {
        transfer_checked_signed(out_token_program, sink.vault, out_mint, sink.user_output_ata, sink.vault_authority, user_receives, decimals, seeds)?;
    }
    if residual > 0 {
        msg!("vault residual {} swept to fee sink", residual);
        transfer_checked_signed(out_token_program, sink.vault, out_mint, sink.fee_destination, sink.vault_authority, residual, decimals, seeds)?;
    }
    require!(read_token_amount(sink.vault)? == 0, RouterError::VaultNotDrained);
    Ok((fee, user_receives))
}

/// (fee, net) for a route's gross output — the single fee formula, shared by
/// every entrypoint: `gross > 0`, fee = ceil(gross × 25 bps) ≥ 1, net = gross − fee.
fn split_fee(gross_out: u64) -> Result<(u64, u64)> {
    let s = split_fees(gross_out, None)?; // v0.4.0: one formula, no integrator sink
    Ok((s.fee, s.user_receives))
}

// ---------------------------------------------------------------------------
// B2 — FeeConfig v1: state, constants, accounts, events.
// ---------------------------------------------------------------------------

/// Canonical single-global-PDA seed.
pub const FEE_CONFIG_SEED: &[u8] = b"fee_config";
/// Total account size (8-byte discriminator included). PRE-SIZED with reserved
/// headroom so the future tier upgrade never reallocs/migrates the account.
pub const FEE_CONFIG_SPACE: usize = 512;
/// Bytes of the body that are pinned today (disc + version + bump + spec §4.1
/// fields, see the offset table on `FeeConfig`).
/// v0.3.1 carved `paused: u8` (byte 225) + `guardian: Pubkey` (226..258) from
/// the FRONT of the former 287-byte `reserved` (the documented append-only rule);
/// every pre-existing offset is unchanged and the live account needs no migration
/// (its bytes 225.. were zero: unpaused, no guardian).
pub const FEE_CONFIG_USED: usize = 8 + 1 + 1 + 32 * 4 + 2 * 3 + 1 + 8 + 8 + 32 + 8 + 8 + 8 + 8 + 1 + 32;
/// Forward-compat headroom. New fields may ONLY ever be appended by carving
/// from the FRONT of this region; every offset above it is frozen.
pub const FEE_CONFIG_RESERVED: usize = FEE_CONFIG_SPACE - FEE_CONFIG_USED;
const _: () = assert!(FEE_CONFIG_USED == 258);
const _: () = assert!(FEE_CONFIG_RESERVED == 254);
const _: () = assert!(FEE_CONFIG_PAUSED_OFF == 8 + 1 + 1 + 32 * 4 + 2 * 3 + 1 + 8 + 8 + 32 + 8 + 8 + 8 + 8);

/// `FeeConfig.version` before / after `finalize_tier_writers`.
pub const FEE_CONFIG_VERSION_INIT: u8 = 1;
pub const FEE_CONFIG_VERSION_FINAL: u8 = 2;

// ---- the ratified tier ladder (Constitution v1.2 §7; economic model decision #9) ----
/// Base tier == the live `PROTOCOL_FEE_BPS` (unit-asserted). Also the ceiling no
/// tier/config value may exceed.
pub const DEFAULT_FEE_BPS: u16 = 25;
/// sFORTI epoch-snapshot holder tier.
pub const HOLDER_FEE_BPS: u16 = 15;
/// veFORTI locked tier (the floor; never 0).
pub const LOCKED_FEE_BPS: u16 = 5;
pub const TIER_FLOOR_BPS: u16 = 5;
pub const TIER_CEIL_BPS: u16 = 25;
/// The immutable ratified ladder, asserted at init.
pub const RATIFIED_TIER_BPS: [u16; 3] = [DEFAULT_FEE_BPS, HOLDER_FEE_BPS, LOCKED_FEE_BPS];
/// Holder-streak requirement N (spec §5.1 R3, threat-model Surface 1.1) —
/// pinned at init as an immutable security parameter (spec OQ-3 recommendation;
/// same value the token-side router-v2 reference pins).
pub const STREAK_N: u8 = 4;

// ---- compile-time floors (spec §4.3): governance can NEVER go under these.
//      UNITS (P6 audit fix, WP #6707): the thresholds are compared by the future
//      `route_tiered` resolver against the sFORTI snapshot `amount` (spec R5) and
//      the veFORTI `effective_ve` weight (spec P4) — both are token amounts in
//      BASE UNITS of the 6-decimal Token-2022 FORTI (tokenomics §D.1, genesis
//      spec Δ6, sforti `constants.rs` FORTI_DECIMALS=6). The floors MUST be in the
//      same unit, otherwise "25_000" would be 0.025 sFORTI and governance COULD
//      dust the thresholds (the exact Surface-6.3 capture the floors exist to
//      block). `init_fee_config` / `propose_threshold_change` params are base
//      units too: 25,000 sFORTI = 25_000_000_000; 100,000 veFORTI = 100_000_000_000. ----
/// FORTI (and sFORTI / veFORTI weight) decimals — 6 (Token-2022). If this ever
/// changes the floors below change with it; the const-asserts make the drift loud.
pub const FORTI_DECIMALS: u8 = 6;
/// Base units in one whole FORTI.
pub const FORTI_UNIT: u64 = 10u64.pow(FORTI_DECIMALS as u32);
/// Ratified 25,000 sFORTI holder gate, in sFORTI base units.
pub const MIN_HOLDER_THRESHOLD: u64 = 25_000 * FORTI_UNIT;
/// Ratified 100,000 veFORTI-weight locker gate, in base units (veFORTI weight =
/// locked FORTI base units × multiplier/1e4, so it shares FORTI's unit).
pub const MIN_LOCKER_THRESHOLD: u64 = 100_000 * FORTI_UNIT;
const _: () = assert!(FORTI_UNIT == 1_000_000);
const _: () = assert!(MIN_HOLDER_THRESHOLD == 25_000_000_000);
const _: () = assert!(MIN_LOCKER_THRESHOLD == 100_000_000_000);
/// Rate-limit between COMMITTED threshold changes (~one governance epoch): 7 days.
pub const MIN_CHANGE_INTERVAL_SECS: i64 = 7 * 24 * 60 * 60;
/// Timelock a proposed threshold change must age before commit: 72 h.
pub const THRESHOLD_TIMELOCK_SECS: i64 = 72 * 60 * 60;

/// The single global fee-config account (spec §4.1 layout, version + reserved
/// per WP #6707 §2.2). PINNED OFFSETS — APPEND-ONLY (byte offsets incl. the
/// 8-byte Anchor discriminator):
///
/// ```text
///   0   disc[8]                 (sha256("account:FeeConfig")[..8])
///   8   version: u8             (1 = init, 2 = tier writers finalized)
///   9   bump: u8
///  10   forti_mint: Pubkey      ┐ IMMUTABLE identity block (R4):
///  42   sforti_mint: Pubkey     │ zero at init, written ONCE by
///  74   sforti_program: Pubkey  │ finalize_tier_writers (version 1→2),
/// 106   ve_program: Pubkey      ┘ then NO mutation path exists
/// 138   tier_bps: [u16;3]       = [25,15,5] — IMMUTABLE, NO mutation ix exists
/// 144   streak_n: u8            IMMUTABLE
/// 145   holder_threshold: u64   ┐ tunable: floors + rate-limit + timelock
/// 153   locker_threshold: u64   ┘
/// 161   authority: Pubkey       governance signer (multisig → execute PDA)
/// 193   last_change_ts: i64     rate-limit anchor (init / last commit)
/// 201   pending_holder: u64     ┐ staged change (0 = none)
/// 209   pending_locker: u64     │
/// 217   pending_effective_ts: i64 ┘ commit only when now >= this
/// 225   paused: u8              v0.3.1 (B-M2): 1 = every route ix reverts 6042
/// 226   guardian: Pubkey        v0.3.1: may PAUSE (not unpause); zero = none
/// 258   reserved: [u8; 254]     zero; future fields carve from the front
/// 512   (end)
/// ```
#[account]
pub struct FeeConfig {
    pub version: u8,
    pub bump: u8,
    pub forti_mint: Pubkey,
    pub sforti_mint: Pubkey,
    pub sforti_program: Pubkey,
    pub ve_program: Pubkey,
    pub tier_bps: [u16; 3],
    pub streak_n: u8,
    pub holder_threshold: u64,
    pub locker_threshold: u64,
    pub authority: Pubkey,
    pub last_change_ts: i64,
    pub pending_holder: u64,
    pub pending_locker: u64,
    pub pending_effective_ts: i64,
    pub paused: u8,
    pub guardian: Pubkey,
    pub reserved: [u8; FEE_CONFIG_RESERVED],
}

impl FeeConfig {
    /// Init-time immutability guard for the ladder: exactly the ratified
    /// {25,15,5}, each in [5,25], strictly decreasing.
    pub fn tier_bps_ok(tier_bps: &[u16; 3]) -> bool {
        *tier_bps == RATIFIED_TIER_BPS
            && tier_bps.iter().all(|b| *b >= TIER_FLOOR_BPS && *b <= TIER_CEIL_BPS)
            && tier_bps[0] > tier_bps[1]
            && tier_bps[1] > tier_bps[2]
    }
}

/// Zero-sized marker binding `Program<'info, ThisProgram>` to THIS program's id
/// (`crate::ID`). Used by the CC-1 init gate: `Program<>` checks the passed
/// account key `== ThisProgram::id()`, so together with the `programdata_address`
/// / `upgrade_authority_address` constraints it proves the `init_fee_config`
/// payer is the program's own upgrade authority.
pub struct ThisProgram;
impl anchor_lang::Id for ThisProgram {
    fn id() -> Pubkey {
        crate::ID
    }
}

/// B3: account-less read-only view.
#[derive(Accounts)]
pub struct Version {}

/// One-time init of the global `fee_config` PDA, gated to the upgrade authority
/// (CC-1): `program` pins THIS program and ties to its `program_data`, whose
/// `upgrade_authority_address` must equal the `payer` signer.
#[derive(Accounts)]
pub struct InitFeeConfig<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = FEE_CONFIG_SPACE,
        seeds = [FEE_CONFIG_SEED],
        bump
    )]
    pub fee_config: Account<'info, FeeConfig>,
    /// This program's own account; its `programdata_address` must be
    /// `program_data` (implicitly: it is a BPFUpgradeable program).
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key())
            @ RouterError::NotUpgradeAuthority
    )]
    pub program: Program<'info, ThisProgram>,
    /// The program's ProgramData; its upgrade authority MUST be `payer`.
    #[account(
        constraint = program_data.upgrade_authority_address == Some(payer.key())
            @ RouterError::NotUpgradeAuthority
    )]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

/// Write-once tier writer identity (authority-gated, version 1 → 2).
#[derive(Accounts)]
pub struct FinalizeTierWriters<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [FEE_CONFIG_SEED], bump = fee_config.bump)]
    pub fee_config: Account<'info, FeeConfig>,
}

/// Governance step 1: stage a threshold change (authority-gated, floored,
/// rate-limited, timelocked).
#[derive(Accounts)]
pub struct ProposeThresholdChange<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [FEE_CONFIG_SEED], bump = fee_config.bump)]
    pub fee_config: Account<'info, FeeConfig>,
}

/// Governance step 2: commit a staged change after the timelock (permissionless).
#[derive(Accounts)]
pub struct CommitThresholdChange<'info> {
    #[account(mut, seeds = [FEE_CONFIG_SEED], bump = fee_config.bump)]
    pub fee_config: Account<'info, FeeConfig>,
}

/// Migrate the governance `authority` — current-authority-gated; sole mutator.
#[derive(Accounts)]
pub struct MigrateFeeAuthority<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [FEE_CONFIG_SEED], bump = fee_config.bump)]
    pub fee_config: Account<'info, FeeConfig>,
}

/// v0.3.1 — pause / unpause (`signer` = guardian or authority; unpause = authority only, checked in-instruction).
#[derive(Accounts)]
pub struct SetPaused<'info> {
    pub signer: Signer<'info>,
    #[account(mut, seeds = [FEE_CONFIG_SEED], bump = fee_config.bump)]
    pub fee_config: Account<'info, FeeConfig>,
}

/// v0.3.1 — set / clear the guardian (authority-gated).
#[derive(Accounts)]
pub struct SetGuardian<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [FEE_CONFIG_SEED], bump = fee_config.bump)]
    pub fee_config: Account<'info, FeeConfig>,
}

#[event]
pub struct FeeConfigInitialized {
    pub authority: Pubkey,
    pub holder_threshold: u64,
    pub locker_threshold: u64,
    pub tier_bps: [u16; 3],
}
#[event]
pub struct TierWritersFinalized {
    pub forti_mint: Pubkey,
    pub sforti_mint: Pubkey,
    pub sforti_program: Pubkey,
    pub ve_program: Pubkey,
}
#[event]
pub struct ThresholdChangeProposed {
    pub new_holder: u64,
    pub new_locker: u64,
    pub effective_ts: i64,
}
#[event]
pub struct ThresholdChangeCommitted {
    pub holder_threshold: u64,
    pub locker_threshold: u64,
}
#[event]
pub struct FeeAuthorityMigrated {
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}
/// v0.3.1 — emitted by `set_paused`.
#[event]
pub struct PauseSet {
    pub paused: bool,
    pub by: Pubkey,
}
/// v0.3.1 — emitted by `set_guardian`.
#[event]
pub struct GuardianSet {
    pub old_guardian: Pubkey,
    pub new_guardian: Pubkey,
}

#[event]
pub struct RouteExecuted {
    pub user: Pubkey,
    pub hops: u8,
    pub amount_in: u64,
    pub gross_out: u64,
    pub fee: u64,
    pub user_receives: u64,
}

/// v0.4.0 — emitted by `route_v3` next to the unchanged `RouteExecuted`:
/// the integrator sink and the amount that landed there (`floor(gross × bps)`;
/// may be 0 for dust). `RouteExecuted.gross_out − fee − amount == user_receives`.
#[event]
pub struct IntegratorFeePaid {
    pub user: Pubkey,
    pub integrator_wallet: Pubkey,
    pub integrator_fee_destination: Pubkey,
    pub bps: u16,
    pub amount: u64,
}

/// v0.3.0 — companion to `RouteExecuted` for delegated routes: who acted
/// (`delegate`), who paid rent (`payer`), for whom (`user` = the token-account
/// owner, the same value `RouteExecuted.user` carries) and on which mints.
#[event]
pub struct DelegatedRouteExecuted {
    pub user: Pubkey,
    pub delegate: Pubkey,
    pub payer: Pubkey,
    pub input_mint: Pubkey,
    pub output_mint: Pubkey,
}

#[cfg(test)]
mod fee_tests {
    use super::{
        ceil_fee, check_delegation, degen_buy_max_debit, floor_fee, graduation_grad_sum, legs_prefix_ok,
        looks_like_mint, looks_like_token_account, parse_token_delegate, split_fee, split_fees,
        MAX_INTEGRATOR_FEE_BPS,
        tlv_has_extension, FeeConfig, VAULT_AUTHORITY_SEED, ACCOUNT_TYPE_ACCOUNT,
        ACCOUNT_TYPE_OFF, EXT_TRANSFER_FEE_CONFIG, EXT_TRANSFER_HOOK, TLV_START,
        ACCOUNT_TYPE_MINT, DEFAULT_FEE_BPS, FEE_CONFIG_PAUSED_OFF, FEE_CONFIG_RESERVED,
        FEE_CONFIG_SEED, FEE_CONFIG_SPACE, FEE_CONFIG_USED, FORTI_DECIMALS, FORTI_UNIT,
        HOLDER_FEE_BPS, LOCKED_FEE_BPS, MAX_FEE_BPS, MIN_CHANGE_INTERVAL_SECS,
        MIN_HOLDER_THRESHOLD, MIN_LOCKER_THRESHOLD, PROTOCOL_FEE_BPS, RATIFIED_TIER_BPS,
        ROUTER_VERSION, SPL_MINT_LEN, TA_LEN, TA_STATE_INITIALIZED, THRESHOLD_TIMELOCK_SECS,
        TIER_CEIL_BPS, TIER_FLOOR_BPS, DEGEN_BUY_FEE_PPM, PPM_DENOM,
    };
    use anchor_lang::prelude::*;
    use anchor_lang::Discriminator;

    const INIT: Option<u8> = Some(TA_STATE_INITIALIZED);

    // Round-2 Low fix: an 82-byte MINT must NOT be classified as a token account.
    #[test]
    fn mint_len_is_not_a_token_account() {
        assert!(!looks_like_token_account(SPL_MINT_LEN, None, INIT)); // 82-byte mint -> not an account
        assert!(looks_like_mint(SPL_MINT_LEN, None)); // ...it's a mint
    }
    #[test]
    fn base_token_account_classifies() {
        assert!(looks_like_token_account(TA_LEN, None, INIT)); // 165 + initialized -> account
        assert!(!looks_like_mint(TA_LEN, None)); // 165 -> not a mint
    }
    #[test]
    fn extended_uses_account_type_byte() {
        // >165 with type byte 2 = Account, 1 = Mint.
        assert!(looks_like_token_account(200, Some(ACCOUNT_TYPE_ACCOUNT), INIT));
        assert!(!looks_like_token_account(200, Some(ACCOUNT_TYPE_MINT), INIT));
        assert!(looks_like_mint(200, Some(ACCOUNT_TYPE_MINT)));
        assert!(!looks_like_mint(200, Some(ACCOUNT_TYPE_ACCOUNT)));
    }
    #[test]
    fn short_or_ambiguous_is_neither() {
        assert!(!looks_like_token_account(72, None, INIT)); // old min-len is no longer enough
        assert!(!looks_like_mint(100, None)); // between 82 and 165, no type byte
    }
    // S3 (round-3 L-2): an allocated-but-UNINITIALIZED (state 0) or FROZEN (2)
    // token-program-owned account with the right shape must NOT classify.
    #[test]
    fn uninitialized_or_frozen_is_not_a_token_account() {
        assert!(!looks_like_token_account(TA_LEN, None, Some(0)));
        assert!(!looks_like_token_account(TA_LEN, None, Some(2)));
        assert!(!looks_like_token_account(TA_LEN, None, None));
        assert!(!looks_like_token_account(200, Some(ACCOUNT_TYPE_ACCOUNT), Some(0)));
        assert!(looks_like_token_account(200, Some(ACCOUNT_TYPE_ACCOUNT), INIT));
    }

    // ---- B2: FeeConfig v1 invariants ----
    // The live const IS the ratified base tier (code/config drift impossible).
    #[test]
    fn protocol_fee_is_base_tier() {
        assert_eq!(PROTOCOL_FEE_BPS, RATIFIED_TIER_BPS[0] as u64);
        assert_eq!(RATIFIED_TIER_BPS, [25, 15, 5]);
        assert_eq!(RATIFIED_TIER_BPS, [DEFAULT_FEE_BPS, HOLDER_FEE_BPS, LOCKED_FEE_BPS]);
        assert!(FeeConfig::tier_bps_ok(&RATIFIED_TIER_BPS));
        assert!(TIER_FLOOR_BPS >= 1 && TIER_CEIL_BPS as u64 <= MAX_FEE_BPS);
    }
    // Only the exact ratified ladder passes: no re-ordering, no zero tier, no
    // ceiling breach, no flat ladder.
    #[test]
    fn tier_bps_guard_rejects_everything_else() {
        assert!(!FeeConfig::tier_bps_ok(&[25, 15, 0]));
        assert!(!FeeConfig::tier_bps_ok(&[30, 15, 5]));
        assert!(!FeeConfig::tier_bps_ok(&[5, 15, 25]));
        assert!(!FeeConfig::tier_bps_ok(&[25, 25, 5]));
        assert!(!FeeConfig::tier_bps_ok(&[25, 15, 6]));
        assert!(!FeeConfig::tier_bps_ok(&[20, 15, 5]));
    }
    // Pinned layout: 512-byte account, 258 used (225 in v0.2.0/v0.3.0 + the
    // v0.3.1 `paused` byte + `guardian`), 254 reserved; the Borsh body
    // serializes to exactly SPACE-8 so the on-chain offsets documented on
    // `FeeConfig` are the real ones and the account never needs realloc.
    #[test]
    fn fee_config_layout_is_pinned() {
        assert_eq!(FEE_CONFIG_SPACE, 512);
        assert_eq!(FEE_CONFIG_USED, 258);
        assert_eq!(FEE_CONFIG_RESERVED, 254);
        assert_eq!(FEE_CONFIG_PAUSED_OFF, 225);
        let guardian = Pubkey::new_unique();
        let cfg = FeeConfig {
            version: 1,
            bump: 255,
            forti_mint: Pubkey::default(),
            sforti_mint: Pubkey::default(),
            sforti_program: Pubkey::default(),
            ve_program: Pubkey::default(),
            tier_bps: RATIFIED_TIER_BPS,
            streak_n: 4,
            holder_threshold: MIN_HOLDER_THRESHOLD,
            locker_threshold: MIN_LOCKER_THRESHOLD,
            authority: Pubkey::new_unique(),
            last_change_ts: 1,
            pending_holder: 0,
            pending_locker: 0,
            pending_effective_ts: 0,
            paused: 1,
            guardian,
            reserved: [0u8; FEE_CONFIG_RESERVED],
        };
        let mut buf = Vec::new();
        cfg.try_serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), FEE_CONFIG_SPACE);
        assert_eq!(buf[225], 1); // paused
        assert_eq!(&buf[226..258], guardian.as_ref()); // guardian
        assert!(buf[258..].iter().all(|b| *b == 0));
        // The v0.2.0 live bytes (paused/guardian region zero) decode as unpaused + no guardian.
        let mut live = buf.clone();
        live[225..].fill(0);
        let decoded = FeeConfig::try_deserialize(&mut &live[..]).unwrap();
        assert_eq!(decoded.paused, 0);
        assert_eq!(decoded.guardian, Pubkey::default());
        assert_eq!(decoded.authority, cfg.authority);
        // Spot-check the documented offsets.
        assert_eq!(buf[8], 1); // version
        assert_eq!(buf[9], 255); // bump
        assert_eq!(&buf[138..144], &[25, 0, 15, 0, 5, 0]); // tier_bps LE
        assert_eq!(buf[144], 4); // streak_n
        assert_eq!(&buf[145..153], &MIN_HOLDER_THRESHOLD.to_le_bytes());
        assert_eq!(&buf[153..161], &MIN_LOCKER_THRESHOLD.to_le_bytes());
        assert_eq!(&buf[161..193], cfg.authority.as_ref());
        assert_eq!(&buf[193..201], &1i64.to_le_bytes());
    }
    // v0.3.1: the constant fee_config address IS the canonical PDA.
    #[test]
    fn fee_config_pda_constant_matches_derivation() {
        let (pda, _bump) = Pubkey::find_program_address(&[FEE_CONFIG_SEED], &crate::ID);
        assert_eq!(pda, super::fee_config_pda::ID);
        assert!(!pda.is_on_curve());
    }
    // v0.3.1 A-7: the legs length-prefix guard.
    #[test]
    fn legs_prefix_guard() {
        let v2 = crate::instruction::RouteV2::DISCRIMINATOR;
        let dl = crate::instruction::RouteV2Delegated::DISCRIMINATOR;
        let ix = |disc: &[u8], len: u32, body: &[u8]| { let mut d = disc.to_vec(); d.extend_from_slice(&len.to_le_bytes()); d.extend_from_slice(body); d };
        // well-formed: len == bytes present (1 leg + 2 u64)
        assert!(legs_prefix_ok(&ix(v2, 1, &[0u8; 17])));
        assert!(legs_prefix_ok(&ix(dl, 2, &[0u8; 18])));
        // len prefix may be <= remaining bytes (Borsh ignores trailing bytes)
        assert!(legs_prefix_ok(&ix(v2, 0, &[0u8; 16])));
        // overflowing prefixes: 4 GiB, 1 MiB, 33 KiB (heap), and "one past the end"
        for len in [u32::MAX, 1_000_000, 33 * 1024, 18] {
            assert!(!legs_prefix_ok(&ix(v2, len, &[0u8; 17])), "len {len}");
            assert!(!legs_prefix_ok(&ix(dl, len, &[0u8; 17])), "len {len}");
        }
        // not our business: other discriminators (snipe, version, junk), short data -> Anchor decides
        assert!(legs_prefix_ok(&ix(crate::instruction::RouteV2Snipe::DISCRIMINATOR, u32::MAX, &[0u8; 12])));
        assert!(legs_prefix_ok(&ix(crate::instruction::Version::DISCRIMINATOR, u32::MAX, &[])));
        // v0.4.0: route_v3's first arg is `legs` too — guarded identically
        let v3 = crate::instruction::RouteV3::DISCRIMINATOR;
        assert!(legs_prefix_ok(&ix(v3, 1, &[0u8; 19])));
        for len in [u32::MAX, 1_000_000, 33 * 1024, 20] { assert!(!legs_prefix_ok(&ix(v3, len, &[0u8; 19])), "v3 len {len}"); }
        assert!(legs_prefix_ok(&[0u8; 12]));
        assert!(legs_prefix_ok(&v2[..5]));
        assert!(legs_prefix_ok(&ix(v2, 0, &[])[..10])); // truncated prefix -> Anchor 102
        assert!(legs_prefix_ok(&[]));
    }
    // ---- v0.4.0: integrator fee (route_v3) ----
    // The protocol fee is a function of GROSS alone: identical with and without
    // an integrator sink, for every bps in range, across the dust range.
    #[test]
    fn integrator_fee_never_touches_the_protocol_fee() {
        for gross in [1u64, 2, 3, 49, 99, 100, 1_050, 3_333_333, 1_000_000, u64::MAX / 400] {
            let base = split_fees(gross, None).unwrap();
            assert_eq!(base.fee, ceil_fee(gross, PROTOCOL_FEE_BPS).unwrap());
            assert_eq!(base.integrator_fee, 0);
            assert_eq!(base.user_receives, gross - base.fee);
            assert_eq!(base.gross, gross);
            for bps in [1u16, 25, 100, 255, MAX_INTEGRATOR_FEE_BPS] {
                let s = split_fees(gross, Some(bps)).unwrap();
                assert_eq!(s.fee, base.fee, "protocol fee unchanged (gross {gross}, bps {bps})");
                assert_eq!(s.integrator_fee, floor_fee(gross, bps as u64).unwrap());
                assert_eq!(s.integrator_fee, (gross as u128 * bps as u128 / 10_000) as u64);
                assert_eq!(s.fee + s.integrator_fee + s.user_receives, gross, "conservation");
                assert!(s.user_receives <= base.user_receives);
                assert_eq!(base.user_receives - s.user_receives, s.integrator_fee, "the integrator fee comes out of the USER's net, never the protocol's");
            }
        }
    }
    // Cap: 0 and cap+1 are rejected by the formula itself (the handler checks
    // too); the cap is exactly 300 bps and both fees fit in gross at the cap.
    #[test]
    fn integrator_fee_cap() {
        assert_eq!(MAX_INTEGRATOR_FEE_BPS, 300);
        assert!(split_fees(1_000_000, Some(0)).is_err());
        assert!(split_fees(1_000_000, Some(MAX_INTEGRATOR_FEE_BPS + 1)).is_err());
        assert!(split_fees(1_000_000, Some(u16::MAX)).is_err());
        let s = split_fees(1_000_000, Some(MAX_INTEGRATOR_FEE_BPS)).unwrap();
        assert_eq!((s.fee, s.integrator_fee, s.user_receives), (2_500, 30_000, 967_500));
        // dust: protocol takes its ≥1 unit first; the integrator floor rounds to 0; no underflow anywhere
        for gross in 1..=40u64 {
            let s = split_fees(gross, Some(MAX_INTEGRATOR_FEE_BPS)).unwrap();
            assert_eq!(s.fee, 1);
            assert_eq!(s.integrator_fee, gross * 300 / 10_000);
            assert_eq!(s.user_receives, gross - 1 - s.integrator_fee);
        }
        assert!(split_fees(0, Some(1)).is_err()); // NoNetOutput
        assert_eq!(floor_fee(1_000_000, 100).unwrap(), 10_000);
        assert_eq!(floor_fee(9_999, 1).unwrap(), 0);
        assert_eq!(floor_fee(10_000, 1).unwrap(), 1);
        assert_eq!(floor_fee(u64::MAX, 300).unwrap(), (u64::MAX as u128 * 300 / 10_000) as u64); // u128 math, no overflow
    }

    // v0.3.1 C-1: Degen buy debit bound = amount + ceil(1%) + measured rent.
    #[test]
    fn degen_buy_debit_bound() {
        assert_eq!(DEGEN_BUY_FEE_PPM, 10_000);
        assert_eq!(PPM_DENOM, 1_000_000);
        assert_eq!(degen_buy_max_debit(100_000_000, 0).unwrap(), 101_000_000); // live-verified: 0.1 XNT -> 101_000_000 debited
        assert_eq!(degen_buy_max_debit(100_000_000, 4_113_360).unwrap(), 105_113_360); // + meme (2,074,080) + WXNT (2,039,280) ATA rents
        assert_eq!(degen_buy_max_debit(1, 0).unwrap(), 2); // ceil: 0.01 -> 1
        assert_eq!(degen_buy_max_debit(99, 0).unwrap(), 100); // ceil(0.99) = 1
        assert_eq!(degen_buy_max_debit(100, 0).unwrap(), 101); // exact 1
        assert!(degen_buy_max_debit(u64::MAX, 1).is_err()); // overflow is an error, never a wrap
    }
    // R-1 (v0.3.1): the graduation-allowance arithmetic (`graduation_grad_sum`,
    // the pure half of `degen_graduation_allowance`). Numbers are the LIVE
    // rent-exempt minimums measured on the real graduating buy
    // (`v0.3.1-review` RV-C2a / `tests/degen-live.test.ts` DL5):
    // pool_state 5,324,400 · observation 29,252,880 · lp_mint 1,461,600 ·
    // 3× LP-ATA 2,039,280 each · vault1 2,039,280 (vault0's rent-exempt part
    // is the same formula; its migrated LIQUIDITY is excluded because the
    // formula is `minimum_balance(data_len)`, never the observed lamport
    // delta) · create_pool_fee 100,000,000.
    #[test]
    fn graduation_grad_sum_sums_created_account_rents_plus_capped_fee() {
        // Representative rent-exempt minimums for a graduation's new accounts
        // (standard SPL Token account 165 B -> 2,039,280; standard SPL mint
        // 82 B -> 1,461,600 — both well-known constants; the pool/observation
        // sizes are XDEX-specific and are read live via `Rent::minimum_balance`
        // in `degen_graduation_allowance`, not asserted here). This test only
        // pins the SUMMATION behaviour; the exact live total (and that the
        // sum stays inside a sane ceiling of the measured ~0.134 XNT cost) is
        // pinned end-to-end by `tests/degen-live.test.ts` DL5 against the
        // real Degen + XDEX bytes.
        let created = [5_324_400u64, 29_252_880, 1_461_600, 2_039_280, 2_039_280, 2_039_280, 2_039_280];
        let create_pool_fee = 100_000_000u64;
        let sum_rents: u64 = created.iter().sum();
        assert_eq!(
            graduation_grad_sum(&created, create_pool_fee, create_pool_fee).unwrap(),
            sum_rents + create_pool_fee,
        );
        // The fee term is additive but independent of the rent sum.
        assert_eq!(
            graduation_grad_sum(&created, 0, create_pool_fee).unwrap(),
            sum_rents,
        );
    }
    // A rogue AMM cannot raise the allowance beyond the REAL configured fee —
    // an inflated observed delta is capped at `create_pool_fee`.
    #[test]
    fn graduation_grad_sum_caps_the_fee_delta_at_amm_configured_fee() {
        assert_eq!(graduation_grad_sum(&[], 500_000_000, 100_000_000).unwrap(), 100_000_000);
        assert_eq!(graduation_grad_sum(&[], 0, 100_000_000).unwrap(), 0);
        assert_eq!(graduation_grad_sum(&[], 100_000_000, 100_000_000).unwrap(), 100_000_000);
    }
    // No accounts newly created (a re-graduation replay / non-graduating
    // path) contributes zero rent, only the (capped) fee delta.
    #[test]
    fn graduation_grad_sum_empty_created_set() {
        assert_eq!(graduation_grad_sum(&[], 0, 0).unwrap(), 0);
    }
    // Overflow anywhere (rent sum or the final add) is an error, never a wrap.
    #[test]
    fn graduation_grad_sum_overflow_is_an_error() {
        assert!(graduation_grad_sum(&[u64::MAX, 1], 0, 0).is_err());
        assert!(graduation_grad_sum(&[u64::MAX], u64::MAX, u64::MAX).is_err());
    }
    // Governance knobs: floors are the ratified gates; timelock >= 48h; the
    // rate-limit is at least as long as the timelock (no stacking).
    #[test]
    fn governance_constants_sane() {
        // Floors are BASE UNITS of the 6-decimal FORTI (P6 audit fix): 25,000
        // sFORTI and 100,000 veFORTI weight — NOT the whole-token numerals.
        assert_eq!(FORTI_DECIMALS, 6);
        assert_eq!(FORTI_UNIT, 1_000_000);
        assert_eq!(MIN_HOLDER_THRESHOLD, 25_000 * FORTI_UNIT);
        assert_eq!(MIN_LOCKER_THRESHOLD, 100_000 * FORTI_UNIT);
        assert_eq!(MIN_HOLDER_THRESHOLD, 25_000_000_000);
        assert_eq!(MIN_LOCKER_THRESHOLD, 100_000_000_000);
        // A whole-token numeral must be BELOW the floor (the pre-fix bug shape).
        assert!(25_000 < MIN_HOLDER_THRESHOLD && 100_000 < MIN_LOCKER_THRESHOLD);
        assert!(THRESHOLD_TIMELOCK_SECS >= 48 * 3600);
        assert!(MIN_CHANGE_INTERVAL_SECS >= THRESHOLD_TIMELOCK_SECS);
    }
    // B3: the on-chain version marker mirrors the crate version (== IDL version).
    #[test]
    fn version_marker() {
        assert_eq!(ROUTER_VERSION, "0.4.3");
    }

    // ---- v0.3.0 (#450): delegation parse/check, shared fee split, drain ----
    fn token_bytes(delegate: Option<(Pubkey, u64)>) -> Vec<u8> {
        let mut d = vec![0u8; TA_LEN];
        d[108] = TA_STATE_INITIALIZED;
        if let Some((k, a)) = delegate {
            d[72..76].copy_from_slice(&1u32.to_le_bytes());
            d[76..108].copy_from_slice(k.as_ref());
            d[121..129].copy_from_slice(&a.to_le_bytes());
        }
        d
    }
    #[test]
    fn delegate_parse_none_when_unset() {
        assert_eq!(parse_token_delegate(&token_bytes(None)), None);
        // tag 1 but truncated buffer -> None (never reads out of bounds)
        assert_eq!(parse_token_delegate(&token_bytes(None)[..100]), None);
    }
    #[test]
    fn delegate_parse_reads_key_and_amount() {
        let k = Pubkey::new_unique();
        assert_eq!(parse_token_delegate(&token_bytes(Some((k, 12_345)))), Some((k, 12_345)));
        // Token-2022 extended account: same base offsets, longer buffer.
        let mut ext = token_bytes(Some((k, 7)));
        ext.resize(200, 0);
        ext[165] = ACCOUNT_TYPE_ACCOUNT;
        assert_eq!(parse_token_delegate(&ext), Some((k, 7)));
    }
    #[test]
    fn delegation_check_rejects_missing_wrong_or_short() {
        let d = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        assert!(check_delegation(None, &d, 1).is_err()); // NotDelegate
        assert!(check_delegation(Some((other, 1_000)), &d, 1).is_err()); // NotDelegate
        assert!(check_delegation(Some((d, 999)), &d, 1_000).is_err()); // InsufficientDelegation
        assert!(check_delegation(Some((d, 1_000)), &d, 1_000).is_ok()); // exact
        assert!(check_delegation(Some((d, u64::MAX)), &d, 1_000).is_ok()); // surplus
    }
    // The delegated + snipe paths use the SAME fee numbers as route_v2:
    // fee = ceil(gross * 25 bps) >= 1, net = gross - fee, gross must be > 0.
    #[test]
    fn split_fee_matches_route_v2_formula() {
        for gross in [1u64, 49, 1_050, 3_333_333, 1_000_000, u64::MAX] {
            let (fee, net) = split_fee(gross).unwrap();
            assert_eq!(fee, ceil_fee(gross, PROTOCOL_FEE_BPS).unwrap());
            assert_eq!(net, gross - fee);
            assert!(fee >= 1);
        }
        assert_eq!(split_fee(3_333_333).unwrap(), (8_334, 3_324_999));
        assert_eq!(split_fee(1).unwrap(), (1, 0)); // dust: fee 1, user 0
        assert!(split_fee(0).is_err()); // NoNetOutput
    }
    // Drain arithmetic: fee + net + residual == everything the vault held, so
    // the exit assertion (balance == 0) is exactly the "nothing left behind" invariant.
    #[test]
    fn vault_drain_is_exact() {
        for (gross, residual) in [(1u64, 0u64), (3_333_333, 0), (1_000_000, 777), (5, 5)] {
            let (fee, net) = split_fee(gross).unwrap();
            assert_eq!(fee + net + residual, gross + residual);
        }
    }
    // M-1: the TLV walk finds TransferFeeConfig (1) / TransferHook (14) on an
    // extended Token-2022 mint and nothing on base mints / token accounts.
    fn t22_mint(exts: &[(u16, usize)]) -> Vec<u8> {
        let mut d = vec![0u8; TLV_START];
        d[ACCOUNT_TYPE_OFF] = ACCOUNT_TYPE_MINT;
        for &(t, len) in exts {
            d.extend_from_slice(&t.to_le_bytes());
            d.extend_from_slice(&(len as u16).to_le_bytes());
            d.extend(std::iter::repeat(0xAA).take(len));
        }
        d
    }
    #[test]
    fn tlv_walk_finds_transfer_fee_and_hook() {
        let fee_mint = t22_mint(&[(18, 64), (EXT_TRANSFER_FEE_CONFIG, 108)]); // MetadataPointer, TransferFeeConfig
        assert!(tlv_has_extension(&fee_mint, EXT_TRANSFER_FEE_CONFIG).unwrap());
        assert!(!tlv_has_extension(&fee_mint, EXT_TRANSFER_HOOK).unwrap());
        let hook_mint = t22_mint(&[(EXT_TRANSFER_HOOK, 64)]);
        assert!(tlv_has_extension(&hook_mint, EXT_TRANSFER_HOOK).unwrap());
        assert!(!tlv_has_extension(&hook_mint, EXT_TRANSFER_FEE_CONFIG).unwrap());
        let plain = t22_mint(&[(18, 64), (19, 40)]); // USDC.X-shaped: metadata only
        assert!(!tlv_has_extension(&plain, EXT_TRANSFER_FEE_CONFIG).unwrap());
        assert!(!tlv_has_extension(&vec![0u8; SPL_MINT_LEN], EXT_TRANSFER_FEE_CONFIG).unwrap()); // base mint
        let mut acct = vec![0u8; 200]; acct[ACCOUNT_TYPE_OFF] = ACCOUNT_TYPE_ACCOUNT; // token account, not a mint
        assert!(!tlv_has_extension(&acct, EXT_TRANSFER_FEE_CONFIG).unwrap());
        assert_eq!(EXT_TRANSFER_FEE_CONFIG, 1);
    }

    // The vault authority PDA is canonical and off-curve (no private key can exist).
    #[test]
    fn vault_authority_pda_is_off_curve() {
        let (pda, _bump) = Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED], &crate::ID);
        assert!(!pda.is_on_curve());
        assert_eq!(VAULT_AUTHORITY_SEED, b"vault_authority");
    }

    // The fee bps constant is within the hard cap (compile-time-ish invariant).
    #[test]
    fn fee_bps_within_cap() {
        assert!(PROTOCOL_FEE_BPS <= MAX_FEE_BPS);
    }

    // 20 bps of a round amount, exact.
    #[test]
    fn fee_exact() {
        assert_eq!(ceil_fee(1_000_000, 20).unwrap(), 2_000);
    }

    // Rounds UP (protocol-favourable): 20 bps of 1_050 = 2.1 -> 3.
    #[test]
    fn fee_rounds_up() {
        assert_eq!(ceil_fee(1_050, 20).unwrap(), 3);
    }

    // Dust still pays >= 1 unit — sub-unit splitting cannot evade the fee.
    #[test]
    fn dust_pays_one() {
        assert_eq!(ceil_fee(1, 20).unwrap(), 1);
        assert_eq!(ceil_fee(49, 20).unwrap(), 1); // 0.098 -> 1
    }

    // Zero in either operand -> zero fee (only reachable when gross_out == 0).
    #[test]
    fn zero() {
        assert_eq!(ceil_fee(0, 20).unwrap(), 0);
        assert_eq!(ceil_fee(1_000_000, 0).unwrap(), 0);
    }

    // Fee never exceeds the amount, even at the cap.
    #[test]
    fn capped_at_amount() {
        assert!(ceil_fee(u64::MAX, MAX_FEE_BPS).unwrap() <= u64::MAX);
        assert_eq!(ceil_fee(5, 100).unwrap(), 1); // 1% of 5 = 0.05 -> 1, <= 5
    }
}

#[error_code]
pub enum RouterError {
    #[msg("num_hops must be between 1 and MAX_HOPS")]
    BadHopCount,
    #[msg("remaining_accounts length must equal num_hops * 13")]
    BadAccountCount,
    #[msg("amount_in must be greater than zero")]
    ZeroAmountIn,
    #[msg("swap authority must be the transaction's user")]
    AuthorityNotUser,
    #[msg("swap authority must be a signer")]
    AuthorityNotSigner,
    #[msg("pool account is not owned by the XDEX program")]
    PoolNotXdex,
    #[msg("token account is not owned by the transaction's user")]
    AtaNotUser,
    #[msg("hop input does not chain from the previous hop output")]
    BrokenRoute,
    #[msg("account is not a valid SPL/Token-2022 token account")]
    NotATokenAccount,
    #[msg("account is not a valid SPL/Token-2022 mint")]
    NotAMint,
    #[msg("token account mint does not match the hop's mint account")]
    MintMismatch,
    #[msg("token program is not SPL Token or Token-2022")]
    BadTokenProgram,
    #[msg("output mint has a TransferHook extension (unsupported)")]
    TransferHookUnsupported,
    #[msg("route produced no net output (losing round trip)")]
    NoNetOutput,
    #[msg("fee destination is not the fee wallet's canonical output-mint ATA")]
    WrongFeeDestination,
    #[msg("protocol fee bps exceeds the hard cap")]
    FeeConfig,
    #[msg("arithmetic overflow")]
    MathOverflow,
    #[msg("route output below minimum_amount_out (slippage)")]
    SlippageExceeded,
    // --- v2 (Degen leg support) ---
    #[msg("unknown leg kind (expected 0=XDEX, 1=Degen buy, 2=Degen sell)")]
    BadLegKind,
    #[msg("account is not owned by the Degen program")]
    NotDegenAccount,
    #[msg("expected the WXNT mint on the XNT-hub side of this hop")]
    ExpectedWxntInput,
    #[msg("unsupported leg sequence / medium transition")]
    UnsupportedLegSequence,
    // --- v0.2.0 (WP #6707 B2: fee_config governance writes only; never a swap revert) ---
    #[msg("caller is not the fee_config governance authority")]
    Unauthorized,
    #[msg("initializer is not the program's upgrade authority (CC-1 init gate)")]
    NotUpgradeAuthority,
    #[msg("tier_bps must be exactly [25,15,5], each in [5,25], strictly decreasing, base == PROTOCOL_FEE_BPS")]
    InvalidTierBps,
    #[msg("threshold below the in-program floor (governance may never go under the ratified value)")]
    ThresholdTooLow,
    #[msg("a threshold change was committed too recently (rate-limit)")]
    RateLimited,
    #[msg("no pending threshold change to commit")]
    NoPendingChange,
    #[msg("threshold-change timelock has not elapsed")]
    TimelockNotElapsed,
    #[msg("tier writer identity already finalized (version != 1 or identity non-zero)")]
    AlreadyFinalized,
    #[msg("tier writer identity must be non-zero and distinct")]
    InvalidIdentity,
    #[msg("authority must be a non-default pubkey")]
    InvalidAuthority,
    // --- v0.3.0 (#450: route_v2_delegated / route_v2_snipe) — APPENDED ---
    #[msg("route_v2_delegated supports XDEX legs only (leg kind 0)")]
    DelegatedLegUnsupported,
    #[msg("delegate_authority is not the SPL delegate on user_input_ata")]
    NotDelegate,
    #[msg("delegated_amount on user_input_ata is below initial_amount_in")]
    InsufficientDelegation,
    #[msg("hop authority slot must be the delegate (hop 0) or the router vault authority (later hops)")]
    BadHopAuthority,
    #[msg("hop output is not the router vault ATA for the hop's output mint")]
    WrongVaultAta,
    #[msg("user_output_ata is not the user's canonical output-mint ATA")]
    WrongUserDestination,
    #[msg("router vault ATA not empty at exit")]
    VaultNotDrained,
    #[msg("route_v2_delegated does not support transfer-fee output mints (use route_v2)")]
    TransferFeeUnsupported,
    // --- v0.3.1 (audit patch set) — APPENDED, codes 6040..6042 ---
    #[msg("input account debit does not equal the hop's amount_in (C-1 input-debit invariant)")]
    InputDebitMismatch,
    #[msg("legs length prefix exceeds the instruction data (A-7)")]
    BadLegsLength,
    #[msg("router is paused (fee_config.paused)")]
    Paused,
    // --- v0.4.0 (integrator fee, #7264) — APPENDED, codes 6043..6045 ---
    #[msg("integrator_fee_bps must be between 1 and MAX_INTEGRATOR_FEE_BPS (300)")]
    BadIntegratorFeeBps,
    #[msg("integrator_fee_destination is not the integrator wallet's canonical output-mint ATA")]
    WrongIntegratorFeeDestination,
    #[msg("integrator_wallet must be a non-default pubkey")]
    InvalidIntegratorWallet,
    #[msg("integrator_fee_destination does not exist — the integrator must create its ATA for the output mint first")]
    IntegratorFeeDestinationMissing,
}
