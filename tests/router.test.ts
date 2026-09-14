/**
 * fortiblox-router tests (LiteSVM) — v0.2.0 (WP #6707 bundle).
 *
 * Tiers:
 *  (A) Input-validation reverts that need NO XDEX — the guards that fire before
 *      any CPI (bad hop count, zero amount, bad account count, bad leg kind).
 *  (B1) v1 `route` DELETION regressions: the retired discriminator
 *      `e517cb977ae3ad2a` must hit Anchor's InstructionFallbackNotFound (error
 *      101) BEFORE any account is deserialized or mutated — a stale client gets a
 *      clean, fee-free revert. Sweep-regression (a mid-route hop must never spend
 *      idle ATA balance) lives in money-path.test.ts (needs real CPIs).
 *  (B3) `version` view: logs + returns the semantic version as return data.
 *
 * Full money-path (real CPIs via the mock AMM) is tests/money-path.test.ts;
 * FeeConfig governance is tests/fee-config.test.ts; IDL/wire pins are
 * tests/wire-compat.test.ts. `ceil_fee` / classifier / layout invariants are
 * unit-tested in-crate (programs/fortiblox-router/src/lib.rs #[cfg(test)]).
 */
import { LiteSVM } from "litesvm";
import { PublicKey, Transaction, TransactionInstruction, Keypair } from "@solana/web3.js";
import { assert } from "chai";
import { NEW_FEE_WALLET } from "./lib/live";
import { createHash } from "crypto";
import { FEE_CONFIG, seedFeeConfig } from "./lib/live";

const PROGRAM_ID = new PublicKey("3geAsZiNaWDuTVtTbdWVQRitd55jY4UoWeeBmJFTJZmE");
const SO = "target/deploy/fortiblox_router.so";

/** WP #7386: the pinned protocol-fee sink has ONE source of truth in the test
 *  tree — re-declaring the literal per file is how it drifts. */
const FEE_WALLET = NEW_FEE_WALLET;
const SYSTEM_PROGRAM = new PublicKey("11111111111111111111111111111111");
const ATA_PROGRAM = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const XDEX_PROGRAM = new PublicKey("sEsYH97wqmfnkzHedjNcw3zyJdPvUmsa9AixhS4b4fN");
const DEGEN_PROGRAM = new PublicKey("degenDXVPhS7vgu3hcdzGA7T6dfCe6qTYyVM7npP3pc");
const TOKEN_PROGRAM = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/** Anchor error code: InstructionFallbackNotFound (unknown discriminator). */
const ANCHOR_INSTRUCTION_FALLBACK_NOT_FOUND = 101;
/** The RETIRED v1 discriminator — never reuse. */
const V1_ROUTE_DISC_HEX = "e517cb977ae3ad2a";

function disc(name: string): Buffer { return createHash("sha256").update("global:" + name).digest().subarray(0, 8); }
function u8(n: number) { return Buffer.from([n]); }
function u64(n: bigint) { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; }
function vecU8(arr: number[]): Buffer { const len = Buffer.alloc(4); len.writeUInt32LE(arr.length); return Buffer.concat([len, Buffer.from(arr)]); }

/** Custom (program) error code out of a failed LiteSVM result, or null. */
export function customCode(res: any): number | null {
  const e = res?.err?.();
  const inner = e?.err?.();
  return inner && typeof inner.code === "number" ? inner.code : null;
}

function send(svm: LiteSVM, user: Keypair, ix: TransactionInstruction) {
  const tx = new Transaction().add(ix);
  tx.recentBlockhash = svm.latestBlockhash();
  tx.feePayer = user.publicKey;
  tx.sign(user);
  return svm.sendTransaction(tx);
}

// v1 `route` wire shape (6 fixed accounts + num_hops/amount/min) — kept ONLY to
// prove the retired discriminator is rejected by the dispatcher.
function v1RouteIx(user: PublicKey, feeDest: PublicKey, numHops: number, amtIn: bigint, minOut: bigint, remaining: PublicKey[]): TransactionInstruction {
  const data = Buffer.concat([Buffer.from(V1_ROUTE_DISC_HEX, "hex"), u8(numHops), u64(amtIn), u64(minOut)]);
  const keys = [
    { pubkey: user, isSigner: true, isWritable: true },
    { pubkey: feeDest, isSigner: false, isWritable: true },
    { pubkey: FEE_WALLET, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: ATA_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: XDEX_PROGRAM, isSigner: false, isWritable: false },
    ...remaining.map((k) => ({ pubkey: k, isSigner: false, isWritable: true })),
  ];
  return new TransactionInstruction({ programId: PROGRAM_ID, keys, data });
}

// v0.4.2: fee_config is a MANDATORY 9th fixed account (security fix, was the
// v0.3.1 B-M2 optional trailing account) — it must sit BEFORE remaining_accounts,
// like every other fixed account, so every route_v2 call needs a live fee_config
// PDA in the SVM (seeded per-test below via seedFeeConfig).
function routeV2Ix(user: PublicKey, feeDest: PublicKey, legs: number[], amtIn: bigint, minOut: bigint, remaining: PublicKey[]): TransactionInstruction {
  const data = Buffer.concat([disc("route_v2"), vecU8(legs), u64(amtIn), u64(minOut)]);
  const keys = [
    { pubkey: user, isSigner: true, isWritable: true },
    { pubkey: feeDest, isSigner: false, isWritable: true },
    { pubkey: FEE_WALLET, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: ATA_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: XDEX_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: DEGEN_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: TOKEN_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: FEE_CONFIG, isSigner: false, isWritable: false },
    ...remaining.map((k) => ({ pubkey: k, isSigner: false, isWritable: true })),
  ];
  return new TransactionInstruction({ programId: PROGRAM_ID, keys, data });
}

describe("fortiblox-router v0.2.0 — B1: v1 `route` is GONE (retired discriminator)", () => {
  let svm: LiteSVM, user: Keypair, feeDest: Keypair;
  beforeEach(() => {
    svm = new LiteSVM();
    svm.addProgramFromFile(PROGRAM_ID, SO);
    seedFeeConfig(svm); // route_v2 needs a live fee_config PDA (v0.4.2, mandatory)
    user = new Keypair();
    feeDest = new Keypair();
    svm.airdrop(user.publicKey, BigInt(1e9));
  });

  it("the retired disc is sha256('global:route')[..8] == e517cb977ae3ad2a (pin)", () => {
    assert.equal(disc("route").toString("hex"), V1_ROUTE_DISC_HEX);
  });

  it("a well-formed v1 call reverts with Anchor 101 InstructionFallbackNotFound (no account touched)", () => {
    const remaining = Array(13).fill(0).map(() => new Keypair().publicKey);
    const before = svm.getBalance(user.publicKey)!;
    const res = send(svm, user, v1RouteIx(user.publicKey, feeDest.publicKey, 1, 1000n, 0n, remaining));
    assert.property(res, "err", "v1 route must revert");
    assert.equal(customCode(res), ANCHOR_INSTRUCTION_FALLBACK_NOT_FOUND, "must be the dispatcher fallback error, not a body error");
    // Failed tx: NO state change beyond the base signature fee (5000 lamports,
    // charged by the runtime on any processed tx) — fee dest never created,
    // no rent paid, no protocol fee.
    assert.isNull(svm.getAccount(feeDest.publicKey), "fee destination must not be created");
    const spent = before - svm.getBalance(user.publicKey)!;
    assert.isTrue(spent <= 5000n, `only the base tx fee may be charged, spent=${spent}`);
  });

  it("even the OLD v1 guard-trip inputs (0 hops / 0 amount) get 101, not a RouterError — proving no v1 body remains", () => {
    for (const [hops, amt, rem] of [[0, 1000n, []], [7, 1000n, []], [1, 0n, Array(13).fill(new Keypair().publicKey)]] as const) {
      const res = send(svm, user, v1RouteIx(user.publicKey, feeDest.publicKey, hops as number, amt as bigint, 0n, rem as PublicKey[]));
      assert.equal(customCode(res), ANCHOR_INSTRUCTION_FALLBACK_NOT_FOUND, `hops=${hops} amt=${amt}`);
    }
  });

  it("route_v2 with the same junk still reaches the BODY guards (BadHopCount 6000) — dispatcher intact", () => {
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest.publicKey, [], 1000n, 0n, []));
    assert.equal(customCode(res), 6000, "BadHopCount");
  });
});

describe("fortiblox-router v0.4.3 — B3: `version` view", () => {
  it("logs and returns 0.4.3 as return data; takes no accounts", () => {
    const svm = new LiteSVM();
    svm.addProgramFromFile(PROGRAM_ID, SO);
    const user = new Keypair();
    svm.airdrop(user.publicKey, BigInt(1e9));
    const ix = new TransactionInstruction({ programId: PROGRAM_ID, keys: [], data: disc("version") });
    const res: any = send(svm, user, ix);
    assert.notProperty(res, "err", "version must succeed: " + (res.toString?.() ?? ""));
    const logs: string[] = res.logs();
    assert.isTrue(logs.some((l) => l.includes("fortiblox-router v0.4.3")), "version log missing: " + logs.join("\n"));
    const rd = res.returnData();
    assert.equal(Buffer.from(rd.data()).toString("utf8"), "0.4.3");
    assert.equal(new PublicKey(rd.programId()).toBase58(), PROGRAM_ID.toBase58());
  });
});

// ===========================================================================
// route_v2 — leg-partition / dispatch / bounds guards that fire BEFORE any CPI.
// Each test would PASS on a vulnerable router that skipped the guard and FAILS
// (reverts) on the fixed one. Full money-path is tests/money-path.test.ts.
// ===========================================================================
describe("fortiblox-router — route_v2 leg partition & bounds (no CPI needed)", () => {
  let svm: LiteSVM, user: Keypair, feeDest: Keypair;
  // One filler pubkey repeated: the message dedups it (tx stays under 1232B),
  // but the instruction still references it N times, so remaining_accounts.len()
  // == N — exactly what the leg-partition guard counts.
  const FILLER = new Keypair().publicKey;
  const fill = (n: number) => Array(n).fill(FILLER);

  beforeEach(() => {
    svm = new LiteSVM();
    svm.addProgramFromFile(PROGRAM_ID, SO);
    seedFeeConfig(svm); // route_v2 needs a live fee_config PDA (v0.4.2, mandatory)
    user = new Keypair();
    feeDest = new Keypair();
    svm.airdrop(user.publicKey, BigInt(1e9));
  });

  function expectFail(legs: number[], amtIn: bigint, remaining: PublicKey[], code?: number) {
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest.publicKey, legs, amtIn, 0n, remaining));
    assert.property(res, "err", "expected route_v2 to revert");
    if (code !== undefined) assert.equal(customCode(res), code, `expected error ${code}`);
  }

  it("rejects empty legs (BadHopCount 6000)", () => expectFail([], 1000n, [], 6000));
  it("rejects legs.len > MAX (BadHopCount 6000)", () => expectFail(Array(7).fill(0), 1000n, fill(7 * 13), 6000));
  it("rejects initial_amount_in = 0 (ZeroAmountIn 6002)", () => expectFail([0], 0n, fill(13), 6002));
  it("rejects unknown leg kind 3 (BadLegKind 6018)", () => expectFail([3], 1000n, fill(28), 6018));
  it("rejects XDEX leg with 12 remaining (BadAccountCount 6001)", () => expectFail([0], 1000n, fill(12), 6001));
  it("rejects Degen-buy leg with 27 remaining (BadAccountCount 6001)", () => expectFail([1], 1000n, fill(27), 6001));
  it("rejects Degen-sell leg with 15 remaining (BadAccountCount 6001)", () => expectFail([2], 1000n, fill(15), 6001));
  it("rejects mixed [XDEX,Degen-buy] with 40 remaining (needs 41) (BadAccountCount)", () => expectFail([0, 1], 1000n, fill(40), 6001));
  it("rejects mixed [XDEX,Degen-buy] with 42 remaining (needs 41) (BadAccountCount)", () => expectFail([0, 1], 1000n, fill(42), 6001));
  it("accepts the 41-account partition then reverts in-leg (XDEX validation, not BadAccountCount)", () => {
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest.publicKey, [0, 1], 1000n, 0n, fill(41)));
    assert.property(res, "err");
    assert.notEqual(customCode(res), 6001, "partition arithmetic must pass; the XDEX leg body must be what reverts");
  });
  it("Degen-buy leg with forged (non-user) signer reverts (AuthorityNotUser 6003)", () => {
    // 28 junk accounts: win[3] (signer) != user -> reverts before any CPI.
    expectFail([1], 1000n, fill(28), 6003);
  });
});
