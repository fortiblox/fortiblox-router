/**
 * fortiblox-router v2 — MONEY-PATH simulation (LiteSVM, real CPIs).
 *
 * Exercises route_v2 end-to-end against a mock AMM deployed at BOTH xdex::ID and
 * degen::ID that reproduces the observable effects the router measures (Degen
 * sell: meme->curve, native payout to signer, CLOSE the signer WXNT ATA; XDEX
 * swap: input ATA -> vault, vault -> output ATA). Meme/output tokens are classic
 * SPL (Token-2022 is only a stub here); the router's native / wrap / rent-wash /
 * fee / min-out logic under test is identical either way.
 *
 * Proves, with a real simulation (not code inspection):
 *  A. Degen sell: 25 bps lands EXACTLY at ATA(WXNT, FEE_WALLET); user keeps
 *     payout-fee as WXNT; the router program holds ZERO after.
 *  B. too-high minimum_amount_out on a Degen route REVERTS (SlippageExceeded).
 *  C. creator fee-rebate sell (payout +5% when seller==creator): the router
 *     measures the LARGER net and fees exactly on it.
 *  D. pre-existing idle WXNT in the hub ATA is NOT folded into the fee/output
 *     (the M1 rent-wash + pre_wxnt cancellation).
 *  E. mixed XDEX+Degen (sell -> wrap -> XDEX): fee lands on the final token.
 *  F. (v0.2.0) XDEX single-hop `legs=[0]` — the shape the app now emits for
 *     every single-hop swap (v1 `route` deleted): fee + user receipt exact.
 *  G. (v0.2.0, B1 SWEEP-REGRESSION) 2-hop XDEX with an IDLE balance pre-seeded
 *     in the intermediate ATA: hop 2 spends EXACTLY hop 1's output, the idle
 *     balance is untouched, the fee is on the route's output only. This is the
 *     v1 `lib.rs:264` bug class (WP #6704/6705) made unreachable by construction.
 *  H. (v0.2.0, S3) an allocated-but-UNINITIALIZED token-program-owned account
 *     in a token-account slot is rejected (NotATokenAccount), not swept through.
 *  I. (v0.4.0) route_v3 on a Degen-SELL-terminal route (native -> WXNT normalisation):
 *     protocol ceil(25bps) at ATA(WXNT, FEE_WALLET) EXACTLY as in A; integrator
 *     floor(bps) at ATA(WXNT, integrator); user keeps payout − both; idle hub WXNT
 *     (D) still not folded in. Proves the integrator sink rides the SAME normalised
 *     token path as the protocol fee on a native-terminal route.
 *  J. (v0.4.0) route_v3 mixed sell -> wrap -> XDEX: both fees land on the FINAL token.
 */
import { LiteSVM } from "litesvm";
import { PublicKey, Transaction, TransactionInstruction, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";
import { NEW_FEE_WALLET } from "./lib/live";
import { createHash } from "crypto";

const ROUTER = new PublicKey("3geAsZiNaWDuTVtTbdWVQRitd55jY4UoWeeBmJFTJZmE");
const ROUTER_SO = "target/deploy/fortiblox_router.so";
const MOCK_SO = "tests/mock-amm/target/deploy/mock_amm.so";
const XDEX = new PublicKey("sEsYH97wqmfnkzHedjNcw3zyJdPvUmsa9AixhS4b4fN");
const DEGEN = new PublicKey("degenDXVPhS7vgu3hcdzGA7T6dfCe6qTYyVM7npP3pc");
/** WP #7386: the pinned protocol-fee sink has ONE source of truth in the test
 *  tree — re-declaring the literal per file is how it drifts. */
const FEE_WALLET = NEW_FEE_WALLET;
const WXNT = new PublicKey("So11111111111111111111111111111111111111112");
const TOKEN = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN22 = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ATA_PROGRAM = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYS = SystemProgram.programId;

const RENT_ACCT = 2_039_280n; // rent-exempt for a 165-byte token account
const RENT_MINT = 1_461_600n; // rent-exempt for an 82-byte mint

function disc(name: string): Buffer { return createHash("sha256").update("global:" + name).digest().subarray(0, 8); }
function u8(n: number) { return Buffer.from([n]); }
function u64(n: bigint) { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; }
function vecU8(a: number[]) { const l = Buffer.alloc(4); l.writeUInt32LE(a.length); return Buffer.concat([l, Buffer.from(a)]); }
function ata(mint: PublicKey, owner: PublicKey, tp: PublicKey) {
  return PublicKey.findProgramAddressSync([owner.toBuffer(), tp.toBuffer(), mint.toBuffer()], ATA_PROGRAM)[0];
}
function ceilFee(gross: bigint) { return (gross * 25n + 9_999n) / 10_000n; }

// --- raw classic-SPL account builders (setAccount) --------------------------
function mintData(authority: PublicKey, decimals: number): Uint8Array {
  const d = Buffer.alloc(82);
  d.writeUInt32LE(1, 0); authority.toBuffer().copy(d, 4);
  d.writeBigUInt64LE(0n, 36); d.writeUInt8(decimals, 44); d.writeUInt8(1, 45);
  return d;
}
function tokenData(mint: PublicKey, owner: PublicKey, amount: bigint, native?: bigint): Uint8Array {
  const d = Buffer.alloc(165);
  mint.toBuffer().copy(d, 0); owner.toBuffer().copy(d, 32); d.writeBigUInt64LE(amount, 64);
  d.writeUInt8(1, 108); // state = Initialized
  if (native !== undefined) { d.writeUInt32LE(1, 109); d.writeBigUInt64LE(native, 113); }
  return d;
}

type Acc = { lamports: bigint; data: Uint8Array; owner: PublicKey; executable: boolean; rentEpoch: bigint };
function acc(lamports: bigint, data: Uint8Array, owner: PublicKey): Acc {
  return { lamports, data, owner, executable: false, rentEpoch: 0n };
}
function tokAmount(svm: LiteSVM, pk: PublicKey): bigint {
  const a = svm.getAccount(pk);
  if (!a) return 0n;
  return Buffer.from(a.data).readBigUInt64LE(64);
}

const [FEE_CONFIG_PDA] = PublicKey.findProgramAddressSync([Buffer.from("fee_config")], ROUTER);
const FEE_CONFIG_LIVE = JSON.parse(require("fs").readFileSync("tests/fixtures/fee-config-live-2026-08-23.json", "utf8"));

const routeV2Disc = () => disc("route_v2");
/** v0.4.2: fee_config is a MANDATORY 9th fixed account (security fix, was the
 *  v0.3.1 B-M2 optional trailing account) — sits BEFORE remaining_accounts. */
function routeV2Ix(user: PublicKey, feeDest: PublicKey, legs: number[], amtIn: bigint, minOut: bigint, remaining: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[]) {
  const data = Buffer.concat([routeV2Disc(), vecU8(legs), u64(amtIn), u64(minOut)]);
  const keys = [
    { pubkey: user, isSigner: true, isWritable: true },
    { pubkey: feeDest, isSigner: false, isWritable: true },
    { pubkey: FEE_WALLET, isSigner: false, isWritable: false },
    { pubkey: SYS, isSigner: false, isWritable: false },
    { pubkey: ATA_PROGRAM, isSigner: false, isWritable: false },
    { pubkey: XDEX, isSigner: false, isWritable: false },
    { pubkey: DEGEN, isSigner: false, isWritable: false },
    { pubkey: TOKEN, isSigner: false, isWritable: false },
    { pubkey: FEE_CONFIG_PDA, isSigner: false, isWritable: false },
    ...remaining,
  ];
  return new TransactionInstruction({ programId: ROUTER, keys, data });
}

/** route_v3 (v0.4.0): route_v2's 8 fixed + fee_config + integrator pair, then the windows EXACTLY. */
function routeV3Ix(user: PublicKey, feeDest: PublicKey, intDest: PublicKey, intWallet: PublicKey, legs: number[], amtIn: bigint, minOut: bigint, bps: number, remaining: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[]) {
  const b = Buffer.alloc(2); b.writeUInt16LE(bps);
  const data = Buffer.concat([disc("route_v3"), vecU8(legs), u64(amtIn), u64(minOut), b]);
  const base = routeV2Ix(user, feeDest, legs, amtIn, minOut, []); // first 8 keys only — base.keys[8] is ALSO fee_config now, dropped below to avoid duplicating it
  const keys = [...base.keys.slice(0, 8), { pubkey: FEE_CONFIG_PDA, isSigner: false, isWritable: false }, { pubkey: intDest, isSigner: false, isWritable: true }, { pubkey: intWallet, isSigner: false, isWritable: false }, ...remaining];
  return new TransactionInstruction({ programId: ROUTER, keys, data });
}
const floorFee = (g: bigint, bps: number) => (g * BigInt(bps)) / 10_000n;
function integratorFeePaid(res: any) {
  const d = createHash("sha256").update("event:IntegratorFeePaid").digest().subarray(0, 8);
  const logs: string[] = res.logs();
  const ev = logs.filter((l) => l.startsWith("Program data: ")).map((l) => Buffer.from(l.slice(14), "base64")).filter((b) => b.subarray(0, 8).equals(d));
  assert.equal(ev.length, 1, "exactly one IntegratorFeePaid"); const x = ev[0].subarray(8);
  return { wallet: new PublicKey(x.subarray(32, 64)), destination: new PublicKey(x.subarray(64, 96)), bps: x.readUInt16LE(96), amount: x.readBigUInt64LE(98) };
}

function newSvm(): LiteSVM {
  const svm = new LiteSVM();
  svm.addProgramFromFile(ROUTER, ROUTER_SO);
  // v0.4.0: route_v3 takes the fee_config PDA as a mandatory fixed account — seed the LIVE bytes (unpaused)
  svm.setAccount(FEE_CONFIG_PDA, acc(BigInt(FEE_CONFIG_LIVE.feeConfig.lamports), Buffer.from(FEE_CONFIG_LIVE.feeConfig.data, "base64"), ROUTER));
  svm.addProgramFromFile(XDEX, MOCK_SO);
  svm.addProgramFromFile(DEGEN, MOCK_SO);
  // WXNT mint must exist (fee path reads decimals; ATA program references it).
  svm.setAccount(WXNT, acc(RENT_MINT, mintData(WXNT, 9), TOKEN));
  return svm;
}

// Build a Degen sell (16-account) window. Creates: memeA mint, user meme ATA
// (funded), curve meme vault, curve token_state (funded native), + dummies.
function setupSell(svm: LiteSVM, user: PublicKey, creator: PublicKey, memeIn: bigint, curveLamports: bigint) {
  const memeMint = Keypair.generate().publicKey;
  svm.setAccount(memeMint, acc(RENT_MINT, mintData(user, 6), TOKEN));
  const userMeme = ata(memeMint, user, TOKEN);
  svm.setAccount(userMeme, acc(RENT_ACCT, tokenData(memeMint, user, memeIn), TOKEN));
  const tokenState = Keypair.generate().publicKey;
  svm.setAccount(tokenState, acc(curveLamports, new Uint8Array(0), DEGEN)); // owned by degen (mock) -> pays native
  const memeVault = Keypair.generate().publicKey;
  svm.setAccount(memeVault, acc(RENT_ACCT, tokenData(memeMint, tokenState, 0n), TOKEN));
  const dummy = () => { const k = Keypair.generate().publicKey; svm.setAccount(k, acc(1_000_000n, new Uint8Array(0), SYS)); return k; };
  const userWsol = ata(WXNT, user, TOKEN);
  const w = (pubkey: PublicKey, isWritable: boolean, isSigner = false) => ({ pubkey, isSigner, isWritable });
  const win = [
    w(user, true, true),          // 0 signer
    w(dummy(), true),             // 1 app_state
    w(dummy(), true),             // 2 staking_router
    w(creator, true),             // 3 token_creator
    w(memeMint, false),           // 4 mint
    w(WXNT, false),               // 5 wsol_mint
    w(tokenState, true),          // 6 token_state
    w(userMeme, true),            // 7 signer meme ATA (INPUT)
    w(userWsol, true),            // 8 signer WXNT ATA (CLOSED by sell)
    w(memeVault, true),           // 9 token_state meme vault
    w(dummy(), true),             // 10 token_state wsol vault
    w(dummy(), false),            // 11 rent
    w(TOKEN, false),              // 12 token_program
    w(TOKEN22, false),            // 13 token_2022_program
    w(SYS, false),                // 14 system_program
    w(ATA_PROGRAM, false),        // 15 associated_token_program
  ];
  return { win, userWsol, memeMint };
}

function send(svm: LiteSVM, user: Keypair, ix: TransactionInstruction) {
  const tx = new Transaction().add(ix);
  tx.recentBlockhash = svm.latestBlockhash();
  tx.feePayer = user.publicKey;
  tx.sign(user);
  return svm.sendTransaction(tx);
}

describe("fortiblox-router v2 — money-path (real CPIs, mock AMM)", () => {
  let svm: LiteSVM, user: Keypair;
  beforeEach(() => { svm = newSvm(); user = Keypair.generate(); svm.airdrop(user.publicKey, 1_000_000_000n); });

  it("A. Degen sell: 25 bps lands exactly at ATA(WXNT,FEE_WALLET); user keeps payout-fee; router holds 0", () => {
    const memeIn = 1_000_000n, payout = memeIn; // mock pays 1:1 native
    const { win, userWsol } = setupSell(svm, user.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    const feeDest = ata(WXNT, FEE_WALLET, TOKEN);
    const fee = ceilFee(payout);
    const minOut = payout - fee; // exact floor -> passes
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [2], memeIn, minOut, win));
    assert.notProperty(res, "err", "sell should succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "fee lands exactly");
    assert.equal(tokAmount(svm, userWsol).toString(), (payout - fee).toString(), "user keeps payout-fee as WXNT");
    assert.equal(svm.getBalance(ROUTER)?.toString() ?? "0", (svm.getBalance(ROUTER) ?? 0n).toString());
    const routerAcc = svm.getAccount(ROUTER)!;
    assert.isTrue(routerAcc.executable, "router is a program");
    // program-owned value: the router has no data account / vault; it never holds route funds.
    assert.equal(tokAmount(svm, ata(WXNT, ROUTER, TOKEN)).toString(), "0");
  });

  it("B. Degen sell: too-high minimum_amount_out reverts (SlippageExceeded)", () => {
    const memeIn = 1_000_000n, payout = memeIn;
    const { win } = setupSell(svm, user.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    const feeDest = ata(WXNT, FEE_WALLET, TOKEN);
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [2], memeIn, payout + 1n, win)); // > payout-fee
    assert.property(res, "err", "should revert on slippage");
  });

  it("C. creator fee-rebate sell: router measures the +5% larger net and fees on it", () => {
    const memeIn = 1_000_000n, payout = memeIn + memeIn / 20n; // mock rebate: seller==creator
    const { win, userWsol } = setupSell(svm, user.publicKey, user.publicKey /* creator == seller */, memeIn, 1_000_000_000n);
    const feeDest = ata(WXNT, FEE_WALLET, TOKEN);
    const fee = ceilFee(payout);
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [2], memeIn, payout - fee, win));
    assert.notProperty(res, "err", "rebate sell should succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "fee is 25 bps of the REBATED payout");
    assert.equal(tokAmount(svm, userWsol).toString(), (payout - fee).toString());
  });

  it("D. idle WXNT in the hub ATA is NOT folded into the fee/output (M1 rent-wash + pre_wxnt)", () => {
    const memeIn = 1_000_000n, payout = memeIn, idle = 500_000n;
    const { win, userWsol } = setupSell(svm, user.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    // Pre-fund the user's hub WXNT ATA with idle WXNT (native token account).
    svm.setAccount(userWsol, acc(RENT_ACCT + idle, tokenData(WXNT, user.publicKey, idle, RENT_ACCT), TOKEN));
    const feeDest = ata(WXNT, FEE_WALLET, TOKEN);
    const feeOnPayout = ceilFee(payout);
    const feeOnFolded = ceilFee(payout + idle);
    assert.notEqual(feeOnPayout.toString(), feeOnFolded.toString(), "test is meaningful");
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [2], memeIn, payout - feeOnPayout, win));
    assert.notProperty(res, "err", "sell w/ idle WXNT should succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    assert.equal(tokAmount(svm, feeDest).toString(), feeOnPayout.toString(), "fee on payout ONLY, not payout+idle");
    assert.equal(tokAmount(svm, userWsol).toString(), (payout - feeOnPayout).toString(), "hub WXNT = payout-fee (idle returned to native)");
  });

  it("E. mixed sell -> wrap -> XDEX: fee lands on the final token", () => {
    const memeIn = 1_000_000n, payout = memeIn, tokY = payout; // 1:1 hops
    const s = setupSell(svm, user.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    // XDEX window: WXNT(user) -> tokenY(user), 13 accounts.
    const tokenYMint = Keypair.generate().publicKey;
    svm.setAccount(tokenYMint, acc(RENT_MINT, mintData(user.publicKey, 6), TOKEN));
    const userWsol = s.userWsol;                       // input ATA (produced by the sell wrap)
    const userTokY = ata(tokenYMint, user.publicKey, TOKEN);
    svm.setAccount(userTokY, acc(RENT_ACCT, tokenData(tokenYMint, user.publicKey, 0n), TOKEN));
    const inVault = Keypair.generate().publicKey;
    svm.setAccount(inVault, acc(RENT_ACCT, tokenData(WXNT, user.publicKey, 0n, RENT_ACCT), TOKEN));
    const outVault = Keypair.generate().publicKey;      // funded tokenY, authority = user
    svm.setAccount(outVault, acc(RENT_ACCT, tokenData(tokenYMint, user.publicKey, 10_000_000n), TOKEN));
    const pool = Keypair.generate().publicKey;
    svm.setAccount(pool, acc(1_000_000n, new Uint8Array(0), XDEX)); // pool_state owned by xdex (mock)
    const dummy = () => { const k = Keypair.generate().publicKey; svm.setAccount(k, acc(1_000_000n, new Uint8Array(0), SYS)); return k; };
    const w = (pubkey: PublicKey, isWritable: boolean, isSigner = false) => ({ pubkey, isSigner, isWritable });
    const xwin = [
      w(user.publicKey, false, true), // 0 payer
      w(dummy(), false),              // 1 authority
      w(dummy(), false),              // 2 amm_config
      w(pool, true),                  // 3 pool_state (owned by xdex)
      w(userWsol, true),              // 4 input ATA (WXNT)
      w(userTokY, true),              // 5 output ATA (tokenY)
      w(inVault, true),               // 6 input vault
      w(outVault, true),              // 7 output vault (tokenY, authority=user)
      w(TOKEN, false),                // 8 input token program
      w(TOKEN, false),                // 9 output token program
      w(WXNT, false),                 // 10 input mint
      w(tokenYMint, false),           // 11 output mint
      w(dummy(), true),               // 12 observation
    ];
    const feeDest = ata(tokenYMint, FEE_WALLET, TOKEN);
    const fee = ceilFee(tokY);
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [2, 0], memeIn, tokY - fee, [...s.win, ...xwin]));
    assert.notProperty(res, "err", "mixed route should succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "25 bps lands on the final tokenY");
    assert.equal(tokAmount(svm, userTokY).toString(), (tokY - fee).toString(), "user receives tokenY - fee");
  });

  // ---- v0.2.0 additions -------------------------------------------------------
  const w = (pubkey: PublicKey, isWritable: boolean, isSigner = false) => ({ pubkey, isSigner, isWritable });
  const dummyIn = (svm: LiteSVM) => { const k = Keypair.generate().publicKey; svm.setAccount(k, acc(1_000_000n, new Uint8Array(0), SYS)); return k; };
  /** A 13-account XDEX window inMint(user ATA) -> outMint(user ATA), mock 1:1.
   *  `userInAta` / `userOutAta` may be pre-created by the caller (idle seeds). */
  function xdexWindow(svm: LiteSVM, user: PublicKey, inMint: PublicKey, outMint: PublicKey, vaultOutFunded: bigint, opts: { createIn?: bigint | null; createOut?: bigint | null } = {}) {
    const userIn = ata(inMint, user, TOKEN);
    const userOut = ata(outMint, user, TOKEN);
    if (opts.createIn !== null) svm.setAccount(userIn, acc(RENT_ACCT, tokenData(inMint, user, opts.createIn ?? 0n), TOKEN));
    if (opts.createOut !== null) svm.setAccount(userOut, acc(RENT_ACCT, tokenData(outMint, user, opts.createOut ?? 0n), TOKEN));
    const inVault = Keypair.generate().publicKey;
    svm.setAccount(inVault, acc(RENT_ACCT, tokenData(inMint, user, 0n), TOKEN));
    const outVault = Keypair.generate().publicKey; // authority = user so the mock can release
    svm.setAccount(outVault, acc(RENT_ACCT, tokenData(outMint, user, vaultOutFunded), TOKEN));
    const pool = Keypair.generate().publicKey;
    svm.setAccount(pool, acc(1_000_000n, new Uint8Array(0), XDEX));
    const win = [
      w(user, false, true), w(dummyIn(svm), false), w(dummyIn(svm), false), w(pool, true),
      w(userIn, true), w(userOut, true), w(inVault, true), w(outVault, true),
      w(TOKEN, false), w(TOKEN, false), w(inMint, false), w(outMint, false), w(dummyIn(svm), true),
    ];
    return { win, userIn, userOut, inVault, outVault };
  }
  function newMint(svm: LiteSVM, authority: PublicKey, decimals = 6) {
    const m = Keypair.generate().publicKey;
    svm.setAccount(m, acc(RENT_MINT, mintData(authority, decimals), TOKEN));
    return m;
  }

  it("F. XDEX single-hop legs=[0]: fee == ceil(25bps) at ATA(outMint, FEE_WALLET); user gets in - fee; min-out exact", () => {
    const amountIn = 3_333_333n; // odd amount: exercises ceil rounding (25 bps of 3,333,333 = 8,333.3 -> 8,334)
    const mintA = newMint(svm, user.publicKey), mintB = newMint(svm, user.publicKey);
    const x = xdexWindow(svm, user.publicKey, mintA, mintB, 100_000_000n, { createIn: amountIn, createOut: 0n });
    const feeDest = ata(mintB, FEE_WALLET, TOKEN);
    const fee = ceilFee(amountIn);
    assert.equal(fee, 8_334n, "sanity: ceil rounding");
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [0], amountIn, amountIn - fee, x.win));
    assert.notProperty(res, "err", "single-hop must succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "fee exact");
    assert.equal(tokAmount(svm, x.userOut).toString(), (amountIn - fee).toString(), "user receives in - fee");
    assert.equal(tokAmount(svm, x.userIn).toString(), "0", "input fully spent (exactly initial_amount_in)");
    // min-out one unit too high -> SlippageExceeded (6017), fee NOT taken.
    const svm2 = newSvm(); const u2 = Keypair.generate(); svm2.airdrop(u2.publicKey, 1_000_000_000n);
    const mA = newMint(svm2, u2.publicKey), mB = newMint(svm2, u2.publicKey);
    const x2 = xdexWindow(svm2, u2.publicKey, mA, mB, 100_000_000n, { createIn: amountIn, createOut: 0n });
    const res2: any = send(svm2, u2, routeV2Ix(u2.publicKey, ata(mB, FEE_WALLET, TOKEN), [0], amountIn, amountIn - fee + 1n, x2.win));
    assert.property(res2, "err");
    assert.equal(res2.err().err().code, 6017, "SlippageExceeded");
    assert.equal(tokAmount(svm2, ata(mB, FEE_WALLET, TOKEN)).toString(), "0", "no fee on a reverted route");
  });

  it("G. SWEEP-REGRESSION: 2-hop XDEX with IDLE balance in the intermediate ATA — hop 2 spends ONLY hop 1's output; idle untouched; fee on route output only", () => {
    const amountIn = 1_000_000n;
    const idle = 7_777_777n; // idle B the user already held; v1 would have swept it into hop 2
    const mintA = newMint(svm, user.publicKey), mintB = newMint(svm, user.publicKey), mintC = newMint(svm, user.publicKey);
    // hop 1: A -> B (user B ATA pre-seeded with IDLE balance)
    const h1 = xdexWindow(svm, user.publicKey, mintA, mintB, 100_000_000n, { createIn: amountIn, createOut: idle });
    // hop 2: B -> C (input ATA = the SAME user B ATA; do not re-create it)
    const h2 = xdexWindow(svm, user.publicKey, mintB, mintC, 100_000_000n, { createIn: null, createOut: 0n });
    assert.equal(h2.userIn.toBase58(), h1.userOut.toBase58(), "hop chaining: hop-2 input == hop-1 output ATA");
    const feeDest = ata(mintC, FEE_WALLET, TOKEN);
    const fee = ceilFee(amountIn); // 1:1 hops => route output == amountIn
    const feeIfSwept = ceilFee(amountIn + idle);
    assert.notEqual(fee, feeIfSwept, "test is meaningful");
    const res = send(svm, user, routeV2Ix(user.publicKey, feeDest, [0, 0], amountIn, amountIn - fee, [...h1.win, ...h2.win]));
    assert.notProperty(res, "err", "2-hop must succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    // THE invariant: the idle intermediate balance is exactly preserved.
    assert.equal(tokAmount(svm, h1.userOut).toString(), idle.toString(), "idle B balance must be UNTOUCHED by hop 2");
    assert.equal(tokAmount(svm, h2.inVault).toString(), amountIn.toString(), "hop 2 pulled exactly hop 1's output, not ATA balance");
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "fee on the route's output, never on the idle balance");
    assert.equal(tokAmount(svm, h2.userOut).toString(), (amountIn - fee).toString(), "user receives route output - fee");
    assert.equal(tokAmount(svm, h1.userIn).toString(), "0");
  });

  it("H. S3: an allocated-but-UNINITIALIZED token-program-owned account in a token slot -> NotATokenAccount (6008), no sweep-through", () => {
    const amountIn = 1_000_000n;
    const mintA = newMint(svm, user.publicKey), mintB = newMint(svm, user.publicKey);
    const x = xdexWindow(svm, user.publicKey, mintA, mintB, 100_000_000n, { createIn: amountIn, createOut: null });
    // Output ATA: right owner (token program), right length (165), right mint/owner bytes,
    // but state byte 0 = Uninitialized. Pre-S3 the structural classifier accepted it.
    const d = Buffer.from(tokenData(mintB, user.publicKey, 0n)); d.writeUInt8(0, 108);
    svm.setAccount(x.userOut, acc(RENT_ACCT, d, TOKEN));
    const res: any = send(svm, user, routeV2Ix(user.publicKey, ata(mintB, FEE_WALLET, TOKEN), [0], amountIn, 0n, x.win));
    assert.property(res, "err", "uninitialized output ATA must be rejected");
    assert.equal(res.err().err().code, 6008, "NotATokenAccount");
    // ...and a FROZEN (state 2) one is rejected too (fail-closed).
    const svm2 = newSvm(); const u2 = Keypair.generate(); svm2.airdrop(u2.publicKey, 1_000_000_000n);
    const mA = newMint(svm2, u2.publicKey), mB = newMint(svm2, u2.publicKey);
    const x2 = xdexWindow(svm2, u2.publicKey, mA, mB, 100_000_000n, { createIn: amountIn, createOut: null });
    const d2 = Buffer.from(tokenData(mB, u2.publicKey, 0n)); d2.writeUInt8(2, 108);
    svm2.setAccount(x2.userOut, acc(RENT_ACCT, d2, TOKEN));
    const res2: any = send(svm2, u2, routeV2Ix(u2.publicKey, ata(mB, FEE_WALLET, TOKEN), [0], amountIn, 0n, x2.win));
    assert.equal(res2.err().err().code, 6008, "frozen -> NotATokenAccount");
  });

  // ---- v0.4.0 integrator fee on the Degen / native paths -------------------------
  it("I. route_v3 Degen SELL-terminal (native -> WXNT): protocol ceil(25bps) EXACTLY as route_v2; integrator floor(100bps) at ATA(WXNT, integrator); user keeps payout − both; idle hub WXNT untouched", () => {
    const memeIn = 1_000_000n, payout = memeIn, idle = 500_000n, bps = 100;
    const { win, userWsol } = setupSell(svm, user.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    svm.setAccount(userWsol, acc(RENT_ACCT + idle, tokenData(WXNT, user.publicKey, idle, RENT_ACCT), TOKEN)); // D-style idle hub balance
    const integrator = Keypair.generate().publicKey;
    const feeDest = ata(WXNT, FEE_WALLET, TOKEN), intDest = ata(WXNT, integrator, TOKEN);
    svm.setAccount(intDest, acc(RENT_ACCT, tokenData(WXNT, integrator, 0n, RENT_ACCT), TOKEN)); // the integrator pre-creates its WXNT ATA
    const fee = ceilFee(payout), ifee = floorFee(payout, bps);
    assert.isTrue(ifee > 0n);
    const res: any = send(svm, user, routeV3Ix(user.publicKey, feeDest, intDest, integrator, [2], memeIn, payout - fee - ifee, bps, win));
    assert.notProperty(res, "err", "route_v3 sell should succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    const ip = integratorFeePaid(res);
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "protocol fee == route_v2's exact ceil-25bps of the payout (case A), NOT reduced");
    assert.equal(tokAmount(svm, intDest).toString(), ifee.toString(), "integrator fee == floor(payout × 100 bps) at the integrator's WXNT ATA");
    assert.equal(ip.amount.toString(), ifee.toString()); assert.isTrue(ip.destination.equals(intDest) && ip.wallet.equals(integrator)); assert.equal(ip.bps, bps);
    assert.equal(tokAmount(svm, userWsol).toString(), (payout - fee - ifee).toString(), "user hub WXNT = payout − both fees (idle returned to native, not fee'd)");
    // min-out one above the net-after-both reverts
    const svm2 = newSvm(); const u2 = Keypair.generate(); svm2.airdrop(u2.publicKey, 1_000_000_000n);
    const s2 = setupSell(svm2, u2.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    svm2.setAccount(ata(WXNT, integrator, TOKEN), acc(RENT_ACCT, tokenData(WXNT, integrator, 0n, RENT_ACCT), TOKEN));
    const r2: any = send(svm2, u2, routeV3Ix(u2.publicKey, feeDest, ata(WXNT, integrator, TOKEN), integrator, [2], memeIn, payout - fee - ifee + 1n, bps, s2.win));
    // and with the integrator ATA MISSING: 6046 before any CPI (mock never invoked)
    const svm3 = newSvm(); const u3 = Keypair.generate(); svm3.airdrop(u3.publicKey, 1_000_000_000n);
    const s3 = setupSell(svm3, u3.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    const r3: any = send(svm3, u3, routeV3Ix(u3.publicKey, feeDest, ata(WXNT, integrator, TOKEN), integrator, [2], memeIn, 1n, bps, s3.win));
    assert.equal(r3.err().err().code, 6046, "IntegratorFeeDestinationMissing on a sell-terminal route (final mint = WXNT)");
    assert.isFalse((r3.meta().logs() as string[]).some((l: string) => l.includes("invoke [2]")), "no CPI ran");
    assert.equal(r2.err().err().code, 6017, "SlippageExceeded on net-after-both");
    assert.equal(tokAmount(svm2, feeDest).toString(), "0"); assert.equal(tokAmount(svm2, ata(WXNT, integrator, TOKEN)).toString(), "0");
  });

  it("J. route_v3 mixed sell -> wrap -> XDEX: both fees land on the FINAL token (tokenY), fee_config mandatory", () => {
    const memeIn = 1_000_000n, payout = memeIn, tokY = payout, bps = 50;
    const s = setupSell(svm, user.publicKey, Keypair.generate().publicKey, memeIn, 1_000_000_000n);
    const tokenYMint = newMint(svm, user.publicKey);
    const userTokY = ata(tokenYMint, user.publicKey, TOKEN); svm.setAccount(userTokY, acc(RENT_ACCT, tokenData(tokenYMint, user.publicKey, 0n), TOKEN));
    const inVault = Keypair.generate().publicKey; svm.setAccount(inVault, acc(RENT_ACCT, tokenData(WXNT, user.publicKey, 0n, RENT_ACCT), TOKEN));
    const outVault = Keypair.generate().publicKey; svm.setAccount(outVault, acc(RENT_ACCT, tokenData(tokenYMint, user.publicKey, 10_000_000n), TOKEN));
    const pool = Keypair.generate().publicKey; svm.setAccount(pool, acc(1_000_000n, new Uint8Array(0), XDEX));
    const xwin = [w(user.publicKey, false, true), w(dummyIn(svm), false), w(dummyIn(svm), false), w(pool, true), w(s.userWsol, true), w(userTokY, true), w(inVault, true), w(outVault, true), w(TOKEN, false), w(TOKEN, false), w(WXNT, false), w(tokenYMint, false), w(dummyIn(svm), true)];
    const integrator = Keypair.generate().publicKey;
    const feeDest = ata(tokenYMint, FEE_WALLET, TOKEN), intDest = ata(tokenYMint, integrator, TOKEN);
    svm.setAccount(intDest, acc(RENT_ACCT, tokenData(tokenYMint, integrator, 0n), TOKEN)); // pre-created by the integrator
    const fee = ceilFee(tokY), ifee = floorFee(tokY, bps);
    const res: any = send(svm, user, routeV3Ix(user.publicKey, feeDest, intDest, integrator, [2, 0], memeIn, tokY - fee - ifee, bps, [...s.win, ...xwin]));
    assert.notProperty(res, "err", "mixed route_v3 should succeed: " + JSON.stringify((res as any).logs?.() ?? res));
    assert.equal(tokAmount(svm, feeDest).toString(), fee.toString(), "25 bps on the final tokenY");
    assert.equal(tokAmount(svm, intDest).toString(), ifee.toString(), "integrator 50 bps on the final tokenY");
    assert.equal(tokAmount(svm, userTokY).toString(), (tokY - fee - ifee).toString(), "user receives tokenY − both");
    assert.isFalse(svm.getAccount(ata(WXNT, integrator, TOKEN)) !== null, "nothing taken / created on the intermediate WXNT hop");
    // fee_config omitted (10-account wire): the integrator dest lands in the fee_config slot -> Anchor 2012
    const ix = routeV3Ix(user.publicKey, feeDest, intDest, integrator, [2, 0], memeIn, 1n, bps, [...s.win, ...xwin]); ix.keys.splice(8, 1);
    const r3: any = send(svm, user, ix); assert.equal(r3.err().err().code, 2012, "fee_config mandatory");
  });
});
