/**
 * fortiblox-router — shared LiteSVM harness for the v0.3.1 audit suites
 * (tests/pause.test.ts, tests/audit-fixes.test.ts, tests/rogue-amm.test.ts, tests/degen-live.test.ts).
 *
 * Real bytes only: the REAL XDEX ELF + live pool state (tests/fixtures/xdex-live.json), the LIVE
 * `fee_config` PDA bytes (tests/fixtures/fee-config-live-2026-08-23.json — authority = the hot key,
 * version 1, paused 0, guardian 0) and, for before/after comparisons, the archived LIVE v0.3.0
 * router ELF (deploy/artifacts/fortiblox_router-live-2026-08-23-v0.3.0-278e0974.so).
 *
 * Wire builders emit the v0.4.2 shapes by default (snipe 19 accounts, delegated 12 fixed, route_v2
 * 9 fixed [8 + MANDATORY fee_config] + windows EXACTLY); `noFeeConfig` reproduces the pre-fix
 * shapes (v0.3.0 for snipe/delegated, the v0.3.1 8-fixed-account route_v2 wire) for the live-bytes
 * baselines. Not a test file (no `.test.ts` suffix — excluded from the mocha glob).
 */
import { LiteSVM } from "litesvm";
import { PublicKey, Transaction, TransactionInstruction, Keypair, SystemProgram, ComputeBudgetProgram } from "@solana/web3.js";
import { assert } from "chai";
import { createHash } from "crypto";
import { readFileSync } from "fs";

export const ROUTER = new PublicKey("3geAsZiNaWDuTVtTbdWVQRitd55jY4UoWeeBmJFTJZmE");
export const BUILT_SO = "target/deploy/fortiblox_router.so";
export const LIVE_V030_SO = "deploy/artifacts/fortiblox_router-live-2026-08-23-v0.3.0-278e0974.so";
/** The LIVE v0.3.1 bytes (archived 2026-08-30 from ProgramData, raw sha fd7de4bb…) — the A/B baseline for the v0.4.0 "route_v2 unchanged" pins. */
export const LIVE_V031_SO = "deploy/artifacts/fortiblox_router-live-2026-08-30-v0.3.1-fd7de4bb.so";
export const FEE_CONFIG_LIVE = JSON.parse(readFileSync("tests/fixtures/fee-config-live-2026-08-23.json", "utf8"));
export const FIXTURE = JSON.parse(readFileSync("tests/fixtures/xdex-live.json", "utf8"));
export const XDEX = new PublicKey(FIXTURE.xdex);
export const DEGEN = new PublicKey("degenDXVPhS7vgu3hcdzGA7T6dfCe6qTYyVM7npP3pc");
/**
 * WP #7386 — v0.4.1 REPOINTS the router's compile-time `fee_wallet::ID`, so which
 * pin a test must present depends on WHICH binary the sandbox loaded: every
 * archived live ELF still carries the OLD sink and answers Anchor 2012
 * (ConstraintAddress) for anything else. That is exactly why the app's
 * ROUTER_FEE_WALLET mirror has to flip in lockstep with the deploy, never before.
 *
 * `FEE_WALLET` therefore FOLLOWS the loaded binary — `addRouterProgram` sets it,
 * so no test picks a pin by hand. It is `let`, so anything derived from it (a fee
 * ATA in particular) MUST be computed after the SVM is built, never captured in a
 * module-level const.
 *
 * (Byte-patching an archived ELF to the new pin is not an option: only 1 of the
 * 12 copies is a contiguous literal — the other 11 are `lddw` immediates split
 * across instruction words.)
 */
export const NEW_FEE_WALLET = new PublicKey("FdQ2FmAydXBe87Nm7w4MjksRqTUjahPaqjj7mVshKvNa");
/** The pin compiled into every archived live ELF (v0.3.0 / v0.3.1 / v0.4.0). */
export const LIVE_FEE_WALLET = new PublicKey("EeWEeLTF7SCp4u3ttxWPjN169wdoZsKqbiszVcJY8NMG");
export let FEE_WALLET = NEW_FEE_WALLET;

/**
 * Load the router ELF `so` into `svm` AND point the harness at the fee wallet
 * THAT binary pins. Every SVM factory routes through here, so a test can never
 * present a pin the loaded binary does not have (WP #7386).
 */
export function addRouterProgram(svm: LiteSVM, so: string = BUILT_SO): void {
  svm.addProgramFromFile(ROUTER, so);
  FEE_WALLET = so === BUILT_SO ? NEW_FEE_WALLET : LIVE_FEE_WALLET;
}
export const TOKEN = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const TOKEN22 = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ATA_PROGRAM = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const SYS = SystemProgram.programId;
export const [XDEX_AUTH] = PublicKey.findProgramAddressSync([Buffer.from("vault_and_lp_mint_auth_seed")], XDEX);
export const [VAULT_AUTH] = PublicKey.findProgramAddressSync([Buffer.from("vault_authority")], ROUTER);
export const [FEE_CONFIG] = PublicKey.findProgramAddressSync([Buffer.from("fee_config")], ROUTER);
assert.equal(FEE_CONFIG.toBase58(), "6kfdAmUEPCQbRWpVchV6wS3K8wtd6vKgSEYvkKPAUoHC", "fee_config PDA pin");

export const disc = (n: string) => createHash("sha256").update("global:" + n).digest().subarray(0, 8);
export const eventDisc = (n: string) => createHash("sha256").update("event:" + n).digest().subarray(0, 8);
export const u64 = (n: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
export const vecU8 = (a: number[]) => { const l = Buffer.alloc(4); l.writeUInt32LE(a.length); return Buffer.concat([l, Buffer.from(a)]); };
export const ata = (mint: PublicKey, owner: PublicKey, tp: PublicKey) =>
  PublicKey.findProgramAddressSync([owner.toBuffer(), tp.toBuffer(), mint.toBuffer()], ATA_PROGRAM)[0];
export const ceilFee = (g: bigint) => (g * 25n + 9_999n) / 10_000n;
/** v0.4.0 integrator fee: floor(gross × bps / 10_000). */
export const floorFee = (g: bigint, bps: number) => (g * BigInt(bps)) / 10_000n;
export const MAX_INTEGRATOR_FEE_BPS = 300;
export const RENT_ACCT = 2_039_280n; // 165-byte token account
export const RENT_MINT = 1_461_600n; // 82-byte mint

/** FeeConfig absolute offsets (lib.rs layout table). */
export const FC = { version: 8, bump: 9, tier_bps: 138, authority: 161, last_change_ts: 193, pending_effective_ts: 217, paused: 225, guardian: 226, reserved: 258, end: 512 };
/** RouterError codes (IDL). */
export const E = { BadHopCount: 6000, BadAccountCount: 6001, ZeroAmountIn: 6002, AuthorityNotUser: 6003, AuthorityNotSigner: 6004, PoolNotXdex: 6005, AtaNotUser: 6006, BrokenRoute: 6007,
  NotATokenAccount: 6008, NotAMint: 6009, MintMismatch: 6010, BadTokenProgram: 6011, TransferHookUnsupported: 6012, NoNetOutput: 6013, WrongFeeDestination: 6014, FeeConfig: 6015,
  MathOverflow: 6016, SlippageExceeded: 6017, BadLegKind: 6018, NotDegenAccount: 6019, ExpectedWxntInput: 6020, UnsupportedLegSequence: 6021, Unauthorized: 6022, NotUpgradeAuthority: 6023,
  InvalidTierBps: 6024, ThresholdTooLow: 6025, RateLimited: 6026, NoPendingChange: 6027, TimelockNotElapsed: 6028, AlreadyFinalized: 6029, InvalidIdentity: 6030, InvalidAuthority: 6031,
  DelegatedLegUnsupported: 6032, NotDelegate: 6033, InsufficientDelegation: 6034, BadHopAuthority: 6035, WrongVaultAta: 6036, WrongUserDestination: 6037, VaultNotDrained: 6038, TransferFeeUnsupported: 6039,
  InputDebitMismatch: 6040, BadLegsLength: 6041, Paused: 6042,
  // v0.4.0 (integrator fee) — appended
  BadIntegratorFeeBps: 6043, WrongIntegratorFeeDestination: 6044, InvalidIntegratorWallet: 6045, IntegratorFeeDestinationMissing: 6046 };
export const ANCHOR = { InstructionFallbackNotFound: 101, InstructionDidNotDeserialize: 102, ConstraintOwner: 2004, ConstraintSeeds: 2006, ConstraintAddress: 2012, AccountNotEnoughKeys: 3005, InvalidProgramId: 3008, AccountNotSigner: 3010 };
/** Token-2022 ExtensionType ids (spl-token-2022-interface src/extension/mod.rs). */
export const EXT = { TransferFeeConfig: 1, MintCloseAuthority: 3, DefaultAccountState: 6, ImmutableOwner: 7, MemoTransfer: 8, NonTransferable: 9, PermanentDelegate: 12, TransferHook: 14 };

export type Pool = { address: PublicKey; ammConfig: PublicKey; vault0: PublicKey; vault1: PublicKey; mint0: PublicKey; mint1: PublicKey; prog0: PublicKey; prog1: PublicKey; observation: PublicKey };
export const pool = (name: string): Pool => { const p = FIXTURE.pools[name]; const k = (x: string) => new PublicKey(p[x]);
  return { address: k("address"), ammConfig: k("ammConfig"), vault0: k("vault0"), vault1: k("vault1"), mint0: k("mint0"), mint1: k("mint1"), prog0: k("prog0"), prog1: k("prog1"), observation: k("observation") }; };
export const P1 = pool("WXNT/USDC.X"), P2 = pool("WXNT/PEPE");
export const WXNT = P1.mint0, USDCX = P1.mint1, PEPE = P2.mint1;
export function side(p: Pool, inMint: PublicKey) {
  const in0 = p.mint0.equals(inMint);
  return { inVault: in0 ? p.vault0 : p.vault1, outVault: in0 ? p.vault1 : p.vault0, inTp: in0 ? p.prog0 : p.prog1, outTp: in0 ? p.prog1 : p.prog0, inMint, outMint: in0 ? p.mint1 : p.mint0 };
}

export type SvmOpts = { routerSo?: string; /** false = do NOT seed the fee_config PDA; a function patches the live bytes first */ feeConfig?: false | ((d: Buffer) => void); xdex?: boolean };
/** LiteSVM with the router (built by default), the real XDEX ELF + live pool state, and the LIVE fee_config PDA. */
export function newSvm(opts: SvmOpts = {}): LiteSVM {
  const svm = new LiteSVM().withLogBytesLimit(2_000_000n);
  addRouterProgram(svm, opts.routerSo ?? BUILT_SO);
  if (opts.xdex !== false) {
    const pd = Buffer.from(FIXTURE.accounts[FIXTURE.xdexProgramData].data, "base64");
    svm.addProgram(XDEX, pd.subarray(45));
    for (const [k, a] of Object.entries<any>(FIXTURE.accounts)) {
      if (k === FIXTURE.xdex || k === FIXTURE.xdexProgramData || a.executable) continue;
      svm.setAccount(new PublicKey(k), { lamports: a.lamports, data: Buffer.from(a.data, "base64"), owner: new PublicKey(a.owner), executable: false, rentEpoch: 0 });
    }
  }
  if (opts.feeConfig !== false) seedFeeConfig(svm, opts.feeConfig);
  const c = svm.getClock(); c.unixTimestamp = BigInt(Math.floor(Date.now() / 1000)); svm.setClock(c);
  return svm;
}
/** Seed the LIVE fee_config bytes (optionally patched: authority / guardian / paused). */
export function seedFeeConfig(svm: LiteSVM, patch?: (d: Buffer) => void) {
  const d = Buffer.from(FEE_CONFIG_LIVE.feeConfig.data, "base64"); assert.equal(d.length, 512);
  if (patch) patch(d);
  svm.setAccount(FEE_CONFIG, { lamports: FEE_CONFIG_LIVE.feeConfig.lamports, data: d, owner: ROUTER, executable: false, rentEpoch: 0 });
}
export const withAuthority = (auth: PublicKey, guardian?: PublicKey) => (d: Buffer) => { auth.toBuffer().copy(d, FC.authority); if (guardian) guardian.toBuffer().copy(d, FC.guardian); };
export const feeConfigBytes = (svm: LiteSVM): Buffer => Buffer.from(svm.getAccount(FEE_CONFIG)!.data);

/** Raw TLV entries appended to a base Token-2022 account/mint. */
export type Tlv = { type: number; data: Buffer };
export const tlvBytes = (exts: Tlv[]) => Buffer.concat(exts.map((e) => { const h = Buffer.alloc(4); h.writeUInt16LE(e.type, 0); h.writeUInt16LE(e.data.length, 2); return Buffer.concat([h, e.data]); }));
/** Re-write a live Token-2022 mint with extra TLV extensions appended after its walked TLV end (what a mint authority could have configured at creation). */
export function mutateMint(svm: LiteSVM, mint: PublicKey, exts: Tlv[]) {
  const a = svm.getAccount(mint)!; const d = Buffer.from(a.data);
  assert.equal(d[165], 1, "extended Token-2022 mint"); let off = 166;
  while (off + 4 <= d.length) { const t = d.readUInt16LE(off); if (t === 0) break; off += 4 + d.readUInt16LE(off + 2); }
  const nd = Buffer.concat([d.subarray(0, off), tlvBytes(exts)]);
  svm.setAccount(mint, { lamports: a.lamports + 10_000_000, data: nd, owner: a.owner, executable: false, rentEpoch: 0 });
}
/** TransferHook extension bytes: authority + program_id (zero = None). */
export const hookExt = (program: PublicKey | null): Tlv => ({ type: EXT.TransferHook, data: Buffer.concat([Keypair.generate().publicKey.toBuffer(), program ? program.toBuffer() : Buffer.alloc(32)]) });

export function tokenData(mint: PublicKey, owner: PublicKey, amount: bigint, opts: { native?: bigint; delegate?: [PublicKey, bigint]; state?: number } = {}): Buffer {
  const d = Buffer.alloc(165);
  mint.toBuffer().copy(d, 0); owner.toBuffer().copy(d, 32); d.writeBigUInt64LE(amount, 64); d.writeUInt8(opts.state ?? 1, 108);
  if (opts.native !== undefined) { d.writeUInt32LE(1, 109); d.writeBigUInt64LE(opts.native, 113); }
  if (opts.delegate) { d.writeUInt32LE(1, 72); opts.delegate[0].toBuffer().copy(d, 76); d.writeBigUInt64LE(opts.delegate[1], 121); }
  return d;
}
export function mintData(authority: PublicKey, decimals: number): Buffer {
  const d = Buffer.alloc(82); d.writeUInt32LE(1, 0); authority.toBuffer().copy(d, 4); d.writeUInt8(decimals, 44); d.writeUInt8(1, 45); return d;
}
/** Seed a token account at `addr` (WXNT = native-backed classic SPL; everything else Token-2022 unless `tp`). */
export function seedTok(svm: LiteSVM, addr: PublicKey, mint: PublicKey, owner: PublicKey, amount: bigint, opts: { tp?: PublicKey; delegate?: [PublicKey, bigint]; state?: number } = {}) {
  const isNative = mint.equals(WXNT); const tp = opts.tp ?? (isNative ? TOKEN : TOKEN22);
  svm.setAccount(addr, { lamports: Number(RENT_ACCT + (isNative ? amount : 0n)), data: tokenData(mint, owner, amount, { native: isNative ? RENT_ACCT : undefined, delegate: opts.delegate, state: opts.state }), owner: tp, executable: false, rentEpoch: 0 });
}
export const tokAmount = (svm: LiteSVM, pk: PublicKey): bigint => { const a = svm.getAccount(pk); return a && a.data.length >= 72 ? Buffer.from(a.data).readBigUInt64LE(64) : 0n; };
export const delegatedAmount = (svm: LiteSVM, pk: PublicKey): bigint => Buffer.from(svm.getAccount(pk)!.data).readBigUInt64LE(121);
export const exists = (svm: LiteSVM, pk: PublicKey) => svm.getAccount(pk) !== null;
export const lamports = (svm: LiteSVM, pk: PublicKey): bigint => svm.getBalance(pk) ?? 0n;

/** `cu = 0` omits the ComputeBudget ix (saves ~40 B for account-heavy legacy txs; LiteSVM's default budget then applies). */
export function send(svm: LiteSVM, feePayer: Keypair, ixs: TransactionInstruction[], extra: Keypair[] = [], cu = 1_000_000) {
  svm.expireBlockhash();
  const tx = new Transaction().add(...(cu > 0 ? [ComputeBudgetProgram.setComputeUnitLimit({ units: cu })] : []), ...ixs);
  tx.recentBlockhash = svm.latestBlockhash(); tx.feePayer = feePayer.publicKey; tx.sign(feePayer, ...extra);
  return svm.sendTransaction(tx);
}
export const failed = (r: any) => typeof r?.err === "function";
export const code = (r: any): number | null => { const e = r?.err?.()?.err?.(); return e && typeof e.code === "number" ? e.code : null; };
export const logsOf = (r: any): string[] => (failed(r) ? r.meta().logs() : r.logs());
export const cuOf = (r: any): bigint => (failed(r) ? r.meta().computeUnitsConsumed() : r.computeUnitsConsumed());
export function mustOk(r: any, what: string) { assert.isFalse(failed(r), `${what} failed: ${code(r)} :: ${logsOf(r).slice(-8).join(" | ")}`); return r; }
export function mustFail(r: any, c: number | null, what: string) {
  assert.isTrue(failed(r), `${what}: expected revert ${c} but tx succeeded`);
  if (c !== null) assert.equal(code(r), c, `${what}: error code :: ${logsOf(r).slice(-5).join(" | ")}`);
  return r;
}
export function events(r: any, name: string): Buffer[] {
  const d = eventDisc(name);
  return logsOf(r).filter((l) => l.startsWith("Program data: ")).map((l) => Buffer.from(l.slice(14), "base64")).filter((b) => b.subarray(0, 8).equals(d)).map((b) => b.subarray(8));
}
export function routeExecuted(r: any) { const e = events(r, "RouteExecuted"); assert.equal(e.length, 1, "exactly one RouteExecuted"); const d = e[0];
  return { user: new PublicKey(d.subarray(0, 32)), hops: d[32], amountIn: d.readBigUInt64LE(33), gross: d.readBigUInt64LE(41), fee: d.readBigUInt64LE(49), net: d.readBigUInt64LE(57) }; }

export type Meta = { pubkey: PublicKey; isSigner: boolean; isWritable: boolean };
export const m = (pubkey: PublicKey, isWritable: boolean, isSigner = false): Meta => ({ pubkey, isSigner, isWritable });
/** 13-account XDEX window: [payer, authority, amm_config, pool, in_ata, out_ata, in_vault, out_vault, in_tp, out_tp, in_mint, out_mint, observation]. */
export function xdexWindow(payer: PublicKey, p: Pool, inMint: PublicKey, inAta: PublicKey, outAta: PublicKey, payerIsSigner: boolean): Meta[] {
  const s = side(p, inMint);
  return [m(payer, false, payerIsSigner), m(XDEX_AUTH, false), m(p.ammConfig, false), m(p.address, true), m(inAta, true), m(outAta, true),
    m(s.inVault, true), m(s.outVault, true), m(s.inTp, false), m(s.outTp, false), m(s.inMint, false), m(s.outMint, false), m(p.observation, true)];
}
export type WireOpts = { /** v0.3.0 shape (no fee_config account) */ noFeeConfig?: boolean; feeConfig?: PublicKey; rawData?: Buffer };
/** route_v2_snipe: 19 accounts (18 + fee_config) — `over` replaces slots. */
export function snipeIx(user: PublicKey, p: Pool, inMint: PublicKey, inAta: PublicKey, outAta: PublicKey, feeDestination: PublicKey, amountIn: bigint, minOut: bigint, o: WireOpts & { over?: Record<number, Meta> } = {}) {
  const s = side(p, inMint);
  const keys: Meta[] = [
    m(user, true, true), m(XDEX_AUTH, false), m(p.ammConfig, false), m(p.address, true), m(inAta, true), m(outAta, true),
    m(s.inVault, true), m(s.outVault, true), m(s.inTp, false), m(s.outTp, false), m(s.inMint, false), m(s.outMint, false), m(p.observation, true),
    m(feeDestination, true), m(FEE_WALLET, false), m(XDEX, false), m(ATA_PROGRAM, false), m(SYS, false),
  ];
  if (!o.noFeeConfig) keys.push(m(o.feeConfig ?? FEE_CONFIG, false));
  for (const [i, v] of Object.entries(o.over ?? {})) keys[Number(i)] = v;
  return new TransactionInstruction({ programId: ROUTER, keys, data: o.rawData ?? Buffer.concat([disc("route_v2_snipe"), u64(amountIn), u64(minOut)]) });
}
export type DelegatedFixed = { user: PublicKey; delegate: PublicKey; payer: PublicKey; userInputAta: PublicKey; userOutputAta: PublicKey; feeDestination: PublicKey };
/** route_v2_delegated: 12 fixed (11 + fee_config) + n x 13. */
export function delegatedIx(f: DelegatedFixed, legs: number[], amountIn: bigint, minOut: bigint, remaining: Meta[], o: WireOpts = {}) {
  const keys: Meta[] = [m(f.user, false), m(f.delegate, false, true), m(f.payer, true, true), m(VAULT_AUTH, false), m(f.userInputAta, true), m(f.userOutputAta, true),
    m(f.feeDestination, true), m(FEE_WALLET, false), m(SYS, false), m(ATA_PROGRAM, false), m(XDEX, false)];
  if (!o.noFeeConfig) keys.push(m(o.feeConfig ?? FEE_CONFIG, false));
  keys.push(...remaining);
  return new TransactionInstruction({ programId: ROUTER, keys, data: o.rawData ?? Buffer.concat([disc("route_v2_delegated"), vecU8(legs), u64(amountIn), u64(minOut)]) });
}
/** route_v2: 9 fixed (8 + MANDATORY `fee_config`, v0.4.2 security fix — was the v0.3.1
 *  B-M2 OPTIONAL trailing account) + windows EXACTLY. `noFeeConfig` reproduces the
 *  pre-fix 8-fixed wire (now `AccountNotEnoughKeys` on the current binary; kept so
 *  the old-wire regression stays pinned). */
export function routeV2Ix(user: PublicKey, feeDest: PublicKey, legs: number[], amountIn: bigint, minOut: bigint, remaining: Meta[], o: WireOpts = {}) {
  const keys: Meta[] = [m(user, true, true), m(feeDest, true), m(FEE_WALLET, false), m(SYS, false), m(ATA_PROGRAM, false), m(XDEX, false), m(DEGEN, false), m(TOKEN, false)];
  if (!o.noFeeConfig) keys.push(m(o.feeConfig ?? FEE_CONFIG, false));
  keys.push(...remaining);
  return new TransactionInstruction({ programId: ROUTER, keys, data: o.rawData ?? Buffer.concat([disc("route_v2"), vecU8(legs), u64(amountIn), u64(minOut)]) });
}
/** LEGACY-BINARY-ONLY: the PRE-v0.4.2 `route_v2` wire (8 fixed + windows + the
 *  fee_config PDA as an OPTIONAL TRAILING remaining account, v0.3.1 B-M2) — the
 *  exact shape the archived `LIVE_V031_SO` ELF still understands. NOT for use
 *  against the current binary (whose `RouteV2` struct now declares fee_config
 *  as a mandatory FIXED field at position 8, before remaining_accounts — see
 *  {@link routeV2Ix}). Exists ONLY so cross-binary A/B tests can send the LIVE
 *  v0.3.1 bytes the wire they actually accept. */
export function routeV2IxLegacyTail(user: PublicKey, feeDest: PublicKey, legs: number[], amountIn: bigint, minOut: bigint, remaining: Meta[]) {
  const keys: Meta[] = [m(user, true, true), m(feeDest, true), m(FEE_WALLET, false), m(SYS, false), m(ATA_PROGRAM, false), m(XDEX, false), m(DEGEN, false), m(TOKEN, false), ...remaining, m(FEE_CONFIG, false)];
  return new TransactionInstruction({ programId: ROUTER, keys, data: Buffer.concat([disc("route_v2"), vecU8(legs), u64(amountIn), u64(minOut)]) });
}
/** route_v3 (v0.4.0): 11 fixed (route_v2's 8 + fee_config + integrator_fee_destination + integrator_wallet) + windows EXACTLY; data = route_v2 args + u16 bps. */
export type RouteV3Opts = { feeConfig?: PublicKey | false; rawData?: Buffer; over?: Record<number, Meta>; tail?: Meta[] };
export function routeV3Ix(user: PublicKey, feeDest: PublicKey, integratorDest: PublicKey, integratorWallet: PublicKey, legs: number[], amountIn: bigint, minOut: bigint, bps: number, remaining: Meta[], o: RouteV3Opts = {}) {
  const keys: Meta[] = [m(user, true, true), m(feeDest, true), m(FEE_WALLET, false), m(SYS, false), m(ATA_PROGRAM, false), m(XDEX, false), m(DEGEN, false), m(TOKEN, false)];
  if (o.feeConfig !== false) keys.push(m(o.feeConfig ?? FEE_CONFIG, false));
  keys.push(m(integratorDest, true), m(integratorWallet, false), ...remaining, ...(o.tail ?? []));
  for (const [i, v] of Object.entries(o.over ?? {})) keys[Number(i)] = v;
  const u16 = Buffer.alloc(2); u16.writeUInt16LE(bps);
  return new TransactionInstruction({ programId: ROUTER, keys, data: o.rawData ?? Buffer.concat([disc("route_v3"), vecU8(legs), u64(amountIn), u64(minOut), u16]) });
}
export function integratorFeePaid(r: any) { const e = events(r, "IntegratorFeePaid"); assert.equal(e.length, 1, "exactly one IntegratorFeePaid"); const d = e[0];
  return { user: new PublicKey(d.subarray(0, 32)), wallet: new PublicKey(d.subarray(32, 64)), destination: new PublicKey(d.subarray(64, 96)), bps: d.readUInt16LE(96), amount: d.readBigUInt64LE(98) }; }
/** Governance / misc ixs. */
export const ixVersion = () => new TransactionInstruction({ programId: ROUTER, keys: [], data: disc("version") });
export const ixSetPaused = (signer: PublicKey, paused: boolean) => new TransactionInstruction({ programId: ROUTER, keys: [m(signer, false, true), m(FEE_CONFIG, true)], data: Buffer.concat([disc("set_paused"), Buffer.from([paused ? 1 : 0])]) });
export const ixSetGuardian = (authority: PublicKey, guardian: PublicKey) => new TransactionInstruction({ programId: ROUTER, keys: [m(authority, false, true), m(FEE_CONFIG, true)], data: Buffer.concat([disc("set_guardian"), guardian.toBuffer()]) });
export const ixMigrate = (authority: PublicKey, newAuth: PublicKey) => new TransactionInstruction({ programId: ROUTER, keys: [m(authority, false, true), m(FEE_CONFIG, true)], data: Buffer.concat([disc("migrate_fee_authority"), newAuth.toBuffer()]) });
export const approveIx = (tp: PublicKey, account: PublicKey, delegate: PublicKey, owner: PublicKey, amount: bigint) =>
  new TransactionInstruction({ programId: tp, keys: [m(account, true), m(delegate, false), m(owner, false, true)], data: Buffer.concat([Buffer.from([4]), u64(amount)]) });

/** A funded user with `wxnt` in the canonical WXNT ATA and an (empty) USDC.X ATA. */
export function setupUser(svm: LiteSVM, wxnt: bigint, usdcx = 0n, user: Keypair = Keypair.generate()) {
  svm.airdrop(user.publicKey, 2_000_000_000n);
  const userWxnt = ata(WXNT, user.publicKey, TOKEN); seedTok(svm, userWxnt, WXNT, user.publicKey, wxnt);
  const userUsdcx = ata(USDCX, user.publicKey, TOKEN22); seedTok(svm, userUsdcx, USDCX, user.publicKey, usdcx);
  return { user, userWxnt, userUsdcx, feeUsdcx: ata(USDCX, FEE_WALLET, TOKEN22), feeWxnt: ata(WXNT, FEE_WALLET, TOKEN) };
}
/** A follower (owner) with WXNT, a delegate/payer, and the canonical destinations. */
export function setupDelegated(svm: LiteSVM, wxnt: bigint, user: Keypair = Keypair.generate(), delegate: Keypair = Keypair.generate()) {
  svm.airdrop(user.publicKey, 1_000_000_000n); svm.airdrop(delegate.publicKey, 1_000_000_000n);
  const userWxnt = ata(WXNT, user.publicKey, TOKEN); seedTok(svm, userWxnt, WXNT, user.publicKey, wxnt);
  const userUsdcx = ata(USDCX, user.publicKey, TOKEN22);
  const s = { user, delegate, userWxnt, userUsdcx, vaultUsdcx: ata(USDCX, VAULT_AUTH, TOKEN22), vaultWxnt: ata(WXNT, VAULT_AUTH, TOKEN), feeUsdcx: ata(USDCX, FEE_WALLET, TOKEN22), feeWxnt: ata(WXNT, FEE_WALLET, TOKEN) };
  const fixed: DelegatedFixed = { user: user.publicKey, delegate: delegate.publicKey, payer: delegate.publicKey, userInputAta: userWxnt, userOutputAta: userUsdcx, feeDestination: s.feeUsdcx };
  return { ...s, fixed };
}
export const IN = 100_000_000n; // 0.1 WXNT — tiny against the live pool (34k WXNT deep)
/** Deterministic keypairs for CU comparisons: PDA/ATA derivation cost (bump search) depends on the keys, so A/B runs must share them. */
export const fixedKey = (n: number) => Keypair.fromSeed(Buffer.alloc(32, n + 1));
