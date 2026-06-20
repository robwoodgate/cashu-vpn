/**
 * Operator sweep — claim locked proofs with the offline xprv.
 *
 * Run this OFF the server, where the xprv lives. For each stored receipt it
 * derives the matching child private key (from the same index the daemon issued
 * the lock at) and claims the P2PK-locked token from the mint, producing fresh
 * unlocked proofs the operator owns. Fixed-pubkey receipts (no index) are listed
 * for manual claiming with the operator's single key.
 *
 * Usage: OPERATOR_XPRV=xprv... PROOFS_PATH=./proofs.json node dist/src/sweep.js
 *
 * The derivation correctness (daemon pubkey <-> operator privkey) is proven by
 * the hdkeys roundtrip test; the online claim is validated at the deploy checkpoint.
 */

import { writeFile } from 'node:fs/promises';
import { Wallet, getDecodedToken, getEncodedToken, sumProofs, type Proof } from '@cashu/cashu-ts';
import { pathToFileURL } from 'node:url';
import { deriveChildKeypair } from './hdkeys.js';
import { normalizePubkey } from './cashu.js';
import { createFileProofStore, type ReceivedPayment } from './wallet.js';

export interface SweepEntry {
  index: number;
  mint: string;
  amountSats: number;
  token: string;
  pubkey: string;
  privkey: string;
}

export interface SweepPlan {
  sweepable: SweepEntry[];
  /** Fixed-pubkey receipts (no index): claim with your single operator key. */
  manual: ReceivedPayment[];
  /** Derived pubkey didn't match the stored lock — should never happen; never claimed. */
  mismatched: ReceivedPayment[];
}

/** Pure: derive the claiming key for each receipt. No network. */
export function planSweep(receipts: ReceivedPayment[], xprv: string): SweepPlan {
  const sweepable: SweepEntry[] = [];
  const manual: ReceivedPayment[] = [];
  const mismatched: ReceivedPayment[] = [];

  for (const r of receipts) {
    if (r.index === undefined) {
      manual.push(r);
      continue;
    }
    const kp = deriveChildKeypair(xprv, r.index);
    if (r.lockPubkey && normalizePubkey(kp.pubkey) !== normalizePubkey(r.lockPubkey)) {
      mismatched.push(r);
      continue;
    }
    sweepable.push({
      index: r.index,
      mint: r.mint,
      amountSats: r.amountSats,
      token: r.token,
      pubkey: kp.pubkey,
      privkey: kp.privkey,
    });
  }

  return { sweepable, manual, mismatched };
}

export interface SweepResult {
  mint: string;
  claimedSats: number;
  /** Number of locked receipts folded into this mint's swap(s). */
  receipts: number;
  /** True if all receipts were claimed in a single batched swap (cheapest). */
  batched: boolean;
  /** Re-encoded unlocked token the operator now owns (import anywhere). */
  token?: string;
  errors: string[];
}

/**
 * Claim a batch of P2PK-locked proofs in ONE swap, signing each with whichever of
 * `privkeys` matches it (cashu-ts picks per proof). One swap means the mint's
 * per-input fee is rounded once for the whole batch instead of once per receipt,
 * so sweeping many small receipts costs far less. Returns fresh unlocked proofs.
 */
export type Claimer = (mint: string, proofs: Proof[], privkeys: string[]) => Promise<Proof[]>;

const defaultClaimer: Claimer = async (mint, proofs, privkeys) => {
  const wallet = new Wallet(mint, { unit: 'sat' });
  await wallet.loadMint();
  return wallet.receive(proofs, { privkey: privkeys });
};

/** Decode a stored (locked) token into its proofs. */
export type Decoder = (token: string) => Proof[];
const defaultDecoder: Decoder = (token) => getDecodedToken(token, []).proofs;

const sum = (proofs: Proof[]): number =>
  proofs.length ? Number((sumProofs(proofs) as { toNumber: () => number }).toNumber()) : 0;

/**
 * Claim every sweepable entry, grouped per mint, batching each mint into a single
 * swap to minimise input fees. If a batch fails (e.g. one receipt was already
 * swept), fall back to claiming that mint's receipts individually so one bad
 * proof can't strand the rest. Online (the claimer hits the mint).
 */
export async function sweepAll(
  plan: SweepPlan,
  claim: Claimer = defaultClaimer,
  encode: (mint: string, proofs: Proof[]) => string = (mint, proofs) =>
    getEncodedToken({ mint, proofs, unit: 'sat' }),
  decode: Decoder = defaultDecoder,
): Promise<SweepResult[]> {
  const byMint = new Map<string, SweepEntry[]>();
  for (const e of plan.sweepable) {
    const list = byMint.get(e.mint);
    if (list) list.push(e);
    else byMint.set(e.mint, [e]);
  }

  const results: SweepResult[] = [];
  for (const [mint, entries] of byMint) {
    const keysOf = (es: SweepEntry[]) => [...new Set(es.map((e) => e.privkey))];
    const proofsOf = (es: SweepEntry[]) => es.flatMap((e) => decode(e.token));

    // Fast path: one swap for the whole mint.
    try {
      const claimed = await claim(mint, proofsOf(entries), keysOf(entries));
      results.push({
        mint, receipts: entries.length, batched: true,
        claimedSats: sum(claimed), token: claimed.length ? encode(mint, claimed) : undefined, errors: [],
      });
      continue;
    } catch (batchErr) {
      // Fall back: isolate each receipt so a single spent/invalid one doesn't
      // sink the others.
      const claimed: Proof[] = [];
      const errors: string[] = [`batch swap failed (${batchErr instanceof Error ? batchErr.message : String(batchErr)}); retried individually`];
      for (const e of entries) {
        try {
          claimed.push(...(await claim(mint, decode(e.token), [e.privkey])));
        } catch (err) {
          errors.push(`index ${e.index}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      results.push({
        mint, receipts: entries.length, batched: false,
        claimedSats: sum(claimed), token: claimed.length ? encode(mint, claimed) : undefined, errors,
      });
    }
  }
  return results;
}

// --- NUT-07 proof-state checks (idempotent sweep + prune) ---

/**
 * Ask the mint the spend state of a batch of proofs. The mint is the source of
 * truth for what's already been swept, so we never rely on local bookkeeping.
 * Returns states in the same order as the input.
 *
 * Note: checking proofs together lets the mint see they're related — but a
 * batched receive already spends them together, so when batching this leaks
 * nothing new. (Want maximum unlinkability? Sweep receipts one-by-one, unbatched,
 * at higher fees.)
 */
export type StateChecker = (mint: string, proofs: Array<{ secret: string; id: string }>) => Promise<string[]>;

const defaultStateChecker: StateChecker = async (mint, proofs) => {
  const wallet = new Wallet(mint, { unit: 'sat' });
  await wallet.loadMint();
  const states = await wallet.checkProofsStates(proofs);
  return states.map((s) => s.state);
};

/** A receipt is fully swept when every one of its proofs reads SPENT at the mint. */
async function fullySpentByMint<T extends { mint: string; token: string }>(
  items: T[],
  decode: Decoder,
  check: StateChecker,
): Promise<Map<T, boolean>> {
  const result = new Map<T, boolean>();
  const byMint = new Map<string, T[]>();
  for (const it of items) {
    const list = byMint.get(it.mint);
    if (list) list.push(it);
    else byMint.set(it.mint, [it]);
  }
  for (const [mint, group] of byMint) {
    // One state check per mint: flatten all proofs, remember each item's span.
    const spans: Array<{ item: T; start: number; len: number }> = [];
    const flat: Array<{ secret: string; id: string }> = [];
    for (const item of group) {
      const proofs = decode(item.token);
      spans.push({ item, start: flat.length, len: proofs.length });
      for (const p of proofs) flat.push({ secret: p.secret, id: p.id });
    }
    const states = await check(mint, flat);
    for (const { item, start, len } of spans) {
      const slice = states.slice(start, start + len);
      result.set(item, len > 0 && slice.every((s) => s === 'SPENT'));
    }
  }
  return result;
}

/** Split a plan's sweepable entries into those still claimable vs already swept. */
export async function filterUnswept(
  plan: SweepPlan,
  decode: Decoder = defaultDecoder,
  check: StateChecker = defaultStateChecker,
): Promise<{ sweepable: SweepEntry[]; alreadySwept: SweepEntry[] }> {
  const spent = await fullySpentByMint(plan.sweepable, decode, check);
  const sweepable: SweepEntry[] = [];
  const alreadySwept: SweepEntry[] = [];
  for (const e of plan.sweepable) (spent.get(e) ? alreadySwept : sweepable).push(e);
  return { sweepable, alreadySwept };
}

/** Partition raw receipts into keep (not fully spent) vs drop (swept) for prune. */
export async function pruneSpent(
  receipts: ReceivedPayment[],
  decode: Decoder = defaultDecoder,
  check: StateChecker = defaultStateChecker,
): Promise<{ keep: ReceivedPayment[]; dropped: ReceivedPayment[] }> {
  const spent = await fullySpentByMint(receipts, decode, check);
  const keep: ReceivedPayment[] = [];
  const dropped: ReceivedPayment[] = [];
  for (const r of receipts) (spent.get(r) ? dropped : keep).push(r);
  return { keep, dropped };
}

// --- CLI ---

async function runSweep(proofsPath: string, xprv: string): Promise<void> {
  const store = createFileProofStore(proofsPath);
  const receipts = await store.list();
  const plan = planSweep(receipts, xprv);
  // Skip receipts the mint already shows as spent (idempotent re-runs).
  const { sweepable, alreadySwept } = await filterUnswept(plan);
  console.error(
    `receipts: ${receipts.length} | claimable: ${sweepable.length} | already-swept: ${alreadySwept.length} | ` +
      `manual(fixed-key): ${plan.manual.length} | mismatched: ${plan.mismatched.length}`,
  );
  const results = await sweepAll({ ...plan, sweepable });
  const out = process.env.SWEEP_OUT;
  if (out) {
    await writeFile(out, JSON.stringify(results, null, 2) + '\n', 'utf8');
    console.error(`wrote claimed tokens -> ${out}`);
  }
  console.log(JSON.stringify(results, null, 2));
}

/** Keyless: drop receipts the mint shows as fully spent. Safe to run on the box. */
async function runPrune(proofsPath: string): Promise<void> {
  const store = createFileProofStore(proofsPath);
  const before = await store.list();
  const { keep, dropped } = await pruneSpent(before);
  // Re-read just before writing and re-attach any receipts that arrived meanwhile,
  // so a concurrent daemon append isn't lost to the prune.
  const now = await store.list();
  const keepIds = new Set(keep.map((r) => r.purchaseId));
  const droppedIds = new Set(dropped.map((r) => r.purchaseId));
  const merged = now.filter((r) => keepIds.has(r.purchaseId) || !droppedIds.has(r.purchaseId));
  await store.replaceAll(merged);
  console.error(`pruned ${dropped.length} swept receipt(s); kept ${merged.length}`);
}

async function main(): Promise<void> {
  const prune = process.argv.includes('--prune');
  const proofsPath = process.env.PROOFS_PATH ?? process.argv.find((a) => a !== '--prune' && a.endsWith('.json'));
  if (!proofsPath) throw new Error('set PROOFS_PATH or pass the proof store path as an arg');

  if (prune) {
    await runPrune(proofsPath);
    return;
  }

  const xprv = process.env.OPERATOR_XPRV;
  if (!xprv) throw new Error('set OPERATOR_XPRV (your offline xprv) to sweep');
  await runSweep(proofsPath, xprv);
}

const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) {
  void main().catch((e) => {
    console.error('sweep failed:', e instanceof Error ? e.message : e);
    process.exitCode = 1;
  });
}
