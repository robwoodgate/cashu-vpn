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

import { Wallet, getEncodedToken, sumProofs, type Proof } from '@cashu/cashu-ts';
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
  /** Re-encoded unlocked token the operator now owns (import anywhere). */
  token?: string;
  errors: string[];
}

/** Claim one locked token with its private key, returning fresh unlocked proofs. */
export type Claimer = (mint: string, token: string, privkey: string) => Promise<Proof[]>;

const defaultClaimer: Claimer = async (mint, token, privkey) => {
  const wallet = new Wallet(mint, { unit: 'sat' });
  await wallet.loadMint();
  return wallet.receive(token, { privkey });
};

/** Claim every sweepable entry, grouped per mint. Online (claimer hits the mint). */
export async function sweepAll(
  plan: SweepPlan,
  claim: Claimer = defaultClaimer,
  encode: (mint: string, proofs: Proof[]) => string = (mint, proofs) =>
    getEncodedToken({ mint, proofs, unit: 'sat' }),
): Promise<SweepResult[]> {
  const byMint = new Map<string, SweepEntry[]>();
  for (const e of plan.sweepable) {
    const list = byMint.get(e.mint);
    if (list) list.push(e);
    else byMint.set(e.mint, [e]);
  }

  const results: SweepResult[] = [];
  for (const [mint, entries] of byMint) {
    const proofs: Proof[] = [];
    const errors: string[] = [];
    for (const e of entries) {
      try {
        proofs.push(...(await claim(mint, e.token, e.privkey)));
      } catch (err) {
        errors.push(`index ${e.index}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    results.push({
      mint,
      claimedSats: proofs.length ? Number((sumProofs(proofs) as { toNumber: () => number }).toNumber()) : 0,
      token: proofs.length ? encode(mint, proofs) : undefined,
      errors,
    });
  }
  return results;
}

async function main(): Promise<void> {
  const xprv = process.env.OPERATOR_XPRV;
  const proofsPath = process.env.PROOFS_PATH ?? process.argv[2];
  if (!xprv) throw new Error('set OPERATOR_XPRV (your offline xprv) to sweep');
  if (!proofsPath) throw new Error('set PROOFS_PATH or pass the proof store path as the first arg');

  const receipts = await createFileProofStore(proofsPath).list();
  const plan = planSweep(receipts, xprv);
  console.error(
    `receipts: ${receipts.length} | sweepable: ${plan.sweepable.length} | ` +
      `manual(fixed-key): ${plan.manual.length} | mismatched: ${plan.mismatched.length}`,
  );
  const results = await sweepAll(plan);
  console.log(JSON.stringify(results, null, 2));
}

const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) {
  void main().catch((e) => {
    console.error('sweep failed:', e instanceof Error ? e.message : e);
    process.exitCode = 1;
  });
}
