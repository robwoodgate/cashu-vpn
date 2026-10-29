/**
 * Buyer-side helpers (shared by the browser client and node tests).
 *
 * Mirrors the proven testclient flow: decode the daemon's 402 PaymentRequest,
 * create a Lightning mint quote, wait for payment, then mint proofs carrying the
 * request's lock (nutroot on a v3 keyset, NUT-11 before). The result is a NUT-18
 * payment payload the browser POSTs to /pay/:orderId, the same shape a Cashu wallet
 * delivers over the request's HTTP transport. So the human just pays a Lightning
 * invoice; no Cashu wallet needed.
 */

import {
  decodePaymentRequest,
  isBlsKeyset,
  nutrootToLockOptions,
  p2pkToLockOptions,
  type LockOptions,
  type MintQuoteBolt11Response,
  type PaymentRequest,
  type Proof,
} from '@cashu/cashu-ts';
import { popcount } from './cashu.js';

/** How long a renewed lease keeps working after the renewal, so the buyer can import the new config. */
export const RENEWAL_GRACE_MS = 15 * 60 * 1000;

export interface Challenge {
  amount: number;
  mintUrl: string;
  unit: string;
  request: PaymentRequest;
}

/** Decode the daemon's creqA (402 x-cashu) into the fields the buyer needs. */
export function decodeChallenge(creq: string): Challenge {
  const pr = decodePaymentRequest(creq);
  const amount = pr.amount ? Number(pr.amount.toNumber()) : 0;
  const mintUrl = pr.mints?.[0] ?? '';
  if (!amount || !mintUrl || !(pr.nut10 || pr.toNutrootOptions())) {
    throw new Error('invalid or unsupported payment request');
  }
  return { amount, mintUrl, unit: pr.unit ?? 'sat', request: pr };
}

// The slice of cashu-ts Wallet the buyer flow uses (so tests can fake it).
export type MintQuote = MintQuoteBolt11Response;
interface MintRun {
  privkey(k: string): MintRun;
  run(): Promise<Proof[]>;
}
export interface MintWallet {
  createQuoteLockKey(): Promise<{ pubkey: string; privkey: string }>;
  createMintQuoteBolt11(amount: number, pubkey: string): Promise<MintQuote>;
  checkMintQuoteBolt11(quote: string): Promise<MintQuote>;
  getKeyset(): { id: string };
  getFeesForKeyset(nInputs: number, keysetId: string): { toNumber(): number };
  /** NUT-17 WebSocket events (present on a real cashu-ts Wallet); used by waitForPaid. */
  on?: { onceMintPaid(id: string, opts?: { signal?: AbortSignal; timeoutMs?: number }): Promise<unknown> };
  ops: {
    mintBolt11(amount: number, quote: MintQuote): { asLocked(lock: LockOptions): MintRun };
  };
}

/**
 * Wait until a mint quote is paid. Resolves true on PAID/ISSUED, false on timeout.
 *
 * Primary: a NUT-17 WebSocket subscription (wallet.on.onceMintPaid) — event-driven,
 * so it's far lighter on the mint's rate limits than polling. If the WS isn't
 * available, or drops EARLY (a connection failure rather than a genuine timeout),
 * fall back to polling for whatever budget remains. The polling path is unchanged
 * and is what the unit tests exercise (their fake wallet has no `on`).
 */
export async function waitForPaid(
  wallet: MintWallet,
  quoteId: string,
  opts: { tries?: number; intervalMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<boolean> {
  const tries = opts.tries ?? 90;
  const intervalMs = opts.intervalMs ?? 2000;
  const sleep = opts.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  const budgetMs = tries * intervalMs;

  if (wallet.on?.onceMintPaid) {
    const start = Date.now();
    try {
      await wallet.on.onceMintPaid(quoteId, { timeoutMs: budgetMs });
      return true;
    } catch {
      // Burned most of the budget → it was a real timeout (not paid in time).
      if (Date.now() - start >= budgetMs - intervalMs) return false;
      // Dropped early → poll the remaining budget as a safety net.
    }
    const remainingTries = Math.ceil(Math.max(0, budgetMs - (Date.now() - start)) / intervalMs);
    return pollPaid(wallet, quoteId, remainingTries, intervalMs, sleep);
  }

  return pollPaid(wallet, quoteId, tries, intervalMs, sleep);
}

async function pollPaid(
  wallet: MintWallet,
  quoteId: string,
  tries: number,
  intervalMs: number,
  sleep: (ms: number) => Promise<void>,
): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const { state } = await wallet.checkMintQuoteBolt11(quoteId);
    if (state === 'PAID' || state === 'ISSUED') return true;
    await sleep(intervalMs);
  }
  return false;
}

/** A NUT-18 payment payload: what a wallet POSTs to the request's transport target. */
export interface PaymentPayload {
  mint: string;
  unit: string;
  proofs: Proof[];
}

/** Amount to mint so the payee still nets the price after spending the proofs (NUT-02 input fees). */
export function mintAmount(wallet: MintWallet, challenge: Challenge): number {
  const keysetId = wallet.getKeyset().id;
  let gross = challenge.amount;
  while (gross - wallet.getFeesForKeyset(popcount(gross), keysetId).toNumber() < challenge.amount) gross++;
  return gross;
}

/**
 * Mint proofs carrying the request's lock and return them as a NUT-18 payload.
 * `quoteKey` signs a locked mint quote; omit it only for a legacy unlocked one.
 */
export async function mintLockedPayload(
  wallet: MintWallet,
  challenge: Challenge,
  quote: MintQuote,
  quoteKey?: string,
): Promise<PaymentPayload> {
  // The request states one lock in two encodings: follow the one this keyset takes (as sendToRequest does).
  const pr = challenge.request;
  const nutroot = pr.toNutrootOptions();
  const nut10 = pr.toP2PKOptions();
  const lock = isBlsKeyset(wallet.getKeyset().id) ? nutroot && nutrootToLockOptions(nutroot) : nut10 && p2pkToLockOptions(nut10);
  if (!lock) throw new Error('the payment request has no lock this mint’s keyset can carry');
  const mint = wallet.ops.mintBolt11(mintAmount(wallet, challenge), quote).asLocked(lock);
  const proofs = await (quoteKey ? mint.privkey(quoteKey) : mint).run();
  return { mint: challenge.mintUrl, unit: challenge.unit, proofs };
}
