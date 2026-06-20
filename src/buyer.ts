/**
 * Buyer-side helpers (shared by the browser client and node tests).
 *
 * Mirrors the proven testclient flow: decode the daemon's 402 PaymentRequest,
 * create a Lightning mint quote, wait for payment, then mint proofs P2PK-locked
 * to the daemon's per-tx pubkey (with DLEQ). The result is a NUT-18 payment
 * payload the browser POSTs to /pay/:orderId — the same shape a Cashu wallet
 * delivers over the request's HTTP transport. So the human just pays a Lightning
 * invoice — no Cashu wallet needed.
 *
 * cashu-ts calls here are identical to what was validated live against testnut.
 */

import { OutputData, decodePaymentRequest, type Proof } from '@cashu/cashu-ts';

export interface Challenge {
  amount: number;
  mintUrl: string;
  unit: string;
  lockPubkey: string;
}

/** Decode the daemon's creqA (402 x-cashu) into the fields the buyer needs. */
export function decodeChallenge(creq: string): Challenge {
  const pr = decodePaymentRequest(creq);
  const amount = pr.amount ? Number(pr.amount.toNumber()) : 0;
  const mintUrl = pr.mints?.[0] ?? '';
  const lockPubkey = pr.nut10?.data ?? '';
  if (!amount || !mintUrl || !lockPubkey) throw new Error('invalid or unsupported payment request');
  return { amount, mintUrl, unit: pr.unit ?? 'sat', lockPubkey };
}

// The slice of cashu-ts Wallet the buyer flow uses (so tests can fake it).
export interface MintQuote {
  quote: string;
  request?: string;
  state: string;
}
export interface MintWallet {
  createMintQuoteBolt11(amount: number): Promise<MintQuote>;
  checkMintQuoteBolt11(quote: string): Promise<{ state: string }>;
  getKeyset(): unknown;
  ops: {
    mintBolt11(amount: number, quote: MintQuote): { asCustom(outputs: unknown): { run(): Promise<Proof[]> } };
  };
}

/** Poll a mint quote until it is paid. Resolves true on PAID/ISSUED, false on timeout. */
export async function waitForPaid(
  wallet: MintWallet,
  quoteId: string,
  opts: { tries?: number; intervalMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<boolean> {
  const tries = opts.tries ?? 90;
  const intervalMs = opts.intervalMs ?? 2000;
  const sleep = opts.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
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

/** Mint proofs P2PK-locked to lockPubkey and return them as a NUT-18 payload. */
export async function mintLockedPayload(
  wallet: MintWallet,
  challenge: Challenge,
  quote: MintQuote,
): Promise<PaymentPayload> {
  const outputs = OutputData.createP2PKData(
    { pubkey: challenge.lockPubkey },
    challenge.amount,
    wallet.getKeyset() as Parameters<typeof OutputData.createP2PKData>[2],
  );
  const proofs = await wallet.ops.mintBolt11(challenge.amount, quote).asCustom(outputs).run();
  return { mint: challenge.mintUrl, unit: challenge.unit, proofs };
}
