/**
 * Cashu payment: a 402 with a NUT-18 request, verified NON-CUSTODIALLY.
 *
 * The daemon NEVER holds spendable ecash. Each order's request demands proofs locked to a fresh
 * xpub child key (locks.ts) whose private key never touches the box, and the delivered token is
 * verified ENTIRELY OFFLINE, with no swap and no per-sale mint call:
 *
 *   1. getTokenMetadata(): mint and unit pre-check
 *   2. isMintSigned(): the mint signed each proof (NUT-12 DLEQ, or BLS on v3)
 *   3. isPaymentRequestSatisfied(): exactly the requested lock (nut10, or nutroot on v3), netting
 *      the price after input fees
 *   4. a proof-count cap against dust griefing
 *
 * The only mint interaction is loadMint() to fetch public keysets, cached per mint for a TTL.
 * Received tokens are stored locked; the operator sweeps them offline with their key.
 */

import {
  PaymentRequestBuilder,
  getTokenMetadata,
  getDecodedToken,
  verifyReceivedProofs,
  Wallet,
  sumProofs,
  type PaymentRequest,
  type Proof,
  type TokenMetadata,
  type HasKeysetKeys,
} from '@cashu/cashu-ts';

/** Per NUT-00, mint URLs are compared with trailing slashes stripped. */
export function normalizeMintUrl(url: string): string {
  return String(url ?? '').trim().replace(/\/+$/, '');
}

/**
 * Normalize a P2PK pubkey for comparison: lowercase, x-only. Strip the 02/03
 * parity prefix ONLY from a full 66-char compressed key — must be idempotent, or
 * re-normalizing an already-x-only key whose coordinate starts 02/03 over-strips
 * it (LockBook.resolve normalizes input that verifyPayment already normalized;
 * ~0.8% of xpub locks would then miss the lookup and reject a paid buyer).
 */
export function normalizePubkey(k: string): string {
  const s = String(k ?? '').toLowerCase();
  return s.length === 66 && /^0[23]/.test(s) ? s.slice(2) : s;
}

/**
 * The request every order quotes: `amountSats` net of input fees, locked to `lockPubkey`.
 * Carries both encodings (NUT-18): nutroot as a NUMS tree with one unblinded leaf, which a
 * watch-only payee can check (a key-path lock needs the private key, NUT-28), plus a nut10 twin.
 */
export function lockedRequest(opts: { amountSats: number; mints: string[]; lockPubkey: string; unit?: string }): PaymentRequestBuilder {
  // The builder validates what the lenient PaymentRequest class does not: the
  // lock pubkey must be compressed and on-curve, and mint URLs must parse.
  return new PaymentRequestBuilder()
    .amount(opts.amountSats, opts.unit ?? 'sat')
    .addMint(opts.mints)
    .lock({ leaves: [{ type: 'threshold', n: 1, keys: [opts.lockPubkey] }] })
    .nut10({ kind: 'P2PK', data: opts.lockPubkey, tags: [] });
}

/**
 * Build the NUT-18 PaymentRequest (creqA) used as the NUT-24 402 challenge.
 * `lockPubkey` is the P2PK pubkey the requested proofs must be locked to — a
 * fresh xpub-derived per-tx pubkey (see locks.ts).
 *
 * The request carries a NUT-18 HTTP POST transport, so a wallet pays and POSTs the
 * proofs straight to that URL (the per-order /pay/:orderId sink) — no copy/paste.
 * An agent does the same: decode the creqA, mint locked proofs, POST to the
 * transport target, then read the config from the response (or poll /order).
 */
export function buildPaymentRequest(opts: {
  paymentId: string;
  amountSats: number;
  mints: string[];
  lockPubkey: string;
  unit?: string;
  description?: string;
  transportTarget?: string;
}): string {
  const builder = lockedRequest(opts).id(opts.paymentId);
  if (opts.description) builder.description(opts.description);
  if (opts.transportTarget) builder.addHttpPostTransport(opts.transportTarget);
  return builder.build().toEncodedCreqA();
}

/** Number of set bits in a non-negative integer (minimal power-of-two split size). */
export function popcount(n: number): number {
  let count = 0;
  let v = Math.max(0, Math.floor(n));
  while (v > 0) {
    v &= v - 1;
    count++;
  }
  return count;
}

export interface VerifyResult {
  valid: boolean;
  amountSats: number;
  mint?: string;
  /** The (already locked) token to store for the operator to sweep. */
  token?: string;
  /** Proof secrets, for replay/double-spend dedupe in the store. */
  secrets?: string[];
  /** Normalized P2PK pubkey the proofs are locked to; the caller authorizes it. */
  lockPubkey?: string;
  error?: string;
}

interface MintContext {
  keysetIds: string[];
  getKeyset: (id: string) => HasKeysetKeys;
}

/** Seams so offline verification can be unit-tested without a live mint. */
export interface VerifyDeps {
  getMetadata?: (token: string) => TokenMetadata;
  loadMintContext?: (mint: string, unit: string) => Promise<MintContext>;
  decode?: (token: string, keysetIds: string[]) => Proof[];
  checkMintSignature?: (proof: Proof, keyset: HasKeysetKeys) => Promise<boolean>;
  checkRequest?: (request: PaymentRequest, proofs: Proof[], mint: string, unit: string) => Promise<boolean>;
}

/**
 * True if the mint signed this proof: DLEQ (NUT-12) on v0-v2 keysets, the BLS pairing on v3.
 * `require: true` refuses a proof with no DLEQ, which the spec default would pass.
 */
async function isMintSigned(proof: Proof, keyset: HasKeysetKeys): Promise<boolean> {
  const { invalid } = await verifyReceivedProofs([proof], () => keyset, { require: true });
  return invalid.length === 0;
}

function amountToNumber(a: unknown): number {
  if (a && typeof (a as { toNumber?: unknown }).toNumber === 'function') {
    return (a as { toNumber: () => number }).toNumber();
  }
  return Number(a);
}

// Mints are rate-limited; cache the loaded Wallet (and thus its public keysets)
// per mint+unit so loadMint() isn't re-run per purchase. A failed load is never
// cached. Keyset rotations are rare; the TTL bounds staleness.
const WALLET_CACHE_TTL_MS = 10 * 60 * 1000;
const walletCache = new Map<string, { wallet: Promise<Wallet>; createdAt: number }>();

function getCachedWallet(mint: string, unit: string): Promise<Wallet> {
  const key = `${mint}|${unit}`;
  const hit = walletCache.get(key);
  if (hit && Date.now() - hit.createdAt < WALLET_CACHE_TTL_MS) return hit.wallet;

  const wallet = (async () => {
    const w = new Wallet(mint, { unit });
    await w.loadMint();
    return w;
  })();
  wallet.catch(() => walletCache.delete(key));
  walletCache.set(key, { wallet, createdAt: Date.now() });
  return wallet;
}

const defaultLoadMintContext = async (mint: string, unit: string): Promise<MintContext> => {
  const wallet = await getCachedWallet(mint, unit);
  return {
    keysetIds: wallet.keyChain.getAllKeysetIds(),
    getKeyset: (id) => {
      const ks = wallet.keyChain.getKeyset(id);
      return { id: ks.id, keys: ks.keys };
    },
  };
};

/** True if the proofs settle `request` (lock + net amount); throws if they don't carry its lock. */
async function requestSatisfied(request: PaymentRequest, proofs: Proof[], mint: string, unit: string): Promise<boolean> {
  return (await getCachedWallet(mint, unit)).isPaymentRequestSatisfied(request, proofs);
}

/**
 * Verify a delivered Cashu token fully offline (no swap, no per-sale mint call).
 * Returns the operator-locked token + proof secrets on success.
 */
export async function verifyPayment(
  encodedToken: string,
  opts: { acceptedMints: string[]; requiredSats: number; lockPubkey: string; unit?: string; proofCountMargin?: number },
  deps: VerifyDeps = {},
): Promise<VerifyResult> {
  const unit = opts.unit ?? 'sat';
  const getMetadata = deps.getMetadata ?? getTokenMetadata;
  const loadMintContext = deps.loadMintContext ?? defaultLoadMintContext;
  const decode = deps.decode ?? ((t, ids) => getDecodedToken(t, ids).proofs);
  const checkMintSignature = deps.checkMintSignature ?? isMintSigned;
  const checkRequest = deps.checkRequest ?? requestSatisfied;

  let meta: TokenMetadata;
  try {
    meta = getMetadata(encodedToken);
  } catch {
    return { valid: false, amountSats: 0, error: 'invalid_token' };
  }

  const mint = normalizeMintUrl(meta.mint);
  if (!mint || !opts.acceptedMints.map(normalizeMintUrl).includes(mint)) {
    return { valid: false, amountSats: 0, error: 'mint_not_accepted' };
  }

  if (meta.unit && meta.unit !== unit) {
    return { valid: false, amountSats: 0, error: 'wrong_unit' };
  }

  let ctx: MintContext;
  try {
    ctx = await loadMintContext(mint, unit);
  } catch (e) {
    return { valid: false, amountSats: 0, error: `mint_unavailable: ${e instanceof Error ? e.message : String(e)}` };
  }

  let proofs: Proof[];
  try {
    proofs = decode(encodedToken, ctx.keysetIds);
  } catch {
    return { valid: false, amountSats: 0, error: 'invalid_token' };
  }
  if (!proofs.length) {
    return { valid: false, amountSats: 0, error: 'no_proofs' };
  }

  for (const proof of proofs) {
    let keyset: HasKeysetKeys;
    try {
      keyset = ctx.getKeyset(proof.id);
    } catch {
      return { valid: false, amountSats: 0, error: 'unknown_keyset' };
    }
    // Proof is genuinely mint-signed (verified offline); a throw counts as unsigned.
    let signed: boolean;
    try {
      signed = await checkMintSignature(proof, keyset);
    } catch {
      signed = false;
    }
    if (!signed) {
      return { valid: false, amountSats: 0, error: 'invalid_signature' };
    }
  }

  // Exactly the requested lock (nut10, or the nutroot tree on v3) with no refund or extra
  // signer, and enough to net the price after input fees (NUT-18). A throw is a lock failure.
  const amountSats = amountToNumber(sumProofs(proofs));
  const request = lockedRequest({ amountSats: opts.requiredSats, mints: opts.acceptedMints, lockPubkey: opts.lockPubkey, unit }).build();
  let satisfied: boolean;
  try {
    satisfied = await checkRequest(request, proofs, mint, unit);
  } catch {
    return { valid: false, amountSats, error: 'lock_mismatch' };
  }
  if (!satisfied) {
    return { valid: false, amountSats, error: 'amount_too_low' };
  }

  // Dust-griefing guard. A power-of-two split of `amountSats` needs exactly
  // popcount(amountSats) proofs; honest wallets land at or near that. A griefer
  // can instead pad the payment with many tiny proofs — each one an extra input
  // fee the operator eats when sweeping. Cap the count and reject BEFORE storing,
  // so the rejected token stays locked to us and is stranded for the griefer.
  const margin = opts.proofCountMargin ?? 0;
  if (proofs.length > popcount(amountSats) + margin) {
    return { valid: false, amountSats, error: 'too_many_proofs' };
  }

  return {
    valid: true,
    amountSats,
    mint,
    token: encodedToken,
    secrets: proofs.map((p) => p.secret),
    lockPubkey: normalizePubkey(opts.lockPubkey),
  };
}
