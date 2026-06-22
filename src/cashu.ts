/**
 * Cashu payment — NUT-24 (HTTP 402) with NON-CUSTODIAL verification.
 *
 * The daemon NEVER holds spendable ecash. The PaymentRequest demands proofs
 * NUT-11 P2PK-locked to the operator's pubkey; the operator's PRIVATE key never
 * touches the box. On the paid retry the daemon verifies the token ENTIRELY
 * OFFLINE — no swap, no per-sale mint call:
 *
 *   1. getTokenMetadata()      — local mint + amount pre-check
 *   2. hasValidDleq()  (NUT-12) — proves the mint genuinely signed it, checked
 *                                 offline against the mint's public keyset
 *   3. P2PK witness pubkeys (NUT-11) include the operator's pubkey — only the
 *                                 operator can ever spend it
 *
 * The only mint interaction is loadMint() to fetch public keysets, cached per
 * mint for a TTL. The buyer's wallet does all the minting (rate limits fan out
 * across clients). Received tokens are stored locked; the operator sweeps them
 * offline with their key.
 *
 * The lock pubkey is chosen by the caller (server.ts): a fixed operator pubkey,
 * or a fresh xpub-derived per-transaction pubkey (locks.ts) so the mint can't
 * correlate an operator's payments. verifyPayment returns the lock pubkey it
 * found; the caller authorizes it.
 */

import {
  PaymentRequest,
  PaymentRequestTransportType,
  getTokenMetadata,
  getDecodedToken,
  hasValidDleq,
  getP2PKExpectedWitnessPubkeys,
  Wallet,
  sumProofs,
  type Proof,
  type PaymentRequestTransport,
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
 * True if a NUT-11 P2PK secret carries a locktime/refund escape — i.e. someone
 * other than the lock holder could reclaim the proofs later. Reject those so the
 * operator is the sole, permanent spender. Fails open (returns false) if the
 * secret can't be parsed; the witness-pubkey check already confirmed it is P2PK.
 */
function hasEscapeClause(secret: string): boolean {
  try {
    const parsed = JSON.parse(secret) as [string, { tags?: string[][] }];
    const tags = parsed?.[1]?.tags ?? [];
    return tags.some((t) => Array.isArray(t) && (t[0] === 'locktime' || t[0] === 'refund'));
  } catch {
    return false;
  }
}

/**
 * Build the NUT-18 PaymentRequest (creqA) used as the NUT-24 402 challenge.
 * `lockPubkey` is the P2PK pubkey the requested proofs must be locked to — a
 * fixed operator pubkey, or a fresh xpub-derived per-tx pubkey (see locks.ts).
 *
 * When `transportTarget` is set the request carries a NUT-18 HTTP POST transport,
 * so a NUT-18 wallet pays and POSTs the proofs straight to that URL (the
 * per-order /pay/:orderId sink) — no copy/paste. A NUT-24 agent ignores the
 * transport and delivers the same proofs via the `X-Cashu` retry header instead.
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
  // NUT-10 spending condition: lock the requested proofs to lockPubkey.
  const nut10 = { kind: 'P2PK', data: opts.lockPubkey, tags: [] as string[][] };
  const transports: PaymentRequestTransport[] | undefined = opts.transportTarget
    ? [{ type: PaymentRequestTransportType.POST, target: opts.transportTarget, tags: [] }]
    : undefined;
  return new PaymentRequest(
    transports,
    opts.paymentId,
    opts.amountSats,
    opts.unit ?? 'sat',
    opts.mints,
    opts.description,
    undefined,
    nut10,
  ).toEncodedCreqA();
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
  checkDleq?: (proof: Proof, keyset: HasKeysetKeys) => boolean;
  witnessPubkeys?: (secret: string) => string[];
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

/**
 * Verify a Cashu token delivered via the `X-Cashu` header, fully offline.
 * Returns the operator-locked token + proof secrets on success; never swaps.
 */
export async function verifyPayment(
  encodedToken: string,
  opts: { acceptedMints: string[]; requiredSats: number; unit?: string; proofCountMargin?: number },
  deps: VerifyDeps = {},
): Promise<VerifyResult> {
  const unit = opts.unit ?? 'sat';
  const getMetadata = deps.getMetadata ?? getTokenMetadata;
  const loadMintContext = deps.loadMintContext ?? defaultLoadMintContext;
  const decode = deps.decode ?? ((t, ids) => getDecodedToken(t, ids).proofs);
  const checkDleq = deps.checkDleq ?? ((p, k) => hasValidDleq(p, k));
  const witnessPubkeys = deps.witnessPubkeys ?? getP2PKExpectedWitnessPubkeys;

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

  // Every proof must be DLEQ-valid and P2PK-locked to one consistent pubkey.
  // The caller authorizes that pubkey (fixed operator key, or an issued xpub
  // child — see server.ts).
  let lockPubkey: string | undefined;
  for (const proof of proofs) {
    let keyset: HasKeysetKeys;
    try {
      keyset = ctx.getKeyset(proof.id);
    } catch {
      return { valid: false, amountSats: 0, error: 'unknown_keyset' };
    }
    // NUT-12: proof is genuinely mint-signed (verified offline).
    if (!checkDleq(proof, keyset)) {
      return { valid: false, amountSats: 0, error: 'invalid_dleq' };
    }
    // NUT-11: require a SINGLE-signer P2PK lock with no refund/locktime escape,
    // so the lock-key holder is the sole, permanent spender — a buyer can't lock
    // with a multisig or a refund path and reclaim the proofs after getting access.
    // A plain (non-P2PK) secret isn't JSON, so getP2PKExpectedWitnessPubkeys
    // throws — treat that as unlocked (many wallets ignore the PR's nut10 lock and
    // send ordinary ecash; we reject it rather than custody spendable proofs).
    let wits: string[];
    try {
      wits = witnessPubkeys(proof.secret).map(normalizePubkey).filter(Boolean);
    } catch {
      return { valid: false, amountSats: 0, error: 'not_locked' };
    }
    if (wits.length === 0) {
      return { valid: false, amountSats: 0, error: 'not_locked' };
    }
    if (wits.length > 1) {
      return { valid: false, amountSats: 0, error: 'multisig_lock' };
    }
    if (hasEscapeClause(proof.secret)) {
      return { valid: false, amountSats: 0, error: 'refundable_lock' };
    }
    if (lockPubkey === undefined) {
      lockPubkey = wits[0];
    } else if (wits[0] !== lockPubkey) {
      return { valid: false, amountSats: 0, error: 'inconsistent_lock' };
    }
  }

  const amountSats = amountToNumber(sumProofs(proofs));
  if (amountSats < opts.requiredSats) {
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
    lockPubkey,
  };
}
