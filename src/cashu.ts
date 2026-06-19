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
  getTokenMetadata,
  getDecodedToken,
  hasValidDleq,
  getP2PKExpectedWitnessPubkeys,
  Wallet,
  sumProofs,
  type Proof,
  type TokenMetadata,
  type HasKeysetKeys,
} from '@cashu/cashu-ts';

/** Per NUT-00, mint URLs are compared with trailing slashes stripped. */
export function normalizeMintUrl(url: string): string {
  return String(url ?? '').trim().replace(/\/+$/, '');
}

/** Normalize a P2PK pubkey for comparison: lowercase, x-only (strip 02/03). */
export function normalizePubkey(k: string): string {
  return String(k ?? '').toLowerCase().replace(/^0[23]/, '');
}

/**
 * Build the NUT-18 PaymentRequest (creqA) used as the NUT-24 402 challenge.
 * `lockPubkey` is the P2PK pubkey the requested proofs must be locked to — a
 * fixed operator pubkey, or a fresh xpub-derived per-tx pubkey (see locks.ts).
 */
export function buildPaymentRequest(opts: {
  paymentId: string;
  amountSats: number;
  mints: string[];
  lockPubkey: string;
  unit?: string;
  description?: string;
}): string {
  // NUT-10 spending condition: lock the requested proofs to lockPubkey.
  const nut10 = { kind: 'P2PK', data: opts.lockPubkey, tags: [] as string[][] };
  return new PaymentRequest(
    undefined, // no embedded transport: delivery is the HTTP X-Cashu retry
    opts.paymentId,
    opts.amountSats,
    opts.unit ?? 'sat',
    opts.mints,
    opts.description,
    undefined,
    nut10,
  ).toEncodedCreqA();
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
  opts: { acceptedMints: string[]; requiredSats: number; unit?: string },
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
    // NUT-11: proof must be P2PK-locked, so only the lock-key holder can spend it.
    const wits = witnessPubkeys(proof.secret).map(normalizePubkey).filter(Boolean);
    if (!wits.length) {
      return { valid: false, amountSats: 0, error: 'not_locked' };
    }
    if (lockPubkey === undefined) {
      lockPubkey = wits[0];
    } else if (!wits.includes(lockPubkey)) {
      return { valid: false, amountSats: 0, error: 'inconsistent_lock' };
    }
  }

  const amountSats = amountToNumber(sumProofs(proofs));
  if (amountSats < opts.requiredSats) {
    return { valid: false, amountSats, error: 'amount_too_low' };
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
