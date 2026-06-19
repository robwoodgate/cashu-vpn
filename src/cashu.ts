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
 * v0 locks every payment to a single operator pubkey (the mint can correlate an
 * operator's payments — documented limitation). xpub-derived per-transaction
 * locks close that; see the lockPubkeyFor() seam and task #5.
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

/**
 * The pubkey a given purchase's proofs must be locked to. v0 returns the single
 * configured operator pubkey; the xpub-per-tx upgrade (task #5) swaps the body
 * here to derive a fresh child pubkey, with no change to callers.
 */
export function lockPubkeyFor(operatorPubkey: string): string {
  return operatorPubkey;
}

/** Build the NUT-18 PaymentRequest (creqA) used as the NUT-24 402 challenge. */
export function buildPaymentRequest(opts: {
  paymentId: string;
  amountSats: number;
  mints: string[];
  operatorPubkey: string;
  unit?: string;
  description?: string;
}): string {
  // NUT-10 spending condition: lock the requested proofs to the operator pubkey.
  const nut10 = { kind: 'P2PK', data: lockPubkeyFor(opts.operatorPubkey), tags: [] as string[][] };
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
  /** The (already operator-locked) token to store for the operator to sweep. */
  token?: string;
  /** Proof secrets, for replay/double-spend dedupe in the store. */
  secrets?: string[];
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

// Compare P2PK pubkeys leniently: hex, case-insensitive, x-only or 02/03-prefixed.
function pubkeyMatches(expected: string[], operatorPubkey: string): boolean {
  const norm = (k: string) => k.toLowerCase().replace(/^0[23]/, '');
  const op = norm(operatorPubkey);
  return expected.some((k) => norm(k) === op);
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
  opts: { acceptedMints: string[]; requiredSats: number; operatorPubkey: string; unit?: string },
  deps: VerifyDeps = {},
): Promise<VerifyResult> {
  const unit = opts.unit ?? 'sat';
  const getMetadata = deps.getMetadata ?? getTokenMetadata;
  const loadMintContext = deps.loadMintContext ?? defaultLoadMintContext;
  const decode = deps.decode ?? ((t, ids) => getDecodedToken(t, ids).proofs);
  const checkDleq = deps.checkDleq ?? ((p, k) => hasValidDleq(p, k));
  const witnessPubkeys = deps.witnessPubkeys ?? getP2PKExpectedWitnessPubkeys;
  const lockKey = lockPubkeyFor(opts.operatorPubkey);

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
    // NUT-11: proof is locked to the operator, so only the operator can spend it.
    if (!pubkeyMatches(witnessPubkeys(proof.secret), lockKey)) {
      return { valid: false, amountSats: 0, error: 'not_locked_to_operator' };
    }
  }

  const amountSats = amountToNumber(sumProofs(proofs));
  if (amountSats < opts.requiredSats) {
    return { valid: false, amountSats, error: 'amount_too_low' };
  }

  return { valid: true, amountSats, mint, token: encodedToken, secrets: proofs.map((p) => p.secret) };
}
