/**
 * BIP32 watch-only key derivation for per-transaction privacy.
 *
 * The operator generates an HD key OFFLINE and gives the daemon only the xpub.
 * The daemon derives a fresh child PUBLIC key per purchase (non-hardened, from
 * the xpub alone — no private key ever on the box) and locks that purchase's
 * proofs to it, so the mint can't correlate one operator's payments. The
 * operator later sweeps with the matching child PRIVATE keys derived from their
 * offline xprv.
 *
 * deriveChildPubkey (daemon) and deriveChildKeypair (operator sweep) MUST agree
 * for the same index, or funds are stranded — see the roundtrip test.
 */

import { HDKey } from '@scure/bip32';

const HARDENED_OFFSET = 0x80000000;

function toHex(u8: Uint8Array): string {
  return Buffer.from(u8).toString('hex');
}

function assertNonHardenedIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new Error(`derivation index must be a non-hardened uint31: ${index}`);
  }
}

/** Derive the non-hardened child PUBLIC key (compressed hex) at `index` from an xpub. */
export function deriveChildPubkey(xpub: string, index: number): string {
  assertNonHardenedIndex(index);
  const child = HDKey.fromExtendedKey(xpub).deriveChild(index);
  if (!child.publicKey) throw new Error('failed to derive child public key');
  return toHex(child.publicKey);
}

/**
 * Derive the child keypair (compressed pubkey hex + 32-byte privkey hex) at
 * `index` from an xprv. Operator-side, for the offline sweep.
 */
export function deriveChildKeypair(
  xprv: string,
  index: number,
): { index: number; pubkey: string; privkey: string } {
  assertNonHardenedIndex(index);
  const child = HDKey.fromExtendedKey(xprv).deriveChild(index);
  if (!child.publicKey || !child.privateKey) {
    throw new Error('failed to derive child keypair (an xprv is required)');
  }
  return { index, pubkey: toHex(child.publicKey), privkey: toHex(child.privateKey) };
}

/** True if the extended key is a private (xprv) rather than public (xpub) key. */
export function isPrivateExtendedKey(extKey: string): boolean {
  try {
    return HDKey.fromExtendedKey(extKey).privateKey != null;
  } catch {
    return false;
  }
}
