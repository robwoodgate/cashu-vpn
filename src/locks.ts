/**
 * LockBook — issues per-transaction P2PK lock pubkeys from an operator xpub.
 *
 * Each 402 challenge gets a fresh child pubkey (so the mint can't correlate an
 * operator's payments). We persist only a monotonic counter; the pubkey->index
 * map is rebuilt at startup by deriving [0, counter) from the xpub. The index is
 * recorded on each receipt so the operator can sweep the matching child key.
 *
 * No private key or seed ever touches the box — only the xpub.
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { deriveChildPubkey } from './hdkeys.js';
import { normalizePubkey } from './cashu.js';
import { serialize } from './serialize.js';

export interface IssuedLock {
  index: number;
  /** Compressed-hex child pubkey (as derived; pass to buildPaymentRequest). */
  pubkey: string;
}

export interface LockBook {
  /** Allocate the next index, derive its pubkey, persist the counter. */
  issue(): Promise<IssuedLock>;
  /** Map a (normalized) lock pubkey back to the index we issued, or undefined. */
  resolve(pubkey: string): number | undefined;
}

export async function createLockBook(xpub: string, counterPath?: string): Promise<LockBook> {
  let counter = await readCounter(counterPath);

  // Rebuild the lookup map for everything issued so far.
  const indexByPubkey = new Map<string, number>();
  for (let i = 0; i < counter; i++) {
    indexByPubkey.set(normalizePubkey(deriveChildPubkey(xpub, i)), i);
  }

  // Serialize issuance so concurrent /purchase hits can't race the counter write:
  // two unserialized writeCounter() calls share one tmp path and can ENOENT on
  // rename or persist a counter below the highest index issued (stranding a later
  // payment as lock_not_recognized after a restart).
  const mutate = serialize();

  return {
    issue() {
      return mutate(async () => {
        const index = counter;
        const pubkey = deriveChildPubkey(xpub, index);
        counter += 1;
        await writeCounter(counterPath, counter);
        indexByPubkey.set(normalizePubkey(pubkey), index);
        return { index, pubkey };
      });
    },
    resolve(pubkey) {
      return indexByPubkey.get(normalizePubkey(pubkey));
    },
  };
}

async function readCounter(path?: string): Promise<number> {
  if (!path) return 0;
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (e: unknown) {
    // Only a MISSING file means "fresh start, child 0". Any other read error
    // (and below, any unparseable/invalid content) must fail closed: silently
    // resetting the counter to 0 would reissue child 0 and reopen replay.
    if (e instanceof Error && 'code' in e && (e as NodeJS.ErrnoException).code === 'ENOENT') return 0;
    throw e;
  }
  const value = (JSON.parse(raw) as { next?: unknown })?.next;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) {
    throw new Error(`${path}: invalid lock counter (next=${String(value)}); refusing to reset issuance and reopen replay`);
  }
  return next;
}

async function writeCounter(path: string | undefined, next: number): Promise<void> {
  if (!path) return;
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify({ next }) + '\n', 'utf8');
  await rename(tmp, path);
}
