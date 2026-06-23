/**
 * Operator locked-proof vault.
 *
 * Received payments are NUT-11 P2PK-locked to the operator's pubkey (see
 * cashu.ts), so what we store here is NOT spendable by anyone holding the box —
 * only the operator's offline key can claim it. We persist the (locked) cashu
 * token so the operator can sweep across restarts, plus the proof secrets so we
 * can reject replays of an already-seen token. Storing the encoded token rather
 * than raw Proof objects keeps the file portable and dodges Amount JSON pitfalls.
 */

import { mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { serialize } from './serialize.js';

export interface ReceivedPayment {
  purchaseId: string;
  mint: string;
  amountSats: number;
  /** Operator-locked cashu token (cashuB...) for the operator to sweep offline. */
  token: string;
  /** Proof secrets, used for replay/double-spend dedupe. */
  secrets: string[];
  /** Normalized P2PK pubkey the proofs are locked to. */
  lockPubkey: string;
  /** xpub child index this lock was derived at (xpub mode); absent for fixed-pubkey mode. */
  index?: number;
  receivedAt: string;
}

export interface ProofStore {
  add(payment: ReceivedPayment): Promise<void>;
  list(): Promise<ReceivedPayment[]>;
  /** True if any of the given proof secrets has already been recorded. */
  hasAnyOf(secrets: string[]): Promise<boolean>;
  /** Atomically replace the whole store (used by prune to drop swept receipts). */
  replaceAll(payments: ReceivedPayment[]): Promise<void>;
  /**
   * Atomically re-read, transform, and write the store as one unit. Used by prune
   * to drop swept receipts WITHOUT losing a receipt the daemon appended since the
   * caller's snapshot: the transform re-applies the drop against the current file
   * contents under the same (cross-process) lock the daemon's writes take.
   */
  compact(transform: (records: ReceivedPayment[]) => ReceivedPayment[]): Promise<{ before: number; after: number }>;
}

function anySeen(records: ReceivedPayment[], secrets: string[]): boolean {
  const seen = new Set<string>();
  for (const r of records) for (const s of r.secrets ?? []) seen.add(s);
  return secrets.some((s) => seen.has(s));
}

export function createMemoryProofStore(initial: ReceivedPayment[] = []): ProofStore {
  const records = [...initial];
  return {
    async add(payment) {
      // Idempotent: a provision that failed mid-way and is retried (resumed) must
      // not store the same token twice (which would double the sweep attempt).
      if (payment.secrets?.length && anySeen(records, payment.secrets)) return;
      records.push(payment);
    },
    async list() {
      return records.map((r) => ({ ...r }));
    },
    async hasAnyOf(secrets) {
      return anySeen(records, secrets);
    },
    async replaceAll(payments) {
      records.length = 0;
      records.push(...payments);
    },
    async compact(transform) {
      const before = records.length;
      const kept = transform([...records]);
      records.length = 0;
      records.push(...kept);
      return { before, after: kept.length };
    },
  };
}

// --- Cross-process advisory lock ---
//
// The daemon (in-process serialize()) and the off-box pruner are SEPARATE
// processes, so the per-process serializer can't stop the pruner overwriting a
// receipt the daemon appended mid-prune (a lost paid token). An O_EXCL lockfile
// is the cross-process mutex both take around their read-modify-write.
// ponytail: lockfile, not a lease/heartbeat lock. A holder that crashes mid-write
// leaves a stale lockfile; we steal it after LOCK_STALE_MS. Our locked sections
// are tiny (read+write a small JSON, network spent-checks stay OUTSIDE the lock),
// so the steal window can't fire mid-operation. Move to a real lock lib only if
// the locked sections ever grow long.
const LOCK_STALE_MS = 30_000;
const LOCK_RETRY_MS = 50;
const LOCK_TIMEOUT_MS = 10_000;

async function withFileLock<T>(lockPath: string, fn: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    let acquired = false;
    try {
      await mkdir(dirname(lockPath), { recursive: true });
      const fh = await open(lockPath, 'wx'); // O_CREAT|O_EXCL — fails if held
      await fh.close();
      acquired = true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      // Held elsewhere — steal it if stale (holder likely crashed mid-write).
      try {
        const st = await stat(lockPath);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) { await unlink(lockPath).catch(() => {}); continue; }
      } catch { continue; } // vanished between open and stat — race to re-acquire
      if (Date.now() > deadline) throw new Error(`could not acquire lock ${lockPath} within ${LOCK_TIMEOUT_MS}ms`);
      await new Promise((r) => setTimeout(r, LOCK_RETRY_MS));
    }
    if (acquired) {
      try { return await fn(); }
      finally { await unlink(lockPath).catch(() => {}); }
    }
  }
}

export function createFileProofStore(path: string): ProofStore {
  // serialize() guards in-process; withFileLock guards across processes (the
  // off-box pruner). A lost locked token is an unsweepable (lost) payment, so
  // every read-modify-write takes both. Reads stay lock-free — writeStoreFile's
  // atomic tmp+rename means a reader always sees a whole file, never a partial.
  const mutate = serialize();
  const lockPath = `${path}.lock`;
  const locked = <T>(fn: () => Promise<T>): Promise<T> => mutate(() => withFileLock(lockPath, fn));
  return {
    add(payment) {
      return locked(async () => {
        const records = await readStoreFile(path);
        // Idempotent (see memory store): a resumed provision must not re-store the token.
        if (payment.secrets?.length && anySeen(records, payment.secrets)) return;
        records.push(payment);
        await writeStoreFile(path, records);
      });
    },
    async list() {
      return readStoreFile(path);
    },
    async hasAnyOf(secrets) {
      return anySeen(await readStoreFile(path), secrets);
    },
    replaceAll(payments) {
      return locked(() => writeStoreFile(path, payments));
    },
    compact(transform) {
      return locked(async () => {
        const before = await readStoreFile(path);
        const after = transform(before);
        await writeStoreFile(path, after);
        return { before: before.length, after: after.length };
      });
    },
  };
}

async function readStoreFile(path: string): Promise<ReceivedPayment[]> {
  try {
    const data = await readFile(path, 'utf8');
    const parsed = JSON.parse(data);
    if (!Array.isArray(parsed)) throw new Error('proof store must be a JSON array');
    return parsed as ReceivedPayment[];
  } catch (e: unknown) {
    if (e instanceof Error && 'code' in e && (e as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw e;
  }
}

async function writeStoreFile(path: string, records: ReceivedPayment[]): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(records, null, 2) + '\n', 'utf8');
  await rename(tmp, path);
}
