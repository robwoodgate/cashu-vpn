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

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
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
  };
}

export function createFileProofStore(path: string): ProofStore {
  // Serialize mutations so two concurrent payments can't both read-then-write and
  // drop a receipt — a lost locked token is an unsweepable (lost) payment.
  const mutate = serialize();
  return {
    add(payment) {
      return mutate(async () => {
        const records = await readStoreFile(path);
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
      return mutate(async () => {
        await writeStoreFile(path, payments);
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
