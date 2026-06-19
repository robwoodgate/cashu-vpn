import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

// --- Types ---

export type LeaseStatus = 'active' | 'expired';

export interface PeerLease {
  purchaseId: string;
  clientPublicKey: string;
  tunnelIp: string;
  createdAt: string;
  expiresAt: string;
  status: LeaseStatus;
}

export interface PeerAllocator {
  allocateTunnelIp(purchaseId: string, clientPublicKey: string): string;
}

export interface PeerLedger {
  record(lease: PeerLease): Promise<void>;
  list(now?: Date): Promise<PeerLease[]>;
  listExpiredActive(now: Date): Promise<PeerLease[]>;
  markExpired(purchaseId: string): Promise<void>;
}

// --- Allocator ---

const SUBNET = '10.77.0';
const RESERVED = new Set([0, 1, 255]);

export function createAllocator(): PeerAllocator {
  return {
    allocateTunnelIp(purchaseId: string, clientPublicKey: string): string {
      const digest = createHash('sha256')
        .update(`${purchaseId}:${clientPublicKey}`)
        .digest();

      for (const byte of digest) {
        const host = 2 + (byte % 253);
        if (!RESERVED.has(host)) return `${SUBNET}.${host}`;
      }
      return `${SUBNET}.2`;
    }
  };
}

// --- In-memory ledger ---

export function createMemoryLedger(initial: PeerLease[] = []): PeerLedger {
  const records = [...initial];

  return {
    async record(lease) { records.push(lease); },

    async list(now = new Date()) {
      return records.map((r) => ({
        ...r,
        status: new Date(r.expiresAt).getTime() <= now.getTime() ? 'expired' as const : r.status
      }));
    },

    async listExpiredActive(now) {
      return records
        .filter((r) => r.status === 'active' && new Date(r.expiresAt).getTime() <= now.getTime())
        .map((r) => ({ ...r }));
    },

    async markExpired(purchaseId) {
      for (let i = 0; i < records.length; i++) {
        if (records[i]?.purchaseId === purchaseId) {
          records[i] = { ...records[i], status: 'expired' };
        }
      }
    }
  };
}

// --- File-backed ledger ---

export function createFileLedger(path: string): PeerLedger {
  return {
    async record(lease) {
      const records = await readLedgerFile(path);
      records.push(lease);
      await writeLedgerFile(path, records);
    },

    async list(now = new Date()) {
      return (await readLedgerFile(path)).map((r) => ({
        ...r,
        status: new Date(r.expiresAt).getTime() <= now.getTime() ? 'expired' as const : r.status
      }));
    },

    async listExpiredActive(now) {
      return (await readLedgerFile(path))
        .filter((r) => r.status === 'active' && new Date(r.expiresAt).getTime() <= now.getTime())
        .map((r) => ({ ...r }));
    },

    async markExpired(purchaseId) {
      const records = await readLedgerFile(path);
      await writeLedgerFile(path, records.map((r) =>
        r.purchaseId === purchaseId ? { ...r, status: 'expired' as const } : r
      ));
    }
  };
}

async function readLedgerFile(path: string): Promise<PeerLease[]> {
  try {
    const data = await readFile(path, 'utf8');
    const parsed = JSON.parse(data);
    if (!Array.isArray(parsed)) throw new Error('peer ledger must be a JSON array');
    return parsed as PeerLease[];
  } catch (e: unknown) {
    if (e instanceof Error && 'code' in e && (e as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw e;
  }
}

async function writeLedgerFile(path: string, records: PeerLease[]): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(records, null, 2) + '\n', 'utf8');
  await rename(tmp, path);
}
