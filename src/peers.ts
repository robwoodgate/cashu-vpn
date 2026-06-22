import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { serialize } from './serialize.js';

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
  /** `taken` is the set of tunnel IPs currently in use; the result avoids them. */
  allocateTunnelIp(purchaseId: string, clientPublicKey: string, taken?: Set<string>): string;
}

export interface PeerLedger {
  record(lease: PeerLease): Promise<void>;
  list(now?: Date): Promise<PeerLease[]>;
  listExpiredActive(now: Date): Promise<PeerLease[]>;
  markExpired(purchaseId: string): Promise<void>;
  /** Forget leases that expired at/before `cutoff`. Returns how many were removed. */
  pruneExpiredBefore(cutoff: Date): Promise<number>;
}

// --- Allocator ---

const SUBNET = '10.77.0';
const HOST_COUNT = 253; // usable hosts 2..254 (.0/.1/.255 reserved)

export function createAllocator(): PeerAllocator {
  return {
    allocateTunnelIp(purchaseId: string, clientPublicKey: string, taken = new Set<string>()): string {
      // Deterministic starting host from the hash (stable per purchase), then
      // linear-probe forward to the first free one. Two live leases must never
      // share a /32: WireGuard would reassign the allowed-ip to the newest peer
      // and silently break the earlier buyer's tunnel.
      const digest = createHash('sha256')
        .update(`${purchaseId}:${clientPublicKey}`)
        .digest();
      const start = digest[0]! % HOST_COUNT;
      for (let i = 0; i < HOST_COUNT; i++) {
        const host = 2 + ((start + i) % HOST_COUNT); // 2..254
        const ip = `${SUBNET}.${host}`;
        if (!taken.has(ip)) return ip;
      }
      throw new Error(`tunnel subnet exhausted (${HOST_COUNT} active leases)`);
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
    },

    async pruneExpiredBefore(cutoff) {
      const before = records.length;
      const kept = records.filter((r) => new Date(r.expiresAt).getTime() > cutoff.getTime());
      records.length = 0;
      records.push(...kept);
      return before - records.length;
    }
  };
}

// --- File-backed ledger ---

export function createFileLedger(path: string): PeerLedger {
  // Serialize every read-modify-write so concurrent provisions can't clobber each
  // other's appends (last-writer-wins would silently drop a lease record).
  const mutate = serialize();
  return {
    record(lease) {
      return mutate(async () => {
        const records = await readLedgerFile(path);
        records.push(lease);
        await writeLedgerFile(path, records);
      });
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

    markExpired(purchaseId) {
      return mutate(async () => {
        const records = await readLedgerFile(path);
        await writeLedgerFile(path, records.map((r) =>
          r.purchaseId === purchaseId ? { ...r, status: 'expired' as const } : r
        ));
      });
    },

    pruneExpiredBefore(cutoff) {
      return mutate(async () => {
        const records = await readLedgerFile(path);
        const kept = records.filter((r) => new Date(r.expiresAt).getTime() > cutoff.getTime());
        if (kept.length !== records.length) await writeLedgerFile(path, kept);
        return records.length - kept.length;
      });
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
