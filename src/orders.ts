/**
 * Pending-order store (per-order delivery model).
 *
 * Each unpaid POST /purchase mints an unguessable, crypto-random order id — a
 * capability token. The buyer's wallet pays the PaymentRequest and POSTs the
 * proofs to /pay/:orderId; the daemon verifies, provisions the peer, and marks
 * the order `ready` with its rendered .conf. The browser polls GET /order/:orderId
 * and shows ONLY its own config (it holds the matching private key locally).
 *
 * Source of truth is an in-memory Map (so the frequent poll never re-parses a
 * file); mutations are persisted to disk with an atomic tmp+rename and serialized
 * through a single promise chain so concurrent writes can't interleave or corrupt
 * the file. Expired *pending* orders are pruned lazily on access; `ready` orders
 * are retained (within the file) so a buyer can re-download across reloads.
 *
 * The store NEVER holds the buyer's WireGuard private key — only the public key.
 */

import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { PeerLease } from './peers.js';

export type OrderStatus = 'pending' | 'ready';

export interface Order {
  /** Unguessable capability id, used in /pay/:id and /order/:id. */
  id: string;
  status: OrderStatus;
  /** Buyer's WireGuard public key (the peer to provision). Never the private key. */
  clientPublicKey: string;
  /** P2PK pubkey the creqA demands proofs be locked to (operator key or xpub child). */
  lockPubkey: string;
  /** xpub child index this order's lock was issued at (xpub mode); absent for fixed-pubkey mode. */
  lockIndex?: number;
  createdAt: string;
  /** Pending orders past this are treated as gone. */
  expiresAt: string;
  // --- populated when status === 'ready' ---
  purchaseId?: string;
  tunnelIp?: string;
  amountSats?: number;
  /** Rendered .conf with a `# PrivateKey` placeholder the browser fills locally. */
  clientConfig?: string;
  lease?: PeerLease;
}

/** Fields the daemon supplies when a paid order is provisioned. */
export type ReadyPatch = Pick<Order, 'purchaseId' | 'tunnelIp' | 'amountSats' | 'clientConfig' | 'lease'>;

export interface OrderStore {
  create(order: Order): Promise<void>;
  /** The order, or undefined if unknown or an expired pending order. */
  get(id: string, now?: Date): Promise<Order | undefined>;
  /** Atomically transition pending -> ready. Returns the updated order, or undefined if the id is unknown / not pending. */
  markReady(id: string, patch: ReadyPatch): Promise<Order | undefined>;
}

/** A fresh, URL-safe capability id with ~192 bits of entropy. */
export function newOrderId(): string {
  return randomBytes(24).toString('base64url');
}

function isExpiredPending(order: Order, now: Date): boolean {
  return order.status === 'pending' && new Date(order.expiresAt).getTime() <= now.getTime();
}

function makeStore(records: Map<string, Order>, persist: (recs: Order[]) => Promise<void>): OrderStore {
  // Serialize all mutations so read-modify-write of the backing file can't interleave.
  let tail: Promise<unknown> = Promise.resolve();
  const queue = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(fn, fn);
    tail = run.then(() => undefined, () => undefined);
    return run;
  };

  return {
    create(order) {
      return queue(async () => {
        records.set(order.id, order);
        await persist([...records.values()]);
      });
    },

    async get(id, now = new Date()) {
      const order = records.get(id);
      if (!order) return undefined;
      if (isExpiredPending(order, now)) {
        // Prune lazily; best-effort persist (don't block the read on it).
        void queue(async () => {
          const cur = records.get(id);
          if (cur && isExpiredPending(cur, new Date())) {
            records.delete(id);
            await persist([...records.values()]);
          }
        });
        return undefined;
      }
      return { ...order };
    },

    markReady(id, patch) {
      return queue(async () => {
        const order = records.get(id);
        if (!order || order.status !== 'pending') return undefined;
        const updated: Order = { ...order, ...patch, status: 'ready' };
        records.set(id, updated);
        await persist([...records.values()]);
        return { ...updated };
      });
    },
  };
}

export function createMemoryOrderStore(initial: Order[] = []): OrderStore {
  const records = new Map(initial.map((o) => [o.id, o]));
  return makeStore(records, async () => {});
}

export async function createFileOrderStore(path: string): Promise<OrderStore> {
  const records = new Map((await readOrdersFile(path)).map((o) => [o.id, o]));
  return makeStore(records, (recs) => writeOrdersFile(path, recs));
}

async function readOrdersFile(path: string): Promise<Order[]> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error('order store must be a JSON array');
    return parsed as Order[];
  } catch (e: unknown) {
    if (e instanceof Error && 'code' in e && (e as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw e;
  }
}

async function writeOrdersFile(path: string, records: Order[]): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(records, null, 2) + '\n', 'utf8');
  await rename(tmp, path);
}
