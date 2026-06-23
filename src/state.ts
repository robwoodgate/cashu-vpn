/**
 * Unified order+lease state (one file, one writer).
 *
 * A lease is simply the provisioned half of an order, so we keep ONE record per
 * order and embed its lease. "Mark the order ready" and "create the lease" are
 * therefore a SINGLE atomic write (tmp+rename) — there is no window where one is
 * persisted without the other. That is what lets the old two-file design's
 * rollback / reactivate / crash-recovery choreography all go away.
 *
 * WireGuard is a DERIVED cache: desired state is "every order with an active
 * lease has a peer". We commit desired state here first, then make the interface
 * match (apply-after-commit + startup/periodic reconcile). App state is NEVER
 * rolled back to repair WireGuard.
 *
 * The lease view (list / listExpiredActive / markExpired / pruneExpiredBefore)
 * satisfies PeerLedger, so the WireGuard cleanup/data-cap/reconcile code reads
 * leases straight out of the orders with no separate ledger file.
 *
 * Source of truth is an in-memory Map (so the frequent poll never re-parses a
 * file); mutations persist with an atomic tmp+rename, serialized through one
 * promise chain. NEVER holds the buyer's WireGuard private key — only the public.
 */

import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { PeerLease, PeerLedger } from './peers.js';

export type OrderStatus = 'pending' | 'ready';

export interface Order {
  /** Unguessable capability id, used in /pay/:id and /order/:id. */
  id: string;
  status: OrderStatus;
  /** Buyer's WireGuard public key (the peer to provision). Never the private key. */
  clientPublicKey: string;
  /** P2PK pubkey the creqA demands proofs be locked to (operator key or xpub child). */
  lockPubkey: string;
  /** xpub child index this order's lock was issued at (recorded on the receipt for sweeping). */
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
  /** The provisioned half of this order. Its expiresAt drives lease expiry. */
  lease?: PeerLease;
}

/** Inputs for the atomic provision() commit. */
export interface ProvisionArgs {
  /** Pre-generated so the caller can write the proof receipt under the same id first. */
  purchaseId: string;
  clientPublicKey: string;
  amountSats?: number;
  leaseDurationMs: number;
  now: Date;
  /** Allocate a fresh tunnel IP avoiding `taken` (fresh provision only). */
  allocate: (taken: Set<string>) => string;
  /**
   * Live `wg` counter (rx+tx) for a renewed peer, to rebase its data-cap baseline.
   * Called ONLY on a same-key renewal of a still-live lease (peer present), so it
   * can't race cleanup's remove. A throw aborts the commit (caller retries) rather
   * than baselining to 0 and insta-capping the paid renewal.
   */
  readPeerCounter: () => Promise<number>;
  /** Render the buyer .conf once the tunnel IP is fixed (pure, sync). */
  renderConfig: (tunnelIp: string, purchaseId: string) => string;
}

export interface StateStore extends PeerLedger {
  createOrder(order: Order): Promise<void>;
  /**
   * The order, or undefined if unknown or an expired pending order. `includeExpired`
   * returns an expired pending order within a short delivery grace (see below) so a
   * payment landing just after the TTL still provisions.
   */
  getOrder(id: string, now?: Date, opts?: { includeExpired?: boolean }): Promise<Order | undefined>;
  /**
   * Atomic commit: transition a pending order -> ready AND create its lease in one
   * write. On a same-key renewal of a still-live lease, expires that prior lease and
   * REUSES its tunnel IP (no route churn, no `wg` counter reset), rebasing the data
   * cap to the peer's current counter. Returns the ready order (alreadyReady=true if
   * it was already provisioned — idempotent), or undefined if the id is unknown.
   */
  provision(orderId: string, args: ProvisionArgs): Promise<{ order: Order; alreadyReady: boolean } | undefined>;
}

// How long past its TTL a pending order stays payable: clock skew + NUT-18 delivery
// latency, so a payment landing just after expiry still provisions — without leaving
// the order payable until retention prunes it (forever when RETAIN_EXPIRED_MS=0).
const DELIVERY_GRACE_MS = 5 * 60 * 1000;

/** A fresh, URL-safe capability id with ~192 bits of entropy. */
export function newOrderId(): string {
  return randomBytes(24).toString('base64url');
}

export function newPurchaseId(): string {
  return `p-${Date.now()}-${randomBytes(3).toString('hex')}`;
}

function isExpiredPending(order: Order, now: Date): boolean {
  return order.status === 'pending' && new Date(order.expiresAt).getTime() <= now.getTime();
}

/** The moment an order stops being useful: a ready order's lease end, else its request expiry. */
function effectiveExpiry(order: Order): number {
  const ts = order.status === 'ready' ? order.lease?.expiresAt ?? order.expiresAt : order.expiresAt;
  return new Date(ts).getTime();
}

const isLive = (lease: PeerLease, now: Date): boolean =>
  lease.status === 'active' && new Date(lease.expiresAt).getTime() > now.getTime();

/** Lease as the WireGuard side should see it: status recomputed by wall-clock expiry. */
function leaseView(order: Order, now: Date): PeerLease | undefined {
  const lease = order.lease;
  if (!lease) return undefined;
  return new Date(lease.expiresAt).getTime() <= now.getTime() && lease.status === 'active'
    ? { ...lease, status: 'expired' }
    : { ...lease };
}

function makeStore(records: Map<string, Order>, persist: (recs: Order[]) => Promise<void>): StateStore {
  // Serialize every mutation so read-modify-write of the backing file can't interleave.
  let tail: Promise<unknown> = Promise.resolve();
  const queue = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(fn, fn);
    tail = run.then(() => undefined, () => undefined);
    return run;
  };

  return {
    createOrder(order) {
      return queue(async () => {
        records.set(order.id, order);
        await persist([...records.values()]);
      });
    },

    async getOrder(id, now = new Date(), opts) {
      const order = records.get(id);
      if (!order) return undefined;
      if (isExpiredPending(order, now)) {
        // Past the TTL: gone for pollers, and for /pay only within the delivery
        // grace — so the TTL actually bounds payability (removal is pruneExpiredBefore's).
        if (!opts?.includeExpired) return undefined;
        if (new Date(order.expiresAt).getTime() + DELIVERY_GRACE_MS <= now.getTime()) return undefined;
      }
      return { ...order };
    },

    provision(orderId, args) {
      return queue(async () => {
        const order = records.get(orderId);
        if (!order) return undefined;
        if (order.status === 'ready') return { order: { ...order }, alreadyReady: true };

        const { purchaseId, clientPublicKey, amountSats, leaseDurationMs, now, allocate, readPeerCounter, renderConfig } = args;

        // Renewal = a still-live lease for the same WireGuard key (necessarily on
        // another order). Reuse its IP and rebase the data cap; expire it here. A
        // prior lease that's already expired-by-time is NOT a renewal — it falls to
        // fresh allocation, so we never read a counter for a peer cleanup may remove.
        const priors = [...records.values()].filter(
          (o) => o.id !== orderId && o.lease && o.lease.clientPublicKey === clientPublicKey && isLive(o.lease, now)
        );

        let tunnelIp: string;
        let capBaseline: number;
        if (priors.length > 0) {
          tunnelIp = priors[0]!.lease!.tunnelIp;
          capBaseline = await readPeerCounter();
          for (const p of priors) records.set(p.id, { ...p, lease: { ...p.lease!, status: 'expired' } });
        } else {
          const taken = new Set(
            [...records.values()].flatMap((o) => (o.lease && isLive(o.lease, now) ? [o.lease.tunnelIp] : []))
          );
          tunnelIp = allocate(taken);
          capBaseline = 0;
        }

        const lease: PeerLease = {
          purchaseId,
          clientPublicKey,
          tunnelIp,
          createdAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + leaseDurationMs).toISOString(),
          status: 'active',
          capBaseline,
        };
        const ready: Order = {
          ...order,
          status: 'ready',
          purchaseId,
          tunnelIp,
          amountSats,
          clientConfig: renderConfig(tunnelIp, purchaseId),
          lease,
        };
        records.set(orderId, ready);
        await persist([...records.values()]);
        return { order: { ...ready }, alreadyReady: false };
      });
    },

    // --- PeerLedger (lease view over orders) ---

    async list(now = new Date()) {
      return [...records.values()].flatMap((o) => {
        const v = leaseView(o, now);
        return v ? [v] : [];
      });
    },

    async listExpiredActive(now) {
      return [...records.values()].flatMap((o) =>
        o.lease && o.lease.status === 'active' && new Date(o.lease.expiresAt).getTime() <= now.getTime()
          ? [{ ...o.lease }]
          : []
      );
    },

    markExpired(purchaseId) {
      return queue(async () => {
        let changed = false;
        for (const [id, o] of records) {
          if (o.lease?.purchaseId === purchaseId && o.lease.status === 'active') {
            records.set(id, { ...o, lease: { ...o.lease, status: 'expired' } });
            changed = true;
          }
        }
        if (changed) await persist([...records.values()]);
      });
    },

    pruneExpiredBefore(cutoff) {
      return queue(async () => {
        let removed = 0;
        for (const [id, order] of records) {
          if (effectiveExpiry(order) <= cutoff.getTime()) {
            records.delete(id);
            removed++;
          }
        }
        if (removed > 0) await persist([...records.values()]);
        return removed;
      });
    },
  };
}

export function createMemoryStateStore(initial: Order[] = []): StateStore {
  const records = new Map(initial.map((o) => [o.id, o]));
  return makeStore(records, async () => {});
}

export async function createFileStateStore(path: string): Promise<StateStore> {
  const records = new Map((await readStateFile(path)).map((o) => [o.id, o]));
  return makeStore(records, (recs) => writeStateFile(path, recs));
}

async function readStateFile(path: string): Promise<Order[]> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error('state store must be a JSON array');
    return parsed as Order[];
  } catch (e: unknown) {
    if (e instanceof Error && 'code' in e && (e as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw e;
  }
}

async function writeStateFile(path: string, records: Order[]): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(records, null, 2) + '\n', 'utf8');
  await rename(tmp, path);
}
