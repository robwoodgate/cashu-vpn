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
import type { Tier } from './config.js';
import type { PeerLease, PeerLedger } from './peers.js';
import { RENEWAL_GRACE_MS } from './buyer.js';

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
  /**
   * Snapshot of the plan quoted at order creation — payment verification and
   * provisioning read THIS, not live config, so a config change can't reprice
   * an open order. Absent on pre-tier orders (fall back to config).
   */
  tier?: Tier;
  /** Pending renewal: the order whose live lease this one extends. Dropped once provisioned. */
  renewOf?: string;
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
  /** Per-lease data cap written onto the lease; 0/absent = the global default applies. */
  capBytes?: number;
  now: Date;
  /** Allocate a fresh tunnel IP avoiding `taken` (fresh provision only). */
  allocate: (taken: Set<string>) => string;
  /** Fresh WireGuard preshared key for this lease's peer. */
  presharedKey: string;
  /** Render the buyer .conf once the tunnel IP is fixed (pure, sync). */
  renderConfig: (tunnelIp: string, purchaseId: string) => string;
}

export interface StateStore extends PeerLedger {
  createOrder(order: Order): Promise<void>;
  /** A still-payable pending order for this WireGuard key, if any. */
  findPending(clientPublicKey: string, now?: Date): Promise<Order | undefined>;
  /**
   * The order, or undefined if unknown or an expired pending order. `includeExpired`
   * returns an expired pending order within a short delivery grace (see below) so a
   * payment landing just after the TTL still provisions.
   */
  getOrder(id: string, now?: Date, opts?: { includeExpired?: boolean }): Promise<Order | undefined>;
  /**
   * Atomic commit: transition a pending order -> ready AND create its lease in one
   * write. A renewal (`renewOf` a still-live lease) gets a new key and IP and starts
   * its time where the prior lease ends; the prior is cut to RENEWAL_GRACE_MS. Throws
   * KEY_IN_USE if another live lease holds this key. Returns the ready order
   * (alreadyReady=true if already provisioned), or undefined if the id is unknown.
   */
  provision(orderId: string, args: ProvisionArgs): Promise<{ order: Order; alreadyReady: boolean } | undefined>;
}

// How long past its TTL a pending order stays payable: clock skew + NUT-18 delivery
// latency, so a payment landing just after expiry still provisions — without leaving
// the order payable until retention prunes it (forever when RETAIN_EXPIRED_MS=0).
const DELIVERY_GRACE_MS = 5 * 60 * 1000;

export { RENEWAL_GRACE_MS };

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

    async findPending(clientPublicKey, now = new Date()) {
      const order = [...records.values()].find(
        (o) => o.status === 'pending' && o.clientPublicKey === clientPublicKey && !isExpiredPending(o, now)
      );
      return order && { ...order };
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

        const { purchaseId, clientPublicKey, amountSats, leaseDurationMs, capBytes, now, allocate, presharedKey, renderConfig } = args;
        const live = [...records.values()].flatMap((o) => (o.lease && isLive(o.lease, now) ? [o.lease] : []));
        // One live lease per key: a second would fight the first for the same wg peer.
        if (live.some((l) => l.clientPublicKey === clientPublicKey)) {
          throw Object.assign(new Error('another live lease holds this WireGuard key'), { code: 'KEY_IN_USE' });
        }
        // A renewal's clock starts where the prior lease ends, so paying early tops up time.
        // The prior then gets RENEWAL_GRACE_MS to switch configs, not its remaining time,
        // so a renewal can't double as a second device for free.
        const priorOrder = order.renewOf ? records.get(order.renewOf) : undefined;
        const prior = priorOrder?.lease && isLive(priorOrder.lease, now) ? priorOrder.lease : undefined;
        const expiryBase = prior ? new Date(prior.expiresAt).getTime() : now.getTime();
        if (prior) {
          const cut = Math.min(expiryBase, now.getTime() + RENEWAL_GRACE_MS);
          records.set(priorOrder!.id, { ...priorOrder!, lease: { ...prior, expiresAt: new Date(cut).toISOString() } });
        }
        // An expired lease's IP stays taken until cleanup has removed its peer, or that
        // removal's `ip route del` would cut whoever got the IP in between.
        const taken = [...records.values()].flatMap((o) => (o.lease?.status === 'active' ? [o.lease.tunnelIp] : []));
        const tunnelIp = allocate(new Set(taken));

        const lease: PeerLease = {
          purchaseId,
          clientPublicKey,
          tunnelIp,
          createdAt: now.toISOString(),
          expiresAt: new Date(expiryBase + leaseDurationMs).toISOString(),
          status: 'active',
          presharedKey,
          ...(capBytes !== undefined ? { capBytes } : {}),
        };
        const ready: Order = {
          ...order,
          renewOf: undefined, // the link between the two keys isn't kept once provisioned
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

    async countOccupied() {
      return [...records.values()].filter((o) => o.lease?.status === 'active').length;
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
