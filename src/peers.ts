import { createHash } from 'node:crypto';

// --- Types ---

export type LeaseStatus = 'active' | 'expired';

export interface PeerLease {
  purchaseId: string;
  clientPublicKey: string;
  tunnelIp: string;
  createdAt: string;
  expiresAt: string;
  status: LeaseStatus;
  /**
   * The peer's cumulative `wg` transfer counter at the moment this lease was
   * provisioned. Data-cap usage for this lease is (current counter − baseline),
   * so a same-key renewal that reuses the peer doesn't inherit the prior lease's
   * traffic. Absent/0 for fresh peers (counter starts at 0).
   */
  capBaseline?: number;
}

export interface PeerAllocator {
  /** `taken` is the set of tunnel IPs currently in use; the result avoids them. */
  allocateTunnelIp(purchaseId: string, clientPublicKey: string, taken?: Set<string>): string;
}

/**
 * The lease view the WireGuard cleanup / data-cap / reconcile code reads. The
 * unified state store (state.ts) implements it over its orders — leases are not a
 * separate file. Leases are CREATED only through StateStore.provision (atomic with
 * the order going ready), so there is no standalone allocate/record here.
 */
export interface PeerLedger {
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
      throw Object.assign(new Error(`tunnel subnet exhausted (${HOST_COUNT} active leases)`), { code: 'SUBNET_EXHAUSTED' });
    }
  };
}
