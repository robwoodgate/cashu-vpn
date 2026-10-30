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
   * The peer's cumulative `wg` counter when this lease began; data-cap usage is the
   * counter minus this. Only leases from the old same-key renewal carry one.
   */
  capBaseline?: number;
  /** WireGuard preshared key for this peer (absent on leases from before PSKs). */
  presharedKey?: string;
  /** Set when a renewal took this lease over: it only runs out its switch-over grace now. */
  renewed?: boolean;
  /** This lease's data cap in bytes (from its tier). Absent = the global default applies. */
  capBytes?: number;
}

export interface PeerAllocator {
  /** `taken` is the set of tunnel IPs currently in use; the result avoids them. */
  allocateTunnelIp(purchaseId: string, clientPublicKey: string, taken?: Set<string>): string;
  /** Total usable tunnel IPs — i.e. the max number of concurrent live leases. */
  readonly capacity: number;
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
  /** How many tunnel IPs are held: leases whose peer cleanup hasn't removed yet (expired or not). */
  countOccupied(): Promise<number>;
  markExpired(purchaseId: string): Promise<void>;
  /** Forget leases that expired at/before `cutoff`. Returns how many were removed. */
  pruneExpiredBefore(cutoff: Date): Promise<number>;
}

// --- Allocator ---

// 10.77.0.0/16. Host index 0 is the network address, 1 is the server
// (10.77.0.1), 65535 the broadcast — usable hosts are 2..65534.
const SUBNET = '10.77';
const HOST_COUNT = 65533;

export function createAllocator(): PeerAllocator {
  return {
    capacity: HOST_COUNT,
    allocateTunnelIp(purchaseId: string, clientPublicKey: string, taken = new Set<string>()): string {
      // Deterministic starting host from the hash (stable per purchase), then
      // linear-probe forward to the first free one. Two live leases must never
      // share a /32: WireGuard would reassign the allowed-ip to the newest peer
      // and silently break the earlier buyer's tunnel.
      const digest = createHash('sha256')
        .update(`${purchaseId}:${clientPublicKey}`)
        .digest();
      const start = digest.readUInt16BE(0) % HOST_COUNT;
      for (let i = 0; i < HOST_COUNT; i++) {
        const host = 2 + ((start + i) % HOST_COUNT); // 2..65534
        const ip = `${SUBNET}.${host >> 8}.${host & 255}`;
        if (!taken.has(ip)) return ip;
      }
      throw Object.assign(new Error(`tunnel subnet exhausted (${HOST_COUNT} active leases)`), { code: 'SUBNET_EXHAUSTED' });
    }
  };
}
