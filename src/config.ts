export interface Config {
  mode: 'dry-run' | 'live';
  host: string;
  port: number;
  wgInterface: string;
  serverPublicKey: string;
  endpoint: string;
  peerLedgerPath?: string;
  leaseDurationMs: number;
  cleanupIntervalMs?: number;
  acceptedMints: string[];
  priceSats: number;
  unit: string;
  /**
   * Externally reachable base URL (behind TLS), used to build the NUT-18 POST
   * transport target a paying wallet hits (`<base>/pay/:orderId`). When unset it
   * is derived per-request from the forwarded proto + host headers.
   */
  publicBaseUrl?: string;
  /** Where the pending-order store persists (per-order delivery model). */
  orderStorePath?: string;
  /** How long an unpaid order's PaymentRequest stays valid. */
  orderTtlMs: number;
  /**
   * Dust-griefing guard: reject tokens whose proof count exceeds
   * popcount(amount) + this margin. Honest wallets pay near the popcount minimum;
   * only a griefer pads a payment with many dust proofs (each costs us an input
   * fee to sweep). See verifyPayment.
   */
  proofCountMargin: number;
  /** Fixed operator P2PK pubkey to lock proofs to (live mode needs this OR operatorXpub). */
  operatorPubkey: string;
  /** Operator xpub for per-transaction lock pubkeys (private; preferred over operatorPubkey). */
  operatorXpub?: string;
  /** Where the LockBook persists its index counter (xpub mode). */
  lockCounterPath?: string;
  proofStorePath?: string;
  /** Max /purchase requests per IP per window (0 disables). */
  rateLimitMax: number;
  rateLimitWindowMs: number;
}

const DEFAULT_LEASE_MS = 24 * 60 * 60 * 1000; // 1 day — short leases get eaten by client setup time
const DEFAULT_PRICE_SATS = 1000;
const DEFAULT_ORDER_TTL_MS = 30 * 60 * 1000; // 30 minutes
const DEFAULT_PROOF_COUNT_MARGIN = 4;
const DEFAULT_CLEANUP_INTERVAL_MS = 60 * 1000; // 1 minute — on by default so expired peers always get removed

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const mode = env.MODE === 'live' ? 'live' : 'dry-run';

  // Expired-peer cleanup runs in-process. On by default; set CLEANUP_INTERVAL_MS=0
  // to disable. Any other non-negative integer overrides the interval.
  let cleanupIntervalMs: number | undefined = DEFAULT_CLEANUP_INTERVAL_MS;
  if (env.CLEANUP_INTERVAL_MS !== undefined && env.CLEANUP_INTERVAL_MS !== '') {
    const parsed = Number(env.CLEANUP_INTERVAL_MS);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw new Error('CLEANUP_INTERVAL_MS must be a non-negative integer (0 disables cleanup)');
    }
    cleanupIntervalMs = parsed === 0 ? undefined : parsed;
  }

  const acceptedMints = env.ACCEPTED_MINTS
    ? env.ACCEPTED_MINTS.split(',').map((m) => m.trim()).filter(Boolean)
    : ['https://mint.minibits.cash/Bitcoin'];

  return {
    mode,
    host: env.HOST ?? '127.0.0.1',
    port: Number(env.PORT ?? '3087'),
    wgInterface: env.WG_INTERFACE ?? 'wg0',
    serverPublicKey: env.SERVER_PUBLIC_KEY ?? '',
    endpoint: env.WG_ENDPOINT ?? '',
    peerLedgerPath: env.PEER_LEDGER_PATH,
    leaseDurationMs: Number(env.LEASE_DURATION_MS ?? DEFAULT_LEASE_MS),
    cleanupIntervalMs,
    acceptedMints,
    priceSats: Number(env.PRICE_SATS ?? DEFAULT_PRICE_SATS),
    unit: env.MINT_UNIT ?? 'sat',
    publicBaseUrl: env.PUBLIC_BASE_URL ? env.PUBLIC_BASE_URL.replace(/\/+$/, '') : undefined,
    orderStorePath: env.ORDERS_PATH,
    orderTtlMs: Number(env.ORDER_TTL_MS ?? DEFAULT_ORDER_TTL_MS),
    proofCountMargin: Number(env.PROOF_COUNT_MARGIN ?? DEFAULT_PROOF_COUNT_MARGIN),
    operatorPubkey: env.OPERATOR_PUBKEY ?? '',
    operatorXpub: env.OPERATOR_XPUB || undefined,
    lockCounterPath: env.LOCK_COUNTER_PATH,
    proofStorePath: env.PROOFS_PATH,
    rateLimitMax: Number(env.RATE_LIMIT_MAX ?? '30'),
    rateLimitWindowMs: Number(env.RATE_LIMIT_WINDOW_MS ?? '60000'),
  };
}
