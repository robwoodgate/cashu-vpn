export interface Config {
  mode: 'dry-run' | 'live';
  host: string;
  port: number;
  wgInterface: string;
  serverPublicKey: string;
  endpoint: string;
  /**
   * DNS resolver(s) written into the buyer's WireGuard config. Required for a
   * full-tunnel (AllowedIPs = 0.0.0.0/0) config to actually work: without it the
   * client keeps its LAN resolver, which is unreachable through the tunnel, so
   * names stop resolving and it looks like "connected but no internet". Defaults
   * to a public privacy-respecting resolver; override with WG_DNS.
   */
  dns: string[];
  peerLedgerPath?: string;
  leaseDurationMs: number;
  /**
   * Per-lease cumulative data cap in bytes (rx + tx). Once a buyer reaches it the
   * cleanup tick disconnects them, same as expiry — bounds how much a single
   * lease can bill against the host's egress allowance (e.g. Hetzner's ~20 TB/mo).
   * 0 disables the cap.
   */
  leaseDataCapBytes: number;
  cleanupIntervalMs?: number;
  /**
   * How long to keep expired leases/orders before the cleanup tick forgets them.
   * Bounds the lease ledger and order store so per-purchase writes (which rewrite
   * the whole file) stay small. 0 keeps everything forever.
   */
  retainExpiredMs: number;
  acceptedMints: string[];
  priceSats: number;
  unit: string;
  /** Optional operator notice (MOTD) shown on the buyer page and in /info. */
  notice?: string;
  /** Optional acceptable-use / terms URL, linked on the buyer page and in /info. */
  termsUrl?: string;
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
const DEFAULT_RETAIN_EXPIRED_MS = 24 * 60 * 60 * 1000; // keep expired records 1 day, then forget (bounds file growth)

// Parse a non-negative integer env var, falling back to `def` when unset/empty.
// Throws on anything non-numeric so a fat-fingered value fails fast instead of
// becoming NaN — a NaN priceSats makes `amount < requiredSats` always false and
// accepts ANY payment; a NaN duration throws later on new Date(NaN).toISOString().
function intEnv(env: NodeJS.ProcessEnv, key: string, def: number, min = 0): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min) {
    throw new Error(`${key} must be an integer >= ${min}`);
  }
  return n;
}

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

  // How long expired records are kept before the cleanup tick forgets them.
  // 0 keeps everything. Bounds file growth (each purchase rewrites the file).
  let retainExpiredMs = DEFAULT_RETAIN_EXPIRED_MS;
  if (env.RETAIN_EXPIRED_MS !== undefined && env.RETAIN_EXPIRED_MS !== '') {
    const parsed = Number(env.RETAIN_EXPIRED_MS);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw new Error('RETAIN_EXPIRED_MS must be a non-negative integer (0 keeps everything)');
    }
    retainExpiredMs = parsed;
  }

  // DNS resolver(s) for the buyer config. Default Cloudflare 1.1.1.1: fastest
  // public resolver, unfiltered, no-log (audited). Queries exit masqueraded
  // behind the box's IP, so they aren't tied to the buyer. Comma-separated to
  // set several; override with WG_DNS.
  const dns = (env.WG_DNS ?? '1.1.1.1')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  // Per-lease data cap. Default 50 GiB; set LEASE_DATA_CAP_GB=0 to disable.
  let leaseDataCapBytes = 50 * 1024 ** 3;
  if (env.LEASE_DATA_CAP_GB !== undefined && env.LEASE_DATA_CAP_GB !== '') {
    const gb = Number(env.LEASE_DATA_CAP_GB);
    if (!Number.isFinite(gb) || gb < 0) {
      throw new Error('LEASE_DATA_CAP_GB must be a non-negative number (0 disables the cap)');
    }
    leaseDataCapBytes = Math.round(gb * 1024 ** 3);
  }

  const acceptedMints = env.ACCEPTED_MINTS
    ? env.ACCEPTED_MINTS.split(',').map((m) => m.trim()).filter(Boolean)
    : ['https://mint.minibits.cash/Bitcoin'];

  return {
    mode,
    host: env.HOST ?? '127.0.0.1',
    port: intEnv(env, 'PORT', 3087, 1),
    wgInterface: env.WG_INTERFACE ?? 'wg0',
    serverPublicKey: env.SERVER_PUBLIC_KEY ?? '',
    endpoint: env.WG_ENDPOINT ?? '',
    dns,
    peerLedgerPath: env.PEER_LEDGER_PATH,
    leaseDurationMs: intEnv(env, 'LEASE_DURATION_MS', DEFAULT_LEASE_MS, 1),
    leaseDataCapBytes,
    cleanupIntervalMs,
    retainExpiredMs,
    acceptedMints,
    priceSats: intEnv(env, 'PRICE_SATS', DEFAULT_PRICE_SATS, 1),
    unit: env.MINT_UNIT ?? 'sat',
    notice: env.NOTICE || undefined,
    termsUrl: env.TERMS_URL || undefined,
    publicBaseUrl: env.PUBLIC_BASE_URL ? env.PUBLIC_BASE_URL.replace(/\/+$/, '') : undefined,
    orderStorePath: env.ORDERS_PATH,
    orderTtlMs: intEnv(env, 'ORDER_TTL_MS', DEFAULT_ORDER_TTL_MS, 1),
    proofCountMargin: intEnv(env, 'PROOF_COUNT_MARGIN', DEFAULT_PROOF_COUNT_MARGIN, 0),
    operatorPubkey: env.OPERATOR_PUBKEY ?? '',
    operatorXpub: env.OPERATOR_XPUB || undefined,
    lockCounterPath: env.LOCK_COUNTER_PATH,
    proofStorePath: env.PROOFS_PATH,
    rateLimitMax: intEnv(env, 'RATE_LIMIT_MAX', 30, 0),
    rateLimitWindowMs: intEnv(env, 'RATE_LIMIT_WINDOW_MS', 60000, 1),
  };
}
