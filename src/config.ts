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
}

const DEFAULT_LEASE_MS = 3 * 60 * 60 * 1000; // 3 hours
const DEFAULT_PRICE_SATS = 250;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const mode = env.MODE === 'live' ? 'live' : 'dry-run';

  const cleanupValue = env.CLEANUP_INTERVAL_MS;
  let cleanupIntervalMs: number | undefined;
  if (cleanupValue) {
    cleanupIntervalMs = Number(cleanupValue);
    if (!Number.isInteger(cleanupIntervalMs) || cleanupIntervalMs <= 0) {
      throw new Error('CLEANUP_INTERVAL_MS must be a positive integer');
    }
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
  };
}
