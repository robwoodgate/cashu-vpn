import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { PeerLedger, PeerLease } from './peers.js';

const execFileAsync = promisify(execFile);

// --- Types ---

/** A single command, expressed as an argv array — never a shell string. */
export interface CommandStep {
  argv: string[];
}

export interface CommandPlan {
  iface: string;
  steps: CommandStep[];
}

export interface CommandResult {
  argv: string[];
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CleanupResult {
  inspected: number;
  cleaned: PeerLease[];
  skipped: PeerLease[];
}

/**
 * A serializer shared by provisioning and cleanup so their WireGuard mutations
 * can't interleave on a shared peer key. Same shape as serialize() — pass the
 * one instance to both sides. Defaults to running inline (no shared lock).
 */
export type WgLock = <T>(fn: () => Promise<T>) => Promise<T>;
const runDirect: WgLock = (fn) => fn();

// --- Interface validation ---

export function validateInterface(name: string): string {
  if (!/^[a-zA-Z0-9_=+.-]{1,15}$/u.test(name) || name.startsWith('-')) {
    throw new Error(`Invalid WireGuard interface name: ${name}`);
  }
  return name;
}

// WireGuard public keys are base64-encoded 32-byte Curve25519 keys: 43 base64
// chars followed by a single '=' pad. The charset has no shell metacharacters,
// which (together with execFile) is what closes the command-injection vector.
const PUBKEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const TUNNEL_IP_RE = /^10\.77\.0\.(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/;

export function validatePublicKey(key: string): string {
  if (!PUBKEY_RE.test(key)) {
    throw new Error('Invalid WireGuard public key');
  }
  return key;
}

function isTunnelCidr(value: string): boolean {
  return value.endsWith('/32') && TUNNEL_IP_RE.test(value.slice(0, -3));
}

// --- Command planning ---

export function planAddPeer(iface: string, clientPubKey: string, tunnelIp: string): CommandPlan {
  return {
    iface,
    steps: [
      { argv: ['wg', 'set', iface, 'peer', clientPubKey, 'allowed-ips', `${tunnelIp}/32`] },
      { argv: ['ip', 'route', 'replace', `${tunnelIp}/32`, 'dev', iface] },
    ],
  };
}

export function planRemovePeer(iface: string, clientPubKey: string, tunnelIp: string): CommandPlan {
  return {
    iface,
    steps: [
      { argv: ['wg', 'set', iface, 'peer', clientPubKey, 'remove'] },
      { argv: ['ip', 'route', 'del', `${tunnelIp}/32`, 'dev', iface] },
    ],
  };
}

// --- Command execution ---

// Whitelist the exact argv shapes we ever run. Every field is checked against a
// strict pattern, so a hostile clientPublicKey cannot smuggle extra args, flags,
// or shell metacharacters. Combined with execFile (no shell), there is no
// injection surface even before this check.
function validateStep(iface: string, argv: string[]): void {
  // wg set <iface> peer <pubkey> allowed-ips <ip>/32
  if (
    argv.length === 7 &&
    argv[0] === 'wg' && argv[1] === 'set' && argv[2] === iface &&
    argv[3] === 'peer' && PUBKEY_RE.test(argv[4]!) &&
    argv[5] === 'allowed-ips' && isTunnelCidr(argv[6]!)
  ) return;

  // wg set <iface> peer <pubkey> remove
  if (
    argv.length === 6 &&
    argv[0] === 'wg' && argv[1] === 'set' && argv[2] === iface &&
    argv[3] === 'peer' && PUBKEY_RE.test(argv[4]!) && argv[5] === 'remove'
  ) return;

  // ip route replace|del <ip>/32 dev <iface>
  if (
    argv.length === 6 &&
    argv[0] === 'ip' && argv[1] === 'route' &&
    (argv[2] === 'replace' || argv[2] === 'del') &&
    isTunnelCidr(argv[3]!) && argv[4] === 'dev' && argv[5] === iface
  ) return;

  throw new Error(`Unsafe WireGuard command: ${argv.join(' ')}`);
}

export async function executePlan(plan: CommandPlan): Promise<CommandResult[]> {
  validateInterface(plan.iface);
  for (const step of plan.steps) validateStep(plan.iface, step.argv);

  const results: CommandResult[] = [];
  for (const step of plan.steps) {
    const result = await runStep(step.argv);
    results.push(result);
    if (result.exitCode !== 0) {
      throw new Error(
        `WireGuard command failed (exit ${result.exitCode}): ${step.argv.join(' ')}\n${result.stderr}`
      );
    }
  }
  return results;
}

async function runStep(argv: string[]): Promise<CommandResult> {
  const [program, ...args] = argv;
  try {
    const { stdout, stderr } = await execFileAsync(program!, args);
    return { argv, exitCode: 0, stdout, stderr };
  } catch (e: unknown) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return {
      argv,
      exitCode: typeof err.code === 'number' ? err.code : 1,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
    };
  }
}

// --- Client config generation ---

export function generateClientConfig(opts: {
  tunnelIp: string;
  serverPublicKey: string;
  endpoint: string;
  purchaseId: string;
  dryRun: boolean;
  dns?: string[];
}): string {
  // Full-tunnel (AllowedIPs = 0.0.0.0/0) needs an explicit DNS line, or the
  // client keeps its LAN resolver — unreachable through the tunnel — and name
  // resolution silently dies ("connected but no internet").
  const dnsLine = opts.dns && opts.dns.length > 0 ? `DNS = ${opts.dns.join(', ')}` : undefined;

  if (opts.dryRun) {
    return [
      '# dry-run WireGuard client config preview',
      '[Interface]',
      `Address = ${opts.tunnelIp}/32`,
      ...(dnsLine ? [dnsLine] : []),
      '# PrivateKey = <generate locally>',
      '',
      '[Peer]',
      `# purchase: ${opts.purchaseId}`,
      '# PublicKey = <operator server key>',
      '# Endpoint = <operator endpoint>',
      'AllowedIPs = 0.0.0.0/0',
    ].join('\n');
  }

  return [
    '[Interface]',
    `Address = ${opts.tunnelIp}/32`,
    ...(dnsLine ? [dnsLine] : []),
    '# PrivateKey = <generate locally>',
    '',
    '[Peer]',
    `PublicKey = ${opts.serverPublicKey}`,
    `Endpoint = ${opts.endpoint}`,
    'AllowedIPs = 0.0.0.0/0',
    'PersistentKeepalive = 25',
  ].join('\n');
}

// --- Per-peer data usage ---

export interface PeerTransfer {
  /** Bytes received from the peer (buyer uploads). */
  rx: number;
  /** Bytes sent to the peer (buyer downloads). */
  tx: number;
}

/**
 * Read cumulative per-peer transfer counters from `wg show <iface> transfer`.
 * Output is one tab-separated `pubkey\trx\ttx` line per peer. Counters are
 * since the peer was added and reset if it is removed and re-added.
 */
export async function readPeerTransfers(iface: string): Promise<Map<string, PeerTransfer>> {
  validateInterface(iface);
  const { stdout } = await execFileAsync('wg', ['show', iface, 'transfer']);
  const transfers = new Map<string, PeerTransfer>();
  for (const line of stdout.split('\n')) {
    const parts = line.split('\t');
    if (parts.length !== 3) continue;
    const [pub, rx, tx] = parts;
    // wg emits the counters as plain integers; guard against anything else.
    const rxN = Number(rx);
    const txN = Number(tx);
    if (!pub || !Number.isFinite(rxN) || !Number.isFinite(txN)) continue;
    transfers.set(pub, { rx: rxN, tx: txN });
  }
  return transfers;
}

// --- Shared peer removal ---

/**
 * Remove a peer for a lease we snapshotted as removable — but FIRST re-check, under
 * the shared wg lock, that no *other* live lease still claims this WireGuard key. A
 * concurrent re-buy with the same key (allocateAndRecord expires our snapshotted
 * lease and records a new live one, then `wg set`s the peer to a new IP) would
 * otherwise be cut by our `wg ... peer remove`, since WireGuard keys a peer by its
 * pubkey. Returns true if the peer was removed. Must be called inside the wg lock so
 * the re-check and the removal are atomic w.r.t. provisioning's `wg set`.
 */
async function removeStalePeer(
  ledger: PeerLedger,
  iface: string,
  lease: PeerLease,
  now: Date,
  exec: typeof executePlan
): Promise<boolean> {
  const renewed = (await ledger.list(now)).some(
    (l) =>
      l.clientPublicKey === lease.clientPublicKey &&
      l.status === 'active' &&
      l.purchaseId !== lease.purchaseId
  );
  if (renewed) return false; // a re-buy owns this key now — leave its peer alone
  await exec(planRemovePeer(iface, lease.clientPublicKey, lease.tunnelIp));
  await ledger.markExpired(lease.purchaseId);
  return true;
}

// --- Data-cap enforcement ---

/**
 * Pure selection: of the given active leases, which have reached `capBytes` of
 * cumulative usage (rx + tx)? Both directions count — buyer downloads (tx) and
 * uploads (rx) both leave the box on its public NIC, so both bill against the
 * host's egress allowance. Leases with no transfer entry (peer not on the
 * interface) are skipped. `capBytes <= 0` selects nothing (cap disabled).
 */
export function leasesOverCap(
  active: PeerLease[],
  transfers: Map<string, PeerTransfer>,
  capBytes: number
): PeerLease[] {
  if (!(capBytes > 0)) return [];
  return active.filter((lease) => {
    const usage = transfers.get(lease.clientPublicKey);
    return usage !== undefined && usage.rx + usage.tx >= capBytes;
  });
}

/**
 * Disconnect any active lease whose cumulative usage has reached `capBytes`.
 * Mirrors expiry: the peer is removed from the interface and the lease marked
 * expired. `capBytes <= 0` disables the cap (no-op).
 */
export async function enforceDataCaps(
  ledger: PeerLedger,
  iface: string,
  capBytes: number,
  dryRun: boolean,
  now = new Date(),
  wgLock: WgLock = runDirect,
  exec: typeof executePlan = executePlan
): Promise<CleanupResult> {
  if (!(capBytes > 0)) return { inspected: 0, cleaned: [], skipped: [] };

  const active = (await ledger.list(now)).filter((l) => l.status === 'active');
  if (active.length === 0) return { inspected: 0, cleaned: [], skipped: [] };

  const transfers = await readPeerTransfers(iface);
  const overCap = leasesOverCap(active, transfers, capBytes);
  const cleaned: PeerLease[] = [];
  const skipped: PeerLease[] = [];

  for (const lease of overCap) {
    if (dryRun) {
      skipped.push(lease);
      continue;
    }

    try {
      if (await wgLock(() => removeStalePeer(ledger, iface, lease, now, exec))) {
        cleaned.push({ ...lease, status: 'expired' });
      } else {
        skipped.push(lease);
      }
    } catch {
      skipped.push(lease);
    }
  }

  return { inspected: active.length, cleaned, skipped };
}

// --- Expired peer cleanup ---

export async function cleanupExpiredPeers(
  ledger: PeerLedger,
  iface: string,
  dryRun: boolean,
  now = new Date(),
  wgLock: WgLock = runDirect,
  exec: typeof executePlan = executePlan
): Promise<CleanupResult> {
  const expired = await ledger.listExpiredActive(now);
  const cleaned: PeerLease[] = [];
  const skipped: PeerLease[] = [];

  for (const lease of expired) {
    if (dryRun) {
      skipped.push(lease);
      continue;
    }

    try {
      if (await wgLock(() => removeStalePeer(ledger, iface, lease, now, exec))) {
        cleaned.push({ ...lease, status: 'expired' });
      } else {
        skipped.push(lease);
      }
    } catch {
      skipped.push(lease);
    }
  }

  return { inspected: expired.length, cleaned, skipped };
}
