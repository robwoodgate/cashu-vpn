import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { PeerLedger, PeerLease } from './peers.js';

const execAsync = promisify(exec);

// --- Types ---

export interface CommandPlan {
  iface: string;
  commands: string[];
}

export interface CommandResult {
  command: string;
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CleanupResult {
  inspected: number;
  cleaned: PeerLease[];
  skipped: PeerLease[];
}

// --- Interface validation ---

export function validateInterface(name: string): string {
  if (!/^[a-zA-Z0-9_=+.-]{1,15}$/u.test(name) || name.startsWith('-')) {
    throw new Error(`Invalid WireGuard interface name: ${name}`);
  }
  return name;
}

// --- Command planning ---

export function planAddPeer(iface: string, clientPubKey: string, tunnelIp: string): CommandPlan {
  return {
    iface,
    commands: [
      `wg set ${iface} peer ${clientPubKey} allowed-ips ${tunnelIp}/32`,
      `ip route replace ${tunnelIp}/32 dev ${iface}`
    ]
  };
}

export function planRemovePeer(iface: string, clientPubKey: string, tunnelIp: string): CommandPlan {
  return {
    iface,
    commands: [
      `wg set ${iface} peer ${clientPubKey} remove`,
      `ip route del ${tunnelIp}/32 dev ${iface}`
    ]
  };
}

// --- Command execution ---

function validateCommand(iface: string, command: string): void {
  const esc = iface.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const ip = '10\\.77\\.0\\.(?:[2-9]|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-4])';
  const patterns = [
    new RegExp(`^wg set ${esc} peer [^\\s]+ allowed-ips ${ip}/32$`),
    new RegExp(`^ip route replace ${ip}/32 dev ${esc}$`),
    new RegExp(`^wg set ${esc} peer [^\\s]+ remove$`),
    new RegExp(`^ip route del ${ip}/32 dev ${esc}$`),
  ];
  if (!patterns.some((p) => p.test(command))) {
    throw new Error(`Unsafe WireGuard command: ${command}`);
  }
}

export async function executePlan(plan: CommandPlan): Promise<CommandResult[]> {
  validateInterface(plan.iface);
  for (const cmd of plan.commands) validateCommand(plan.iface, cmd);

  const results: CommandResult[] = [];
  for (const cmd of plan.commands) {
    const result = await runCommand(cmd);
    results.push(result);
    if (result.exitCode !== 0) {
      throw new Error(`WireGuard command failed (exit ${result.exitCode}): ${cmd}\n${result.stderr}`);
    }
  }
  return results;
}

async function runCommand(command: string): Promise<CommandResult> {
  try {
    const { stdout, stderr } = await execAsync(command);
    return { command, exitCode: 0, stdout, stderr };
  } catch (e: unknown) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return {
      command,
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
}): string {
  if (opts.dryRun) {
    return [
      '# dry-run WireGuard client config preview',
      '[Interface]',
      `Address = ${opts.tunnelIp}/32`,
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
    '# PrivateKey = <generate locally>',
    '',
    '[Peer]',
    `PublicKey = ${opts.serverPublicKey}`,
    `Endpoint = ${opts.endpoint}`,
    'AllowedIPs = 0.0.0.0/0',
    'PersistentKeepalive = 25',
  ].join('\n');
}

// --- Expired peer cleanup ---

export async function cleanupExpiredPeers(
  ledger: PeerLedger,
  iface: string,
  dryRun: boolean,
  now = new Date()
): Promise<CleanupResult> {
  const expired = await ledger.listExpiredActive(now);
  const cleaned: PeerLease[] = [];
  const skipped: PeerLease[] = [];

  for (const lease of expired) {
    if (dryRun) {
      skipped.push(lease);
      continue;
    }

    const plan = planRemovePeer(iface, lease.clientPublicKey, lease.tunnelIp);
    try {
      await executePlan(plan);
      await ledger.markExpired(lease.purchaseId);
      cleaned.push({ ...lease, status: 'expired' });
    } catch {
      skipped.push(lease);
    }
  }

  return { inspected: expired.length, cleaned, skipped };
}
