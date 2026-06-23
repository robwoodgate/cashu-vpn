/**
 * Operator discovery — non-mutating.
 *
 * Reads the WireGuard server public key, listen port, and a best-effort public
 * endpoint off a live interface so an operator can fill in the daemon's env in
 * one step. Runs only read-only commands (`wg show`, `ip route get`); never
 * touches the host. Mirrors the discovery JSON in the Hetzner smoke-evidence
 * notes (hostMutationPerformed: false).
 *
 * Usage: node dist/src/discover.js [interface] [public-ip-or-host]
 *   - interface defaults to $WG_INTERFACE or "wg0"
 *   - public host defaults to $WG_ENDPOINT host, else best-effort autodetect
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { validateInterface } from './wireguard.js';

const execFileAsync = promisify(execFile);

export interface Discovery {
  interfaceName: string;
  serverPublicKey: string;
  listenPort: string;
  endpoint: string;
  hostMutationPerformed: false;
}

/** Runs a read-only command and returns trimmed stdout. */
export type Runner = (cmd: string, args: string[]) => Promise<string>;

const defaultRunner: Runner = async (cmd, args) => {
  const { stdout } = await execFileAsync(cmd, args);
  return stdout.trim();
};

/** Parse the `src` IPv4 from `ip route get` output. */
export function parseRouteSrcIp(routeOutput: string): string {
  const m = routeOutput.match(/\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})\b/);
  return m ? m[1]! : '';
}

export async function detectPublicHost(run: Runner = defaultRunner): Promise<string> {
  // Best effort: the src address of the default route to a public IP. On a
  // typical VPS this is the public IPv4; behind NAT the operator should pass an
  // explicit host (arg or WG_ENDPOINT).
  try {
    return parseRouteSrcIp(await run('ip', ['-4', 'route', 'get', '1.1.1.1']));
  } catch {
    return '';
  }
}

export async function discover(
  iface: string,
  opts: { hostHint?: string } = {},
  run: Runner = defaultRunner,
): Promise<Discovery> {
  validateInterface(iface);

  const serverPublicKey = (await run('wg', ['show', iface, 'public-key'])).trim();
  const listenPort = (await run('wg', ['show', iface, 'listen-port'])).trim();
  const host = (opts.hostHint && opts.hostHint.trim()) || (await detectPublicHost(run));
  const endpoint = host && listenPort ? `${host}:${listenPort}` : '';

  return { interfaceName: iface, serverPublicKey, listenPort, endpoint, hostMutationPerformed: false };
}

/** Render a paste-ready env block for the operator. */
export function renderEnvBlock(d: Discovery): string {
  const endpoint = d.endpoint || '<your-public-ip>:' + (d.listenPort || '51820');
  return [
    '# cashu-vpn operator config (discovered — nothing on the host was changed)',
    'MODE=live',
    `WG_INTERFACE=${d.interfaceName}`,
    `SERVER_PUBLIC_KEY=${d.serverPublicKey || '<wg show ' + d.interfaceName + ' public-key>'}`,
    `WG_ENDPOINT=${endpoint}`,
    '# Still required — set these yourself:',
    'OPERATOR_XPUB=<your account xpub; the xprv stays OFF this box> (run `npm run keygen`)',
    'ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin',
    'PRICE_SATS=250',
  ].join('\n');
}

async function main(): Promise<void> {
  const iface = process.argv[2] ?? process.env.WG_INTERFACE ?? 'wg0';
  const hostHint = process.argv[3] ?? hostFromEndpoint(process.env.WG_ENDPOINT);
  const d = await discover(iface, { hostHint });
  console.log(JSON.stringify(d, null, 2));
  console.log('\n' + renderEnvBlock(d));
}

function hostFromEndpoint(endpoint?: string): string | undefined {
  if (!endpoint) return undefined;
  const i = endpoint.lastIndexOf(':');
  return i > 0 ? endpoint.slice(0, i) : endpoint;
}

const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) {
  void main().catch((e) => {
    console.error('discovery failed:', e instanceof Error ? e.message : e);
    process.exitCode = 1;
  });
}
