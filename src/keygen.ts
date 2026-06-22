/**
 * Offline operator key generator.
 *
 * Run this on a machine that is NOT your server. It creates a BIP32 HD key pair:
 *
 *   OPERATOR_XPUB  — goes on the box. It can only derive PUBLIC keys, never spend.
 *   OPERATOR_XPRV  — your funds key. Keep it OFFLINE. This string is your backup.
 *
 * The daemon derives a fresh child pubkey per sale from the xpub and locks that
 * sale's ecash to it; you later sweep with the matching child private keys from
 * the xprv. Both are the same account node, so they always agree — which this
 * generator verifies before printing.
 *
 *   npm run keygen          # human-readable
 *   npm run keygen -- --json  # {"xpub":"...","xprv":"..."}
 */

import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { HDKey } from '@scure/bip32';
import { deriveChildPubkey, deriveChildKeypair } from './hdkeys.js';
import { normalizePubkey } from './cashu.js';

// Account node the keys are derived at. The daemon works purely from the
// extended keys below, so this path is internal — but fixing it keeps generation
// deterministic and documented. (1597 = "VPN" on a phone keypad.)
const ACCOUNT_PATH = "m/1597'/0'";

/** Generate a fresh operator key pair (512-bit random seed). */
export function generateOperatorKeys(): { xpub: string; xprv: string } {
  const account = HDKey.fromMasterSeed(randomBytes(64)).derive(ACCOUNT_PATH);
  const xpub = account.publicExtendedKey;
  const xprv = account.privateExtendedKey;
  // Self-check: the daemon's xpub-derived child must equal the sweep's
  // xprv-derived child, or funds would be stranded.
  if (normalizePubkey(deriveChildPubkey(xpub, 0)) !== normalizePubkey(deriveChildKeypair(xprv, 0).pubkey)) {
    throw new Error('key self-check failed — do not use these keys');
  }
  return { xpub, xprv };
}

function main(): void {
  const { xpub, xprv } = generateOperatorKeys();

  if (process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify({ xpub, xprv }) + '\n');
    return;
  }

  process.stdout.write(`
cashu-vpn operator keys  (generated offline, path ${ACCOUNT_PATH})

  Put this on your server, in .env:

    OPERATOR_XPUB=${xpub}

  KEEP THIS OFFLINE. It controls your funds and is your only backup.
  Never put it on the server:

    OPERATOR_XPRV=${xprv}

The xpub can only watch and derive public keys, never spend. Sweep your earnings
later with the xprv (see "Getting paid" in the README).
`);
}

const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) main();
