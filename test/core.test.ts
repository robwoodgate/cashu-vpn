import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { AddressInfo } from 'node:net';

import { decodePaymentRequest } from '@cashu/cashu-ts';
import { loadConfig } from '../src/config.js';
import { createAllocator, createMemoryLedger, createFileLedger } from '../src/peers.js';
import { createMemoryProofStore, createFileProofStore } from '../src/wallet.js';
import { createMemoryOrderStore, newOrderId } from '../src/orders.js';
import {
  validateInterface,
  validatePublicKey,
  planAddPeer,
  planRemovePeer,
  executePlan,
  generateClientConfig,
  leasesOverCap,
} from '../src/wireguard.js';
import type { PeerLease } from '../src/peers.js';
import { HDKey } from '@scure/bip32';
import { createP2PKsecret, getP2PKExpectedWitnessPubkeys } from '@cashu/cashu-ts';
import { buildPaymentRequest, normalizeMintUrl, normalizePubkey, verifyPayment, popcount, type VerifyDeps } from '../src/cashu.js';
import { discover, parseRouteSrcIp } from '../src/discover.js';
import { deriveChildPubkey, deriveChildKeypair, isPrivateExtendedKey } from '../src/hdkeys.js';
import { generateOperatorKeys } from '../src/keygen.js';
import { createLockBook } from '../src/locks.js';
import { planSweep, sweepAll, filterUnswept, pruneSpent } from '../src/sweep.js';
import { decodeChallenge, waitForPaid } from '../src/buyer.js';
import { createRateLimiter } from '../src/ratelimit.js';
import type { ReceivedPayment } from '../src/wallet.js';
import { createServer } from '../src/server.js';

// --- Config ---

test('loadConfig returns dry-run defaults', () => {
  const c = loadConfig({});
  assert.equal(c.mode, 'dry-run');
  assert.equal(c.port, 3087);
  assert.equal(c.host, '127.0.0.1');
  assert.equal(c.wgInterface, 'wg0');
  assert.equal(c.priceSats, 1000);
  assert.equal(c.leaseDurationMs, 24 * 60 * 60 * 1000);
  assert.equal(c.cleanupIntervalMs, 60000); // on by default
  assert.deepEqual(c.acceptedMints, ['https://mint.minibits.cash/Bitcoin']);
});

test('loadConfig reads env overrides', () => {
  const c = loadConfig({
    MODE: 'live',
    PORT: '4000',
    HOST: '0.0.0.0',
    WG_INTERFACE: 'wg1',
    PRICE_SATS: '500',
    LEASE_DURATION_MS: '7200000',
    CLEANUP_INTERVAL_MS: '30000',
    ACCEPTED_MINTS: 'https://mint.a.com,https://mint.b.com',
    SERVER_PUBLIC_KEY: 'abc',
    WG_ENDPOINT: '1.2.3.4:51820',
  });
  assert.equal(c.mode, 'live');
  assert.equal(c.port, 4000);
  assert.equal(c.wgInterface, 'wg1');
  assert.equal(c.priceSats, 500);
  assert.equal(c.cleanupIntervalMs, 30000); // explicit override
  assert.deepEqual(c.acceptedMints, ['https://mint.a.com', 'https://mint.b.com']);
});

test('CLEANUP_INTERVAL_MS=0 disables cleanup; invalid values are rejected', () => {
  assert.equal(loadConfig({ CLEANUP_INTERVAL_MS: '0' }).cleanupIntervalMs, undefined);
  assert.equal(loadConfig({ CLEANUP_INTERVAL_MS: '' }).cleanupIntervalMs, 60000); // empty → default
  assert.throws(() => loadConfig({ CLEANUP_INTERVAL_MS: '-1' }), /non-negative integer/);
  assert.throws(() => loadConfig({ CLEANUP_INTERVAL_MS: 'soon' }), /non-negative integer/);
});

test('RETAIN_EXPIRED_MS defaults to 1 day; 0 keeps everything; invalid rejected', () => {
  assert.equal(loadConfig({}).retainExpiredMs, 24 * 60 * 60 * 1000);
  assert.equal(loadConfig({ RETAIN_EXPIRED_MS: '0' }).retainExpiredMs, 0);
  assert.equal(loadConfig({ RETAIN_EXPIRED_MS: '3600000' }).retainExpiredMs, 3600000);
  assert.throws(() => loadConfig({ RETAIN_EXPIRED_MS: '-5' }), /non-negative integer/);
});

test('LEASE_DATA_CAP_GB defaults to 50 GiB; 0 disables; invalid rejected', () => {
  assert.equal(loadConfig({}).leaseDataCapBytes, 50 * 1024 ** 3);
  assert.equal(loadConfig({ LEASE_DATA_CAP_GB: '0' }).leaseDataCapBytes, 0);
  assert.equal(loadConfig({ LEASE_DATA_CAP_GB: '10' }).leaseDataCapBytes, 10 * 1024 ** 3);
  assert.equal(loadConfig({ LEASE_DATA_CAP_GB: '' }).leaseDataCapBytes, 50 * 1024 ** 3); // empty → default
  assert.throws(() => loadConfig({ LEASE_DATA_CAP_GB: '-1' }), /non-negative number/);
  assert.throws(() => loadConfig({ LEASE_DATA_CAP_GB: 'lots' }), /non-negative number/);
});

test('loadConfig rejects non-numeric price/lease/ttl/port (no silent NaN)', () => {
  // A NaN priceSats would make `amount < requiredSats` always false → accept any
  // payment; a NaN duration throws later on new Date(NaN).toISOString().
  assert.throws(() => loadConfig({ PRICE_SATS: 'free' }), /PRICE_SATS/);
  assert.throws(() => loadConfig({ PRICE_SATS: '0' }), /PRICE_SATS/); // must be >= 1
  assert.throws(() => loadConfig({ LEASE_DURATION_MS: 'forever' }), /LEASE_DURATION_MS/);
  assert.throws(() => loadConfig({ ORDER_TTL_MS: '-1' }), /ORDER_TTL_MS/);
  assert.throws(() => loadConfig({ PORT: 'abc' }), /PORT/);
  assert.throws(() => loadConfig({ RATE_LIMIT_MAX: '1.5' }), /RATE_LIMIT_MAX/);
  // Empty string still falls back to the default.
  assert.equal(loadConfig({ PRICE_SATS: '' }).priceSats, 1000);
  assert.equal(loadConfig({ RATE_LIMIT_MAX: '0' }).rateLimitMax, 0); // 0 disables, allowed
});

// --- Allocator ---

test('allocator produces deterministic IPs in valid range', () => {
  const alloc = createAllocator();
  const ip1 = alloc.allocateTunnelIp('p1', 'key1');
  const ip2 = alloc.allocateTunnelIp('p1', 'key1');
  assert.equal(ip1, ip2); // deterministic
  assert.match(ip1, /^10\.77\.0\.\d+$/);

  // never reserved
  for (let i = 0; i < 500; i++) {
    const ip = alloc.allocateTunnelIp(`p-${i}`, `k-${i}`);
    const host = Number(ip.split('.')[3]);
    assert.notEqual(host, 0);
    assert.notEqual(host, 1);
    assert.notEqual(host, 255);
  }
});

test('allocator avoids IPs already in use', () => {
  const alloc = createAllocator();
  const first = alloc.allocateTunnelIp('p1', 'key1');
  // Same inputs but that IP is taken → must hand back a different, valid one.
  const second = alloc.allocateTunnelIp('p1', 'key1', new Set([first]));
  assert.notEqual(second, first);
  assert.match(second, /^10\.77\.0\.\d+$/);
  // Subnet exhausted → throws rather than colliding.
  const all = new Set<string>();
  for (let h = 2; h <= 254; h++) all.add(`10.77.0.${h}`);
  assert.throws(() => alloc.allocateTunnelIp('p1', 'key1', all), /exhausted/);
});

// --- Ledger ---

test('memory ledger records and lists with expiry', async () => {
  const ledger = createMemoryLedger();

  await ledger.record({
    purchaseId: 'p1', clientPublicKey: 'k1', tunnelIp: '10.77.0.10',
    createdAt: '2026-01-01T00:00:00Z', expiresAt: '2026-01-01T01:00:00Z', status: 'active',
  });

  // Before expiry
  const before = await ledger.list(new Date('2026-01-01T00:30:00Z'));
  assert.equal(before[0]?.status, 'active');

  // After expiry
  const after = await ledger.list(new Date('2026-01-01T01:00:01Z'));
  assert.equal(after[0]?.status, 'expired');

  // listExpiredActive
  const expired = await ledger.listExpiredActive(new Date('2026-01-01T01:00:01Z'));
  assert.equal(expired.length, 1);

  // markExpired
  await ledger.markExpired('p1');
  const marked = await ledger.listExpiredActive(new Date('2026-01-01T01:00:01Z'));
  assert.equal(marked.length, 0); // already marked
});

test('file-backed ledger persists across instances', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'nvpn-test-'));
  const path = join(dir, 'ledger.json');

  try {
    const l1 = createFileLedger(path);
    await l1.record({
      purchaseId: 'fp1', clientPublicKey: 'fk1', tunnelIp: '10.77.0.20',
      createdAt: '2026-01-01T00:00:00Z', expiresAt: '2026-01-01T00:01:00Z', status: 'active',
    });

    // New instance reads same file
    const l2 = createFileLedger(path);
    const list = await l2.list(new Date('2026-01-01T00:01:01Z'));
    assert.equal(list.length, 1);
    assert.equal(list[0]?.purchaseId, 'fp1');
    assert.equal(list[0]?.status, 'expired');

    // Verify file content
    const raw = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(raw.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('concurrent file-ledger records do not clobber each other', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'nvpn-test-'));
  const path = join(dir, 'ledger.json');
  try {
    const ledger = createFileLedger(path);
    // Fire 25 appends at once; without serialization the read-modify-write race
    // would drop most of them (last writer wins).
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        ledger.record({
          purchaseId: `p${i}`, clientPublicKey: `k${i}`, tunnelIp: `10.77.0.${i + 2}`,
          createdAt: '2026-01-01T00:00:00Z', expiresAt: '2999-01-01T00:00:00Z', status: 'active',
        })
      )
    );
    const list = await ledger.list();
    assert.equal(list.length, 25);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('concurrent file proof-store adds do not lose receipts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'nvpn-test-'));
  const path = join(dir, 'proofs.json');
  try {
    const store = createFileProofStore(path);
    const mk = (i: number): ReceivedPayment => ({
      purchaseId: `p${i}`, mint: 'https://m', amountSats: 1, token: `t${i}`,
      secrets: [`s${i}`], lockPubkey: 'k', receivedAt: '2026-01-01T00:00:00Z',
    });
    await Promise.all(Array.from({ length: 25 }, (_, i) => store.add(mk(i))));
    assert.equal((await store.list()).length, 25);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ledger pruneExpiredBefore forgets old leases, keeps recent/active', async () => {
  const ledger = createMemoryLedger();
  await ledger.record({
    purchaseId: 'old', clientPublicKey: 'k', tunnelIp: '10.77.0.2',
    createdAt: '2026-01-01T00:00:00Z', expiresAt: '2026-01-01T01:00:00Z', status: 'active',
  });
  await ledger.record({
    purchaseId: 'recent', clientPublicKey: 'k', tunnelIp: '10.77.0.3',
    createdAt: '2026-06-01T00:00:00Z', expiresAt: '2999-01-01T00:00:00Z', status: 'active',
  });
  const removed = await ledger.pruneExpiredBefore(new Date('2026-02-01T00:00:00Z'));
  assert.equal(removed, 1);
  const list = await ledger.list(new Date('2026-06-02T00:00:00Z'));
  assert.equal(list.length, 1);
  assert.equal(list[0]?.purchaseId, 'recent');
});

// --- WireGuard ---

test('validateInterface rejects unsafe names', () => {
  assert.throws(() => validateInterface('; rm -rf /'));
  assert.throws(() => validateInterface('-bad'));
  assert.throws(() => validateInterface('a'.repeat(16)));
  assert.doesNotThrow(() => validateInterface('wg0'));
  assert.doesNotThrow(() => validateInterface('wg-test0'));
});

test('planAddPeer and planRemovePeer produce correct argv steps', () => {
  const add = planAddPeer('wg0', 'PUBKEY', '10.77.0.42');
  assert.deepEqual(add.steps.map((s) => s.argv), [
    ['wg', 'set', 'wg0', 'peer', 'PUBKEY', 'allowed-ips', '10.77.0.42/32'],
    ['ip', 'route', 'replace', '10.77.0.42/32', 'dev', 'wg0'],
  ]);

  const rm = planRemovePeer('wg0', 'PUBKEY', '10.77.0.42');
  assert.deepEqual(rm.steps.map((s) => s.argv), [
    ['wg', 'set', 'wg0', 'peer', 'PUBKEY', 'remove'],
    ['ip', 'route', 'del', '10.77.0.42/32', 'dev', 'wg0'],
  ]);
});

test('validatePublicKey accepts WG keys and rejects injection attempts', () => {
  // Real key from the Hetzner smoke-test note.
  const good = 'nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=';
  assert.equal(validatePublicKey(good), good);
  assert.throws(() => validatePublicKey('aa;reboot'));
  assert.throws(() => validatePublicKey('$(reboot)'));
  assert.throws(() => validatePublicKey('short='));
  assert.throws(() => validatePublicKey(good.slice(0, -1))); // missing '=' pad
});

test('executePlan rejects unsafe steps before running anything', async () => {
  // A key with no whitespace passed the old regex guard and reached the shell.
  // It must now be rejected at the execution boundary (no wg/ip ever runs).
  await assert.rejects(
    executePlan({
      iface: 'wg0',
      steps: [{ argv: ['wg', 'set', 'wg0', 'peer', 'aa;reboot', 'allowed-ips', '10.77.0.5/32'] }],
    }),
    /Unsafe WireGuard command/
  );
});

test('generateClientConfig dry-run vs live', () => {
  const dry = generateClientConfig({
    tunnelIp: '10.77.0.42', serverPublicKey: 'SPK', endpoint: '1.2.3.4:51820',
    purchaseId: 'p1', dryRun: true,
  });
  assert.match(dry, /dry-run/);
  assert.match(dry, /10\.77\.0\.42\/32/);
  assert.doesNotMatch(dry, /SPK/); // no real key in dry-run

  const live = generateClientConfig({
    tunnelIp: '10.77.0.42', serverPublicKey: 'SPK', endpoint: '1.2.3.4:51820',
    purchaseId: 'p1', dryRun: false, dns: ['1.1.1.1'],
  });
  assert.doesNotMatch(live, /dry-run/);
  assert.match(live, /PublicKey = SPK/);
  assert.match(live, /Endpoint = 1\.2\.3\.4:51820/);
  // Full-tunnel config must carry a DNS line, or names won't resolve client-side.
  assert.match(live, /DNS = 1\.1\.1\.1/);
});

test('leasesOverCap selects only leases at/over the cap (rx + tx)', () => {
  const lease = (purchaseId: string, clientPublicKey: string): PeerLease => ({
    purchaseId, clientPublicKey, tunnelIp: '10.77.0.5',
    createdAt: '2026-01-01T00:00:00Z', expiresAt: '2999-01-01T00:00:00Z', status: 'active',
  });
  const active = [lease('under', 'kU'), lease('at', 'kA'), lease('over', 'kO'), lease('missing', 'kM')];
  const cap = 1000;
  const transfers = new Map([
    ['kU', { rx: 400, tx: 400 }], // 800 < cap
    ['kA', { rx: 600, tx: 400 }], // 1000 == cap
    ['kO', { rx: 900, tx: 900 }], // 1800 > cap
    // kM absent: peer not on the interface
  ]);

  const over = leasesOverCap(active, transfers, cap).map((l) => l.purchaseId).sort();
  assert.deepEqual(over, ['at', 'over']);

  // cap <= 0 disables the cap entirely
  assert.deepEqual(leasesOverCap(active, transfers, 0), []);
});

// --- HTTP server ---

test('GET /health returns ok', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.mode, 'dry-run');
  });
});

test('GET /info returns config summary', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/info`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.mode, 'dry-run');
    assert.equal(body.priceSats, 1000);
    assert.ok(body.acceptedMints.length > 0);
  });
});

test('POST /purchase dry-run creates lease without payment', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: 'test-key-123' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.match(body.purchaseId, /^p-/);
    assert.match(body.tunnelIp, /^10\.77\.0\./);
    assert.equal(body.mode, 'dry-run');
    assert.ok(body.clientConfig);
    assert.equal(body.lease.status, 'active');
  });
});

test('POST /purchase rejects missing clientPublicKey', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, 'missing_client_public_key');
  });
});

test('GET /peers is removed (privacy: no global lease list)', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/peers`);
    assert.equal(res.status, 404);
  });
});

test('GET /order/:id 404s for an unknown order id', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/order/${newOrderId()}`);
    assert.equal(res.status, 404);
  });
});

test('GET /marketplace returns HTML page', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/marketplace`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /text\/html/);
    const html = await res.text();
    assert.match(html, /Cashu VPN/);
    assert.match(html, /Get VPN config/);
    // Pay panel (LN + Cashu) and the bundled client are wired in.
    assert.match(html, /id="pay"/);
    assert.match(html, /Generate Lightning invoice/);
    // The paste box is gone; the wallet delivers over the request transport.
    assert.doesNotMatch(html, /Complete &amp; get config/);
    assert.doesNotMatch(html, /id="token"/);
    assert.match(html, /Your access/);
    // Buyers are told they need the WireGuard app, with a link + import QR slot.
    assert.match(html, /wireguard\.com\/install/);
    assert.match(html, /id="qrcfg"/);
    assert.match(html, /<script src="\/client\.js">/);
  });
});

test('NOTICE and TERMS_URL surface on the page and in /info', async () => {
  const env = { NOTICE: 'Demo node — be nice', TERMS_URL: 'https://example.com/terms' };
  await withServer(async (url) => {
    const info = await (await fetch(`${url}/info`)).json();
    assert.equal(info.notice, 'Demo node — be nice');
    assert.equal(info.termsUrl, 'https://example.com/terms');
    const html = await (await fetch(url)).text();
    assert.match(html, /Demo node — be nice/);
    assert.match(html, /href="https:\/\/example\.com\/terms"/);
  }, env);
});

test('no notice/terms shown when unset', async () => {
  await withServer(async (url) => {
    const info = await (await fetch(`${url}/info`)).json();
    assert.equal(info.notice, undefined);
    assert.equal(info.termsUrl, undefined);
    const html = await (await fetch(url)).text();
    assert.doesNotMatch(html, /class="panel notice"/);
    assert.doesNotMatch(html, /Terms of use/);
  });
});

test('GET /client.js serves the esbuild bundle', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/client.js`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /javascript/);
    const js = await res.text();
    assert.ok(js.length > 1000); // bundled cashu-ts etc.
  });
});

test('GET / serves marketplace page', async () => {
  await withServer(async (url) => {
    const res = await fetch(url);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Cashu VPN/);
  });
});

test('unknown route returns 404', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/nope`);
    assert.equal(res.status, 404);
  });
});

test('malformed percent-escape in /pay path 404s (not 500)', async () => {
  await withServer(async (url) => {
    // %zz is not a valid escape — decodeURIComponent would throw; must be a clean 404.
    const res = await fetch(`${url}/pay/%zz`, { method: 'POST' });
    assert.equal(res.status, 404);
  });
});

// --- Cashu payment ---

test('normalizeMintUrl strips trailing slashes', () => {
  assert.equal(normalizeMintUrl('https://mint.example.com/'), 'https://mint.example.com');
  assert.equal(normalizeMintUrl('  https://mint.example.com///  '), 'https://mint.example.com');
});

test('normalizeMintUrl is idempotent (safe to call twice)', () => {
  // A normalize fn that isn't idempotent corrupts already-normalized input on a
  // re-pass — the trap that bit normalizePubkey. Pin normalize(normalize(x)) === normalize(x).
  for (const raw of ['https://mint.example.com///', '  https://mint.example.com/  ', 'https://mint.example.com', '']) {
    const once = normalizeMintUrl(raw);
    assert.equal(normalizeMintUrl(once), once);
  }
});

const OP_PUBKEY = '02' + 'a'.repeat(64);

test('buildPaymentRequest produces a decodable creqA locked to the pubkey', () => {
  const pr = buildPaymentRequest({
    paymentId: 'pid-1',
    amountSats: 250,
    mints: ['https://mint.example.com'],
    lockPubkey: OP_PUBKEY,
    unit: 'sat',
    description: 'cashu-vpn access',
  });
  assert.match(pr, /^creqA/);

  const decoded = decodePaymentRequest(pr);
  assert.deepEqual(decoded.mints, ['https://mint.example.com']);
  assert.equal(decoded.unit, 'sat');
  assert.equal(decoded.amount?.toNumber(), 250);
  assert.equal(decoded.nut10?.kind, 'P2PK');
  assert.equal(decoded.nut10?.data, OP_PUBKEY);
});

test('buildPaymentRequest embeds a NUT-18 POST transport when given a target', () => {
  const pr = buildPaymentRequest({
    paymentId: 'ord-123',
    amountSats: 250,
    mints: ['https://mint.example.com'],
    lockPubkey: OP_PUBKEY,
    transportTarget: 'https://host.example/pay/ord-123',
  });
  const decoded = decodePaymentRequest(pr);
  const t = decoded.transport?.[0];
  assert.equal(t?.type, 'post');
  assert.equal(t?.target, 'https://host.example/pay/ord-123');
});

test('popcount returns the minimal power-of-two split size', () => {
  assert.equal(popcount(0), 0);
  assert.equal(popcount(1), 1);
  assert.equal(popcount(255), 8);
  assert.equal(popcount(256), 1);
  assert.equal(popcount(260), 2); // 256 + 4
});

// Build verifyPayment deps that succeed, so each test can override one field to
// exercise a single failure branch. Proofs/keysets are faked; the real DLEQ /
// P2PK crypto is exercised against a live mint at the deploy checkpoint.
function okDeps(over: Record<string, unknown> = {}) {
  return {
    getMetadata: () => ({ mint: 'https://good.mint', amount: 300, unit: 'sat' }) as never,
    loadMintContext: async () => ({
      keysetIds: ['k1'],
      getKeyset: () => ({ id: 'k1', keys: {} as never }),
    }),
    decode: () => [{ id: 'k1', secret: 's1', amount: 260 }] as never,
    checkDleq: () => true,
    witnessPubkeys: () => [OP_PUBKEY],
    ...over,
  };
}

const VERIFY_OPTS = { acceptedMints: ['https://good.mint'], requiredSats: 250, unit: 'sat' };

test('verifyPayment rejects an unaccepted mint', async () => {
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    getMetadata: () => ({ mint: 'https://evil.mint', amount: 300, unit: 'sat' }) as never,
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'mint_not_accepted');
});

test('verifyPayment rejects a proof that fails DLEQ', async () => {
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({ checkDleq: () => false }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'invalid_dleq');
});

test('verifyPayment rejects an unlocked proof', async () => {
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({ witnessPubkeys: () => [] }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'not_locked');
});

test('verifyPayment rejects a plain (non-P2PK) secret without throwing', async () => {
  // Real wallets that ignore the PR's nut10 lock send ordinary ecash, whose
  // secret is plain hex — getP2PKExpectedWitnessPubkeys throws on it. Must be a
  // clean not_locked rejection, not a 500.
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    witnessPubkeys: () => { throw new Error('Can\'t parse secret'); },
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'not_locked');
});

test('verifyPayment rejects a multisig lock (not sole operator)', async () => {
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    witnessPubkeys: () => [OP_PUBKEY, '02' + 'b'.repeat(64)],
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'multisig_lock');
});

test('verifyPayment rejects a lock with a refund/locktime escape', async () => {
  const secret = JSON.stringify(['P2PK', { nonce: 'n', data: OP_PUBKEY, tags: [['locktime', '1']] }]);
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    decode: () => [{ id: 'k1', secret, amount: 260 }] as never,
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'refundable_lock');
});

test('verifyPayment rejects a wrong-unit token', async () => {
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    getMetadata: () => ({ mint: 'https://good.mint', amount: 300, unit: 'usd' }) as never,
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'wrong_unit');
});

test('verifyPayment rejects inconsistent lock pubkeys across proofs', async () => {
  let n = 0;
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    decode: () => [{ id: 'k1', secret: 's1', amount: 130 }, { id: 'k1', secret: 's2', amount: 130 }] as never,
    witnessPubkeys: () => [n++ === 0 ? OP_PUBKEY : '02' + 'b'.repeat(64)],
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'inconsistent_lock');
});

test('verifyPayment rejects too-low amount', async () => {
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({
    decode: () => [{ id: 'k1', secret: 's1', amount: 100 }] as never,
  }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'amount_too_low');
});

test('verifyPayment rejects dust-griefing (too many proofs for the amount)', async () => {
  // 20 proofs summing to 260; popcount(260)=2, default margin 0 here → cap 2.
  const proofs = Array.from({ length: 20 }, (_, i) => ({ id: 'k1', secret: `s${i}`, amount: 13 }));
  const r = await verifyPayment('tok', VERIFY_OPTS, okDeps({ decode: () => proofs as never }));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'too_many_proofs');
});

test('verifyPayment proofCountMargin tolerates non-minimal honest splits', async () => {
  // 5 proofs summing to 260; popcount(260)=2, margin 4 → cap 6, so 5 is allowed.
  const proofs = Array.from({ length: 5 }, (_, i) => ({ id: 'k1', secret: `s${i}`, amount: 52 }));
  const r = await verifyPayment('tok', { ...VERIFY_OPTS, proofCountMargin: 4 }, okDeps({ decode: () => proofs as never }));
  assert.equal(r.valid, true);
  assert.equal(r.amountSats, 260);
});

test('verifyPayment accepts a genuine, locked token and returns the lock pubkey', async () => {
  const r = await verifyPayment('tok-abc', VERIFY_OPTS, okDeps());
  assert.equal(r.valid, true);
  assert.equal(r.amountSats, 260);
  assert.equal(r.mint, 'https://good.mint');
  assert.equal(r.token, 'tok-abc');
  assert.deepEqual(r.secrets, ['s1']);
  assert.equal(r.lockPubkey, 'a'.repeat(64)); // normalized (02 stripped)
});

// --- HTTP server: live-mode 402 flow ---

const LIVE_ENV = {
  MODE: 'live',
  SERVER_PUBLIC_KEY: 'nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=',
  WG_ENDPOINT: '1.2.3.4:51820',
  ACCEPTED_MINTS: 'https://mint.example.com',
  OPERATOR_PUBKEY: '02' + 'a'.repeat(64),
} satisfies NodeJS.ProcessEnv;

const VALID_WG_KEY = 'nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=';

test('live POST /purchase without payment returns 402 + x-cashu challenge', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
    });
    assert.equal(res.status, 402);
    const creq = res.headers.get('x-cashu') ?? '';
    assert.match(creq, /^creqA/);
    const decoded = decodePaymentRequest(creq);
    assert.equal(decoded.amount?.toNumber(), 1000);
    assert.deepEqual(decoded.mints, ['https://mint.example.com']);
    assert.equal(decoded.nut10?.kind, 'P2PK');
    assert.equal(decoded.nut10?.data, '02' + 'a'.repeat(64));
    const body = await res.json();
    assert.equal(body.error, 'payment_required');
    // Per-order: the creqA carries a NUT-18 POST transport to this order's sink.
    assert.ok(body.orderId);
    assert.equal(decoded.id, body.orderId); // paymentId == orderId
    const transport = decoded.transport?.[0];
    assert.equal(transport?.type, 'post');
    assert.match(transport?.target ?? '', new RegExp(`/pay/${body.orderId}$`));
  }, LIVE_ENV);
});

test('order lifecycle: pending order, poll, CORS preflight, and /pay validation', async () => {
  await withServer(async (url) => {
    const r = await fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
    });
    assert.equal(r.status, 402);
    const { orderId } = await r.json();
    assert.ok(orderId);

    // Browser poll: still pending (capability id required — unknown ids 404).
    const poll = await fetch(`${url}/order/${orderId}`);
    assert.equal(poll.status, 200);
    assert.equal((await poll.json()).status, 'pending');

    // CORS preflight for browser-based Cashu wallets POSTing to the transport.
    const opt = await fetch(`${url}/pay/${orderId}`, { method: 'OPTIONS' });
    assert.equal(opt.status, 204);
    assert.equal(opt.headers.get('access-control-allow-origin'), '*');

    // Garbage body → 400 invalid_payload (CORS header still set).
    const bad = await fetch(`${url}/pay/${orderId}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nope: 1 }),
    });
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, 'invalid_payload');
    assert.equal(bad.headers.get('access-control-allow-origin'), '*');

    // Unverifiable token → 402 payment_failed (real DLEQ/P2PK tested live).
    const badtok = await fetch(`${url}/pay/${orderId}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: 'cashuBnotreal' }),
    });
    assert.equal(badtok.status, 402);
    assert.equal((await badtok.json()).error, 'payment_failed');

    // Unknown order id → 404.
    const unk = await fetch(`${url}/pay/${newOrderId()}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: 'x' }),
    });
    assert.equal(unk.status, 404);
  }, LIVE_ENV);
});

test('live POST /purchase rejects a malformed client key with 400', async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: 'aa;reboot' }),
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, 'invalid_client_public_key');
  }, LIVE_ENV);
});

test('live xpub mode issues a fresh per-tx lock pubkey on each 402', async () => {
  const xpub = HDKey.fromMasterSeed(new Uint8Array(64).fill(21)).derive("m/1597'/0'").publicExtendedKey;
  const lockBook = await createLockBook(xpub);
  const env = {
    MODE: 'live',
    SERVER_PUBLIC_KEY: VALID_WG_KEY,
    WG_ENDPOINT: '1.2.3.4:51820',
    ACCEPTED_MINTS: 'https://mint.example.com',
  } satisfies NodeJS.ProcessEnv; // no OPERATOR_PUBKEY — lockBook provides the lock
  await withServer(async (url) => {
    const get402Lock = async () => {
      const res = await fetch(`${url}/purchase`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
      });
      assert.equal(res.status, 402);
      return decodePaymentRequest(res.headers.get('x-cashu') ?? '').nut10?.data ?? '';
    };
    const d1 = await get402Lock();
    const d2 = await get402Lock();
    assert.notEqual(d1, d2); // per-tx unlinkable locks
    assert.equal(lockBook.resolve(d1), 0);
    assert.equal(lockBook.resolve(d2), 1);
  }, env, { lockBook });
});

// --- HD key derivation (xpub per-tx privacy) ---

const pkNorm = (k: string) => k.toLowerCase().replace(/^0[23]/, '');

test('HD derivation: xpub child pubkey == xprv child pubkey (no stranded funds)', () => {
  const acct = HDKey.fromMasterSeed(new Uint8Array(64).fill(7)).derive("m/1597'/0'");
  const xpub = acct.publicExtendedKey;
  const xprv = acct.privateExtendedKey;
  assert.equal(isPrivateExtendedKey(xpub), false);
  assert.equal(isPrivateExtendedKey(xprv), true);

  for (const i of [0, 1, 5, 42, 1000]) {
    const pub = deriveChildPubkey(xpub, i);
    const kp = deriveChildKeypair(xprv, i);
    assert.equal(kp.pubkey, pub, `index ${i} pub mismatch — operator could not sweep`);
  }
  // per-transaction unlinkability: different index -> different lock pubkey
  assert.notEqual(deriveChildPubkey(xpub, 0), deriveChildPubkey(xpub, 1));
});

test('HD-derived pubkey works as a P2PK lock and is recoverable', () => {
  const acct = HDKey.fromMasterSeed(new Uint8Array(64).fill(9)).derive("m/1597'/0'");
  const pub = deriveChildPubkey(acct.publicExtendedKey, 3);
  const secret = createP2PKsecret(pub);
  const expected = getP2PKExpectedWitnessPubkeys(secret);
  assert.ok(expected.map(pkNorm).includes(pkNorm(pub)));
});

test('generateOperatorKeys produces a matching, sweepable xpub/xprv pair', () => {
  const { xpub, xprv } = generateOperatorKeys();
  assert.ok(xpub.startsWith('xpub'));
  assert.ok(xprv.startsWith('xprv'));
  assert.equal(isPrivateExtendedKey(xpub), false);
  assert.equal(isPrivateExtendedKey(xprv), true);
  // The daemon's xpub-derived child equals the operator's xprv-derived child,
  // so locks the daemon issues can always be swept.
  assert.equal(pkNorm(deriveChildPubkey(xpub, 0)), pkNorm(deriveChildKeypair(xprv, 0).pubkey));
  assert.equal(pkNorm(deriveChildPubkey(xpub, 7)), pkNorm(deriveChildKeypair(xprv, 7).pubkey));
  // Each call generates a different key.
  assert.notEqual(generateOperatorKeys().xprv, xprv);
});

test('deriveChildKeypair refuses an xpub, and indices are bounded', () => {
  const xpub = HDKey.fromMasterSeed(new Uint8Array(64).fill(3)).derive("m/0'").publicExtendedKey;
  assert.throws(() => deriveChildKeypair(xpub, 0));
  assert.throws(() => deriveChildPubkey(xpub, -1));
  assert.throws(() => deriveChildPubkey(xpub, 2 ** 31));
});

// --- LockBook (xpub per-tx issuance) ---

test('LockBook issues distinct per-tx pubkeys and resolves them to indices', async () => {
  const xpub = HDKey.fromMasterSeed(new Uint8Array(64).fill(11)).derive("m/1597'/0'").publicExtendedKey;
  const book = await createLockBook(xpub); // memory mode (no counter path)
  const a = await book.issue();
  const b = await book.issue();
  assert.equal(a.index, 0);
  assert.equal(b.index, 1);
  assert.notEqual(a.pubkey, b.pubkey);
  assert.equal(book.resolve(a.pubkey), 0);
  assert.equal(book.resolve(b.pubkey), 1);
  // normalized lookups work too (02/03-stripped, lowercase)
  assert.equal(book.resolve(a.pubkey.toLowerCase().replace(/^0[23]/, '')), 0);
  assert.equal(book.resolve('02' + 'f'.repeat(64)), undefined);
});

test('LockBook resolves locks whose x-only coordinate starts 02/03 (normalize is idempotent)', async () => {
  // Regression: resolve() re-normalizes the pubkey verifyPayment already
  // normalized. A non-idempotent normalize over-strips keys whose x-only form
  // begins 02/03 (~0.8% of indices), rejecting a paid buyer as lock_not_recognized.
  const xpub = HDKey.fromMasterSeed(new Uint8Array(64).fill(7)).derive("m/1597'/0'").publicExtendedKey;
  const book = await createLockBook(xpub);
  let issued: { index: number; pubkey: string } | undefined;
  // Index 18 is the first child here whose x-only coordinate starts 02/03.
  for (let i = 0; i <= 18; i++) issued = await book.issue();
  const xonly = issued!.pubkey.toLowerCase().replace(/^0[23]/, '');
  assert.match(xonly, /^0[23]/); // precondition: this key actually triggers the trap
  assert.equal(book.resolve(xonly), 18); // the already-normalized form must still resolve
});

test('LockBook persists its counter and rebuilds the map across instances', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cvpn-locks-'));
  const counterPath = join(dir, 'counter.json');
  try {
    const xpub = HDKey.fromMasterSeed(new Uint8Array(64).fill(13)).derive("m/1597'/0'").publicExtendedKey;
    const b1 = await createLockBook(xpub, counterPath);
    const first = await b1.issue(); // index 0
    await b1.issue(); // index 1

    const b2 = await createLockBook(xpub, counterPath);
    const third = await b2.issue();
    assert.equal(third.index, 2); // continued from persisted counter
    assert.equal(b2.resolve(first.pubkey), 0); // map rebuilt from xpub
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// --- Rate limiting ---

test('rate limiter allows up to max then blocks within the window', () => {
  let t = 1000;
  const rl = createRateLimiter({ max: 3, windowMs: 1000, now: () => t });
  assert.equal(rl.check('a').allowed, true);
  assert.equal(rl.check('a').allowed, true);
  assert.equal(rl.check('a').allowed, true);
  const blocked = rl.check('a');
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterMs > 0 && blocked.retryAfterMs <= 1000);
  assert.equal(rl.check('b').allowed, true); // independent key
  t += 1001; // window slides
  assert.equal(rl.check('a').allowed, true);
});

test('POST /purchase is rate limited per IP', async () => {
  await withServer(async (url) => {
    const post = () => fetch(`${url}/purchase`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: 'k' }),
    });
    assert.equal((await post()).status, 200);
    assert.equal((await post()).status, 200);
    const third = await post();
    assert.equal(third.status, 429);
    assert.ok(third.headers.get('retry-after'));
  }, { RATE_LIMIT_MAX: '2', RATE_LIMIT_WINDOW_MS: '60000' });
});

// --- Buyer-side helpers (browser flow) ---

test('decodeChallenge extracts amount/mint/unit/lock from a creqA', () => {
  const creq = buildPaymentRequest({
    paymentId: 'x', amountSats: 250, mints: ['https://mint.example.com'],
    lockPubkey: OP_PUBKEY, unit: 'sat',
  });
  const c = decodeChallenge(creq);
  assert.equal(c.amount, 250);
  assert.equal(c.mintUrl, 'https://mint.example.com');
  assert.equal(c.unit, 'sat');
  assert.equal(c.lockPubkey, OP_PUBKEY);
});

test('waitForPaid resolves once the quote is PAID', async () => {
  let n = 0;
  const wallet = { checkMintQuoteBolt11: async () => ({ state: n++ < 2 ? 'UNPAID' : 'PAID' }) };
  const ok = await waitForPaid(wallet as never, 'q', { tries: 5, sleep: async () => {} });
  assert.equal(ok, true);
  assert.equal(n, 3);
});

test('waitForPaid times out if never paid', async () => {
  const wallet = { checkMintQuoteBolt11: async () => ({ state: 'UNPAID' }) };
  const ok = await waitForPaid(wallet as never, 'q', { tries: 3, sleep: async () => {} });
  assert.equal(ok, false);
});

// --- Order store (per-order delivery) ---

test('order store: create, poll, markReady once, and prune expired pending', async () => {
  const store = createMemoryOrderStore();
  const id = newOrderId();
  const future = new Date(Date.now() + 60_000).toISOString();
  await store.create({
    id, status: 'pending', clientPublicKey: 'k', lockPubkey: OP_PUBKEY,
    lockIndex: 3, createdAt: new Date().toISOString(), expiresAt: future,
  });

  assert.equal((await store.get(id))?.status, 'pending');

  const lease = {
    purchaseId: 'p1', clientPublicKey: 'k', tunnelIp: '10.77.0.9',
    createdAt: 't', expiresAt: 't', status: 'active' as const,
  };
  const ready = await store.markReady(id, {
    purchaseId: 'p1', tunnelIp: '10.77.0.9', amountSats: 250, clientConfig: 'CONF', lease,
  });
  assert.equal(ready?.status, 'ready');
  assert.equal((await store.get(id))?.clientConfig, 'CONF');

  // Second markReady is a no-op (no longer pending).
  assert.equal(await store.markReady(id, { purchaseId: 'p2', tunnelIp: 'x', amountSats: 1, clientConfig: 'X', lease }), undefined);

  // Expired pending orders read as gone.
  const expiredId = newOrderId();
  const past = new Date(Date.now() - 1000).toISOString();
  await store.create({
    id: expiredId, status: 'pending', clientPublicKey: 'k', lockPubkey: OP_PUBKEY,
    createdAt: past, expiresAt: past,
  });
  assert.equal(await store.get(expiredId), undefined);
  // ...but a late /pay can still fetch + provision it (no stranded payment).
  assert.equal((await store.get(expiredId, undefined, { includeExpired: true }))?.id, expiredId);
  assert.equal((await store.markReady(expiredId, {
    purchaseId: 'p9', tunnelIp: '10.77.0.9', amountSats: 1, clientConfig: 'C', lease,
  }))?.status, 'ready');
});

test('order store pruneExpiredBefore forgets ready leases past cutoff, keeps live', async () => {
  const store = createMemoryOrderStore();
  const past = new Date(Date.now() - 1000).toISOString();
  const future = new Date(Date.now() + 3600_000).toISOString();
  // ready order whose lease already expired
  await store.create({
    id: newOrderId(), status: 'ready', clientPublicKey: 'k', lockPubkey: OP_PUBKEY,
    createdAt: past, expiresAt: past,
    lease: { purchaseId: 'p', clientPublicKey: 'k', tunnelIp: '10.77.0.2', createdAt: past, expiresAt: past, status: 'active' },
  });
  // pending order still within its request window
  const live = newOrderId();
  await store.create({
    id: live, status: 'pending', clientPublicKey: 'k', lockPubkey: OP_PUBKEY,
    createdAt: new Date().toISOString(), expiresAt: future,
  });
  const removed = await store.pruneExpiredBefore(new Date());
  assert.equal(removed, 1);
  assert.ok(await store.get(live)); // the live pending order survived
});

// --- Sweep (operator claims locked proofs offline) ---

test('planSweep derives a matching claim key for each xpub receipt', () => {
  const acct = HDKey.fromMasterSeed(new Uint8Array(64).fill(31)).derive("m/1597'/0'");
  const xpub = acct.publicExtendedKey;
  const xprv = acct.privateExtendedKey;
  const mk = (i: number, over: Partial<ReceivedPayment> = {}): ReceivedPayment => ({
    purchaseId: `p${i}`, mint: 'https://m', amountSats: 250, token: `tok${i}`, secrets: [`s${i}`],
    lockPubkey: pkNorm(deriveChildPubkey(xpub, i)), index: i, receivedAt: 't', ...over,
  });
  const receipts = [mk(0), mk(1), mk(2, { index: undefined }), mk(3, { lockPubkey: 'ff'.repeat(32) })];
  const plan = planSweep(receipts, xprv);

  assert.equal(plan.sweepable.length, 2);
  assert.equal(plan.manual.length, 1);
  assert.equal(plan.mismatched.length, 1);
  for (const e of plan.sweepable) {
    assert.equal(pkNorm(deriveChildKeypair(xprv, e.index).pubkey), pkNorm(e.pubkey));
  }
});

test('sweepAll batches each mint into one swap and aggregates claimed proofs', async () => {
  const plan = {
    sweepable: [
      { index: 0, mint: 'https://m1', amountSats: 250, token: 't0', pubkey: 'p', privkey: 'k0' },
      { index: 1, mint: 'https://m1', amountSats: 250, token: 't1', pubkey: 'p', privkey: 'k1' },
      { index: 2, mint: 'https://m2', amountSats: 250, token: 't2', pubkey: 'p', privkey: 'k2' },
    ],
    manual: [],
    mismatched: [],
  };
  // decode: one proof per token; claim: one 100-sat output per input proof.
  const decode = (token: string) => [{ amount: 250, secret: token }] as never;
  const swaps: Array<{ mint: string; nProofs: number; nKeys: number }> = [];
  const claim = async (mint: string, proofs: unknown[], keys: string[]) => {
    swaps.push({ mint, nProofs: proofs.length, nKeys: keys.length });
    return proofs.map(() => ({ amount: 100 })) as never;
  };
  const encode = (mint: string, proofs: unknown[]) => `cashuB-${mint}-${proofs.length}`;
  const results = await sweepAll(plan, claim, encode, decode);

  const m1 = results.find((r) => r.mint === 'https://m1');
  const m2 = results.find((r) => r.mint === 'https://m2');
  assert.equal(m1?.claimedSats, 200);
  assert.equal(m1?.token, 'cashuB-https://m1-2');
  assert.equal(m1?.batched, true);
  assert.equal(m1?.receipts, 2);
  assert.equal(m2?.claimedSats, 100);
  assert.deepEqual(m1?.errors, []);
  // m1's two receipts were claimed in a SINGLE swap with both keys.
  const m1swaps = swaps.filter((s) => s.mint === 'https://m1');
  assert.equal(m1swaps.length, 1);
  assert.deepEqual(m1swaps[0], { mint: 'https://m1', nProofs: 2, nKeys: 2 });
});

test('sweepAll falls back to per-receipt claims when the batch swap fails', async () => {
  const plan = {
    sweepable: [
      { index: 0, mint: 'https://m', amountSats: 250, token: 'good', pubkey: 'p', privkey: 'k0' },
      { index: 1, mint: 'https://m', amountSats: 250, token: 'bad', pubkey: 'p', privkey: 'k1' },
    ],
    manual: [],
    mismatched: [],
  };
  const decode = (token: string) => [{ amount: 130, secret: token }] as never;
  const claim = async (_mint: string, proofs: Array<{ secret: string }>) => {
    if (proofs.some((p) => p.secret === 'bad')) throw new Error('already spent');
    return proofs.map(() => ({ amount: 130 })) as never;
  };
  const [res] = await sweepAll(plan, claim as never, () => 'tok', decode);
  assert.equal(res?.claimedSats, 130); // only the good receipt
  assert.equal(res?.batched, false);
  assert.ok(res?.errors.some((e) => /already spent/.test(e)));
});

test('filterUnswept skips receipts the mint reports as SPENT (idempotent re-runs)', async () => {
  const plan = {
    sweepable: [
      { index: 0, mint: 'https://m', amountSats: 250, token: 'spent', pubkey: 'p', privkey: 'k0' },
      { index: 1, mint: 'https://m', amountSats: 250, token: 'live', pubkey: 'p', privkey: 'k1' },
    ],
    manual: [],
    mismatched: [],
  };
  const decode = (token: string) => [{ secret: token, id: '00' }] as never;
  const check = async (_mint: string, proofs: Array<{ secret: string }>) =>
    proofs.map((p) => (p.secret === 'spent' ? 'SPENT' : 'UNSPENT'));
  const { sweepable, alreadySwept } = await filterUnswept(plan, decode, check);
  assert.equal(sweepable.length, 1);
  assert.equal(sweepable[0]?.index, 1);
  assert.equal(alreadySwept.length, 1);
  assert.equal(alreadySwept[0]?.index, 0);
});

test('pruneSpent keeps unspent receipts and drops fully-swept ones', async () => {
  const mk = (id: string, token: string): ReceivedPayment => ({
    purchaseId: id, mint: 'https://m', amountSats: 250, token, secrets: [token], lockPubkey: 'p', receivedAt: 't',
  });
  const receipts = [mk('p0', 'spent'), mk('p1', 'live')];
  const decode = (token: string) => [{ secret: token, id: '00' }] as never;
  const check = async (_mint: string, proofs: Array<{ secret: string }>) =>
    proofs.map((p) => (p.secret === 'spent' ? 'SPENT' : 'UNSPENT'));
  const { keep, dropped } = await pruneSpent(receipts, decode, check);
  assert.equal(keep.length, 1);
  assert.equal(keep[0]?.purchaseId, 'p1');
  assert.equal(dropped.length, 1);
  assert.equal(dropped[0]?.purchaseId, 'p0');
});

// --- Operator discovery ---

test('parseRouteSrcIp extracts the src IPv4', () => {
  assert.equal(
    parseRouteSrcIp('1.1.1.1 via 157.180.114.1 dev eth0 src 157.180.114.119 uid 0'),
    '157.180.114.119'
  );
  assert.equal(parseRouteSrcIp('no src here'), '');
});

test('discover reads key/port and builds endpoint (non-mutating)', async () => {
  const calls: string[][] = [];
  const run = async (cmd: string, args: string[]) => {
    calls.push([cmd, ...args]);
    if (args.join(' ') === 'show wg0 public-key') return 'nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=';
    if (args.join(' ') === 'show wg0 listen-port') return '51820';
    if (cmd === 'ip') return '1.1.1.1 dev eth0 src 157.180.114.119 uid 0';
    return '';
  };

  const d = await discover('wg0', {}, run);
  assert.equal(d.interfaceName, 'wg0');
  assert.equal(d.serverPublicKey, 'nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=');
  assert.equal(d.listenPort, '51820');
  assert.equal(d.endpoint, '157.180.114.119:51820');
  assert.equal(d.hostMutationPerformed, false);
  // Only read-only commands were ever issued.
  for (const c of calls) {
    assert.ok(c[0] === 'wg' || c[0] === 'ip', `unexpected command: ${c.join(' ')}`);
    if (c[0] === 'wg') assert.equal(c[1], 'show');
  }
});

test('discover honours an explicit host hint over autodetect', async () => {
  const run = async (cmd: string, args: string[]) => {
    if (args.join(' ') === 'show wg0 public-key') return 'PUBKEY';
    if (args.join(' ') === 'show wg0 listen-port') return '51820';
    throw new Error('should not autodetect when hint is given');
  };
  const d = await discover('wg0', { hostHint: '203.0.113.7' }, run);
  assert.equal(d.endpoint, '203.0.113.7:51820');
});

// --- Test helper ---

async function withServer(
  fn: (url: string) => Promise<void>,
  env: NodeJS.ProcessEnv = {},
  extra: Partial<Parameters<typeof createServer>[0]> = {}
): Promise<void> {
  const config = loadConfig(env);
  const server = createServer({
    config,
    allocator: createAllocator(),
    ledger: createMemoryLedger(),
    proofStore: createMemoryProofStore(),
    orderStore: createMemoryOrderStore(),
    ...extra,
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((e) => e ? reject(e) : resolve());
    });
  }
}

// --- Property tests ---
//
// These randomize over many inputs to catch the probabilistic bugs a fixed
// fixture can't — the kind that ship because the happy path eats them (e.g. the
// normalizePubkey double-strip that only bit keys whose x-coordinate starts
// 02/03). Each pins an INVARIANT, not a specific output. Seeded so failures
// reproduce: any assertion below names the input that broke it.

/** Seeded PRNG (mulberry32) so a property failure reproduces from its seed. */
function prng(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('property: normalizePubkey is idempotent, parity-blind, and case-insensitive', () => {
  const rnd = prng(1);
  const hex64 = () => Array.from({ length: 64 }, () => Math.floor(rnd() * 16).toString(16)).join('');
  for (let i = 0; i < 1000; i++) {
    const x = hex64(); // an x-only coordinate (may itself start 02/03 — the trap)
    const n = normalizePubkey('02' + x);
    assert.equal(n, x, `compressed key must reduce to its x-only coordinate (x=${x})`);
    assert.equal(normalizePubkey('03' + x), n, `parity must not change the result (x=${x})`);
    assert.equal(normalizePubkey(n), n, `must be idempotent on an already-x-only key (x=${x})`);
    assert.equal(normalizePubkey(('02' + x).toUpperCase()), n, `must be case-insensitive (x=${x})`);
  }
});

test('property: every issued xpub lock resolves via its raw AND normalized form', async () => {
  // The form server.ts hands resolve() is the normalized (x-only) one from
  // verifyPayment, so resolve MUST accept that form for every issued index —
  // including keys whose x-coordinate starts 02/03 (the original bug). Find a few
  // such trap indices first, then assert ALL issued locks up to there resolve.
  const xpub = HDKey.fromMasterSeed(new Uint8Array(64).fill(7)).derive("m/1597'/0'").publicExtendedKey;
  const traps: number[] = [];
  let maxIdx = 0;
  for (let i = 0; traps.length < 3 && i < 5000; i++) {
    if (/^0[23]/.test(normalizePubkey(deriveChildPubkey(xpub, i)))) { traps.push(i); maxIdx = i; }
  }
  assert.ok(traps.length >= 1, 'expected at least one 02/03-coordinate key in range to make this meaningful');

  const book = await createLockBook(xpub);
  for (let i = 0; i <= maxIdx; i++) {
    const { index, pubkey } = await book.issue();
    assert.equal(book.resolve(pubkey), index, `raw compressed key must resolve (index ${index})`);
    assert.equal(book.resolve(normalizePubkey(pubkey)), index, `normalized x-only key must resolve (index ${index})`);
  }
});

test('property: proof store flags any token sharing a secret with a stored one (replay-once)', async () => {
  const rnd = prng(9);
  const store = createMemoryProofStore();
  const stored: string[] = [];
  for (let i = 0; i < 200; i++) {
    // Fresh, disjoint secrets must read as unseen, then as seen once stored.
    const secrets = Array.from({ length: 1 + Math.floor(rnd() * 4) }, (_, j) => `g${i}_${j}`);
    assert.equal(await store.hasAnyOf(secrets), false, `fresh secrets must be unseen (i=${i})`);
    await store.add({
      purchaseId: `p${i}`, mint: 'https://m', amountSats: 1, token: `t${i}`,
      secrets, lockPubkey: 'a'.repeat(64), receivedAt: new Date().toISOString(),
    });
    stored.push(...secrets);
    // Any single stored secret, or a new token reusing just one, is a replay.
    const reused = stored[Math.floor(rnd() * stored.length)]!;
    assert.equal(await store.hasAnyOf(['brand-new', reused]), true, `one overlapping secret must flag replay (i=${i})`);
  }
});

test('property: an honest power-of-two split never trips the dust guard', async () => {
  // A griefer pads a payment with dust proofs (each an extra sweep input fee); the
  // cap rejects them. But the minimal split of ANY amount is exactly popcount(n)
  // proofs, so an honest wallet must always pass at margin 0. Pins that the guard
  // never rejects a legitimate payment.
  const rnd = prng(11);
  for (let t = 0; t < 400; t++) {
    const n = 1 + Math.floor(rnd() * 1_000_000);
    const parts: number[] = [];
    for (let b = 0; b < 31; b++) if (n & (1 << b)) parts.push(1 << b);
    assert.equal(parts.length, popcount(n), `minimal split size must equal popcount (n=${n})`);
    const proofs = parts.map((amount, i) => ({ id: 'k1', secret: `s${t}_${i}`, amount }));
    const r = await verifyPayment(
      'tok',
      { acceptedMints: ['https://good.mint'], requiredSats: n, unit: 'sat', proofCountMargin: 0 },
      okDeps({ decode: () => proofs as never }),
    );
    assert.equal(r.valid, true, `honest split must verify (n=${n})`);
    assert.equal(r.amountSats, n, `verified amount must equal the split sum (n=${n})`);
  }
});

test('property: planSweep partitions every receipt exactly once', () => {
  const root = HDKey.fromMasterSeed(new Uint8Array(64).fill(3));
  const xprv = root.privateExtendedKey;
  const rnd = prng(7);
  const receipts: ReceivedPayment[] = [];
  for (let i = 0; i < 300; i++) {
    const base = {
      purchaseId: `p${i}`, mint: 'https://m', amountSats: 1 + Math.floor(rnd() * 1000),
      token: `t${i}`, secrets: [`s${i}`], lockPubkey: '', receivedAt: '',
    };
    const r = rnd();
    if (r < 1 / 3) receipts.push({ ...base }); // no index → manual (fixed-key)
    else if (r < 2 / 3) {
      const kp = deriveChildKeypair(xprv, i); // matching lock → sweepable
      receipts.push({ ...base, index: i, lockPubkey: normalizePubkey(kp.pubkey) });
    } else receipts.push({ ...base, index: i, lockPubkey: 'deadbeef' }); // wrong lock → mismatched
  }
  const plan = planSweep(receipts, xprv);

  // Conservation: every receipt lands in exactly one bucket, none lost or duplicated.
  const seen = new Set<string>();
  for (const e of plan.sweepable) seen.add(e.token);
  for (const r of [...plan.manual, ...plan.mismatched]) seen.add(r.token);
  assert.equal(plan.sweepable.length + plan.manual.length + plan.mismatched.length, receipts.length);
  assert.equal(seen.size, receipts.length, 'no receipt may be dropped or double-counted');
  // Buckets match their defining condition.
  assert.ok(plan.manual.every((r) => r.index === undefined), 'manual = receipts with no index');
  assert.ok(plan.mismatched.every((r) => r.index !== undefined), 'mismatched = indexed but wrong lock');
});

// --- Atomic provisioning + cross-process prune lock ---

// Allocate the lowest free host; if `taken` isn't updated atomically per record,
// two concurrent calls collide on the same IP.
const lowestFree = (taken: Set<string>): string => {
  for (let h = 2; h < 255; h++) { const ip = `10.77.0.${h}`; if (!taken.has(ip)) return ip; }
  throw new Error('subnet exhausted');
};

test('allocateAndRecord expires a prior active lease for the same key (one key, one lease)', async () => {
  const ledger = createMemoryLedger();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60_000).toISOString();
  const first = await ledger.allocateAndRecord({ purchaseId: 'a', clientPublicKey: 'K', now, expiresAt, allocate: lowestFree });
  const second = await ledger.allocateAndRecord({ purchaseId: 'b', clientPublicKey: 'K', now, expiresAt, allocate: lowestFree });
  assert.deepEqual(second.expiredPriorIds, ['a'], 'the prior same-key lease is reported as expired');
  assert.deepEqual(first.expiredPriorIds, [], 'the first lease expired nothing');
  const active = (await ledger.list()).filter((l) => l.status === 'active');
  assert.equal(active.length, 1, 'the prior lease for this key is expired');
  assert.equal(active[0]!.purchaseId, 'b', 'the newest lease wins');
  assert.equal((await ledger.list()).length, 2, 'the old lease is expired, not deleted');
  assert.ok(second.lease.tunnelIp.startsWith('10.77.0.'));
});

test('reactivate restores an expired lease (rollback of a failed renewal)', async () => {
  const ledger = createMemoryLedger();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60_000).toISOString();
  const first = await ledger.allocateAndRecord({ purchaseId: 'a', clientPublicKey: 'K', now, expiresAt, allocate: lowestFree });
  const second = await ledger.allocateAndRecord({ purchaseId: 'b', clientPublicKey: 'K', now, expiresAt, allocate: lowestFree });
  // Simulate provisionPeer's wg-failure rollback: expire the new, re-activate the prior.
  await ledger.markExpired('b');
  await ledger.reactivate(second.expiredPriorIds);
  const active = (await ledger.list()).filter((l) => l.status === 'active');
  assert.equal(active.length, 1, 'exactly one active lease after rollback');
  assert.equal(active[0]!.purchaseId, 'a', 'the original lease is live again, so cleanup still reaps its peer');
  assert.ok(first.lease.tunnelIp.startsWith('10.77.0.'));
});

test('file ledger allocateAndRecord serializes allocation — no IP collisions under concurrency', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cvpn-alloc-'));
  const path = join(dir, 'ledger.json');
  try {
    const ledger = createFileLedger(path);
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    // 20 distinct keys provisioning at once: if the read-allocate-write weren't
    // serialized, they'd read the same free-IP snapshot and pick duplicate /32s.
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) =>
      ledger.allocateAndRecord({ purchaseId: `p${i}`, clientPublicKey: `key-${i}`, now: new Date(), expiresAt, allocate: lowestFree })));
    assert.equal(new Set(results.map((r) => r.lease.tunnelIp)).size, 20, 'every concurrent allocation got a distinct IP');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('file proof store: prune compact and a concurrent daemon append lose nothing (cross-process lock)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cvpn-proofs-'));
  const path = join(dir, 'proofs.json');
  const rcpt = (id: string, secrets: string[]): ReceivedPayment => ({
    purchaseId: id, mint: 'https://m', amountSats: 1, token: `tok-${id}`,
    secrets, lockPubkey: 'a'.repeat(64), receivedAt: new Date().toISOString(),
  });
  try {
    // Two SEPARATE store instances stand in for two processes: each has its own
    // in-process serialize(), so only the on-disk lockfile coordinates them.
    const daemon = createFileProofStore(path);
    const pruner = createFileProofStore(path);
    await daemon.add(rcpt('keep', ['s1']));
    await daemon.add(rcpt('spent', ['s2']));

    const droppedIds = new Set(['spent']);
    await Promise.all([
      pruner.compact((recs) => recs.filter((r) => !droppedIds.has(r.purchaseId))),
      daemon.add(rcpt('newcomer', ['s3'])), // appended mid-prune
    ]);

    const ids = (await daemon.list()).map((r) => r.purchaseId).sort();
    // 'spent' dropped; 'keep' and the concurrently-appended 'newcomer' both survive,
    // whichever order the lock grants — never a lost paid token.
    assert.deepEqual(ids, ['keep', 'newcomer']);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('property: sweepAll conserves sats across batch and fallback paths', async () => {
  // Whatever the claimer does, claimedSats must equal the sats actually claimed —
  // batching or per-receipt fallback must never drop or duplicate a proof.
  const rnd = prng(5);
  const amtByToken = new Map<string, number>();
  const sweepable = Array.from({ length: 50 }, (_, i) => {
    const token = `t${i}`;
    const amt = 1 + Math.floor(rnd() * 1000);
    amtByToken.set(token, amt);
    return { index: i, mint: i % 2 ? 'https://a' : 'https://b', amountSats: amt, token, pubkey: 'p', privkey: 'k' };
  });
  const plan = { sweepable, manual: [], mismatched: [] };
  const expected = sweepable.reduce((a, e) => a + e.amountSats, 0);

  const decode = (token: string) => [{ id: 'k', secret: token, amount: amtByToken.get(token)! }] as never;
  const encode = () => 'x';
  // Identity claimer (batch path): claimed proofs == input proofs.
  const idClaim = async (_m: string, proofs: never) => proofs;
  const batch = await sweepAll(plan, idClaim as never, encode, decode);
  assert.equal(batch.reduce((a, r) => a + r.claimedSats, 0), expected, 'batch path must conserve sats');

  // Forced-fallback claimer: throws on a multi-proof batch, succeeds one at a time.
  const fallbackClaim = async (_m: string, proofs: { length: number }) => {
    if (proofs.length > 1) throw new Error('batch rejected');
    return proofs as never;
  };
  const fallback = await sweepAll(plan, fallbackClaim as never, encode, decode);
  assert.equal(fallback.reduce((a, r) => a + r.claimedSats, 0), expected, 'fallback path must conserve sats');
  assert.ok(fallback.every((r) => !r.batched), 'fallback path must report batched=false');
});

// --- Concurrency: the double-provision guards ---
//
// The inflightSecrets / processing guards are correct by construction (the
// check-and-set is synchronous), so these don't hunt for a race — they pin the
// invariant (one payment => exactly one peer + one receipt) so a future edit that
// slips an await between the check and the add, or drops the guard, goes red. A
// deliberately slow proof-store widens the commit window so such a regression
// actually manifests instead of slipping through on timing.
// Seam note: verifyDeps fakes the offline verify; execPlan no-ops WireGuard — this
// is the only coverage of a *completed* live provision (every other live test
// stops at a 402 before provisioning).

const slept = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** A memory proof store whose add() lingers, widening the reserve->commit window. */
function slowProofStore(delayMs: number) {
  const inner = createMemoryProofStore();
  return { ...inner, add: async (p: ReceivedPayment) => { await slept(delayMs); return inner.add(p); } };
}

// Offline verify that always passes, locked to LIVE_ENV's OPERATOR_PUBKEY, with a
// FIXED secret so every concurrent delivery looks like the same token (the replay
// the guards must collapse to one).
const PASS_VERIFY: VerifyDeps = {
  getMetadata: () => ({ mint: 'https://mint.example.com', amount: 1000, unit: 'sat' }) as never,
  // The delay converges all concurrent requests at this await, so they resume and
  // pile into the reservation together — that's what makes an await-between-check-
  // and-add regression actually contend (and the test go red). Verified by control.
  loadMintContext: async () => { await slept(20); return { keysetIds: ['k1'], getKeyset: () => ({ id: 'k1', keys: {} as never }) }; },
  decode: () => [{ id: 'k1', secret: 'shared-secret', amount: 1000 }] as never,
  checkDleq: () => true,
  witnessPubkeys: () => ['02' + 'a'.repeat(64)],
};

test('concurrent /pay deliveries for one order provision exactly once', async () => {
  const ledger = createMemoryLedger();
  const proofStore = slowProofStore(40);
  await withServer(async (url) => {
    const r = await fetch(`${url}/purchase`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
    });
    const { orderId } = await r.json();
    const deliver = () => fetch(`${url}/pay/${orderId}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: 'tok' }),
    });
    const res = await Promise.all(Array.from({ length: 8 }, deliver));
    const codes = res.map((x) => x.status);

    // Invariant: one peer, one receipt — no double-provision regardless of interleaving.
    assert.equal((await ledger.list()).length, 1, 'exactly one lease provisioned');
    assert.equal((await proofStore.list()).length, 1, 'exactly one receipt stored');
    assert.ok(codes.includes(200), 'at least one delivery succeeds');
    // Losers are rejected cleanly: 409 in-progress, or 200 idempotent (order already ready).
    assert.ok(codes.every((c) => c === 200 || c === 409), `unexpected status: ${codes}`);
  }, LIVE_ENV, { ledger, proofStore, verifyDeps: PASS_VERIFY, execPlan: async () => [] });
});

test('concurrent inline X-Cashu deliveries provision exactly once', async () => {
  const ledger = createMemoryLedger();
  const proofStore = slowProofStore(40);
  await withServer(async (url) => {
    // Same token (same secret) delivered inline 8x at once. The inline path has no
    // per-order guard — only inflightSecrets stands between it and a double-spend.
    const deliver = () => fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-cashu': 'tok' },
      body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
    });
    const codes = (await Promise.all(Array.from({ length: 8 }, deliver))).map((x) => x.status);

    assert.equal(codes.filter((c) => c === 200).length, 1, 'exactly one inline delivery provisions');
    assert.ok(codes.filter((c) => c === 402).length >= 1, 'the rest are rejected as already_redeemed');
    assert.equal((await ledger.list()).length, 1, 'exactly one lease provisioned');
    assert.equal((await proofStore.list()).length, 1, 'exactly one receipt stored');
  }, LIVE_ENV, { ledger, proofStore, verifyDeps: PASS_VERIFY, execPlan: async () => [] });
});

test('malformed JSON returns 400 and an oversized body 413 (not 500)', async () => {
  await withServer(async (url) => {
    const bad = await fetch(`${url}/purchase`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{ not json',
    });
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, 'invalid_json');

    const big = await fetch(`${url}/purchase`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(20_000),
    });
    assert.equal(big.status, 413);
    assert.equal((await big.json()).error, 'payload_too_large');
  }, LIVE_ENV);
});

test('re-buying with an already-active key replaces the old lease (no early disconnect)', async () => {
  // WireGuard keys a peer by its pubkey, so a second purchase with the same key
  // moves the peer to a new IP; the old lease must be expired (not left active),
  // or its cleanup later runs `wg ... peer remove` and cuts the new buyer.
  const ledger = createMemoryLedger();
  let n = 0;
  const verifyDeps: VerifyDeps = { ...PASS_VERIFY, decode: () => [{ id: 'k1', secret: `uniq-${n++}`, amount: 1000 }] as never };
  await withServer(async (url) => {
    const buy = () => fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-cashu': 'tok' },
      body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
    });
    assert.equal((await buy()).status, 200);
    assert.equal((await buy()).status, 200);

    const all = await ledger.list();
    assert.equal(all.length, 2, 'both purchases recorded a lease');
    const active = all.filter((l) => l.status === 'active' && l.clientPublicKey === VALID_WG_KEY);
    assert.equal(active.length, 1, 'one key holds exactly one active lease (old one expired, not removed)');
  }, LIVE_ENV, { ledger, verifyDeps, execPlan: async () => [] });
});

test('a failed wg renewal keeps the original lease active (no orphaned peer)', async () => {
  // Renewal expires the prior lease atomically; if `wg set` then fails, the prior
  // lease must be re-activated, or cleanup (active-only) never reaps its live peer.
  const ledger = createMemoryLedger();
  let n = 0;
  const verifyDeps: VerifyDeps = { ...PASS_VERIFY, decode: () => [{ id: 'k1', secret: `u${n++}`, amount: 1000 }] as never };
  let calls = 0;
  const execPlan = async () => { calls += 1; if (calls === 2) throw new Error('wg down'); return []; };
  await withServer(async (url) => {
    const buy = () => fetch(`${url}/purchase`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-cashu': 'tok' },
      body: JSON.stringify({ clientPublicKey: VALID_WG_KEY }),
    });
    assert.equal((await buy()).status, 200);            // first lease provisioned
    assert.equal((await buy()).status, 500);            // renewal: wg fails mid-provision → rolled back

    const all = await ledger.list();
    assert.equal(all.length, 2, 'both leases recorded');
    const active = all.filter((l) => l.status === 'active' && l.clientPublicKey === VALID_WG_KEY);
    assert.equal(active.length, 1, 'the original lease is active again — its peer stays reapable, not orphaned');
  }, LIVE_ENV, { ledger, verifyDeps, execPlan: execPlan as never });
});

// --- Real P2PK secret parsing through verifyPayment (offline, no mint) ---
//
// The witness-pubkey extraction is the half of verification that breaks silently
// on a cashu-ts upgrade. Other verify tests fake witnessPubkeys; these drive the
// REAL getP2PKExpectedWitnessPubkeys (and the real escape-clause parse) end-to-end
// through verifyPayment, with only DLEQ + mint context faked. DLEQ itself needs a
// mint-signed proof — covered by the live deploy check, not here.

const REAL_P2PK_PUB = deriveChildPubkey(
  HDKey.fromMasterSeed(new Uint8Array(64).fill(9)).derive("m/1597'/0'").publicExtendedKey, 3,
);
const REAL_P2PK_OPTS = { acceptedMints: ['https://good.mint'], requiredSats: 1000, unit: 'sat', proofCountMargin: 0 };
const realP2PKDeps = (secret: string): VerifyDeps => ({
  getMetadata: () => ({ mint: 'https://good.mint', amount: 1000, unit: 'sat' }) as never,
  loadMintContext: async () => ({ keysetIds: ['k1'], getKeyset: () => ({ id: 'k1', keys: {} as never }) }),
  decode: () => [{ id: 'k1', secret, amount: 1000 }] as never,
  checkDleq: () => true,
  // witnessPubkeys left to the real getP2PKExpectedWitnessPubkeys default.
});

test('verifyPayment accepts a REAL P2PK secret and recovers the lock pubkey', async () => {
  const secret = createP2PKsecret(REAL_P2PK_PUB);
  const r = await verifyPayment('tok', REAL_P2PK_OPTS, realP2PKDeps(secret));
  assert.equal(r.valid, true);
  assert.equal(r.lockPubkey, normalizePubkey(REAL_P2PK_PUB));
});

test('verifyPayment rejects a REAL P2PK secret carrying a locktime escape', async () => {
  // Real secret, real witness extraction (passes), real escape-clause parse (trips).
  const secret = createP2PKsecret(REAL_P2PK_PUB, [['locktime', '9999999999']]);
  const r = await verifyPayment('tok', REAL_P2PK_OPTS, realP2PKDeps(secret));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'refundable_lock');
});
