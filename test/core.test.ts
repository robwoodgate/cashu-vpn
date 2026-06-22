import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { AddressInfo } from 'node:net';

import { decodePaymentRequest } from '@cashu/cashu-ts';
import { loadConfig } from '../src/config.js';
import { createAllocator, createMemoryLedger, createFileLedger } from '../src/peers.js';
import { createMemoryProofStore } from '../src/wallet.js';
import { createMemoryOrderStore, newOrderId } from '../src/orders.js';
import {
  validateInterface,
  validatePublicKey,
  planAddPeer,
  planRemovePeer,
  executePlan,
  generateClientConfig,
} from '../src/wireguard.js';
import { HDKey } from '@scure/bip32';
import { createP2PKsecret, getP2PKExpectedWitnessPubkeys } from '@cashu/cashu-ts';
import { buildPaymentRequest, normalizeMintUrl, verifyPayment, popcount } from '../src/cashu.js';
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
    purchaseId: 'p1', dryRun: false,
  });
  assert.doesNotMatch(live, /dry-run/);
  assert.match(live, /PublicKey = SPK/);
  assert.match(live, /Endpoint = 1\.2\.3\.4:51820/);
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

// --- Cashu payment ---

test('normalizeMintUrl strips trailing slashes', () => {
  assert.equal(normalizeMintUrl('https://mint.example.com/'), 'https://mint.example.com');
  assert.equal(normalizeMintUrl('  https://mint.example.com///  '), 'https://mint.example.com');
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
