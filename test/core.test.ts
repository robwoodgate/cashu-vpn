import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { AddressInfo } from 'node:net';

import { loadConfig } from '../src/config.js';
import { createAllocator, createMemoryLedger, createFileLedger } from '../src/peers.js';
import {
  validateInterface,
  validatePublicKey,
  planAddPeer,
  planRemovePeer,
  executePlan,
  generateClientConfig,
} from '../src/wireguard.js';
import { createServer } from '../src/server.js';

// --- Config ---

test('loadConfig returns dry-run defaults', () => {
  const c = loadConfig({});
  assert.equal(c.mode, 'dry-run');
  assert.equal(c.port, 3087);
  assert.equal(c.host, '127.0.0.1');
  assert.equal(c.wgInterface, 'wg0');
  assert.equal(c.priceSats, 250);
  assert.equal(c.leaseDurationMs, 3 * 60 * 60 * 1000);
  assert.equal(c.cleanupIntervalMs, undefined);
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
    CLEANUP_INTERVAL_MS: '60000',
    ACCEPTED_MINTS: 'https://mint.a.com,https://mint.b.com',
    SERVER_PUBLIC_KEY: 'abc',
    WG_ENDPOINT: '1.2.3.4:51820',
  });
  assert.equal(c.mode, 'live');
  assert.equal(c.port, 4000);
  assert.equal(c.wgInterface, 'wg1');
  assert.equal(c.priceSats, 500);
  assert.equal(c.cleanupIntervalMs, 60000);
  assert.deepEqual(c.acceptedMints, ['https://mint.a.com', 'https://mint.b.com']);
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
    assert.equal(body.priceSats, 250);
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

test('GET /peers shows recorded leases', async () => {
  await withServer(async (url) => {
    // Purchase first
    await fetch(`${url}/purchase`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: 'peer-test-key' }),
    });

    const res = await fetch(`${url}/peers`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.count, 1);
    assert.equal(body.peers[0]?.clientPublicKey, 'peer-test-key');
    assert.equal(body.peers[0]?.status, 'active');
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

// --- Test helper ---

async function withServer(fn: (url: string) => Promise<void>): Promise<void> {
  const config = loadConfig({});
  const server = createServer({
    config,
    allocator: createAllocator(),
    ledger: createMemoryLedger(),
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
