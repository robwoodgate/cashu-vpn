import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Config } from './config.js';
import type { PeerAllocator, PeerLedger, PeerLease } from './peers.js';
import type { ProofStore } from './wallet.js';
import type { LockBook } from './locks.js';
import { newOrderId, type Order, type OrderStore } from './orders.js';
import { createRateLimiter, type RateLimiter } from './ratelimit.js';
import { generateClientConfig, planAddPeer, executePlan, cleanupExpiredPeers, validatePublicKey } from './wireguard.js';
import { buildPaymentRequest, verifyPayment, normalizePubkey, type VerifyResult } from './cashu.js';
import { getEncodedToken, type Proof } from '@cashu/cashu-ts';

const MAX_BODY_BYTES = 16 * 1024;
const ORDER_ID_RE = /^[A-Za-z0-9_-]{16,}$/;

// Reported by /info. Read from package.json (repo root, two levels up from
// dist/src) so it never drifts from the published version.
const VERSION = ((): string => {
  try {
    return JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

export interface ServerDeps {
  config: Config;
  allocator: PeerAllocator;
  ledger: PeerLedger;
  proofStore: ProofStore;
  orderStore: OrderStore;
  /** Present in xpub mode: issues per-transaction lock pubkeys. */
  lockBook?: LockBook;
}

// Everything a request handler needs, assembled once in createServer.
interface Ctx extends ServerDeps {
  limiter?: RateLimiter;
  /** Order ids currently being provisioned, to serialize concurrent /pay hits. */
  processing: Set<string>;
}

export function createServer(deps: ServerDeps): http.Server {
  const { config } = deps;

  const limiter = config.rateLimitMax > 0
    ? createRateLimiter({ max: config.rateLimitMax, windowMs: config.rateLimitWindowMs })
    : undefined;

  const ctx: Ctx = { ...deps, limiter, processing: new Set() };

  // Cleanup interval
  let cleanupTimer: NodeJS.Timeout | undefined;
  if (config.cleanupIntervalMs) {
    const intervalMs = config.cleanupIntervalMs;
    cleanupTimer = setInterval(() => {
      cleanupExpiredPeers(deps.ledger, config.wgInterface, config.mode === 'dry-run').catch((e) => {
        console.error('cleanup failed:', e instanceof Error ? e.message : e);
      });
    }, intervalMs);
    cleanupTimer.unref();
  }

  const server = http.createServer((req, res) => {
    void handleRequest(req, res, ctx);
  });

  server.once('close', () => {
    if (cleanupTimer) clearInterval(cleanupTimer);
  });

  return server;
}

async function handleRequest(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  const { config } = ctx;
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;

  try {
    if (req.method === 'GET' && path === '/health') {
      return json(res, 200, { ok: true, mode: config.mode });
    }

    if (req.method === 'GET' && path === '/info') {
      return json(res, 200, {
        version: VERSION,
        mode: config.mode,
        priceSats: config.priceSats,
        unit: config.unit,
        leaseDuration: `${config.leaseDurationMs / 1000}s`,
        acceptedMints: config.acceptedMints,
        lock: ctx.lockBook ? 'xpub-per-tx' : config.operatorPubkey ? 'fixed-pubkey' : 'none',
      });
    }

    if (req.method === 'GET' && path === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'POST' && path === '/purchase') {
      if (ctx.limiter) {
        const { allowed, retryAfterMs } = ctx.limiter.check(clientIp(req));
        if (!allowed) {
          res.writeHead(429, {
            'content-type': 'application/json; charset=utf-8',
            'retry-after': String(Math.ceil(retryAfterMs / 1000)),
          });
          res.end(JSON.stringify({ error: 'rate_limited', retryAfterMs }));
          return;
        }
      }
      return await handlePurchase(req, res, ctx);
    }

    // NUT-18 transport sink: a paying wallet POSTs proofs to /pay/:orderId.
    const payId = matchPath(path, '/pay/');
    if (payId !== undefined) {
      if (req.method === 'OPTIONS') return preflight(res);
      if (req.method === 'POST') return await handlePay(req, res, ctx, payId);
    }

    // Per-order poll: the browser fetches ONLY its own order by capability id.
    const orderId = matchPath(path, '/order/');
    if (orderId !== undefined && req.method === 'GET') {
      return await handleOrderStatus(res, ctx, orderId);
    }

    if (req.method === 'GET' && (path === '/' || path === '/marketplace')) {
      return html(res, 200, renderPage(config));
    }

    if (req.method === 'GET' && path === '/client.js') {
      return await serveClientJs(res);
    }

    json(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error('request error:', e);
    json(res, 500, { error: 'internal_error' });
  }
}

// --- POST /purchase ---

async function handlePurchase(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  const { config } = ctx;
  const body = await readBody(req);

  if (!isObj(body)) {
    return json(res, 400, { error: 'invalid_body', message: 'Request body must be a JSON object' });
  }

  const { clientPublicKey } = body;
  if (typeof clientPublicKey !== 'string' || !clientPublicKey) {
    return json(res, 400, { error: 'missing_client_public_key' });
  }

  // Dry-run skips payment entirely and provisions immediately.
  if (config.mode !== 'live') {
    const bundle = await provisionPeer(ctx, clientPublicKey, undefined, undefined);
    return json(res, 200, { ...bundle, mode: config.mode });
  }

  if (!ctx.lockBook && !config.operatorPubkey) {
    // Misconfiguration: nothing to lock proofs to. Fail loudly, never fall back
    // to custodial behaviour.
    return json(res, 503, { error: 'operator_lock_not_configured' });
  }

  // The key is interpolated into a `wg set` command, so reject anything that
  // isn't a real base64 WireGuard public key before it reaches the host.
  try {
    validatePublicKey(clientPublicKey);
  } catch {
    return json(res, 400, {
      error: 'invalid_client_public_key',
      message: 'clientPublicKey must be a base64 WireGuard public key',
    });
  }

  // NUT-24 same-client path (agents): proofs delivered inline via X-Cashu. Verify
  // and provision in this same response, no order/poll round-trip needed.
  const headerToken = firstHeader(req.headers['x-cashu']);
  if (headerToken) {
    const verified = await verifyAndAuthorize(ctx, headerToken);
    if ('error' in verified) {
      return json(res, 402, { error: 'payment_failed', detail: verified.error });
    }
    const bundle = await provisionPeer(ctx, clientPublicKey, verified.payment, verified.lockIndex);
    return json(res, 200, { ...bundle, mode: config.mode });
  }

  // Otherwise create an order and answer with a 402 + PaymentRequest. The creqA
  // carries a NUT-18 POST transport to /pay/:orderId, so a wallet pays and
  // delivers automatically; the browser polls GET /order/:orderId.
  const lock = ctx.lockBook ? await ctx.lockBook.issue() : undefined;
  const lockPubkey = lock ? lock.pubkey : config.operatorPubkey;
  const orderId = newOrderId();
  const now = new Date();
  const order: Order = {
    id: orderId,
    status: 'pending',
    clientPublicKey,
    lockPubkey,
    lockIndex: lock?.index,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.orderTtlMs).toISOString(),
  };
  await ctx.orderStore.create(order);

  const creq = buildPaymentRequest({
    paymentId: orderId,
    amountSats: config.priceSats,
    mints: config.acceptedMints,
    lockPubkey,
    unit: config.unit,
    description: 'cashu-vpn access',
    transportTarget: `${baseUrl(req, config)}/pay/${orderId}`,
  });

  res.writeHead(402, { 'content-type': 'application/json; charset=utf-8', 'x-cashu': creq });
  res.end(JSON.stringify({
    error: 'payment_required',
    orderId,
    creq,
    quotedSats: config.priceSats,
    unit: config.unit,
    acceptedMints: config.acceptedMints,
    hint: 'Pay the request; a NUT-18 wallet delivers automatically, then poll GET /order/:orderId.',
  }));
}

// --- POST /pay/:orderId (NUT-18 transport sink) ---

async function handlePay(req: IncomingMessage, res: ServerResponse, ctx: Ctx, orderId: string): Promise<void> {
  cors(res);
  const tag = orderId.slice(0, 8);
  console.log(`[pay] hit order=${tag} origin=${firstHeader(req.headers.origin) || '-'} ct=${firstHeader(req.headers['content-type']) || '-'}`);

  if (!ORDER_ID_RE.test(orderId)) {
    return json(res, 404, { error: 'order_not_found' });
  }

  const order = await ctx.orderStore.get(orderId);
  if (!order) {
    return json(res, 404, { error: 'order_not_found' });
  }
  if (order.status === 'ready') {
    // Idempotent: the order was already paid and provisioned.
    return json(res, 200, { ok: true, status: 'ready' });
  }

  const body = await readBody(req);
  console.log(`[pay] order=${tag} payload=${describePayload(body)}`);
  let encodedToken: string;
  try {
    encodedToken = encodeFromPayload(body);
  } catch {
    console.log(`[pay] order=${tag} rejected: invalid_payload`);
    return json(res, 400, { error: 'invalid_payload', message: 'Expected a NUT-18 payload {mint,unit,proofs} or {token}' });
  }

  // Serialize concurrent deliveries for the same order so we never double-provision.
  if (ctx.processing.has(orderId)) {
    return json(res, 409, { error: 'order_in_progress' });
  }
  ctx.processing.add(orderId);
  try {
    // Re-check after acquiring the guard (a racing request may have finished).
    const fresh = await ctx.orderStore.get(orderId);
    if (!fresh) return json(res, 404, { error: 'order_not_found' });
    if (fresh.status === 'ready') return json(res, 200, { ok: true, status: 'ready' });

    const verified = await verifyAndAuthorize(ctx, encodedToken);
    if ('error' in verified) {
      console.log(`[pay] order=${tag} rejected: ${verified.error}`);
      return json(res, 402, { error: 'payment_failed', detail: verified.error });
    }

    // Bind the payment to THIS order's challenge: the proofs must be locked to the
    // exact pubkey we issued for it, not merely some key we control.
    if (verified.payment.lockPubkey !== normalizePubkey(fresh.lockPubkey)) {
      console.log(`[pay] order=${tag} rejected: lock_mismatch`);
      return json(res, 402, { error: 'payment_failed', detail: 'lock_mismatch' });
    }

    const bundle = await provisionPeer(ctx, fresh.clientPublicKey, verified.payment, fresh.lockIndex);
    await ctx.orderStore.markReady(orderId, bundle);
    console.log(`[pay] order=${tag} ready: ${verified.payment.amountSats} sat`);
    return json(res, 200, { ok: true, status: 'ready' });
  } finally {
    ctx.processing.delete(orderId);
  }
}

// --- GET /order/:orderId (browser poll) ---

async function handleOrderStatus(res: ServerResponse, ctx: Ctx, orderId: string): Promise<void> {
  if (!ORDER_ID_RE.test(orderId)) {
    return json(res, 404, { error: 'order_not_found' });
  }
  const order = await ctx.orderStore.get(orderId);
  if (!order) {
    return json(res, 404, { error: 'order_not_found' });
  }
  if (order.status === 'ready') {
    return json(res, 200, {
      status: 'ready',
      mode: ctx.config.mode,
      purchaseId: order.purchaseId,
      tunnelIp: order.tunnelIp,
      amountSats: order.amountSats,
      clientConfig: order.clientConfig,
      lease: order.lease,
    });
  }
  return json(res, 200, { status: 'pending', mode: ctx.config.mode });
}

// --- Payment verification + lock authorization ---

interface Authorized { payment: VerifyResult; lockIndex?: number; }

/**
 * Verify a delivered token offline (DLEQ + P2PK + amount + proof cap + replay)
 * and authorize its lock against a key the operator controls. Returns the
 * verified payment plus the xpub child index to record for sweeping, or `{error}`.
 */
async function verifyAndAuthorize(ctx: Ctx, encodedToken: string): Promise<Authorized | { error: string }> {
  const { config } = ctx;
  const payment = await verifyPayment(encodedToken, {
    acceptedMints: config.acceptedMints,
    requiredSats: config.priceSats,
    unit: config.unit,
    proofCountMargin: config.proofCountMargin,
  });
  if (!payment.valid || !payment.lockPubkey) {
    return { error: payment.error ?? 'unverified' };
  }

  // The lock must be a pubkey WE control, or the operator can't sweep it.
  let lockIndex: number | undefined;
  if (ctx.lockBook) {
    lockIndex = ctx.lockBook.resolve(payment.lockPubkey);
    if (lockIndex === undefined) return { error: 'lock_not_recognized' };
  } else if (payment.lockPubkey !== normalizePubkey(config.operatorPubkey)) {
    return { error: 'not_locked_to_operator' };
  }

  // Reject replays of an already-redeemed token.
  if (payment.secrets && (await ctx.proofStore.hasAnyOf(payment.secrets))) {
    return { error: 'already_redeemed' };
  }

  return { payment, lockIndex };
}

// --- Provisioning (shared by every delivery path) ---

interface ProvisionBundle {
  purchaseId: string;
  tunnelIp: string;
  amountSats?: number;
  lease: PeerLease;
  clientConfig: string;
}

async function provisionPeer(
  ctx: Ctx,
  clientPublicKey: string,
  payment: VerifyResult | undefined,
  lockIndex: number | undefined,
): Promise<ProvisionBundle> {
  const { config, allocator, ledger, proofStore } = ctx;

  const purchaseId = newPurchaseId();
  const tunnelIp = allocator.allocateTunnelIp(purchaseId, clientPublicKey);

  if (config.mode === 'live') {
    await executePlan(planAddPeer(config.wgInterface, clientPublicKey, tunnelIp));
  }

  const now = new Date();
  const lease: PeerLease = {
    purchaseId,
    clientPublicKey,
    tunnelIp,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.leaseDurationMs).toISOString(),
    status: 'active',
  };
  await ledger.record(lease);

  // Persist the operator-locked token so the operator can sweep it offline.
  // Not spendable from the box, only the operator's offline key can claim it.
  if (payment?.valid && payment.token && payment.mint) {
    await proofStore.add({
      purchaseId,
      mint: payment.mint,
      amountSats: payment.amountSats,
      token: payment.token,
      secrets: payment.secrets ?? [],
      lockPubkey: payment.lockPubkey ?? '',
      index: lockIndex,
      receivedAt: now.toISOString(),
    });
  }

  const clientConfig = generateClientConfig({
    tunnelIp,
    serverPublicKey: config.serverPublicKey,
    endpoint: config.endpoint,
    purchaseId,
    dryRun: config.mode === 'dry-run',
  });

  return { purchaseId, tunnelIp, amountSats: payment?.amountSats, lease, clientConfig };
}

function newPurchaseId(): string {
  return `p-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// --- NUT-18 payload handling ---

/** One-line summary of a /pay body for diagnostics (no secrets logged). */
function describePayload(body: unknown): string {
  if (!isObj(body)) return typeof body;
  const keys = Object.keys(body).join(',');
  if (Array.isArray(body.proofs)) {
    const proofs = body.proofs as Array<Record<string, unknown>>;
    const withDleq = proofs.filter((p) => isObj(p) && p.dleq != null).length;
    return `keys=[${keys}] mint=${typeof body.mint === 'string' ? body.mint : '?'} proofs=${proofs.length} dleq=${withDleq}/${proofs.length}`;
  }
  return `keys=[${keys}] token=${typeof body.token === 'string'}`;
}

/** Reconstruct an encoded cashu token from a /pay body: NUT-18 payload or {token}. */
function encodeFromPayload(body: unknown): string {
  if (!isObj(body)) throw new Error('not an object');
  if (typeof body.token === 'string' && body.token) return body.token;

  const { mint, proofs } = body;
  const unit = typeof body.unit === 'string' ? body.unit : 'sat';
  if (typeof mint !== 'string' || !mint || !Array.isArray(proofs) || proofs.length === 0) {
    throw new Error('missing mint/proofs');
  }
  return getEncodedToken({ mint, proofs: proofs as Proof[], unit });
}

// --- HTTP helpers ---

function matchPath(path: string, prefix: string): string | undefined {
  if (!path.startsWith(prefix)) return undefined;
  const rest = path.slice(prefix.length);
  // Single path segment only (no nested slashes).
  if (rest === '' || rest.includes('/')) return undefined;
  return decodeURIComponent(rest);
}

function firstHeader(value: string | string[] | undefined): string {
  const v = Array.isArray(value) ? value[0] : value;
  return (v ?? '').trim();
}

// External base URL for the NUT-18 transport target: explicit config, else the
// forwarded proto/host (Caddy sets these in front of the daemon).
function baseUrl(req: IncomingMessage, config: Config): string {
  if (config.publicBaseUrl) return config.publicBaseUrl;
  const proto = firstHeader(req.headers['x-forwarded-proto']).split(',')[0]!.trim() || 'https';
  const host = firstHeader(req.headers['x-forwarded-host']) || firstHeader(req.headers.host);
  return `${proto}://${host}`;
}

// Real client IP: first X-Forwarded-For hop (set by Caddy) else the socket peer.
function clientIp(req: IncomingMessage): string {
  const xff = firstHeader(req.headers['x-forwarded-for']);
  if (xff) return xff.split(',')[0]!.trim();
  return req.socket.remoteAddress ?? 'unknown';
}

function cors(res: ServerResponse): void {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'POST, OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type');
}

function preflight(res: ServerResponse): void {
  cors(res);
  res.writeHead(204);
  res.end();
}

// --- Body parsing ---

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let bytes = 0;

  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buf.byteLength;
    if (bytes > MAX_BODY_BYTES) {
      throw Object.assign(new Error('body too large'), { statusCode: 413 });
    }
    chunks.push(buf);
  }

  if (chunks.length === 0) return undefined;

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('invalid JSON'), { statusCode: 400 });
  }
}

// --- Helpers ---

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function html(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(body);
}

// The esbuild-bundled browser client (dist/public/client.js), cached after first read.
const CLIENT_JS_PATH = fileURLToPath(new URL('../public/client.js', import.meta.url));
let clientJsCache: string | undefined;

async function serveClientJs(res: ServerResponse): Promise<void> {
  try {
    if (clientJsCache === undefined) clientJsCache = await readFile(CLIENT_JS_PATH, 'utf8');
    res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8' });
    res.end(clientJsCache);
  } catch {
    json(res, 404, { error: 'client_bundle_not_built', message: 'run `npm run build:client`' });
  }
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// --- Marketplace page ---

function renderPage(config: Config): string {
  const price = `${config.priceSats} sats / ${config.leaseDurationMs / 3600000}h`;
  const isDryRun = config.mode === 'dry-run';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cashu VPN</title>
  <style>
    :root { color-scheme: dark; --bg: #0b0f14; --panel: #121821; --line: #273241; --text: #eef4fb; --muted: #93a4b7; --accent: #38bdf8; --good: #41d695; --warn: #f4c95d; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); }
    main { max-width: 720px; margin: 0 auto; padding: 32px 16px; }
    h1 { margin: 0 0 4px; font-size: 1.8rem; }
    h2 { margin: 24px 0 12px; font-size: 1.1rem; }
    p, label { color: var(--muted); margin: 0; }
    pre { background: #080b10; border: 1px solid var(--line); border-radius: 8px; color: #dcecff; padding: 14px; overflow-x: auto; white-space: pre-wrap; margin: 0; }
    .pill { border: 1px solid rgba(65,214,149,.35); border-radius: 999px; color: var(--good); padding: 6px 10px; font-size: .85rem; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-top: 12px; }
    .facts { display: grid; grid-template-columns: repeat(3,1fr); gap: 10px; margin: 12px 0; }
    .fact { background: #17202b; border: 1px solid var(--line); border-radius: 8px; padding: 10px; }
    .fact span { color: var(--muted); font-size: .75rem; display: block; margin-bottom: 2px; }
    button { background: var(--accent); border: 0; border-radius: 8px; color: #03121f; cursor: pointer; font: inherit; font-weight: 700; padding: 12px 16px; }
    button:disabled { opacity: .5; cursor: wait; }
    .row { display: flex; gap: 10px; align-items: center; }
    .msg { min-height: 1.4em; margin-top: 8px; }
    .msg.ok { color: var(--good); }
    .msg.err { color: var(--warn); }
    .hdr { display: flex; justify-content: space-between; align-items: flex-start; }
    .access { margin-top: 8px; }
    .acc { background: #17202b; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; margin-top: 6px; font-size: .9rem; display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .acc small { color: var(--muted); }
    .empty { color: var(--muted); border: 1px dashed var(--line); border-radius: 8px; padding: 12px; margin-top: 8px; }
    h3 { font-size: 1rem; margin: 18px 0 4px; color: var(--text); }
    .ghost { background: transparent; border: 1px solid var(--line); color: var(--text); }
    .qr { margin-top: 10px; }
    .qr img { background: #fff; padding: 8px; border-radius: 8px; display: block; width: 240px; max-width: 100%; height: auto; image-rendering: pixelated; }
    a { color: var(--accent); }
    code { background: #080b10; border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; font-size: .85em; }
    .acc small.expired { color: var(--warn); }
    @media (max-width: 600px) { .facts { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <div class="hdr">
    <div><h1>Cashu VPN</h1><p>${esc(price)}</p></div>
    <span class="pill">${isDryRun ? 'Dry-run' : 'Live'}</span>
  </div>

  <div class="facts">
    <div class="fact"><span>Price</span><strong>${esc(price)}</strong></div>
    <div class="fact"><span>Payment</span><strong>Cashu ecash</strong></div>
    <div class="fact"><span>Protocol</span><strong>WireGuard</strong></div>
  </div>

  <div class="panel">
    <h2>Get connected</h2>
    ${isDryRun
      ? '<p>Dry-run mode: no payment required, no real WireGuard peer created. A keypair is still generated in your browser.</p>'
      : '<p>Pay privately in Bitcoin using Cashu ecash. Your WireGuard keypair is generated in your browser. The private key never leaves this page.</p>'}
    <div class="row" style="margin-top:10px">
      <button id="buy" type="button">Get VPN config</button>
      <button type="button" id="dl" disabled class="ghost">Download .conf</button>
    </div>
    <p class="msg" id="msg"></p>
  </div>

  <div class="panel" id="pay" style="display:none">
    <h2>Pay <span id="payamt">${esc(price)}</span></h2>

    <h3>⚡ Pay with Lightning</h3>
    <p>No Cashu wallet needed! Pay a Lightning invoice and we mint the ecash in your browser and deliver it. Payments in sats using Cashu ecash for privacy.</p>
    <div class="row" style="margin-top:10px"><button id="lnbtn" type="button">Generate Lightning invoice</button></div>
    <div id="qrln" class="qr"></div>
    <pre id="lninvoice"></pre>
    <button type="button" id="copyln" class="ghost">Copy invoice</button>

    <h3>Or pay with a Cashu wallet</h3>
    <p>Scan or copy this payment request with a NUT-18 wallet that supports P2PK Locked tokens (NUT-11). It pays and delivers the ecash automatically, and this page updates itself.</p>
    <div id="qrcreq" class="qr"></div>
    <pre id="creq"></pre>
    <button type="button" id="copyreq" class="ghost">Copy request</button>
  </div>

  <div class="panel">
    <h2>WireGuard config</h2>
    <pre id="cfg">Purchase a lease to generate a config.</pre>
    <div id="cfghelp" style="display:none">
      <p style="margin-top:12px">To connect, install the free <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener">WireGuard app</a> (macOS, Windows, Linux, iOS, Android — it is not built into your OS VPN settings). Open it, choose <strong>Import tunnel from file</strong>, and pick the <code>.conf</code> you downloaded — then activate it.</p>
      <p style="margin-top:8px">On a phone, scan this in the WireGuard app instead:</p>
      <div id="qrcfg" class="qr"></div>
      <p style="margin-top:10px">If a tunnel ever stops passing traffic — for example once its lease expires — switch it off in the WireGuard app to restore your connection.</p>
    </div>
  </div>

  <div class="panel">
    <h2>Your access</h2>
    <div id="access"><div class="empty">No access yet.</div></div>
  </div>
</main>
<script src="/client.js"></script>
</body></html>`;
}
