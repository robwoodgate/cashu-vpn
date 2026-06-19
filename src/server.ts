import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import type { Config } from './config.js';
import type { PeerAllocator, PeerLedger, PeerLease } from './peers.js';
import type { ProofStore } from './wallet.js';
import { generateClientConfig, planAddPeer, executePlan, cleanupExpiredPeers, validatePublicKey } from './wireguard.js';
import { buildPaymentRequest, verifyPayment, type VerifyResult } from './cashu.js';

const MAX_BODY_BYTES = 16 * 1024;

export interface ServerDeps {
  config: Config;
  allocator: PeerAllocator;
  ledger: PeerLedger;
  proofStore: ProofStore;
}

export function createServer(deps: ServerDeps): http.Server {
  const { config, allocator, ledger, proofStore } = deps;

  // Cleanup interval
  let cleanupTimer: NodeJS.Timeout | undefined;
  if (config.cleanupIntervalMs) {
    const intervalMs = config.cleanupIntervalMs;
    cleanupTimer = setInterval(() => {
      cleanupExpiredPeers(ledger, config.wgInterface, config.mode === 'dry-run').catch((e) => {
        console.error('cleanup failed:', e instanceof Error ? e.message : e);
      });
    }, intervalMs);
    cleanupTimer.unref();
  }

  const server = http.createServer((req, res) => {
    void handleRequest(req, res, config, allocator, ledger, proofStore);
  });

  server.once('close', () => {
    if (cleanupTimer) clearInterval(cleanupTimer);
  });

  return server;
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  config: Config,
  allocator: PeerAllocator,
  ledger: PeerLedger,
  proofStore: ProofStore
): Promise<void> {
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;

  try {
    if (req.method === 'GET' && path === '/health') {
      return json(res, 200, { ok: true, mode: config.mode });
    }

    if (req.method === 'GET' && path === '/info') {
      return json(res, 200, {
        version: '0.1.0',
        mode: config.mode,
        priceSats: config.priceSats,
        leaseDuration: `${config.leaseDurationMs / 1000}s`,
        acceptedMints: config.acceptedMints,
      });
    }

    if (req.method === 'POST' && path === '/purchase') {
      return await handlePurchase(req, res, config, allocator, ledger, proofStore);
    }

    if (req.method === 'GET' && path === '/peers') {
      const peers = await ledger.list();
      return json(res, 200, { count: peers.length, peers });
    }

    if (req.method === 'GET' && (path === '/' || path === '/marketplace')) {
      return html(res, 200, renderPage(config));
    }

    json(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error('request error:', e);
    json(res, 500, { error: 'internal_error' });
  }
}

async function handlePurchase(
  req: IncomingMessage,
  res: ServerResponse,
  config: Config,
  allocator: PeerAllocator,
  ledger: PeerLedger,
  proofStore: ProofStore
): Promise<void> {
  const body = await readBody(req);

  if (!isObj(body)) {
    return json(res, 400, { error: 'invalid_body', message: 'Request body must be a JSON object' });
  }

  const { clientPublicKey } = body;

  if (typeof clientPublicKey !== 'string' || !clientPublicKey) {
    return json(res, 400, { error: 'missing_client_public_key' });
  }

  // Live mode runs the NUT-24 (HTTP 402) payment handshake. Dry-run skips it.
  let payment: VerifyResult | undefined;
  if (config.mode === 'live') {
    if (!config.operatorPubkey) {
      // Misconfiguration: we can't lock proofs to the operator. Fail loudly,
      // never fall back to custodial behaviour.
      return json(res, 503, { error: 'operator_pubkey_not_configured' });
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

    // No payment yet → answer with a 402 + PaymentRequest (creqA) in x-cashu.
    // The request demands proofs P2PK-locked to the operator pubkey.
    const token = firstHeader(req.headers['x-cashu']);
    if (!token) {
      const challengeId = newPurchaseId();
      const creq = buildPaymentRequest({
        paymentId: challengeId,
        amountSats: config.priceSats,
        mints: config.acceptedMints,
        operatorPubkey: config.operatorPubkey,
        unit: config.unit,
        description: 'cashu-vpn access',
      });
      res.writeHead(402, { 'content-type': 'application/json; charset=utf-8', 'x-cashu': creq });
      res.end(
        JSON.stringify({
          error: 'payment_required',
          quotedSats: config.priceSats,
          unit: config.unit,
          acceptedMints: config.acceptedMints,
          hint: 'Pay the request, then retry POST /purchase with an X-Cashu header.',
        })
      );
      return;
    }

    // Payment present → verify offline (DLEQ + P2PK-locked-to-operator) before
    // provisioning anything. No swap, no per-sale mint call.
    payment = await verifyPayment(token, {
      acceptedMints: config.acceptedMints,
      requiredSats: config.priceSats,
      operatorPubkey: config.operatorPubkey,
      unit: config.unit,
    });
    if (!payment.valid) {
      return json(res, 402, { error: 'payment_failed', detail: payment.error });
    }

    // Reject replays of an already-redeemed token.
    if (payment.secrets && (await proofStore.hasAnyOf(payment.secrets))) {
      return json(res, 402, { error: 'payment_failed', detail: 'already_redeemed' });
    }
  }

  // Allocate peer
  const purchaseId = newPurchaseId();
  const tunnelIp = allocator.allocateTunnelIp(purchaseId, clientPublicKey);

  // In live mode, actually add the WireGuard peer
  if (config.mode === 'live') {
    const plan = planAddPeer(config.wgInterface, clientPublicKey, tunnelIp);
    await executePlan(plan);
  }

  // Record lease
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
  // Not spendable from the box — only the operator's offline key can claim it.
  if (payment?.valid && payment.token && payment.mint) {
    await proofStore.add({
      purchaseId,
      mint: payment.mint,
      amountSats: payment.amountSats,
      token: payment.token,
      secrets: payment.secrets ?? [],
      receivedAt: now.toISOString(),
    });
  }

  // Generate client config
  const clientConfig = generateClientConfig({
    tunnelIp,
    serverPublicKey: config.serverPublicKey,
    endpoint: config.endpoint,
    purchaseId,
    dryRun: config.mode === 'dry-run',
  });

  json(res, 200, {
    purchaseId,
    tunnelIp,
    mode: config.mode,
    amountSats: payment?.amountSats,
    lease,
    clientConfig,
  });
}

function newPurchaseId(): string {
  return `p-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function firstHeader(value: string | string[] | undefined): string {
  const v = Array.isArray(value) ? value[0] : value;
  return (v ?? '').trim();
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
    textarea, input { background: #080b10; border: 1px solid var(--line); border-radius: 8px; color: var(--text); font: inherit; padding: 10px; width: 100%; resize: vertical; }
    textarea { min-height: 80px; font-family: monospace; font-size: .85rem; }
    button { background: var(--accent); border: 0; border-radius: 8px; color: #03121f; cursor: pointer; font: inherit; font-weight: 700; padding: 12px 16px; }
    button:disabled { opacity: .5; cursor: wait; }
    .row { display: flex; gap: 10px; align-items: center; }
    .msg { min-height: 1.4em; margin-top: 8px; }
    .msg.ok { color: var(--good); }
    .msg.err { color: var(--warn); }
    .hdr { display: flex; justify-content: space-between; align-items: flex-start; }
    .leases { margin-top: 8px; }
    .lease { background: #17202b; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; margin-top: 6px; font-size: .9rem; }
    .lease small { color: var(--muted); }
    .empty { color: var(--muted); border: 1px dashed var(--line); border-radius: 8px; padding: 12px; margin-top: 8px; }
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
    ${isDryRun ? '<p>Dry-run mode: no payment required, no real WireGuard peer created.</p>' : `<label>Paste Cashu token (${esc(String(config.priceSats))} sats minimum)</label>`}
    <form id="f" style="margin-top:10px">
      ${isDryRun ? '' : '<textarea id="token" placeholder="cashuB..." required></textarea>'}
      <div class="row" style="margin-top:10px">
        <button id="buy" type="submit">Get VPN config</button>
        <button type="button" id="dl" disabled style="background:transparent;border:1px solid var(--line);color:var(--text)">Download .conf</button>
      </div>
    </form>
    <p class="msg" id="msg"></p>
  </div>

  <div class="panel">
    <h2>WireGuard config</h2>
    <pre id="cfg">Purchase a lease to generate a config.</pre>
  </div>

  <div class="panel">
    <h2>Active leases</h2>
    <div id="leases"><div class="empty">No leases.</div></div>
  </div>
</main>
<script>
const $ = (s) => document.getElementById(s);
let conf = '', pid = '';

async function load() {
  try {
    const r = await fetch('/peers');
    const d = await r.json();
    if (!d.peers?.length) { $('leases').innerHTML = '<div class="empty">No leases.</div>'; return; }
    $('leases').innerHTML = d.peers.slice().reverse().map(p =>
      '<div class="lease"><strong>'+h(p.purchaseId)+'</strong> &middot; '+h(p.tunnelIp)+' &middot; <small>'+h(p.status)+' &middot; expires '+new Date(p.expiresAt).toLocaleTimeString()+'</small></div>'
    ).join('');
  } catch { $('leases').innerHTML = '<div class="empty">Could not load.</div>'; }
}

$('f').onsubmit = async (e) => {
  e.preventDefault();
  $('buy').disabled = true;
  $('msg').className = 'msg'; $('msg').textContent = 'Creating...';

  const key = 'browser-' + crypto.randomUUID().slice(0,12);
  const body = { clientPublicKey: key };
  ${isDryRun ? '' : "body.cashuToken = $('token').value.trim();"}

  const r = await fetch('/purchase', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body) });
  const d = await r.json();

  if (r.ok) {
    conf = d.clientConfig || '';
    pid = d.purchaseId || '';
    $('cfg').textContent = conf + '\\n\\nLease: ' + d.tunnelIp + ' until ' + new Date(d.lease?.expiresAt).toLocaleString();
    $('msg').className = 'msg ok'; $('msg').textContent = 'Config ready.';
    $('dl').disabled = false;
  } else {
    $('cfg').textContent = JSON.stringify(d, null, 2);
    $('msg').className = 'msg err'; $('msg').textContent = d.error || 'Failed';
  }
  $('buy').disabled = false;
  load();
};

$('dl').onclick = () => {
  if (!conf) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([conf+'\\n'],{type:'text/plain'}));
  a.download = (pid||'vpn') + '.conf';
  a.click();
};

function h(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
load();
</script>
</body></html>`;
}
