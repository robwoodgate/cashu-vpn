/**
 * Browser client (bundled to dist/public/client.js by esbuild; not type-checked
 * by the node tsconfig). Drives the per-order buyer UX over the shared, tested
 * buyer.ts helpers.
 *
 * Flow: POST /purchase → 402 with a creqA (carrying a NUT-18 POST transport to
 * /pay/:orderId) + an orderId. Two ways the proofs reach the daemon:
 *  - Lightning (primary): mint P2PK-locked proofs in-browser, then POST the
 *    NUT-18 payload to /pay/:orderId. No Cashu wallet.
 *  - Cashu wallet: scan/copy the creqA; the wallet pays and POSTs to the same
 *    transport target automatically.
 * Either way the browser polls GET /order/:orderId until its config is ready.
 *
 * The WireGuard private key is generated here, kept only in this browser
 * (localStorage), and injected into the .conf locally — it never leaves the page.
 */

import { Wallet } from '@cashu/cashu-ts';
import qrcode from 'qrcode-generator';
import { decodeChallenge, waitForPaid, mintLockedPayload, type MintWallet, type Challenge } from './buyer.js';
// Inlined as data-URIs by esbuild (--loader:.svg=dataurl). Centre-overlay marks for
// the Cashu / Lightning QR tabs; the unified (BIP-321) tab shows none.
import cashuIcon from './icons/cashu.svg';
import lnIcon from './icons/lightning.svg';

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const btn = (id: string) => document.getElementById(id) as HTMLButtonElement;
const b64 = (s: string) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); return t + '='.repeat((4 - (t.length % 4)) % 4); };

const LS_KEY = 'cashu-vpn-orders';

interface OrderRec {
  id: string;
  priv: string;
  pub: string;
  status: 'pending' | 'ready';
  creq?: string; // the payment request, kept so a pending order can be resumed after a reload
  conf?: string;
  tunnelIp?: string;
  createdAt?: string;
  expiresAt?: string;
}

// How long "Your access" keeps entries before pruning them on load.
const PENDING_MAX_AGE_MS = 60 * 60 * 1000; // drop unpaid orders after 1h (server TTL is shorter)
const EXPIRED_GRACE_MS = 7 * 24 * 60 * 60 * 1000; // keep expired leases ~7 days so "Buy again" stays handy

// localStorage holds this browser's own orders (and their private keys) so "Your
// access" survives reloads and configs can be re-downloaded.
function loadOrders(): OrderRec[] {
  try { return JSON.parse(localStorage.getItem(LS_KEY) ?? '[]') as OrderRec[]; } catch { return []; }
}
function saveOrders(list: OrderRec[]): void { localStorage.setItem(LS_KEY, JSON.stringify(list)); }
function upsertOrder(rec: Partial<OrderRec> & { id: string }): OrderRec {
  const list = loadOrders();
  const i = list.findIndex((o) => o.id === rec.id);
  const base = i >= 0 ? list[i]! : { status: 'pending' as const, priv: '', pub: '', createdAt: new Date().toISOString() };
  const merged = { ...base, ...rec } as OrderRec;
  if (i >= 0) list[i] = merged; else list.push(merged);
  saveOrders(list);
  return merged;
}

// Drop stale entries on load: unpaid orders past PENDING_MAX_AGE_MS, and expired
// leases past EXPIRED_GRACE_MS. Recently-expired leases are kept so "Buy again"
// stays available.
function pruneOrders(): void {
  const now = Date.now();
  const list = loadOrders();
  const kept = list.filter((o) => {
    if (o.status === 'ready') {
      const exp = o.expiresAt ? new Date(o.expiresAt).getTime() : Infinity;
      return exp + EXPIRED_GRACE_MS > now;
    }
    const created = o.createdAt ? new Date(o.createdAt).getTime() : now;
    return created + PENDING_MAX_AGE_MS > now;
  });
  if (kept.length !== list.length) saveOrders(kept);
}

let priv = '', pubKey = '';
let challenge: Challenge | null = null;
let currentOrderId = '';
const polling = new Set<string>();

async function genKeys(): Promise<void> {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const prv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  pubKey = b64(pub.x as string);
  priv = b64(prv.d as string);
}

function setMsg(text: string, cls = ''): void {
  const m = $('msg');
  m.className = 'msg ' + cls;
  m.textContent = text;
}

async function copyToClipboard(text: string): Promise<boolean> {
  if (!text) return false;
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

// Flash a button's label to confirm a copy, then restore it.
function flashButton(b: HTMLButtonElement): void {
  const prev = b.textContent;
  b.textContent = 'Copied!';
  setTimeout(() => { b.textContent = prev; }, 1200);
}

// Render a QR, and make the whole code click-to-copy. `qrText` is what the QR
// encodes; `copyText` is what gets copied (defaults to the same — they differ for
// the Lightning invoice, whose QR is uppercased for density but copies as-is).
function renderQR(elId: string, qrText: string, copyText: string = qrText, icon?: string): void {
  const qr = qrcode(0, 'M');
  qr.addData(qrText);
  qr.make();
  const el = $(elId);
  el.innerHTML = qr.createImgTag(4, 8);
  el.style.position = 'relative';
  el.style.display = 'inline-block';
  // Small centre logo (~3% of QR area) — well within 'M' error correction.
  if (icon) {
    const ic = document.createElement('img');
    ic.src = icon;
    ic.className = 'qricon';
    el.appendChild(ic);
  }
  el.title = 'Click to copy';
  el.style.cursor = 'pointer';
  el.onclick = async () => {
    const ok = await copyToClipboard(copyText);
    el.querySelectorAll('.qrnote').forEach((n) => n.remove()); // no stacking on repeat clicks
    const note = document.createElement('div');
    note.className = 'qrnote';
    note.textContent = ok ? '✓ Copied!' : 'Copy failed — copy it manually';
    note.style.cssText = 'width:240px;max-width:100%;text-align:center;font-weight:700;font-size:1.05rem;margin-top:8px;color:var(--' + (ok ? 'good' : 'warn') + ')';
    el.appendChild(note);
    setTimeout(() => note.remove(), 1500);
  };
}

function injectPriv(clientConfig: string, privKey: string): string {
  return String(clientConfig ?? '').replace('# PrivateKey = <generate locally>', 'PrivateKey = ' + privKey);
}

// Render a ready config into the main panel + enable its download.
function showConfig(conf: string, name: string, tunnelIp?: string, expiresAt?: string): void {
  $('cfg').textContent = conf + (tunnelIp ? '\n\nLease: ' + tunnelIp + (expiresAt ? ' until ' + new Date(expiresAt).toLocaleString() : '') : '');
  renderQR('qrcfg', conf); // for one-tap import into the WireGuard mobile app
  $('cfghelp').style.display = '';
  setMsg('Config ready.', 'ok');
  const dl = btn('dl');
  dl.disabled = false;
  dl.onclick = () => download(conf, name);
  $('pay').style.display = 'none';
}

function download(conf: string, name: string): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([conf + '\n'], { type: 'text/plain' }));
  a.download = (name || 'vpn') + '.conf';
  a.click();
}

// --- Unified pay panel: Auto (BIP-321) / Lightning / Cashu tabs ---

type PayMode = 'unified' | 'lightning' | 'cashu';
const payQr: Record<PayMode, string> = { unified: '', lightning: '', cashu: '' };
const payCopy: Record<PayMode, string> = { unified: '', lightning: '', cashu: '' };
let payMode: PayMode = 'unified';

const PAY_TIPS: Record<PayMode, string> = {
  unified: 'Scan with any Lightning or Cashu wallet — it uses whichever rail it supports. Keep this page open.',
  lightning: 'Pay this Lightning invoice with any wallet. The ecash is minted here and delivered automatically — keep this page open.',
  cashu: 'Scan or copy with a NUT-18 Cashu wallet that supports P2PK (NUT-11). It pays and delivers automatically.',
};

// Centre-overlay mark per tab. Unified (BIP-321) shows none — dual-protocol, and
// the denser payload wants the error-correction headroom.
const PAY_ICONS: Record<PayMode, string | undefined> = { unified: undefined, lightning: lnIcon, cashu: cashuIcon };

// Render the active tab's QR + copy text (or a placeholder until the quote lands).
function drawTab(mode: PayMode): void {
  payMode = mode;
  document.querySelectorAll('[data-tab]').forEach((b) => {
    const active = (b as HTMLElement).dataset.tab === mode;
    b.classList.toggle('is-active', active);
    b.setAttribute('aria-selected', String(active));
  });
  $('paytip').textContent = PAY_TIPS[mode];
  if (payQr[mode]) {
    renderQR('payqr', payQr[mode], payCopy[mode] || payQr[mode], PAY_ICONS[mode]);
  } else {
    $('payqr').innerHTML = '<div class="empty">Generating invoice…</div>';
  }
}

// Show the pay panel. The Cashu request works immediately; the Auto (BIP-321) and
// Lightning QRs fill in once the in-browser mint quote is ready (armLightning).
// NB: the creq stays as creqA (base64url) — it carries the nut10 P2PK lock our
// verification requires, and creqB (the uppercase-safe form) drops nut10 in
// cashu-ts. So the cashu/unified QRs are byte-mode; only the bolt11 is uppercased.
function openPayPanel(orderId: string, creq: string): void {
  currentOrderId = orderId;
  challenge = decodeChallenge(creq);
  $('payamt').textContent = challenge.amount + ' ' + challenge.unit;
  payQr.unified = ''; payQr.lightning = ''; payQr.cashu = creq;
  payCopy.unified = ''; payCopy.lightning = ''; payCopy.cashu = creq;
  $('pay').style.display = '';
  drawTab('unified');
  void armLightning(orderId, creq);
}

// Browser-side: create a mint quote, build the Auto (BIP-321) + Lightning payloads,
// then wait for the invoice to be paid and mint+deliver the locked proofs. The mint
// call is per-buyer (fanned out across their own IPs), never via our server.
async function armLightning(orderId: string, creq: string): Promise<void> {
  if (!challenge) return;
  try {
    const wallet = new Wallet(challenge.mintUrl, { unit: challenge.unit });
    await wallet.loadMint();
    const w = wallet as unknown as MintWallet;
    const quote = await w.createMintQuoteBolt11(challenge.amount);
    const bolt11 = quote.request ?? '';
    if (currentOrderId !== orderId) return; // a newer order took over while we waited
    // BIP-321 unified URI carries both rails. bolt11 is uppercased (bech32, dense);
    // the creqA can't be (base64url, case-sensitive), so the unified QR is byte-mode.
    const ln = bolt11.toUpperCase();
    const unified = 'bitcoin:?lightning=' + ln + '&creq=' + creq;
    payQr.unified = unified; payCopy.unified = unified;
    // Uppercase scheme + bolt11 → pure QR-alphanumeric (denser). Copy keeps the raw invoice.
    payQr.lightning = 'LIGHTNING:' + ln; payCopy.lightning = bolt11;
    drawTab(payMode); // re-render the current tab now that the payloads exist

    const paid = await waitForPaid(w, quote.quote, { intervalMs: 2000, tries: 150 });
    if (!paid || currentOrderId !== orderId) return;
    setMsg('Minting & delivering…');
    const payload = await mintLockedPayload(w, challenge, quote);
    const r = await fetch('/pay/' + encodeURIComponent(orderId), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: orderId, ...payload }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { setMsg(d.detail ?? d.error ?? 'Delivery failed', 'err'); return; }
    if (d.clientConfig) applyReady(orderId, d); else void poll(orderId); // /pay returns the config
  } catch (e) {
    // Mint/Lightning unreachable — the Cashu tab still works (a wallet pays the creqA).
    if (currentOrderId === orderId) setMsg('Lightning unavailable; use the Cashu tab. (' + errText(e) + ')', 'err');
  }
}

// Reopen a still-pending order after a reload, so it can be paid.
function resumeOrder(id: string): void {
  const rec = loadOrders().find((o) => o.id === id);
  if (!rec?.creq) return;
  try {
    openPayPanel(id, rec.creq);
  } catch (e) {
    setMsg(errText(e), 'err');
    return;
  }
  setMsg('Finish paying for this order below.');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  void poll(id);
}

async function purchase(): Promise<Response> {
  return fetch('/purchase', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ clientPublicKey: pubKey }),
  });
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

btn('buy').onclick = async () => {
  btn('buy').disabled = true;
  try {
    setMsg('Generating keys…');
    await genKeys();
    setMsg('Requesting access…');
    const r = await purchase();
    if (r.status === 402) {
      const d = await r.json();
      const creq = r.headers.get('x-cashu') ?? d.creq ?? '';
      const orderId = String(d.orderId ?? '');
      upsertOrder({ id: orderId, priv, pub: pubKey, status: 'pending', creq });
      openPayPanel(orderId, creq);
      setMsg('Payment required — pay below.');
      renderAccess();
      void poll(orderId);
    } else if (r.ok) {
      // Dry-run: provisioned immediately, no payment.
      const d = await r.json();
      const conf = injectPriv(String(d.clientConfig ?? ''), priv);
      const id = String(d.purchaseId ?? 'dry-run');
      upsertOrder({ id, priv, pub: pubKey, status: 'ready', conf, tunnelIp: d.tunnelIp, expiresAt: d.lease?.expiresAt });
      showConfig(conf, id, d.tunnelIp, d.lease?.expiresAt);
      renderAccess();
    } else {
      const d = await r.json();
      setMsg(d.error ?? 'Failed', 'err');
    }
  } catch (e) {
    setMsg(errText(e), 'err');
  }
  btn('buy').disabled = false;
};

// Tab switching + a single copy button for the active tab.
document.querySelectorAll('[data-tab]').forEach((b) => {
  b.addEventListener('click', () => drawTab((b as HTMLElement).dataset.tab as PayMode));
});
btn('copypay').onclick = async () => { if (await copyToClipboard(payCopy[payMode])) flashButton(btn('copypay')); };

// Apply a ready order's config: store it and, if it's the active order, show it.
// Shared by the in-browser Lightning delivery and the /order poll (cashu-wallet path).
function applyReady(id: string, d: { clientConfig?: string; tunnelIp?: string; lease?: { expiresAt?: string } }): void {
  const rec = loadOrders().find((o) => o.id === id);
  const conf = injectPriv(String(d.clientConfig ?? ''), rec?.priv ?? '');
  upsertOrder({ id, status: 'ready', conf, tunnelIp: d.tunnelIp, expiresAt: d.lease?.expiresAt });
  if (id === currentOrderId) showConfig(conf, id, d.tunnelIp, d.lease?.expiresAt);
  renderAccess();
}

// Poll an order until it is ready (or gone). Many can run at once; dedup by id.
// Catches the cashu-wallet path (a wallet delivers to /pay without this browser).
async function poll(id: string): Promise<void> {
  if (!id || polling.has(id)) return;
  polling.add(id);
  try {
    for (let i = 0; i < 300; i++) {
      let r: Response;
      try { r = await fetch('/order/' + encodeURIComponent(id)); } catch { await sleep(2000); continue; }
      if (r.status === 404) { dropOrder(id); renderAccess(); return; }
      if (r.ok) {
        const d = await r.json();
        if (d.status === 'ready') { applyReady(id, d); return; }
      }
      await sleep(2000);
    }
  } finally {
    polling.delete(id);
  }
}

function sleep(ms: number): Promise<void> { return new Promise((r) => setTimeout(r, ms)); }

function dropOrder(id: string): void {
  saveOrders(loadOrders().filter((o) => o.id !== id));
}

const esc = (s: unknown) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// "Your access": this browser's own orders, from localStorage. A ready lease
// shows its expiry and flips to "expired" once the time passes (the peer is
// removed server-side at that point, so the config stops working).
function renderAccess(): void {
  const list = loadOrders();
  const el = $('access');
  if (!list.length) { el.innerHTML = '<div class="empty">No access yet.</div>'; return; }
  const now = Date.now();
  el.innerHTML = list.slice().reverse().map((o) => {
    const label = o.tunnelIp ? esc(o.tunnelIp) : esc(o.id.slice(0, 10) + '…');
    const when = o.expiresAt ? new Date(o.expiresAt) : null;
    let status: string, action = '';
    if (o.status !== 'ready') {
      status = '<small>waiting for payment…</small>';
      if (o.creq) action = '<button class="payacc" data-id="' + esc(o.id) + '" type="button">Pay</button>';
    } else if (when && when.getTime() <= now) {
      // Expired: the peer is gone server-side, so the old config is dead. Offer a
      // fresh purchase rather than a download that can't connect.
      status = '<small class="expired">expired ' + esc(when.toLocaleString()) + '</small>';
      action = '<button class="buyagain" type="button">Buy again</button>';
    } else {
      status = '<small>active' + (when ? ' until ' + esc(when.toLocaleString()) : '') + '</small>';
      action = '<button class="ghost dlacc" data-id="' + esc(o.id) + '" type="button">Download</button>';
    }
    return '<div class="acc"><span><strong>' + label + '</strong> &middot; ' + status + '</span>' + action + '</div>';
  }).join('');
  el.querySelectorAll('.dlacc').forEach((b) => {
    b.addEventListener('click', () => {
      const id = (b as HTMLElement).dataset.id ?? '';
      const rec = loadOrders().find((o) => o.id === id);
      if (rec?.conf) { showConfig(rec.conf, id, rec.tunnelIp, rec.expiresAt); download(rec.conf, id); }
    });
  });
  // "Pay" reopens a still-pending order so it can be paid after a reload.
  el.querySelectorAll('.payacc').forEach((b) => {
    b.addEventListener('click', () => resumeOrder((b as HTMLElement).dataset.id ?? ''));
  });
  // "Buy again" starts a brand-new purchase (fresh key + lease), not a renewal.
  el.querySelectorAll('.buyagain').forEach((b) => {
    b.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
      btn('buy').click();
    });
  });
}

// On load: prune stale entries, show stored access, resume polling pending orders.
pruneOrders();
renderAccess();
setInterval(renderAccess, 60000); // keep "active → expired" current on a long-open page
for (const o of loadOrders()) {
  if (o.status === 'pending') void poll(o.id);
}
