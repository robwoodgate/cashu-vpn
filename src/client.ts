/**
 * Browser client (bundled to dist/public/client.js by esbuild; not type-checked
 * by the node tsconfig). Drives the buyer UX over the shared, tested buyer.ts.
 *
 * Two ways to pay the 402 challenge:
 *  - Lightning (primary): create a mint quote, show the bolt11 + QR, poll, then
 *    mint P2PK-locked proofs in-browser and deliver via X-Cashu. No Cashu wallet.
 *  - Cashu wallet: scan/copy the creqA and pay with a NUT-18 wallet, paste token.
 *
 * The WireGuard keypair is generated here; only the public key leaves the page.
 */

import { Wallet } from '@cashu/cashu-ts';
import qrcode from 'qrcode-generator';
import { decodeChallenge, waitForPaid, mintLockedToken, type MintWallet, type Challenge } from './buyer.js';

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const btn = (id: string) => document.getElementById(id) as HTMLButtonElement;
const b64 = (s: string) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); return t + '='.repeat((4 - (t.length % 4)) % 4); };

let priv = '', pubKey = '', conf = '', pid = '';
let challenge: Challenge | null = null;

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

function renderQR(elId: string, text: string): void {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  $(elId).innerHTML = qr.createImgTag(4, 8);
}

function showConfig(d: Record<string, unknown>): void {
  const lease = d.lease as { expiresAt?: string } | undefined;
  conf = String(d.clientConfig ?? '').replace('# PrivateKey = <generate locally>', 'PrivateKey = ' + priv);
  pid = String(d.purchaseId ?? '');
  $('cfg').textContent = conf + '\n\nLease: ' + String(d.tunnelIp) + (lease?.expiresAt ? ' until ' + new Date(lease.expiresAt).toLocaleString() : '');
  setMsg('Config ready.', 'ok');
  btn('dl').disabled = false;
  $('pay').style.display = 'none';
  void load();
}

async function purchase(token?: string): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token) headers['X-Cashu'] = token;
  return fetch('/purchase', { method: 'POST', headers, body: JSON.stringify({ clientPublicKey: pubKey }) });
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
      const creq = r.headers.get('x-cashu') ?? '';
      challenge = decodeChallenge(creq);
      $('creq').textContent = creq;
      renderQR('qrcreq', creq);
      $('payamt').textContent = challenge.amount + ' ' + challenge.unit;
      $('pay').style.display = '';
      setMsg('Payment required — pay below.');
    } else if (r.ok) {
      showConfig(await r.json());
    } else {
      const d = await r.json();
      setMsg(d.error ?? 'Failed', 'err');
    }
  } catch (e) {
    setMsg(errText(e), 'err');
  }
  btn('buy').disabled = false;
};

// Pay with Lightning: mint P2PK-locked proofs in-browser, then deliver.
btn('lnbtn').onclick = async () => {
  if (!challenge) return;
  btn('lnbtn').disabled = true;
  try {
    setMsg('Connecting to mint…');
    const wallet = new Wallet(challenge.mintUrl, { unit: challenge.unit });
    await wallet.loadMint();
    const w = wallet as unknown as MintWallet;
    const quote = await w.createMintQuoteBolt11(challenge.amount);
    if (quote.request) {
      $('lninvoice').textContent = quote.request;
      renderQR('qrln', quote.request.toUpperCase()); // bolt11 QR is uppercased for density
    }
    setMsg('Waiting for Lightning payment…');
    const paid = await waitForPaid(w, quote.quote, { intervalMs: 2000, tries: 150 });
    if (!paid) { setMsg('Invoice not paid in time.', 'err'); btn('lnbtn').disabled = false; return; }
    setMsg('Minting & delivering…');
    const token = await mintLockedToken(w, challenge, quote);
    const r = await purchase(token);
    if (r.ok) showConfig(await r.json());
    else { const d = await r.json(); setMsg(d.detail ?? d.error ?? 'Failed', 'err'); }
  } catch (e) {
    setMsg(errText(e), 'err');
  }
  btn('lnbtn').disabled = false;
};

// Cashu-wallet fallback: paste the token your wallet produced.
btn('complete').onclick = async () => {
  const token = ($('token') as HTMLTextAreaElement).value.trim();
  if (!token) { setMsg('Paste a token first.', 'err'); return; }
  btn('complete').disabled = true;
  setMsg('Verifying payment…');
  try {
    const r = await purchase(token);
    if (r.ok) showConfig(await r.json());
    else { const d = await r.json(); setMsg(d.detail ?? d.error ?? 'Failed', 'err'); }
  } catch (e) {
    setMsg(errText(e), 'err');
  }
  btn('complete').disabled = false;
};

btn('copyreq').onclick = () => void navigator.clipboard?.writeText($('creq').textContent ?? '');
btn('copyln').onclick = () => void navigator.clipboard?.writeText($('lninvoice').textContent ?? '');

btn('dl').onclick = () => {
  if (!conf) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([conf + '\n'], { type: 'text/plain' }));
  a.download = (pid || 'vpn') + '.conf';
  a.click();
};

const esc = (s: unknown) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

async function load(): Promise<void> {
  try {
    const r = await fetch('/peers');
    const d = await r.json();
    const el = $('leases');
    if (!d.peers?.length) { el.innerHTML = '<div class="empty">No leases.</div>'; return; }
    el.innerHTML = d.peers.slice().reverse().map((p: Record<string, unknown>) =>
      '<div class="lease"><strong>' + esc(p.purchaseId) + '</strong> &middot; ' + esc(p.tunnelIp) +
      ' &middot; <small>' + esc(p.status) + '</small></div>').join('');
  } catch {
    $('leases').innerHTML = '<div class="empty">Could not load.</div>';
  }
}

void load();
