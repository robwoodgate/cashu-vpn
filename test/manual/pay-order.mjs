// Buyer/agent test client: get the 402 (order id + creqA with a NUT-18 POST
// transport), mint ecash at the test mint, pay the request with cashu-ts's own
// sendToRequest (it picks the lock for the keyset and covers input fees), then
// POST the NUT-18 payload to /pay/:orderId. The .conf comes back in the /pay response (the agent path);
// this script also polls /order/:orderId, the way the browser does.
import { Wallet, decodePaymentRequest } from '@cashu/cashu-ts';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

const DAEMON = process.env.DAEMON || 'http://127.0.0.1:3087';
const log = (o) => console.log(JSON.stringify(o));
const b64 = (s) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); return t + '='.repeat((4 - (t.length % 4)) % 4); };

function genWgKey() {
  const { publicKey } = generateKeyPairSync('x25519');
  return b64(publicKey.export({ format: 'jwk' }).x);
}
const clientPub = genWgKey();
const secret = randomBytes(24).toString('base64url');

// 1) Unpaid request -> 402 + orderId + creqA (with transport)
const r1 = await fetch(`${DAEMON}/purchase`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ clientPublicKey: clientPub, secret }),
});
if (r1.status !== 402) throw new Error(`expected 402, got ${r1.status}: ${await r1.text()}`);
const { orderId } = await r1.json();
const pr = decodePaymentRequest(r1.headers.get('x-cashu'));
const amount = pr.amount.toNumber();
const mintUrl = pr.mints[0];
log({ step: '402', orderId, amount, transport: pr.transport?.[0]?.target });

// 2) Mint ecash at the mint named in the request, with headroom for the input fees
const wallet = new Wallet(mintUrl, { unit: 'sat' });
await wallet.loadMint();
const funding = amount + 16;
const { pubkey: quotePub, privkey: quoteKey } = await wallet.createQuoteLockKey();
let quote = await wallet.createMintQuoteBolt11(funding, quotePub);
log({ step: 'quote', quote: quote.quote, state: quote.state });
let state = quote.state;
for (let i = 0; i < 30 && state !== 'PAID'; i++) {
  await new Promise((r) => setTimeout(r, 1000));
  quote = await wallet.checkMintQuoteBolt11(quote.quote);
  state = quote.state;
}
if (state !== 'PAID') throw new Error(`mint quote not PAID (state=${state}); if a real mint, pay: ${quote.request}`);

const minted = await wallet.ops.mintBolt11(funding, quote).privkey(quoteKey).run();
const { send: proofs } = await wallet.ops.sendToRequest(pr, minted).run();
log({ step: 'locked', keyset: wallet.getKeyset().id.slice(0, 8), proofs: proofs.length, spendInfo: proofs.every((p) => p.spend_info != null) });

// 3) Deliver the NUT-18 payload to the order's transport sink. The .conf comes
//    back here directly — an agent can stop at this step.
const r2 = await fetch(`${DAEMON}/pay/${orderId}`, {
  method: 'POST', headers: { 'content-type': 'application/json', 'x-order-secret': secret },
  body: JSON.stringify({ id: orderId, mint: mintUrl, unit: 'sat', proofs }),
});
const payBody = await r2.json();
log({ step: 'pay', status: r2.status, tunnelIp: payBody.tunnelIp, hasConfig: !!payBody.clientConfig });
if (r2.status !== 200) process.exit(1);

// 4) Poll the order until ready (the browser path — it isn't the one POSTing above)
for (let i = 0; i < 15; i++) {
  const r = await fetch(`${DAEMON}/order/${orderId}`, { headers: { 'x-order-secret': secret } });
  const d = await r.json();
  if (d.status === 'ready') {
    log({ step: 'ready', tunnelIp: d.tunnelIp, amountSats: d.amountSats, hasConfig: !!d.clientConfig });
    process.exit(0);
  }
  await new Promise((r) => setTimeout(r, 1000));
}
throw new Error('order never became ready');
