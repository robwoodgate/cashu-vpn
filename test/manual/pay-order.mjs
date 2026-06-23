// Buyer/agent test client: get the 402 (order id + creqA with a NUT-18 POST
// transport), mint P2PK-locked proofs at the test mint, POST the NUT-18 payload
// to /pay/:orderId. The .conf comes back in the /pay response (the agent path);
// this script also polls /order/:orderId, the way the browser does.
import { Wallet, OutputData, decodePaymentRequest } from '@cashu/cashu-ts';
import { generateKeyPairSync } from 'node:crypto';

const DAEMON = process.env.DAEMON || 'http://127.0.0.1:3087';
const log = (o) => console.log(JSON.stringify(o));
const b64 = (s) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); return t + '='.repeat((4 - (t.length % 4)) % 4); };

function genWgKey() {
  const { publicKey } = generateKeyPairSync('x25519');
  return b64(publicKey.export({ format: 'jwk' }).x);
}
const clientPub = genWgKey();

// 1) Unpaid request -> 402 + orderId + creqA (with transport)
const r1 = await fetch(`${DAEMON}/purchase`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ clientPublicKey: clientPub }),
});
if (r1.status !== 402) throw new Error(`expected 402, got ${r1.status}: ${await r1.text()}`);
const { orderId } = await r1.json();
const pr = decodePaymentRequest(r1.headers.get('x-cashu'));
const amount = pr.amount.toNumber();
const mintUrl = pr.mints[0];
const lockPubkey = pr.nut10.data;
log({ step: '402', orderId, amount, transport: pr.transport?.[0]?.target });

// 2) Mint P2PK-locked proofs at the mint named in the request
const wallet = new Wallet(mintUrl, { unit: 'sat' });
await wallet.loadMint();
const quote = await wallet.createMintQuoteBolt11(amount);
log({ step: 'quote', quote: quote.quote, state: quote.state });
let state = quote.state;
for (let i = 0; i < 30 && state !== 'PAID'; i++) {
  await new Promise((r) => setTimeout(r, 1000));
  state = (await wallet.checkMintQuoteBolt11(quote.quote)).state;
}
if (state !== 'PAID') throw new Error(`mint quote not PAID (state=${state}); if a real mint, pay: ${quote.request}`);

const keyset = wallet.getKeyset();
const outputs = OutputData.createP2PKData({ pubkey: lockPubkey }, amount, keyset);
const proofs = await wallet.ops.mintBolt11(amount, quote).asCustom(outputs).run();
log({ step: 'minted', proofs: proofs.length, hasDleq: proofs.every((p) => p.dleq != null) });

// 3) Deliver the NUT-18 payload to the order's transport sink. The .conf comes
//    back here directly — an agent can stop at this step.
const r2 = await fetch(`${DAEMON}/pay/${orderId}`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ id: orderId, mint: mintUrl, unit: 'sat', proofs }),
});
const payBody = await r2.json();
log({ step: 'pay', status: r2.status, tunnelIp: payBody.tunnelIp, hasConfig: !!payBody.clientConfig });
if (r2.status !== 200) process.exit(1);

// 4) Poll the order until ready (the browser path — it isn't the one POSTing above)
for (let i = 0; i < 15; i++) {
  const r = await fetch(`${DAEMON}/order/${orderId}`);
  const d = await r.json();
  if (d.status === 'ready') {
    log({ step: 'ready', tunnelIp: d.tunnelIp, amountSats: d.amountSats, hasConfig: !!d.clientConfig });
    process.exit(0);
  }
  await new Promise((r) => setTimeout(r, 1000));
}
throw new Error('order never became ready');
