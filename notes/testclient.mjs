// Buyer-side test client: get the daemon's 402 challenge, mint P2PK-locked
// proofs (with DLEQ) at the test mint, then pay the daemon and get a .conf.
// Generates its own WireGuard keypair so a real wg0 peer is added.
import { Wallet, OutputData, getEncodedToken, decodePaymentRequest } from '@cashu/cashu-ts';
import { generateKeyPairSync } from 'node:crypto';

const DAEMON = process.env.DAEMON || 'http://127.0.0.1:3087';
const log = (o) => console.log(JSON.stringify(o));
const b64 = (s) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); return t + '='.repeat((4 - (t.length % 4)) % 4); };

function genWgKey() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    pub: b64(publicKey.export({ format: 'jwk' }).x),
    priv: b64(privateKey.export({ format: 'jwk' }).d),
  };
}

const { pub: clientPub } = genWgKey();

// 1) Unpaid request -> 402 + creqA
const r1 = await fetch(`${DAEMON}/purchase`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ clientPublicKey: clientPub }),
});
if (r1.status !== 402) throw new Error(`expected 402, got ${r1.status}: ${await r1.text()}`);
const pr = decodePaymentRequest(r1.headers.get('x-cashu'));
const amount = pr.amount.toNumber();
const mintUrl = pr.mints[0];
const lockPubkey = pr.nut10.data;
log({ step: '402', amount, mintUrl, lockPubkey: lockPubkey.slice(0, 14) + '…' });

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
const token = getEncodedToken({ mint: mintUrl, proofs, unit: 'sat' });
log({ step: 'minted', proofs: proofs.length, hasDleq: proofs.every((p) => p.dleq != null) });

// 3) Pay the daemon with the locked token
const r2 = await fetch(`${DAEMON}/purchase`, {
  method: 'POST', headers: { 'content-type': 'application/json', 'X-Cashu': token },
  body: JSON.stringify({ clientPublicKey: clientPub }),
});
const body = await r2.json();
log({ step: 'paid', status: r2.status, amountSats: body.amountSats, tunnelIp: body.tunnelIp, hasConfig: !!body.clientConfig, detail: body.detail });
if (r2.status !== 200) process.exit(1);
