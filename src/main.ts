import { loadConfig } from './config.js';
import { createAllocator } from './peers.js';
import { createMemoryProofStore, createFileProofStore } from './wallet.js';
import { createMemoryStateStore, createFileStateStore } from './state.js';
import { createLockBook, type LockBook } from './locks.js';
import { reconcileActivePeers } from './wireguard.js';
import { createServer } from './server.js';

const config = loadConfig();

// Fail fast rather than sell a dead config: live mode hands the buyer a .conf
// built from these, and a blank PublicKey/Endpoint connects to nothing.
if (config.mode === 'live' && (!config.serverPublicKey || !config.endpoint)) {
  throw new Error('live mode requires SERVER_PUBLIC_KEY and WG_ENDPOINT (run `npm run discover`)');
}

// Live mode locks every payment to a fresh per-transaction xpub child (privacy +
// single-use replay protection). There is no fixed-pubkey fallback.
if (config.mode === 'live' && !config.operatorXpub) {
  throw new Error('live mode requires OPERATOR_XPUB (run `npm run keygen`)');
}

// The lock counter MUST be durable in live mode. Replay protection is the
// order<->lock binding, which only holds if each lock pubkey is issued once,
// ever. An in-memory counter resets to 0 on restart and reissues child 0, 1, …
// — so an old (even already-swept) token for child 0 would satisfy the first new
// order after every restart. Require persistence so lock pubkeys never repeat.
if (config.mode === 'live' && !config.lockCounterPath) {
  throw new Error('live mode requires LOCK_COUNTER_PATH (durable lock counter prevents payment replay across restarts)');
}

// Orders+proofs MUST be durable in live mode. A memory store loses unswept
// receipts (operator can't get paid) and the lease ledger on restart — leaving
// live WireGuard peers with no record, so cleanup/reconcile no longer owns them.
if (config.mode === 'live' && (!config.orderStorePath || !config.proofStorePath)) {
  throw new Error('live mode requires ORDERS_PATH and PROOFS_PATH (durable order+proof stores; a restart must not strand receipts or orphan peers)');
}

const allocator = createAllocator();
const proofStore = config.proofStorePath
  ? createFileProofStore(config.proofStorePath)
  : createMemoryProofStore();
// One store holds orders AND their leases (a lease is the provisioned half of an
// order), so the two commit atomically. ORDERS_PATH is its file; PEER_LEDGER_PATH
// is no longer used.
const store = config.orderStorePath
  ? await createFileStateStore(config.orderStorePath)
  : createMemoryStateStore();

// Issue a fresh per-transaction lock pubkey from the operator xpub so
// the mint can't correlate payments.
let lockBook: LockBook | undefined;
if (config.operatorXpub) {
  lockBook = await createLockBook(config.operatorXpub, config.lockCounterPath);
}

// A restart brings wg0 up from wg0.conf, which has none of the runtime peers
// (they're added live via `wg set`). Re-apply active leases before serving so
// already-paid buyers aren't silently dropped while their orders read ready.
if (config.mode === 'live') {
  const { restored, failed } = await reconcileActivePeers(store, config.wgInterface);
  if (restored || failed) console.log(`restored ${restored} active peer(s)${failed ? `, ${failed} failed` : ''}`);
}

const server = createServer({ config, allocator, store, proofStore, lockBook });

server.listen(config.port, config.host, () => {
  console.log(`cashu-vpn listening on http://${config.host}:${config.port} (${config.mode})`);
});
