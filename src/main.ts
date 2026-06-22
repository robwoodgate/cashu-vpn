import { loadConfig } from './config.js';
import { createAllocator, createMemoryLedger, createFileLedger } from './peers.js';
import { createMemoryProofStore, createFileProofStore } from './wallet.js';
import { createMemoryOrderStore, createFileOrderStore } from './orders.js';
import { createLockBook, type LockBook } from './locks.js';
import { createServer } from './server.js';

const config = loadConfig();

// Fail fast rather than sell a dead config: live mode hands the buyer a .conf
// built from these, and a blank PublicKey/Endpoint connects to nothing.
if (config.mode === 'live' && (!config.serverPublicKey || !config.endpoint)) {
  throw new Error('live mode requires SERVER_PUBLIC_KEY and WG_ENDPOINT (run `npm run discover`)');
}

const allocator = createAllocator();
const ledger = config.peerLedgerPath
  ? createFileLedger(config.peerLedgerPath)
  : createMemoryLedger();
const proofStore = config.proofStorePath
  ? createFileProofStore(config.proofStorePath)
  : createMemoryProofStore();
const orderStore = config.orderStorePath
  ? await createFileOrderStore(config.orderStorePath)
  : createMemoryOrderStore();

// xpub mode: issue a fresh per-transaction lock pubkey from the operator xpub so
// the mint can't correlate payments. Without an xpub we fall back to the fixed
// operator pubkey.
let lockBook: LockBook | undefined;
if (config.operatorXpub) {
  lockBook = await createLockBook(config.operatorXpub, config.lockCounterPath);
}

const server = createServer({ config, allocator, ledger, proofStore, orderStore, lockBook });

server.listen(config.port, config.host, () => {
  console.log(`cashu-vpn listening on http://${config.host}:${config.port} (${config.mode})`);
});
