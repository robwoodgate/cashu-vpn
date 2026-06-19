import { loadConfig } from './config.js';
import { createAllocator, createMemoryLedger, createFileLedger } from './peers.js';
import { createMemoryProofStore, createFileProofStore } from './wallet.js';
import { createServer } from './server.js';

const config = loadConfig();
const allocator = createAllocator();
const ledger = config.peerLedgerPath
  ? createFileLedger(config.peerLedgerPath)
  : createMemoryLedger();
const proofStore = config.proofStorePath
  ? createFileProofStore(config.proofStorePath)
  : createMemoryProofStore();

const server = createServer({ config, allocator, ledger, proofStore });

server.listen(config.port, config.host, () => {
  console.log(`cashu-vpn listening on http://${config.host}:${config.port} (${config.mode})`);
});
