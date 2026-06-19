import { loadConfig } from './config.js';
import { createAllocator, createMemoryLedger, createFileLedger } from './peers.js';
import { createServer } from './server.js';

const config = loadConfig();
const allocator = createAllocator();
const ledger = config.peerLedgerPath
  ? createFileLedger(config.peerLedgerPath)
  : createMemoryLedger();

const server = createServer({ config, allocator, ledger });

server.listen(config.port, config.host, () => {
  console.log(`nostr-vpn listening on http://${config.host}:${config.port} (${config.mode})`);
});
