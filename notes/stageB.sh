#!/usr/bin/env bash
# Stage B+C live validation at testnut (free): full paid loop + sweep + cleanup.
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd /root/cashu-vpn

XPUB=$(node -e "console.log(require('./state/test-key.json').xpub)")
XPRV=$(node -e "console.log(require('./state/test-key.json').xprv)")
WGKEY="nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU="
rm -f state/proofs.json state/locks.json state/peers.json

MODE=live WG_INTERFACE=wg0 SERVER_PUBLIC_KEY="$WGKEY" WG_ENDPOINT=157.180.114.119:51820 \
  OPERATOR_XPUB="$XPUB" LOCK_COUNTER_PATH=state/locks.json PROOFS_PATH=state/proofs.json PEER_LEDGER_PATH=state/peers.json \
  ACCEPTED_MINTS=https://testnut.cashudevkit.org PRICE_SATS=5 PORT=3087 HOST=127.0.0.1 \
  node dist/src/main.js > state/daemon.log 2>&1 &
PID=$!
sleep 1.5

echo "=== TEST CLIENT (mint P2PK-locked @ testnut -> pay daemon) ==="
node testclient.mjs; TC=$?
echo "testclient exit: $TC"

echo "=== wg0 marketplace peer (expect one 10.77.0.x) ==="
wg show wg0 allowed-ips | grep '10.77.0' || echo "(none)"

if [ -f state/proofs.json ]; then
  echo "=== stored receipt ==="
  node -e "console.log(JSON.stringify(require('./state/proofs.json').map(x=>({mint:x.mint,amountSats:x.amountSats,index:x.index,lock:x.lockPubkey.slice(0,12)+'…'})),null,2))"
  echo "=== SWEEP (claim locked proofs with offline xprv) ==="
  OPERATOR_XPRV="$XPRV" PROOFS_PATH=state/proofs.json node dist/src/sweep.js
fi

echo "=== CLEANUP: remove test peer, leave wg0 pristine ==="
if [ -f state/peers.json ]; then
  CP=$(node -e "const r=require('./state/peers.json');console.log(r[r.length-1].clientPublicKey)")
  TIP=$(node -e "const r=require('./state/peers.json');console.log(r[r.length-1].tunnelIp)")
  wg set wg0 peer "$CP" remove 2>/dev/null || true
  ip route del "$TIP"/32 dev wg0 2>/dev/null || true
  echo "removed peer $TIP"
fi
kill $PID 2>/dev/null || true
sleep 0.3
wg show wg0 allowed-ips | grep -q '10.77.0' && echo "WARN: 10.77 peer remains" || echo "OK: no 10.77 peers remain"
echo "=== daemon.log tail ==="; tail -4 state/daemon.log
