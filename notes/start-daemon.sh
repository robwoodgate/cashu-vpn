#!/usr/bin/env bash
# Start the daemon live (testnut, xpub) on 127.0.0.1:3087, detached, for the
# public TLS browser smoke. Writes PID to state/daemon.pid.
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd /root/cashu-vpn
XPUB=$(node -e "console.log(require('./state/test-key.json').xpub)")
WGKEY="nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU="
pkill -f dist/src/main.js 2>/dev/null; sleep 0.5
rm -f state/proofs.json state/locks.json state/peers.json

MODE=live WG_INTERFACE=wg0 SERVER_PUBLIC_KEY="$WGKEY" WG_ENDPOINT=157.180.114.119:51820 \
  OPERATOR_XPUB="$XPUB" LOCK_COUNTER_PATH=state/locks.json PROOFS_PATH=state/proofs.json PEER_LEDGER_PATH=state/peers.json \
  ACCEPTED_MINTS=https://testnut.cashudevkit.org PRICE_SATS=5 PORT=3087 HOST=127.0.0.1 \
  setsid node dist/src/main.js > state/daemon.log 2>&1 < /dev/null &
echo $! > state/daemon.pid
sleep 1.5
echo "daemon pid $(cat state/daemon.pid)"
echo "local /health:"; curl -s localhost:3087/health; echo
