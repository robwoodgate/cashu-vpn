#!/usr/bin/env bash
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd /root/cashu-vpn
npm install --no-audit --no-fund >/dev/null 2>&1
npm run build >/dev/null 2>&1 || { echo "BUILD FAILED"; npm run build 2>&1 | tail -20; exit 1; }
echo "bundle bytes (built): $(wc -c < dist/public/client.js)"

PORT=3099 HOST=127.0.0.1 node dist/src/main.js >/tmp/d.log 2>&1 &
PID=$!
sleep 2
echo "=== page references bundle? ==="; curl -s localhost:3099/ | grep -o '<script src="/client.js"></script>'
echo "=== /client.js response ==="; curl -s -D - -o /tmp/c.js localhost:3099/client.js | tr -d '\r' | grep -iE '^HTTP|content-type'
echo "bundle served bytes: $(wc -c < /tmp/c.js)"
echo "=== bundle is our client (X25519 marker count): $(grep -c 'X25519' /tmp/c.js) ==="
kill "$PID" 2>/dev/null
echo "=== daemon.log ==="; tail -2 /tmp/d.log
