#!/usr/bin/env bash
# Install cashu-vpn as a systemd service behind the existing Caddy TLS.
# Minibits mint, 1500 sats / 1-day lease (~$1/day). Flex PRICE_SATS /
# LEASE_DURATION_MS in cashu-vpn.env then `systemctl restart cashu-vpn`.
set -e
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd /root/cashu-vpn
NODEBIN="$(nvm which 20)"
XPUB=$(node -e "console.log(require('./state/test-key.json').xpub)")
mkdir -p state
rm -f state/proofs.json state/peers.json state/locks.json state/orders.json

cat > /root/cashu-vpn/cashu-vpn.env <<EOF
MODE=live
WG_INTERFACE=wg0
SERVER_PUBLIC_KEY=nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=
WG_ENDPOINT=157.180.114.119:51820
OPERATOR_XPUB=$XPUB
ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin
PRICE_SATS=1500
PUBLIC_BASE_URL=https://vpn-157-180-114-119.nip.io
MINT_UNIT=sat
LEASE_DURATION_MS=86400000
CLEANUP_INTERVAL_MS=60000
RATE_LIMIT_MAX=20
RATE_LIMIT_WINDOW_MS=60000
HOST=127.0.0.1
PORT=3087
PROOFS_PATH=/root/cashu-vpn/state/proofs.json
PEER_LEDGER_PATH=/root/cashu-vpn/state/peers.json
ORDERS_PATH=/root/cashu-vpn/state/orders.json
LOCK_COUNTER_PATH=/root/cashu-vpn/state/locks.json
EOF

cat > /etc/systemd/system/cashu-vpn.service <<EOF
[Unit]
Description=cashu-vpn daemon
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/root/cashu-vpn
EnvironmentFile=/root/cashu-vpn/cashu-vpn.env
ExecStart=$NODEBIN /root/cashu-vpn/dist/src/main.js
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

pkill -f dist/src/main.js 2>/dev/null || true
systemctl daemon-reload
systemctl enable cashu-vpn >/dev/null 2>&1 || true
systemctl restart cashu-vpn
sleep 2
echo "active: $(systemctl is-active cashu-vpn)"
echo "health: $(curl -s localhost:3087/health)"
echo "info:   $(curl -s localhost:3087/info)"
