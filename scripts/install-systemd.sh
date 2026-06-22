#!/usr/bin/env bash
# Install cashu-vpn as a systemd service that reads its config from ./.env.
# If DOMAIN is set in .env and Caddy is installed, it also adds an HTTPS site.
#
# Your xprv is never read or stored by this script — only the xpub from .env.
#
# Usage (from the repo root, as root):
#   cp .env.example .env   # then edit .env
#   sudo scripts/install-systemd.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$REPO/.env"

[ -f "$ENV_FILE" ] || { echo "No $ENV_FILE — copy .env.example to .env and fill it in first."; exit 1; }
[ "$(id -u)" = "0" ] || { echo "Run as root (it writes to /etc/systemd). Try: sudo $0"; exit 1; }

# Locate node: prefer one already on PATH, fall back to nvm's.
if ! NODE_BIN="$(command -v node)"; then
  # shellcheck disable=SC1090
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"; [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" >/dev/null 2>&1 || true
  NODE_BIN="$(command -v node || true)"
fi
[ -n "$NODE_BIN" ] || { echo "node not found on PATH. Install Node.js >= 20 first."; exit 1; }

# Build if it hasn't been built yet.
if [ ! -f "$REPO/dist/src/main.js" ]; then
  echo "Building…"; (cd "$REPO" && npm install --no-audit --no-fund && npm run build)
fi

read_env() { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-; }
PORT="$(read_env PORT)"; PORT="${PORT:-3087}"
DOMAIN="$(read_env DOMAIN)"

echo "Installing systemd service…"
cat > /etc/systemd/system/cashu-vpn.service <<EOF
[Unit]
Description=cashu-vpn daemon
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$REPO
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN $REPO/dist/src/main.js
Restart=always
RestartSec=3
# WireGuard peer management needs privileges; runs as root by default.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cashu-vpn
sleep 2
echo "service: $(systemctl is-active cashu-vpn)"

# Optional Caddy HTTPS site.
if [ -n "$DOMAIN" ] && command -v caddy >/dev/null 2>&1; then
  CF=/etc/caddy/Caddyfile
  if grep -q "$DOMAIN" "$CF" 2>/dev/null; then
    echo "Caddy site $DOMAIN already present."
  else
    cp -n "$CF" "$CF.bak.cashuvpn" 2>/dev/null || true
    printf '\n%s {\n  reverse_proxy 127.0.0.1:%s\n}\n' "$DOMAIN" "$PORT" >> "$CF"
    if caddy validate --config "$CF" --adapter caddyfile >/dev/null 2>&1; then
      systemctl reload caddy && echo "Added Caddy site $DOMAIN"
    else
      echo "Caddy config invalid — restoring backup."; cp "$CF.bak.cashuvpn" "$CF"; systemctl reload caddy || true
    fi
  fi
elif [ -n "$DOMAIN" ]; then
  echo "DOMAIN set but Caddy not found — configure your reverse proxy manually."
fi

echo "health: $(curl -s "localhost:$PORT/health" || echo unreachable)"
