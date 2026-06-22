#!/usr/bin/env bash
# Update an installed cashu-vpn: pull the latest code, reinstall deps, rebuild,
# and restart the service. Run it from the repo root on the server (as root, the
# same as the installer).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "→ git pull"
git pull --ff-only

echo "→ npm ci"
npm ci --no-audit --no-fund

echo "→ build"
npm run build

if command -v systemctl >/dev/null 2>&1 && systemctl cat cashu-vpn >/dev/null 2>&1; then
  echo "→ restart cashu-vpn"
  systemctl restart cashu-vpn
  sleep 2
  echo "service: $(systemctl is-active cashu-vpn)"
else
  echo "→ no systemd 'cashu-vpn' service found; restart it however you run it"
fi

echo "✓ updated to $(git rev-parse --short HEAD)"
