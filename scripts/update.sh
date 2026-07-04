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

# The allocator hands out IPs across 10.77.0.0/16; a wg0 still configured /24
# (older installs, some provider WireGuard images) NATs only the first 253
# leases and silently blackholes the rest.
WG_CONF="/etc/wireguard/${WG_INTERFACE:-wg0}.conf"
if [ -f "$WG_CONF" ] && grep -q '10\.77\.0\.1/24' "$WG_CONF"; then
  echo "⚠ $WG_CONF still uses 10.77.0.1/24 — widen it (and any /24 MASQUERADE rule) to /16:"
  echo "    Address = 10.77.0.1/16"
  echo "    iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o <public-iface> -j MASQUERADE"
fi

echo "✓ updated to $(git rev-parse --short HEAD)"
