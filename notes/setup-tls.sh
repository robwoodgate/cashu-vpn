#!/usr/bin/env bash
# Additively add a cashu-vpn HTTPS site to the box's existing Caddy (WG-UI site
# left intact). Backs up + validates before reloading.
set -e
HOST="vpn-157-180-114-119.nip.io"
cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak.cashuvpn 2>/dev/null || true

if ! grep -q "$HOST" /etc/caddy/Caddyfile; then
cat >> /etc/caddy/Caddyfile <<EOF

$HOST {
  reverse_proxy 127.0.0.1:3087
}
EOF
  echo "added site $HOST"
else
  echo "site $HOST already present"
fi

caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 && \
  systemctl reload caddy && echo "caddy reloaded OK" || { echo "VALIDATE/RELOAD FAILED — restoring backup"; cp /etc/caddy/Caddyfile.bak.cashuvpn /etc/caddy/Caddyfile; systemctl reload caddy; exit 1; }
