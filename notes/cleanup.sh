#!/usr/bin/env bash
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd /root/cashu-vpn
echo "peers before:"; wg show wg0 allowed-ips | grep 10.77 || echo "  none"
if [ -f state/peers.json ]; then
  CP=$(node -e "const r=require('./state/peers.json');console.log(r[r.length-1].clientPublicKey)")
  TIP=$(node -e "const r=require('./state/peers.json');console.log(r[r.length-1].tunnelIp)")
  wg set wg0 peer "$CP" remove 2>/dev/null || true
  ip route del "$TIP"/32 dev wg0 2>/dev/null || true
  echo "removed peer $TIP"
fi
[ -f state/daemon.pid ] && kill "$(cat state/daemon.pid)" 2>/dev/null && echo "daemon stopped"
sleep 0.3
echo "peers after:"; wg show wg0 allowed-ips | grep -q 10.77 && echo "  WARN: 10.77 remains" || echo "  none (clean)"
echo "wg0.conf sha256: $(sha256sum /etc/wireguard/wg0.conf | cut -d' ' -f1)"
