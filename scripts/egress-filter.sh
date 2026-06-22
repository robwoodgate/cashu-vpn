#!/usr/bin/env bash
# Restrict what buyer traffic is allowed to leave the box (egress allow-list).
#
# Buyers route through the tunnel, so the box's IP is the apparent source of
# whatever they do. Limiting their egress to DNS + web + ICMP removes the abuse
# that gets a host account suspended — outbound spam (SMTP), port scanning,
# SSH/RDP brute-forcing, and most torrenting — while normal web browsing keeps
# working. It does NOT stop bad things done over HTTPS itself; pair it with an
# upstream VPN (e.g. an upstream VPN) if you want that residual risk off your host too.
#
# This only touches FORWARD (routed buyer traffic). It never affects the box's
# own SSH/HTTP/daemon (those are INPUT/OUTPUT), so it can't lock you out.
#
# Works on both legacy-iptables and nftables hosts: it calls `iptables`, which on
# modern distros is the iptables-nft shim, so these become native nft rules and
# coexist with an existing nft ruleset (a drop here is terminal, so it still wins
# over a permissive `iifname wgX accept`). On a pure-nft host with no iptables
# shim at all, translate these few rules to `nft` instead.
#
# Apply:   sudo scripts/egress-filter.sh
# Remove:  sudo scripts/egress-filter.sh --remove
#
# Rules are not persistent across reboot on their own. To make them stick, run
# this from your WireGuard interface's PostUp (and `--remove` from PostDown):
#   PostUp = /root/cashu-vpn/scripts/egress-filter.sh
#   PostDown = /root/cashu-vpn/scripts/egress-filter.sh --remove
set -euo pipefail

command -v iptables >/dev/null || { echo "iptables not found — on a pure-nft host, translate these rules to nft directly"; exit 1; }

SUBNET="${WG_SUBNET:-10.77.0.0/24}"   # buyer tunnel subnet (matches the daemon's allocator)
CHAIN="CASHU_EGRESS"

remove() {
  # Detach the jump (possibly several copies) then drop the chain.
  while iptables -D FORWARD -s "$SUBNET" -j "$CHAIN" 2>/dev/null; do :; done
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "egress filter removed for $SUBNET"
}

if [ "${1:-}" = "--remove" ]; then
  remove
  exit 0
fi

# Idempotent: rebuild from scratch each run.
remove 2>/dev/null || true
iptables -N "$CHAIN"

# Let replies to allowed, already-open connections through.
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# DNS (so names resolve — without this the tunnel looks broken).
iptables -A "$CHAIN" -p udp --dport 53 -j ACCEPT
iptables -A "$CHAIN" -p tcp --dport 53 -j ACCEPT
# Web.
iptables -A "$CHAIN" -p tcp --dport 80  -j ACCEPT
iptables -A "$CHAIN" -p tcp --dport 443 -j ACCEPT
iptables -A "$CHAIN" -p udp --dport 443 -j ACCEPT   # QUIC / HTTP/3
# Ping / path-MTU.
iptables -A "$CHAIN" -p icmp -j ACCEPT
# Everything else from a buyer is dropped (SMTP, SSH-out, scanning, torrents…).
iptables -A "$CHAIN" -j DROP

# Send new buyer-sourced traffic into the chain (insert at the top so it wins).
iptables -I FORWARD 1 -s "$SUBNET" -j "$CHAIN"

echo "egress filter applied for $SUBNET: DNS + 80/443 + ICMP allowed, rest dropped"
