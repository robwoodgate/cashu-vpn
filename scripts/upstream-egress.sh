#!/usr/bin/env bash
# Route buyer egress through an upstream WireGuard VPN (e.g. an upstream VPN), so abuse
# complaints about buyer traffic land on the upstream provider instead of your
# host. Only the buyer subnet is sent through the upstream; the box's own traffic
# (SSH, the daemon, Caddy) stays on the normal default route. If the upstream
# tunnel drops, buyer traffic is blackholed (killswitch) rather than leaking out
# your host's real IP.
#
# This is provider-agnostic — it works with any WireGuard upstream (an upstream VPN, an upstream VPN,
# a second VPS you run). You supply the tunnel; this just steers the buyer subnet.
#
# PREREQUISITE — bring the upstream tunnel up WITHOUT hijacking the box's routes:
#   1. Get a WireGuard config from your provider (an upstream VPN: Account → WireGuard).
#   2. Add `Table = off` under its [Interface]. This is essential: otherwise
#      wg-quick installs a default route that sends the WHOLE box (including your
#      SSH session) through the VPN. `Table = off` lets the tunnel come up while
#      this script decides what actually uses it.
#   3. wg-quick up <iface>   (e.g. save as /etc/wireguard/upstream.conf, then
#      `wg-quick up upstream`)
#   4. Run this script with that interface name.
#
# Buyer packets are SNATed as they leave the upstream interface by the existing
# `iifname <buyer-wg> masquerade` NAT rule, so no extra NAT is needed in the
# common WireGuard setup. Pair with scripts/egress-filter.sh to also limit which
# ports buyers may reach.
#
# Apply:   sudo scripts/upstream-egress.sh <upstream-iface>
# Remove:  sudo scripts/upstream-egress.sh --remove
#
# Persist by running it from the upstream tunnel's wg-quick hooks (%i = iface):
#   PostUp   = /root/cashu-vpn/scripts/upstream-egress.sh %i
#   PostDown = /root/cashu-vpn/scripts/upstream-egress.sh --remove
set -euo pipefail

SUBNET="${WG_SUBNET:-10.77.0.0/24}"        # buyer tunnel subnet (matches the daemon's allocator)
TABLE="${UPSTREAM_TABLE:-1597}"            # dedicated routing table for buyer traffic
PRIO="${UPSTREAM_RULE_PRIO:-1597}"         # ip rule priority

usage() { echo "usage: $0 <upstream-iface> | --remove"; exit 1; }

remove() {
  while ip rule del from "$SUBNET" table "$TABLE" 2>/dev/null; do :; done
  ip route flush table "$TABLE" 2>/dev/null || true
  echo "upstream egress removed for $SUBNET (table $TABLE)"
}

[ $# -ge 1 ] || usage
[ "$(id -u)" = "0" ] || { echo "run as root (changes routing). Try: sudo $0 $*"; exit 1; }

if [ "$1" = "--remove" ]; then
  remove
  exit 0
fi

IF="$1"
ip link show "$IF" >/dev/null 2>&1 || {
  echo "interface '$IF' not found — bring up your upstream tunnel first (wg-quick up $IF, with Table=off in its config)"; exit 1; }

remove 2>/dev/null || true
# Buyer subnet gets its own routing table.
ip rule add from "$SUBNET" table "$TABLE" priority "$PRIO"
# Preferred route: out the upstream tunnel. Blackhole fallback = killswitch: if the
# tunnel goes down its device route disappears and buyer traffic is dropped here
# instead of falling through to the host's real default route.
ip route add default dev "$IF" table "$TABLE" metric 1
ip route add blackhole default table "$TABLE" metric 1000

echo "buyer egress ($SUBNET) now routes via $IF (table $TABLE); blackholed if $IF goes down"
