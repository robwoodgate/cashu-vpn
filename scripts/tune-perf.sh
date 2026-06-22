#!/usr/bin/env bash
# Tune the box for WireGuard throughput over a high-latency exit.
#
# A VPN exit is usually far (tens of ms) from the buyer, so the bandwidth-delay
# product is large. Two kernel defaults throttle this badly:
#
#   * Socket buffers (net.core.rmem_max/wmem_max) default to ~208 KB. That caps
#     a TCP flow at roughly buffer/RTT — e.g. ~27 Mbit/s at 60 ms — and also
#     starves WireGuard's own UDP socket, so it drops encrypted packets under
#     load. Raising them to 16 MB lets windows actually fill the pipe.
#   * CUBIC congestion control treats every loss as congestion and collapses the
#     window. On a jittery path it never recovers. BBR paces instead and stays
#     fast through loss — the standard fix for VPNs. Pair it with the `fq` qdisc.
#
# On a real test (UK buyer -> Helsinki box, ~62 ms) this took download from
# ~37 Mbit/s to ~140 Mbit/s. Upload is bounded by the buyer's own uplink and
# their OS's congestion control, so it gains little from box-side tuning.
#
# This only touches the box's own networking sysctls — it does not affect buyer
# routing, the egress filter, or the daemon.
#
# Apply:   sudo scripts/tune-perf.sh
# Remove:  sudo scripts/tune-perf.sh --remove
#
# Persistent across reboot (writes /etc/sysctl.d + /etc/modules-load.d).
set -euo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-wg-perf.conf"
MODULE_FILE="/etc/modules-load.d/bbr.conf"
WAN_IFACE="${WAN_IFACE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')}"

if [ "${1:-}" = "--remove" ]; then
  rm -f "$SYSCTL_FILE" "$MODULE_FILE"
  echo "removed $SYSCTL_FILE and $MODULE_FILE"
  echo "running kernel values are unchanged until reboot; reset them by hand if needed"
  exit 0
fi

# BBR lives in a module on most distros; load it now and on every boot.
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > "$MODULE_FILE"

cat > "$SYSCTL_FILE" <<EOF
# WireGuard throughput tuning for a high-RTT exit (see scripts/tune-perf.sh).
# Big socket buffers so TCP windows and the WG UDP socket can fill the BDP;
# BBR + fq to stay fast through path loss instead of collapsing on it.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 16384
net.core.default_qdisc = fq
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -q -p "$SYSCTL_FILE"

# default_qdisc only applies to interfaces brought up afterwards; switch the
# already-up WAN interface to fq now so BBR gets its pacing immediately.
if [ -n "$WAN_IFACE" ]; then
  tc qdisc replace dev "$WAN_IFACE" root fq 2>/dev/null \
    && echo "set $WAN_IFACE qdisc to fq" \
    || echo "note: could not set fq on $WAN_IFACE (it takes effect on next boot regardless)"
fi

cc=$(sysctl -n net.ipv4.tcp_congestion_control)
echo "perf tuning applied: congestion control = $cc, socket buffers = 16 MB, qdisc = fq"
[ "$cc" = bbr ] || echo "WARNING: congestion control is '$cc', not bbr — kernel may lack tcp_bbr"
