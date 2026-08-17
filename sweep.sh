#!/usr/bin/env bash
# Remote sweep without remembering the incantation: fetches OPERATOR_XPRV from
# the OS secret store and hands off to scripts/sweep-remote.sh.
#
# Usage:
#   ./sweep.sh user@host [remote-cashu-vpn-dir]
#
# user@host is the ssh destination (eg root@203.0.113.7, or a Host alias from
# ~/.ssh/config); remote-cashu-vpn-dir is where the repo lives on the box
# (default /root/cashu-vpn). Set the destination once in your shell profile,
#   export CASHU_VPN_REMOTE=root@203.0.113.7
# and it is just ./sweep.sh
#
# One-time key setup (you are prompted for the xprv, so it never enters shell
# history or this file):
#   macOS:  security add-generic-password -a "$USER" -s cashu-vpn-operator-xprv -w
#   Linux:  secret-tool store --label='cashu-vpn operator xprv' service cashu-vpn-operator-xprv
#
# An OPERATOR_XPRV already set in the environment wins over the secret store.
set -euo pipefail
cd "$(dirname "$0")"

SERVICE="${XPRV_SERVICE:-cashu-vpn-operator-xprv}"
REMOTE="${1:-${CASHU_VPN_REMOTE:-}}"

if [ -z "$REMOTE" ]; then
  echo "usage: ./sweep.sh user@host [remote-dir]  (or set CASHU_VPN_REMOTE)" >&2
  exit 1
fi
[ $# -gt 0 ] && shift

if [ -z "${OPERATOR_XPRV:-}" ]; then
  if command -v security >/dev/null 2>&1; then
    OPERATOR_XPRV="$(security find-generic-password -s "$SERVICE" -w 2>/dev/null)" || true
  elif command -v secret-tool >/dev/null 2>&1; then
    OPERATOR_XPRV="$(secret-tool lookup service "$SERVICE" 2>/dev/null)" || true
  fi
fi

# Pasted secrets often pick up stray whitespace; base58 never contains any.
OPERATOR_XPRV="${OPERATOR_XPRV:-}"
OPERATOR_XPRV="${OPERATOR_XPRV//[[:space:]]/}"

if [ -z "${OPERATOR_XPRV:-}" ]; then
  echo "OPERATOR_XPRV is not set and there is no '$SERVICE' item in the secret store." >&2
  echo "Store it once (you will be prompted; it stays out of shell history):" >&2
  echo "  macOS:  security add-generic-password -a \"\$USER\" -s $SERVICE -w" >&2
  echo "  Linux:  secret-tool store --label='cashu-vpn operator xprv' service $SERVICE" >&2
  exit 1
fi

export OPERATOR_XPRV
exec bash scripts/sweep-remote.sh "$REMOTE" "$@"
