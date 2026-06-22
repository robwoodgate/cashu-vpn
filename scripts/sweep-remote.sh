#!/usr/bin/env bash
# Remote sweep, made simple.
#
# Pulls the locked receipts off your box, claims them LOCALLY with your offline
# xprv (one batched swap per mint), saves the resulting unlocked tokens to a file,
# then prunes the swept receipts on the box. Your xprv NEVER touches the server.
#
# Usage:
#   OPERATOR_XPRV=xprv... npm run sweep:remote user@host [remote-cashu-vpn-dir]
#
# Requires: ssh/scp access to the box, and this repo built locally (npm run build).
set -euo pipefail

REMOTE="${1:?usage: OPERATOR_XPRV=... sweep-remote.sh user@host [remote-dir]}"
REMOTE_DIR="${2:-/root/cashu-vpn}"
: "${OPERATOR_XPRV:?set OPERATOR_XPRV to your OFFLINE xprv (it stays on this machine)}"

RPROOFS="$REMOTE_DIR/state/proofs.json"
TMP="$(mktemp -d)"
LOCAL="$TMP/proofs.json"
OUT="swept-$(date +%Y%m%d-%H%M%S).json"

echo "→ pulling locked receipts from $REMOTE:$RPROOFS"
scp -q "$REMOTE:$RPROOFS" "$LOCAL"

echo "→ sweeping locally (xprv stays on this machine)"
SWEEP_OUT="$OUT" PROOFS_PATH="$LOCAL" OPERATOR_XPRV="$OPERATOR_XPRV" node dist/src/sweep.js

echo "→ pruning swept receipts on the box (keyless state check)"
ssh "$REMOTE" "export NVM_DIR=\$HOME/.nvm; [ -s \$NVM_DIR/nvm.sh ] && . \$NVM_DIR/nvm.sh >/dev/null 2>&1; cd '$REMOTE_DIR' && PROOFS_PATH='$RPROOFS' node dist/src/sweep.js --prune"

rm -rf "$TMP"
echo "✓ done — unlocked tokens saved to ./$OUT (import into any cashu wallet)"
