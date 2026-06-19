#!/usr/bin/env bash
# Stage A live validation (no money): dry-run + live 402 challenge + per-tx locks.
set -e
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd /root/cashu-vpn

XPUB=$(node -e "console.log(require('./state/test-key.json').xpub)")
WGKEY="nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU="

MODE=live WG_INTERFACE=wg0 SERVER_PUBLIC_KEY="$WGKEY" \
  WG_ENDPOINT=157.180.114.119:51820 OPERATOR_XPUB="$XPUB" \
  LOCK_COUNTER_PATH=state/locks.json PROOFS_PATH=state/proofs.json PEER_LEDGER_PATH=state/peers.json \
  ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin PRICE_SATS=250 PORT=3087 HOST=127.0.0.1 \
  node dist/src/main.js > state/daemon.log 2>&1 &
PID=$!
sleep 1.5

echo "=== /health ==="; curl -s localhost:3087/health; echo
echo "=== /info ===";   curl -s localhost:3087/info;   echo

req() { curl -s -D - -o /dev/null -X POST localhost:3087/purchase \
  -H 'content-type: application/json' -d "{\"clientPublicKey\":\"$WGKEY\"}" \
  | tr -d '\r' | awk 'tolower($1)=="x-cashu:"{print $2}'; }

CREQ1=$(req); CREQ2=$(req)
echo "=== 402 challenge #1 ==="; echo "${CREQ1:0:36}..."
echo "=== 402 challenge #2 ==="; echo "${CREQ2:0:36}..."
if [ -n "$CREQ1" ] && [ "$CREQ1" != "$CREQ2" ]; then echo "PER-TX OK: lock pubkeys differ"; else echo "WARN: locks missing or identical"; fi

CREQ1="$CREQ1" node --input-type=module -e '
import { decodePaymentRequest } from "@cashu/cashu-ts";
import { deriveChildPubkey } from "./dist/src/hdkeys.js";
import { normalizePubkey } from "./dist/src/cashu.js";
import { readFileSync } from "node:fs";
const { xpub } = JSON.parse(readFileSync("./state/test-key.json","utf8"));
const d = decodePaymentRequest(process.env.CREQ1);
console.log("decoded: amount", d.amount?.toNumber(), d.unit, "| nut10", d.nut10?.kind);
console.log("lock == child[0]:", normalizePubkey(d.nut10?.data) === normalizePubkey(deriveChildPubkey(xpub, 0)));
'

kill "$PID" 2>/dev/null || true
echo "=== daemon.log (tail) ==="; tail -3 state/daemon.log
