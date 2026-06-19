# cashu-vpn live paid-loop evidence — 2026-06-19

## Result

**Pass.** The full non-custodial paid loop works end-to-end on a live host, using
the CDK test mint (`https://testnut.cashudevkit.org`) so no real value moved. This
is the first end-to-end proof of the NUT-24 + DLEQ + P2PK + xpub-privacy + sweep
path against a real mint and a real WireGuard interface.

## Host

- `157.180.114.119` (`ubuntu-4gb-hel1-1`), Hetzner WireGuard app image, same box as
  the earlier WG add/remove smoke.
- `wg0` live: pubkey `nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=`, port 51820.
- Node 20.20.2 via nvm (project requires >=20; system node 18 left untouched).
- Code at `/root/cashu-vpn` (rsync of the working tree); old `/root/nostr-vpn-marketplace`
  and `/etc/wireguard/wg0.conf` left untouched.

## Config (live, xpub mode, localhost-bound)

```
MODE=live WG_INTERFACE=wg0 SERVER_PUBLIC_KEY=nKpu... WG_ENDPOINT=157.180.114.119:51820
OPERATOR_XPUB=<throwaway test xpub>  LOCK_COUNTER_PATH/PROOFS_PATH/PEER_LEDGER_PATH=state/*
ACCEPTED_MINTS=https://testnut.cashudevkit.org  PRICE_SATS=5  HOST=127.0.0.1 PORT=3087
```

A throwaway HD key was generated on the box; only the xpub went to the daemon.

## Stage A — non-money (all pass)

- `npm run build` + 40/40 tests on node 20.
- `npm run discover wg0` → `serverPublicKey`, `listenPort 51820`, `endpoint
  157.180.114.119:51820`, `hostMutationPerformed:false`.
- Live `/health`, `/info` ok.
- `POST /purchase` (no payment) → `402` + `x-cashu: creqA…`. Two requests returned
  **different** lock pubkeys; challenge #1 decoded to amount 5 sat, `nut10` P2PK,
  lock == `deriveChildPubkey(xpub, 0)`.

## Stage B+C — full paid loop + sweep (all pass)

Buyer-side test client (`testclient.mjs`): mints P2PK-locked proofs at testnut and
pays the daemon.

```
{"step":"402","amount":5,"mintUrl":"https://testnut.cashudevkit.org","lockPubkey":"02a61230e64e9c…"}
{"step":"minted","proofs":2,"hasDleq":true}
{"step":"paid","status":200,"amountSats":5,"tunnelIp":"10.77.0.86","hasConfig":true}
```

- Daemon verified the token **fully offline** (DLEQ valid + P2PK-locked to the
  issued per-tx pubkey + amount) — no swap, no per-sale mint call — and provisioned.
- `wg show wg0` showed the real peer `8gRJOaZg…=  10.77.0.86/32`.
- Stored receipt: `{ mint: testnut, amountSats: 5, index: 0, lockPubkey: a61230… }`.
- **Sweep** with the offline xprv: `sweepable: 1`, `claimedSats: 4`, re-encoded an
  unlocked token — non-custodial recovery proven.

## Findings

- **Input fee on claim:** 5 sat minted → **4 sat** swept. The mint charges a
  per-swap input fee (NUT-02 `input_fee_ppk`) when the operator claims. The operator
  nets `price − claim fee`; negligible at 250 sat but worth pricing in / documenting.
- **DLEQ present:** testnut/CDK returns DLEQ on minted proofs, so the daemon's
  `hasValidDleq` (require=true) path works against a real mint.

## Cleanup / non-destructive proof

- Test peer removed; `wg show wg0` shows **no peers**.
- `/etc/wireguard/wg0.conf` sha256 `34a33b9401804109921f7262024408fd0e1c5e294e07e7bd8f94e4820a7f8c08`
  — **identical** to the prior smoke note; never modified.
- Daemon stopped. testnut proofs were valueless and already swept.

## Not yet done (optional, Rob's call)

- A real-value smoke (e.g. minibits) — the protocol/crypto is already proven here;
  this would only confirm a production mint + real settlement.
- Public exposure: reverse proxy + TLS (the box has Caddy) and per-IP rate limiting
  on `/purchase` before any public launch.
```
