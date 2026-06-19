# cashu-vpn build status — 2026-06-19

Autonomous build session (Rob offline). All gates green at every commit
(`npm run typecheck && npm run lint && npm test`, 40/40). Nothing was deployed
and no real money moved — that's the live checkpoint, which waits for Rob.

## Shipped this session (commits on `main`, pushed)

- `f0ad8f3` Fix command-injection RCE in the WireGuard peer path (execFile/argv +
  strict key validation).
- `7fd9a99` Rename nostr-vpn → cashu-vpn.
- `98ab439` Non-custodial NUT-24 (HTTP 402) payment core.
- `71e4a17` Non-mutating operator discovery (`npm run discover`).
- `768511f` Browser flow: client-side WG keypair gen (WebCrypto X25519) + 402 pay UX.
- `da0caff` BIP32 watch-only key derivation (xpub per-tx privacy core).
- `296185e` Wire xpub per-tx privacy into the daemon (LockBook + lock authorization).
- `cb3929c` Operator sweep tool (`npm run sweep`).

## Architecture as built

- **Payment = NUT-24 (HTTP 402) over a NUT-18 PaymentRequest.** `POST /purchase`
  with no payment → `402` + `x-cashu: creqA…` demanding proofs **P2PK-locked**;
  pay, then retry with `X-Cashu: <token>` → peer added + `.conf` returned.
- **Non-custodial.** The daemon never holds spendable ecash. It verifies the paid
  token **fully offline** — `hasValidDleq` (NUT-12, genuine) + P2PK-locked to a
  pubkey the operator controls (NUT-11) + amount + replay dedupe — then stores the
  **locked** token. Box theft ≠ fund theft. Only mint call is a cached `loadMint`
  for public keysets (not per-sale), so mint rate limits aren't a problem.
- **Privacy (xpub mode).** With `OPERATOR_XPUB` set, each 402 locks to a fresh
  xpub-derived child pubkey (LockBook persists only a counter; no privkey/seed on
  the box), so the mint can't correlate an operator's payments. Without an xpub it
  falls back to a single `OPERATOR_PUBKEY` (simpler; mint-correlatable).
- **Sweep.** Operator runs `npm run sweep` OFF the box with `OPERATOR_XPRV`; it
  derives the child key per receipt index and claims each locked token. The
  derivation roundtrip is proven by tests (funds can't be stranded).

## Operator quickstart (dry-run works today)

```bash
npm install && npm run build
# discover server key/port/endpoint off a live wg0 (read-only):
npm run discover wg0
# live (xpub mode — recommended):
MODE=live WG_INTERFACE=wg0 SERVER_PUBLIC_KEY=<key> WG_ENDPOINT=<ip:51820> \
  OPERATOR_XPUB=<your xpub> LOCK_COUNTER_PATH=./state/locks.json \
  PROOFS_PATH=./state/proofs.json PEER_LEDGER_PATH=./state/peers.json \
  ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin PRICE_SATS=250 npm start
```

## What's verified vs not

- **Verified offline (40 tests):** RCE fix, allocator/ledger, 402 challenge,
  verifyPayment branch logic (injected deps), HD derivation roundtrip + P2PK
  recoverability, LockBook issue/resolve/persist, xpub-mode 402 over HTTP, sweep
  planning/grouping, discovery parsing, served page structure.
- **NOT yet validated against a live mint/LN (needs the deploy checkpoint):**
  the real DLEQ/P2PK crypto on genuine tokens, and the online sweep claim. The
  logic is structured and unit-tested with stubs; only the live crypto path is
  unproven.

## Remaining (need Rob / live)

- **#4 — live VPS proof:** deploy to one Hetzner box, complete one real paid loop
  (real Cashu payment over 402), validate DLEQ/P2PK + sweep against a live mint,
  write a dated evidence note. Real infra + money → stopped here for Rob.
- **#6 — browser LN auto-pay:** the slick "just pay Lightning, mint P2PK-locked
  proofs in-browser" UX + QR + esbuild bundle. Deferred (needs a live mint to
  validate; risky to build blind). Today's page works for NUT-18 wallets via
  scan-request → paste-token-back.

## Follow-ups worth noting

- PRD.md predates this architecture (it still says Cashu-only paste-token); update
  it to the 402 / P2PK / xpub model.
- Rate-limit `/purchase` per IP before any public exposure (abuse + mint-call
  amplification on junk tokens).
- xpub LockBook rebuilds its map by deriving [0, counter) at startup — fine for v0
  volumes; revisit if a counter grows large. Consider cashu-ts v5 #697 for
  first-class deterministic locked-receive.
```
