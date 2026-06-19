# cashu-vpn

A **Cashu-paid WireGuard access daemon**. Independent operators sell short-lived
VPN access for ecash — no accounts, no subscriptions, and **the operator never
custodies spendable ecash on the box**. Pay a Lightning invoice (or a Cashu
wallet), get a WireGuard config.

Freedom tech: it's designed so *anyone* can stand one up. This is FOSS, not a
product — see the security model below for why that's safe to run.

> **Status:** the full loop is proven end-to-end on a live host (incl. a public
> TLS browser smoke against the [CDK test mint](https://testnut.cashudevkit.org)).
> Before a real public launch see **Production checklist** below.

## How payment works (NUT-24 over NUT-18, non-custodial)

```
buyer                              daemon                         mint
  │  POST /purchase (no payment)     │                             │
  │ ───────────────────────────────►│  402 + x-cashu: creqA…       │
  │ ◄───────────────────────────────│  (PaymentRequest, P2PK-lock) │
  │  pay LN invoice / mint ecash ───────────────────────────────► mint
  │  POST /purchase  X-Cashu: token  │                             │
  │ ───────────────────────────────►│  verify OFFLINE, add peer    │
  │ ◄───────────────────────────────│  200 + WireGuard .conf       │
```

The daemon answers an unpaid `/purchase` with **HTTP 402** and a NUT-18
`PaymentRequest` (`creqA…`) that demands proofs **NUT-11 P2PK-locked to the
operator's pubkey**. On the paid retry it verifies the token **entirely offline**:

1. **NUT-12 DLEQ** — proves the mint genuinely signed the proofs, checked locally
   against the mint's public keyset (fetched once, cached). No swap.
2. **NUT-11 P2PK** — proves the proofs are locked to a pubkey the operator
   controls, so only the operator can ever spend them.
3. amount ≥ price, accepted mint, and replay dedupe.

There is **no per-sale mint call** and **no swap** — the buyer's wallet does all
the minting (so mint rate limits fan out across buyers). Received tokens are
stored *locked*; the operator sweeps them later with an **offline** key. If the
box is stolen, the funds aren't: the spending key was never on it.

### Privacy (xpub mode, recommended)

Set `OPERATOR_XPUB` and every payment is locked to a **fresh BIP32-derived child
pubkey** (watch-only — only the xpub is on the box), so the mint can't correlate
an operator's payments. The operator sweeps with the matching `xprv` offline
(`npm run sweep`). Without an xpub it falls back to a single `OPERATOR_PUBKEY`
(simpler, but mint-correlatable).

## Buyer experience

Open the operator's page and click **Get VPN config**. A WireGuard keypair is
generated **in your browser** (the private key never leaves the page). Then pay:

- **⚡ Lightning** — no Cashu wallet needed. The page mints the ecash in your
  browser from a Lightning invoice and delivers it automatically.
- **Cashu wallet** — scan/copy the payment request with a NUT-18 wallet and paste
  the token back.

You get a ready-to-use `.conf` to download. (The page needs a **secure context** —
HTTPS or localhost — for in-browser key generation.)

## Operator quickstart

Requirements: a Linux box with WireGuard up (`wg0`), **Node.js ≥ 20**, and — for
real tunnels — **UDP/51820** open in your firewall.

```bash
git clone <repo> && cd cashu-vpn
npm install && npm run build

# Discover your server key / port / endpoint off the live interface (read-only):
npm run discover wg0

# Run live (xpub mode — private + recommended). Generate an HD key OFFLINE and
# put only the xpub here; keep the xprv off this machine.
MODE=live WG_INTERFACE=wg0 \
  SERVER_PUBLIC_KEY=<from discover> WG_ENDPOINT=<ip>:51820 \
  OPERATOR_XPUB=<your xpub> \
  ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin PRICE_SATS=250 \
  PROOFS_PATH=./state/proofs.json PEER_LEDGER_PATH=./state/peers.json \
  LOCK_COUNTER_PATH=./state/locks.json CLEANUP_INTERVAL_MS=60000 \
  npm start
```

The daemon binds `127.0.0.1` by default — put it behind a TLS reverse proxy
(e.g. Caddy) for public access; browsers need HTTPS for the in-browser keygen.
It **adopts an existing `wg0` at runtime** via `wg set` / `ip route` and never
edits `/etc/wireguard/wg0.conf`.

### Claiming your earnings (sweep)

Run this **off the box**, where your `xprv` lives:

```bash
OPERATOR_XPRV=<your xprv> PROOFS_PATH=./state/proofs.json npm run sweep
```

It derives the child key for each receipt and claims the locked tokens into fresh,
unlocked ecash you own. (Mints charge a small input fee on the claim swap, so you
net price minus a sat or two.)

## Configuration (environment variables)

| Var | Default | Purpose |
|---|---|---|
| `MODE` | `dry-run` | `live` enables payment + real WireGuard mutation |
| `HOST` / `PORT` | `127.0.0.1` / `3087` | listen address |
| `WG_INTERFACE` | `wg0` | WireGuard interface to manage |
| `SERVER_PUBLIC_KEY` | — | server's WG public key (in the buyer `.conf`) |
| `WG_ENDPOINT` | — | `host:port` buyers connect to |
| `OPERATOR_XPUB` | — | BIP32 xpub for per-tx P2PK locks (private mode) |
| `OPERATOR_PUBKEY` | — | fixed P2PK pubkey (used if no xpub); live needs one of these |
| `ACCEPTED_MINTS` | minibits | comma-separated mint URLs |
| `PRICE_SATS` | `250` | price per lease |
| `MINT_UNIT` | `sat` | cashu unit |
| `LEASE_DURATION_MS` | `10800000` (3h) | lease length |
| `CLEANUP_INTERVAL_MS` | off | how often to remove expired peers |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | `30` / `60000` | per-IP `/purchase` limit (0 disables) |
| `PROOFS_PATH` | memory | locked-proof vault file |
| `PEER_LEDGER_PATH` | memory | lease ledger file |
| `LOCK_COUNTER_PATH` | memory | xpub lock index counter file |

## HTTP API

- `GET /` · `GET /marketplace` — buyer page · `GET /client.js` — browser bundle
- `GET /health` · `GET /info` — status / price / accepted mints
- `POST /purchase` — `{clientPublicKey}`; 402 → pay → retry with `X-Cashu` header
- `GET /peers` — active leases

## Security model

- **Non-custodial:** received proofs are P2PK-locked to an off-box key; the daemon
  stores but cannot spend them.
- **Offline verification:** DLEQ + P2PK checked locally; no swap, no per-sale mint
  call (so a hostile buyer can't force mint traffic, and rate limits stay fanned
  out across real buyers).
- **No shell injection:** WireGuard commands run via `execFile` with an argv
  allowlist and strict key/IP validation — never a shell string.
- **Rate limited:** per-IP cap on `/purchase`.
- **No anonymity/legal claims.** Operators run their own exits and carry that
  responsibility; this software does not route or proxy traffic itself.

## Project layout

```
src/
  config.ts     env config
  server.ts     HTTP server, 402 flow, buyer page
  cashu.ts      PaymentRequest + offline verify (DLEQ + P2PK)
  locks.ts      xpub LockBook (per-tx pubkeys)
  hdkeys.ts     BIP32 watch-only derivation
  wallet.ts     locked-proof vault
  peers.ts      IP allocation + lease ledger
  wireguard.ts  argv command planning/execution (execFile)
  ratelimit.ts  per-IP limiter
  buyer.ts      shared buyer-side helpers (also used by the browser)
  client.ts     browser bundle (esbuild → dist/public/client.js)
  discover.ts   operator discovery CLI
  sweep.ts      offline sweep CLI
```

## Scripts

`npm run build` (tsc + esbuild) · `test` · `lint` · `typecheck` · `start` ·
`discover [iface] [host]` · `sweep`

## License / status

Freedom-tech FOSS. Not production-hardened for unattended public operation yet —
see **Production checklist**: add a process supervisor (systemd), keep
`CLEANUP_INTERVAL_MS` set, front it with TLS, tune `RATE_LIMIT_*`, and use a real
`OPERATOR_XPUB` with the `xprv` kept offline.
