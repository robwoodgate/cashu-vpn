# cashu-vpn

Sell short-lived WireGuard VPN access for Cashu ecash. No accounts, no
subscriptions, and no ecash sitting on your server waiting to be stolen.

A buyer opens your page, pays a Lightning invoice (or a Cashu wallet), and gets a
working WireGuard config in their browser. You collect ecash you can claim later
with a key that never touches the server.

It's freedom tech, not a SaaS: the whole point is that anyone can run one.

> **Status:** the full buyer→pay→connect loop runs on a live host behind TLS. It's
> usable for testing today; read [Before you go public](#before-you-go-public)
> first if you want to run one for real.

## What you get

- **Buyers:** pay, get a `.conf`, connect. No sign-up, no app, no Cashu wallet
  required (there's an in-browser Lightning option).
- **Operators:** one Node process in front of an existing WireGuard interface.
  Ecash lands locked to a key you keep offline. If someone steals the box, they
  can't spend a sat.

## Run your own

You need a Linux box with WireGuard already up (`wg0`), Node.js ≥ 20, and
UDP/51820 open if you want real tunnels.

```bash
git clone <repo> && cd cashu-vpn
npm install && npm run build

# Read your server's key, port, and endpoint off the live interface (read-only):
npm run discover wg0
```

Generate an HD key **offline** and keep the private half (`xprv`) off this
machine. Put only the public half (`xpub`) in the config below. Then start it:

```bash
MODE=live WG_INTERFACE=wg0 \
  SERVER_PUBLIC_KEY=<from discover> WG_ENDPOINT=<ip>:51820 \
  OPERATOR_XPUB=<your xpub> \
  ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin PRICE_SATS=250 \
  PROOFS_PATH=./state/proofs.json PEER_LEDGER_PATH=./state/peers.json \
  ORDERS_PATH=./state/orders.json LOCK_COUNTER_PATH=./state/locks.json \
  CLEANUP_INTERVAL_MS=60000 \
  npm start
```

The daemon listens on `127.0.0.1` and expects a TLS reverse proxy (Caddy works
well) in front of it — browsers need HTTPS for in-browser key generation. It
attaches peers to your running `wg0` with `wg set` / `ip route` and never edits
`wg0.conf`.

Leave `MODE` unset (or `dry-run`) to try everything locally with no payment and
no changes to the host.

## Getting your sats out

Everything you earn is stored as ecash **locked to your offline key**. The server
only holds the watch-only `xpub` and a list of locked receipts
(`state/proofs.json`). To claim, you do a quick offline step on your own machine,
where the `xprv` lives.

One command does the whole thing:

```bash
OPERATOR_XPRV=<your xprv> npm run sweep:remote root@your-box
```

That pulls the receipts off the box, claims them locally (your `xprv` never leaves
your machine), saves the unlocked tokens to `swept-<timestamp>.json`, and cleans
the swept receipts off the box. Import the saved tokens into any Cashu wallet.

Prefer to do it by hand? The steps are just:

```bash
scp root@your-box:/root/cashu-vpn/state/proofs.json ./proofs.json
OPERATOR_XPRV=<your xprv> PROOFS_PATH=./proofs.json npm run sweep
```

A few things worth knowing:

- **It's cheap.** All of a mint's receipts are claimed in one swap, so you pay the
  mint's input fee once for the batch instead of once per sale.
- **It's safe to re-run.** The sweep asks the mint which receipts are already spent
  and skips them, so running it twice won't double-anything or error out.
- **Keep the file tidy.** `npm run prune` (or the remote sweep, which does it for
  you) drops already-claimed receipts from `proofs.json`. It only reads spend
  state from the mint, so it's safe to run on the box — no key needed.

> The demo deploy keeps a throwaway `xprv` in `state/test-key.json` for hands-off
> test sweeps. Don't do that with real money: generate your key offline and keep
> the `xprv` off the server.

## What buyers see

They click **Get VPN config**. Their browser makes a WireGuard keypair (the
private key never leaves the page) and shows two ways to pay:

- **⚡ Lightning** — no Cashu wallet needed. Pay the invoice and the page mints the
  ecash for you and delivers it. (Ecash-only? Most wallets can melt to pay this.)
- **Cashu wallet** — scan the payment request with a NUT-18 wallet; it pays and
  delivers automatically.

The page finishes on its own and hands over a ready-to-use `.conf`. Past orders
stay under **Your access** in that browser so they can be re-downloaded.

> Note: paying from a Cashu wallet needs one that locks its proofs to the
> request's NUT-11 key — e.g. [cashu.me](https://cashu.me) on cashu-ts ≥ 4.6.0.
> Wallets that ignore the lock will fail (the daemon won't accept unlocked ecash);
> the Lightning option works with any wallet.

## Configuration

Set these as environment variables.

| Var | Default | Purpose |
|---|---|---|
| `MODE` | `dry-run` | `live` enables payment + real WireGuard changes |
| `HOST` / `PORT` | `127.0.0.1` / `3087` | listen address |
| `WG_INTERFACE` | `wg0` | WireGuard interface to manage |
| `SERVER_PUBLIC_KEY` | — | server's WG public key (goes in the buyer `.conf`) |
| `WG_ENDPOINT` | — | `host:port` buyers connect to |
| `OPERATOR_XPUB` | — | BIP32 xpub for per-sale P2PK locks (recommended) |
| `OPERATOR_PUBKEY` | — | fixed P2PK pubkey (used if no xpub); live needs one of these |
| `ACCEPTED_MINTS` | minibits | comma-separated mint URLs |
| `PRICE_SATS` | `250` | price per lease |
| `MINT_UNIT` | `sat` | cashu unit |
| `LEASE_DURATION_MS` | `10800000` (3h) | lease length |
| `CLEANUP_INTERVAL_MS` | off | how often to remove expired peers |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | `30` / `60000` | per-IP `/purchase` limit (0 disables) |
| `PUBLIC_BASE_URL` | request-derived | your public URL, used to build the wallet's delivery address; set it behind a proxy |
| `ORDER_TTL_MS` | `1800000` (30m) | how long an unpaid order stays valid |
| `PROOF_COUNT_MARGIN` | `4` | dust guard (see [How it works](#how-it-works)) |
| `PROOFS_PATH` | memory | locked-receipt file |
| `PEER_LEDGER_PATH` | memory | lease ledger file |
| `ORDERS_PATH` | memory | pending-order file |
| `LOCK_COUNTER_PATH` | memory | xpub lock index counter file |

Leave the `*_PATH` vars unset to keep state in memory (handy for dev; lost on
restart).

## HTTP API

- `GET /` — buyer page · `GET /client.js` — its bundle
- `GET /health` · `GET /info` — status, price, accepted mints
- `POST /purchase` `{clientPublicKey}` — returns **402** with an `orderId` and a
  payment request. (Agents can instead retry with an `X-Cashu` header to pay and
  receive the config in one shot.)
- `POST /pay/:orderId` — where a paying wallet delivers its proofs
- `GET /order/:orderId` — poll your order; returns the `.conf` once it's ready

There's no endpoint that lists everyone's leases — orders are private to whoever
holds the order id.

## How it works

The flow, end to end:

```
buyer                              daemon                         mint
  │  POST /purchase (no payment)     │                             │
  │ ───────────────────────────────►│  402 + orderId + request     │
  │ ◄───────────────────────────────│  (locked to your key,        │
  │                                  │   deliver to /pay/:orderId)  │
  │  pay LN invoice / mint ecash ───────────────────────────────► mint
  │  POST /pay/:orderId  {proofs} ──►│  verify offline, add peer    │
  │  GET /order/:orderId (poll) ────►│  ◄ ready + WireGuard .conf   │
```

**Non-custodial by design.** The payment request demands proofs locked (NUT-11
P2PK) to a key you control. The daemon stores those locked proofs but can't spend
them — only your offline key can. So the server never holds spendable money.

**Verified offline, no swap.** When proofs arrive the daemon checks them locally:
the mint's signature is genuine (NUT-12 DLEQ, against a cached public keyset),
they're locked to your key, the amount covers the price, the mint is one you
accept, and they're not a replay. The buyer's wallet did the minting, so your
server never makes a per-sale call to the mint.

**Privacy.** With `OPERATOR_XPUB` set, each sale locks to a fresh derived child
key, so the mint can't tie your sales together. You sweep with the matching
offline `xprv`. (A single fixed `OPERATOR_PUBKEY` also works but is correlatable.)

**Dust guard.** A buyer could try to grief you by paying in hundreds of tiny
proofs that cost you fees to claim. The daemon rejects any token with more proofs
than a normal split needs (`popcount(amount) + PROOF_COUNT_MARGIN`) before storing
it, so a griefer's token just stays locked and useless to them.

**No shell.** WireGuard commands run as argv arrays through `execFile` with a
strict allowlist and key/IP validation, so a malicious public key can't smuggle in
a command.

## Project layout

```
src/
  server.ts     HTTP server, per-order payment flow, buyer page
  cashu.ts      payment request + offline verification
  orders.ts     pending-order store (capability ids)
  locks.ts      per-sale lock keys from your xpub
  hdkeys.ts     BIP32 watch-only derivation
  wallet.ts     locked-receipt store
  peers.ts      IP allocation + lease ledger
  wireguard.ts  wg/ip command planning + execution
  ratelimit.ts  per-IP limiter
  buyer.ts      shared buyer-side helpers (also bundled for the browser)
  client.ts     browser bundle
  discover.ts   read interface key/port/endpoint
  sweep.ts      offline sweep + prune
```

## Scripts

| Command | Does |
|---|---|
| `npm run build` | compile (tsc) + bundle the browser client (esbuild) |
| `npm test` / `npm run lint` / `npm run typecheck` | checks |
| `npm start` | run the daemon |
| `npm run discover [iface] [host]` | read key/port/endpoint off a live interface |
| `npm run sweep:remote user@host` | pull receipts, claim locally, prune the box |
| `npm run sweep` | claim a local `proofs.json` (needs `OPERATOR_XPRV`) |
| `npm run prune` | drop already-claimed receipts from a `proofs.json` |

## Before you go public

This is FOSS and not yet hardened for unattended public operation. Before running
one for real:

- put it behind TLS and a process supervisor (systemd)
- keep `CLEANUP_INTERVAL_MS` set so expired peers get removed
- tune `RATE_LIMIT_*` for your traffic
- use a real `OPERATOR_XPUB` and keep the `xprv` offline

And the obvious one: operators run their own exit, so the traffic leaving your box
is your responsibility. This software doesn't route or proxy any of it for you.
