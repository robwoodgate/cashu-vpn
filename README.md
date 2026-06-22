# cashu-vpn

cashu-vpn lets you sell short-lived WireGuard VPN access for Cashu ecash. There are no accounts, no subscriptions, and no ecash sitting on your server waiting to be stolen.

A buyer opens your page, pays with Lightning or a Cashu wallet, and their browser hands them a ready-to-use WireGuard config. You collect the ecash and claim it later with a key that never touches the server.

It is freedom tech rather than a product. The whole idea is that anyone can run one, so this guide assumes no special knowledge beyond being comfortable in a terminal.

## How it works

When someone wants access, their browser asks your cashu-vpn daemon for a config. The daemon replies that payment is due and hands back a Cashu payment request locked to a public key that you control (P2PK).

The buyer pays, their wallet (or the built-in Lightning option) delivers the ecash straight back to cashu-vpn, which checks the payment, adds them as a WireGuard peer, and returns the config. The page then shows the finished `.conf` to download.

The money you receive is locked to your key, so even if someone steals the whole server they cannot spend a single sat. You claim your earnings separately, on your own computer, with a private key that never goes near the box. More detail is in [Under the hood](#under-the-hood).

## Try it first, with no risk

Before touching a real server or any money, you can run the whole thing locally. Clone the project, install, build, and start it in its default dry-run mode:

```bash
git clone https://github.com/robwoodgate/cashu-vpn.git && cd cashu-vpn
npm install && npm run build
npm start
```

Open `http://localhost:3087` and click through the buyer flow. In dry-run mode nothing is charged and no changes are made to your machine, so it is a safe way to see exactly what your buyers will experience.

## Set up your own VPN

You need a Linux server with Node.js 20 or newer, root access, and a domain name pointed at the server so it can get an HTTPS certificate. The two host-level pieces are WireGuard and a reverse proxy; the steps below cover both.

**1. Get the project onto the server and build it.**

```bash
git clone https://github.com/robwoodgate/cashu-vpn.git && cd cashu-vpn
npm install && npm run build
```

**2. Set up WireGuard.** If you do not already have a WireGuard interface, create a minimal one:

```bash
umask 077

# Generate the server key pair
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub

# Write a minimal interface config
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/server.key)
EOF

# Bring it up now and on boot
wg-quick up wg0
systemctl enable wg-quick@wg0

# Open the listen port in your firewall (example: UFW)
ufw allow 51820/udp

# Optional: let buyers reach the internet through the box
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE   # eth0 = your public interface

# Recommended on any real exit: tune kernel buffers + enable BBR, or throughput
# is capped to tens of Mbit/s by the small default socket buffers (see Troubleshooting)
sudo scripts/tune-perf.sh
```

Whether you create `wg0` here or already had one, cashu-vpn attaches and removes buyer peers on it at runtime with `wg set` and `ip route`, and never edits `wg0.conf`.

**3. Read your WireGuard details.** This reads your server's public key, port, and public address off the live interface without changing anything. Note them down.

```bash
npm run discover wg0
```

**4. Create your payout key.** On your own computer — not the server — generate a BIP32 HD key pair:

```bash
npm run keygen
```

It prints an `OPERATOR_XPUB` and an `OPERATOR_XPRV`. cashu-vpn uses the `xpub` to lock each sale to a fresh key and can never spend; only the `xprv` can. Put the `xpub` on the server in the next step, and keep the `xprv` somewhere safe and offline — that string is your only backup and it controls your funds.

**5. Configure.** Copy the sample config and fill it in with the values from steps 3 and 4:

```bash
cp .env.example .env
nano .env   # set SERVER_PUBLIC_KEY, WG_ENDPOINT, OPERATOR_XPUB, PUBLIC_BASE_URL, DOMAIN
```

**6. Install it as a service.** This writes a systemd unit that runs the daemon from your `.env`, starts it on boot, and restarts it if it crashes. If you set `DOMAIN` in `.env` and have [Caddy](https://caddyserver.com) installed, it also adds an HTTPS site that proxies to the daemon and fetches a certificate automatically.

```bash
sudo scripts/install-systemd.sh
```

That is it. If you would rather wire up TLS yourself, leave `DOMAIN` blank: the daemon listens on `127.0.0.1:3087`, so point any reverse proxy at it over HTTPS. Browsers need HTTPS for the in-page key generation, and `PUBLIC_BASE_URL` must be your public address so paying wallets know where to deliver.

To update later, pull and restart in one step from the repo on the server:

```bash
npm run update
```

## Getting paid

Everything you earn is stored as ecash locked to your offline key. The server only ever holds the watch-only `xpub` and a list of locked receipts in `state/proofs.json`, so there is nothing on it worth stealing. Claiming is a quick step you run on your own computer, where the `xprv` lives.

One command does it all:

```bash
OPERATOR_XPRV=<your xprv> npm run sweep:remote root@your-box
```

This copies the receipts off the server, claims them locally so your `xprv` never leaves your machine, saves the unlocked tokens to a timestamped file, and tidies the claimed receipts off the server afterwards. Import the saved tokens into any Cashu wallet and you are done.

If you would rather do it by hand, the same thing in two steps is to copy the receipts down and sweep them locally:

```bash
scp root@your-box:/root/cashu-vpn/state/proofs.json ./proofs.json
OPERATOR_XPRV=<your xprv> PROOFS_PATH=./proofs.json npm run sweep
```

A sweep is cheap because all of a mint's receipts are claimed in a single swap, so you pay the mint's fee once for the batch rather than once per sale. It is also safe to run as often as you like: the sweep first asks the mint which receipts are already claimed and skips them, so it never double-claims or errors out on a repeat run. To keep `state/proofs.json` from growing forever, `npm run prune` drops already-claimed receipts from it. Prune only reads spend status from the mint and needs no key, so it is safe to run on the server, and the remote sweep does it for you.

> The demo deploy keeps a throwaway `xprv` in `state/test-key.json` so unattended test sweeps work. Never do that with real money. Generate your key offline and keep the `xprv` off the server.

## What your buyers see

A buyer opens your page and clicks **Get VPN config**. Their browser generates a WireGuard key pair on the spot, and the private key never leaves the page. They then pay one of two ways. The Lightning option needs no Cashu wallet at all: they pay an invoice and the page mints the ecash and delivers it for them. Alternatively, they scan the payment request with a Cashu wallet, which pays and delivers automatically. Either way the page finishes on its own and offers a ready-to-use `.conf` to download.

To connect, they import it into the free [WireGuard app](https://www.wireguard.com/install/), a separate app, not the VPN settings built into macOS or Windows, and the page links to it and shows a QR for one-tap import on mobile. Past orders are remembered under **Your access** in that browser, where each shows whether it is active or expired, so they can be downloaded again later.

> Paying from a Cashu wallet needs a wallet that locks its proofs to the payment request. Wallets that ignore the lock are refused, because cashu-vpn never accepts unlocked ecash. The Lightning option works with any wallet, and most ecash-only wallets can melt to pay it.

## Settings

Everything is configured with environment variables.

| Variable | Default | What it does |
|---|---|---|
| `MODE` | `dry-run` | set to `live` to take payment and manage real WireGuard peers |
| `HOST` / `PORT` | `127.0.0.1` / `3087` | address the daemon listens on |
| `WG_INTERFACE` | `wg0` | the WireGuard interface to manage |
| `SERVER_PUBLIC_KEY` | — | your server's WireGuard public key, included in the buyer's config |
| `WG_ENDPOINT` | — | the `host:port` buyers connect to |
| `OPERATOR_XPUB` | — | your BIP32 xpub, used to lock each sale to a fresh key (recommended) |
| `OPERATOR_PUBKEY` | — | a single fixed lock key, used if you have no xpub; live mode needs one of these |
| `ACCEPTED_MINTS` | minibits | comma-separated list of mint URLs you accept |
| `PRICE_SATS` | `1000` | price per lease, roughly one US dollar a day at recent prices |
| `MINT_UNIT` | `sat` | the Cashu unit |
| `NOTICE` | — | optional operator notice (MOTD) shown on the page and in `/info` |
| `TERMS_URL` | — | optional acceptable-use / terms URL, linked on the page and in `/info` |
| `LEASE_DURATION_MS` | `86400000` | how long access lasts, one day by default |
| `CLEANUP_INTERVAL_MS` | `60000` | how often to remove expired peers and run retention; set `0` to disable |
| `RETAIN_EXPIRED_MS` | `86400000` (1 day) | how long expired leases/orders are kept before they are forgotten; `0` keeps everything |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | `30` / `60000` | per-IP limit on `/purchase`; set max to 0 to disable |
| `PUBLIC_BASE_URL` | from request | your public URL, used to tell wallets where to deliver payment |
| `ORDER_TTL_MS` | `1800000` | how long an unpaid order stays valid, 30 minutes by default |
| `PROOF_COUNT_MARGIN` | `4` | dust-payment guard, explained in [Under the hood](#under-the-hood) |
| `PROOFS_PATH` | memory | file for the locked receipts you will sweep |
| `PEER_LEDGER_PATH` | memory | file for the lease ledger |
| `ORDERS_PATH` | memory | file for pending orders |
| `LOCK_COUNTER_PATH` | memory | file for the xpub lock counter |

Leave the file path settings unset to keep state in memory, which is handy for development but lost on restart.

## The HTTP endpoints

The buyer page is served at `/`, with its script at `/client.js`. `GET /health` and `GET /info` report status, price, and accepted mints. A buyer starts with `POST /purchase`, sending their WireGuard public key, and gets back a `402` response carrying an order id and a payment request. Their wallet then delivers the paid ecash to `POST /pay/:orderId`, and the browser watches `GET /order/:orderId` until the config is ready. An automated client can skip the back-and-forth by retrying `POST /purchase` with an `X-Cashu` header to pay and receive the config in one request.

There is deliberately no endpoint that lists everyone's leases. Each order is private to whoever holds its order id.

## Under the hood

```
buyer                              daemon                         mint
  │  POST /purchase (no payment)     │                              │
  │ ───────────────────────────────► │  402 + orderId + request     │
  │ ◄─────────────────────────────── │  (locked to your key,        │
  │                                  │   deliver to /pay/:orderId)  │
  │  pay LN invoice / mint ecash ───────────────────────────────► mint
  │  POST /pay/:orderId  {proofs} ──►│  verify offline, add peer    │
  │  GET /order/:orderId (poll) ────►│  ◄ ready + WireGuard .conf   │
```

The design is non-custodial by construction. The payment request demands proofs locked to a key you control, using NUT-11 pay-to-public-key. cashu-vpn stores those locked proofs but cannot spend them, because only your offline key can. The server therefore never holds spendable money.

Payments are verified entirely offline, with no swap and no per-sale call to the mint. When proofs arrive cashu-vpn checks, against a cached copy of the mint's public keys, that the mint genuinely signed them (NUT-12 DLEQ), that they are locked to your key, that the amount covers the price, that the mint is one you accept, and that they are not a replay. Because the buyer's wallet does the minting, your server never generates mint traffic of its own.

Privacy comes from the xpub. With `OPERATOR_XPUB` set, every sale is locked to a fresh derived key, so the mint cannot tie your sales together, and you sweep them all with the matching offline key. A single fixed `OPERATOR_PUBKEY` also works but lets the mint correlate your income.

A dust guard protects you from griefing. Someone could try to pay in hundreds of tiny proofs that would each cost you a fee to claim, so cashu-vpn rejects any payment with more proofs than a normal split needs, which is the number of set bits in the amount plus `PROOF_COUNT_MARGIN`. The rejected payment simply stays locked to you and useless to the sender.

Finally, there is no shell anywhere near WireGuard. Commands run as argument arrays through `execFile` with a strict allow-list and key and address validation, so a malicious public key cannot smuggle in a command.

## Project layout

```
src/
  server.ts     HTTP server, per-order payment flow, buyer page
  cashu.ts      payment request and offline verification
  orders.ts     pending-order store keyed by capability id
  locks.ts      per-sale lock keys derived from your xpub
  hdkeys.ts     BIP32 watch-only key derivation
  wallet.ts     store of locked receipts
  peers.ts      IP allocation and lease ledger
  wireguard.ts  wg/ip command planning and execution
  ratelimit.ts  per-IP rate limiter
  buyer.ts      buyer-side helpers, also bundled into the browser
  client.ts     browser bundle
  keygen.ts     generate an operator xpub/xprv pair (offline)
  discover.ts   reads interface key, port, and endpoint
  sweep.ts      offline sweep and prune
scripts/
  install-systemd.sh   install as a systemd service (+ optional Caddy site)
  update.sh            pull, reinstall, rebuild, restart (npm run update)
  egress-filter.sh     restrict buyer egress to DNS + web + ICMP
  upstream-egress.sh   route buyer egress through an upstream WireGuard VPN
  tune-perf.sh         raise socket buffers + enable BBR for a high-RTT exit
  sweep-remote.sh      pull receipts, sweep locally, prune the server
test/
  core.test.ts         unit and HTTP tests (npm test)
  manual/              live integration clients (see test/manual/README.md)
```

## Commands

| Command | What it does |
|---|---|
| `npm run build` | compile the daemon and bundle the browser client |
| `npm test` / `npm run lint` / `npm run typecheck` | the checks |
| `npm start` | run the daemon |
| `npm run update` | pull latest, reinstall, rebuild, restart the service (run on the server) |
| `npm run keygen` | generate an operator xpub/xprv pair (run offline) |
| `npm run discover [iface] [host]` | read key, port, and endpoint off a live interface |
| `npm run sweep:remote user@host` | pull receipts, claim them locally, and prune the server |
| `npm run sweep` | claim a local `proofs.json`, using your `OPERATOR_XPRV` |
| `npm run prune` | drop already-claimed receipts from a `proofs.json` |

## Before you run one for real

This is FOSS and is not yet hardened for unattended public operation. Before you open it up, put it behind HTTPS and a process supervisor such as systemd, tune the rate limit for your traffic, and use a real `OPERATOR_XPUB` with the `xprv` kept offline.

And the obvious thing: when you run an exit, the traffic leaving your server is your responsibility. This software does not route or proxy any of it for you, and it makes no promise of anonymity or legal protection.

**Limiting exit abuse.** Because buyers exit from your IP, you'll want to bound what they can do. `scripts/egress-filter.sh` restricts buyer egress to DNS + HTTP/HTTPS + ICMP, which removes the abuse that gets host accounts suspended (outbound spam, port scanning, brute-forcing, most torrenting) while normal browsing keeps working. For stronger insulation, `scripts/upstream-egress.sh` routes the buyer subnet out through a separate upstream WireGuard VPN — abuse complaints then land on that upstream rather than your host, and a killswitch drops buyer traffic if the tunnel goes down so nothing leaks out your real IP. Use an upstream whose terms permit this (running your own second VPS avoids any question). The two stack. A `NOTICE` / `TERMS_URL` can also state your acceptable-use policy on the page.

## Troubleshooting

**Buyer connects but has no internet.** The tunnel hands shakes, but pages won't load. Almost always one of two things, in this order:

- **No DNS in the config.** A full-tunnel config (`AllowedIPs = 0.0.0.0/0`) needs an explicit `DNS =` line, or the client keeps its LAN resolver — which is unreachable through the tunnel — and names silently stop resolving. The daemon writes this line for you from `WG_DNS` (default `1.1.1.1`); only older hand-made configs lack it. Tell-tale sign: on the box, the egress DNS counter stays at zero while 443 still moves — `iptables -L CASHU_EGRESS -v -n` shows `0 packets` on the `dpt:53` rules. Fix a stuck config by adding `DNS = 1.1.1.1` under `[Interface]` and reconnecting.
- **No NAT / masquerade.** Buyer packets get forwarded out with their private `10.77.0.x` source and the replies never come back. Add the rule from setup: `iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE`.

  Gotcha: if WireGuard was brought up by `wg-quick`/`systemd-networkd`, the masquerade may already exist as a **native nftables** rule (`iifname "wg0" masquerade`) — which is invisible to `iptables -t nat -S`. Always check `nft list ruleset` before concluding NAT is missing, or you'll add a duplicate.

**Tunnel works but is slow (tens of Mbit/s).** An exit is usually far from the buyer, so the bandwidth-delay product is large — but the kernel defaults to ~208 KB socket buffers (which caps a flow at roughly buffer ÷ RTT, e.g. ~27 Mbit/s at 60 ms, and starves WireGuard's UDP socket) and to CUBIC congestion control (which collapses on the path's loss). Run `sudo scripts/tune-perf.sh` to raise the buffers to 16 MB and switch to BBR + `fq`; it's persistent across reboot. In one test (UK→Helsinki, ~62 ms) this took download from ~37 to ~140 Mbit/s. Confirm with `iperf3` over the tunnel — a slow link shows a high `Retr` count under load even when an idle `ping` reports 0% loss. Upload stays bounded by the buyer's own uplink and OS, so box-side tuning barely moves it.

## License

[MIT](LICENSE).
