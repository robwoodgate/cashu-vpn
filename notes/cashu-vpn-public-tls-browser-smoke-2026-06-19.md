# cashu-vpn public TLS + browser smoke — 2026-06-19

## Result

**Pass.** The full buyer flow runs in a real browser over public HTTPS, end to end,
producing a usable WireGuard config. Closes the task-#6 "browser click-through"
caveat (WebCrypto, mint CORS, QR, DOM wiring) — all now proven, not just built.

## Public TLS (Caddy, additive)

- Added a site to the box's existing Caddy (WG-UI site on `:5000` left intact;
  Caddyfile backed up to `Caddyfile.bak.cashuvpn`, `caddy validate` before reload):
  ```
  vpn-157-180-114-119.nip.io { reverse_proxy 127.0.0.1:3087 }
  ```
- ACME succeeded immediately (nip.io already worked for the WG-UI host).
- Firewall: TCP 80/443 (Caddy/ACME) + TCP 22 + **UDP 51820** (Rob opened it — real
  tunnels now connect). Daemon stays on `127.0.0.1:3087`, private behind Caddy.

## Browser smoke (headless Chrome via Playwright, local → public URL)

Daemon: live, xpub mode, throwaway test key, `ACCEPTED_MINTS=testnut.cashudevkit.org`,
`PRICE_SATS=5`, behind Caddy at `https://vpn-157-180-114-119.nip.io`.

Steps executed in-browser:
1. Load page over public TLS → OK.
2. Click "Get VPN config" → **WebCrypto X25519 keygen** + POST → **402** shown.
3. Click "Generate Lightning invoice" → browser **minted P2PK-locked proofs (DLEQ)
   at testnut in-browser (CORS OK)**, testnut auto-paid, delivered via `X-Cashu`.
4. Daemon verified offline → added peer `10.77.0.44` → returned a usable `.conf`:
   ```
   [Interface]
   Address = 10.77.0.44/32
   PrivateKey = <browser-generated>
   [Peer]
   PublicKey = nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=
   Endpoint = 157.180.114.119:51820
   AllowedIPs = 0.0.0.0/0
   PersistentKeepalive = 25
   ```
   Asserts passed: PrivateKey, Address 10.77.0.x, server PublicKey, Endpoint.

## Cleanup / state

- Smoke peer removed; `wg show wg0` shows no `10.77` peers; `wg0.conf` sha256
  `34a33b94…` unchanged.
- Test daemon **stopped** — not left publicly accepting peers (testnut = free, no
  rate-limiting yet). Caddy site persists; restart with `notes/start-daemon.sh`.

## Before a real public launch

- `/purchase` per-IP rate limiting (free/cheap mints + no auth = peer-spam vector).
- A systemd unit for the daemon (currently a detached process) + a cleanup interval
  (`CLEANUP_INTERVAL_MS`) so expired peers are removed.
- Real operator config: real `OPERATOR_XPUB` (private!), a production mint, real price.
- Harness scripts live in notes/: setup-tls, start-daemon, servecheck, stageA/B,
  testclient, cleanup.
