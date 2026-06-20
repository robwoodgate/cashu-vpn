# cashu-vpn hardened demo — LIVE (2026-06-20)

Deployed the hardened build as a systemd service behind the existing Caddy TLS,
once Rob unlocked his machine and SSH returned.

## What's running

- `https://vpn-157-180-114-119.nip.io` → Caddy → `127.0.0.1:3087`
- systemd unit `cashu-vpn` (Restart=always, **enabled** = survives reboot),
  node 20 via nvm, EnvironmentFile `/root/cashu-vpn/cashu-vpn.env`.
- Config (intentionally "up but not casually usable"):
  - `ACCEPTED_MINTS=https://mint.minibits.cash/Bitcoin`
  - `PRICE_SATS=1000000` (≈$600 — flex this down to test live)
  - `OPERATOR_XPUB` = throwaway test key (state/test-key.json); swap for a real
    xpub for real operation, xprv kept offline
  - `LEASE_DURATION_MS=600000`, `CLEANUP_INTERVAL_MS=60000`, rate limit on
  - `HOST=127.0.0.1` (private behind Caddy)

## Verified

- Public `GET /health` → 200 `{ok:true,mode:live}`.
- `GET /info` → price 1000000, minibits, unit sat, `lock: xpub-per-tx`.
- `POST /purchase` (no payment) → `402` + `x-cashu: creqA…` over public HTTPS.
- Box clean: `wg show wg0` 0 `10.77` peers; `cashu-vpn` active+enabled;
  `/etc/wireguard/wg0.conf` sha256 `34a33b94…` unchanged.

## To test live (Rob)

Edit `/root/cashu-vpn/cashu-vpn.env` — lower `PRICE_SATS` (and set your real
`OPERATOR_XPUB` if you want to keep the sats) — then `systemctl restart cashu-vpn`.
Manage: `systemctl status|restart|stop cashu-vpn`, logs `journalctl -u cashu-vpn -f`.
Sweep earnings off-box: `OPERATOR_XPRV=… PROOFS_PATH=/root/cashu-vpn/state/proofs.json npm run sweep`.
Real tunnels: UDP/51820 is open, so a bought `.conf` connects.
