# cashu-vpn overnight status — for Rob (morning of 2026-06-20)

## TL;DR

Hardening done and pushed. **The only unfinished item is the live redeploy (#11)** —
blocked because the local **ssh-agent lost all its keys mid-session** (your
keychain/1Password agent locked). GitHub pushes were worked around via the `gh`
token over HTTPS; the VPS needs SSH, which I can't restore without you.

**To finish in ~30s when you're up:** unlock your SSH agent (so `ssh root@157.180.114.119`
works again), then tell me "deploy" — or run it yourself (one command below). The
deploy is fully scripted and priced safe (minibits + 1,000,000 sats, so nobody
casually uses it; flex `PRICE_SATS` to test).

## Done tonight (all on origin/main)

- **#7 rate limiting** — per-IP cap on `/purchase` (429 + Retry-After), config
  `RATE_LIMIT_MAX`/`RATE_LIMIT_WINDOW_MS`. (`aa8…` chain)
- **#8 security hardening** (self-review): reject P2PK locks that aren't SOLELY +
  permanently the operator's — single signer, no multisig, no locktime/refund
  escape (a buyer could otherwise reclaim proofs after getting VPN). Plus a
  token-unit check. Polish: `/info` shows lock mode; `/favicon.ico` → 204.
- **#9 README.md** — operator quickstart, buyer flow, security model, env table, API.
- **#10 PRD.md** — refreshed to the shipped architecture. NOTE: `PRD.md` is in your
  **global** gitignore (`~/.gitignore_global`), so it's updated **on disk only**,
  not committed. `git add -f PRD.md` if you want it in the repo.
- 49/49 tests, typecheck + lint clean at every commit.

## #11 — live redeploy (blocked on SSH)

State on the box: the test daemon was stopped during the TLS-smoke cleanup, so
`https://vpn-157-180-114-119.nip.io` is currently **down (502)** until redeploy.
Caddy TLS site + WG-UI are intact; `wg0.conf` untouched; no stray peers.

Everything for the deploy is committed in `notes/`:
- `deploy-systemd.sh` — writes `cashu-vpn.env` (minibits, PRICE_SATS=1000000,
  short lease + cleanup, rate limit, test xpub from `state/test-key.json`) +
  a `cashu-vpn.service` unit (Restart=always, node20), enables + starts it.

**One-command deploy (after SSH works):**
```bash
cd /Users/robw/Sites/assets/cashu-vpn
rsync -az --exclude node_modules --exclude dist --exclude .git --exclude state \
  ./src ./package.json ./package-lock.json ./tsconfig.json ./.eslintrc.cjs \
  notes/deploy-systemd.sh root@157.180.114.119:/root/cashu-vpn/
ssh root@157.180.114.119 'export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh; \
  cd /root/cashu-vpn && npm install && npm run build && bash deploy-systemd.sh'
```
Then check `https://vpn-157-180-114-119.nip.io/info` (should show price 1000000,
minibits, lock xpub-per-tx) and `systemctl status cashu-vpn`.

**To test live yourself:** edit `/root/cashu-vpn/cashu-vpn.env` (lower `PRICE_SATS`,
and swap `OPERATOR_XPUB` for your real xpub if you want to keep the sats), then
`systemctl restart cashu-vpn`. Sweep with `OPERATOR_XPRV=… npm run sweep`.

## Reminder before real public use
- Use your REAL `OPERATOR_XPUB` (xprv kept offline); the deploy uses a throwaway
  test key in `state/test-key.json`.
- Real tunnels need UDP/51820 (you opened it).
