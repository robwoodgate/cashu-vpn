# Nostr VPN Hetzner App-Image Live Smoke Evidence - 2026-06-19

## Result

Pass. This is the missing Hetzner WireGuard app-image adoption proof, not the earlier plain-Ubuntu smoke.

The host at `157.180.114.119` was a Hetzner WireGuard one-click app image. It had WireGuard, WireGuard UI, Caddy, nftables, and Hetzner setup scripts installed, but the first-login app setup had not been run yet, so `wg0` did not exist.

I ran Hetzner's own `/opt/hcloud/wireguard_setup.sh` once with a temporary `nip.io` hostname, which created the app-managed `wg0` interface. Then I ran the marketplace bounded add/remove path against `wg0` without editing `/etc/wireguard/wg0.conf`.

## Host

- Host: `157.180.114.119`
- Hostname: `ubuntu-4gb-hel1-1`
- Provider/model: Hetzner vServer
- OS: Ubuntu 24.04.1 LTS
- Image evidence: `/etc/hetzner-build` present, build date `2025-01-05T04:17:28Z`
- App components found before setup: `/opt/hcloud/wireguard_setup.sh`, `/usr/local/bin/wireguard-ui`, `/usr/local/bin/caddy`, `/etc/default/wireguard-ui`, `/etc/caddy/Caddyfile`, WireGuard packages

## App Setup

Before setup:

```text
wg: /usr/bin/wg
wg show: no interfaces
ip route show dev wg0: Cannot find device "wg0"
/etc/wireguard: empty
wireguard-ui.service: inactive
caddy.service: inactive
wg-quick@wg0.service: inactive
```

After running Hetzner's setup:

```text
wireguard-ui: active
caddy: active
wg-quick@wg0: active
nftables: active

interface: wg0
  public key: nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=
  listening port: 51820

172.30.0.0/24 proto kernel scope link src 172.30.0.1
```

Initial `wg0.conf` hash:

```text
34a33b9401804109921f7262024408fd0e1c5e294e07e7bd8f94e4820a7f8c08  /etc/wireguard/wg0.conf
```

## Discovery

The marketplace operator CLI discovery was non-mutating:

```json
{
  "interfaceName": "wg0",
  "serverPublicKey": "nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=",
  "listenPort": "51820",
  "endpoint": "157.180.114.119:51820",
  "routeContext": "172.30.0.0/24 proto kernel scope link src 172.30.0.1",
  "hostMutationPerformed": false
}
```

## Add Peer

- Purchase id: `hetzner-app-image-smoke-2026-06-19`
- Assigned tunnel IP: `10.77.0.101`

The guarded operator CLI executed only the expected add commands:

```text
wg set wg0 peer <client-public-key> allowed-ips 10.77.0.101/32
ip route replace 10.77.0.101/32 dev wg0
```

Execution report:

```json
{
  "executed": true,
  "hostMutationPerformed": true,
  "results": [0, 0],
  "mode": "real",
  "dryRun": false,
  "leaseRecorded": true
}
```

Live verification immediately after add showed the peer active and the route present:

```text
peer: <client-public-key>
  allowed ips: 10.77.0.101/32

10.77.0.101 scope link
```

The `wg0.conf` hash remained unchanged:

```text
34a33b9401804109921f7262024408fd0e1c5e294e07e7bd8f94e4820a7f8c08  /etc/wireguard/wg0.conf
```

## Remove Peer

The guarded operator CLI removed the same marketplace-owned peer through the ledger-backed rollback path:

```text
wg set wg0 peer <client-public-key> remove
ip route del 10.77.0.101/32 dev wg0
```

Execution report:

```json
{
  "executed": true,
  "hostMutationPerformed": true,
  "results": [0, 0]
}
```

Post-removal verification:

```text
interface: wg0
  public key: nKpu1TI56v6JqS+wxnhMd+hBQJ8X15y7075zpATtJWU=
  listening port: 51820

routes on wg0:
172.30.0.0/24 proto kernel scope link src 172.30.0.1

ledger status: expired
```

No marketplace peer or `10.77.0.101` route remained on `wg0`. The final `wg0.conf` hash still matched the initial hash:

```text
34a33b9401804109921f7262024408fd0e1c5e294e07e7bd8f94e4820a7f8c08  /etc/wireguard/wg0.conf
```

## Remote Evidence

Remote evidence remains on the VPS:

```text
/root/nostr-vpn-marketplace/evidence/hetzner-app-image-smoke-2026-06-19-discover.json
/root/nostr-vpn-marketplace/evidence/hetzner-app-image-smoke-2026-06-19-purchase.json
/root/nostr-vpn-marketplace/evidence/hetzner-app-image-smoke-2026-06-19-remove.json
/root/nostr-vpn-marketplace/evidence/hetzner-app-image-smoke-2026-06-19-post-add.txt
/root/nostr-vpn-marketplace/evidence/hetzner-app-image-smoke-2026-06-19-post-remove.txt
/var/lib/nostr-vpn-marketplace/interface-evidence-hetzner-app-image-smoke-2026-06-19.txt
/var/lib/nostr-vpn-marketplace/rollback-evidence-hetzner-app-image-smoke-2026-06-19.txt
/var/lib/nostr-vpn-marketplace/peer-ledger.json
```

## Local Gates

Local gates passed before the app-image smoke:

```text
npm test
npm run lint
npm run typecheck
```

`npm test` passed 44/44 tests.

## Verdict

The Hetzner WireGuard app image is compatible with the marketplace operator path after the official first-run setup creates `wg0`.

The important proof: marketplace add/remove can safely adopt the existing app-managed `wg0` using live `wg set` and `ip route` commands, while leaving `/etc/wireguard/wg0.conf` unchanged and using the ledger-backed rollback boundary.
