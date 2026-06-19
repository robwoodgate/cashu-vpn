# Nostr VPN Plain-Ubuntu Live Smoke Evidence - 2026-06-19

## Result

Pass, but redundant. Rob clarified the scarce VPS should be preserved rather than rebuilt for a specific Hetzner WireGuard app image. I ran the bounded operator path on the current Hetzner host at `157.180.114.119`.

This reconfirms the plain-Ubuntu/operator-installed mode, which had already been validated on 2026-06-04 using host `188.245.67.111`. It does not validate the distinct Hetzner WireGuard app-image adoption path.

## Host

- Host: `157.180.114.119`
- Hostname: `ubuntu-4gb-hel1-1`
- OS: Ubuntu 24.04.1 LTS
- WireGuard tooling: present
- Node/npm installed for the smoke: Node `v18.19.1`, npm `9.2.0`

## Temporary Interface

- Interface: `wg-demo0`
- Server tunnel address: `10.77.0.1/24`
- Listen port: `51820`
- Endpoint used by the operator CLI: `157.180.114.119:51820`

Discovery was non-mutating and returned:

```json
{
  "mode": "discover-config",
  "hostMutationPerformed": false,
  "interfaceName": "wg-demo0",
  "listenPort": "51820",
  "endpoint": "157.180.114.119:51820",
  "routeContext": "10.77.0.0/24 proto kernel scope link src 10.77.0.1"
}
```

## Add Peer

Purchase id: `hetzner-plain-ubuntu-smoke-2026-06-19`

Assigned tunnel IP: `10.77.0.117`

The guarded operator CLI executed exactly the expected add commands:

```text
wg set wg-demo0 peer <client-public-key> allowed-ips 10.77.0.117/32
ip route replace 10.77.0.117/32 dev wg-demo0
```

Execution report:

```json
{
  "executed": true,
  "hostMutationPerformed": true,
  "requiredAcknowledgement": "APPLY_REAL_WIREGUARD_PEER_ON_DISPOSABLE_VPS",
  "results": [
    { "exitCode": 0 },
    { "exitCode": 0 }
  ]
}
```

Live host verification after add:

```text
peer: <client-public-key>
  allowed ips: 10.77.0.117/32

10.77.0.117 dev wg-demo0 src 10.77.0.1 uid 0
```

The peer lease was recorded in `/var/lib/nostr-vpn-marketplace/peer-ledger.json` as `active`.

## Remove Peer

The guarded operator CLI removed the marketplace-owned peer using the ledger-backed rollback path:

```text
wg set wg-demo0 peer <client-public-key> remove
ip route del 10.77.0.117/32 dev wg-demo0
```

Execution report:

```json
{
  "executed": true,
  "hostMutationPerformed": true,
  "requiredAcknowledgement": "APPLY_REAL_WIREGUARD_PEER_ON_DISPOSABLE_VPS",
  "results": [
    { "exitCode": 0 },
    { "exitCode": 0 }
  ]
}
```

Live host verification after remove:

```text
interface: wg-demo0
  public key: <server-public-key>
  private key: (hidden)
  listening port: 51820
```

No peer remained on `wg-demo0`. The ledger record was marked `expired`.

## Teardown

Because Rob said boxes are in short supply, I preserved the VPS but removed the temporary smoke state:

```text
Device "wg-demo0" does not exist.
Unable to access interface: No such device
ls: cannot access '/tmp/nostr-vpn-client.*': No such file or directory
ls: cannot access '/etc/wireguard/wg-demo0.*': No such file or directory
```

Remote evidence JSON remains under `/var/lib/nostr-vpn-marketplace/`.

## Caveat

This should not be treated as the missing app-image proof. It is a second bounded proof of the plain-Ubuntu path. The app-image-specific question remains separate: can the operator safely adopt a pre-existing Hetzner WireGuard app interface without fighting its config writer?

## Local Gates

All local gates passed after the live smoke:

```text
npm test
npm run lint
npm run typecheck
```

`npm test` passed 44/44 tests.
