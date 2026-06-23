# Manual integration clients

These are not part of `npm test`. They drive a **running daemon** end to end
against a **real mint**, the way a buyer's wallet would, and print what happened
at each step. Use them to sanity-check a live deployment.

Each generates its own throwaway WireGuard key, reads the daemon's payment
request, mints proofs locked to the request's key at the named mint, pays, and
confirms a config comes back.

```bash
# Point at your daemon (defaults to http://127.0.0.1:3087)
DAEMON=https://vpn.example.com node test/manual/pay-order.mjs
```

- **pay-order.mjs** — the delivery flow: `POST /purchase` → decode the creqA →
  mint locked proofs → `POST /pay/:id`. The `.conf` comes back in the `/pay`
  response (what an agent reads); the script also polls `GET /order/:id`, the way
  the browser does (the browser isn't the one POSTing to `/pay`).

Use a test mint such as `https://testnut.cashudevkit.org` (free) so you're not
spending real sats, and make sure the daemon's `ACCEPTED_MINTS` includes it.
