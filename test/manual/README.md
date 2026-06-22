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
DAEMON=https://vpn.example.com node test/manual/pay-header.mjs
```

- **pay-order.mjs** — the per-order flow: `POST /purchase` → pay → `POST /pay/:id`
  → poll `GET /order/:id`. This is what a browser/NUT-18 wallet does.
- **pay-header.mjs** — the single-request NUT-24 flow: pay and retry `POST
  /purchase` with an `X-Cashu` header. This is what an automated client does.

Use a test mint such as `https://testnut.cashudevkit.org` (free) so you're not
spending real sats, and make sure the daemon's `ACCEPTED_MINTS` includes it.
