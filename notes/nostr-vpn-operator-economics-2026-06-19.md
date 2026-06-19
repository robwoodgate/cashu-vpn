# Nostr VPN operator economics and risk calculator - 2026-06-19

## Verdict

Go forward only with a **bounded 3-hour operator trial offer anchored at 250 sats**, and position it as evidence collection, not meaningful income yet.

The economics are barely credible on a cheap EU VPS at modest utilization, but the operator risk is not priced in. The first offer must therefore be allowlisted, rate-limited, visible, and instantly reversible. A 24-hour or 7-day pass at the modeled prices is a no-go unless repriced upward or bundled with much stricter data caps.

## Assumptions

- BTC/USD spot: **$62,614.435** from Coinbase at execution time.
- VPS baseline: **EUR5.00/month all-in assumption** for one small Hetzner-style EU WireGuard host, including a small buffer over the historically cheap CX22-class price and IPv4/rounding noise.
- Bandwidth baseline: EU Hetzner-style allowance is assumed to be large enough for a bounded trial. Hetzner docs say cloud billing is for outgoing traffic and overage starts after included traffic; recent public pricing signals still reference large EU allowances, but June 2026 cloud price changes mean this should be treated as an assumption, not a durable quote.
- FX simplification: **EUR1 = USD1.08**, so EUR5.00/month is modeled as **$5.40/month**.
- Monthly hours: **730**.
- Break-even VPS cost: **8,624 sats/month** at the BTC/USD rate above.
- Utilization means paid lease time as a share of calendar time for one exit slot. It does not assume simultaneous peer scaling.

## Gross monthly revenue

| Offer | Full-utilization gross | 5% utilization | 20% utilization | 50% utilization | Break-even utilization |
|---|---:|---:|---:|---:|---:|
| 250 sats / 3h | 60,833 sats / $38.09 | 3,042 sats / $1.90 | 12,167 sats / $7.62 | 30,417 sats / $19.05 | 14.2% |
| 1,000 sats / 24h | 30,417 sats / $19.05 | 1,521 sats / $0.95 | 6,083 sats / $3.81 | 15,208 sats / $9.52 | 28.4% |
| 5,000 sats / 7d | 21,726 sats / $13.60 | 1,086 sats / $0.68 | 4,345 sats / $2.72 | 10,863 sats / $6.80 | 39.7% |

## Sensitivity

- At the modeled VPS cost, the **250 sats / 3h** offer pays server cost at roughly **14% utilization**, which is about **102 paid hours/month** or **34 leases/month**.
- The **1,000 sats / 24h** offer needs roughly **28% utilization**, about **207 paid hours/month** or **9 leases/month**. It can cover hosting, but it leaves the operator underpaid for abuse exposure.
- The **5,000 sats / 7d** offer needs roughly **40% utilization**, about **290 paid hours/month** or **2 weekly leases/month**. That sounds achievable, but it locks risk onto the operator for too long at too little gross revenue.
- If the real host cost lands closer to EUR10/month, break-even roughly doubles: the 3-hour offer needs about **28% utilization**, the 24-hour offer about **57%**, and the 7-day offer about **79%**.
- If outgoing traffic is capped to a conservative **10 Mbps per active lease**, a 100% utilized single slot is roughly **3.3 TB/month**, below a typical large EU allowance. At **50 Mbps**, the same slot is roughly **16.4 TB/month**. At **100 Mbps**, it is roughly **32.9 TB/month**, which can blow through a 20 TB-style allowance. Rate limiting matters more than CPU here.

## Minimum abuse-control promise

The first operator offer must promise all of this before asking anyone to run an exit:

- One disposable or explicitly selected operator host only.
- One active buyer slot for the first trial.
- Buyer allowlist or manual approval; no public open signup.
- Short leases first: default to 3 hours, no 7-day pass in the first operator trial.
- Visible lease ledger: buyer key, tunnel IP, expiry, status, and removal evidence.
- One-command remove/teardown path already exercised in the packet.
- Rate cap target: start at **10 Mbps** per active lease unless the operator opts up.
- Hard monthly egress stop or alert threshold before provider overage.
- Clear prohibited-use policy and no claim of anonymity, legal protection, or production reliability.

## Go / no-go recommendation

**Go** for a first bounded operator offer only as: **250 sats for 3 hours, one allowlisted buyer slot, 10 Mbps cap, immediate teardown, and evidence-first framing**.

**No-go** for pitching passive income, open public access, 24-hour default passes, or 7-day leases. Those variants do not compensate the operator for IP reputation and legal complaint risk at this stage.

## Next validation action

Prepare one internal operator offer brief for Rob approval: target profile, exact 3-hour offer, abuse-control promise, pass/fail criteria, and outbound message copy. Do not contact operators until Rob approves the copy and target.
