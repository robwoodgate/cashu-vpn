/**
 * Best-effort operator notification on a new sale.
 *
 * When NOTIFY_WEBHOOK is set, every freshly provisioned lease POSTs a one-line
 * plain-text body to that URL. The text body is exactly what an ntfy.sh topic
 * (`https://ntfy.sh/your-topic`, hosted or self-hosted) renders natively — no
 * ntfy-specific code — and most other sinks (a generic webhook relay, a script)
 * accept a text body too. Discord/Slack want JSON, so point those at a one-line
 * relay rather than directly.
 *
 * Fire-and-forget by design: a slow or failing webhook must NEVER delay or break
 * an order. We cap the request with a short timeout and swallow errors (logged,
 * not thrown) so the buyer's provision is never coupled to the operator's phone.
 *
 * The message is deliberately PII-free. There are no accounts here; a sale only
 * exposes an order-id prefix, the amount, and the lease expiry — never the
 * buyer's WireGuard key or tunnel IP.
 */

export interface SaleInfo {
  orderId: string;
  amountSats?: number;
  expiresAt: string;
}

export interface Notifier {
  /** Announce a newly provisioned sale. Returns immediately; delivery is async. */
  saleProvisioned(info: SaleInfo): void;
}

/** How long to wait on the webhook before giving up (it must not block orders). */
const NOTIFY_TIMEOUT_MS = 5000;

/** Injectable POST so tests can assert delivery without a real network call. */
export type WebhookPost = (url: string, body: string) => Promise<void>;

/**
 * Build a Notifier. With no `webhookUrl` it's a no-op (the feature is invisible
 * unless the operator opts in via NOTIFY_WEBHOOK). `post` is a test seam.
 */
export function createNotifier(webhookUrl: string | undefined, post: WebhookPost = defaultPost): Notifier {
  if (!webhookUrl) return { saleProvisioned: () => {} };
  return {
    saleProvisioned(info) {
      const sats = info.amountSats === undefined ? '?' : String(info.amountSats);
      const body = `cashu-vpn: new sale ${info.orderId.slice(0, 8)} — ${sats} sat, expires ${info.expiresAt}`;
      // Never await in the request path: detach delivery and swallow failures.
      void post(webhookUrl, body).catch((e) => {
        console.warn(`[notify] webhook delivery failed: ${e instanceof Error ? e.message : e}`);
      });
    },
  };
}

/** Plain text POST with a hard timeout. A non-2xx response is treated as failure. */
async function defaultPost(url: string, body: string): Promise<void> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), NOTIFY_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'text/plain; charset=utf-8' },
      body,
      signal: ac.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  } finally {
    clearTimeout(timer);
  }
}
