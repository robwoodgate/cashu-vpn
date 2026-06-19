/**
 * Tiny in-memory per-key rate limiter (fixed sliding window).
 *
 * Guards /purchase from peer-spam: without auth and with cheap/free mints, an
 * attacker could otherwise add unbounded WireGuard peers. Per-IP, configurable,
 * with an injectable clock for tests. State is in-memory (single process); fine
 * for one daemon — a multi-node operator would need shared state.
 */

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs: number;
}

export interface RateLimiter {
  check(key: string): RateLimitResult;
}

export function createRateLimiter(opts: {
  max: number;
  windowMs: number;
  now?: () => number;
}): RateLimiter {
  const now = opts.now ?? Date.now;
  const hits = new Map<string, number[]>();
  let lastPrune = now();

  function prune(t: number): void {
    for (const [k, arr] of hits) {
      const live = arr.filter((ts) => t - ts < opts.windowMs);
      if (live.length) hits.set(k, live);
      else hits.delete(k);
    }
    lastPrune = t;
  }

  return {
    check(key) {
      const t = now();
      // Opportunistic prune so the map can't grow unbounded under churn.
      if (t - lastPrune > opts.windowMs) prune(t);

      const recent = (hits.get(key) ?? []).filter((ts) => t - ts < opts.windowMs);
      if (recent.length >= opts.max) {
        hits.set(key, recent);
        return { allowed: false, retryAfterMs: opts.windowMs - (t - recent[0]!) };
      }
      recent.push(t);
      hits.set(key, recent);
      return { allowed: true, retryAfterMs: 0 };
    },
  };
}
