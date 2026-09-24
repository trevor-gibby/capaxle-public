import type {
  RateLimitProvider,
  RateLimitDecision,
  RateLimitView,
} from "./types.js";
import { ownData, RuntimeConfigurationError } from "./registry.js";

export interface FixedWindowRateLimitOptions {
  readonly policies: Readonly<
    Record<
      string,
      {
        readonly limit: number;
        readonly windowMs: number;
        readonly maxBuckets: number;
      }
    >
  >;
  readonly now?: () => number;
}
/** Atomic within this provider instance in one process; no distributed guarantee. */
export function createFixedWindowRateLimitProvider(
  options: FixedWindowRateLimitOptions,
): RateLimitProvider {
  try {
    const carrier = ownData(options, ["policies", "now"]);
    const declarations = ownData(carrier.policies);
    if (carrier.now !== undefined && typeof carrier.now !== "function")
      throw new Error("clock");
    const now = (carrier.now ?? Date.now) as () => number;
    let lastTimestamp = -1;
    const policies = new Map<
      string,
      {
        limit: number;
        windowMs: number;
        maxBuckets: number;
        buckets: Map<string, { used: number; reset: number }>;
      }
    >();
    for (const [name, value] of Object.entries(declarations)) {
      const data = ownData(value, ["limit", "windowMs", "maxBuckets"]);
      for (const key of ["limit", "windowMs", "maxBuckets"])
        if (!Number.isSafeInteger(data[key]) || (data[key] as number) <= 0)
          throw new Error("policy");
      if (!name || name.length > 128) throw new Error("policy");
      policies.set(name, {
        limit: data.limit as number,
        windowMs: data.windowMs as number,
        maxBuckets: data.maxBuckets as number,
        buckets: new Map(),
      });
    }
    if (!policies.size) throw new Error("policy");
    return Object.freeze({
      policies: Object.freeze([...policies.keys()].sort()),
      check: (view: RateLimitView): RateLimitDecision => {
        const policy = policies.get(view.policy);
        const timestamp = now();
        if (
          !policy ||
          !Number.isSafeInteger(timestamp) ||
          timestamp < lastTimestamp ||
          timestamp < 0 ||
          !Number.isSafeInteger(view.cost) ||
          view.cost <= 0 ||
          view.signal.aborted ||
          timestamp >= view.deadlineMs
        )
          throw new Error("unavailable");
        lastTimestamp = timestamp;
        for (const [key, bucket] of policy.buckets)
          if (bucket.reset <= timestamp) policy.buckets.delete(key);
        const principal = view.identity.effective;
        const key = JSON.stringify([
          view.capability.id,
          view.capability.version,
          principal.providerId,
          principal.type,
          principal.subject,
          principal.tenant,
        ]);
        let bucket = policy.buckets.get(key);
        if (!bucket) {
          if (policy.buckets.size >= policy.maxBuckets)
            throw new Error("capacity");
          const reset = timestamp + policy.windowMs;
          if (!Number.isSafeInteger(reset)) throw new Error("clock");
          bucket = { used: 0, reset };
          policy.buckets.set(key, bucket);
        }
        if (view.cost > policy.limit - bucket.used)
          return Object.freeze({
            allowed: false,
            retryAfterMs: bucket.reset - timestamp,
            limit: policy.limit,
            remaining: policy.limit - bucket.used,
            resetAt: new Date(bucket.reset).toISOString(),
          });
        bucket.used += view.cost;
        return Object.freeze({ allowed: true });
      },
    });
  } catch {
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
}
