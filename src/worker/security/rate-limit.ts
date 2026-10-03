/**
 * Rate limiting through Cloudflare's Workers Rate Limiting binding.
 *
 * Each policy has its own binding (limits live in wrangler.jsonc), so login,
 * signup, recovery, provisioning, and reads are limited independently. No
 * in-memory counters: Worker memory is not shared or persistent.
 *
 * Cloudflare's limiter is per-location and eventually consistent; treat it as
 * abuse protection, not an exact quota. Exact quotas (e.g. profiles per user)
 * are enforced in D1.
 */
import type { Logger } from "../utils/log";
import { ApiError } from "../http/errors";

export type RateLimitPolicy = "login" | "signup" | "recovery" | "provision" | "read";

interface PolicyDefinition {
  binding: "RL_LOGIN" | "RL_SIGNUP" | "RL_RECOVERY" | "RL_PROVISION" | "RL_READ";
  /** Seconds until the window resets; sent as Retry-After. Matches wrangler period. */
  periodSeconds: 10 | 60;
  /**
   * When the limiter itself is unavailable: sensitive policies refuse the
   * request (fail closed); ordinary reads proceed (fail open) and log.
   */
  onLimiterFailure: "deny" | "allow";
}

export const RATE_LIMIT_POLICIES: Readonly<Record<RateLimitPolicy, PolicyDefinition>> = {
  login: { binding: "RL_LOGIN", periodSeconds: 60, onLimiterFailure: "deny" },
  signup: { binding: "RL_SIGNUP", periodSeconds: 60, onLimiterFailure: "deny" },
  recovery: { binding: "RL_RECOVERY", periodSeconds: 60, onLimiterFailure: "deny" },
  provision: { binding: "RL_PROVISION", periodSeconds: 60, onLimiterFailure: "deny" },
  read: { binding: "RL_READ", periodSeconds: 60, onLimiterFailure: "allow" },
};

/**
 * What a limit is keyed on. Prefer stable account identifiers over IPs; use
 * IPs only for unauthenticated endpoints. Keys are namespaced by kind so a
 * user id can never collide with an IP.
 */
export type RateLimitSubject =
  | { kind: "user"; id: string }
  | { kind: "ip"; address: string }
  | { kind: "account"; id: string };

export function rateLimitKey(policy: RateLimitPolicy, subject: RateLimitSubject): string {
  const value = subject.kind === "ip" ? subject.address : subject.id;
  return `${policy}:${subject.kind}:${value}`;
}

export type RateLimitDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number };

export interface RateLimiter {
  check(policy: RateLimitPolicy, subject: RateLimitSubject): Promise<RateLimitDecision>;
}

type RateLimitBindings = Pick<Env, PolicyDefinition["binding"]>;

export class CloudflareRateLimiter implements RateLimiter {
  constructor(
    private readonly bindings: Partial<RateLimitBindings>,
    private readonly logger: Logger,
  ) {}

  async check(policy: RateLimitPolicy, subject: RateLimitSubject): Promise<RateLimitDecision> {
    const definition = RATE_LIMIT_POLICIES[policy];
    const binding = this.bindings[definition.binding];
    const denied: RateLimitDecision = { allowed: false, retryAfterSeconds: definition.periodSeconds };
    if (!binding) {
      this.logger.error("ratelimit.binding_missing", { policy, binding: definition.binding });
      return definition.onLimiterFailure === "deny" ? denied : { allowed: true };
    }
    try {
      const { success } = await binding.limit({ key: rateLimitKey(policy, subject) });
      if (!success) {
        this.logger.warn("ratelimit.exceeded", { policy, subjectKind: subject.kind });
      }
      return success ? { allowed: true } : denied;
    } catch (error) {
      this.logger.error("ratelimit.limiter_failed", { policy, errorName: error instanceof Error ? error.name : typeof error });
      return definition.onLimiterFailure === "deny" ? denied : { allowed: true };
    }
  }
}

/** Throw RATE_LIMITED (429 + Retry-After) when the policy denies the request. */
export async function enforceRateLimit(
  limiter: RateLimiter,
  policy: RateLimitPolicy,
  subject: RateLimitSubject,
): Promise<void> {
  const decision = await limiter.check(policy, subject);
  if (!decision.allowed) {
    throw new ApiError("RATE_LIMITED", {
      headers: { "retry-after": String(decision.retryAfterSeconds) },
      logReason: `rate limit ${policy}`,
    });
  }
}
