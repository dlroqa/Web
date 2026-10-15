/**
 * Rate-limit policies: which binding each uses, its period, what happens if
 * the limiter is unavailable, and (for some) the authoritative limit.
 * Dependency-free so configuration tests can compare it with wrangler.jsonc.
 */
export type RateLimitPolicy =
  | "login"
  | "signup"
  | "recovery"
  | "provision"
  | "read"
  | "passkey_login"
  | "security_write";

export interface PolicyDefinition {
  binding: "RL_LOGIN" | "RL_SIGNUP" | "RL_RECOVERY" | "RL_PROVISION" | "RL_READ" | "RL_PASSKEY_LOGIN" | "RL_SECURITY_WRITE";
  /** Seconds until the window resets; sent as Retry-After. Matches wrangler period. */
  periodSeconds: 10 | 60;
  /**
   * When the limiter itself is unavailable: sensitive policies refuse the
   * request (fail closed); ordinary reads proceed (fail open) and log.
   */
  onLimiterFailure: "deny" | "allow";
  /**
   * The Durable Object limit that decides admission, over the same period.
   * Equal to the binding's wrangler.jsonc limit (tests/static checks this).
   */
  authoritative?: { limit: number };
}

export const RATE_LIMIT_POLICIES: Readonly<Record<RateLimitPolicy, PolicyDefinition>> = {
  login: { binding: "RL_LOGIN", periodSeconds: 60, onLimiterFailure: "deny", authoritative: { limit: 20 } },
  signup: { binding: "RL_SIGNUP", periodSeconds: 60, onLimiterFailure: "deny", authoritative: { limit: 10 } },
  recovery: { binding: "RL_RECOVERY", periodSeconds: 60, onLimiterFailure: "deny" },
  provision: { binding: "RL_PROVISION", periodSeconds: 60, onLimiterFailure: "deny" },
  read: { binding: "RL_READ", periodSeconds: 60, onLimiterFailure: "allow" },
  passkey_login: { binding: "RL_PASSKEY_LOGIN", periodSeconds: 60, onLimiterFailure: "deny", authoritative: { limit: 20 } },
  security_write: { binding: "RL_SECURITY_WRITE", periodSeconds: 60, onLimiterFailure: "deny" },
};
