/**
 * Rate limiting.
 *
 * Two layers:
 *
 * - Cloudflare's Workers Rate Limiting bindings, one per policy (limits in
 *   wrangler.jsonc). Per-location and eventually consistent, and observed
 *   on staging (2026-10-15) never to refuse at all (cloudflare/workers-sdk
 *   #16097). A refusal from a binding is honoured; an approval is not proof
 *   of anything.
 * - For policies with an `authoritative` limit, a Durable Object counter
 *   (rate-limit-do.ts) that makes the actual admission decision, exactly
 *   and atomically, and fails closed.
 *
 * No in-memory counters: Worker memory is not shared or persistent.
 * Exact quotas (e.g. profiles per user) are enforced in D1.
 */
import type { Logger } from "../utils/log";
import { ApiError } from "../http/errors";
import { hmacSha256Hex } from "../utils/crypto";
import type { Admission, AuthRateLimiter } from "./rate-limit-do";
import { RATE_LIMIT_POLICIES, type PolicyDefinition, type RateLimitPolicy } from "./rate-limit-policies";

export { RATE_LIMIT_POLICIES, type RateLimitPolicy } from "./rate-limit-policies";

/**
 * What a limit is keyed on. Prefer stable account identifiers over IPs; use
 * IPs only for unauthenticated endpoints. Keys are namespaced by kind so a
 * user id can never collide with an IP. An `ip` subject's address comes from
 * `rateLimitAddress` (client-address.ts); null means the client could not be
 * identified.
 */
export type RateLimitSubject =
  | { kind: "user"; id: string }
  | { kind: "ip"; address: string | null }
  | { kind: "account"; id: string };

export function rateLimitKey(policy: RateLimitPolicy, subject: RateLimitSubject): string {
  const value = subject.kind === "ip" ? (subject.address ?? "unknown") : subject.id;
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

  /** The binding's answer, with "unavailable" kept distinct from a refusal. */
  async probe(policy: RateLimitPolicy, subject: RateLimitSubject): Promise<"allowed" | "denied" | "unavailable"> {
    const definition = RATE_LIMIT_POLICIES[policy];
    const binding = this.bindings[definition.binding];
    if (!binding) {
      this.logger.error("ratelimit.binding_missing", { policy, binding: definition.binding });
      return "unavailable";
    }
    try {
      const { success } = await binding.limit({ key: rateLimitKey(policy, subject) });
      if (!success) {
        this.logger.warn("ratelimit.exceeded", { policy, subjectKind: subject.kind, layer: "binding" });
      }
      return success ? "allowed" : "denied";
    } catch (error) {
      this.logger.error("ratelimit.limiter_failed", { policy, errorName: error instanceof Error ? error.name : typeof error });
      return "unavailable";
    }
  }

  async check(policy: RateLimitPolicy, subject: RateLimitSubject): Promise<RateLimitDecision> {
    const definition = RATE_LIMIT_POLICIES[policy];
    const outcome = await this.probe(policy, subject);
    if (outcome === "allowed" || (outcome === "unavailable" && definition.onLimiterFailure === "allow")) return { allowed: true };
    return { allowed: false, retryAfterSeconds: definition.periodSeconds };
  }
}

/** Domain separation for the counter-name key derived from BETTER_AUTH_SECRET. */
const COUNTER_KEY_LABEL = "lightagent-ratelimit-counter-key:v1";
const encoder = new TextEncoder();

export interface AuthoritativeRateLimiterOptions {
  /** The binding layer, consulted first. */
  bindings: CloudflareRateLimiter;
  /** The AUTH_RATE_LIMITER namespace; missing means every authoritative check refuses. */
  namespace: DurableObjectNamespace<AuthRateLimiter> | undefined;
  /** ENVIRONMENT; part of every counter name. */
  environment: string;
  /** BETTER_AUTH_SECRET; counter names are keyed on a value derived from it. */
  secret: string;
  logger: Logger;
}

/**
 * Policies with an `authoritative` limit: a binding refusal is final; then
 * the Durable Object counter decides. Anything that prevents a decision
 * (unidentified client, missing namespace, Durable Object error) refuses.
 * Policies without one behave exactly as CloudflareRateLimiter.
 */
export class AuthoritativeRateLimiter implements RateLimiter {
  private counterKey: Promise<Uint8Array> | undefined;

  constructor(private readonly options: AuthoritativeRateLimiterOptions) {}

  /**
   * The Durable Object name for a counter: environment, policy and subject
   * kind in clear (so policies and environments never share a counter),
   * the subject value only as an HMAC under a key derived from the secret.
   */
  async counterName(policy: RateLimitPolicy, subject: RateLimitSubject): Promise<string> {
    this.counterKey ??= hmacSha256Hex(encoder.encode(this.options.secret), COUNTER_KEY_LABEL).then((hex) => encoder.encode(hex));
    const value = subject.kind === "ip" ? subject.address : subject.id;
    const digest = await hmacSha256Hex(await this.counterKey, `${policy}\n${subject.kind}\n${value ?? ""}`);
    return `rl1:${this.options.environment}:${policy}:${subject.kind}:${digest}`;
  }

  async check(policy: RateLimitPolicy, subject: RateLimitSubject): Promise<RateLimitDecision> {
    const definition = RATE_LIMIT_POLICIES[policy];
    if (!definition.authoritative) return this.options.bindings.check(policy, subject);
    const { logger } = this.options;
    const denied: RateLimitDecision = { allowed: false, retryAfterSeconds: definition.periodSeconds };

    if (subject.kind === "ip" && subject.address === null) {
      logger.warn("ratelimit.client_unidentified", { policy });
      return denied;
    }
    if ((await this.options.bindings.probe(policy, subject)) === "denied") return denied;

    const namespace = this.options.namespace;
    if (!namespace) {
      logger.error("ratelimit.authoritative_missing", { policy });
      return denied;
    }
    let admission: Admission;
    try {
      const stub = namespace.getByName(await this.counterName(policy, subject));
      admission = await stub.admit(definition.authoritative.limit, definition.periodSeconds);
    } catch (error) {
      logger.error("ratelimit.authoritative_failed", { policy, errorName: error instanceof Error ? error.name : typeof error });
      return denied;
    }
    if (admission.allowed) return { allowed: true };
    logger.warn("ratelimit.exceeded", { policy, subjectKind: subject.kind, layer: "authoritative" });
    return { allowed: false, retryAfterSeconds: admission.retryAfterSeconds };
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
