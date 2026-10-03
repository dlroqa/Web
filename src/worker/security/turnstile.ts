/**
 * Server-side Cloudflare Turnstile verification.
 *
 * A browser-side "success" proves nothing; only Siteverify does. A token is
 * accepted only when Siteverify says success AND the token was solved on an
 * expected hostname AND for the expected action AND recently. Siteverify
 * itself rejects reused tokens (`timeout-or-duplicate`) and tokens older than
 * five minutes. Tokens are never logged.
 *
 * Cloudflare's published test secrets (and any result flagged
 * `result_with_testing_key`) are accepted only in development; staging and
 * production refuse them.
 */
import type { Environment } from "../config/config";
import { z } from "../../shared/zod";
import { fetchWithTimeout, readBoundedText, type FetchFn } from "../utils/fetch";
import type { Logger } from "../utils/log";

export const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const SITEVERIFY_TIMEOUT_MS = 5_000;
const MAX_TOKEN_LENGTH = 2_048;
const MAX_RESPONSE_BYTES = 16 * 1024;
/** Siteverify's own validity window is 300 s; allow small clock skew. */
const MAX_CHALLENGE_AGE_MS = 300_000 + 30_000;

/** Cloudflare's documented dummy secrets (always pass / always fail / spent). */
const TEST_SECRETS: ReadonlySet<string> = new Set([
  "1x0000000000000000000000000000000AA",
  "2x0000000000000000000000000000000AA",
  "3x0000000000000000000000000000000AA",
]);

/** Actions are what the widget declares (`data-action`); keep them explicit. */
export type TurnstileAction = "login" | "signup" | "recovery" | "email_verification" | "provision";

export type TurnstileFailure =
  | "missing_token"
  | "token_too_long"
  | "not_configured"
  | "test_key_not_allowed"
  | "siteverify_unavailable"
  | "siteverify_malformed"
  | "rejected"
  | "hostname_mismatch"
  | "action_mismatch"
  | "challenge_stale";

export type TurnstileResult =
  | { ok: true; hostname: string; challengeTs: string; testing: boolean }
  | { ok: false; reason: TurnstileFailure; errorCodes: string[] };

const SiteverifyResponse = z.object({
  success: z.boolean(),
  "error-codes": z.array(z.string().max(100)).max(20).default([]),
  challenge_ts: z.string().max(64).optional(),
  hostname: z.string().max(253).optional(),
  action: z.string().max(64).optional(),
  cdata: z.string().max(255).optional(),
  metadata: z.object({ result_with_testing_key: z.boolean().optional() }).loose().optional(),
});

export interface TurnstileVerifierOptions {
  secret: string | undefined;
  environment: Environment;
  expectedHostnames: ReadonlySet<string>;
  logger: Logger;
  fetchFn?: FetchFn;
  now?: () => number;
}

export interface TurnstileVerifyInput {
  token: unknown;
  expectedAction: TurnstileAction;
  /** Visitor IP from CF-Connecting-IP; optional extra signal for Siteverify. */
  remoteIp?: string | undefined;
  /** Use the request id so a retried Siteverify call is idempotent. */
  idempotencyKey?: string;
}

export class TurnstileVerifier {
  constructor(private readonly options: TurnstileVerifierOptions) {}

  async verify(input: TurnstileVerifyInput): Promise<TurnstileResult> {
    const { secret, environment, expectedHostnames, logger } = this.options;
    const fail = (reason: TurnstileFailure, errorCodes: string[] = []): TurnstileResult => {
      logger.warn("turnstile.failed", { reason, errorCodes, action: input.expectedAction });
      return { ok: false, reason, errorCodes };
    };

    if (typeof input.token !== "string" || input.token.length === 0) return fail("missing_token");
    if (input.token.length > MAX_TOKEN_LENGTH) return fail("token_too_long");
    if (!secret) return fail("not_configured");
    const testSecret = TEST_SECRETS.has(secret);
    if (testSecret && environment !== "development") return fail("test_key_not_allowed");
    if (expectedHostnames.size === 0 && !testSecret) return fail("not_configured");

    const form = new URLSearchParams();
    form.set("secret", secret);
    form.set("response", input.token);
    if (input.remoteIp) form.set("remoteip", input.remoteIp);
    if (input.idempotencyKey) form.set("idempotency_key", input.idempotencyKey);

    let body: unknown;
    try {
      const response = await fetchWithTimeout(
        SITEVERIFY_URL,
        { method: "POST", body: form, headers: { "content-type": "application/x-www-form-urlencoded" } },
        { timeoutMs: SITEVERIFY_TIMEOUT_MS, ...(this.options.fetchFn ? { fetchFn: this.options.fetchFn } : {}) },
      );
      if (!response.ok) {
        await response.body?.cancel();
        return fail("siteverify_unavailable", [`http_${response.status}`]);
      }
      body = JSON.parse(await readBoundedText(response.body, MAX_RESPONSE_BYTES));
    } catch (error) {
      return fail("siteverify_unavailable", [error instanceof Error ? error.name : "unknown"]);
    }

    const parsed = SiteverifyResponse.safeParse(body);
    if (!parsed.success) return fail("siteverify_malformed");
    const result = parsed.data;
    const testing = result.metadata?.result_with_testing_key === true;
    if (testing && environment !== "development") return fail("test_key_not_allowed");
    if (!result.success) return fail("rejected", result["error-codes"]);

    // Test-key results carry a dummy hostname and no action. They are only
    // reachable in development (checked above), where they are accepted as-is.
    if (!testing) {
      if (!result.hostname || !expectedHostnames.has(result.hostname.toLowerCase())) {
        return fail("hostname_mismatch");
      }
      if (result.action !== input.expectedAction) return fail("action_mismatch");
      const issued = result.challenge_ts ? Date.parse(result.challenge_ts) : Number.NaN;
      const now = (this.options.now ?? Date.now)();
      if (!Number.isFinite(issued) || now - issued > MAX_CHALLENGE_AGE_MS || issued - now > 60_000) {
        return fail("challenge_stale");
      }
    }

    return { ok: true, hostname: result.hostname ?? "", challengeTs: result.challenge_ts ?? "", testing };
  }
}
