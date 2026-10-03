import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../../src/worker/http/errors";
import {
  CloudflareRateLimiter,
  enforceRateLimit,
  RATE_LIMIT_POLICIES,
  rateLimitKey,
  type RateLimitPolicy,
} from "../../src/worker/security/rate-limit";
import { createLogger } from "../../src/worker/utils/log";

const quiet = () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
};

function binding(success: boolean | Error): RateLimit & { keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    async limit({ key }) {
      keys.push(key);
      if (success instanceof Error) throw success;
      return { success };
    },
  };
}

describe("rate limit policies", () => {
  it("use a separate Cloudflare binding per operation", () => {
    const bindings = Object.values(RATE_LIMIT_POLICIES).map((policy) => policy.binding);
    expect(new Set(bindings).size).toBe(bindings.length);
  });

  it("fail closed for sensitive operations and open only for reads", () => {
    for (const policy of ["login", "signup", "recovery", "provision"] as RateLimitPolicy[]) {
      expect(RATE_LIMIT_POLICIES[policy].onLimiterFailure).toBe("deny");
    }
    expect(RATE_LIMIT_POLICIES.read.onLimiterFailure).toBe("allow");
  });

  it("namespace keys by policy and subject kind", () => {
    expect(rateLimitKey("login", { kind: "ip", address: "203.0.113.9" })).toBe("login:ip:203.0.113.9");
    expect(rateLimitKey("provision", { kind: "user", id: "usr_abc" })).toBe("provision:user:usr_abc");
  });
});

describe("CloudflareRateLimiter", () => {
  it("allows when the binding allows", async () => {
    const rl = binding(true);
    const limiter = new CloudflareRateLimiter({ RL_LOGIN: rl }, createLogger());
    await expect(limiter.check("login", { kind: "ip", address: "203.0.113.9" })).resolves.toEqual({ allowed: true });
    expect(rl.keys).toEqual(["login:ip:203.0.113.9"]);
  });

  it("denies with the window as Retry-After when the binding denies", async () => {
    quiet();
    const limiter = new CloudflareRateLimiter({ RL_PROVISION: binding(false) }, createLogger());
    await expect(limiter.check("provision", { kind: "user", id: "usr_a" })).resolves.toEqual({ allowed: false, retryAfterSeconds: 60 });
    vi.restoreAllMocks();
  });

  it("fails closed for login when the binding is missing or throws", async () => {
    quiet();
    await expect(new CloudflareRateLimiter({}, createLogger()).check("login", { kind: "ip", address: "x" })).resolves.toMatchObject({ allowed: false });
    await expect(
      new CloudflareRateLimiter({ RL_LOGIN: binding(new Error("down")) }, createLogger()).check("login", { kind: "ip", address: "x" }),
    ).resolves.toMatchObject({ allowed: false });
    vi.restoreAllMocks();
  });

  it("fails open for reads when the limiter is unavailable", async () => {
    quiet();
    await expect(new CloudflareRateLimiter({}, createLogger()).check("read", { kind: "user", id: "usr_a" })).resolves.toEqual({ allowed: true });
    vi.restoreAllMocks();
  });

  it("works against the real local binding from wrangler.jsonc", async () => {
    const { env } = await import("cloudflare:test");
    const limiter = new CloudflareRateLimiter(env, createLogger());
    await expect(limiter.check("read", { kind: "user", id: "usr_real" })).resolves.toEqual({ allowed: true });
  });
});

describe("enforceRateLimit", () => {
  it("throws RATE_LIMITED (429) with Retry-After", async () => {
    quiet();
    const limiter = new CloudflareRateLimiter({ RL_SIGNUP: binding(false) }, createLogger());
    const error = await enforceRateLimit(limiter, "signup", { kind: "ip", address: "x" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("RATE_LIMITED");
    expect((error as ApiError).status).toBe(429);
    expect((error as ApiError).headers["retry-after"]).toBe("60");
    vi.restoreAllMocks();
  });

  it("brute-force attempts beyond the limit are constrained", async () => {
    quiet();
    let remaining = 3;
    const counting: RateLimit = { limit: async () => ({ success: remaining-- > 0 }) };
    const limiter = new CloudflareRateLimiter({ RL_LOGIN: counting }, createLogger());
    const outcomes = await Promise.all(
      Array.from({ length: 6 }, () => enforceRateLimit(limiter, "login", { kind: "ip", address: "x" }).then(() => "ok", () => "limited")),
    );
    expect(outcomes.filter((o) => o === "ok")).toHaveLength(3);
    vi.restoreAllMocks();
  });
});
