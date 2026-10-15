import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../../src/worker/http/errors";
import { env } from "cloudflare:test";
import type { Admission, AuthRateLimiter } from "../../src/worker/security/rate-limit-do";
import {
  AuthoritativeRateLimiter,
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

/** A namespace whose objects answer with `answer` (or throw it) and record calls. */
function fakeNamespace(answer: Admission | Error) {
  const calls: { name: string; limit: number; period: number }[] = [];
  const namespace = {
    getByName: (name: string) => ({
      admit: async (limit: number, period: number) => {
        calls.push({ name, limit, period });
        if (answer instanceof Error) throw answer;
        return answer;
      },
    }),
  } as unknown as DurableObjectNamespace<AuthRateLimiter>;
  return { namespace, calls };
}

function authoritative(options: { bindings?: Partial<Record<string, RateLimit>>; namespace?: DurableObjectNamespace<AuthRateLimiter>; environment?: string; secret?: string }) {
  const logger = createLogger();
  return new AuthoritativeRateLimiter({
    bindings: new CloudflareRateLimiter(options.bindings ?? {}, logger),
    namespace: options.namespace,
    environment: options.environment ?? "development",
    secret: options.secret ?? "test-only-secret-0123456789abcdef0123456789",
    logger,
  });
}

const ADDRESS = { kind: "ip", address: "203.0.113.9" } as const;

describe("AuthoritativeRateLimiter", () => {
  it("covers login, passkey login and signup with the deployed limits", () => {
    expect(RATE_LIMIT_POLICIES.login.authoritative).toEqual({ limit: 20 });
    expect(RATE_LIMIT_POLICIES.passkey_login.authoritative).toEqual({ limit: 20 });
    expect(RATE_LIMIT_POLICIES.signup.authoritative).toEqual({ limit: 10 });
    for (const policy of ["recovery", "provision", "read", "security_write"] as RateLimitPolicy[]) {
      expect(RATE_LIMIT_POLICIES[policy].authoritative, policy).toBeUndefined();
    }
  });

  it("does not treat a binding approval as authoritative", async () => {
    quiet();
    const { namespace, calls } = fakeNamespace({ allowed: false, retryAfterSeconds: 17 });
    const limiter = authoritative({ bindings: { RL_LOGIN: binding(true) }, namespace });
    await expect(limiter.check("login", ADDRESS)).resolves.toEqual({ allowed: false, retryAfterSeconds: 17 });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ limit: 20, period: 60 });
    vi.restoreAllMocks();
  });

  it("admits when the object admits", async () => {
    const { namespace } = fakeNamespace({ allowed: true, retryAfterSeconds: 0 });
    await expect(authoritative({ bindings: { RL_PASSKEY_LOGIN: binding(true) }, namespace }).check("passkey_login", ADDRESS)).resolves.toEqual({ allowed: true });
  });

  it("honours a binding refusal without consulting the object", async () => {
    quiet();
    const { namespace, calls } = fakeNamespace({ allowed: true, retryAfterSeconds: 0 });
    await expect(authoritative({ bindings: { RL_LOGIN: binding(false) }, namespace }).check("login", ADDRESS)).resolves.toEqual({ allowed: false, retryAfterSeconds: 60 });
    expect(calls).toHaveLength(0);
    vi.restoreAllMocks();
  });

  it("lets the object decide when the binding is missing or failing", async () => {
    quiet();
    const { namespace, calls } = fakeNamespace({ allowed: true, retryAfterSeconds: 0 });
    await expect(authoritative({ namespace }).check("login", ADDRESS)).resolves.toEqual({ allowed: true });
    await expect(authoritative({ bindings: { RL_LOGIN: binding(new Error("down")) }, namespace }).check("login", ADDRESS)).resolves.toEqual({ allowed: true });
    expect(calls).toHaveLength(2);
    vi.restoreAllMocks();
  });

  it("fails closed when the object is unavailable or the namespace is missing", async () => {
    quiet();
    const { namespace } = fakeNamespace(new Error("Durable Object reset because its code was updated"));
    await expect(authoritative({ bindings: { RL_LOGIN: binding(true) }, namespace }).check("login", ADDRESS)).resolves.toEqual({ allowed: false, retryAfterSeconds: 60 });
    await expect(authoritative({ bindings: { RL_SIGNUP: binding(true) } }).check("signup", ADDRESS)).resolves.toEqual({ allowed: false, retryAfterSeconds: 60 });
    vi.restoreAllMocks();
  });

  it("refuses an unidentified client without consulting either layer", async () => {
    quiet();
    const rl = binding(true);
    const { namespace, calls } = fakeNamespace({ allowed: true, retryAfterSeconds: 0 });
    await expect(authoritative({ bindings: { RL_LOGIN: rl }, namespace }).check("login", { kind: "ip", address: null })).resolves.toMatchObject({ allowed: false });
    expect(rl.keys).toEqual([]);
    expect(calls).toHaveLength(0);
    vi.restoreAllMocks();
  });

  it("leaves policies without an authoritative limit to the binding, unchanged", async () => {
    quiet();
    const { namespace, calls } = fakeNamespace({ allowed: false, retryAfterSeconds: 1 });
    const limiter = authoritative({ bindings: { RL_READ: binding(true), RL_SECURITY_WRITE: binding(false) }, namespace });
    await expect(limiter.check("read", { kind: "user", id: "usr_a" })).resolves.toEqual({ allowed: true });
    await expect(limiter.check("security_write", { kind: "user", id: "usr_a" })).resolves.toMatchObject({ allowed: false });
    await expect(authoritative({}).check("read", { kind: "user", id: "usr_a" })).resolves.toEqual({ allowed: true });
    expect(calls).toHaveLength(0);
    vi.restoreAllMocks();
  });
});

describe("counter names", () => {
  const name = (policy: RateLimitPolicy, subject: Parameters<AuthoritativeRateLimiter["counterName"]>[1], options: { environment?: string; secret?: string } = {}) =>
    authoritative(options).counterName(policy, subject);

  it("are deterministic and never contain the address", async () => {
    const first = await name("login", ADDRESS);
    expect(await name("login", ADDRESS)).toBe(first);
    expect(first).toMatch(/^rl1:development:login:ip:[0-9a-f]{64}$/);
    expect(first).not.toContain("203.0.113.9");
  });

  it("separate policies, subject kinds, subjects and environments", async () => {
    const names = await Promise.all([
      name("login", ADDRESS),
      name("passkey_login", ADDRESS),
      name("signup", ADDRESS),
      name("login", { kind: "ip", address: "203.0.113.10" }),
      name("login", { kind: "user", id: "203.0.113.9" }),
      name("login", { kind: "account", id: "203.0.113.9" }),
      name("login", ADDRESS, { environment: "staging" }),
      name("login", ADDRESS, { environment: "production" }),
    ]);
    expect(new Set(names).size).toBe(names.length);
  });

  it("depend on the deployment secret, so they cannot be precomputed from an address", async () => {
    expect(await name("login", ADDRESS, { secret: "another-secret-0123456789abcdef0123456789ab" })).not.toBe(await name("login", ADDRESS));
  });

  it("route to independent objects in the real namespace", async () => {
    const limiter = authoritative({ namespace: env.AUTH_RATE_LIMITER });
    const subject = { kind: "ip", address: "198.51.100.200" } as const;
    for (let i = 0; i < 10; i += 1) await limiter.check("signup", subject);
    await expect(limiter.check("signup", subject)).resolves.toMatchObject({ allowed: false });
    // Same subject, other policies and another environment: untouched.
    await expect(limiter.check("login", subject)).resolves.toEqual({ allowed: true });
    await expect(limiter.check("passkey_login", subject)).resolves.toEqual({ allowed: true });
    await expect(authoritative({ namespace: env.AUTH_RATE_LIMITER, environment: "staging" }).check("signup", subject)).resolves.toEqual({ allowed: true });
  });
});
