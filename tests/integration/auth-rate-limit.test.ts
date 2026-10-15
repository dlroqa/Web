/**
 * Authoritative (Durable Object) rate limiting on the unauthenticated
 * authentication paths, end to end through the Worker.
 *
 * Every test here replaces the Workers Rate Limiting bindings with ones that
 * always approve, as the live bindings were observed to do on staging
 * (cloudflare/workers-sdk#16097), so only the Durable Object stands between
 * a client and unlimited attempts.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IdentityService } from "../../src/worker/auth/identity";
import { createWorker } from "../../src/worker/index";
import { UserRepository } from "../../src/worker/db/users";
import { ApiError } from "../../src/worker/http/errors";
import { AuthoritativeRateLimiter, CloudflareRateLimiter } from "../../src/worker/security/rate-limit";
import type { AuthRateLimiter } from "../../src/worker/security/rate-limit-do";
import { createLogger } from "../../src/worker/utils/log";
import { randomId } from "../../src/worker/utils/random";
import { FakeProviders, identity, signIn } from "../helpers/auth";
import { CookieJar } from "../helpers/cookies";
import { BASE, call, testEnv } from "../helpers/worker";

const approveAll: RateLimit = { limit: async () => ({ success: true }) };
const permissive = (overrides: Partial<Env> = {}) =>
  testEnv({ RL_LOGIN: approveAll, RL_PASSKEY_LOGIN: approveAll, RL_SIGNUP: approveAll, ...overrides });

let providers: FakeProviders;
beforeEach(() => {
  for (const level of ["log", "info", "warn", "error"] as const) vi.spyOn(console, level).mockImplementation(() => {});
  providers = new FakeProviders().install();
});
afterEach(() => {
  providers.restore();
  vi.restoreAllMocks();
});

/** A TEST-NET-2 address unique to this run. */
function freshIp(): string {
  const [a = 0, b = 0] = crypto.getRandomValues(new Uint8Array(2));
  return `198.51.${a}.${b}`;
}

const siteverifyCalls = () => providers.outbound.filter((o) => o.includes("/turnstile/v0/siteverify")).length;
const providerCalls = () => providers.outbound.filter((o) => !o.includes("/turnstile/")).length;
const challengeRows = async () => (await env.DB.prepare(`SELECT COUNT(*) AS n FROM "verification"`).first<{ n: number }>())?.n ?? 0;

function startSignIn(headers: Record<string, string>, environment: Env = permissive()) {
  return call(
    "/api/auth/sign-in/social",
    { method: "POST", headers: { origin: BASE, "content-type": "application/json", ...headers }, body: JSON.stringify({ provider: "google", turnstileToken: "invalid" }) },
    { env: environment },
  );
}

const passkeyOptions = (headers: Record<string, string>, environment: Env = permissive()) =>
  call("/api/auth/passkey/generate-authenticate-options", { headers }, { env: environment });

async function codeOf(response: Response): Promise<string> {
  return ((await response.json()) as { error?: { code: string } }).error?.code ?? "OK";
}

describe("sign-in start (login policy, 20 / 60 s)", () => {
  it("refuses the 21st attempt from one address even though the binding approves everything", async () => {
    providers.turnstile = "fail";
    const ip = freshIp();
    const codes: string[] = [];
    for (let i = 0; i < 25; i += 1) {
      const response = await startSignIn({ "cf-connecting-ip": ip });
      codes.push(await codeOf(response));
      if (response.status === 429) {
        const retryAfter = Number(response.headers.get("retry-after"));
        expect(retryAfter).toBeGreaterThanOrEqual(1);
        expect(retryAfter).toBeLessThanOrEqual(60);
      }
    }
    expect(codes.slice(0, 20).every((c) => c === "TURNSTILE_FAILED")).toBe(true);
    expect(codes.slice(20).every((c) => c === "RATE_LIMITED")).toBe(true);
    // Turnstile is never consulted for a refused attempt.
    expect(siteverifyCalls()).toBe(20);
  }, 30_000);

  it("concurrent attempts cannot race past the limit", async () => {
    const ip = freshIp();
    const statuses = await Promise.all(Array.from({ length: 30 }, () => startSignIn({ "cf-connecting-ip": ip }).then((r) => r.status)));
    expect(statuses.filter((s) => s === 200)).toHaveLength(20);
    expect(statuses.filter((s) => s === 429)).toHaveLength(10);
  }, 30_000);

  it("ignores client-supplied forwarding headers", async () => {
    const ip = freshIp();
    const statuses: number[] = [];
    for (let i = 0; i < 21; i += 1) {
      const spoofed = `203.0.113.${i}`;
      statuses.push((await startSignIn({ "cf-connecting-ip": ip, "x-forwarded-for": spoofed, "x-real-ip": spoofed, "true-client-ip": spoofed })).status);
    }
    expect(statuses.at(-1)).toBe(429);
  }, 30_000);

  it("keys IPv6 clients on their /64, so rotating addresses does not reset the count", async () => {
    const prefix = `2001:db8:${crypto.getRandomValues(new Uint16Array(1))[0]?.toString(16)}:1`;
    const statuses: number[] = [];
    for (let i = 0; i < 21; i += 1) statuses.push((await startSignIn({ "cf-connecting-ip": `${prefix}::${(i + 1).toString(16)}` })).status);
    expect(statuses.slice(0, 20).every((s) => s === 200)).toBe(true);
    expect(statuses[20]).toBe(429);
    // A different /64 has its own counter.
    expect((await startSignIn({ "cf-connecting-ip": `${prefix.slice(0, -1)}2::1` })).status).toBe(200);
  }, 30_000);

  it("refuses a request whose client cannot be identified, before Turnstile", async () => {
    for (const headers of [{ "cf-connecting-ip": "unknown" } as Record<string, string>, { "cf-connecting-ip": "203.0.113.9, 198.51.100.1" }, { "cf-connecting-ip": "", "x-forwarded-for": "203.0.113.9" }]) {
      const response = await startSignIn(headers);
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("60");
    }
    // No CF-Connecting-IP at all (the test helper would otherwise add one).
    const ctx = createExecutionContext();
    const bare = new Request(`${BASE}/api/auth/sign-in/social`, { method: "POST", headers: { origin: BASE, "content-type": "application/json" }, body: JSON.stringify({ provider: "google", turnstileToken: "invalid" }) });
    const response = await createWorker({ cspMode: "production" }).fetch(bare, permissive(), ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(429);
    expect(siteverifyCalls()).toBe(0);
  });
});

describe("other authentication paths share or have their own authoritative counters", () => {
  it("the OAuth callback shares the login counter and is refused before Better Auth", async () => {
    const ip = freshIp();
    for (let i = 0; i < 20; i += 1) await startSignIn({ "cf-connecting-ip": ip });
    const before = providerCalls();
    const callback = await call("/api/auth/callback/google?code=c&state=s", { headers: { "cf-connecting-ip": ip } }, { env: permissive() });
    expect(callback.status).toBe(429);
    expect(providerCalls()).toBe(before);
  }, 30_000);

  it("passkey sign-in options: the 21st request is refused and writes no challenge", async () => {
    const ip = freshIp();
    for (let i = 0; i < 20; i += 1) expect((await passkeyOptions({ "cf-connecting-ip": ip })).status).toBe(200);
    const rows = await challengeRows();
    const refused = await passkeyOptions({ "cf-connecting-ip": ip });
    expect(refused.status).toBe(429);
    expect(Number(refused.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    expect(refused.headers.getSetCookie()).toEqual([]);
    expect(await challengeRows()).toBe(rows);
    // Passkey verification shares the counter: refused before its body is read.
    const verify = await call(
      "/api/auth/passkey/verify-authentication",
      { method: "POST", headers: { origin: BASE, "content-type": "application/json", "cf-connecting-ip": ip }, body: "{}" },
      { env: permissive() },
    );
    expect(verify.status).toBe(429);
  }, 30_000);

  it("exhausting one policy leaves the others for the same address alone", async () => {
    const ip = freshIp();
    for (let i = 0; i < 21; i += 1) await passkeyOptions({ "cf-connecting-ip": ip });
    expect((await passkeyOptions({ "cf-connecting-ip": ip })).status).toBe(429);
    expect((await startSignIn({ "cf-connecting-ip": ip })).status).toBe(200);
  }, 30_000);

  it("a full OAuth sign-in still works for an ordinary client", async () => {
    const jar = new CookieJar();
    const result = await signIn(providers, identity("google"), jar, { env: permissive() });
    expect(result.location).toBe(`${BASE}/dashboard`);
  });
});

describe("when the authoritative limiter is unavailable", () => {
  const broken = {
    getByName: () => ({
      admit: async () => {
        throw new Error("Durable Object is overloaded");
      },
    }),
  } as unknown as DurableObjectNamespace<AuthRateLimiter>;

  it.each([
    ["throws", { AUTH_RATE_LIMITER: broken }],
    ["is not bound", { AUTH_RATE_LIMITER: undefined as unknown as DurableObjectNamespace<AuthRateLimiter> }],
  ])("sign-in and passkey options fail closed when the namespace %s", async (_label, overrides) => {
    const environment = permissive(overrides);
    const rows = await challengeRows();
    const start = await startSignIn({ "cf-connecting-ip": freshIp() }, environment);
    expect(start.status).toBe(429);
    expect(start.headers.get("retry-after")).toBe("60");
    const options = await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment);
    expect(options.status).toBe(429);
    expect(siteverifyCalls()).toBe(0);
    expect(await challengeRows()).toBe(rows);
  });
});

describe("signup (profile creation, 10 / 60 s)", () => {
  const service = () => {
    const logger = createLogger();
    const limiter = new AuthoritativeRateLimiter({
      bindings: new CloudflareRateLimiter({ RL_SIGNUP: approveAll }, logger),
      namespace: env.AUTH_RATE_LIMITER,
      environment: "development",
      secret: "test-only-better-auth-secret-0123456789abcdef",
      logger,
    });
    return new IdentityService(new UserRepository(env.DB), "open", limiter);
  };

  it("creates at most 10 new profiles per address; returning users are never limited", async () => {
    const identityService = service();
    const sourceAddress = freshIp();
    const first = randomId("auth");
    await identityService.ensureProfile(first, { sourceAddress });
    for (let i = 0; i < 9; i += 1) await identityService.ensureProfile(randomId("auth"), { sourceAddress });
    const refused = await identityService.ensureProfile(randomId("auth"), { sourceAddress }).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(ApiError);
    expect((refused as ApiError).code).toBe("RATE_LIMITED");
    await expect(identityService.ensureProfile(first, { sourceAddress })).resolves.toMatchObject({ created: false });
  });

  it("refuses to create a profile for an unidentified source", async () => {
    await expect(service().ensureProfile(randomId("auth"), { sourceAddress: null })).rejects.toMatchObject({ code: "RATE_LIMITED" });
  });
});
