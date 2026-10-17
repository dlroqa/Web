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
import { FakeProviders, identity, send, signIn, type Identity } from "../helpers/auth";
import { CookieJar } from "../helpers/cookies";
import { SoftAuthenticator } from "../helpers/webauthn";
import { BASE, call, testEnv } from "../helpers/worker";

const approveAll: RateLimit = { limit: async () => ({ success: true }) };
const permissive = (overrides: Partial<Env> = {}) =>
  testEnv({ RL_LOGIN: approveAll, RL_PASSKEY_LOGIN: approveAll, RL_SIGNUP: approveAll, ...overrides });

let providers: FakeProviders;
let logLines: string[] = [];
beforeEach(() => {
  logLines = [];
  for (const level of ["log", "info", "warn", "error"] as const) vi.spyOn(console, level).mockImplementation((line: unknown) => void logLines.push(String(line)));
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

/** Passkey sign-in options as the login page sends them (POST, trusted origin, Turnstile token). */
const passkeyOptions = (headers: Record<string, string>, environment: Env = permissive(), body: unknown = { turnstileToken: "t" }) =>
  call(
    "/api/auth/passkey/generate-authenticate-options",
    { method: "POST", headers: { origin: BASE, "content-type": "application/json", ...headers }, body: JSON.stringify(body) },
    { env: environment },
  );

/** Start an OAuth sign-in in `jar` and register a provider code for it; the callback is left to the test. */
async function startFlow(who: Identity, jar: CookieJar, environment: Env, ip?: string): Promise<{ state: string; code: string }> {
  const start = await call(
    "/api/auth/sign-in/social",
    {
      method: "POST",
      headers: { origin: BASE, "content-type": "application/json", cookie: jar.header(), ...(ip ? { "cf-connecting-ip": ip } : {}) },
      body: JSON.stringify({ provider: who.provider, turnstileToken: "t" }),
    },
    { env: environment },
  );
  jar.store(start);
  expect(start.status).toBe(200);
  const url = new URL(((await start.json()) as { data: { url: string } }).data.url);
  const code = randomId("code");
  const nonce = url.searchParams.get("nonce") ?? undefined;
  providers.codes.set(code, { ...who, ...(nonce ? { nonce } : {}) });
  return { state: url.searchParams.get("state") ?? "", code };
}

async function codeOf(response: Response): Promise<string> {
  return ((await response.json()) as { error?: { code: string } }).error?.code ?? "OK";
}

/** The real namespace, counting admission calls (one `getByName` per call). */
function countingNamespace(): { namespace: DurableObjectNamespace<AuthRateLimiter>; calls: string[] } {
  const calls: string[] = [];
  const namespace = {
    getByName: (name: string) => {
      calls.push(name);
      return env.AUTH_RATE_LIMITER.getByName(name);
    },
  } as unknown as DurableObjectNamespace<AuthRateLimiter>;
  return { namespace, calls };
}

const logged = (event: string) => logLines.some((line) => line.includes(`"${event}"`));

describe("sign-in start (login policy, 20 / 60 s)", () => {
  it("refuses the 21st attempt with a valid token from one address, after Turnstile, before Better Auth", async () => {
    const ip = freshIp();
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    for (let i = 0; i < 20; i += 1) expect((await startSignIn({ "cf-connecting-ip": ip }, environment)).status).toBe(200);
    const refused = await startSignIn({ "cf-connecting-ip": ip }, environment);
    expect(refused.status).toBe(429);
    expect(await codeOf(refused)).toBe("RATE_LIMITED");
    const retryAfter = Number(refused.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(60);
    // Turnstile was verified for every attempt; the limit then refused the
    // 21st before Better Auth (which would have set the state cookie).
    expect(siteverifyCalls()).toBe(21);
    expect(calls).toHaveLength(21);
    expect(refused.headers.getSetCookie()).toEqual([]);
  }, 30_000);

  it("an invalid Turnstile token never reaches the Durable Object and uses up no admissions", async () => {
    providers.turnstile = "fail";
    const ip = freshIp();
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    for (let i = 0; i < 25; i += 1) expect(await codeOf(await startSignIn({ "cf-connecting-ip": ip }, environment))).toBe("TURNSTILE_FAILED");
    expect(siteverifyCalls()).toBe(25);
    expect(calls).toHaveLength(0);
    // The failed attempts consumed nothing: the full allowance remains.
    providers.turnstile = "pass";
    for (let i = 0; i < 20; i += 1) expect((await startSignIn({ "cf-connecting-ip": ip }, environment)).status).toBe(200);
    expect((await startSignIn({ "cf-connecting-ip": ip }, environment)).status).toBe(429);
  }, 30_000);

  it("rejects an invalid request, an unavailable provider or a foreign origin before Turnstile and the Durable Object", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const post = (body: unknown, origin = BASE) =>
      call("/api/auth/sign-in/social", { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify(body) }, { env: environment });
    expect((await post({ provider: "google" })).status).toBe(400);
    expect((await post({ provider: "google", turnstileToken: "t", extra: 1 })).status).toBe(400);
    expect((await post({ provider: "facebook", turnstileToken: "t" })).status).toBe(400);
    expect((await post({ provider: "google", turnstileToken: "t" }, "https://evil.example")).status).toBe(403);
    expect(siteverifyCalls()).toBe(0);
    expect(calls).toHaveLength(0);
  });

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
    const { namespace, calls } = countingNamespace();
    const response = await createWorker({ cspMode: "production" }).fetch(bare, permissive({ AUTH_RATE_LIMITER: namespace }), ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(429);
    expect(siteverifyCalls()).toBe(0);
    expect(calls).toHaveLength(0);
    expect(logged("ratelimit.client_unidentified")).toBe(true);
  });
});

describe("other authentication paths share or have their own authoritative counters", () => {
  it("the OAuth callback shares the login counter and is refused before Better Auth", async () => {
    const ip = freshIp();
    const jar = new CookieJar();
    const flow = await startFlow(identity("google"), jar, permissive(), ip);
    for (let i = 0; i < 19; i += 1) await startSignIn({ "cf-connecting-ip": ip });
    const before = providerCalls();
    const callback = await call(`/api/auth/callback/google?code=${flow.code}&state=${flow.state}`, { headers: { "cf-connecting-ip": ip, cookie: jar.header() } }, { env: permissive() });
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
    // Passkey verification shares the counter: with a live challenge (issued
    // to another address), refused before its body is read.
    const browser = new CookieJar();
    browser.store(await passkeyOptions({ "cf-connecting-ip": freshIp() }));
    const verify = await call(
      "/api/auth/passkey/verify-authentication",
      { method: "POST", headers: { origin: BASE, "content-type": "application/json", "cf-connecting-ip": ip, cookie: browser.header() }, body: "{}" },
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

describe("OAuth callback precondition (state parameter and Better Auth's state cookie)", () => {
  const callback = (provider: string, query: string, cookie: string, environment: Env) =>
    call(`/api/auth/callback/${provider}?${query}`, { headers: cookie ? { cookie } : {} }, { env: environment });
  const loginCalls = (calls: string[]) => calls.filter((name) => name.includes(":login:")).length;
  const stateCookieName = (jar: CookieJar) => jar.names().find((name) => name.endsWith(".state")) ?? "missing";

  it.each(["google", "github"] as const)("a valid %s callback is unchanged and counted once by the login limit", async (provider) => {
    const { namespace, calls } = countingNamespace();
    const result = await signIn(providers, identity(provider), new CookieJar(), { env: permissive({ AUTH_RATE_LIMITER: namespace }) });
    expect(result.location).toBe(`${BASE}/dashboard`);
    // Start and callback each take one login admission; a new profile one signup admission.
    expect(loginCalls(calls)).toBe(2);
    expect(calls.filter((name) => name.includes(":signup:"))).toHaveLength(1);
  });

  it("a provider error callback with a valid state still reaches Better Auth", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const jar = new CookieJar();
    const flow = await startFlow(identity("google"), jar, environment);
    const response = await callback("google", `error=access_denied&error_description=denied&state=${flow.state}`, jar.header(), environment);
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(`${BASE}/login?error=access_denied`);
    expect(loginCalls(calls)).toBe(2);
  });

  it("a callback without a state is refused before the limiter, as Better Auth would (state_not_found)", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const jar = new CookieJar();
    const flow = await startFlow(identity("google"), jar, environment);
    const before = providerCalls();
    for (const query of [`code=${flow.code}`, `code=${flow.code}&state=`, "error=access_denied", ""]) {
      const response = await callback("google", query, jar.header(), environment);
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toBe(`${BASE}/login?error=state_not_found`);
      expect(response.headers.getSetCookie()).toEqual([]);
    }
    expect(loginCalls(calls)).toBe(1); // the start only
    expect(providerCalls()).toBe(before);
    expect(logged("auth.oauth.callback.failure")).toBe(true);
  });

  it("a callback without Better Auth's state cookie is refused before the limiter (state_mismatch) and consumes nothing", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const jar = new CookieJar();
    const who = identity("github");
    const flow = await startFlow(who, jar, environment);
    const name = stateCookieName(jar);
    expect(name).toBe("lightagent.state"); // Better Auth's database strategy, cookie prefix `lightagent`
    const before = providerCalls();
    for (const cookie of ["", "other=1", `state=${jar.get(name)}`, `better-auth.state=${jar.get(name)}`, `${name}=`]) {
      const response = await callback("github", `code=${flow.code}&state=${flow.state}`, cookie, environment);
      expect(response.headers.get("location")).toBe(`${BASE}/login?error=state_mismatch`);
    }
    expect(loginCalls(calls)).toBe(1);
    expect(providerCalls()).toBe(before);
    // The refused callbacks consumed neither the state nor an admission: the real one still completes.
    const real = await callback("github", `code=${flow.code}&state=${flow.state}`, jar.header(), environment);
    expect(real.headers.get("location")).toBe(`${BASE}/dashboard`);
  });

  it("a present but forged state cookie is left to Better Auth, which refuses it", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const jar = new CookieJar();
    const flow = await startFlow(identity("google"), jar, environment);
    jar.set(stateCookieName(jar), `${flow.state}.forged-signature`);
    const response = await callback("google", `code=${flow.code}&state=${flow.state}`, jar.header(), environment);
    jar.store(response);
    expect(response.headers.get("location")).toMatch(new RegExp(`^${BASE}/login\\?error=`));
    expect(jar.get("lightagent.session_token")).toBeUndefined();
    expect(loginCalls(calls)).toBe(2);
  });

  it("replaying a completed callback with its original cookies is refused by Better Auth (single-use state)", async () => {
    const environment = permissive();
    const jar = new CookieJar();
    const flow = await startFlow(identity("google"), jar, environment);
    const cookies = jar.header();
    const first = await callback("google", `code=${flow.code}&state=${flow.state}`, cookies, environment);
    expect(first.headers.get("location")).toBe(`${BASE}/dashboard`);
    const replay = await callback("google", `code=${flow.code}&state=${flow.state}`, cookies, environment);
    expect(replay.headers.get("location")).toMatch(new RegExp(`^${BASE}/login\\?error=`));
    expect(replay.headers.getSetCookie().some((c) => c.startsWith("lightagent.session_token=") && !c.startsWith("lightagent.session_token=;"))).toBe(false);
  });
});

describe("passkey sign-in options: Turnstile before the limiter (M3a)", () => {
  it("a failing token never reaches the Durable Object and writes no challenge", async () => {
    providers.turnstile = "fail";
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const ip = freshIp();
    const rows = await challengeRows();
    for (let i = 0; i < 21; i += 1) {
      const response = await passkeyOptions({ "cf-connecting-ip": ip }, environment, { turnstileToken: "invalid" });
      expect(response.status).toBe(403);
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(await codeOf(response)).toBe("TURNSTILE_FAILED");
    }
    expect(siteverifyCalls()).toBe(21);
    expect(calls).toEqual([]);
    expect(await challengeRows()).toBe(rows);
    // No admissions were used: the address still has its full allowance.
    providers.turnstile = "pass";
    for (let i = 0; i < 20; i += 1) expect((await passkeyOptions({ "cf-connecting-ip": ip }, environment)).status).toBe(200);
    expect(calls).toHaveLength(20);
  }, 30_000);

  it("fails closed without the Durable Object when Siteverify is unavailable", async () => {
    providers.turnstile = "unavailable";
    const { namespace, calls } = countingNamespace();
    const rows = await challengeRows();
    const response = await passkeyOptions({ "cf-connecting-ip": freshIp() }, permissive({ AUTH_RATE_LIMITER: namespace }));
    expect(response.status).toBe(403);
    expect(await codeOf(response)).toBe("TURNSTILE_FAILED");
    expect(siteverifyCalls()).toBe(1);
    expect(calls).toEqual([]);
    expect(await challengeRows()).toBe(rows);
    expect(logged("turnstile.failed")).toBe(true);
  });

  it("accepts only a token solved for the login action on an expected hostname", async () => {
    providers.turnstile = "real";
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    expect((await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment)).status).toBe(200);
    providers.turnstileAction = "signup";
    const wrongAction = await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment);
    expect(wrongAction.status).toBe(403);
    expect(await codeOf(wrongAction)).toBe("TURNSTILE_FAILED");
    providers.turnstileAction = "login";
    providers.turnstileHostname = "evil.example";
    const wrongHost = await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment);
    expect(wrongHost.status).toBe(403);
    expect(await codeOf(wrongHost)).toBe("TURNSTILE_FAILED");
    expect(siteverifyCalls()).toBe(3);
    expect(calls).toHaveLength(1);
  });

  it("refuses a GET, a foreign or missing origin, a non-JSON body and a bad body before Turnstile and the Durable Object", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const path = "/api/auth/passkey/generate-authenticate-options";
    const json = JSON.stringify({ turnstileToken: "t" });
    const get = await call(path, { headers: { "cf-connecting-ip": freshIp() } }, { env: environment });
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
    expect((await call(path, { method: "POST", headers: { origin: "https://evil.example", "content-type": "application/json" }, body: json }, { env: environment })).status).toBe(403);
    expect((await call(path, { method: "POST", headers: { "content-type": "application/json" }, body: json }, { env: environment })).status).toBe(403);
    expect((await call(path, { method: "POST", headers: { origin: BASE, "content-type": "text/plain" }, body: json }, { env: environment })).status).toBe(415);
    for (const body of [{}, { turnstileToken: "" }, { turnstileToken: "t", userId: "usr_someone" }, { turnstileToken: "x".repeat(2049) }]) {
      expect((await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment, body)).status).toBe(400);
    }
    expect(siteverifyCalls()).toBe(0);
    expect(calls).toEqual([]);
  });

  it("refuses an unidentifiable client before Turnstile", async () => {
    const response = await passkeyOptions({ "cf-connecting-ip": "unknown" });
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("60");
    expect(siteverifyCalls()).toBe(0);
  });
});

describe("passkey verification: a live challenge before the limiter (M3b)", () => {
  /** BETTER_AUTH_SECRET of the test environment (vitest.config.ts). */
  const TEST_SECRET = "test-only-better-auth-secret-0123456789abcdef";
  const OTHER_SECRET = "another-secret-of-sufficient-length-0123456789";
  const encoder = new TextEncoder();
  /** A well-formed assertion for a credential nobody enrolled. */
  const UNKNOWN_CREDENTIAL = { response: { id: "AAAA", rawId: "AAAA", type: "public-key", response: { clientDataJSON: "e30", authenticatorData: "AAAA", signature: "AAAA" } } };

  /** A better-call signed cookie value for `token`, made independently of the code under test. */
  async function signedValue(token: string, secret = TEST_SECRET): Promise<string> {
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(token)));
    return encodeURIComponent(`${token}.${btoa(String.fromCharCode(...mac))}`);
  }

  /** A browser holding a live challenge from the options endpoint, and the challenge cookie's name. */
  async function liveChallenge(environment: Env): Promise<{ browser: CookieJar; name: string; options: { challenge: string } }> {
    const browser = new CookieJar();
    const response = await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment);
    expect(response.status).toBe(200);
    browser.store(response);
    const name = browser.names().find((n) => n.endsWith("better-auth-passkey"));
    if (!name) throw new Error("no challenge cookie");
    return { browser, name, options: (await response.json()) as { challenge: string } };
  }

  const verify = (cookie: string, environment: Env, body: unknown = UNKNOWN_CREDENTIAL) =>
    call(
      "/api/auth/passkey/verify-authentication",
      { method: "POST", headers: { origin: BASE, "content-type": "application/json", "cf-connecting-ip": freshIp(), cookie }, body: JSON.stringify(body) },
      { env: environment },
    );

  /** Sign a user in with Google and enroll a passkey through the real endpoints. */
  async function enrolledUser(environment: Env): Promise<SoftAuthenticator> {
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar, { env: environment });
    const authenticator = new SoftAuthenticator("localhost", BASE);
    const options = await call("/api/auth/passkey/generate-register-options?name=Key", { headers: { cookie: jar.header() } }, { env: environment });
    jar.store(options);
    const credential = await authenticator.register((await options.json()) as { challenge: string });
    expect((await send("POST", "/api/auth/passkey/verify-registration", jar, { response: credential, name: "Key" }, { env: environment })).status).toBe(200);
    return authenticator;
  }

  const preconditionFailures = (reason: string) =>
    logLines.filter((line) => line.includes('"auth.passkey.login.failure"') && line.includes('"precondition"') && line.includes(`"${reason}"`)).length;

  it("a missing, malformed, forged or unknown challenge never reaches the Durable Object", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const { name } = await liveChallenge(environment);
    const before = calls.length;
    const cases: Array<[string, string]> = [
      ["missing", ""],
      ["malformed", `${name}=no-signature`],
      ["malformed", `${name}=${encodeURIComponent(`${randomId("tok")}.${"A".repeat(44)}`)}`], // 44 characters, no trailing "="
      ["bad_signature", `${name}=${await signedValue(randomId("tok"), OTHER_SECRET)}`],
      ["bad_signature", `${name}=${encodeURIComponent(`${randomId("tok")}.${"A".repeat(43)}=`)}`],
      ["not_found", `${name}=${await signedValue(randomId("tok"))}`], // correctly signed, but never issued
    ];
    for (const [, cookie] of cases) {
      const response = await verify(cookie, environment);
      expect(response.status).toBe(400);
      expect(await codeOf(response)).toBe("INVALID_REQUEST");
      expect(response.headers.getSetCookie()).toEqual([]);
    }
    expect(calls.length).toBe(before);
    for (const reason of ["missing", "malformed", "bad_signature", "not_found"]) {
      expect(preconditionFailures(reason)).toBe(cases.filter(([r]) => r === reason).length);
    }
  });

  it("an expired challenge is refused without the Durable Object, and the check deletes nothing", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const { name } = await liveChallenge(environment);
    const before = calls.length;
    const token = randomId("tok");
    const other = randomId("tok");
    const past = new Date(Date.now() - 60_000).toISOString();
    for (const identifier of [token, other]) {
      await env.DB.prepare(`INSERT INTO "verification" ("id", "identifier", "value", "expiresAt", "createdAt", "updatedAt") VALUES (?1, ?2, ?3, ?4, ?4, ?4)`)
        .bind(randomId("ver"), identifier, JSON.stringify({ type: "authentication", expectedChallenge: "x", userData: { id: "" } }), past)
        .run();
    }
    const response = await verify(`${name}=${await signedValue(token)}`, environment);
    expect(response.status).toBe(400);
    expect(calls.length).toBe(before);
    expect(preconditionFailures("expired")).toBe(1);
    // findVerificationValue would have deleted every expired row; the read-only lookup deleted none.
    const left = await env.DB.prepare(`SELECT COUNT(*) AS n FROM "verification" WHERE "identifier" IN (?1, ?2)`).bind(token, other).first<{ n: number }>();
    expect(left?.n).toBe(2);
  });

  it("a live challenge is admitted and consumed by Better Auth; replaying it never reaches the Durable Object", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const authenticator = await enrolledUser(environment);
    const { browser, options } = await liveChallenge(environment);
    const assertion = await authenticator.authenticate(options);
    const before = calls.length;
    expect((await verify(browser.header(), environment, { response: assertion })).status).toBe(200);
    expect(calls.length).toBe(before + 1);
    const replay = await verify(browser.header(), environment, { response: assertion });
    expect(replay.status).toBe(400);
    expect(calls.length).toBe(before + 1);
    expect(preconditionFailures("not_found")).toBe(1);
  }, 30_000);

  it("concurrent verifications of one challenge: Better Auth lets exactly one through", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const authenticator = await enrolledUser(environment);
    const { browser, options } = await liveChallenge(environment);
    const assertion = await authenticator.authenticate(options);
    const before = calls.length;
    const responses = await Promise.all(Array.from({ length: 5 }, () => verify(browser.header(), environment, { response: assertion })));
    expect(responses.map((r) => r.status).sort((a, b) => a - b)).toEqual([200, 400, 400, 400, 400]);
    expect(calls.length - before).toBeGreaterThanOrEqual(1);
    expect(calls.length - before).toBeLessThanOrEqual(5);
  }, 30_000);

  it("with two challenge cookies of one name, the check reads the one Better Auth reads (the first)", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = permissive({ AUTH_RATE_LIMITER: namespace });
    const { browser, name } = await liveChallenge(environment);
    const live = browser.get(name) ?? "";
    const forged = await signedValue(randomId("tok"), OTHER_SECRET);
    const before = calls.length;
    // Forged first: refused by the check, as Better Auth's getSignedCookie would refuse it.
    expect((await verify(`${name}=${forged}; ${name}=${live}`, environment)).status).toBe(400);
    expect(calls.length).toBe(before);
    // Live first: admitted, and Better Auth consumes that same challenge (then finds no such credential: 401).
    const rows = await challengeRows();
    expect((await verify(`${name}=${live}; ${name}=${forged}`, environment)).status).toBe(401);
    expect(calls.length).toBe(before + 1);
    expect(await challengeRows()).toBe(rows - 1);
  });

  it("fails closed without the Durable Object when the challenge lookup fails (D1)", async () => {
    const { name } = await liveChallenge(permissive());
    const { namespace, calls } = countingNamespace();
    const failing = new Proxy(env.DB, {
      get(target, property) {
        if (property === "prepare") {
          return (sql: string) => {
            if (sql.includes("verification")) throw new Error("D1_ERROR: simulated outage");
            return target.prepare(sql);
          };
        }
        const value: unknown = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const response = await verify(`${name}=${await signedValue(randomId("tok"))}`, permissive({ AUTH_RATE_LIMITER: namespace, DB: failing }));
    expect(response.status).toBe(500);
    expect(await codeOf(response)).toBe("INTERNAL_ERROR");
    expect(calls).toEqual([]);
    expect(logged("auth.passkey.precheck_failed")).toBe(true);
  });
});

describe("when the authoritative limiter is unavailable", () => {
  const throwing = (message: string) =>
    ({
      getByName: () => ({
        admit: async () => {
          throw new Error(message);
        },
      }),
    }) as unknown as DurableObjectNamespace<AuthRateLimiter>;

  it.each([
    ["throws", { AUTH_RATE_LIMITER: throwing("Durable Object is overloaded") }, "ratelimit.authoritative_failed"],
    // The shape of a Workers Free daily-quota refusal: fails closed like any other error.
    ["is over its daily quota", { AUTH_RATE_LIMITER: throwing("Exceeded allowed rows written in Durable Objects free tier.") }, "ratelimit.authoritative_failed"],
    ["is not bound", { AUTH_RATE_LIMITER: undefined as unknown as DurableObjectNamespace<AuthRateLimiter> }, "ratelimit.authoritative_missing"],
  ])("sign-in and passkey options fail closed when the namespace %s", async (_label, overrides, event) => {
    const environment = permissive(overrides);
    const rows = await challengeRows();
    const start = await startSignIn({ "cf-connecting-ip": freshIp() }, environment);
    expect(start.status).toBe(429);
    expect(start.headers.get("retry-after")).toBe("60");
    // Turnstile passed, then the limiter refused: Better Auth was never reached.
    expect(siteverifyCalls()).toBe(1);
    expect(start.headers.getSetCookie()).toEqual([]);
    const options = await passkeyOptions({ "cf-connecting-ip": freshIp() }, environment);
    expect(options.status).toBe(429);
    expect(await challengeRows()).toBe(rows);
    expect(logged(event)).toBe(true);
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
