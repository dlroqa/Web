import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IdentityService } from "../../src/worker/auth/identity";
import { safeCallbackLocation } from "../../src/worker/auth/gateway";
import { UserRepository } from "../../src/worker/db/users";
import { CloudflareRateLimiter } from "../../src/worker/security/rate-limit";
import { createLogger } from "../../src/worker/utils/log";
import { randomId } from "../../src/worker/utils/random";
import { FakeProviders, get, identity, send, signIn } from "../helpers/auth";
import { CookieJar, parseSetCookie } from "../helpers/cookies";
import { BASE, call, testEnv } from "../helpers/worker";

const SESSION_COOKIE = "lightagent.session_token";
let providers: FakeProviders;
let logLines: string[];

beforeEach(() => {
  logLines = [];
  for (const level of ["log", "info", "warn", "error"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      logLines.push(args.map((a) => (a instanceof Error ? `${a.message} ${a.stack}` : typeof a === "string" ? a : JSON.stringify(a))).join(" "));
    });
  }
  providers = new FakeProviders().install();
});

afterEach(() => {
  providers.restore();
  vi.restoreAllMocks();
});

async function me(jar: CookieJar) {
  const response = await get("/api/me", jar);
  return { status: response.status, body: (await response.json()) as { ok: boolean; data?: { id: string; status: string; displayName: string | null }; error?: { code: string } } };
}

async function profileFor(authEmail: string) {
  const row = await env.DB.prepare(`SELECT p.* FROM user_profiles p JOIN "user" u ON u.id = p.auth_user_id WHERE u.email = ?1`).bind(authEmail).first<{ id: string; status: string }>();
  return row;
}

describe("first sign-in creates the application identity", () => {
  it("creates exactly one active profile, returns it from /api/me, and reuses it on repeat sign-in", async () => {
    const who = identity("google", { name: "Ada Lovelace" });
    const jar = new CookieJar();
    const first = await signIn(providers, who, jar);
    expect(first.location).toBe(`${BASE}/dashboard`);
    const firstMe = await me(jar);
    expect(firstMe.status).toBe(200);
    expect(firstMe.body.data).toMatchObject({ status: "active", displayName: "Ada Lovelace" });
    expect(firstMe.body.data?.id).toMatch(/^usr_[a-z0-9]{26}$/);

    const again = new CookieJar();
    await signIn(providers, who, again);
    expect((await me(again)).body.data?.id).toBe(firstMe.body.data?.id);
    const count = await env.DB.prepare(`SELECT COUNT(*) AS n FROM user_profiles WHERE auth_user_id = (SELECT id FROM "user" WHERE email = ?1)`).bind(who.email).first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it("concurrent first authentications create exactly one profile", async () => {
    const service = new IdentityService(new UserRepository(env.DB), "open", new CloudflareRateLimiter(env, createLogger()));
    const authUserId = randomId("auth");
    const results = await Promise.all(Array.from({ length: 10 }, () => service.ensureProfile(authUserId, { name: "x", sourceAddress: "203.0.113.1" })));
    expect(new Set(results.map((r) => r.user.id)).size).toBe(1);
    expect(results.filter((r) => r.created)).toHaveLength(1);
  });

  it("does not create any agent profile or provisioning job", async () => {
    const jar = new CookieJar();
    await signIn(providers, identity("github"), jar);
    const id = (await me(jar)).body.data?.id;
    const agents = await env.DB.prepare(`SELECT COUNT(*) AS n FROM agent_profiles WHERE user_id = ?1`).bind(id).first<{ n: number }>();
    const jobs = await env.DB.prepare(`SELECT COUNT(*) AS n FROM provisioning_jobs WHERE user_id = ?1`).bind(id).first<{ n: number }>();
    expect([agents?.n, jobs?.n]).toEqual([0, 0]);
  });

  it("under the approval policy, new accounts are pending: identity only, no application pages", async () => {
    const approvalEnv = testEnv({ SIGNUP_POLICY: "approval" });
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar, { env: approvalEnv });
    const response = await get("/api/me", jar, { env: approvalEnv });
    expect(((await response.json()) as { data: { status: string } }).data.status).toBe("pending");
    const security = await get("/api/security/sessions", jar, { env: approvalEnv });
    expect(security.status).toBe(403);
    expect(((await security.json()) as { error: { code: string } }).error.code).toBe("ACCOUNT_PENDING");
  });
});

describe("application status is authoritative over the session", () => {
  it.each(["suspended", "disabled"] as const)("a %s account is denied even with a valid session, and cannot sign in again", async (status) => {
    const who = identity("google");
    const jar = new CookieJar();
    await signIn(providers, who, jar);
    const users = new UserRepository(env.DB);
    const profile = await profileFor(who.email);
    if (!profile) throw new Error("no profile");
    if (status === "suspended") await users.transition(profile.id, "suspended");
    else await users.transition(profile.id, "disabled");

    const denied = await me(jar);
    expect(denied.status).toBe(403);
    expect(denied.body.error?.code).toBe("ACCOUNT_DISABLED");
    expect((await get("/api/security/sessions", jar)).status).toBe(403);
    expect((await call("/api/auth/passkey/generate-register-options", { headers: { cookie: jar.header() } })).status).toBe(403);

    const retry = new CookieJar();
    const result = await signIn(providers, who, retry);
    expect(result.location).toMatch(/\/login\?error=/);
    expect(retry.get(SESSION_COOKIE)).toBeUndefined();
  });

  it("/api/session reports sign-in state without erroring, and hides blocked accounts", async () => {
    const anonymous = (await (await get("/api/session", new CookieJar())).json()) as { data: unknown };
    expect(anonymous.data).toEqual({ signedIn: false });
    const who = identity("google");
    const jar = new CookieJar();
    await signIn(providers, who, jar);
    const signedIn = (await (await get("/api/session", jar)).json()) as { data: { signedIn: boolean; me: { status: string } } };
    expect(signedIn.data).toMatchObject({ signedIn: true, me: { status: "active" } });
    const profile = await profileFor(who.email);
    await new UserRepository(env.DB).transition(profile?.id ?? "", "suspended");
    const blocked = (await (await get("/api/session", jar)).json()) as { data: unknown };
    expect(blocked.data).toEqual({ signedIn: false, blocked: true, status: "suspended" });
  });

  it("requests without a session get AUTH_REQUIRED", async () => {
    const response = await get("/api/me", new CookieJar());
    expect(response.status).toBe(401);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe("AUTH_REQUIRED");
  });

  it("a forged or random session cookie is rejected", async () => {
    const jar = new CookieJar();
    jar.set(SESSION_COOKIE, `${randomId("forged")}.${randomId("sig")}`);
    expect((await me(jar)).status).toBe(401);
  });
});

describe("OAuth", () => {
  it("requests only minimum identity scopes, with PKCE and state", async () => {
    const google = await signIn(providers, identity("google"), new CookieJar());
    const g = google.authorizationUrl.searchParams;
    expect(g.get("scope")).toBe("openid email profile");
    expect(g.get("include_granted_scopes")).toBeNull();
    expect(g.get("code_challenge_method")).toBe("S256");
    expect(g.get("state")).toMatch(/.{16,}/);
    expect(g.get("redirect_uri")).toBe(`${BASE}/api/auth/callback/google`);

    const github = await signIn(providers, identity("github"), new CookieJar());
    expect(github.authorizationUrl.searchParams.get("scope")).toBe("read:user user:email");
  });

  it("the browser cannot add scopes, choose redirect targets, or pass unknown fields", async () => {
    for (const body of [
      { provider: "google", turnstileToken: "t", scopes: ["https://www.googleapis.com/auth/drive"] },
      { provider: "google", turnstileToken: "t", callbackURL: "https://evil.example/dashboard" },
      { provider: "google", turnstileToken: "t", callbackURL: "//evil.example" },
      { provider: "google", turnstileToken: "t", errorCallbackURL: "https://evil.example" },
      { provider: "google", turnstileToken: "t", idToken: { token: "x" } },
      { provider: "evil", turnstileToken: "t" },
    ]) {
      const response = await send("POST", "/api/auth/sign-in/social", new CookieJar(), body);
      expect(response.status, JSON.stringify(body)).toBe(400);
    }
  });

  it("requires a valid Turnstile token to start sign-in", async () => {
    providers.turnstile = "fail";
    const response = await send("POST", "/api/auth/sign-in/social", new CookieJar(), { provider: "google", turnstileToken: "bad" });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe("TURNSTILE_FAILED");
    const missing = await send("POST", "/api/auth/sign-in/social", new CookieJar(), { provider: "google" });
    expect(missing.status).toBe(400);
  });

  it("rejects a callback with a missing or forged state", async () => {
    const jar = new CookieJar();
    const code = randomId("code");
    providers.codes.set(code, identity("google"));
    const noState = await call(`/api/auth/callback/google?code=${code}`, { headers: { cookie: jar.header() } });
    expect(noState.headers.get("location")).toMatch(/\/login\?error=/);
    const forged = await call(`/api/auth/callback/google?code=${code}&state=${randomId("state")}`, { headers: { cookie: jar.header() } });
    expect(forged.headers.get("location")).toMatch(/\/login\?error=/);
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
  });

  it("a state started in one browser cannot be completed in another (login CSRF)", async () => {
    const victim = new CookieJar();
    const attacker = new CookieJar();
    const start = await send("POST", "/api/auth/sign-in/social", attacker, { provider: "google", turnstileToken: "t" });
    const url = new URL(((await start.json()) as { data: { url: string } }).data.url);
    const code = randomId("code");
    providers.codes.set(code, identity("google"));
    const callback = await call(`/api/auth/callback/google?code=${code}&state=${url.searchParams.get("state")}`, { headers: { cookie: victim.header() } });
    victim.store(callback);
    expect(callback.headers.get("location")).toMatch(/\/login\?error=/);
    expect(victim.get(SESSION_COOKIE)).toBeUndefined();
  });

  it("provider errors are reduced to a code; provider text never reaches the browser", async () => {
    providers.googleTokenStatus = 500;
    const result = await signIn(providers, identity("google"), new CookieJar());
    expect(result.location).toMatch(/^http:\/\/localhost:5173\/login\?error=[a-z0-9_]+$/);
    expect(result.location).not.toContain("secret provider detail");
    expect(await result.callback.text()).not.toContain("secret provider detail");
  });

  it("safeCallbackLocation only allows our origin and allowlisted pages", () => {
    const origin = "https://app.example";
    expect(safeCallbackLocation(`${origin}/dashboard`, origin)).toEqual({ location: `${origin}/dashboard`, error: null });
    expect(safeCallbackLocation("/security", origin).location).toBe(`${origin}/security`);
    for (const bad of ["https://evil.example/dashboard", "//evil.example", `${origin}/admin`, "javascript:alert(1)", null]) {
      expect(safeCallbackLocation(bad, origin).location).toBe(`${origin}/login?error=callback_failed`);
    }
    expect(safeCallbackLocation(`${origin}/login?error=<script>`, origin).location).toBe(`${origin}/login?error=callback_failed`);
    expect(safeCallbackLocation(`${origin}/login?error=account_not_linked`, origin).location).toBe(`${origin}/login?error=account_not_linked`);
  });
});

describe("rate limiting", () => {
  it("one client address cannot start unlimited sign-ins", async () => {
    const ip = "198.51.100.77";
    const statuses: number[] = [];
    for (let i = 0; i < 25; i += 1) {
      const response = await call("/api/auth/sign-in/social", {
        method: "POST",
        headers: { origin: BASE, "content-type": "application/json", "cf-connecting-ip": ip },
        body: JSON.stringify({ provider: "google", turnstileToken: "t" }),
      });
      statuses.push(response.status);
    }
    expect(statuses.filter((s) => s === 200).length).toBeLessThanOrEqual(20);
    expect(statuses).toContain(429);
    // Another client is unaffected.
    const other = await send("POST", "/api/auth/sign-in/social", new CookieJar(), { provider: "google", turnstileToken: "t" });
    expect(other.status).toBe(200);
  }, 30_000);

  // The live staging finding: every attempt carried an invalid Turnstile
  // token. The limiter must still refuse, because it runs before Siteverify.
  it("refuses one client address even when every attempt fails Turnstile, and stops calling Siteverify", async () => {
    providers.turnstile = "fail";
    const ip = "198.51.100.78";
    const codes: string[] = [];
    for (let i = 0; i < 25; i += 1) {
      const response = await call("/api/auth/sign-in/social", {
        method: "POST",
        headers: { origin: BASE, "content-type": "application/json", "cf-connecting-ip": ip },
        body: JSON.stringify({ provider: "google", turnstileToken: "invalid" }),
      });
      codes.push(((await response.json()) as { error: { code: string } }).error.code);
      if (response.status === 429) expect(response.headers.get("retry-after")).toBe("60");
    }
    expect(codes.filter((c) => c === "TURNSTILE_FAILED").length).toBeLessThanOrEqual(20);
    expect(codes.at(-1)).toBe("RATE_LIMITED");
    expect(providers.outbound.filter((o) => o.includes("/turnstile/v0/siteverify")).length).toBe(codes.filter((c) => c === "TURNSTILE_FAILED").length);
  }, 30_000);

  describe("sign-in start ordering: origin → body → login limiter → Turnstile → Better Auth", () => {
    function countingLimiter(success: boolean): RateLimit & { keys: string[] } {
      const keys: string[] = [];
      return { keys, limit: async ({ key }) => (keys.push(key), { success }) };
    }
    const siteverifyCalls = () => providers.outbound.filter((o) => o.includes("/turnstile/v0/siteverify")).length;
    const start = (rl: RateLimit, init: { origin?: string; body?: string }) =>
      call(
        "/api/auth/sign-in/social",
        {
          method: "POST",
          headers: { origin: init.origin ?? BASE, "content-type": "application/json", "cf-connecting-ip": "198.51.100.79" },
          body: init.body ?? JSON.stringify({ provider: "google", turnstileToken: "t" }),
        },
        { env: testEnv({ RL_LOGIN: rl }) },
      );

    it("a foreign origin is refused before the limiter or Turnstile", async () => {
      const rl = countingLimiter(true);
      expect((await start(rl, { origin: "https://evil.example" })).status).toBe(403);
      expect(rl.keys).toEqual([]);
      expect(siteverifyCalls()).toBe(0);
    });

    it("a malformed body is refused before the limiter or Turnstile", async () => {
      const rl = countingLimiter(true);
      expect((await start(rl, { body: JSON.stringify({ provider: "google" }) })).status).toBe(400);
      expect(rl.keys).toEqual([]);
      expect(siteverifyCalls()).toBe(0);
    });

    it("a limiter refusal is a 429 and never reaches Siteverify or Better Auth", async () => {
      const rl = countingLimiter(false);
      const response = await start(rl, {});
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("60");
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(rl.keys).toEqual(["login:ip:198.51.100.79"]);
      expect(siteverifyCalls()).toBe(0);
    });

    it("the limiter is consulted, keyed on the client address, before Turnstile refuses", async () => {
      providers.turnstile = "fail";
      const rl = countingLimiter(true);
      const response = await start(rl, {});
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe("TURNSTILE_FAILED");
      expect(rl.keys).toEqual(["login:ip:198.51.100.79"]);
      expect(siteverifyCalls()).toBe(1);
    });
  });

  it("passkey sign-in options are refused by their own limiter before Better Auth", async () => {
    const rl: RateLimit = { limit: async () => ({ success: false }) };
    const response = await call("/api/auth/passkey/generate-authenticate-options", { headers: { "cf-connecting-ip": "198.51.100.80" } }, { env: testEnv({ RL_PASSKEY_LOGIN: rl }) });
    expect(response.status).toBe(429);
    expect(response.headers.getSetCookie()).toEqual([]);
  });
});

describe("account linking cannot be used for takeover", () => {
  it("a second provider with the same verified email is not merged into the existing account", async () => {
    const email = `${randomId("victim")}@example.test`;
    const victim = new CookieJar();
    await signIn(providers, identity("google", { email }), victim);
    const victimId = (await me(victim)).body.data?.id;

    const attacker = new CookieJar();
    const result = await signIn(providers, identity("github", { email }), attacker);
    expect(result.location).toMatch(/\/login\?error=/);
    expect(attacker.get(SESSION_COOKIE)).toBeUndefined();
    const accounts = await env.DB.prepare(`SELECT "providerId" FROM account WHERE "userId" = (SELECT id FROM "user" WHERE email = ?1)`).bind(email).all<{ providerId: string }>();
    expect(accounts.results.map((a) => a.providerId)).toEqual(["google"]);
    expect((await me(victim)).body.data?.id).toBe(victimId);
  });

  it("an unverified provider email cannot claim an existing account", async () => {
    const email = `${randomId("victim")}@example.test`;
    await signIn(providers, identity("github", { email }), new CookieJar());
    const result = await signIn(providers, identity("google", { email, emailVerified: false }), new CookieJar());
    expect(result.location).toMatch(/\/login\?error=/);
  });

  it("one provider identity can never belong to two users (database)", async () => {
    const insert = (user: string) =>
      env.DB.prepare(`INSERT INTO account (id, "accountId", "providerId", "userId", "createdAt", "updatedAt") VALUES (?1, 'same-sub', 'google', ?2, '2026-01-01', '2026-01-01')`)
        .bind(randomId("acc"), user)
        .run();
    const users = await env.DB.prepare(`SELECT id FROM "user" LIMIT 2`).all<{ id: string }>();
    const [a, b] = users.results;
    if (!a || !b) throw new Error("need two users");
    await env.DB.prepare(`DELETE FROM account WHERE "accountId" = 'same-sub'`).run();
    await insert(a.id);
    await expect(insert(b.id)).rejects.toThrow(/UNIQUE/);
  });
});

describe("sessions", () => {
  it("session cookies are HttpOnly, SameSite=Strict, and scoped to /api", async () => {
    const result = await signIn(providers, identity("google"), new CookieJar());
    const session = result.callback.headers.getSetCookie().map(parseSetCookie).find((c) => c.name === SESSION_COOKIE);
    expect(session?.attributes).toMatchObject({ httponly: true, samesite: "Strict", path: "/api" });
    const state = result.start.headers.getSetCookie().map(parseSetCookie).find((c) => c.name.endsWith("state"));
    expect(state?.attributes).toMatchObject({ httponly: true, samesite: "Lax", path: "/api" });
  });

  it("staging/production cookies are Secure and __Secure- prefixed", async () => {
    const origin = "https://lightagent-control-staging.eddelaroca.workers.dev";
    const secureEnv = testEnv({ PUBLIC_ORIGIN: origin, PASSKEY_RP_ID: "lightagent-control-staging.eddelaroca.workers.dev", TRUSTED_ORIGINS: origin, ENVIRONMENT: "development" });
    const response = await call("/api/auth/sign-in/social", {
      method: "POST",
      headers: { origin: BASE, "content-type": "application/json" },
      body: JSON.stringify({ provider: "google", turnstileToken: "t" }),
    }, { env: secureEnv });
    // Foreign origin for this config: rejected before anything is set.
    expect(response.status).toBe(403);
    const ok = await (async () => {
      const r = new Request(`${origin}/api/auth/sign-in/social`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ provider: "google", turnstileToken: "t" }) });
      const { createWorker } = await import("../../src/worker/index");
      const { createExecutionContext, waitOnExecutionContext } = await import("cloudflare:test");
      const ctx = createExecutionContext();
      const res = await createWorker({ cspMode: "production" }).fetch(r, secureEnv, ctx);
      await waitOnExecutionContext(ctx);
      return res;
    })();
    const cookies = ok.headers.getSetCookie().map(parseSetCookie);
    expect(cookies.length).toBeGreaterThan(0);
    for (const cookie of cookies) {
      expect(cookie.name.startsWith("__Secure-lightagent.")).toBe(true);
      expect(cookie.attributes["secure"]).toBe(true);
      expect(cookie.attributes["samesite"]).not.toBe("None");
    }
  });

  it("sign-in issues a fresh session; a pre-set session id is never adopted (fixation)", async () => {
    const jar = new CookieJar();
    const planted = `${randomId("planted")}.${randomId("sig")}`;
    jar.set(SESSION_COOKIE, planted);
    await signIn(providers, identity("google"), jar);
    const issued = jar.get(SESSION_COOKIE);
    expect(issued).toBeDefined();
    expect(issued).not.toBe(planted);
    expect((await me(jar)).status).toBe(200);
    const planter = new CookieJar();
    planter.set(SESSION_COOKIE, planted);
    expect((await me(planter)).status).toBe(401);
  });

  it("lists own sessions without tokens and marks the current one", async () => {
    const who = identity("google");
    const a = new CookieJar();
    const b = new CookieJar();
    await signIn(providers, who, a);
    await signIn(providers, who, b);
    const response = await get("/api/security/sessions", a);
    const text = await response.text();
    const sessions = (JSON.parse(text) as { data: Array<{ id: string; current: boolean }> }).data;
    expect(sessions).toHaveLength(2);
    expect(sessions.filter((s) => s.current)).toHaveLength(1);
    const tokenA = a.get(SESSION_COOKIE)?.split(".")[0] ?? "x";
    expect(text).not.toContain(tokenA);
    expect(text).not.toMatch(/token/i);
  });

  it("revoking one session ends only that session", async () => {
    const who = identity("google");
    const keep = new CookieJar();
    const revoke = new CookieJar();
    await signIn(providers, who, keep);
    await signIn(providers, who, revoke);
    const sessions = ((await (await get("/api/security/sessions", keep)).json()) as { data: Array<{ id: string; current: boolean }> }).data;
    const other = sessions.find((s) => !s.current);
    const response = await send("DELETE", `/api/security/sessions/${other?.id}`, keep);
    expect(response.status).toBe(200);
    expect((await me(revoke)).status).toBe(401);
    expect((await me(keep)).status).toBe(200);
  });

  it("sign out everywhere revokes every session, including the current one", async () => {
    const who = identity("github");
    const one = new CookieJar();
    const two = new CookieJar();
    await signIn(providers, who, one);
    await signIn(providers, who, two);
    expect((await send("POST", "/api/security/sessions/revoke-all", one)).status).toBe(200);
    expect((await me(one)).status).toBe(401);
    expect((await me(two)).status).toBe(401);
  });

  it("logout ends the session and clears the cookie", async () => {
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar);
    const response = await send("POST", "/api/auth/sign-out", jar);
    expect(response.status).toBe(200);
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
    expect((await me(jar)).status).toBe(401);
  });

  it("logout from a foreign origin is rejected (CSRF)", async () => {
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar);
    const response = await call("/api/auth/sign-out", { method: "POST", headers: { origin: "https://evil.example", cookie: jar.header(), "content-type": "application/json" }, body: "{}" });
    expect(response.status).toBe(403);
    expect((await me(jar)).status).toBe(200);
  });
});

describe("tenant isolation for sessions", () => {
  it("a user cannot see or revoke another user's session", async () => {
    const alice = new CookieJar();
    const bob = new CookieJar();
    await signIn(providers, identity("google"), alice);
    await signIn(providers, identity("google"), bob);
    const bobSession = ((await (await get("/api/security/sessions", bob)).json()) as { data: Array<{ id: string }> }).data[0]?.id;
    const aliceList = await (await get("/api/security/sessions", alice)).text();
    expect(aliceList).not.toContain(bobSession);
    const attempt = await send("DELETE", `/api/security/sessions/${bobSession}`, alice);
    const unknown = await send("DELETE", `/api/security/sessions/${randomId("sess")}`, alice);
    expect(attempt.status).toBe(404);
    expect(unknown.status).toBe(404);
    expect((await me(bob)).status).toBe(200);
  });
});

describe("Better Auth surface", () => {
  it.each([
    ["GET", "/api/auth/get-session"],
    ["GET", "/api/auth/list-sessions"],
    ["POST", "/api/auth/revoke-session"],
    ["POST", "/api/auth/sign-up/email"],
    ["POST", "/api/auth/sign-in/email"],
    ["POST", "/api/auth/forget-password"],
    ["POST", "/api/auth/delete-user"],
    ["POST", "/api/auth/link-social"],
    ["GET", "/api/auth/passkey/list-user-passkeys"],
    ["POST", "/api/auth/passkey/delete-passkey"],
    ["GET", "/api/auth/ok"],
    ["GET", "/api/auth/callback/evil"],
  ])("%s %s is not exposed", async (method, path) => {
    const response = await call(path, { method, headers: { origin: BASE, "content-type": "application/json" }, ...(method === "POST" ? { body: "{}" } : {}) });
    expect(response.status).toBe(404);
  });

  it("auth is unavailable (fail closed) without an approved origin or secret", async () => {
    for (const overrides of [{ PUBLIC_ORIGIN: "", PASSKEY_RP_ID: "" }, { BETTER_AUTH_SECRET: "" }, { BETTER_AUTH_SECRET: "short" }] as Partial<Env>[]) {
      const response = await call("/api/me", undefined, { env: testEnv(overrides) });
      expect(response.status).toBe(503);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe("AUTH_UNAVAILABLE");
    }
  });

  it("/api/config exposes only public sign-in options", async () => {
    const response = await call("/api/config");
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({ ok: true, data: { signInAvailable: true, providers: ["google", "github"], passkeys: true, turnstileSiteKey: "1x00000000000000000000AA" } });
    expect(text).not.toMatch(/secret|test-google-client/i);
  });
});

describe("no credentials in logs or responses", () => {
  it("OAuth codes, tokens, session cookies, and client secrets never appear in logs", async () => {
    const jar = new CookieJar();
    const result = await signIn(providers, identity("google"), jar);
    await me(jar);
    await send("POST", "/api/auth/sign-out", jar);
    const code = [...providers.codes.keys()].at(-1) ?? "none";
    const sessionToken = result.callback.headers.getSetCookie().map(parseSetCookie).find((c) => c.name === SESSION_COOKIE)?.value.split(".")[0] ?? "none";
    const all = logLines.join("\n");
    expect(logLines.length).toBeGreaterThan(0);
    for (const secret of [code, sessionToken, ...providers.issuedTokens, "test-google-client-secret", "test-only-better-auth-secret", "XXXX.DUMMY.TOKEN.XXXX"]) {
      expect(all).not.toContain(secret);
    }
  });

  it.each(["google", "github"] as const)("%s provider tokens are not stored at all", async (provider) => {
    const who = identity(provider);
    await signIn(providers, who, new CookieJar());
    await signIn(providers, who, new CookieJar()); // the update path too
    const row = await env.DB.prepare(`SELECT "accessToken", "refreshToken", "idToken", password FROM account WHERE "accountId" = ?1`).bind(who.sub).first();
    expect(row).toEqual({ accessToken: null, refreshToken: null, idToken: null, password: null });
  });

  it("sessions never store a client IP", async () => {
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar);
    const rows = await env.DB.prepare(`SELECT "ipAddress" FROM session`).all<{ ipAddress: string | null }>();
    for (const row of rows.results) expect(row.ipAddress === null || row.ipAddress === "").toBe(true);
  });
});
