/**
 * The 24-hour absolute session lifetime, with controlled time (only Date is
 * faked, so I/O and promises run normally): a session expires 24 h after
 * sign-in whatever it is used for, and the 10-minute recent-authentication
 * rule is unchanged.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildAuthOptions, SESSION_EXPIRES_IN_SECONDS, SESSION_FRESH_AGE_SECONDS } from "../../src/worker/auth/options";
import { UserRepository } from "../../src/worker/db/users";
import { FakeProviders, get, identity, send, signIn, type Identity } from "../helpers/auth";
import { CookieJar, parseSetCookie } from "../helpers/cookies";
import { call } from "../helpers/worker";

const SESSION_COOKIE = "lightagent.session_token";
const HOUR = 3_600_000;
const T0 = new Date("2026-10-05T08:00:00.000Z").getTime();
let providers: FakeProviders;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  for (const level of ["log", "info", "warn", "error"] as const) vi.spyOn(console, level).mockImplementation(() => undefined);
  providers = new FakeProviders().install();
});

afterEach(() => {
  providers.restore();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function sessionRow(jar: CookieJar): Promise<{ expiresAt: string; updatedAt: string; createdAt: string } | null> {
  const token = jar.get(SESSION_COOKIE)?.split(".")[0] ?? "";
  return env.DB.prepare(`SELECT "expiresAt", "updatedAt", "createdAt" FROM session WHERE token = ?1`).bind(token).first();
}

async function signedIn(): Promise<{ who: Identity; jar: CookieJar; cookieMaxAge: string | true | undefined }> {
  const who = identity("google");
  const jar = new CookieJar();
  const { callback } = await signIn(providers, who, jar);
  const cookie = callback.headers.getSetCookie().map(parseSetCookie).find((c) => c.name === SESSION_COOKIE);
  return { who, jar, cookieMaxAge: cookie?.attributes["max-age"] };
}

const at = (ms: number) => vi.setSystemTime(T0 + ms);

describe("24-hour absolute session lifetime", () => {
  it("a new session expires 24 hours after sign-in, and so does its cookie", async () => {
    expect(SESSION_EXPIRES_IN_SECONDS).toBe(86_400);
    const { jar, cookieMaxAge } = await signedIn();
    const row = await sessionRow(jar);
    expect(new Date(row?.expiresAt ?? 0).getTime() - new Date(row?.createdAt ?? 0).getTime()).toBe(24 * HOUR);
    expect(new Date(row?.createdAt ?? 0).getTime()).toBe(T0);
    expect(cookieMaxAge).toBe("86400");
  });

  it("is configured as a fixed lifetime with Better Auth's own options (no sliding refresh)", () => {
    const options = buildAuthOptions({ database: env.DB, publicOrigin: "https://example.test", passkeyRpId: "example.test", trustedOrigins: [], secret: "x".repeat(32) });
    expect(options.session).toMatchObject({ expiresIn: 86_400, disableSessionRefresh: true, freshAge: 600 });
    expect(options.session).not.toHaveProperty("updateAge");
  });

  it("use never extends the expiry", async () => {
    const { jar } = await signedIn();
    const issued = await sessionRow(jar);
    for (const hours of [1, 6, 12, 23, 23.9]) {
      at(hours * HOUR);
      expect((await get("/api/me", jar)).status).toBe(200);
      expect((await get("/api/security/sessions", jar)).status).toBe(200);
    }
    expect(await sessionRow(jar)).toEqual(issued);
  });

  it("an expired session is rejected: /api/session reports signed out, /api/me is 401", async () => {
    const { jar } = await signedIn();
    at(24 * HOUR - 1000);
    expect((await get("/api/me", jar)).status).toBe(200);
    at(24 * HOUR + 1000);
    const me = await get("/api/me", jar);
    expect(me.status).toBe(401);
    expect(((await me.json()) as { error: { code: string } }).error.code).toBe("AUTH_REQUIRED");
    expect(((await (await get("/api/session", jar)).json()) as { data: unknown }).data).toEqual({ signedIn: false });
    // Signing in again starts a new 24-hour session.
    const again = new CookieJar();
    await signIn(providers, identity("google"), again);
    expect((await get("/api/me", again)).status).toBe(200);
  });

  it("recent authentication is still 10 minutes, independent of the lifetime", async () => {
    expect(SESSION_FRESH_AGE_SECONDS).toBe(600);
    const { jar } = await signedIn();
    at(9 * 60_000);
    expect((await call("/api/auth/passkey/generate-register-options", { headers: { cookie: jar.header() } })).status).toBe(200);
    at(11 * 60_000);
    const stale = await call("/api/auth/passkey/generate-register-options", { headers: { cookie: jar.header() } });
    expect(stale.status).toBe(403);
    expect(((await stale.json()) as { error: { code: string } }).error.code).toBe("REAUTH_REQUIRED");
  });

  it("sign-out and revocation still end a session immediately, long before it expires", async () => {
    const { jar } = await signedIn();
    at(HOUR);
    await send("POST", "/api/auth/sign-out", jar);
    expect((await get("/api/me", jar)).status).toBe(401);

    const { jar: other } = await signedIn();
    at(2 * HOUR);
    expect((await send("POST", "/api/security/sessions/revoke-all", other)).status).toBe(200);
    expect((await get("/api/me", other)).status).toBe(401);
  });

  it("suspension overrides a session that has not expired", async () => {
    const { who, jar } = await signedIn();
    at(HOUR);
    const profile = await env.DB.prepare(`SELECT p.id FROM user_profiles p JOIN "user" u ON u.id = p.auth_user_id WHERE u.email = ?1`).bind(who.email).first<{ id: string }>();
    await new UserRepository(env.DB).transition(profile?.id ?? "", "suspended");
    expect((await get("/api/me", jar)).status).toBe(403);
  });
});
