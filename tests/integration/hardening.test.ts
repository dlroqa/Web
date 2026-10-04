/**
 * Phase 4.5 hardening: stable denial errors on every sign-in path, sign-out
 * everywhere clears this browser, passkey audit identity, Better Auth
 * diagnostics through the redacting logger, and no session token in any
 * log line, audit row, or response.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mapUpstreamError } from "../../src/worker/auth/gateway";
import { UserRepository } from "../../src/worker/db/users";
import { FakeProviders, get, identity, send, signIn, type Identity } from "../helpers/auth";
import { CookieJar, parseSetCookie } from "../helpers/cookies";
import { SoftAuthenticator } from "../helpers/webauthn";
import { BASE, call } from "../helpers/worker";

const SESSION_COOKIE = "lightagent.session_token";
let providers: FakeProviders;
let logLines: string[];

beforeEach(() => {
  logLines = [];
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void logLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ")));
  }
  providers = new FakeProviders().install();
});

afterEach(() => {
  providers.restore();
  vi.restoreAllMocks();
});

async function profileId(who: Identity): Promise<string> {
  const row = await env.DB.prepare(`SELECT p.id FROM user_profiles p JOIN "user" u ON u.id = p.auth_user_id WHERE u.email = ?1`).bind(who.email).first<{ id: string }>();
  if (!row) throw new Error("no profile");
  return row.id;
}

async function body(response: Response): Promise<{ ok: boolean; data?: unknown; error?: { code: string; message: string } }> {
  return (await response.json()) as { ok: boolean; data?: unknown; error?: { code: string; message: string } };
}

/** Sign in with Google, enroll a passkey, and return everything needed to try passkey sign-in later. */
async function userWithPasskey(): Promise<{ who: Identity; jar: CookieJar; authenticator: SoftAuthenticator; profile: string }> {
  const who = identity("google");
  const jar = new CookieJar();
  await signIn(providers, who, jar);
  const authenticator = new SoftAuthenticator("localhost", BASE);
  const optionsResponse = await call("/api/auth/passkey/generate-register-options?name=Laptop", { headers: { cookie: jar.header() } });
  jar.store(optionsResponse);
  const credential = await authenticator.register((await optionsResponse.json()) as { challenge: string });
  const enrolled = await send("POST", "/api/auth/passkey/verify-registration", jar, { response: credential, name: "Laptop" });
  expect(enrolled.status).toBe(200);
  return { who, jar, authenticator, profile: await profileId(who) };
}

async function passkeyLogin(authenticator: SoftAuthenticator): Promise<{ jar: CookieJar; response: Response }> {
  const jar = new CookieJar();
  const optionsResponse = await call("/api/auth/passkey/generate-authenticate-options", { headers: { cookie: jar.header() } });
  jar.store(optionsResponse);
  const assertion = await authenticator.authenticate((await optionsResponse.json()) as { challenge: string });
  const response = await send("POST", "/api/auth/passkey/verify-authentication", jar, { response: assertion });
  return { jar, response };
}

describe("account-policy denials have one stable error on every sign-in path", () => {
  it.each(["suspended", "disabled"] as const)("%s account: passkey sign-in → 403 ACCOUNT_DISABLED, no session", async (status) => {
    const { authenticator, profile } = await userWithPasskey();
    await new UserRepository(env.DB).transition(profile, status);
    const { jar, response } = await passkeyLogin(authenticator);
    expect(response.status).toBe(403);
    const payload = await body(response);
    expect(payload.error?.code).toBe("ACCOUNT_DISABLED");
    expect(payload.error?.message).toBe("This account is not active.");
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
    // An expected denial is not logged as a fault.
    expect(logLines.some((l) => l.includes('"auth.upstream_error"'))).toBe(false);
  });

  it.each(["suspended", "disabled"] as const)("%s account: OAuth sign-in → /login?error=account_disabled, no session", async (status) => {
    const who = identity("github");
    await signIn(providers, who, new CookieJar());
    await new UserRepository(env.DB).transition(await profileId(who), status);
    const retry = new CookieJar();
    const result = await signIn(providers, who, retry);
    expect(result.location).toBe(`${BASE}/login?error=account_disabled`);
    expect(retry.get(SESSION_COOKIE)).toBeUndefined();
  });

  it("an unexpected failure while creating the session is still INTERNAL_ERROR, with no internal text", async () => {
    const { authenticator } = await userWithPasskey();
    // A real fault inside Better Auth: the session insert itself fails.
    await env.DB.exec(`CREATE TRIGGER test_fail_session BEFORE INSERT ON session BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END;`);
    try {
      const { jar, response } = await passkeyLogin(authenticator);
      expect(response.status).toBe(500);
      const text = await response.text();
      expect(JSON.parse(text).error.code).toBe("INTERNAL_ERROR");
      expect(text).not.toMatch(/simulated|UNABLE_TO_CREATE_SESSION|Better Auth|SQLITE/i);
      expect(jar.get(SESSION_COOKIE)).toBeUndefined();

      const who = identity("google");
      const result = await signIn(providers, who, new CookieJar());
      expect(result.location).toMatch(/\/login\?error=/);
      expect(result.location).not.toContain("account_disabled");
    } finally {
      await env.DB.exec(`DROP TRIGGER test_fail_session;`);
    }
  });

  it("mapUpstreamError: a recorded denial wins; the same Better Auth code without one is INTERNAL_ERROR", () => {
    expect(mapUpstreamError({ status: 500, code: "UNABLE_TO_CREATE_SESSION", denial: "ACCOUNT_DISABLED" })).toBe("ACCOUNT_DISABLED");
    expect(mapUpstreamError({ status: 500, code: "UNABLE_TO_CREATE_SESSION", denial: null })).toBe("INTERNAL_ERROR");
    expect(mapUpstreamError({ status: 401, code: undefined, denial: null })).toBe("AUTH_REQUIRED");
    expect(mapUpstreamError({ status: 403, code: "SESSION_NOT_FRESH", denial: null })).toBe("REAUTH_REQUIRED");
    expect(mapUpstreamError({ status: 403, code: "OTHER", denial: null })).toBe("FORBIDDEN");
    expect(mapUpstreamError({ status: 429, code: undefined, denial: null })).toBe("RATE_LIMITED");
    expect(mapUpstreamError({ status: 400, code: "X", denial: null })).toBe("INVALID_REQUEST");
    // Better Auth reported an internal error: never blamed on the client.
    expect(mapUpstreamError({ status: 400, code: "AUTHENTICATION_FAILED", denial: null, fault: true })).toBe("INTERNAL_ERROR");
    expect(mapUpstreamError({ status: 500, code: "UNABLE_TO_CREATE_SESSION", denial: "ACCOUNT_DISABLED", fault: true })).toBe("ACCOUNT_DISABLED");
  });
});

describe("sign out everywhere", () => {
  it("expires this browser's session cookie exactly as sign-out does, and leaves zero sessions", async () => {
    const who = identity("google");
    const one = new CookieJar();
    const two = new CookieJar();
    await signIn(providers, who, one);
    await signIn(providers, who, two);
    const staleCookie = one.header();

    const response = await send("POST", "/api/security/sessions/revoke-all", one);
    expect(response.status).toBe(200);
    const cleared = response.headers.getSetCookie().map(parseSetCookie);
    const session = cleared.find((c) => c.name === SESSION_COOKIE);
    expect(session?.value).toBe("");
    expect(session?.attributes["max-age"]).toBe("0");
    expect(session?.attributes["path"]).toBe("/api");
    expect(session?.attributes["httponly"]).toBe(true);
    expect(session?.attributes["samesite"]).toBe("Strict");
    expect(one.get(SESSION_COOKIE)).toBeUndefined();

    // Same cookie names and attributes as Better Auth's own sign-out.
    const reference = new CookieJar();
    await signIn(providers, identity("google"), reference);
    const signOut = (await send("POST", "/api/auth/sign-out", reference)).headers.getSetCookie().map(parseSetCookie);
    const shape = (cookies: ReturnType<typeof parseSetCookie>[]) => cookies.map((c) => ({ name: c.name, attributes: c.attributes })).sort((a, b) => a.name.localeCompare(b.name));
    expect(shape(cleared)).toEqual(shape(signOut));

    const authUser = await env.DB.prepare(`SELECT id FROM "user" WHERE email = ?1`).bind(who.email).first<{ id: string }>();
    const remaining = await env.DB.prepare(`SELECT COUNT(*) AS n FROM session WHERE "userId" = ?1`).bind(authUser?.id).first<{ n: number }>();
    expect(remaining?.n).toBe(0);

    // The browser is signed out, and a stale copy of the cookie revives nothing.
    expect((await body(await get("/api/session", one))).data).toEqual({ signedIn: false });
    expect((await get("/api/me", one)).status).toBe(401);
    const stale = await call("/api/me", { headers: { cookie: staleCookie } });
    expect(stale.status).toBe(401);
    expect((await call("/api/session", { headers: { cookie: staleCookie } }).then(body)).data).toEqual({ signedIn: false });
    expect((await get("/api/me", two)).status).toBe(401);
  });

  it("repeating it is safe: AUTH_REQUIRED, and no one else's sessions are touched", async () => {
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar);
    const stale = new CookieJar();
    stale.set(SESSION_COOKIE, jar.get(SESSION_COOKIE) ?? "");
    const bystander = new CookieJar();
    await signIn(providers, identity("github"), bystander);

    expect((await send("POST", "/api/security/sessions/revoke-all", jar)).status).toBe(200);
    const again = await send("POST", "/api/security/sessions/revoke-all", stale);
    expect(again.status).toBe(401);
    expect((await body(again)).error?.code).toBe("AUTH_REQUIRED");
    expect((await send("POST", "/api/security/sessions/revoke-all", jar)).status).toBe(401);
    expect((await get("/api/me", bystander)).status).toBe(200);
  });

  it("revoking this browser's own session from the list also clears its cookie", async () => {
    const jar = new CookieJar();
    await signIn(providers, identity("google"), jar);
    const list = (await body(await get("/api/security/sessions", jar))).data as Array<{ id: string; current: boolean }>;
    const current = list.find((s) => s.current);
    const response = await send("DELETE", `/api/security/sessions/${current?.id}`, jar);
    expect(response.status).toBe(200);
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
    expect((await body(await get("/api/session", jar))).data).toEqual({ signedIn: false });
  });
});

describe("audit identifies passkeys and sessions without credential material", () => {
  it("add, rename, and remove record the passkey id, label, and a credential fingerprint", async () => {
    const { jar, profile } = await userWithPasskey();
    const list = (await body(await get("/api/security/passkeys", jar))).data as Array<{ id: string }>;
    const passkeyId = list[0]?.id ?? "";
    expect((await send("PATCH", `/api/security/passkeys/${passkeyId}`, jar, { name: "Work laptop" })).status).toBe(200);
    expect((await send("DELETE", `/api/security/passkeys/${passkeyId}`, jar)).status).toBe(200);

    const { results } = await env.DB.prepare(
      `SELECT action, target_type, target_id, details_json FROM audit_events WHERE actor_id = ?1 AND action LIKE 'auth.passkey.%' ORDER BY timestamp, rowid`,
    )
      .bind(profile)
      .all<{ action: string; target_type: string; target_id: string; details_json: string }>();
    expect(results.map((r) => r.action)).toEqual(["auth.passkey.add", "auth.passkey.rename", "auth.passkey.remove"]);
    const details = results.map((r) => JSON.parse(r.details_json) as { name: string; fingerprint: string });
    for (const row of results) expect({ type: row.target_type, id: row.target_id }).toEqual({ type: "passkey", id: passkeyId });
    expect(details.map((d) => d.name)).toEqual(["Laptop", "Work laptop", "Work laptop"]);
    expect(new Set(details.map((d) => d.fingerprint)).size).toBe(1);
    expect(details[0]?.fingerprint).toMatch(/^sha256:[0-9a-f]{16}$/);

    // Neither the credential id nor anything key-like is stored.
    const all = JSON.stringify(results);
    expect(all).not.toMatch(/credentialID|publicKey|counter|attestation|signature|clientData/i);
  });

  it("a session revocation records which session (its id, never its token)", async () => {
    const who = identity("google");
    const keep = new CookieJar();
    const other = new CookieJar();
    await signIn(providers, who, keep);
    await signIn(providers, who, other);
    const list = (await body(await get("/api/security/sessions", keep))).data as Array<{ id: string; current: boolean }>;
    const target = list.find((s) => !s.current);
    await send("DELETE", `/api/security/sessions/${target?.id}`, keep);
    const row = await env.DB.prepare(`SELECT target_type, target_id FROM audit_events WHERE action = 'auth.session.revoke' AND target_id = ?1`)
      .bind(target?.id)
      .first<{ target_type: string; target_id: string }>();
    expect(row).toEqual({ target_type: "session", target_id: target?.id });
  });
});

describe("Better Auth diagnostics and session tokens", () => {
  it("Better Auth's messages go through the redacting logger, never raw to the console", async () => {
    const google = identity("google");
    await signIn(providers, google, new CookieJar());
    // Same verified email from a second provider: Better Auth logs account_not_linked.
    const attempt = await signIn(providers, identity("github", { email: google.email }), new CookieJar());
    expect(attempt.location).toBe(`${BASE}/login?error=account_not_linked`);
    // A forged state: Better Auth logs a state failure.
    await call(`/api/auth/callback/google?code=abc&state=${"s".repeat(40)}`);

    expect(logLines.some((l) => l.includes("[Better Auth]"))).toBe(false);
    for (const line of logLines) expect(() => JSON.parse(line)).not.toThrow();
    expect(logLines.some((l) => l.includes('"better_auth.'))).toBe(true);
    expect(logLines.join("\n")).not.toContain("s".repeat(40));
  });

  it("no session token appears in any log line, audit row, or response body", async () => {
    const who = identity("google");
    const jar = new CookieJar();
    const result = await signIn(providers, who, jar);
    const token = jar.get(SESSION_COOKIE)?.split(".")[0] ?? "missing";
    expect(token.length).toBeGreaterThanOrEqual(32);

    const responses = [await result.callback.text()];
    for (const path of ["/api/session", "/api/me", "/api/security/sessions", "/api/security/methods", "/api/security/passkeys", "/api/security/activity"]) {
      responses.push(await (await get(path, jar)).text());
    }
    const second = new CookieJar();
    await signIn(providers, who, second);
    const list = (await body(await get("/api/security/sessions", jar))).data as Array<{ id: string; current: boolean }>;
    responses.push(await (await send("DELETE", `/api/security/sessions/${list.find((s) => !s.current)?.id}`, jar)).text());
    responses.push(await (await send("POST", "/api/security/sessions/revoke-all", jar)).text());

    const { results } = await env.DB.prepare(`SELECT * FROM audit_events`).all();
    for (const haystack of [...responses, ...logLines, JSON.stringify(results)]) {
      expect(haystack).not.toContain(token);
    }
  });
});
