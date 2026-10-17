import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserRepository } from "../../src/worker/db/users";
import { randomId } from "../../src/worker/utils/random";
import { FakeProviders, get, identity, passkeyOptions, send, signIn } from "../helpers/auth";
import { CookieJar } from "../helpers/cookies";
import { SoftAuthenticator } from "../helpers/webauthn";
import { BASE, call } from "../helpers/worker";

const SESSION_COOKIE = "lightagent.session_token";
let providers: FakeProviders;
let logLines: string[];

beforeEach(() => {
  logLines = [];
  for (const level of ["log", "info", "warn", "error"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void logLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ")));
  }
  providers = new FakeProviders().install();
});

afterEach(() => {
  providers.restore();
  vi.restoreAllMocks();
});

const authenticatorFor = () => new SoftAuthenticator("localhost", BASE);

async function signedIn(): Promise<{ jar: CookieJar; email: string }> {
  const who = identity("google");
  const jar = new CookieJar();
  await signIn(providers, who, jar);
  return { jar, email: who.email };
}

async function registerOptions(jar: CookieJar, query = ""): Promise<Response> {
  const response = await call(`/api/auth/passkey/generate-register-options${query}`, { headers: { cookie: jar.header() } });
  jar.store(response);
  return response;
}

/** Enroll a passkey for the jar's user through the real endpoints. */
async function enroll(jar: CookieJar, authenticator: SoftAuthenticator, name = "Test key"): Promise<Response> {
  const options = (await (await registerOptions(jar, `?name=${encodeURIComponent(name)}`)).json()) as { challenge: string };
  const credential = await authenticator.register(options);
  return send("POST", "/api/auth/passkey/verify-registration", jar, { response: credential, name });
}

/** Sign in with a passkey in a fresh browser. */
async function passkeyLogin(authenticator: SoftAuthenticator): Promise<{ jar: CookieJar; response: Response }> {
  const jar = new CookieJar();
  const optionsResponse = await passkeyOptions(jar);
  const options = (await optionsResponse.json()) as { challenge: string };
  const assertion = await authenticator.authenticate(options);
  const response = await send("POST", "/api/auth/passkey/verify-authentication", jar, { response: assertion });
  return { jar, response };
}

async function ageSession(jar: CookieJar, minutes: number): Promise<void> {
  const token = jar.get(SESSION_COOKIE)?.split(".")[0];
  const past = new Date(Date.now() - minutes * 60_000).toISOString();
  await env.DB.prepare(`UPDATE session SET "createdAt" = ?1 WHERE token = ?2`).bind(past, token).run();
}

async function passkeys(jar: CookieJar) {
  const response = await get("/api/security/passkeys", jar);
  const text = await response.text();
  return { status: response.status, text, list: (JSON.parse(text) as { data: Array<{ id: string; name: string | null }> }).data };
}

describe("passkey enrollment", () => {
  it("requires an authenticated session", async () => {
    const anonymous = new CookieJar();
    expect((await registerOptions(anonymous)).status).toBe(401);
    const verify = await send("POST", "/api/auth/passkey/verify-registration", anonymous, { response: { id: "x" } });
    expect(verify.status).toBe(401);
  });

  it("enrolls through Better Auth's WebAuthn verification and lists without credential material", async () => {
    const { jar } = await signedIn();
    const authenticator = authenticatorFor();
    const response = await enroll(jar, authenticator, "MacBook Touch ID");
    expect(response.status).toBe(200);
    const { list, text } = await passkeys(jar);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ name: "MacBook Touch ID", deviceType: "device-bound" });
    expect(text).not.toMatch(/publicKey|credentialID|counter|aaguid/i);
  });

  it("requires recent authentication (fresh session)", async () => {
    const { jar } = await signedIn();
    await ageSession(jar, 30);
    const response = await registerOptions(jar);
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe("REAUTH_REQUIRED");
  });

  it("rejects passkey-first or anonymous registration parameters", async () => {
    const { jar } = await signedIn();
    expect((await registerOptions(jar, "?context=signup")).status).toBe(400);
    const options = (await (await registerOptions(jar)).json()) as { challenge: string };
    const credential = await authenticatorFor().register(options);
    const response = await send("POST", "/api/auth/passkey/verify-registration", jar, { response: credential, createSession: true });
    expect(response.status).toBe(400);
  });

  it("rejects a registration for another origin, a wrong ceremony type, or a forged challenge", async () => {
    const { jar } = await signedIn();
    for (const forge of [{ origin: "https://evil.example" }, { type: "webauthn.get" }]) {
      const options = (await (await registerOptions(jar)).json()) as { challenge: string };
      const credential = await authenticatorFor().register(options, forge);
      expect((await send("POST", "/api/auth/passkey/verify-registration", jar, { response: credential })).status).toBeGreaterThanOrEqual(400);
    }
    await registerOptions(jar);
    const credential = await authenticatorFor().register({ challenge: "Zm9yZ2VkLWNoYWxsZW5nZQ" });
    expect((await send("POST", "/api/auth/passkey/verify-registration", jar, { response: credential })).status).toBeGreaterThanOrEqual(400);
    expect((await passkeys(jar)).list).toHaveLength(0);
  });
});

describe("passkey sign-in", () => {
  it("signs the same user in with a new session, without returning the session to JavaScript", async () => {
    const { jar } = await signedIn();
    const authenticator = authenticatorFor();
    await enroll(jar, authenticator);
    const meBefore = (await (await get("/api/me", jar)).json()) as { data: { id: string } };

    const login = await passkeyLogin(authenticator);
    expect(login.response.status).toBe(200);
    const body = await login.response.text();
    expect(JSON.parse(body)).toEqual({ ok: true, data: { signedIn: true } });
    expect(body).not.toMatch(/token/i);
    expect(login.jar.get(SESSION_COOKIE)).toBeDefined();
    const meAfter = (await (await get("/api/me", login.jar)).json()) as { data: { id: string } };
    expect(meAfter.data.id).toBe(meBefore.data.id);
  });

  it("a captured assertion cannot be replayed", async () => {
    const { jar } = await signedIn();
    const authenticator = authenticatorFor();
    await enroll(jar, authenticator);
    const browser = new CookieJar();
    const optionsResponse = await passkeyOptions(browser);
    const assertion = await authenticator.authenticate((await optionsResponse.json()) as { challenge: string });
    expect((await send("POST", "/api/auth/passkey/verify-authentication", browser, { response: assertion })).status).toBe(200);
    const replayJar = new CookieJar();
    for (const name of browser.names()) if (name !== SESSION_COOKIE) replayJar.set(name, browser.get(name) ?? "");
    const replay = await send("POST", "/api/auth/passkey/verify-authentication", replayJar, { response: assertion });
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replayJar.get(SESSION_COOKIE)).toBeUndefined();
  });

  it.each([
    ["empty object", {}],
    ["garbage response", { response: { id: "x", rawId: "x", type: "public-key", response: { clientDataJSON: "!!", authenticatorData: "", signature: "" } } }],
    ["unknown credential", { response: { id: "AAAA", rawId: "AAAA", type: "public-key", response: { clientDataJSON: "e30", authenticatorData: "AAAA", signature: "AAAA" } } }],
    ["extra fields", { response: {}, userId: "usr_someone" }],
  ])("a malformed assertion (%s) fails safely without a session", async (_label, body) => {
    const jar = new CookieJar();
    await passkeyOptions(jar);
    const response = await send("POST", "/api/auth/passkey/verify-authentication", jar, body);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
  });

  it("does not create an account for an unknown passkey", async () => {
    const before = await env.DB.prepare(`SELECT COUNT(*) AS n FROM "user"`).first<{ n: number }>();
    const stranger = authenticatorFor();
    await stranger.register({ challenge: "c3RyYW5nZXI" });
    const { response } = await passkeyLogin(stranger);
    expect(response.status).toBeGreaterThanOrEqual(400);
    const after = await env.DB.prepare(`SELECT COUNT(*) AS n FROM "user"`).first<{ n: number }>();
    expect(after?.n).toBe(before?.n);
  });

  it("a suspended user's passkey does not sign them in", async () => {
    const { jar, email } = await signedIn();
    const authenticator = authenticatorFor();
    await enroll(jar, authenticator);
    const profile = await env.DB.prepare(`SELECT p.id FROM user_profiles p JOIN "user" u ON u.id = p.auth_user_id WHERE u.email = ?1`).bind(email).first<{ id: string }>();
    await new UserRepository(env.DB).transition(profile?.id ?? "", "suspended");
    const { jar: loginJar, response } = await passkeyLogin(authenticator);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(loginJar.get(SESSION_COOKIE)).toBeUndefined();
  });
});

describe("passkey management", () => {
  it("rename and remove act only on the caller's own passkeys", async () => {
    const alice = await signedIn();
    const bob = await signedIn();
    await enroll(bob.jar, authenticatorFor(), "Bob's key");
    const bobKey = (await passkeys(bob.jar)).list[0]?.id ?? "";

    expect((await passkeys(alice.jar)).text).not.toContain(bobKey);
    const rename = await send("PATCH", `/api/security/passkeys/${bobKey}`, alice.jar, { name: "pwned" });
    const remove = await send("DELETE", `/api/security/passkeys/${bobKey}`, alice.jar);
    const unknown = await send("DELETE", `/api/security/passkeys/${randomId("pk")}`, alice.jar);
    expect([rename.status, remove.status, unknown.status]).toEqual([404, 404, 404]);
    expect((await passkeys(bob.jar)).list).toEqual([expect.objectContaining({ id: bobKey, name: "Bob's key" })]);
  });

  it("the owner can rename and, with a fresh session, remove", async () => {
    const { jar } = await signedIn();
    await enroll(jar, authenticatorFor());
    const id = (await passkeys(jar)).list[0]?.id ?? "";
    expect((await send("PATCH", `/api/security/passkeys/${id}`, jar, { name: "YubiKey 5" })).status).toBe(200);
    expect((await passkeys(jar)).list[0]?.name).toBe("YubiKey 5");
    expect((await send("PATCH", `/api/security/passkeys/${id}`, jar, { name: "x".repeat(81) })).status).toBe(400);

    await ageSession(jar, 30);
    const stale = await send("DELETE", `/api/security/passkeys/${id}`, jar);
    expect(stale.status).toBe(403);
    expect(((await stale.json()) as { error: { code: string } }).error.code).toBe("REAUTH_REQUIRED");

    const fresh = new CookieJar();
    const who = await env.DB.prepare(`SELECT u.email FROM "user" u JOIN passkey p ON p."userId" = u.id WHERE p.id = ?1`).bind(id).first<{ email: string }>();
    const sub = await env.DB.prepare(`SELECT "accountId" FROM account a JOIN "user" u ON u.id = a."userId" WHERE u.email = ?1`).bind(who?.email).first<{ accountId: string }>();
    await signIn(providers, identity("google", { email: who?.email ?? "", sub: sub?.accountId ?? "" }), fresh);
    expect((await send("DELETE", `/api/security/passkeys/${id}`, fresh)).status).toBe(200);
    expect((await passkeys(fresh)).list).toHaveLength(0);
  });

  it("removal from a foreign origin is rejected", async () => {
    const { jar } = await signedIn();
    await enroll(jar, authenticatorFor());
    const id = (await passkeys(jar)).list[0]?.id ?? "";
    const response = await call(`/api/security/passkeys/${id}`, { method: "DELETE", headers: { origin: "https://evil.example", cookie: jar.header() } });
    expect(response.status).toBe(403);
    expect((await passkeys(jar)).list).toHaveLength(1);
  });

  it("security methods and activity reflect only the caller", async () => {
    const { jar } = await signedIn();
    await enroll(jar, authenticatorFor());
    const methods = (await (await get("/api/security/methods", jar)).json()) as { data: { providers: string[]; passkeys: number } };
    expect(methods.data).toEqual({ providers: ["google"], passkeys: 1 });
    const activity = (await (await get("/api/security/activity", jar)).json()) as { data: Array<{ action: string }> };
    const actions = activity.data.map((e) => e.action);
    expect(actions).toEqual(expect.arrayContaining(["auth.account.created", "auth.login.success", "auth.passkey.add"]));
  });
});

describe("no WebAuthn material in logs", () => {
  it("assertions, signatures, and client data never appear in logs", async () => {
    const { jar } = await signedIn();
    const authenticator = authenticatorFor();
    await enroll(jar, authenticator);
    const browser = new CookieJar();
    const optionsResponse = await passkeyOptions(browser);
    const assertion = await authenticator.authenticate((await optionsResponse.json()) as { challenge: string });
    await send("POST", "/api/auth/passkey/verify-authentication", browser, { response: assertion });
    const all = logLines.join("\n");
    for (const secret of [assertion.response.signature, assertion.response.clientDataJSON, assertion.response.authenticatorData]) {
      expect(all).not.toContain(secret);
    }
  });
});
