/**
 * Phase 5 server-side access policy: every account API enforces the shared
 * policy (src/shared/access.ts) for every account status, whatever the
 * browser shows. Plus the new account endpoints.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ACCOUNT_ROUTES } from "../../src/worker/api/security";
import { AgentProfileRepository } from "../../src/worker/db/agent-profiles";
import { UserRepository, type UserStatus } from "../../src/worker/db/users";
import { FakeProviders, get, identity, send, signIn, type Identity } from "../helpers/auth";
import { CookieJar } from "../helpers/cookies";
import { call, testEnv } from "../helpers/worker";

let providers: FakeProviders;
let logLines: string[];

beforeEach(() => {
  logLines = [];
  for (const level of ["log", "info", "warn", "error"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void logLines.push(args.map(String).join(" ")));
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

/** A signed-in browser for an account in `status` (sessions are created while allowed, then the status changes). */
async function account(status: UserStatus, name = "Test User"): Promise<{ who: Identity; jar: CookieJar; userId: string }> {
  const who = identity("google", { name });
  const jar = new CookieJar();
  if (status === "pending") {
    await signIn(providers, who, jar, { env: testEnv({ SIGNUP_POLICY: "approval" }) });
    return { who, jar, userId: await profileId(who) };
  }
  await signIn(providers, who, jar);
  const userId = await profileId(who);
  if (status !== "active") await new UserRepository(env.DB).transition(userId, status);
  return { who, jar, userId };
}

/** A concrete request for each route pattern (ids that don't exist are fine: authorization runs first). */
function requestFor(route: (typeof ACCOUNT_ROUTES)[number]): { method: string; path: string; body?: unknown } {
  const path = route.pattern.source.replace(/^\^/, "").replace(/\$$/, "").replace(/\\\//g, "/").replace("(?<id>[^/]+)", "abcdefgh12345678");
  const body = route.method === "PATCH" ? (path === "/api/me" ? { displayName: "New name" } : { name: "New name" }) : undefined;
  return { method: route.method, path, ...(body ? { body } : {}) };
}

async function hit(jar: CookieJar, route: (typeof ACCOUNT_ROUTES)[number]): Promise<{ status: number; code: string | undefined }> {
  const { method, path, body } = requestFor(route);
  const response = method === "GET" ? await get(path, jar) : await send(method, path, jar, body);
  const json = (await response.json()) as { error?: { code: string } };
  return { status: response.status, code: json.error?.code };
}

describe("every account API enforces the shared policy for every status", () => {
  it("routes are declared: only GET /api/me is identity-level, everything else needs an active account", () => {
    const identityRoutes = ACCOUNT_ROUTES.filter((r) => r.access === "identity").map((r) => `${r.method} ${r.pattern.source}`);
    expect(identityRoutes).toEqual(["GET ^\\/api\\/me$"]);
    expect(ACCOUNT_ROUTES.every((r) => r.access === "identity" || r.access === "active")).toBe(true);
  });

  it("signed out → 401 AUTH_REQUIRED on every route", async () => {
    for (const route of ACCOUNT_ROUTES) expect(await hit(new CookieJar(), route), `${route.method} ${route.pattern}`).toEqual({ status: 401, code: "AUTH_REQUIRED" });
  });

  it("pending → identity only; every active route is 403 ACCOUNT_PENDING", async () => {
    const { jar } = await account("pending");
    for (const route of ACCOUNT_ROUTES) {
      const result = await hit(jar, route);
      if (route.access === "identity") expect(result.status, `${route.method} ${route.pattern}`).toBe(200);
      else expect(result, `${route.method} ${route.pattern}`).toEqual({ status: 403, code: "ACCOUNT_PENDING" });
    }
    // Passkey enrolment is part of the Security page: active only too.
    const options = await call("/api/auth/passkey/generate-register-options", { headers: { cookie: jar.header() } });
    expect(options.status).toBe(403);
    expect(((await options.json()) as { error: { code: string } }).error.code).toBe("ACCOUNT_PENDING");
  });

  it.each(["suspended", "disabled"] as const)("%s → 403 ACCOUNT_DISABLED on every route, despite a valid session", async (status) => {
    const { jar } = await account(status);
    for (const route of ACCOUNT_ROUTES) expect(await hit(jar, route), `${route.method} ${route.pattern}`).toEqual({ status: 403, code: "ACCOUNT_DISABLED" });
    const probe = (await (await get("/api/session", jar)).json()) as { data: unknown };
    expect(probe.data).toEqual({ signedIn: false, blocked: true, status });
  });

  it("active → never an authorization error", async () => {
    const { jar } = await account("active");
    // Sign out everywhere ends this session, so it runs last.
    const ordered = [...ACCOUNT_ROUTES].sort((a, b) => Number(a.pattern.source.includes("revoke-all")) - Number(b.pattern.source.includes("revoke-all")));
    for (const route of ordered) {
      const { status, code } = await hit(jar, route);
      expect([401, 403], `${route.method} ${route.pattern} → ${status} ${code}`).not.toContain(status);
    }
  });

  it("a protected SPA URL serves only the generic document: no account data, whatever the session", async () => {
    const pending = await account("pending", "Pending Person");
    const active = await account("active", "Active Person");
    for (const path of ["/dashboard", "/agents", "/security", "/sessions", "/settings", "/dashboard/../security"]) {
      for (const jar of [new CookieJar(), pending.jar, active.jar]) {
        const response = await call(path, { headers: { cookie: jar.header(), accept: "text/html" } });
        expect(response.status).toBe(200);
        const html = await response.text();
        expect(html).toContain('<div id="root"></div>');
        expect(html).not.toMatch(/Pending Person|Active Person|usr_|session_token/);
      }
    }
  });
});

describe("account endpoints", () => {
  it("the overview shows only safe, own account information", async () => {
    const { jar, who } = await account("active", "Dana");
    const response = await get("/api/account/overview", jar);
    const text = await response.text();
    const { data } = JSON.parse(text) as { data: Record<string, unknown> };
    expect(data).toMatchObject({ displayName: "Dana", status: "active", signIn: { providers: ["google"], passkeys: 0 }, sessions: { active: 1 }, agents: { count: 0 } });
    expect(typeof (data["sessions"] as { currentExpiresAt: number }).currentExpiresAt).toBe("number");
    expect(Object.keys(data).sort()).toEqual(["agents", "displayName", "sessions", "signIn", "status"]);
    expect(text).not.toContain(who.email);
    expect(text).not.toMatch(/usr_|authUserId|token|harness/i);
  });

  it("display name: validated, stored as data (no HTML interpretation), audited without the value", async () => {
    const { jar, userId } = await account("active");
    for (const bad of ["", "   ", "x".repeat(81), "line\nbreak"]) {
      const response = await send("PATCH", "/api/me", jar, { displayName: bad });
      expect(response.status, JSON.stringify(bad)).toBe(400);
    }
    expect((await send("PATCH", "/api/me", jar, { displayName: "ok", role: "admin" })).status).toBe(400);

    const hostile = `<img src=x onerror="alert(1)">`;
    const response = await send("PATCH", "/api/me", jar, { displayName: hostile });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(((await response.json()) as { data: { displayName: string } }).data.displayName).toBe(hostile);
    expect(((await (await get("/api/me", jar)).json()) as { data: { displayName: string } }).data.displayName).toBe(hostile);

    const audit = await env.DB.prepare(`SELECT details_json FROM audit_events WHERE actor_id = ?1 AND action = 'account.profile.update'`).bind(userId).first<{ details_json: string }>();
    expect(JSON.parse(audit?.details_json ?? "{}")).toEqual({ field: "displayName" });
  });

  it("agents: read-only, only the caller's own profiles, without harness or permission details", async () => {
    const owner = await account("active");
    const other = await account("active");
    await new AgentProfileRepository(env.DB).forUser(owner.userId).create({ agentName: "Owner's agent" });
    const mine = (await (await get("/api/agents", owner.jar)).json()) as { data: Array<Record<string, unknown>> };
    expect(mine.data).toHaveLength(1);
    expect(Object.keys(mine.data[0] ?? {}).sort()).toEqual(["createdAt", "id", "name", "status"]);
    expect(((await (await get("/api/agents", other.jar)).json()) as { data: unknown[] }).data).toEqual([]);
    expect((await send("POST", "/api/agents", owner.jar, { name: "x" })).status).toBe(405);
  });

  it("a backend failure returns a generic error and no account data", async () => {
    const { jar } = await account("active", "Hidden Name");
    await env.DB.exec(`ALTER TABLE agent_profiles RENAME TO agent_profiles_offline;`);
    try {
      const response = await get("/api/account/overview", jar);
      expect(response.status).toBe(500);
      const text = await response.text();
      expect(JSON.parse(text).error.code).toBe("INTERNAL_ERROR");
      expect(text).not.toMatch(/Hidden Name|agent_profiles|SQLITE|no such table/i);
    } finally {
      await env.DB.exec(`ALTER TABLE agent_profiles_offline RENAME TO agent_profiles;`);
    }
  });
});
