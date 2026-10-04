/**
 * Client behavior, rendered with react-dom/server (no browser needed):
 * the route gate for every account state, safe rendering of untrusted text,
 * and session-expiry signalling from the API client.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ReactNode } from "react";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../src/client/App";
import { gate, loginUrl } from "../../src/client/components/AccessGate";
import { api, ApiRequestError, onSessionSignal, type Me, type Overview } from "../../src/client/lib/api";
import { StaticRouterProvider } from "../../src/client/lib/router";
import { SessionContext, type SessionState } from "../../src/client/lib/session";
import { AgentsView } from "../../src/client/pages/Agents";
import { DashboardView } from "../../src/client/pages/Dashboard";
import { ActivityList } from "../../src/client/pages/Security";
import { SessionList } from "../../src/client/pages/Sessions";
import { validateDisplayName } from "../../src/client/pages/Settings";

const me = (status: Me["status"], displayName: string | null = "Robin"): Me => ({ id: "usr_abcdefgh12345678", displayName, status });
const STATES: Record<string, SessionState> = {
  loading: { state: "loading" },
  unavailable: { state: "unavailable", message: "Could not reach the server." },
  signedOut: { state: "signed-out", reason: null },
  expired: { state: "signed-out", reason: "expired" },
  pending: { state: "signed-in", me: me("pending") },
  active: { state: "signed-in", me: me("active") },
  suspended: { state: "blocked", status: "suspended" },
  disabled: { state: "blocked", status: "disabled" },
};
const PROTECTED = ["/dashboard", "/agents", "/security", "/sessions", "/settings", "/unknown"];

function render(path: string, session: SessionState, search = ""): string {
  const value = { session, refresh: async () => undefined, signOut: async () => undefined, markSignedOut: () => undefined };
  return renderToString(
    <StaticRouterProvider path={path} search={search}>
      <SessionContext.Provider value={value}>
        <AppRoutes />
      </SessionContext.Provider>
    </StaticRouterProvider>,
  );
}

const html = (node: ReactNode) => renderToString(<StaticRouterProvider path="/dashboard">{node}</StaticRouterProvider>);

afterEach(() => vi.restoreAllMocks());

describe("route gate", () => {
  it("decides every protected page the same way for each account state", () => {
    for (const path of PROTECTED) {
      expect(gate(path, STATES["loading"] as SessionState)).toEqual({ kind: "loading" });
      expect(gate(path, STATES["unavailable"] as SessionState).kind).toBe("unavailable");
      expect(gate(path, STATES["active"] as SessionState)).toEqual({ kind: "page" });
      expect(gate(path, STATES["pending"] as SessionState)).toEqual({ kind: "pending" });
      expect(gate(path, STATES["suspended"] as SessionState)).toEqual({ kind: "blocked", status: "suspended" });
      expect(gate(path, STATES["disabled"] as SessionState)).toEqual({ kind: "blocked", status: "disabled" });
      expect(gate(path, STATES["signedOut"] as SessionState).kind).toBe("redirect");
    }
    expect(gate("/login", STATES["loading"] as SessionState)).toEqual({ kind: "page" });
    expect(gate("/", STATES["active"] as SessionState)).toEqual({ kind: "redirect", to: "/dashboard" });
    expect(gate("/", STATES["signedOut"] as SessionState)).toEqual({ kind: "redirect", to: "/login" });
  });

  it("signed out → login with a safe return path; an expired session says so", () => {
    expect(gate("/sessions", STATES["signedOut"] as SessionState)).toEqual({ kind: "redirect", to: "/login?returnTo=%2Fsessions" });
    expect(gate("/security", STATES["expired"] as SessionState)).toEqual({ kind: "redirect", to: "/login?returnTo=%2Fsecurity&reason=expired" });
    expect(loginUrl("/unknown", null)).toBe("/login");
    expect(loginUrl("//evil.example", "expired")).toBe("/login?reason=expired");
  });

  it("renders no protected content (or app navigation) until the account is active", () => {
    for (const path of PROTECTED) {
      for (const [name, state] of Object.entries(STATES)) {
        const out = render(path, state);
        const shown = out.includes('aria-label="Main"');
        expect(shown, `${path} as ${name}`).toBe(name === "active");
      }
    }
  });

  it("pending accounts get the approval screen, with sign-out and no application pages", () => {
    const out = render("/settings", STATES["pending"] as SessionState);
    expect(out).toContain("Your account is awaiting approval");
    expect(out).toContain("Sign out");
    expect(out).not.toMatch(/Display name|Signed-in browsers|Passkeys/);
  });

  it("suspended and disabled accounts get the blocked screen", () => {
    expect(render("/dashboard", STATES["suspended"] as SessionState)).toContain("This account has been suspended");
    expect(render("/dashboard", STATES["disabled"] as SessionState)).toContain("This account has been disabled");
  });

  it("an unreachable backend shows a retry screen, not stale or protected content", () => {
    const out = render("/dashboard", STATES["unavailable"] as SessionState);
    expect(out).toContain("Can&#x27;t reach Lightagent");
    expect(out).toContain("Try again");
    expect(out).not.toContain('aria-label="Main"');
  });

  it("the login page shows the session-expired message only for the known reason", () => {
    expect(render("/login", STATES["signedOut"] as SessionState, "?reason=expired")).toContain("Your session expired. Please sign in again.");
    expect(render("/login", STATES["signedOut"] as SessionState, "?reason=<b>pwned</b>")).not.toMatch(/pwned/);
  });
});

describe("untrusted text renders as text", () => {
  const hostile = `<img src=x onerror="alert(1)"><script>alert(2)</script>`;
  const noMarkup = (out: string) => {
    expect(out).not.toContain("<img src=x");
    expect(out).not.toContain("<script>");
    expect(out).toContain("&lt;img");
  };

  it("display names (dashboard, pending screen, header)", () => {
    const overview: Overview = { displayName: hostile, status: "active", signIn: { providers: ["google"], passkeys: 1 }, sessions: { active: 1, currentExpiresAt: Date.now() }, agents: { count: 0 } };
    noMarkup(html(<DashboardView overview={overview} />));
    noMarkup(render("/dashboard", { state: "signed-in", me: me("pending", hostile) }));
    noMarkup(render("/dashboard", { state: "signed-in", me: me("active", hostile) }));
  });

  it("session devices, agent names, and audit actions", () => {
    noMarkup(html(<SessionList sessions={[{ id: "s1", device: hostile, createdAt: 1, lastActiveAt: 1, expiresAt: 2, current: false }]} busy={false} onRevoke={() => undefined} />));
    noMarkup(html(<AgentsView agents={[{ id: "agt_x", name: hostile, status: "pending", createdAt: 1 }]} />));
    const activity = html(<ActivityList events={[{ id: "a1", timestamp: 1, action: hostile, result: "denied", country: "US" }]} />);
    expect(activity).toContain("Account event");
    expect(activity).not.toContain("onerror");
  });

  it("client source never injects raw HTML", () => {
    const files = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : [join(dir, n)]));
    for (const file of files("src/client")) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML\s*=|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(/);
    }
  });
});

describe("API client", () => {
  function respond(status: number, body: unknown) {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
  }

  it("a 401 on an application call signals an expired session; the probe never does", async () => {
    const signals: string[] = [];
    const stop = onSessionSignal((s) => signals.push(s));
    respond(401, { ok: false, error: { code: "AUTH_REQUIRED", message: "Sign in to continue." } });
    await expect(api("/api/account/overview")).rejects.toMatchObject({ code: "AUTH_REQUIRED" });
    await expect(api("/api/session")).rejects.toBeInstanceOf(ApiRequestError);
    respond(403, { ok: false, error: { code: "ACCOUNT_DISABLED", message: "This account is not active." } });
    await expect(api("/api/security/sessions")).rejects.toMatchObject({ code: "ACCOUNT_DISABLED" });
    stop();
    expect(signals).toEqual(["expired", "status-changed"]);
  });

  it("network failures and non-JSON errors produce generic messages, never server text", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch https://internal.example/secret"));
    await expect(api("/api/me")).rejects.toMatchObject({ code: "NETWORK_ERROR", message: "Could not reach the server. Check your connection and try again." });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("<html>stack trace at worker.js:12 BETTER_AUTH_SECRET</html>", { status: 502 }));
    const error = await api("/api/me").catch((e: unknown) => e);
    expect(error).toMatchObject({ code: "INTERNAL_ERROR", message: "Something went wrong." });
  });
});

describe("settings validation mirrors the server rule", () => {
  it("accepts 1–80 printable characters", () => {
    expect(validateDisplayName("  Robin  ")).toBeNull();
    expect(validateDisplayName("")).toBe("Enter a name.");
    expect(validateDisplayName("x".repeat(81))).toBe("Use 80 characters or fewer.");
    expect(validateDisplayName("a\u0007b")).toBe("Remove special control characters.");
  });
});
