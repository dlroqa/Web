import { afterEach, describe, expect, it, vi } from "vitest";
import { createLogger, isSensitiveKey, REDACTED, redact } from "../../src/worker/utils/log";

afterEach(() => vi.restoreAllMocks());

describe("redact", () => {
  it.each([
    "authorization", "Authorization", "cookie", "Set-Cookie", "set_cookie", "password", "newPassword", "token", "access_token",
    "refresh_token", "accessToken", "secret", "clientSecret", "BETTER_AUTH_SECRET", "privateKey", "private_key", "apiKey",
    "x-api-key", "signature", "X-Lightagent-Signature", "sessionId", "credential", "turnstileToken",
  ])("treats %s as sensitive", (key) => {
    expect(isSensitiveKey(key)).toBe(true);
    expect(redact({ [key]: "value" })).toEqual({ [key]: REDACTED });
  });

  it.each(["userId", "requestId", "status", "path", "agentName", "durationMs", "event"])("keeps %s", (key) => {
    expect(isSensitiveKey(key)).toBe(false);
  });

  it("redacts nested and array values", () => {
    expect(redact({ a: { b: [{ password: "p", ok: 1 }] } })).toEqual({ a: { b: [{ password: REDACTED, ok: 1 }] } });
  });

  it("redacts credential-shaped values under innocent keys", () => {
    expect(redact({ note: "Bearer abc.def" })).toEqual({ note: REDACTED });
    expect(redact({ value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig" })).toEqual({ value: REDACTED });
    expect(redact({ key: "-----BEGIN PRIVATE KEY-----\nMC4C" })).toEqual({ key: REDACTED });
  });

  it("never serializes Headers, Requests, or Responses", () => {
    const headers = new Headers({ cookie: "session=abc" });
    expect(redact({ headers })).toEqual({ headers: "[Headers]" });
    expect(JSON.stringify(redact({ request: new Request("http://x", { headers }) }))).not.toContain("session=abc");
  });

  it("bounds depth, arrays, and string length", () => {
    expect(JSON.stringify(redact({ s: "x".repeat(5000) })).length).toBeLessThan(2100);
    expect((redact({ a: Array.from({ length: 100 }, (_, i) => i) }) as { a: unknown[] }).a).toHaveLength(51);
    let deep: Record<string, unknown> = {};
    const root = deep;
    for (let i = 0; i < 20; i += 1) deep = deep["n"] = {};
    expect(JSON.stringify(redact(root))).toContain("[Truncated]");
  });
});

describe("createLogger", () => {
  it("writes one redacted JSON line with base fields", () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => void lines.push(line));
    createLogger({ requestId: "req_x" }).info("auth.login", { userId: "usr_a", password: "hunter2", cookie: "s=1" });
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0] ?? "") as Record<string, unknown>;
    expect(parsed).toMatchObject({ level: "info", event: "auth.login", requestId: "req_x", userId: "usr_a", password: REDACTED, cookie: REDACTED });
    expect(lines[0]).not.toContain("hunter2");
  });
});
