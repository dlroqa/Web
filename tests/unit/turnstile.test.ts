import { afterEach, describe, expect, it, vi } from "vitest";
import type { Environment } from "../../src/worker/config/config";
import { SITEVERIFY_URL, TurnstileVerifier } from "../../src/worker/security/turnstile";
import type { FetchFn } from "../../src/worker/utils/fetch";
import { createLogger } from "../../src/worker/utils/log";

const NOW = Date.parse("2026-10-03T12:00:00Z");
const TOKEN = "0.real-looking-turnstile-token-value";
const REAL_SECRET = "0x4AAAAAAA-not-a-real-secret-0000000";

interface Captured {
  url?: string;
  body?: URLSearchParams;
  signal?: AbortSignal | null | undefined;
}

function siteverify(response: unknown, captured: Captured = {}, status = 200): FetchFn {
  return async (input, init) => {
    captured.url = String(input);
    captured.body = new URLSearchParams(String(init?.body));
    captured.signal = init?.signal;
    return new Response(JSON.stringify(response), { status });
  };
}

const ok = { success: true, "error-codes": [], hostname: "app.example.com", action: "login", challenge_ts: "2026-10-03T11:59:30Z" };

function verifier(fetchFn: FetchFn, overrides: { secret?: string | undefined; environment?: Environment; hosts?: string[] } = {}) {
  return new TurnstileVerifier({
    secret: "secret" in overrides ? overrides.secret : REAL_SECRET,
    environment: overrides.environment ?? "production",
    expectedHostnames: new Set(overrides.hosts ?? ["app.example.com"]),
    logger: createLogger(),
    fetchFn,
    now: () => NOW,
  });
}

afterEach(() => vi.restoreAllMocks());

describe("TurnstileVerifier", () => {
  it("accepts a token Siteverify confirms for the right hostname, action, and time", async () => {
    const captured: Captured = {};
    const result = await verifier(siteverify(ok, captured)).verify({
      token: TOKEN,
      expectedAction: "login",
      remoteIp: "203.0.113.9",
      idempotencyKey: "req_abc",
    });
    expect(result).toMatchObject({ ok: true, hostname: "app.example.com", testing: false });
    expect(captured.url).toBe(SITEVERIFY_URL);
    expect(captured.body?.get("secret")).toBe(REAL_SECRET);
    expect(captured.body?.get("response")).toBe(TOKEN);
    expect(captured.body?.get("remoteip")).toBe("203.0.113.9");
    expect(captured.signal).toBeInstanceOf(AbortSignal); // finite timeout attached
  });

  it.each([
    ["rejected", { success: false, "error-codes": ["invalid-input-response"] }],
    ["rejected", { success: false, "error-codes": ["timeout-or-duplicate"] }], // replayed token
    ["hostname_mismatch", { ...ok, hostname: "evil.example" }],
    ["hostname_mismatch", { ...ok, hostname: undefined }],
    ["action_mismatch", { ...ok, action: "signup" }],
    ["action_mismatch", { ...ok, action: undefined }],
    ["challenge_stale", { ...ok, challenge_ts: "2026-10-03T11:50:00Z" }],
    ["challenge_stale", { ...ok, challenge_ts: "not-a-date" }],
    ["siteverify_malformed", { success: "yes" }],
    ["siteverify_malformed", "not an object"],
  ])("fails with %s", async (reason, response) => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = await verifier(siteverify(response)).verify({ token: TOKEN, expectedAction: "login" });
    expect(result).toMatchObject({ ok: false, reason });
  });

  it("surfaces Siteverify error codes on rejection", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = await verifier(siteverify({ success: false, "error-codes": ["timeout-or-duplicate"] })).verify({ token: TOKEN, expectedAction: "login" });
    expect(result).toEqual({ ok: false, reason: "rejected", errorCodes: ["timeout-or-duplicate"] });
  });

  it.each([
    ["missing_token", undefined],
    ["missing_token", ""],
    ["missing_token", 123],
    ["token_too_long", "x".repeat(2049)],
  ])("fails with %s before calling Siteverify", async (reason, token) => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchFn = vi.fn<FetchFn>();
    expect(await verifier(fetchFn).verify({ token, expectedAction: "login" })).toMatchObject({ ok: false, reason });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("fails closed when the secret or hostnames are not configured", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(await verifier(siteverify(ok), { secret: undefined }).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ reason: "not_configured" });
    expect(await verifier(siteverify(ok), { hosts: [] }).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ reason: "not_configured" });
  });

  it("fails closed on HTTP errors, network errors, and timeouts", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(await verifier(siteverify(ok, {}, 500)).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ reason: "siteverify_unavailable" });
    const failing: FetchFn = () => Promise.reject(new TypeError("network"));
    expect(await verifier(failing).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ reason: "siteverify_unavailable" });
  });

  describe("Cloudflare test keys", () => {
    const testing = { success: true, "error-codes": [], hostname: "example.com", challenge_ts: "2026-10-03T11:59:30Z", metadata: { result_with_testing_key: true } };
    const TEST_SECRET = "1x0000000000000000000000000000000AA";

    it.each(["staging", "production"] as const)("are refused in %s without calling Siteverify", async (environment) => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      const fetchFn = vi.fn<FetchFn>();
      expect(await verifier(fetchFn, { secret: TEST_SECRET, environment }).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ reason: "test_key_not_allowed" });
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it("test-key results are refused in production even with a real-looking secret", async () => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      expect(await verifier(siteverify(testing)).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ reason: "test_key_not_allowed" });
    });

    it("are accepted in development and flagged as testing", async () => {
      expect(await verifier(siteverify(testing), { secret: TEST_SECRET, environment: "development", hosts: ["localhost"] }).verify({ token: TOKEN, expectedAction: "login" })).toMatchObject({ ok: true, testing: true });
    });
  });

  it("never logs the token or secret", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "warn").mockImplementation((line: string) => void lines.push(line));
    vi.spyOn(console, "log").mockImplementation((line: string) => void lines.push(line));
    await verifier(siteverify({ success: false, "error-codes": ["invalid-input-response"] })).verify({ token: TOKEN, expectedAction: "login" });
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(line).not.toContain(TOKEN);
      expect(line).not.toContain(REAL_SECRET);
    }
  });
});
