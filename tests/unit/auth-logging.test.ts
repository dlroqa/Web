import { describe, expect, it, vi } from "vitest";
import { betterAuthErrorHandler, betterAuthLogger, describeAuthError, OPAQUE_PLACEHOLDER, sanitizeDiagnostic } from "../../src/worker/auth/logging";
import type { Logger } from "../../src/worker/utils/log";

function recordingLogger() {
  const lines: Array<{ level: string; event: string; fields: Record<string, unknown> | undefined }> = [];
  const make = (level: string) => (event: string, fields?: Record<string, unknown>) => void lines.push({ level, event, fields });
  const logger: Logger = { debug: make("debug"), info: make("info"), warn: make("warn"), error: make("error"), child: () => logger };
  return { logger, lines };
}

describe("sanitizeDiagnostic", () => {
  it("replaces long opaque runs (codes, tokens, ids) and keeps the readable text", () => {
    const token = "Kq3vX9pLm2Rt8YwZ0aBcDeFgHiJkLmNo";
    expect(sanitizeDiagnostic(`State mismatch: verification ${token} not found`)).toBe(`State mismatch: verification ${OPAQUE_PLACEHOLDER} not found`);
    expect(sanitizeDiagnostic("Failed to parse state")).toBe("Failed to parse state");
    expect(sanitizeDiagnostic("code=4/0AbCdEfGhIjKlMnOpQrStUvWxYz&state=x")).not.toContain("4/0AbCdEfGhIjKlMnOpQrStUvWxYz");
    expect(sanitizeDiagnostic("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWJ5dGVz")).toBe(OPAQUE_PLACEHOLDER);
  });

  it("bounds length, strips control characters, and handles non-strings", () => {
    expect(sanitizeDiagnostic("a ".repeat(500)).length).toBeLessThanOrEqual(201);
    expect(sanitizeDiagnostic("line1\nline2\r\u0000x")).toBe("line1 line2 x");
    expect(sanitizeDiagnostic({ token: "x" })).toBe("object");
  });
});

describe("betterAuthLogger", () => {
  it("writes one structured line per message and never logs extra arguments' contents", () => {
    const { logger, lines } = recordingLogger();
    const onFault = vi.fn();
    const adapter = betterAuthLogger(logger, onFault);
    const secret = "session-token-value-0123456789abcdef";
    adapter.log("warn", "Something about a session", { token: secret }, new Error(`boom ${secret}`));
    expect(lines).toEqual([{ level: "warn", event: "better_auth.log", fields: { message: "Something about a session", argTypes: ["object", "Error"] } }]);
    expect(JSON.stringify(lines)).not.toContain(secret);
    expect(onFault).not.toHaveBeenCalled();
  });

  it("reports error-level messages as an internal fault", () => {
    const { logger } = recordingLogger();
    const onFault = vi.fn();
    betterAuthLogger(logger, onFault).log("error", "Failed to verify authentication", new Error("db down"));
    expect(onFault).toHaveBeenCalledOnce();
  });
});

describe("betterAuthErrorHandler", () => {
  it("logs status and code only, never the message or body text", () => {
    const { logger, lines } = recordingLogger();
    const error = Object.assign(new Error("account_not_linked for someone@example.test with code xyz"), { status: "UNAUTHORIZED", body: { code: "ACCOUNT_NOT_LINKED", message: "private detail" } });
    betterAuthErrorHandler(logger)(error);
    expect(lines).toEqual([{ level: "warn", event: "better_auth.api_error", fields: { status: "UNAUTHORIZED", code: "ACCOUNT_NOT_LINKED", errorName: "Error" } }]);
    expect(JSON.stringify(lines)).not.toMatch(/example\.test|private detail|xyz/);
  });

  it("treats internal errors as errors and drops malformed codes", () => {
    const { logger, lines } = recordingLogger();
    betterAuthErrorHandler(logger)({ status: "INTERNAL_SERVER_ERROR", body: { code: "has spaces <script>" } });
    expect(lines[0]?.level).toBe("error");
    expect(describeAuthError({ body: { code: "lower-case" } }).code).toBeNull();
  });
});
