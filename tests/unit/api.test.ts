import { describe, expect, it, vi } from "vitest";
import { ERROR_DEFINITIONS } from "../../src/shared/errors";
import { newRequestId } from "../../src/worker/http/context";
import { randomId } from "../../src/worker/utils/random";
import { call, testEnv } from "../helpers/worker";

describe("GET /health", () => {
  it("returns only a minimal status document", async () => {
    const response = await call("/health");
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("rejects non-read methods with 405 and Allow", async () => {
    const response = await call("/health", { method: "POST" });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, HEAD");
  });
});

describe("request ids", () => {
  it("are prefixed, random, and unique", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => newRequestId()));
    expect(ids.size).toBe(1000);
    for (const id of ids) expect(id).toMatch(/^req_[a-z0-9]{26}$/);
  });

  it("randomId output is a valid Lightagent ProfileId", () => {
    expect(randomId("agt")).toMatch(/^[a-z0-9][a-z0-9_-]{0,63}$/);
  });

  it("appear in the error body and the x-request-id header", async () => {
    const response = await call("/api/nope");
    const body = (await response.json()) as { requestId: string };
    expect(body.requestId).toMatch(/^req_[a-z0-9]{26}$/);
    expect(response.headers.get("x-request-id")).toBe(body.requestId);
  });

  it("are never taken from the client", async () => {
    const response = await call("/api/nope", { headers: { "x-request-id": "attacker-controlled" } });
    expect(response.headers.get("x-request-id")).not.toBe("attacker-controlled");
  });
});

describe("API response headers", () => {
  it("set the central security headers", async () => {
    const headers = (await call("/health")).headers;
    expect(headers.get("x-content-type-options")).toBe("nosniff");
    expect(headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(headers.get("permissions-policy")).toContain("camera=()");
    expect(headers.get("permissions-policy")).toContain("publickey-credentials-get=(self)");
    expect(headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(headers.get("x-frame-options")).toBeNull(); // obsolete; frame-ancestors covers it
  });

  it("omit HSTS over plain HTTP and when disabled", async () => {
    expect((await call("/health")).headers.get("strict-transport-security")).toBeNull();
  });
});

describe("error sanitization", () => {
  it("every error code has a generic message and an HTTP error status", () => {
    for (const [code, { status, message }] of Object.entries(ERROR_DEFINITIONS)) {
      expect(status, code).toBeGreaterThanOrEqual(400);
      expect(message, code).not.toMatch(/sql|stack|http:\/\/|https:\/\/|\/home\/|secret|key/i);
    }
  });

  it("an unexpected failure returns INTERNAL_ERROR without internal details", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const env = testEnv({
      ASSETS: {
        fetch: () => Promise.reject(new Error("SQLITE_ERROR near 'users' at /home/agent/secret/db https://10.0.0.5:8735")),
        connect: () => {
          throw new Error("unused");
        },
      },
    });
    const response = await call("/agents", undefined, { env });
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).toBe("Something went wrong.");
    vi.restoreAllMocks();
  });

  it("invalid configuration fails closed with a generic API error", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const env = testEnv({ ENVIRONMENT: "prod" as Env["ENVIRONMENT"] });
    const response = await call("/api/nope", undefined, { env });
    expect(response.status).toBe(500);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error).toEqual({ code: "INTERNAL_ERROR", message: "Something went wrong." });
    vi.restoreAllMocks();
  });
});
