import { describe, expect, it } from "vitest";
import worker from "../../src/worker/index";

const env = { ENVIRONMENT: "development" } as Env;

function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(`https://control.test${path}`, init), env);
}

describe("GET /health", () => {
  it("returns only a minimal status document", async () => {
    const response = await call("/health");
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("rejects non-read methods", async () => {
    const response = await call("/health", { method: "POST" });
    expect(response.status).toBe(405);
  });
});

describe("unknown API routes", () => {
  it("return a JSON error envelope, not an asset or stack trace", async () => {
    const response = await call("/api/does-not-exist");
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      ok: false,
      error: { code: "NOT_FOUND", message: "Not found." },
    });
  });
});
