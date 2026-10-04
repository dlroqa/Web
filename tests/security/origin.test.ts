import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig, normalizeConfiguredOrigin } from "../../src/worker/config/config";
import { checkOrigin, normalizeOriginHeader } from "../../src/worker/security/origin";
import { BASE, call, testEnv } from "../helpers/worker";

const TRUSTED = new Set(["https://lightagent-control-staging.eddelaroca.workers.dev"]);

function post(origin: string | null, extra: Record<string, string> = {}): Request {
  const headers = new Headers(extra);
  if (origin !== null) headers.set("origin", origin);
  return new Request("https://lightagent-control-staging.eddelaroca.workers.dev/api/x", { method: "POST", headers });
}

describe("checkOrigin", () => {
  it("accepts the exact trusted origin", () => {
    expect(checkOrigin(post("https://lightagent-control-staging.eddelaroca.workers.dev"), TRUSTED)).toEqual({
      allowed: true,
      origin: "https://lightagent-control-staging.eddelaroca.workers.dev",
    });
  });

  it("normalizes case and default ports before comparing", () => {
    expect(checkOrigin(post("HTTPS://Lightagent-Control-Staging.eddelaroca.workers.dev:443"), TRUSTED).allowed).toBe(true);
  });

  it.each([
    ["missing", null],
    ["opaque null", "null"],
    ["empty", ""],
    ["suffix attack", "https://lightagent-control-staging.eddelaroca.workers.dev.evil.example"],
    ["prefix attack", "https://evil-lightagent-control-staging.eddelaroca.workers.dev"],
    ["subdomain", "https://a.lightagent-control-staging.eddelaroca.workers.dev"],
    ["scheme downgrade", "http://lightagent-control-staging.eddelaroca.workers.dev"],
    ["other port", "https://lightagent-control-staging.eddelaroca.workers.dev:8443"],
    ["with path", "https://lightagent-control-staging.eddelaroca.workers.dev/x"],
    ["trailing slash", "https://lightagent-control-staging.eddelaroca.workers.dev/"],
    ["credentials", "https://user@lightagent-control-staging.eddelaroca.workers.dev"],
    ["unrelated", "https://evil.example"],
    ["not a url", "lightagent"],
    ["file scheme", "file://"],
  ])("rejects %s", (_label, origin) => {
    expect(checkOrigin(post(origin), TRUSTED).allowed).toBe(false);
  });

  it("rejects requests the browser marks cross-site even with a trusted Origin", () => {
    const request = post("https://lightagent-control-staging.eddelaroca.workers.dev", { "sec-fetch-site": "cross-site" });
    expect(checkOrigin(request, TRUSTED).allowed).toBe(false);
  });

  it("fails closed when no origins are configured", () => {
    expect(checkOrigin(post("https://lightagent-control-staging.eddelaroca.workers.dev"), new Set()).allowed).toBe(false);
  });

  it("normalizeOriginHeader keeps only scheme://host[:port]", () => {
    expect(normalizeOriginHeader("https://EXAMPLE.com:443")).toBe("https://example.com");
    expect(normalizeOriginHeader("https://example.com/")).toBeUndefined();
    expect(normalizeOriginHeader("javascript:alert(1)")).toBeUndefined();
  });
});

describe("trusted origin configuration", () => {
  it("requires bare https origins", () => {
    expect(normalizeConfiguredOrigin("https://Example.com", "production")).toBe("https://example.com");
    expect(() => normalizeConfiguredOrigin("https://example.com/app", "production")).toThrow(ConfigError);
    expect(() => normalizeConfiguredOrigin("https://example.com?x=1", "production")).toThrow(ConfigError);
    expect(() => normalizeConfiguredOrigin("http://example.com", "production")).toThrow(ConfigError);
    expect(() => normalizeConfiguredOrigin("not a url", "production")).toThrow(ConfigError);
  });

  it("allows http only for loopback in development", () => {
    expect(normalizeConfiguredOrigin("http://localhost:5173", "development")).toBe("http://localhost:5173");
    expect(() => normalizeConfiguredOrigin("http://localhost:5173", "staging")).toThrow(ConfigError);
  });

  it("loads the environment's list from server configuration", () => {
    const config = loadConfig(testEnv());
    expect([...config.trustedOrigins]).toEqual(["http://localhost:5173", "http://127.0.0.1:5173"]);
  });
});

describe("state-changing API requests", () => {
  const methods = ["POST", "PUT", "PATCH", "DELETE"];

  it.each(methods)("%s from a foreign site is rejected before routing", async (method) => {
    const response = await call("/api/anything", { method, headers: { origin: "https://evil.example" } });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ ok: false, error: { code: "FORBIDDEN" } });
  });

  it("without an Origin header is rejected", async () => {
    const response = await call("/api/anything", { method: "POST" });
    expect(response.status).toBe(403);
  });

  it("from the trusted origin reaches routing (404 for an unknown route)", async () => {
    const response = await call("/api/anything", { method: "POST", headers: { origin: BASE } });
    expect(response.status).toBe(404);
  });

  it("are all rejected when the environment trusts no origins", async () => {
    // Production's current shape: no trusted origins and no auth origin.
    const env = testEnv({ TRUSTED_ORIGINS: "", PUBLIC_ORIGIN: "", PASSKEY_RP_ID: "" });
    const response = await call("/api/anything", { method: "POST", headers: { origin: BASE } }, { env });
    expect(response.status).toBe(403);
  });

  it("safe methods are not origin-checked", async () => {
    const response = await call("/api/anything", { headers: { origin: "https://evil.example" } });
    expect(response.status).toBe(404);
  });
});
