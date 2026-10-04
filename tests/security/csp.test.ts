import { describe, expect, it } from "vitest";
import { API_CSP, documentCsp, generateNonce } from "../../src/worker/security/csp";
import { BASE, call, cspNonce, fakeAssets, testEnv } from "../helpers/worker";

const SPA_ROUTES = ["/", "/login", "/register", "/dashboard", "/agents", "/agents/agt_abc123", "/security", "/sessions", "/settings"];

function directives(csp: string): Map<string, string[]> {
  return new Map(
    csp
      .split(";")
      .map((part) => part.trim().split(/\s+/))
      .filter((tokens) => tokens[0])
      .map(([name, ...sources]) => [name as string, sources]),
  );
}

describe("nonce generation", () => {
  it("is 128-bit base64 from the CSPRNG and unique per call", () => {
    const nonces = new Set(Array.from({ length: 1000 }, () => generateNonce()));
    expect(nonces.size).toBe(1000);
    for (const nonce of nonces) expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
  });

  it("refuses to build a policy around a malformed nonce", () => {
    expect(() => documentCsp("abc'; script-src *", "production")).toThrow();
  });
});

describe("HTML documents", () => {
  it.each(SPA_ROUTES)("%s is served as the SPA shell with a nonce CSP", async (path) => {
    const response = await call(path);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(cspNonce(response.headers.get("content-security-policy"))).toBeDefined();
    expect(await response.text()).toContain('<div id="root">');
  });

  it("gives separate requests different nonces", async () => {
    const nonces = await Promise.all(
      Array.from({ length: 5 }, async () => cspNonce((await call("/agents")).headers.get("content-security-policy"))),
    );
    expect(new Set(nonces).size).toBe(5);
  });

  it("writes the CSP-authorized nonce into every marked element and leaves no placeholder", async () => {
    const response = await call("/");
    const nonce = cspNonce(response.headers.get("content-security-policy"));
    const html = await response.text();
    expect(html).not.toContain("LIGHTAGENT_CSP_NONCE");
    const attributes = [...html.matchAll(/nonce="([^"]*)"/g)].map((match) => match[1]);
    expect(attributes.length).toBe(3);
    for (const value of attributes) expect(value).toBe(nonce);
  });

  it("does not add a nonce to inline scripts Vite did not mark", async () => {
    const injected = `<!doctype html><html><head><script>alert(1)</script></head><body><div id="root"></div></body></html>`;
    const env = testEnv({ ASSETS: fakeAssets({ "/": { body: injected, type: "text/html" } }) });
    const html = await (await call("/", undefined, { env })).text();
    expect(html).toContain("<script>alert(1)</script>");
  });

  it("strips validators so a nonce-bearing document is never revalidated from cache", async () => {
    const response = await call("/");
    expect(response.headers.get("etag")).toBeNull();
  });

  it("answers HEAD with headers and no body", async () => {
    const response = await call("/agents", { method: "HEAD" });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("'nonce-");
    expect(await response.text()).toBe("");
  });

  it("rejects non-read methods on documents", async () => {
    const response = await call("/agents", { method: "POST", headers: { origin: BASE } });
    expect(response.status).toBe(405);
  });
});

describe("production document policy", () => {
  const csp = documentCsp(generateNonce(), "production");
  const parsed = directives(csp);

  it("contains the required restrictive directives", () => {
    expect(parsed.get("default-src")).toEqual(["'self'"]);
    expect(parsed.get("base-uri")).toEqual(["'self'"]);
    expect(parsed.get("object-src")).toEqual(["'none'"]);
    expect(parsed.get("frame-ancestors")).toEqual(["'none'"]);
    expect(parsed.get("form-action")).toEqual(["'self'"]);
    expect(parsed.get("style-src")).toEqual(["'self'"]);
    expect(parsed.get("img-src")).toEqual(["'self'", "data:"]);
    expect(parsed.get("font-src")).toEqual(["'self'"]);
    expect(parsed.get("connect-src")).toEqual(["'self'"]);
    expect(parsed.get("script-src")?.[0]).toBe("'self'");
    expect(parsed.get("script-src")?.[1]).toMatch(/^'nonce-[A-Za-z0-9+/]{22}=='$/);
    // The only third-party source: Cloudflare Turnstile, exact origin.
    expect(parsed.get("script-src")?.slice(2)).toEqual(["https://challenges.cloudflare.com"]);
    expect(parsed.get("frame-src")).toEqual(["https://challenges.cloudflare.com"]);
  });

  it("lists no identity-provider origins (OAuth is a top-level navigation)", () => {
    expect(csp).not.toMatch(/google|github|googleapis/);
  });

  it("never allows eval, inline code, or wildcard sources", () => {
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-hashes");
    expect(csp).not.toContain("strict-dynamic");
    for (const sources of parsed.values()) {
      for (const source of sources) {
        expect(source).not.toMatch(/\*/);
        expect(["http:", "https:", "ws:", "wss:"]).not.toContain(source);
      }
    }
  });

  it("is what the Worker serves when built for production", async () => {
    const served = (await call("/", undefined, { mode: "production" })).headers.get("content-security-policy") ?? "";
    expect(directives(served).get("style-src")).toEqual(["'self'"]);
    expect(served).not.toContain("unsafe");
  });

  it("differs in development only by allowing nonce-marked styles", () => {
    const nonce = generateNonce();
    const dev = directives(documentCsp(nonce, "development"));
    const prod = directives(documentCsp(nonce, "production"));
    expect(dev.get("style-src")).toEqual(["'self'", `'nonce-${nonce}'`]);
    dev.delete("style-src");
    prod.delete("style-src");
    expect(dev).toEqual(prod);
  });
});

describe("non-document responses", () => {
  it("API JSON gets the inert API policy, not a document nonce", async () => {
    for (const path of ["/health", "/api/nope"]) {
      const csp = (await call(path)).headers.get("content-security-policy");
      expect(csp).toBe(API_CSP);
      expect(csp).not.toContain("nonce-");
    }
  });

  it.each(["/api", "/api/", "/api/nope", "/api/agents", "/api/agent-profiles/agt_x", "/api/index.html", "/api/login"])(
    "%s never falls through to the SPA shell, even when asking for HTML",
    async (path) => {
      const response = await call(path, { headers: { accept: "text/html" } });
      expect(response.status).toBe(404);
      expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
      const body = await response.text();
      expect(body).not.toContain("<");
      expect(JSON.parse(body)).toMatchObject({ ok: false, error: { code: "NOT_FOUND" } });
    },
  );

  it("a missing static file is a 404, not the SPA shell", async () => {
    const response = await call("/favicon.ico");
    expect(response.status).toBe(404);
    expect(await response.text()).not.toContain("<div");
  });

  it("Vite's extensionless dev modules pass through in development only", async () => {
    const env = testEnv({ ASSETS: fakeAssets({ "/@vite/client": { body: "export {}", type: "text/javascript" } }) });
    const dev = await call("/@vite/client", undefined, { env, mode: "development" });
    expect(dev.headers.get("content-type")).toBe("text/javascript");
    expect(await dev.text()).toBe("export {}");
    const prod = await call("/@vite/client", undefined, { env, mode: "production" });
    expect(prod.headers.get("content-type")).toBe("text/html; charset=utf-8");
  });

  it("an existing static file passes through with nosniff and an inert policy", async () => {
    const env = testEnv({ ASSETS: fakeAssets({ "/robots.txt": { body: "User-agent: *", type: "text/plain" } }) });
    const response = await call("/robots.txt", undefined, { env });
    expect(response.status).toBe(200);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toBe(API_CSP);
  });
});
