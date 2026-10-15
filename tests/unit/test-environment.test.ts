/**
 * The Worker tests run against the top-level (development) configuration of
 * wrangler.jsonc with local bindings only, even when the surrounding build
 * selects a deployed environment (Cloudflare Workers Builds sets
 * CLOUDFLARE_ENV=staging; vitest.config.ts removes it).
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("test environment", () => {
  it("uses the development configuration, never a deployed environment's", () => {
    expect(env.ENVIRONMENT).toBe("development");
    expect(env.PUBLIC_ORIGIN).toBe("http://localhost:5173");
    expect(env.TRUSTED_ORIGINS).toBe("http://localhost:5173,http://127.0.0.1:5173");
    expect(env.SIGNUP_POLICY).toBe("open");
  });
});
