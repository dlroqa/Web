/**
 * Deployment configuration as Wrangler itself resolves it: deployed
 * environments keep per-version Preview URLs off and their own identity, no
 * binding is remote, and the Worker tests cannot inherit a deployed
 * environment from the build (CLOUDFLARE_ENV).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { unstable_readConfig } from "wrangler";

const read = (env?: string) => unstable_readConfig({ config: "wrangler.jsonc", env });

describe("wrangler.jsonc", () => {
  it.each(["staging", "production"])("disables Preview URLs in %s", (env) => {
    expect(read(env).preview_urls).toBe(false);
  });

  it("keeps the staging Worker and D1 identity", () => {
    const staging = read("staging");
    expect(staging.name).toBe("lightagent-control-staging");
    expect(staging.vars["ENVIRONMENT"]).toBe("staging");
    expect(staging.d1_databases).toEqual([
      expect.objectContaining({ binding: "DB", database_name: "lightagent-control-staging", database_id: "3cc0724d-fb83-4477-ac0f-5aee58606fdf" }),
    ]);
  });

  describe.each([undefined, "staging", "production"])("authoritative rate limiter (%s)", (env) => {
    const config = read(env);

    it("binds AUTH_RATE_LIMITER to the SQLite-backed AuthRateLimiter class in this Worker", () => {
      expect(config.durable_objects.bindings).toEqual([{ name: "AUTH_RATE_LIMITER", class_name: "AuthRateLimiter" }]);
      expect(config.migrations).toEqual([{ tag: "v1-auth-rate-limiter", new_sqlite_classes: ["AuthRateLimiter"] }]);
    });
  });

  it("gives every environment its own Worker, so no Durable Object state is shared", () => {
    const names = [undefined, "staging", "production"].map((env) => read(env).name);
    expect(names).toEqual(["lightagent-control", "lightagent-control-staging", "lightagent-control-production"]);
  });

  it.each([undefined, "staging", "production"])("marks no D1 binding remote (%s)", (env) => {
    for (const database of read(env).d1_databases) expect(database.remote, database.binding).toBeFalsy();
  });
});

describe("vitest.config.ts", () => {
  const config = readFileSync("vitest.config.ts", "utf8");

  it("removes CLOUDFLARE_ENV so the Worker tests use the development configuration", () => {
    expect(config).toContain(`delete process.env["CLOUDFLARE_ENV"];`);
  });

  it("disables remote bindings for the Worker tests", () => {
    expect(config).toMatch(/remoteBindings:\s*false/);
  });
});
