/**
 * The one-time carrier deployment script refuses anything but the reviewed
 * carrier: its source, the staging configuration with exactly the
 * AuthRateLimiter binding and migration, a bundle that never uses the
 * binding, and W1 live at 100%.
 */
import { describe, expect, it } from "vitest";
import { bundleProblems, CARRIER, configProblems, liveProblems, sourceDigest } from "../../scripts/deploy-carrier.mjs";

const config = () => ({
  name: "lightagent-control-staging",
  vars: { ENVIRONMENT: "staging" },
  preview_urls: false,
  d1_databases: [{ binding: "DB", database_name: "lightagent-control-staging", database_id: "3cc0724d-fb83-4477-ac0f-5aee58606fdf" }],
  durable_objects: { bindings: [{ name: "AUTH_RATE_LIMITER", class_name: "AuthRateLimiter" }] },
  migrations: [{ tag: "v1-auth-rate-limiter", new_sqlite_classes: ["AuthRateLimiter"] }],
});

describe("deploy-carrier.mjs", () => {
  it("accepts the carrier staging configuration", () => {
    expect(configProblems(config())).toEqual([]);
  });

  it.each<[string, (c: ReturnType<typeof config>) => unknown]>([
    ["another Worker", (c) => ({ ...c, name: "lightagent-control-production" })],
    ["another environment", (c) => ({ ...c, vars: { ENVIRONMENT: "production" } })],
    ["Preview URLs on", (c) => ({ ...c, preview_urls: true })],
    ["another D1", (c) => ({ ...c, d1_databases: [{ ...c.d1_databases[0], database_id: "581f46bc-733c-4d9f-87c9-a5bb90716986" }] })],
    ["no Durable Object binding", (c) => ({ ...c, durable_objects: { bindings: [] } })],
    ["no migration", (c) => ({ ...c, migrations: [] })],
    ["a second migration", (c) => ({ ...c, migrations: [...c.migrations, { tag: "v2", deleted_classes: ["AuthRateLimiter"] }] })],
    ["a key-value class", (c) => ({ ...c, migrations: [{ tag: "v1-auth-rate-limiter", new_classes: ["AuthRateLimiter"] }] })],
  ])("refuses %s", (_label, mutate) => {
    expect(configProblems(mutate(config()) as Record<string, unknown>).length).toBeGreaterThan(0);
  });

  it("accepts a bundle that exports the class without using the binding, and refuses the implementation", () => {
    expect(bundleProblems("var AuthRateLimiter = class {};\nexport { AuthRateLimiter, createWorker, worker_entry_default as default };")).toEqual([]);
    expect(bundleProblems("export { createWorker, worker_entry_default as default };")).toEqual(["AuthRateLimiter is not exported"]);
    expect(bundleProblems("env.AUTH_RATE_LIMITER;\nexport { AuthRateLimiter };")).toEqual(["the bundle uses AUTH_RATE_LIMITER"]);
  });

  it("requires W1 exactly at 100% (so it cannot run twice)", () => {
    expect(liveProblems({ versions: [{ version_id: CARRIER.liveVersion, percentage: 100 }] })).toEqual([]);
    expect(liveProblems({ versions: [{ version_id: "00000000-0000-0000-0000-000000000000", percentage: 100 }] })).toHaveLength(1);
    expect(liveProblems({ versions: [{ version_id: CARRIER.liveVersion, percentage: 50 }, { version_id: "x", percentage: 50 }] })).toHaveLength(1);
    expect(liveProblems(null)).toHaveLength(1);
  });

  it("source digest ignores only the script's own files and is order-independent", () => {
    const a = "100644 blob aa\tsrc/a.ts\n100644 blob bb\tsrc/b.ts\n";
    const withOwn = `100644 blob cc\t${CARRIER.ownFiles[0]}\n${a}`;
    expect(sourceDigest(withOwn)).toBe(sourceDigest(a));
    expect(sourceDigest("100644 blob bb\tsrc/b.ts\n100644 blob aa\tsrc/a.ts")).toBe(sourceDigest(a));
    expect(sourceDigest("100644 blob ab\tsrc/a.ts\n100644 blob bb\tsrc/b.ts\n")).not.toBe(sourceDigest(a));
    expect(CARRIER.sourceDigest).toMatch(/^[0-9a-f]{64}$/);
  });
});
