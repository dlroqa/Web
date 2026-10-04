/**
 * The committed migrations must satisfy the pinned Better Auth version with
 * the Worker's exact options. If an upgrade changes the schema, this fails
 * until a new migration is generated (`npm run auth:schema -- generate`).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { databaseFromMigrations, pendingAuthSchema } from "../../tools/auth-schema";

describe("Better Auth schema", () => {
  it("matches the committed migrations (no pending tables, columns, or indexes)", async () => {
    const plan = await pendingAuthSchema(databaseFromMigrations());
    expect(plan.toBeCreated.map((t) => t.table)).toEqual([]);
    expect(plan.toBeAdded.map((t) => `${t.table}: ${Object.keys(t.fields).join(",")}`)).toEqual([]);
    expect(plan.toBeAddedIndexes.map((i) => i.name)).toEqual([]);
    expect(plan.unsafeChanges).toEqual([]);
    expect(plan.schemaProblems).toEqual([]);
  });

  it("is pinned to exact versions so upgrades cannot change the schema silently", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { dependencies: Record<string, string> };
    expect(pkg.dependencies["better-auth"]).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.dependencies["@better-auth/passkey"]).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.dependencies["@better-auth/passkey"]).toBe(pkg.dependencies["better-auth"]);
  });
});
