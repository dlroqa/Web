import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const db = (): D1Database => env.DB;

const EXPECTED_TABLES = [
  "account",
  "agent_profiles",
  "audit_events",
  "harnesses",
  "passkey",
  "provisioning_jobs",
  "provisioning_nonces",
  "session",
  "user",
  "user_profiles",
  "verification",
];

async function objects(type: string): Promise<string[]> {
  const { results } = await db()
    .prepare(`SELECT name FROM sqlite_master WHERE type = ?1 AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name <> 'd1_migrations' ORDER BY name`)
    .bind(type)
    .all<{ name: string }>();
  return results.map((r) => r.name);
}

describe("migrations", () => {
  it("create every application table, index, and trigger", async () => {
    expect(await objects("table")).toEqual(EXPECTED_TABLES);
    expect((await objects("index")).length).toBeGreaterThanOrEqual(17);
    expect(await objects("trigger")).toContain("agent_profiles_status_transition");
    expect(await objects("trigger")).toContain("audit_events_append_only");
  });

  it("record the applied migration and are a no-op when re-applied", async () => {
    const before = await db().prepare(`SELECT name FROM d1_migrations ORDER BY id`).all<{ name: string }>();
    expect(before.results.map((r) => r.name)).toEqual(["0001_initial.sql", "0002_better_auth.sql"]);
    await applyD1Migrations(env.DB, Reflect.get(env, "TEST_MIGRATIONS") as D1Migration[]);
    const after = await db().prepare(`SELECT COUNT(*) AS n FROM d1_migrations`).first<{ n: number }>();
    expect(after?.n).toBe(2);
    expect(await objects("table")).toEqual(EXPECTED_TABLES);
  });

  it("use STRICT tables (wrong types are rejected, not coerced)", async () => {
    await expect(
      db().prepare(`INSERT INTO provisioning_nonces (nonce_hash, created_at, expires_at) VALUES (?1, 'yesterday', 2)`).bind("a".repeat(64)).run(),
    ).rejects.toThrow();
  });

  it("enforce foreign keys", async () => {
    const fk = await db().prepare(`PRAGMA foreign_keys`).first<{ foreign_keys: number }>();
    expect(fk?.foreign_keys).toBe(1);
    await expect(
      db()
        .prepare(`INSERT INTO agent_profiles (id, user_id, agent_name, permissions_json, created_at, updated_at) VALUES (?1, ?2, 'x', '{}', 1, 1)`)
        .bind("agt_aaaaaaaaaaaa", "usr_doesnotexist0")
        .run(),
    ).rejects.toThrow(/FOREIGN KEY/);
  });
});
