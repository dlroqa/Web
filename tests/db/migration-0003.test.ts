/**
 * Migration 0003 applied to a database that already holds 0001/0002 data
 * (a second, local-only D1 binding). The fresh-database case is every other
 * workers test, which runs on env.DB migrated from empty.
 */
import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { ProvisioningCoordinator } from "../../src/worker/provisioning/coordinator";
import { legacyDb, TEST_KEY_ID } from "../helpers/provisioning";

const migrations = Reflect.get(env, "TEST_MIGRATIONS") as D1Migration[];
const ids = {
  user: "usr_legacyuser000000000001",
  harness: "hns_legacyharness0000000001",
  profile: "agt_legacyprofile0000000001",
  disableJob: "prv_legacydisable000000001",
  createJob: "prv_legacycreate0000000001",
};

beforeAll(async () => {
  const legacy = legacyDb();
  await applyD1Migrations(legacy, migrations.filter((m) => m.name < "0003"));
  // Rows as the pre-W1 schema allowed them, including a v0 profile.disable job.
  await legacy.batch([
    legacy.prepare(`INSERT INTO user_profiles (id, auth_user_id, status, created_at, updated_at) VALUES (?1, 'legacy-auth', 'active', 1, 1)`).bind(ids.user),
    legacy
      .prepare(`INSERT INTO harnesses (id, name, environment, endpoint, key_id, status, capabilities_json, created_at, updated_at) VALUES (?1, 'legacy', 'development', 'https://legacy.example.test', 'k1', 'active', '{"protocolVersions":[1],"operations":["profile.create","profile.disable"]}', 1, 1)`)
      .bind(ids.harness),
    legacy.prepare(`INSERT INTO agent_profiles (id, user_id, agent_name, status, harness_id, permissions_json, created_at, updated_at) VALUES (?1, ?2, 'legacy', 'provisioning', ?3, '{}', 1, 1)`).bind(ids.profile, ids.user, ids.harness),
    legacy
      .prepare(
        `INSERT INTO provisioning_jobs (id, user_id, agent_profile_id, harness_id, operation, request_id, idempotency_key, request_hash, status, attempt_count, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'profile.create', 'req_legacyrequest000000001', 'legacy-idempotency-key-0001', ?5, 'sending', 10, 1, 1)`,
      )
      .bind(ids.createJob, ids.user, ids.profile, ids.harness, "a".repeat(64)),
    legacy
      .prepare(
        `INSERT INTO provisioning_jobs (id, user_id, agent_profile_id, harness_id, operation, request_id, idempotency_key, request_hash, status, attempt_count, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'profile.disable', 'req_legacyrequest000000002', 'legacy-idempotency-key-0002', ?5, 'pending', 0, 1, 1)`,
      )
      .bind(ids.disableJob, ids.user, ids.profile, ids.harness, "b".repeat(64)),
  ]);
  await applyD1Migrations(legacy, migrations);
});

describe("migration 0003 over existing data", () => {
  it("records 0003 once and keeps every existing row unchanged", async () => {
    const legacy = legacyDb();
    const names = await legacy.prepare(`SELECT name FROM d1_migrations ORDER BY id`).all<{ name: string }>();
    expect(names.results.map((r) => r.name)).toEqual(["0001_initial.sql", "0002_better_auth.sql", "0003_provisioning_journal.sql"]);
    await applyD1Migrations(legacy, migrations); // no-op
    expect(await legacy.prepare(`SELECT COUNT(*) AS n FROM d1_migrations`).first()).toEqual({ n: 3 });
    expect(await legacy.prepare(`SELECT id, status, attempt_count, request_hash FROM provisioning_jobs ORDER BY id`).all().then((r) => r.results)).toEqual([
      { id: ids.createJob, status: "sending", attempt_count: 10, request_hash: "a".repeat(64) },
      { id: ids.disableJob, status: "pending", attempt_count: 0, request_hash: "b".repeat(64) },
    ]);
    expect(await legacy.prepare(`SELECT status, harness_id FROM agent_profiles WHERE id = ?1`).bind(ids.profile).first()).toEqual({ status: "provisioning", harness_id: ids.harness });
  });

  it("gives existing jobs neutral defaults for the new columns", async () => {
    const row = await legacyDb().prepare(`SELECT * FROM provisioning_jobs WHERE id = ?1`).bind(ids.createJob).first();
    expect(row).toMatchObject({ operation_id: null, principal_id: null, observed_state: "unknown", observed_owner_bound: null, needs_attention: 0, attention_code: null, next_attempt_at: null });
    expect(await legacyDb().prepare(`SELECT provisioning_hold FROM harnesses WHERE id = ?1`).bind(ids.harness).first()).toEqual({ provisioning_hold: null });
  });

  it("legacy jobs have no fixed command, so they can never be sent; the sweep flags them for an operator", async () => {
    const c = new ProvisioningCoordinator(legacyDb(), { now: () => 1_791_000_000_000 });
    expect(await c.claim(ids.createJob, { keyId: TEST_KEY_ID, automatic: false })).toBeNull();
    await c.reconcileDue();
    const flagged = await legacyDb().prepare(`SELECT id, attention_code, status FROM provisioning_jobs ORDER BY id`).all();
    expect(flagged.results).toEqual([
      { id: ids.createJob, attention_code: "LEGACY_JOB_WITHOUT_COMMAND", status: "sending" },
      { id: ids.disableJob, attention_code: "LEGACY_JOB_WITHOUT_COMMAND", status: "pending" },
    ]);
    expect(await legacyDb().prepare(`SELECT COUNT(*) AS n FROM provisioning_transmissions`).first()).toEqual({ n: 0 });
  });

  it("the replaced profile trigger keeps every old transition and adds provisioning → revoked", async () => {
    const legacy = legacyDb();
    await expect(legacy.prepare(`UPDATE agent_profiles SET status = 'pending' WHERE id = ?1`).bind(ids.profile).run()).rejects.toThrow(/invalid_status_transition/);
    await legacy.prepare(`UPDATE agent_profiles SET status = 'revoked' WHERE id = ?1`).bind(ids.profile).run();
    await expect(legacy.prepare(`UPDATE agent_profiles SET status = 'active' WHERE id = ?1`).bind(ids.profile).run()).rejects.toThrow(/invalid_status_transition/);
  });
});
