/**
 * Migration 0003 invariants on real D1 (workerd). Each test attacks the
 * database directly with raw SQL, so the triggers are shown to hold even if
 * repository or coordinator code were wrong.
 */
import { describe, expect, it } from "vitest";
import { ConstraintViolationError, mapD1Error, ProvisioningGuardError } from "../../src/worker/db/errors";
import { randomId } from "../../src/worker/utils/random";
import { db, harnesses, profiles, users } from "../helpers/db";
import { activeHarness, activeUser, completed, coordinator, jobRow, journalRows, OP, openCreate, TEST_ISSUER, TEST_KEY_ID, TestClock } from "../helpers/provisioning";

const hex64 = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
const raw = (sql: string, ...values: unknown[]) => db().prepare(sql).bind(...values).run();

async function claimed() {
  const clock = new TestClock();
  const c = coordinator(clock);
  const fixture = await openCreate(c);
  const t = await c.claim(fixture.jobId, { keyId: TEST_KEY_ID, automatic: false });
  if (!t) throw new Error("expected a claim");
  return { clock, c, t, ...fixture };
}

describe("fixed logical command (provisioning_commands)", () => {
  it("is written with the job, matches it, and can never be updated or deleted", async () => {
    const { jobId, payloadHash, profile, user } = await openCreate(coordinator());
    const command = await db().prepare(`SELECT * FROM provisioning_commands WHERE job_id = ?1`).bind(jobId).first<Record<string, unknown>>();
    expect(command).toMatchObject({ operation: "profile.create", payload_hash: payloadHash, agent_profile_id: profile.id, user_id: user.id, protocol: "LA-WEB-PROVISIONING/1" });
    expect((await jobRow(jobId))?.["request_hash"]).toBe(payloadHash);
    expect(JSON.parse(String(command?.["payload_json"]))).toEqual({
      displayName: "Research assistant",
      idempotencyKey: (await jobRow(jobId))?.["idempotency_key"],
      issuer: TEST_ISSUER,
      profileId: profile.id,
      subject: user.id,
      template: "assistant",
    });
    await expect(raw(`UPDATE provisioning_commands SET payload_json = '{}' WHERE job_id = ?1`, jobId)).rejects.toThrow(/command_immutable/);
    await expect(raw(`DELETE FROM provisioning_commands WHERE job_id = ?1`, jobId)).rejects.toThrow(/command_immutable/);
    // The job it belongs to cannot be deleted either (FK RESTRICT).
    await expect(raw(`DELETE FROM provisioning_jobs WHERE id = ?1`, jobId)).rejects.toThrow(/FOREIGN KEY/);
  });

  it("a rename never changes the logical command", async () => {
    const { jobId, profile, user } = await openCreate(coordinator());
    const before = await db().prepare(`SELECT payload_json, payload_hash FROM provisioning_commands WHERE job_id = ?1`).bind(jobId).first();
    await profiles().forUser(user.id).rename(profile.id, "Renamed");
    expect(await db().prepare(`SELECT payload_json, payload_hash FROM provisioning_commands WHERE job_id = ?1`).bind(jobId).first()).toEqual(before);
  });

  it("refuses a command that does not restate its job", async () => {
    const { jobId, profile, user, harness } = await openCreate(coordinator());
    const other = await activeHarness();
    // A second command row for the same job is a primary-key conflict; a fresh job with a mismatching command is refused by the trigger.
    const job2 = randomId("prv");
    await raw(
      `INSERT INTO provisioning_jobs (id, user_id, agent_profile_id, harness_id, operation, request_id, idempotency_key, request_hash, status, attempt_count, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, 'profile.revoke', ?5, ?6, ?7, 'pending', 0, 1, 1)`,
      job2, user.id, profile.id, harness.id, randomId("req"), randomId("idk"), "c".repeat(64),
    );
    const insert = (harnessId: string, hash: string) =>
      raw(
        `INSERT INTO provisioning_commands (job_id, user_id, agent_profile_id, harness_id, protocol, operation, idempotency_key, target_operation_id, payload_json, payload_hash, created_at)
         SELECT id, user_id, agent_profile_id, ?2, 'LA-WEB-PROVISIONING/1', operation, idempotency_key, ?3, ?4, ?5, 1791000000000 FROM provisioning_jobs WHERE id = ?1`,
        job2, harnessId, OP, JSON.stringify({ operationId: OP, profileId: profile.id }), hash,
      );
    // Both of these also lack a create that returned OP; SQLite does not order BEFORE triggers, so either guard may report.
    await expect(insert(other.id, "c".repeat(64))).rejects.toThrow(/command_mismatch|provisioning_not_allowed/); // cross-harness substitution
    await expect(insert(harness.id, "d".repeat(64))).rejects.toThrow(/command_mismatch|provisioning_not_allowed/); // hash ≠ request_hash
    await expect(insert(harness.id, "c".repeat(64))).rejects.toThrow(/provisioning_not_allowed/); // no create returned OP
    expect(await jobRow(jobId)).toBeTruthy();
  });

  it("only an active owner's own, provisionable profile on an active harness can get a create", async () => {
    const c = coordinator();
    const owner = await activeUser();
    const stranger = await activeUser();
    const harness = await activeHarness();
    const profile = await profiles().forUser(owner.id).create({ agentName: "Mine" });
    const open = (userId: string, harnessId = harness.id) => c.openCreateJob({ userId, agentProfileId: profile.id, harnessId, requestId: randomId("req"), issuer: TEST_ISSUER });

    // Cross-user: another user's profile looks like a missing one.
    await expect(open(stranger.id)).rejects.toMatchObject({ name: "NotFoundError" });
    // A disabled harness never gets new work.
    const disabled = await harnesses().registerAdmin({ name: `h ${randomId("h")}`, environment: "development", endpoint: "https://disabled.example.test", keyId: TEST_KEY_ID, capabilities: { protocolVersions: [1], operations: [] } });
    await expect(open(owner.id, disabled.id)).rejects.toBeInstanceOf(ProvisioningGuardError);
    // A suspended owner gets no new provisioning.
    const suspended = await activeUser();
    const theirs = await profiles().forUser(suspended.id).create({ agentName: "Theirs" });
    await users().transition(suspended.id, "suspended");
    await expect(c.openCreateJob({ userId: suspended.id, agentProfileId: theirs.id, harnessId: harness.id, requestId: randomId("req"), issuer: TEST_ISSUER })).rejects.toMatchObject({
      reason: "provisioning_not_allowed",
    });
    // Nothing was written by any refused attempt.
    expect(await db().prepare(`SELECT COUNT(*) AS n FROM provisioning_jobs WHERE agent_profile_id IN (?1, ?2)`).bind(profile.id, theirs.id).first<{ n: number }>()).toEqual({ n: 0 });

    // One unresolved create per profile; never a second create after one succeeded.
    await open(owner.id);
    await expect(open(owner.id)).rejects.toBeTruthy();
  });

  it("refuses a display name the harness would refuse, before anything is written (§8.1)", async () => {
    const c = coordinator();
    const user = await activeUser();
    const harness = await activeHarness();
    const profile = await profiles().forUser(user.id).create({ agentName: "x".repeat(65) });
    await expect(c.openCreateJob({ userId: user.id, agentProfileId: profile.id, harnessId: harness.id, requestId: randomId("req"), issuer: TEST_ISSUER })).rejects.toMatchObject({ code: "INVALID_DISPLAY_NAME" });
    expect((await profiles().getByIdTrusted(profile.id))?.status).toBe("pending");
  });
});

describe("transmission journal (append-only)", () => {
  it("a journaled row is never updated or deleted, and its identity is complete", async () => {
    const { t, jobId, payloadHash } = await claimed();
    const [row] = await journalRows(jobId);
    expect(row).toMatchObject({ command_id: t.commandId, seq: 1, operation: "profile.create", payload_hash: payloadHash, issued_at: 1_791_000_000, expires_at: 1_791_000_060 });
    expect(row?.["nonce_hash"]).toMatch(/^[0-9a-f]{64}$/);
    expect(row?.["nonce_hash"]).not.toContain(t.nonce);
    await expect(raw(`UPDATE provisioning_transmissions SET expires_at = expires_at + 1 WHERE command_id = ?1`, t.commandId)).rejects.toThrow(/journal_append_only/);
    await expect(raw(`DELETE FROM provisioning_transmissions WHERE command_id = ?1`, t.commandId)).rejects.toThrow(/journal_append_only/);
    await expect(raw(`DELETE FROM provisioning_deliveries WHERE job_id = ?1`, jobId)).rejects.toThrow(/journal_append_only/);
  });

  it("only the current lease holder journals, with the next sequence number and the fixed payload", async () => {
    const { t, jobId, harness, profile } = await claimed();
    const insert = (overrides: { lease?: string; seq?: number; hash?: string; harnessId?: string }) =>
      raw(
        `INSERT INTO provisioning_transmissions (command_id, job_id, seq, harness_id, agent_profile_id, protocol, operation, target_operation_id, payload_hash,
           key_id, nonce_hash, issued_at, expires_at, lease_token, lease_holder, automatic, journaled_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'LA-WEB-PROVISIONING/1', 'profile.create', NULL, ?6, 'w1-test-only-key', ?7, 1791000001, 1791000061, ?8, ?9, 0, 1791000001000)`,
        randomId("cmd"), jobId, overrides.seq ?? 1, overrides.harnessId ?? harness.id, profile.id, overrides.hash ?? t.payloadHash, hex64(),
        overrides.lease ?? t.leaseToken, t.leaseHolder,
      );
    await expect(insert({ lease: "x".repeat(32) })).rejects.toThrow(/journal_lease_required/); // forged lease
    await expect(insert({ seq: 1 })).rejects.toThrow(/journal_lease_required|UNIQUE/); // seq already used
    await expect(insert({ seq: 0 })).rejects.toThrow(); // seq ≥ 1
    expect((await journalRows(jobId)).length).toBe(1);
  });

  it("a retry with a different payload hash is refused, and the failed batch claims nothing", async () => {
    const { c, t, jobId, harness, profile } = await claimed();
    await c.record(t, { kind: "uncertain", reason: "TIMEOUT" });
    // Hand-built claim batch with a forged payload hash for the job's own operation.
    const token = "y".repeat(32);
    await expect(
      db().batch([
        db().prepare(`UPDATE provisioning_deliveries SET lease_token = ?2, lease_holder = 'attacker', lease_until = 1791000999000, next_seq = next_seq + 1 WHERE job_id = ?1`).bind(jobId, token),
        db()
          .prepare(
            `INSERT INTO provisioning_transmissions (command_id, job_id, seq, harness_id, agent_profile_id, protocol, operation, target_operation_id, payload_hash,
               key_id, nonce_hash, issued_at, expires_at, lease_token, lease_holder, automatic, journaled_at)
             VALUES (?1, ?2, 2, ?3, ?4, 'LA-WEB-PROVISIONING/1', 'profile.create', NULL, ?5, 'w1-test-only-key', ?6, 1791000001, 1791000061, ?7, 'attacker', 0, 1791000001000)`,
          )
          .bind(randomId("cmd"), jobId, harness.id, profile.id, "b".repeat(64), "f".repeat(64), token),
      ]),
    ).rejects.toThrow(/payload_mismatch/);
    expect((await db().prepare(`SELECT next_seq, lease_token FROM provisioning_deliveries WHERE job_id = ?1`).bind(jobId).first())).toEqual({ next_seq: 2, lease_token: null });
  });

  it("a status poll must address the job's known operation id", async () => {
    const { c, t, jobId } = await claimed();
    expect(await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: false, operation: "profile.status" })).toBeNull(); // no operation id yet
    await c.record(t, completed());
    await c.reconcileJob(jobId);
    const poll = await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: false, operation: "profile.status" });
    expect(poll).toMatchObject({ operation: "profile.status", targetOperationId: OP });
    expect(JSON.parse(poll?.payloadJson ?? "{}")).toEqual({ operationId: OP, profileId: poll?.profileId });
  });

  it("nonce hashes are unique across the journal", async () => {
    const { jobId } = await claimed();
    const [row] = await journalRows(jobId);
    const other = await claimed();
    await expect(
      db().batch([
        db().prepare(`UPDATE provisioning_deliveries SET lease_token = NULL, lease_holder = NULL, lease_until = NULL WHERE job_id = ?1`).bind(other.jobId),
        db().prepare(`UPDATE provisioning_deliveries SET lease_token = ?2, lease_holder = 'h', lease_until = 1791000999000, next_seq = next_seq + 1 WHERE job_id = ?1`).bind(other.jobId, "z".repeat(32)),
        db()
          .prepare(
            `INSERT INTO provisioning_transmissions (command_id, job_id, seq, harness_id, agent_profile_id, protocol, operation, target_operation_id, payload_hash,
               key_id, nonce_hash, issued_at, expires_at, lease_token, lease_holder, automatic, journaled_at)
             SELECT ?1, job_id, 2, harness_id, agent_profile_id, protocol, 'profile.create', NULL, payload_hash, 'w1-test-only-key', ?2, 1791000001, 1791000061, ?3, 'h', 0, 1791000001000
             FROM provisioning_commands WHERE job_id = ?4`,
          )
          .bind(randomId("cmd"), row?.["nonce_hash"], "z".repeat(32), other.jobId),
      ]),
    ).rejects.toThrow(/UNIQUE/);
  });
});

describe("outcomes (insert-only; an answer is final)", () => {
  it("an answer is final; an uncertain mark cannot follow it; a late answer may follow an uncertain mark", async () => {
    const { c, t } = await claimed();
    expect(await c.record(t, { kind: "uncertain", reason: "TIMEOUT" })).toBe(true);
    expect(await c.record(t, { kind: "uncertain", reason: "TIMEOUT" })).toBe(false); // idempotent
    expect(await c.record(t, { kind: "refused", code: "QUOTA_EXCEEDED" })).toBe(true); // late answer
    expect(await c.record(t, completed())).toBe(false); // already answered
    await expect(
      raw(`INSERT INTO provisioning_transmission_outcomes (command_id, disposition, uncertain_reason, recorded_by, recorded_at) VALUES (?1, 'uncertain', 'X', 'r', 1791000000001)`, t.commandId),
    ).rejects.toThrow(/journal_answer_final|UNIQUE/);
    await expect(raw(`UPDATE provisioning_transmission_outcomes SET refusal_code = 'EXPIRED' WHERE command_id = ?1`, t.commandId)).rejects.toThrow(/journal_append_only/);
    await expect(raw(`DELETE FROM provisioning_transmission_outcomes WHERE command_id = ?1`, t.commandId)).rejects.toThrow(/journal_append_only/);
  });

  it("a create answered with a non-terminal state cannot be stored, even by raw SQL", async () => {
    const { t } = await claimed();
    await expect(
      raw(
        `INSERT INTO provisioning_transmission_outcomes (command_id, disposition, outcome_kind, operation_id, operation_state, owner_bound, principal_id, recorded_by, recorded_at)
         VALUES (?1, 'answered', 'operation', ?2, 'pending', 1, 'p', 'r', 1791000000001)`,
        t.commandId, OP,
      ),
    ).rejects.toThrow(/outcome_inconsistent/);
  });
});

describe("delivery bookkeeping", () => {
  it("counters only move forward, one transmission at a time", async () => {
    const { jobId } = await claimed();
    await expect(raw(`UPDATE provisioning_deliveries SET next_seq = 1 WHERE job_id = ?1`, jobId)).rejects.toThrow(/delivery_bookkeeping/);
    await expect(raw(`UPDATE provisioning_deliveries SET next_seq = next_seq + 2 WHERE job_id = ?1`, jobId)).rejects.toThrow(/delivery_bookkeeping/);
    await expect(raw(`UPDATE provisioning_deliveries SET auto_attempts = auto_attempts + 5 WHERE job_id = ?1`, jobId)).rejects.toThrow(/delivery_bookkeeping/);
  });
});

describe("job observations", () => {
  it("observed state only moves forward and the operation id is learned once", async () => {
    const { c, t, jobId } = await claimed();
    await c.record(t, completed());
    await c.reconcileJob(jobId);
    expect(await jobRow(jobId)).toMatchObject({ status: "completed", observed_state: "completed", operation_id: OP, observed_owner_bound: 1 });
    await expect(raw(`UPDATE provisioning_jobs SET observed_state = 'pending' WHERE id = ?1`, jobId)).rejects.toThrow(/observed_state_regression/);
    await expect(raw(`UPDATE provisioning_jobs SET observed_state = 'failed' WHERE id = ?1`, jobId)).rejects.toThrow(/observed_state_regression/);
    await expect(raw(`UPDATE provisioning_jobs SET operation_id = ?2 WHERE id = ?1`, jobId, "e".repeat(32))).rejects.toThrow(/immutable_column/);
    await raw(`UPDATE provisioning_jobs SET observed_state = 'revoked' WHERE id = ?1`, jobId); // completed → revoked is forward
  });

  it("attempt_count saturates at the legacy cap while the journal keeps counting", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    for (let i = 0; i < 12; i += 1) {
      const t = await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: false });
      if (!t) throw new Error("claim");
      await c.record(t, { kind: "uncertain", reason: "TIMEOUT" });
      clock.advance(60);
    }
    expect(await jobRow(jobId)).toMatchObject({ attempt_count: 10, status: "sending" });
    expect((await journalRows(jobId)).length).toBe(12);
  });
});

describe("profiles", () => {
  it("a suspended owner's profile can never enter provisioning or active", async () => {
    const user = await activeUser();
    const harness = await activeHarness();
    const profile = await profiles().forUser(user.id).create({ agentName: "p" });
    await profiles().transitionTrusted(profile.id, "provisioning", { harnessId: harness.id });
    await users().transition(user.id, "suspended");
    await expect(profiles().transitionTrusted(profile.id, "active")).rejects.toBeInstanceOf(ProvisioningGuardError);
    await expect(profiles().transitionTrusted(profile.id, "revoked")).resolves.toMatchObject({ status: "revoked" });
  });

  it("a profile's harness placement is permanent (no silent move to another harness id)", async () => {
    const user = await activeUser();
    const [a, b] = [await activeHarness(), await activeHarness()];
    const profile = await profiles().forUser(user.id).create({ agentName: "p" });
    await profiles().transitionTrusted(profile.id, "provisioning", { harnessId: a.id });
    await profiles().transitionTrusted(profile.id, "failed");
    await expect(profiles().transitionTrusted(profile.id, "provisioning", { harnessId: b.id })).rejects.toBeInstanceOf(ConstraintViolationError);
  });
});

describe("harness retirement records", () => {
  async function retire(harnessId: string) {
    await harnesses().setStatusAdmin(harnessId, "disabled");
    await raw(`INSERT INTO harness_retirements (harness_id, reason_code, retired_by, operation_id, retired_at) VALUES (?1, 'LEDGER_LOST', 'opr_testoperator1', ?2, 1791000000000)`, harnessId, randomId("op"));
  }

  it("retirement needs a disabled harness, is append-only, and is permanent", async () => {
    const h = await activeHarness();
    await expect(raw(`INSERT INTO harness_retirements (harness_id, reason_code, retired_by, operation_id, retired_at) VALUES (?1, 'LEDGER_LOST', 'opr_testoperator1', ?2, 1791000000000)`, h.id, randomId("op"))).rejects.toThrow(/harness_not_disabled/);
    await retire(h.id);
    await expect(harnesses().setStatusAdmin(h.id, "active")).rejects.toBeInstanceOf(ProvisioningGuardError);
    await expect(harnesses().setStatusAdmin(h.id, "draining")).rejects.toThrow();
    await expect(raw(`UPDATE harness_retirements SET reason_code = 'X' WHERE harness_id = ?1`, h.id)).rejects.toThrow(/harness_record_append_only/);
    await expect(raw(`DELETE FROM harness_retirements WHERE harness_id = ?1`, h.id)).rejects.toThrow(/harness_record_append_only/);
    // The id can neither be deleted nor registered again.
    await expect(raw(`DELETE FROM harnesses WHERE id = ?1`, h.id)).rejects.toThrow(/FOREIGN KEY/);
    await expect(
      raw(`INSERT INTO harnesses (id, name, environment, endpoint, key_id, created_at, updated_at) VALUES (?1, ?2, 'development', 'https://reuse.example.test', 'k', 1, 1)`, h.id, randomId("n")),
    ).rejects.toThrow(/UNIQUE|PRIMARY/);
  });

  it("a harness at a retired endpoint stays inactive until an operator approves it as a replacement", async () => {
    const endpoint = `https://${randomId("gw").replace("_", "-")}.example.test`;
    const old = await activeHarness(endpoint);
    await retire(old.id);
    const next = await harnesses().registerAdmin({ name: `h ${randomId("h")}`, environment: "development", endpoint, keyId: TEST_KEY_ID, capabilities: { protocolVersions: [1], operations: [] } });
    await expect(harnesses().setStatusAdmin(next.id, "active")).rejects.toMatchObject({ reason: "replacement_not_approved" });
    await expect(raw(`INSERT INTO harness_replacements (replacement_harness_id, retired_harness_id, approved_by, operation_id, approved_at) VALUES (?1, ?1, 'opr_testoperator1', ?2, 1791000000000)`, next.id, randomId("op"))).rejects.toThrow();
    await raw(`INSERT INTO harness_replacements (replacement_harness_id, retired_harness_id, approved_by, operation_id, approved_at) VALUES (?1, ?2, 'opr_testoperator1', ?3, 1791000000000)`, next.id, old.id, randomId("op"));
    await expect(harnesses().setStatusAdmin(next.id, "active")).resolves.toMatchObject({ status: "active" });
    // A retired id can never be approved as someone's replacement.
    const another = await activeHarness();
    await retire(another.id);
    await expect(raw(`INSERT INTO harness_replacements (replacement_harness_id, retired_harness_id, approved_by, operation_id, approved_at) VALUES (?1, ?2, 'opr_testoperator1', ?3, 1791000000000)`, another.id, old.id, randomId("op"))).rejects.toThrow(/replacement_invalid/);
  });
});

describe("typed errors", () => {
  it("maps every 0003 trigger message to a ProvisioningGuardError", () => {
    expect(mapD1Error(new Error("D1_ERROR: journal_append_only: SQLITE_CONSTRAINT"))).toMatchObject({ name: "ProvisioningGuardError", reason: "journal_append_only" });
    expect(mapD1Error(new Error("harness_retired"))).toMatchObject({ reason: "harness_retired" });
    expect(mapD1Error(new Error("payload_mismatch"))).toMatchObject({ reason: "payload_mismatch" });
  });
});
