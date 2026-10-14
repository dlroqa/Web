/**
 * W1 coordinator on real D1 in workerd: write-before-send, crash recovery,
 * conservative create resolution, suspension (R6), harness retirement and
 * ledger continuity (§10.6). Crash points are modelled by stopping the
 * Worker's step sequence; the harness is the in-memory FakeHarness. Nothing
 * here, or in the code under test, opens a network connection.
 */
import { describe, expect, it } from "vitest";
import { OperatorService } from "../../src/operator/service";
import { ProvisioningCoordinator, type SendableTransmission } from "../../src/worker/provisioning/coordinator";
import { randomId } from "../../src/worker/utils/random";
import { db, harnesses, profiles, users } from "../helpers/db";
import {
  activeHarness,
  activeUser,
  completed,
  coordinator,
  FakeHarness,
  jobRow,
  JournalCheckingTransport,
  journalRows,
  OP,
  openCreate,
  profileStatus,
  refused,
  TEST_ISSUER,
  TEST_KEY_ID,
  TestClock,
  uncertain,
} from "../helpers/provisioning";

const OPERATOR = { kind: "operator", operatorId: "opr_testoperator1", channel: "cli" } as const;
const REASON = "W1 provisioning test";
const manual = { keyId: TEST_KEY_ID, automatic: false } as const;

async function claim(c: ProvisioningCoordinator, jobId: string): Promise<SendableTransmission> {
  const t = await c.claim(jobId, manual);
  if (!t) throw new Error("expected to win the delivery lease");
  return t;
}

const seconds = (clock: TestClock) => Math.floor(clock.ms / 1000);

async function revokeJobs(profileId: string) {
  const { results } = await db()
    .prepare(
      `SELECT j.id, j.status, c.target_operation_id FROM provisioning_jobs j JOIN provisioning_commands c ON c.job_id = j.id
       WHERE j.agent_profile_id = ?1 AND j.operation = 'profile.revoke'`,
    )
    .bind(profileId)
    .all<{ id: string; status: string; target_operation_id: string }>();
  return results;
}

describe("write before send (RC6, §13.10)", () => {
  it("every send is preceded by a durable journal row; a lost claim sends nothing", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    const harness = new FakeHarness();
    const transport = new JournalCheckingTransport((t) => harness.execute(t, seconds(clock)));
    const { sent, report } = await c.deliverOnce(jobId, transport, manual);
    expect(sent).not.toBeNull();
    expect(transport.sends).toBe(1);
    expect(report).toMatchObject({ resolution: { status: "resolved", state: "completed" }, plan: "none", applied: true });
    expect(await jobRow(jobId)).toMatchObject({ status: "completed", observed_state: "completed", operation_id: harness.operation?.id });

    // A completed job journals nothing more for its own operation, so nothing more can be sent.
    const again = await c.deliverOnce(jobId, transport, manual);
    expect(again.sent).toBeNull();
    expect(transport.sends).toBe(1);
  });

  it("crash before the journal commit: nothing was journaled, nothing was sent, the job stays unresolved", async () => {
    const clock = new TestClock();
    const { jobId } = await openCreate(coordinator(clock));
    // The claim batch fails (the Worker dies, or D1 errors) before it commits.
    const failing = new Proxy(db(), {
      get(target, key) {
        if (key === "batch") return () => Promise.reject(new Error("worker evicted"));
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const dying = new ProvisioningCoordinator(failing as D1Database, { now: clock.now });
    const transport = new JournalCheckingTransport(() => completed());
    // The raw failure is mapped to a sanitized database error before anything is sent.
    await expect(dying.deliverOnce(jobId, transport, manual)).rejects.toMatchObject({ name: "UnexpectedDbError" });
    expect(transport.sends).toBe(0);
    expect(await journalRows(jobId)).toEqual([]);
    const report = await coordinator(clock).reconcileJob(jobId);
    expect(report).toMatchObject({ resolution: { status: "unresolved" }, plan: "send-create" });
  });

  it("crash after the commit, before send: the row stays potentially delivered and is never refused", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    await claim(c, jobId); // the Worker dies here, holding the lease
    expect(await c.claim(jobId, manual)).toBeNull(); // lease still live
    clock.advance(31);
    expect(await c.recoverLeases()).toBe(1);
    expect(await journalRows(jobId)).toMatchObject([{ seq: 1, outcome_kind: null, uncertain_reason: "LEASE_EXPIRED" }]);
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "unresolved" });
    expect(await jobRow(jobId)).toMatchObject({ status: "sending" });
  });

  it("crash after send, before the answer was written: a resend learns the recorded operation", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    const harness = new FakeHarness();
    const first = await claim(c, jobId);
    harness.execute(first, seconds(clock)); // executed on the harness; the Worker died before step 7
    clock.advance(31);
    await c.recoverLeases();
    harness.quotaOpen = false; // a new create would now be refused, but the key already has an operation
    const transport = new JournalCheckingTransport((t) => harness.execute(t, seconds(clock)));
    const { report } = await c.deliverOnce(jobId, transport, manual);
    expect(report.resolution).toEqual({ status: "resolved", operationId: harness.operation?.id, state: "completed" });
    expect(harness.received.map((t) => t.payloadHash)).toEqual([first.payloadHash, first.payloadHash]);
  });

  it("a lost success answer is uncertain; the resend returns the same operation (one binding)", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, profile } = await openCreate(c);
    const harness = new FakeHarness();
    const first = await claim(c, jobId);
    harness.execute(first, seconds(clock));
    await c.record(first, uncertain("TIMEOUT")); // the 201 never arrived
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "unresolved" });
    expect(await profileStatus(profile.id)).toBe("provisioning");
    clock.advance(10);
    await c.deliverOnce(jobId, new JournalCheckingTransport((t) => harness.execute(t, seconds(clock))), manual);
    expect(await jobRow(jobId)).toMatchObject({ status: "completed", operation_id: harness.operation?.id });
    expect(await profileStatus(profile.id)).toBe("active");
  });

  it("a lost failure answer is uncertain, never failed", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    const harness = new FakeHarness();
    harness.quotaOpen = false;
    const first = await claim(c, jobId);
    harness.execute(first, seconds(clock)); // QUOTA_EXCEEDED, lost
    await c.record(first, uncertain("NETWORK_ERROR"));
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "unresolved" });
    expect(await jobRow(jobId)).toMatchObject({ status: "sending", error_code: null });
  });

  it("retries renew per-transmission fields and keep the logical command", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, payloadHash, profile, user } = await openCreate(c);
    const sent: SendableTransmission[] = [];
    for (let i = 0; i < 3; i += 1) {
      const t = await claim(c, jobId);
      sent.push(t);
      await c.record(t, uncertain());
      if (i === 0) await profiles().forUser(user.id).rename(profile.id, "Renamed between retries");
      clock.advance(40);
    }
    expect(new Set(sent.map((t) => t.payloadHash))).toEqual(new Set([payloadHash]));
    expect(new Set(sent.map((t) => t.payloadJson)).size).toBe(1);
    expect(JSON.parse(sent[2]?.payloadJson ?? "{}")).toMatchObject({ displayName: "Research assistant" });
    expect(new Set(sent.map((t) => t.commandId)).size).toBe(3);
    expect(new Set(sent.map((t) => t.nonce)).size).toBe(3);
    expect(sent.map((t) => t.seq)).toEqual([1, 2, 3]);
    expect(sent.map((t) => t.issuedAt)).toEqual([1_791_000_000, 1_791_000_040, 1_791_000_080]);
  });
});

describe("leases and concurrency", () => {
  it("eight concurrent Workers: exactly one journals and may send", async () => {
    const clock = new TestClock();
    const { jobId } = await openCreate(coordinator(clock));
    const workers = Array.from({ length: 8 }, (_, i) => new ProvisioningCoordinator(db(), { now: clock.now, holder: `worker:${i}` }));
    const results = await Promise.all(workers.map((w) => w.claim(jobId, manual)));
    expect(results.filter((r) => r !== null)).toHaveLength(1);
    expect(await journalRows(jobId)).toHaveLength(1);
  });

  it("a stalled Worker past its lease and a new Worker both journal; both rows are reasoned over", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    const harness = new FakeHarness();
    const stalled = await claim(c, jobId);
    clock.advance(31); // lease expired, no recovery ran yet
    const other = new ProvisioningCoordinator(db(), { now: clock.now, holder: "worker:other" });
    const second = await claim(other, jobId);
    await other.record(second, harness.execute(second, seconds(clock)));
    // The stalled Worker wakes up, sends its journaled row, and records the (replayed) answer.
    await c.record(stalled, harness.execute(stalled, seconds(clock)));
    expect((await journalRows(jobId)).map((r) => [r["seq"], r["outcome_kind"]])).toEqual([[1, "operation"], [2, "operation"]]);
    expect((await c.reconcileJob(jobId)).resolution).toMatchObject({ status: "resolved", state: "completed" });
    // Recording against a lease that was taken over never released the new holder's lease.
  });

  it("an expired lease can be reclaimed; the recovered row stays uncertain (not evidence of non-delivery)", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    await claim(c, jobId);
    clock.advance(30);
    await c.recoverLeases();
    const next = await claim(c, jobId);
    expect(next.seq).toBe(2);
    await c.record(next, refused("QUOTA_EXCEEDED")); // inside row 1's horizon: proves nothing about row 1
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "unresolved" });
  });
});

describe("conservative resolution and retry budget", () => {
  it("exhausting the retry budget raises attention and slows down, but never fails the job", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    const delays: number[] = [];
    for (let i = 0; i < 11; i += 1) {
      const t = await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: true });
      if (!t) throw new Error(`automatic claim ${i} refused`);
      await c.record(t, uncertain());
      await c.reconcileJob(jobId);
      const due = Number((await jobRow(jobId))?.["next_attempt_at"]);
      delays.push(due - clock.ms);
      expect(await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: true })).toBeNull(); // not due yet
      clock.ms = due;
    }
    // R4 backoff: 10 s, 30 s, 2 min, then every 15 min.
    expect(delays).toEqual([10_000, 30_000, 120_000, ...Array.from({ length: 8 }, () => 900_000)]);
    const job = await jobRow(jobId);
    expect(job).toMatchObject({ status: "sending", error_code: null, needs_attention: 1, attention_code: "RETRY_BUDGET_EXHAUSTED", attempt_count: 10 });
    // It is still delivered at the slow cadence, and a late answer still resolves it and clears the flag.
    const t = await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: true });
    await c.record(t as SendableTransmission, completed());
    await c.reconcileJob(jobId);
    expect(await jobRow(jobId)).toMatchObject({ status: "completed", needs_attention: 0, attention_code: null });
  });

  it("fails only when a merits refusal at or after every open row's horizon rules it out (R3)", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, profile } = await openCreate(c);
    const harness = new FakeHarness();
    harness.quotaOpen = false;
    const first = await claim(c, jobId);
    harness.admitAndWait(first, seconds(clock)); // waits for the lock; answer lost
    await c.record(first, uncertain());
    clock.advance(119); // one second short of the horizon
    const early = await claim(c, jobId);
    await c.record(early, harness.execute(early, seconds(clock)));
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "unresolved" });
    clock.advance(1); // exactly expiresAt + 60
    const late = await claim(c, jobId);
    await c.record(late, harness.execute(late, seconds(clock)));
    harness.drain(seconds(clock)); // the waiting copy is fenced out
    expect(harness.operation).toBeNull();
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "failed", code: "QUOTA_EXCEEDED" });
    expect(await jobRow(jobId)).toMatchObject({ status: "failed", error_code: "QUOTA_EXCEEDED" });
    expect(await profileStatus(profile.id)).toBe("failed");
    // A failed job can never journal another create.
    expect(await c.claim(jobId, manual)).toBeNull();
  });

  it("a failure conclusion is not applied if the journal moved after the authoritative read", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    const t = await claim(c, jobId);
    await c.record(t, refused("UNAUTHENTICATED")); // post-nonce, final: alone it would fail the job
    const snapshot = await c.journal.snapshot(jobId);
    if (!snapshot) throw new Error("snapshot");
    // Another Worker journals a transmission between the read and the write.
    const racing = await claim(new ProvisioningCoordinator(db(), { now: clock.now, holder: "worker:race" }), jobId);
    expect(racing.seq).toBe(2);
    const applied = await c.journal.applyPass(jobId, snapshot.version, "r".repeat(32), [{ kind: "job-status", jobId, to: "failed", from: ["sending"], errorCode: "UNAUTHENTICATED" }]);
    expect(applied).toBe(false);
    expect(await jobRow(jobId)).toMatchObject({ status: "sending" });
    // The full pass re-reads, sees the open row, and stays unresolved.
    expect((await c.reconcileJob(jobId)).resolution).toEqual({ status: "unresolved" });
  });

  it("classifies pre-nonce, nonce-stage and post-nonce refusals as r4 requires", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    for (const [code, expected] of [
      ["UNKNOWN_KEY", { status: "unresolved" }],
      ["EXPIRED", { status: "unresolved" }],
      ["WRONG_AUDIENCE", { status: "unresolved" }],
      ["NONCE_STORE_UNAVAILABLE", { status: "unresolved" }],
      ["REPLAY_DETECTED", { status: "unresolved" }],
      ["UNAUTHENTICATED", { status: "failed", code: "UNAUTHENTICATED" }],
      ["INVALID_DISPLAY_NAME", { status: "failed", code: "INVALID_DISPLAY_NAME" }],
    ] as const) {
      const { jobId } = await openCreate(c);
      const t = await claim(c, jobId);
      await c.record(t, refused(code));
      expect((await c.reconcileJob(jobId)).resolution, code).toEqual(expected);
    }
    // REPLAY_DETECTED is stored as uncertain, never as a refusal.
    const { jobId } = await openCreate(c);
    const t = await claim(c, jobId);
    await c.record(t, refused("REPLAY_DETECTED"));
    expect(await journalRows(jobId)).toMatchObject([{ outcome_kind: null, uncertain_reason: "REPLAY_DETECTED" }]);
  });

  it("PROFILE_UNAVAILABLE with an open transmission needs an operator and is never failed (R3a)", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, profile } = await openCreate(c);
    const first = await claim(c, jobId);
    await c.record(first, uncertain());
    clock.advance(120);
    const second = await claim(c, jobId);
    await c.record(second, refused("PROFILE_UNAVAILABLE"));
    const report = await c.reconcileJob(jobId);
    expect(report).toMatchObject({ resolution: { status: "attention", code: "PROFILE_UNAVAILABLE_WHILE_OPEN" }, plan: "operator-attention" });
    expect(await jobRow(jobId)).toMatchObject({ status: "sending", needs_attention: 1, attention_code: "PROFILE_UNAVAILABLE_WHILE_OPEN" });
    expect(await profileStatus(profile.id)).toBe("provisioning");
    expect(await c.claim(jobId, manual)).toBeNull(); // paused for the operator
  });

  it("a create answered with a non-terminal state is recorded as uncertain", async () => {
    const c = coordinator();
    const { jobId } = await openCreate(c);
    const t = await claim(c, jobId);
    await c.record(t, { kind: "operation", operationId: OP, state: "pending", failure: null, ownerBound: false, principalId: "p" });
    expect(await journalRows(jobId)).toMatchObject([{ outcome_kind: null, uncertain_reason: "RESPONSE_INVALID" }]);
  });
});

describe("ownership observations (§13.1)", () => {
  it("completed with ownerBound=false completes the job, keeps the profile active, and flags OWNERSHIP_LOST until a status says bound", async () => {
    const c = coordinator();
    const { jobId, profile } = await openCreate(c);
    const t = await claim(c, jobId);
    await c.record(t, completed(OP, false));
    await c.reconcileJob(jobId);
    expect(await jobRow(jobId)).toMatchObject({ status: "completed", observed_state: "completed", observed_owner_bound: 0, needs_attention: 1, attention_code: "OWNERSHIP_LOST" });
    expect(await profileStatus(profile.id)).toBe("active");
    const poll = await c.claim(jobId, { ...manual, operation: "profile.status" });
    await c.record(poll as SendableTransmission, completed(OP, true));
    await c.reconcileJob(jobId);
    expect(await jobRow(jobId)).toMatchObject({ observed_owner_bound: 1, needs_attention: 0 });
  });

  it("a completed operation whose ownership was lost is still revoked when the owner is suspended (§13.1, R6)", async () => {
    const c = coordinator();
    const { jobId, user, profile } = await openCreate(c);
    await c.record(await claim(c, jobId), completed(OP, false));
    await c.reconcileJob(jobId);
    expect(await jobRow(jobId)).toMatchObject({ attention_code: "OWNERSHIP_LOST" });
    await new OperatorService(db()).changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    await c.reconcileDue(500);
    expect(await revokeJobs(profile.id)).toMatchObject([{ status: "pending", target_operation_id: OP }]);
  });

  it("a status answer that would move the observed state backwards is an anomaly, never applied", async () => {
    const c = coordinator();
    const { jobId } = await openCreate(c);
    await c.record(await claim(c, jobId), completed());
    await c.reconcileJob(jobId);
    const poll = await c.claim(jobId, { ...manual, operation: "profile.status" });
    await c.record(poll as SendableTransmission, { kind: "operation", operationId: OP, state: "pending", failure: null, ownerBound: true, principalId: "ext-test-principal" });
    await c.reconcileJob(jobId);
    expect(await jobRow(jobId)).toMatchObject({ observed_state: "completed", attention_code: "STATE_REGRESSION" });
  });
});

describe("user suspension (R6)", () => {
  it("suspension revokes every profile's Web access in the same transaction, and reactivation never restores it", async () => {
    const user = await activeUser();
    const harness = await activeHarness();
    const owned = profiles().forUser(user.id);
    const a = await owned.create({ agentName: "a" });
    const b = await owned.create({ agentName: "b" });
    await profiles().transitionTrusted(b.id, "provisioning", { harnessId: harness.id });
    await profiles().transitionTrusted(b.id, "active");
    const service = new OperatorService(db());
    const result = await service.changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    expect(result).toMatchObject({ to: "suspended", profilesRevoked: 2 });
    expect([await profileStatus(a.id), await profileStatus(b.id)]).toEqual(["revoked", "revoked"]);
    const events = await db().prepare(`SELECT action FROM audit_events WHERE request_id = ?1 ORDER BY action`).bind(result.operationId).all<{ action: string }>();
    expect(events.results.map((e) => e.action)).toEqual(["admin.user.profiles.revoke", "admin.user.suspend"]);
    await service.changeStatus(OPERATOR, "reactivate", { userId: user.id, reason: REASON });
    expect([await profileStatus(a.id), await profileStatus(b.id)]).toEqual(["revoked", "revoked"]);
    await expect(profiles().transitionTrusted(b.id, "active")).rejects.toThrow();
  });

  it("a pending create that was never sent is cancelled (nothing journaled, nothing can exist)", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, user, profile } = await openCreate(c);
    await new OperatorService(db()).changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    const report = await c.reconcileJob(jobId);
    expect(report).toMatchObject({ plan: "none", applied: true });
    expect(await jobRow(jobId)).toMatchObject({ status: "cancelled" });
    expect(await profileStatus(profile.id)).toBe("revoked");
    expect(await c.claim(jobId, manual)).toBeNull();
  });

  it("a create in flight during suspension keeps being resent to learn its operation id, then is revoked", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, user, profile } = await openCreate(c);
    const harness = new FakeHarness();
    const first = await claim(c, jobId);
    harness.admitAndWait(first, seconds(clock));
    await c.record(first, uncertain());
    await new OperatorService(db()).changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    // Unknown operation id: R4 keeps resending the SAME create; no revoke can be fixed yet.
    expect(await c.reconcileJob(jobId)).toMatchObject({ resolution: { status: "unresolved" }, plan: "send-create" });
    expect(await revokeJobs(profile.id)).toEqual([]);
    harness.drain(seconds(clock)); // the first copy completes late
    clock.advance(10);
    const { report } = await c.deliverOnce(jobId, new JournalCheckingTransport((t) => harness.execute(t, seconds(clock))), manual);
    expect(report).toMatchObject({ resolution: { status: "resolved", state: "completed" }, plan: "revoke" });
    // The late completion never gives the suspended user access.
    expect(await profileStatus(profile.id)).toBe("revoked");
    expect(await jobRow(jobId)).toMatchObject({ status: "completed", operation_id: harness.operation?.id });
    // A revoke job with a fixed command for the learned operation id exists; it is not delivered in W1.
    const [revoke] = await revokeJobs(profile.id);
    expect(revoke).toMatchObject({ status: "pending", target_operation_id: harness.operation?.id });
  });

  it("a create that completed before suspension gets a revoke job from the level-triggered sweep", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, user, profile } = await openCreate(c);
    await c.record(await claim(c, jobId), completed());
    await c.reconcileJob(jobId);
    expect(await profileStatus(profile.id)).toBe("active");
    await new OperatorService(db()).changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    expect(await profileStatus(profile.id)).toBe("revoked"); // requested revocation (Web access withdrawn)...
    expect(await revokeJobs(profile.id)).toEqual([]); // ...not observed revocation
    const reports = await c.reconcileDue(500);
    expect(reports.find((r) => r.jobId === jobId)).toMatchObject({ plan: "revoke" });
    expect(await revokeJobs(profile.id)).toMatchObject([{ status: "pending", target_operation_id: OP }]);
    // Idempotent: another sweep does not open a second revoke.
    await c.reconcileDue(500);
    expect(await revokeJobs(profile.id)).toHaveLength(1);
  });

  it("a revoke job's outcomes follow R5 and update the create's observation", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, user, profile } = await openCreate(c);
    await c.record(await claim(c, jobId), completed());
    await c.reconcileJob(jobId);
    await new OperatorService(db()).changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    await c.reconcileJob(jobId);
    const [revoke] = await revokeJobs(profile.id);
    if (!revoke) throw new Error("revoke job");
    const r1 = await claim(c, revoke.id);
    await c.record(r1, uncertain());
    expect(await c.reconcileJob(revoke.id)).toMatchObject({ resolution: { status: "unresolved" }, plan: "revoke" });
    clock.advance(10);
    const r2 = await claim(c, revoke.id);
    await c.record(r2, { kind: "operation", operationId: OP, state: "revoked", failure: null, ownerBound: false, principalId: "ext-test-principal" });
    await c.reconcileJob(revoke.id);
    expect(await jobRow(revoke.id)).toMatchObject({ status: "completed" });
    expect(await jobRow(jobId)).toMatchObject({ observed_state: "revoked", observed_owner_bound: 0 }); // observed revocation
  });

  it("OWNERSHIP_CHANGED fails the revoke with attention; UNKNOWN_OPERATION is never treated as revoked", async () => {
    for (const [code, expected] of [
      ["OWNERSHIP_CHANGED", { status: "failed", error_code: "OWNERSHIP_CHANGED", attention_code: "OWNERSHIP_CHANGED" }],
      ["UNKNOWN_OPERATION", { status: "sending", attention_code: "UNKNOWN_OPERATION" }],
    ] as const) {
      const c = coordinator();
      const { jobId, user, profile } = await openCreate(c);
      await c.record(await claim(c, jobId), completed());
      await c.reconcileJob(jobId);
      await new OperatorService(db()).changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
      await c.reconcileJob(jobId);
      const [revoke] = await revokeJobs(profile.id);
      await c.record(await claim(c, revoke?.id ?? ""), refused(code));
      await c.reconcileJob(revoke?.id ?? "");
      expect(await jobRow(revoke?.id ?? ""), code).toMatchObject({ ...expected, needs_attention: 1 });
      expect((await jobRow(jobId))?.["observed_state"], code).toBe("completed");
    }
  });
});

describe("harness retirement and ledger continuity (§10.6)", () => {
  it("LEDGER_CONTINUITY_FAILED circuit-breaks the harness, pauses the job for an operator, and is never failure", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, harness, profile } = await openCreate(c);
    // A second job on the same harness.
    const other = await activeUser();
    const otherProfile = await profiles().forUser(other.id).create({ agentName: "other" });
    const { jobId: otherJob } = await c.openCreateJob({ userId: other.id, agentProfileId: otherProfile.id, harnessId: harness.id, requestId: randomId("req"), issuer: TEST_ISSUER });

    const first = await claim(c, jobId);
    await c.record(first, uncertain());
    clock.advance(120);
    await c.record(await claim(c, jobId), refused("LEDGER_CONTINUITY_FAILED"));
    const report = await c.reconcileJob(jobId);
    expect(report).toMatchObject({ resolution: { status: "attention", code: "LEDGER_CONTINUITY_FAILED" }, plan: "operator-attention" });
    expect(await jobRow(jobId)).toMatchObject({ status: "sending", needs_attention: 1, attention_code: "LEDGER_CONTINUITY_FAILED" });
    expect(await profileStatus(profile.id)).toBe("provisioning");
    expect((await harnesses().getById(harness.id))?.status).toBe("active");
    expect(await db().prepare(`SELECT provisioning_hold FROM harnesses WHERE id = ?1`).bind(harness.id).first()).toEqual({ provisioning_hold: "LEDGER_CONTINUITY_FAILED" });

    // No ordinary delivery reaches that harness any more, for any job.
    expect(await c.claim(otherJob, manual)).toBeNull();
    expect(await c.reconcileJob(otherJob)).toMatchObject({ plan: "operator-attention", attention: "HARNESS_HOLD" });

    // The operator lifts the hold once continuity is shown; the other job resumes, the affected one stays in attention (R3a).
    const service = new OperatorService(db());
    const attention = await service.provisioningAttention(OPERATOR, { harnessId: harness.id });
    expect(attention.jobs.map((j) => j["id"]).sort()).toEqual([jobId, otherJob].sort());
    await service.releaseHarnessHold(OPERATOR, { harnessId: harness.id, reason: REASON });
    await c.reconcileJob(otherJob);
    expect(await jobRow(otherJob)).toMatchObject({ needs_attention: 0 });
    expect(await c.claim(otherJob, manual)).not.toBeNull();
    expect(await c.claim(jobId, manual)).toBeNull();
  });

  it("retiring a harness stops all delivery, leaves unresolved creates unresolved, and the id is never reused", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId, harness, profile } = await openCreate(c);
    await c.record(await claim(c, jobId), uncertain());
    const service = new OperatorService(db());
    await expect(service.retireHarness(OPERATOR, { harnessId: harness.id, reasonCode: "LEDGER_LOST", reason: REASON, confirm: false })).rejects.toMatchObject({ code: "CONFIRMATION_REQUIRED" });
    const retired = await service.retireHarness(OPERATOR, { harnessId: harness.id, reasonCode: "LEDGER_LOST", reason: REASON, confirm: true });
    expect(retired).toMatchObject({ harnessId: harness.id, unresolvedJobs: 1 });
    await expect(service.retireHarness(OPERATOR, { harnessId: harness.id, reasonCode: "LEDGER_LOST", reason: REASON, confirm: true })).rejects.toMatchObject({ code: "CONFLICT" });

    clock.advance(31);
    expect(await c.claim(jobId, manual)).toBeNull();
    const report = await c.reconcileJob(jobId);
    expect(report).toMatchObject({ resolution: { status: "unresolved" }, plan: "operator-attention", attention: "HARNESS_RETIRED" });
    expect(await jobRow(jobId)).toMatchObject({ status: "sending", needs_attention: 1, attention_code: "HARNESS_RETIRED" });
    expect(await profileStatus(profile.id)).toBe("provisioning");
    // New work cannot be placed on a retired id, and nothing is moved to a replacement automatically.
    const user = await activeUser();
    const fresh = await profiles().forUser(user.id).create({ agentName: "new" });
    await expect(c.openCreateJob({ userId: user.id, agentProfileId: fresh.id, harnessId: harness.id, requestId: randomId("req"), issuer: TEST_ISSUER })).rejects.toBeTruthy();
    const replacement = await harnesses().registerAdmin({ name: `r ${randomId("h")}`, environment: "development", endpoint: harness.endpoint, keyId: TEST_KEY_ID, capabilities: { protocolVersions: [1], operations: [] } });
    await expect(harnesses().setStatusAdmin(replacement.id, "active")).rejects.toMatchObject({ reason: "replacement_not_approved" });
    await expect(service.approveHarnessReplacement(OPERATOR, { retiredHarnessId: harness.id, replacementHarnessId: replacement.id, reason: REASON, confirm: true })).resolves.toMatchObject({ replacementHarnessId: replacement.id });
    await harnesses().setStatusAdmin(replacement.id, "active");
    expect(await db().prepare(`SELECT COUNT(*) AS n FROM provisioning_jobs WHERE harness_id = ?1`).bind(replacement.id).first()).toEqual({ n: 0 });
    expect((await profiles().getByIdTrusted(profile.id))?.harnessId).toBe(harness.id);
  });

  it("a completed create on a retired harness with desired absent needs an operator (no revoke is fixed)", async () => {
    const c = coordinator();
    const { jobId, harness, user, profile } = await openCreate(c);
    await c.record(await claim(c, jobId), completed());
    await c.reconcileJob(jobId);
    const service = new OperatorService(db());
    await service.retireHarness(OPERATOR, { harnessId: harness.id, reasonCode: "DECOMMISSIONED", reason: REASON, confirm: true });
    await service.changeStatus(OPERATOR, "suspend", { userId: user.id, reason: REASON });
    expect(await c.reconcileJob(jobId)).toMatchObject({ plan: "operator-attention", attention: "HARNESS_RETIRED" });
    expect(await revokeJobs(profile.id)).toEqual([]);
  });
});

describe("isolation", () => {
  it("cross-harness substitution: a transmission is always journaled for the command's own harness and profile", async () => {
    const c = coordinator();
    const { jobId, harness, profile } = await openCreate(c);
    const t = await claim(c, jobId);
    expect([t.harnessId, t.profileId]).toEqual([harness.id, profile.id]);
    const rows = await db().prepare(`SELECT harness_id, agent_profile_id FROM provisioning_transmissions WHERE job_id = ?1`).bind(jobId).all();
    expect(rows.results).toEqual([{ harness_id: harness.id, agent_profile_id: profile.id }]);
  });

  it("cross-user: jobs of one user are invisible to another through owner-scoped lookups", async () => {
    const c = coordinator();
    const a = await openCreate(c);
    const b = await activeUser();
    const { ProvisioningJobRepository } = await import("../../src/worker/db/provisioning-jobs");
    expect(await new ProvisioningJobRepository(db()).getForUser(a.jobId, b.id)).toBeNull();
    expect(await new ProvisioningJobRepository(db()).getForUser(a.jobId, a.user.id)).toMatchObject({ id: a.jobId });
  });
});

describe("authoritative reads (§13.10 r4)", () => {
  it("reconciliation reads only through a first-primary session, never an unconstrained replica read", async () => {
    const clock = new TestClock();
    const c = coordinator(clock);
    const { jobId } = await openCreate(c);
    await c.record(await claim(c, jobId), refused("UNAUTHENTICATED"));
    const constraints: string[] = [];
    // A database whose unconstrained reads of the journal fail: only session reads work.
    const guarded = new Proxy(db(), {
      get(target, key) {
        if (key === "withSession")
          return (constraint: string) => {
            constraints.push(constraint);
            return target.withSession(constraint as D1SessionConstraint);
          };
        if (key === "prepare")
          return (sql: string) => {
            if (/^\s*SELECT\b/i.test(sql) && /provisioning_transmission/.test(sql)) throw new Error("unconstrained journal read");
            return target.prepare(sql);
          };
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const authoritative = new ProvisioningCoordinator(guarded as D1Database, { now: clock.now });
    const report = await authoritative.reconcileJob(jobId);
    expect(report).toMatchObject({ resolution: { status: "failed", code: "UNAUTHENTICATED" }, applied: true });
    expect(constraints).toContain("first-primary");
    expect(constraints.every((k) => k === "first-primary")).toBe(true);
  });
});

describe("legacy jobs", () => {
  it("a job without a fixed command can never be sent and is flagged for an operator", async () => {
    const user = await activeUser();
    const harness = await activeHarness();
    const profile = await profiles().forUser(user.id).create({ agentName: "legacy" });
    const { ProvisioningJobRepository } = await import("../../src/worker/db/provisioning-jobs");
    const { job } = await new ProvisioningJobRepository(db()).createOrGet({
      userId: user.id,
      agentProfileId: profile.id,
      harnessId: harness.id,
      operation: "profile.create",
      requestId: randomId("req"),
      idempotencyKey: randomId("idk"),
      requestHash: "a".repeat(64),
    });
    const c = coordinator();
    expect(await c.claim(job.id, manual)).toBeNull();
    expect(await c.reconcileJob(job.id)).toMatchObject({ resolution: { status: "legacy" }, attention: "LEGACY_JOB_WITHOUT_COMMAND" });
    expect(await jobRow(job.id)).toMatchObject({ status: "pending", needs_attention: 1, attention_code: "LEGACY_JOB_WITHOUT_COMMAND" });
    expect(users).toBeDefined();
  });
});
