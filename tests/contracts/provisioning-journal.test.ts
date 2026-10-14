/**
 * RC6 (PROVISIONING_PROTOCOL §13.10): a transmission is durably journaled in
 * D1 before it can be sent, and Web's create resolution reads only the
 * journal. Runs on real D1 in workerd with the test-only reference tables of
 * journal.ts (this file's isolated storage; dropped afterwards).
 *
 * Assumptions: the fake harness follows PR #26 semantics for one key
 * (idempotency hit returns the recorded operation; otherwise quota decides);
 * clocks agree; signatures are not modelled (protocol-layer tests cover them).
 * Crash points are modelled by stopping the Worker's step sequence.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ProvisioningJobRepository } from "../../src/worker/db/provisioning-jobs";
import { randomId } from "../../src/worker/utils/random";
import { db, newHarness, newUser, profiles } from "../helpers/db";
import { type JournaledTransmission, ReferenceJournal } from "./provisioning/journal";
import { ACCEPTANCE_HORIZON_SECONDS, planReconciliation, resolveCreateJob } from "./provisioning/reference";

const journal = new ReferenceJournal(db());
const T0 = 1_791_000_000;
const LEASE = 30;
const OP = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

beforeAll(async () => {
  await journal.install();
});
afterAll(async () => {
  await journal.uninstall();
});

/** PR #26 semantics for one idempotency key, plus a delayed-execution queue. */
class FakeHarness {
  operation: "completed" | null = null;
  quotaOpen = true;
  received: string[] = [];
  private readonly queued: string[] = [];

  /** The command executes now and answers. */
  execute(commandId: string): { kind: "operation"; operationId: string; state: string } | { kind: "refused"; code: string } {
    this.received.push(commandId);
    if (this.operation) return { kind: "operation", operationId: OP, state: this.operation };
    if (!this.quotaOpen) return { kind: "refused", code: "QUOTA_EXCEEDED" };
    this.operation = "completed";
    return { kind: "operation", operationId: OP, state: "completed" };
  }

  /** The command was admitted and waits for the ledger lock; its answer will never reach Web. */
  enqueue(commandId: string): void {
    this.received.push(commandId);
    this.queued.push(commandId);
  }

  drainQueue(): void {
    while (this.queued.shift() !== undefined) {
      if (!this.operation && this.quotaOpen) this.operation = "completed";
    }
  }
}

async function newJob(desired: "present" | "absent" = "present"): Promise<string> {
  const user = await newUser();
  const harness = await newHarness();
  const profile = await profiles().forUser(user.id).create({ agentName: "Research assistant" });
  const payload = JSON.stringify({ displayName: "Research assistant", idempotencyKey: randomId("idk"), profileId: profile.id, template: "assistant" });
  const { job } = await new ProvisioningJobRepository(db()).createOrGet({
    userId: user.id,
    agentProfileId: profile.id,
    harnessId: harness.id,
    operation: "profile.create",
    requestId: randomId("req"),
    idempotencyKey: randomId("idk"),
    requestHash: "a".repeat(64),
  });
  await journal.open(job.id, payload, desired);
  return job.id;
}

const send = (jobId: string, now: number) => journal.journal(jobId, { now, leaseSeconds: LEASE, harnessId: "hns_fixtureharnessalpha0000001", keyId: "web-test-active" });
const resolution = async (jobId: string) => resolveCreateJob(await journal.transmissions(jobId));
const journaledOrThrow = (t: JournaledTransmission | null): JournaledTransmission => {
  if (!t) throw new Error("expected to win the delivery lease");
  return t;
};

describe("RC6 write-before-send journal (§13.10)", () => {
  it("crash before journaling: nothing can have been sent", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    // The Worker built the command in memory and died before the journal batch committed.
    expect(await journal.transmissions(job)).toEqual([]);
    expect(harness.received).toEqual([]);
    expect(await resolution(job)).toEqual({ status: "unresolved" });
    expect(planReconciliation(await resolution(job), "present")).toBe("send-create");
  });

  it("crash after the journal commit, before send: potentially sent, never refused", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    journaledOrThrow(await send(job, T0));
    // Worker dies. The lease expires and recovery marks the row uncertain.
    expect(await journal.recoverExpiredLeases(T0 + LEASE)).toBe(1);
    expect((await journal.rows(job)).map((r) => r.state)).toEqual(["uncertain"]);
    harness.quotaOpen = false;
    const retry = journaledOrThrow(await send(job, T0 + 40));
    await journal.recordAnswer(retry, harness.execute(retry.commandId));
    // A merits refusal inside the first row's horizon proves nothing about it.
    expect(await resolution(job)).toEqual({ status: "unresolved" });
    const late = journaledOrThrow(await send(job, T0 + 60 + ACCEPTANCE_HORIZON_SECONDS));
    await journal.recordAnswer(late, harness.execute(late.commandId));
    expect(await resolution(job)).toEqual({ status: "failed", code: "QUOTA_EXCEEDED" });
    expect(harness.operation).toBeNull();
  });

  it("crash during send (request never reached the harness): retry creates it", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    journaledOrThrow(await send(job, T0));
    await journal.recoverExpiredLeases(T0 + LEASE);
    const retry = journaledOrThrow(await send(job, T0 + 31));
    await journal.recordAnswer(retry, harness.execute(retry.commandId));
    expect(await resolution(job)).toEqual({ status: "resolved", operationId: OP, state: "completed" });
  });

  it("crash after send, before the answer is persisted: the journal keeps it uncertain", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    const first = journaledOrThrow(await send(job, T0));
    harness.execute(first.commandId); // executed; the answer died with the Worker
    await journal.recoverExpiredLeases(T0 + LEASE);
    harness.quotaOpen = false; // a new create would now be refused, but the key has an operation
    const retry = journaledOrThrow(await send(job, T0 + 31));
    await journal.recordAnswer(retry, harness.execute(retry.commandId));
    expect(await resolution(job)).toEqual({ status: "resolved", operationId: OP, state: "completed" });
  });

  it("a lost refusal answer is uncertain, not failed", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    harness.quotaOpen = false;
    const first = journaledOrThrow(await send(job, T0));
    harness.execute(first.commandId); // QUOTA_EXCEEDED, answer lost
    await journal.markUncertain(first);
    expect(await resolution(job)).toEqual({ status: "unresolved" });
  });

  it("concurrent Workers: exactly one journals and may send", async () => {
    const job = await newJob();
    const attempts = await Promise.all(Array.from({ length: 8 }, () => send(job, T0)));
    expect(attempts.filter((a) => a !== null)).toHaveLength(1);
    expect(await journal.rows(job)).toHaveLength(1);
  });

  it("a stalled Worker past its lease and a new Worker both journal: both are uncertain until answered", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    const stalled = journaledOrThrow(await send(job, T0));
    expect(await send(job, T0 + 5)).toBeNull(); // lease still held
    const second = journaledOrThrow(await send(job, T0 + LEASE)); // lease expired, no recovery yet
    await journal.recordAnswer(second, harness.execute(second.commandId));
    // The stalled Worker's send arrives later; same key, so the same operation.
    await journal.recordAnswer(stalled, harness.execute(stalled.commandId));
    expect((await journal.rows(job)).map((r) => r.seq)).toEqual([1, 2]);
    expect(await resolution(job)).toEqual({ status: "resolved", operationId: OP, state: "completed" });
  });

  it("retries keep one logical identity; the journal refuses another payload", async () => {
    const job = await newJob();
    const a = journaledOrThrow(await send(job, T0));
    await journal.markUncertain(a);
    const b = journaledOrThrow(await send(job, T0 + 1));
    const rows = await journal.rows(job);
    expect(new Set(rows.map((r) => r.payload_hash)).size).toBe(1);
    expect(new Set(rows.map((r) => r.command_id)).size).toBe(2);
    await journal.markUncertain(b);
    await expect(
      journal.journal(job, { now: T0 + 2, leaseSeconds: LEASE, harnessId: "hns_x0000000000", keyId: "k-1", payloadHash: "b".repeat(64) }),
    ).rejects.toThrow(/payload_mismatch/);
    // The failed batch rolled back its lease claim too.
    expect(journaledOrThrow(await send(job, T0 + 3)).seq).toBe(3);
  });

  it("the journal is append-only and recorded answers are final", async () => {
    const job = await newJob();
    const t = journaledOrThrow(await send(job, T0));
    await journal.recordAnswer(t, { kind: "refused", code: "QUOTA_EXCEEDED" });
    expect(await journal.recordAnswer(t, { kind: "operation", operationId: OP, state: "completed" })).toBe(false);
    await expect(db().prepare(`UPDATE l0_ref_transmissions SET state = 'uncertain' WHERE command_id = ?1`).bind(t.commandId).run()).rejects.toThrow(
      /journal_immutable/,
    );
    await expect(db().prepare(`DELETE FROM l0_ref_transmissions WHERE command_id = ?1`).bind(t.commandId).run()).rejects.toThrow(
      /journal_append_only/,
    );
  });

  it("suspension while a create is uncertain: resend the same create, then revoke", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    const first = journaledOrThrow(await send(job, T0));
    harness.enqueue(first.commandId);
    await journal.markUncertain(first);
    await journal.setDesired(job, "absent"); // the user is suspended
    expect(planReconciliation(await resolution(job), "absent")).toBe("send-create");
    harness.drainQueue();
    const retry = journaledOrThrow(await send(job, T0 + 31));
    await journal.recordAnswer(retry, harness.execute(retry.commandId));
    const resolved = await resolution(job);
    expect(resolved).toEqual({ status: "resolved", operationId: OP, state: "completed" });
    expect(planReconciliation(resolved, "absent")).toBe("revoke");
  });

  it("late completion after the Worker restarts never meets a failed job", async () => {
    const job = await newJob();
    const harness = new FakeHarness();
    harness.quotaOpen = false;
    const first = journaledOrThrow(await send(job, T0));
    harness.enqueue(first.commandId); // waits for the ledger lock
    await journal.recoverExpiredLeases(T0 + LEASE); // the Worker restarted
    const quick = journaledOrThrow(await send(job, T0 + 40));
    await journal.recordAnswer(quick, harness.execute(quick.commandId)); // QUOTA_EXCEEDED inside the horizon
    expect(await resolution(job)).toEqual({ status: "unresolved" });
    harness.quotaOpen = true;
    harness.drainQueue(); // the first copy completes late
    const next = journaledOrThrow(await send(job, T0 + 200));
    await journal.recordAnswer(next, harness.execute(next.commandId));
    expect(await resolution(job)).toEqual({ status: "resolved", operationId: OP, state: "completed" });
  });

  it("classifies failure safely", async () => {
    const refusedOnly = await newJob();
    for (const [i, code] of (["UNAUTHENTICATED", "QUOTA_EXCEEDED"] as const).entries()) {
      const t = journaledOrThrow(await send(refusedOnly, T0 + i * 10));
      await journal.recordAnswer(t, { kind: "refused", code });
    }
    expect(await resolution(refusedOnly)).toEqual({ status: "failed", code: "QUOTA_EXCEEDED" });

    const protocolOnly = await newJob();
    const p = journaledOrThrow(await send(protocolOnly, T0));
    await journal.recordAnswer(p, { kind: "refused", code: "UNKNOWN_KEY" });
    expect(await resolution(protocolOnly)).toEqual({ status: "unresolved" });

    const exhausted = await newJob();
    for (let i = 0; i < 12; i += 1) {
      const t = journaledOrThrow(await send(exhausted, T0 + i * 100));
      await journal.markUncertain(t);
    }
    expect(await resolution(exhausted)).toEqual({ status: "unresolved" });
  });
});
