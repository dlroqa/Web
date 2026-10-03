import { describe, expect, it } from "vitest";
import { IdempotencyConflictError, InvalidTransitionError, UniqueConflictError } from "../../src/worker/db/errors";
import { JOB_STATUSES, JOB_TRANSITIONS, MAX_ATTEMPTS, ProvisioningJobRepository, type NewJob } from "../../src/worker/db/provisioning-jobs";
import { NonceReplayError } from "../../src/worker/db/errors";
import { hashNonce, NonceRepository } from "../../src/worker/db/nonces";
import { randomBase64, randomId } from "../../src/worker/utils/random";
import { db, newHarness, newUser, profiles } from "../helpers/db";

const jobs = () => new ProvisioningJobRepository(db());
const hash = (c: string) => c.repeat(64);

async function newJobInput(overrides: Partial<NewJob> = {}): Promise<NewJob> {
  const user = await newUser();
  const harness = await newHarness();
  const profile = await profiles().forUser(user.id).create({ agentName: "t" });
  return {
    userId: user.id,
    agentProfileId: profile.id,
    harnessId: harness.id,
    operation: "profile.create",
    requestId: randomId("req"),
    idempotencyKey: randomId("idem"),
    requestHash: hash("a"),
    ...overrides,
  };
}

describe("provisioning job idempotency", () => {
  it("same key + same request returns the existing job, not a second one", async () => {
    const input = await newJobInput();
    const first = await jobs().createOrGet(input);
    const retry = await jobs().createOrGet({ ...input, requestId: randomId("req") });
    expect(first.created).toBe(true);
    expect(retry.created).toBe(false);
    expect(retry.job.id).toBe(first.job.id);
    const count = await db().prepare(`SELECT COUNT(*) AS n FROM provisioning_jobs WHERE idempotency_key = ?1`).bind(input.idempotencyKey).first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it("same key + different request hash is a conflict", async () => {
    const input = await newJobInput();
    await jobs().createOrGet(input);
    await expect(jobs().createOrGet({ ...input, requestHash: hash("b") })).rejects.toBeInstanceOf(IdempotencyConflictError);
  });

  it("same key reused by another user or profile is a conflict", async () => {
    const input = await newJobInput();
    await jobs().createOrGet(input);
    const other = await newJobInput({ idempotencyKey: input.idempotencyKey, requestHash: input.requestHash });
    await expect(jobs().createOrGet(other)).rejects.toBeInstanceOf(IdempotencyConflictError);
  });

  it("concurrent creates with one key produce exactly one job", async () => {
    const input = await newJobInput();
    const results = await Promise.all(Array.from({ length: 10 }, () => jobs().createOrGet(input)));
    expect(new Set(results.map((r) => r.job.id)).size).toBe(1);
    expect(results.filter((r) => r.created)).toHaveLength(1);
  });

  it("only one in-flight job per profile and operation", async () => {
    const input = await newJobInput();
    await jobs().createOrGet(input);
    await expect(jobs().createOrGet({ ...input, idempotencyKey: randomId("idem"), requestHash: hash("c") })).rejects.toBeInstanceOf(UniqueConflictError);
  });

  it("rejects malformed keys and hashes", async () => {
    const input = await newJobInput();
    await expect(jobs().createOrGet({ ...input, idempotencyKey: "short" })).rejects.toThrow();
    await expect(jobs().createOrGet({ ...input, requestHash: "XYZ" })).rejects.toThrow();
  });

  it("job lookups for users are owner-scoped", async () => {
    const input = await newJobInput();
    const { job } = await jobs().createOrGet(input);
    const stranger = await newUser();
    expect(await jobs().getForUser(job.id, stranger.id)).toBeNull();
    expect(await jobs().getForUser(job.id, input.userId)).toMatchObject({ id: job.id });
    expect(await jobs().latestForProfileOfUser(input.agentProfileId, stranger.id)).toBeNull();
  });
});

describe("provisioning job transitions", () => {
  const pairs = JOB_STATUSES.flatMap((from) => JOB_STATUSES.filter((to) => to !== from).map((to) => [from, to] as const));
  const path = {
    pending: [],
    sending: ["sending"],
    accepted: ["sending", "accepted"],
    completed: ["sending", "completed"],
    failed: ["failed"],
    cancelled: ["cancelled"],
  } as const;

  it.each(pairs)("%s → %s follows the transition table", async (from, to) => {
    const { job } = await jobs().createOrGet(await newJobInput());
    for (const step of path[from]) await jobs().transitionTrusted(job.id, step, { errorCode: "PROVISIONING_FAILED" });
    const attempt = jobs().transitionTrusted(job.id, to, { errorCode: "PROVISIONING_FAILED" });
    if (JOB_TRANSITIONS[from].includes(to)) await expect(attempt).resolves.toMatchObject({ status: to });
    else await expect(attempt).rejects.toBeInstanceOf(InvalidTransitionError);
  });

  it("counts attempts, sets completed_at on terminal states, and requires an error code to fail", async () => {
    const { job } = await jobs().createOrGet(await newJobInput());
    const sending = await jobs().transitionTrusted(job.id, "sending");
    expect(sending.attemptCount).toBe(1);
    expect(sending.completedAt).toBeNull();
    await jobs().transitionTrusted(job.id, "pending");
    expect((await jobs().transitionTrusted(job.id, "sending")).attemptCount).toBe(2);
    await expect(jobs().transitionTrusted(job.id, "failed")).rejects.toBeInstanceOf(InvalidTransitionError);
    const failed = await jobs().transitionTrusted(job.id, "failed", { errorCode: "HARNESS_UNAVAILABLE" });
    expect(failed).toMatchObject({ status: "failed", errorCode: "HARNESS_UNAVAILABLE" });
    expect(failed.completedAt).not.toBeNull();
  });

  it("stops after MAX_ATTEMPTS sends", async () => {
    const { job } = await jobs().createOrGet(await newJobInput());
    for (let i = 0; i < MAX_ATTEMPTS; i += 1) {
      await jobs().transitionTrusted(job.id, "sending");
      await jobs().transitionTrusted(job.id, "pending");
    }
    await expect(jobs().transitionTrusted(job.id, "sending")).rejects.toBeInstanceOf(InvalidTransitionError);
  });

  it("rejects free-form or oversized error codes", async () => {
    const { job } = await jobs().createOrGet(await newJobInput());
    await expect(jobs().transitionTrusted(job.id, "failed", { errorCode: "stack trace at /home/x" })).rejects.toThrow();
    await expect(jobs().transitionTrusted(job.id, "failed", { errorCode: "A".repeat(65) })).rejects.toThrow();
  });

  it("command identity columns are immutable", async () => {
    const { job } = await jobs().createOrGet(await newJobInput());
    await expect(db().prepare(`UPDATE provisioning_jobs SET request_hash = ?1 WHERE id = ?2`).bind(hash("f"), job.id).run()).rejects.toThrow(/immutable_column/);
  });
});

describe("nonce registry", () => {
  const nonces = () => new NonceRepository(db());

  it("records a nonce once and detects replay", async () => {
    const nonce = randomBase64(16);
    await nonces().recordOnce(nonce, Date.now() + 60_000);
    expect(await nonces().isRecorded(nonce)).toBe(true);
    await expect(nonces().recordOnce(nonce, Date.now() + 60_000)).rejects.toBeInstanceOf(NonceReplayError);
  });

  it("stores only the hash, never the nonce", async () => {
    const nonce = randomBase64(16);
    await nonces().recordOnce(nonce, Date.now() + 60_000);
    const { results } = await db().prepare(`SELECT * FROM provisioning_nonces`).all();
    expect(JSON.stringify(results)).not.toContain(nonce);
    expect(results.map((r) => r["nonce_hash"])).toContain(await hashNonce(nonce));
  });

  it("concurrent records of one nonce: exactly one succeeds", async () => {
    const nonce = randomBase64(16);
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => nonces().recordOnce(nonce, Date.now() + 60_000)));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  });

  it("refuses past or excessive expiries", async () => {
    await expect(nonces().recordOnce(randomBase64(16), Date.now() - 1)).rejects.toThrow(RangeError);
    await expect(nonces().recordOnce(randomBase64(16), Date.now() + 3_600_000)).rejects.toThrow(RangeError);
  });

  it("purges only expired records", async () => {
    let clock = Date.now();
    const repo = new NonceRepository(db(), { now: () => clock });
    const stale = randomBase64(16);
    const fresh = randomBase64(16);
    await repo.recordOnce(stale, clock + 1_000);
    await repo.recordOnce(fresh, clock + 500_000);
    clock += 2_000;
    expect(await repo.purgeExpired()).toBeGreaterThanOrEqual(1);
    expect(await repo.isRecorded(stale)).toBe(false);
    expect(await repo.isRecorded(fresh)).toBe(true);
  });
});
