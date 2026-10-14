/**
 * Seeded crash/retry schedules on real D1 (workerd). Each schedule drives one
 * create job through random Worker crashes (before send, after send, before
 * the answer is written), lost and delayed copies, lock waits, lease expiry
 * and recovery, quota changes and reconciliation passes, against the
 * FakeHarness (PR #26 semantics with the r3 fence and durable nonces).
 *
 * Checked after every schedule:
 *   S  Web concluded `failed` ⇒ the harness recorded no operation, even after
 *      every delayed copy has executed (§13.2.1)
 *   J  every send was journaled first, and the journal holds every claim
 *   R1 a resolved job names the harness's one operation
 * Deterministic: the seed fixes every choice, so a failure replays exactly.
 */
import { describe, expect, it } from "vitest";
import type { SendableTransmission } from "../../src/worker/provisioning/coordinator";
import { coordinator, FakeHarness, jobRow, JournalCheckingTransport, journalRows, openCreate, TEST_KEY_ID, TestClock, uncertain } from "../helpers/provisioning";

const SEED = 0x57a1_0001;
const SCHEDULES = 80;

/** mulberry32: small, deterministic PRNG for test schedules. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("seeded crash/retry schedules", () => {
  it(`${SCHEDULES} schedules (seed ${SEED.toString(16)}): never failed while an operation exists; every send journaled first`, { timeout: 180_000 }, async () => {
    const random = prng(SEED);
    const pick = <T,>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
    const totals = { failed: 0, resolved: 0, unresolved: 0, sends: 0, claims: 0 };

    for (let schedule = 0; schedule < SCHEDULES; schedule += 1) {
      const clock = new TestClock();
      const c = coordinator(clock);
      const { jobId } = await openCreate(c);
      const harness = new FakeHarness();
      harness.quotaOpen = random() < 0.5;
      const now = () => Math.floor(clock.ms / 1000);
      const transport = new JournalCheckingTransport((t) => harness.execute(t, now()));
      const claims: SendableTransmission[] = [];

      for (let step = 0; step < 14; step += 1) {
        const action = pick(["send", "send", "send", "crash-before-send", "crash-after-send", "delayed", "lost-answer", "advance", "advance", "recover", "reconcile", "drain", "quota"] as const);
        if (action === "advance") clock.advance(pick([1, 10, 30, 59, 60, 61, 119, 120, 121, 200]));
        else if (action === "recover") await c.recoverLeases();
        else if (action === "reconcile") await c.reconcileJob(jobId);
        else if (action === "drain") harness.drain(now());
        else if (action === "quota") harness.quotaOpen = !harness.quotaOpen;
        else {
          const t = await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: false });
          if (!t) continue;
          claims.push(t);
          if (action === "send") {
            const outcome = await transport.send(t);
            await c.record(t, outcome);
          } else if (action === "crash-after-send") {
            await transport.send(t); // executed; the answer died with the Worker
          } else if (action === "delayed") {
            harness.admitAndWait(t, now()); // admitted, waits for the ledger lock
            await c.record(t, uncertain("TIMEOUT"));
          } else if (action === "lost-answer") {
            await transport.send(t);
            await c.record(t, uncertain("NETWORK_ERROR"));
          }
          // crash-before-send: journaled, never sent, nothing recorded.
        }
      }

      // Every delayed copy eventually runs; the final pass reads everything.
      clock.advance(60);
      harness.drain(now());
      clock.advance(31);
      await c.recoverLeases();
      const report = await c.reconcileJob(jobId);
      const job = await jobRow(jobId);
      const rows = await journalRows(jobId);

      const context = `schedule ${schedule}`;
      expect(rows.map((r) => r["command_id"]), context).toEqual(claims.map((t) => t.commandId)); // J: the journal holds every claim
      if (job?.["status"] === "failed") {
        expect(harness.operation, `${context}: S violated`).toBeNull(); // S
        totals.failed += 1;
      } else if (report.resolution && "operationId" in report.resolution) {
        expect(report.resolution.operationId, context).toBe(harness.operation?.id); // R1
        totals.resolved += 1;
      } else {
        totals.unresolved += 1;
      }
      totals.sends += transport.sends;
      totals.claims += claims.length;
    }
    console.info(`W1 schedules (seed ${SEED.toString(16)}): ${JSON.stringify(totals)}`);
    // The schedules exercise every outcome, not just the easy one.
    expect(totals.failed).toBeGreaterThan(0);
    expect(totals.resolved).toBeGreaterThan(0);
    expect(totals.unresolved).toBeGreaterThan(0);
    expect(totals.claims).toBeGreaterThan(totals.sends);
  });
});
