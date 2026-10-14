/**
 * W1 provisioning fixtures for workerd tests. Everything is TEST-ONLY:
 * harness endpoints are unroutable `.example.test` names that nothing ever
 * contacts, and key ids are placeholders, never key material.
 */
import { env } from "cloudflare:test";
import { ProvisioningCoordinator, type ProvisioningTransport, type SendableTransmission } from "../../src/worker/provisioning/coordinator";
import type { ObservedOutcome } from "../../src/worker/provisioning/protocol";
import { randomId } from "../../src/worker/utils/random";
import { db, harnesses, profiles, users } from "./db";

/** Placeholder signing-key id (§4.4 format). There is no key behind it. */
export const TEST_KEY_ID = "w1-test-only-key";
/** Web's issuer identifier for tests (§4.5); not a configured value. */
export const TEST_ISSUER = "https://lightagent-control.example";
export const T0 = 1_791_000_000_000;

export class TestClock {
  constructor(public ms = T0) {}
  readonly now = () => this.ms;
  advance(seconds: number): void {
    this.ms += seconds * 1000;
  }
}

export async function activeUser() {
  const user = await users().create({ authUserId: randomId("auth") });
  return users().transition(user.id, "active");
}

/** A registered, active harness with its own endpoint (retirement tests compare endpoints). */
export async function activeHarness(endpoint = `https://${randomId("h").replace("_", "-")}.example.test`) {
  const harness = await harnesses().registerAdmin({
    name: `harness ${randomId("h")}`,
    environment: "development",
    endpoint,
    keyId: TEST_KEY_ID,
    capabilities: { protocolVersions: [1], operations: ["profile.create", "profile.revoke"] },
  });
  return harnesses().setStatusAdmin(harness.id, "active");
}

export function coordinator(clock = new TestClock(), database: D1Database = db()) {
  return new ProvisioningCoordinator(database, { now: clock.now });
}

/** An active user, an active harness, a pending profile, and an opened create job. */
export async function openCreate(c: ProvisioningCoordinator, options: { agentName?: string } = {}) {
  const user = await activeUser();
  const harness = await activeHarness();
  const profile = await profiles().forUser(user.id).create({ agentName: options.agentName ?? "Research assistant" });
  const { jobId, payloadHash } = await c.openCreateJob({ userId: user.id, agentProfileId: profile.id, harnessId: harness.id, requestId: randomId("req"), issuer: TEST_ISSUER });
  return { user, harness, profile, jobId, payloadHash };
}

export const OP = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
export const completed = (operationId = OP, ownerBound = true): ObservedOutcome => ({ kind: "operation", operationId, state: "completed", failure: null, ownerBound, principalId: "ext-test-principal" });
export const refused = (code: string): ObservedOutcome => ({ kind: "refused", code });
export const uncertain = (reason = "TIMEOUT"): ObservedOutcome => ({ kind: "uncertain", reason });

/**
 * A harness with PR #26 semantics for one idempotency key, plus the r3/r4
 * execution fence and durable nonces (§9.2, §10.5): what Lightagent L1–L3
 * provide. In memory only; it is a model, never a network peer.
 */
export class FakeHarness {
  operation: { id: string; state: "completed" | "revoked" } | null = null;
  quotaOpen = true;
  fence = 0;
  readonly nonces = new Set<string>();
  readonly received: SendableTransmission[] = [];
  private readonly queue: Array<{ t: SendableTransmission; copy: boolean }> = [];
  private readonly operationId = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  /** One copy of `t` reaches the harness at Web-clock second `now` and executes immediately. */
  execute(t: SendableTransmission, now: number): ObservedOutcome {
    this.received.push(t);
    if (now >= t.expiresAt + 30) return refused("EXPIRED"); // step 12, pre-nonce
    if (this.nonces.has(t.nonce)) return { kind: "refused", code: "REPLAY_DETECTED" };
    this.nonces.add(t.nonce);
    return this.underLock(t, now);
  }

  /** Admitted at step 12 now, but waits for the ledger lock; its answer is lost. */
  admitAndWait(t: SendableTransmission, now: number): void {
    this.received.push(t);
    if (now >= t.expiresAt + 30 || this.nonces.has(t.nonce)) return;
    this.nonces.add(t.nonce);
    this.queue.push({ t, copy: false });
  }

  /** Queued copies acquire the lock, in order, at second `now`. */
  drain(now: number): void {
    for (let item = this.queue.shift(); item; item = this.queue.shift()) this.underLock(item.t, now);
  }

  get waiting(): number {
    return this.queue.length;
  }

  private underLock(t: SendableTransmission, now: number): ObservedOutcome {
    if (t.operation !== "profile.create") throw new Error("model covers creates only");
    // Step 14: execution deadline on the clock and on the durable fence.
    if (now >= t.expiresAt + 30 || t.expiresAt + 30 <= this.fence) return refused("EXPIRED");
    // Step 15 then fence advance, durable before unlock.
    this.fence = Math.max(this.fence, t.issuedAt - 30);
    if (this.operation) return completed(this.operation.id);
    if (!this.quotaOpen) return refused("QUOTA_EXCEEDED");
    this.operation = { id: this.operationId, state: "completed" };
    return completed(this.operation.id);
  }
}

/** A transport over a FakeHarness that checks write-before-send on every call. */
export class JournalCheckingTransport implements ProvisioningTransport {
  sends = 0;
  constructor(
    private readonly respond: (t: SendableTransmission) => ObservedOutcome | Promise<ObservedOutcome>,
    private readonly database: D1Database = db(),
  ) {}

  async send(t: SendableTransmission): Promise<ObservedOutcome> {
    const row = await this.database.prepare(`SELECT command_id FROM provisioning_transmissions WHERE command_id = ?1`).bind(t.commandId).first();
    if (!row) throw new Error(`RC6 violated: ${t.commandId} sent before it was journaled`);
    this.sends += 1;
    return this.respond(t);
  }
}

export async function jobRow(jobId: string, database: D1Database = db()) {
  return database.prepare(`SELECT * FROM provisioning_jobs WHERE id = ?1`).bind(jobId).first<Record<string, unknown>>();
}

export async function journalRows(jobId: string, database: D1Database = db()) {
  const { results } = await database
    .prepare(
      `SELECT t.command_id, t.seq, t.operation, t.payload_hash, t.nonce_hash, t.issued_at, t.expires_at,
              a.outcome_kind, a.refusal_code, a.operation_state, u.uncertain_reason
         FROM provisioning_transmissions t
         LEFT JOIN provisioning_transmission_outcomes a ON a.command_id = t.command_id AND a.disposition = 'answered'
         LEFT JOIN provisioning_transmission_outcomes u ON u.command_id = t.command_id AND u.disposition = 'uncertain'
        WHERE t.job_id = ?1 ORDER BY t.seq`,
    )
    .bind(jobId)
    .all<Record<string, unknown>>();
  return results;
}

export async function profileStatus(profileId: string): Promise<string | undefined> {
  return (await profiles().getByIdTrusted(profileId))?.status;
}

export const legacyDb = (): D1Database => Reflect.get(env, "LEGACY_DB") as D1Database;
