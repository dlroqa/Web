/**
 * Provisioning coordinator (Web W1): durable, crash-recoverable coordination
 * of provisioning jobs over the D1 journal. It never contacts a harness.
 *
 *   openCreateJob   authorize, fix the logical command, persist it (§13.10 1–3)
 *   claim           write-before-send: lease + journal row in one batch (4–5)
 *   record          persist what a send produced, or that it is uncertain (7)
 *   deliverOnce     claim → transport.send → record → reconcile, in that order
 *   recoverLeases   dead or stalled claims: their rows become uncertain
 *   reconcileJob    the authoritative pass (8): §13.2 over a first-primary
 *                   snapshot, then §13.3–§13.5 and §10.6, applied only if the
 *                   journal is unchanged since the snapshot
 *   reconcileDue    the level-triggered sweep (R6) a Cron Trigger will run (W2)
 *
 * Safety rests on the journal, the immutable command and the r4 rules; the
 * lease only avoids duplicate work. Nothing here infers "not sent" from a
 * missing answer, or "failed" from time, retries or a lease expiry.
 *
 * W1 has NO transport: `ProvisioningTransport` is an interface, implemented
 * only by tests. No signing key, endpoint or fetch is used anywhere here.
 */
import { createAuditEvent, type AuditEvent, type AuditEventInput } from "../audit/audit";
import { AgentProfileRepository } from "../db/agent-profiles";
import { type Clock, systemClock } from "../db/common";
import { NotFoundError } from "../db/errors";
import { HarnessRepository } from "../db/harnesses";
import {
  type ClaimedTransmission,
  type JobSnapshot,
  type JournalTransmission,
  type PassWrite,
  ProvisioningJournalRepository,
} from "../db/provisioning-journal";
import { UserRepository } from "../db/users";
import { sha256Hex } from "../utils/crypto";
import { randomId } from "../utils/random";
import {
  assessOwnership,
  type CreateResolution,
  isForwardObservation,
  type ObservedState,
  planReconciliation,
  type ReconciliationStep,
  resolveCreateJob,
  resolveRevokeJob,
  retryBudgetExhausted,
  retryDelayMs,
  SLOW_RETRY_MS,
  type Transmission,
} from "./lifecycle";
import {
  canonicalize,
  COMMAND_LIFETIME_SECONDS,
  createPayload,
  normalizeOutcome,
  type ObservedOutcome,
  operationPayload,
  payloadHash,
  PATTERNS,
} from "./protocol";

/** Longer than a 10 s send timeout plus the outcome write. */
export const LEASE_MS = 30_000;

/** Attention the reconciler may clear by itself when the condition goes away. Every other code waits for an operator. */
const AUTO_CLEARABLE_ATTENTION = new Set(["RETRY_BUDGET_EXHAUSTED", "OWNERSHIP_LOST", "HARNESS_HOLD", "HARNESS_DISABLED"]);

const SYSTEM_ACTOR = { type: "system", id: "provisioning-reconciler" } as const;

/** What a sender gets: the claim plus the values that exist only in memory. */
export interface SendableTransmission extends ClaimedTransmission {
  /** Plaintext nonce (§9.2). Never stored; the journal holds its hash. */
  nonce: string;
  /** Canonical payload (§5) of this transmission. */
  payloadJson: string;
  harnessId: string;
  profileId: string;
}

/** A future HTTPS sender (W2). In W1 only tests implement this. */
export interface ProvisioningTransport {
  send(transmission: SendableTransmission): Promise<ObservedOutcome>;
}

export interface ReconcileReport {
  jobId: string;
  operation: string;
  resolution: CreateResolution | ReturnType<typeof resolveRevokeJob> | { status: "legacy" } | null;
  plan: ReconciliationStep | null;
  attention: string | null;
  applied: boolean;
  bookmark: string | null;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** §4.4 nonce: 32 CSPRNG bytes, base64url without padding. */
function newNonce(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function hashTransmissionNonce(nonce: string): Promise<string> {
  return sha256Hex(`nonce:v1:${nonce}`);
}

function resolutionInput(t: JournalTransmission): Transmission {
  const outcome: Transmission["outcome"] =
    t.answer === null
      ? { kind: "uncertain" }
      : t.answer.kind === "operation"
        ? { kind: "operation", operationId: t.answer.operationId, state: t.answer.state }
        : { kind: "refused", code: t.answer.code };
  return { issuedAt: t.issuedAt, expiresAt: t.expiresAt, outcome };
}

export class ProvisioningCoordinator {
  readonly journal: ProvisioningJournalRepository;
  private readonly now: Clock;
  private readonly holder: string;

  constructor(
    private readonly db: D1Database,
    options: { now?: Clock; holder?: string } = {},
  ) {
    this.now = options.now ?? systemClock;
    this.holder = options.holder ?? `worker:${randomId("w", 16).slice(2)}`;
    this.journal = new ProvisioningJournalRepository(db, { now: this.now });
  }

  /**
   * Authorize and persist a profile.create job with its fixed logical command
   * (§13.10 steps 1–3). `userId` must come from the authenticated session;
   * the profile is looked up through the owner-scoped repository, so another
   * user's profile is NotFound. The issuer is Web's configured identifier,
   * never request input. Database triggers re-check every condition.
   */
  async openCreateJob(input: { userId: string; agentProfileId: string; harnessId: string; requestId: string; issuer: string }): Promise<{ jobId: string; payloadHash: string }> {
    const profile = await new AgentProfileRepository(this.db).forUser(input.userId).get(input.agentProfileId);
    if (!profile) throw new NotFoundError("agent_profile");
    const user = await new UserRepository(this.db).getById(input.userId);
    if (!user) throw new NotFoundError("user");
    const harness = await new HarnessRepository(this.db).getById(input.harnessId);
    if (!harness) throw new NotFoundError("harness");

    const idempotencyKey = randomId("idk");
    const payload = createPayload({
      profileId: profile.id,
      issuer: input.issuer,
      subject: user.id,
      displayName: profile.agentName,
      idempotencyKey,
    });
    const hash = await payloadHash("profile.create", payload);
    const jobId = randomId("prv");
    await this.journal.openJob({
      jobId,
      userId: user.id,
      agentProfileId: profile.id,
      harnessId: harness.id,
      operation: "profile.create",
      requestId: input.requestId,
      idempotencyKey,
      targetOperationId: null,
      payloadJson: canonicalize(payload),
      payloadHash: hash,
      audit: this.audit({
        actor: { type: "user", id: user.id },
        action: "provision.job.open",
        target: { type: "provisioning_job", id: jobId },
        requestId: input.requestId,
        result: "success",
        metadata: { operation: "profile.create", profile: profile.id, harness: harness.id },
      }),
    });
    return { jobId, payloadHash: hash };
  }

  /**
   * Write before send (§13.10 steps 4–5). Returns null when this Worker may
   * not send now. The returned value is the only input a sender accepts; its
   * nonce lives only in memory.
   */
  async claim(jobId: string, options: { keyId: string; automatic: boolean; operation?: "profile.status" }): Promise<SendableTransmission | null> {
    if (!PATTERNS.keyId.test(options.keyId)) throw new RangeError("invalid keyId");
    const snapshot = await this.journal.snapshot(jobId);
    if (!snapshot?.command) return null;
    const command = snapshot.command;
    const operation = options.operation ?? command.operation;

    let statusTarget: { operationId: string; payloadHash: string } | null = null;
    let payloadJson = command.payload_json;
    if (operation === "profile.status") {
      const operationId = snapshot.job.operation_id ?? command.target_operation_id;
      if (!operationId) return null;
      const payload = operationPayload({ operationId, profileId: command.agent_profile_id });
      payloadJson = canonicalize(payload);
      statusTarget = { operationId, payloadHash: await payloadHash("profile.status", payload) };
    }

    const nonce = newNonce();
    const now = this.now();
    const issuedAt = Math.floor(now / 1000);
    const claim = await this.journal.claim({
      jobId,
      commandId: randomId("cmd"),
      operation,
      statusTarget,
      keyId: options.keyId,
      nonceHash: await hashTransmissionNonce(nonce),
      issuedAt,
      expiresAt: issuedAt + COMMAND_LIFETIME_SECONDS,
      leaseToken: toBase64Url(crypto.getRandomValues(new Uint8Array(24))),
      leaseHolder: this.holder,
      leaseUntil: now + LEASE_MS,
      automatic: options.automatic,
    });
    if (!claim) return null;
    return { ...claim, nonce, payloadJson, harnessId: command.harness_id, profileId: command.agent_profile_id };
  }

  /**
   * §13.10 step 7. The outcome is normalized with the §12.4 rules first
   * (indeterminate or malformed answers become uncertain). Returns false if
   * the transmission already had a final answer.
   */
  async record(claim: SendableTransmission, outcome: ObservedOutcome): Promise<boolean> {
    const normalized = normalizeOutcome(claim.operation, outcome, claim.targetOperationId);
    return this.journal.recordOutcome(claim, normalized, this.holder);
  }

  /** Claim, send, record, reconcile. A transport error is an uncertain outcome. */
  async deliverOnce(jobId: string, transport: ProvisioningTransport, options: { keyId: string; automatic: boolean; operation?: "profile.status" }): Promise<{ sent: SendableTransmission | null; report: ReconcileReport }> {
    const claim = await this.claim(jobId, options);
    if (claim) {
      let outcome: ObservedOutcome;
      try {
        outcome = await transport.send(claim);
      } catch {
        outcome = { kind: "uncertain", reason: "NETWORK_ERROR" };
      }
      await this.record(claim, outcome);
    }
    return { sent: claim, report: await this.reconcileJob(jobId) };
  }

  async recoverLeases(): Promise<number> {
    return this.journal.recoverLeases(this.holder);
  }

  /** The level-triggered sweep: recover dead claims, flag legacy jobs, reconcile due work and R6 obligations. */
  async reconcileDue(limit = 50): Promise<ReconcileReport[]> {
    await this.recoverLeases();
    await this.journal.flagLegacyJobs(limit);
    const ids = new Set([...(await this.journal.dueJobs(limit)), ...(await this.journal.absentObligations(limit))]);
    const reports: ReconcileReport[] = [];
    for (const id of ids) reports.push(await this.reconcileJob(id));
    return reports;
  }

  /** One authoritative pass for one job; retried if the journal moves underneath it. */
  async reconcileJob(jobId: string): Promise<ReconcileReport> {
    for (let attempt = 0; ; attempt += 1) {
      const snapshot = await this.journal.snapshot(jobId);
      if (!snapshot) throw new NotFoundError("provisioning_job");
      if (!snapshot.command || !snapshot.delivery) {
        await this.journal.flagLegacyJobs(500);
        return { jobId, operation: snapshot.job.operation, resolution: { status: "legacy" }, plan: "operator-attention", attention: "LEGACY_JOB_WITHOUT_COMMAND", applied: false, bookmark: snapshot.bookmark };
      }
      const decision = snapshot.command.operation === "profile.create" ? await this.decideCreate(snapshot) : await this.decideRevoke(snapshot);
      const applied = await this.journal.applyPass(jobId, snapshot.version, toBase64Url(crypto.getRandomValues(new Uint8Array(24))), decision.writes);
      if (applied) {
        const report = { jobId, operation: snapshot.command.operation, resolution: decision.resolution, plan: decision.plan, attention: decision.attention, applied, bookmark: snapshot.bookmark };
        if (decision.followUp) await this.reconcileJob(decision.followUp);
        return report;
      }
      if (attempt >= 4) return { jobId, operation: snapshot.command.operation, resolution: decision.resolution, plan: decision.plan, attention: decision.attention, applied, bookmark: snapshot.bookmark };
    }
  }

  // -------------------------------------------------------------------------

  private audit(input: AuditEventInput): AuditEvent {
    return createAuditEvent(input, () => new Date(this.now()));
  }

  private systemAudit(passId: string, input: Omit<AuditEventInput, "actor" | "requestId" | "result">): PassWrite {
    return { kind: "audit", event: this.audit({ ...input, actor: SYSTEM_ACTOR, requestId: passId, result: "success" }) };
  }

  /** Harness-level stop conditions (§10.6): retired, or circuit-broken after LEDGER_CONTINUITY_FAILED. */
  private harnessGate(s: JobSnapshot, writes: PassWrite[], passId: string): { blocked: boolean; code: string | null } {
    const sawContinuityFailure = s.transmissions.some((t) => t.answer?.kind === "refused" && t.answer.code === "LEDGER_CONTINUITY_FAILED");
    let held = s.context.harness_hold !== null;
    if (sawContinuityFailure && !held) {
      held = true;
      writes.push(
        { kind: "hold-harness", harnessId: s.job.harness_id, code: "LEDGER_CONTINUITY_FAILED" },
        this.systemAudit(passId, { action: "provision.harness.hold", target: { type: "harness", id: s.job.harness_id }, metadata: { code: "LEDGER_CONTINUITY_FAILED", job: s.job.id } }),
      );
    }
    if (s.context.harness_retired === 1) return { blocked: true, code: "HARNESS_RETIRED" };
    if (held) return { blocked: true, code: "HARNESS_HOLD" };
    if (s.context.harness_status === "disabled") return { blocked: true, code: "HARNESS_DISABLED" };
    return { blocked: false, code: null };
  }

  /** Keep an operator-only attention code; otherwise set (or clear) the computed one. */
  private attentionWrite(s: JobSnapshot, jobId: string, current: string | null, wanted: string | null, writes: PassWrite[], passId: string): string | null {
    if (current !== null && !AUTO_CLEARABLE_ATTENTION.has(current)) return current;
    if (current === wanted) return current;
    writes.push({ kind: "attention", jobId, code: wanted });
    if (wanted !== null) {
      writes.push(this.systemAudit(passId, { action: "provision.job.attention", target: { type: "provisioning_job", id: jobId }, metadata: { code: wanted, harness: s.job.harness_id } }));
    }
    return wanted;
  }

  private desired(s: JobSnapshot): "present" | "absent" {
    return s.context.profile_status === "revoked" || s.context.owner_status === "suspended" || s.context.owner_status === "disabled" ? "absent" : "present";
  }

  private schedule(s: JobSnapshot, jobId: string, writes: PassWrite[]): boolean {
    const attempts = s.delivery?.auto_attempts ?? 0;
    const exhausted = retryBudgetExhausted(attempts);
    const delay = exhausted ? SLOW_RETRY_MS : retryDelayMs(attempts);
    writes.push({ kind: "next-attempt", jobId, at: this.now() + delay });
    return exhausted;
  }

  /**
   * Nothing can be sent to this harness. A retired id never serves again, so
   * its delivery is paused for good (§10.6 step 3). A held or disabled
   * harness may come back: re-check at the slow cadence, sending nothing.
   */
  private blockedSchedule(s: JobSnapshot, code: string | null, writes: PassWrite[]): void {
    if (code === "HARNESS_RETIRED") writes.push({ kind: "delivery-mode", jobId: s.job.id, mode: "paused" }, { kind: "next-attempt", jobId: s.job.id, at: null });
    else writes.push({ kind: "next-attempt", jobId: s.job.id, at: this.now() + SLOW_RETRY_MS });
  }

  /** §13.1 observations, folded in answer order over every operation answer about this job's operation. */
  private observe(s: JobSnapshot, operationId: string, writes: PassWrite[]): { state: ObservedState; ownerBound: boolean | null; regression: boolean } {
    const answers = [...s.transmissions, ...s.related]
      .flatMap((t) => (t.answer?.kind === "operation" && t.answer.operationId === operationId ? [t.answer] : []))
      .sort((a, b) => a.at - b.at);
    let state: ObservedState = "unknown";
    let regression = false;
    for (const a of answers) {
      if (isForwardObservation(state, a.state)) state = a.state;
      else regression = true;
    }
    const last = answers[answers.length - 1];
    if (last && (state !== s.job.observed_state || (last.ownerBound ? 1 : 0) !== s.job.observed_owner_bound || last.at !== s.job.observed_at)) {
      if (isForwardObservation(s.job.observed_state, state)) {
        writes.push({ kind: "observe", jobId: s.job.id, operationId, principalId: last.principalId, state, ownerBound: last.ownerBound, at: last.at });
      } else {
        regression = true;
      }
    }
    return { state, ownerBound: last ? last.ownerBound : null, regression };
  }

  private async decideCreate(s: JobSnapshot): Promise<{ writes: PassWrite[]; resolution: CreateResolution; plan: ReconciliationStep; attention: string | null; followUp?: string }> {
    const passId = randomId("rcn");
    const writes: PassWrite[] = [];
    const own = s.transmissions.filter((t) => t.operation === "profile.create");
    const resolution = resolveCreateJob(own.map(resolutionInput));
    const desired = this.desired(s);
    const gate = this.harnessGate(s, writes, passId);
    const plan = planReconciliation(resolution, desired, gate.blocked ? "retired" : "active");
    const current = s.job.needs_attention === 1 ? s.job.attention_code : null;
    let wanted: string | null = null;
    const live = ["pending", "sending", "accepted"];

    if (resolution.status === "resolved") {
      const observation = this.observe(s, resolution.operationId, writes);
      if (observation.regression) wanted = "STATE_REGRESSION";
      const state = observation.state === "unknown" ? resolution.state : observation.state;
      if (live.includes(s.job.status)) {
        if (resolution.state === "failed") {
          const failure = own.find((t) => t.answer?.kind === "operation" && t.answer.failure !== null)?.answer;
          const code = failure?.kind === "operation" && failure.failure ? failure.failure : "OPERATION_FAILED";
          writes.push({ kind: "job-status", jobId: s.job.id, to: "failed", from: live, errorCode: code }, { kind: "profile-status", profileId: s.job.agent_profile_id, from: "provisioning", to: "failed" });
        } else {
          writes.push({ kind: "job-status", jobId: s.job.id, to: "completed", from: ["sending", "accepted"], errorCode: null });
          if (resolution.state === "completed") writes.push({ kind: "profile-status", profileId: s.job.agent_profile_id, from: "provisioning", to: "active" });
          if (resolution.state === "revoked") {
            // §13.7: a create that resolves revoked (after lost Web records) needs an operator.
            wanted = "CREATE_RESOLVED_REVOKED";
            writes.push({ kind: "profile-status", profileId: s.job.agent_profile_id, from: "provisioning", to: "revoked" });
          }
        }
        writes.push(this.systemAudit(passId, { action: "provision.job.resolve", target: { type: "provisioning_job", id: s.job.id }, metadata: { state: resolution.state, rule: "R1" } }));
      }
      // §13.1 ownership; §13.5 confirmation of failed/revoked operations while desired is absent.
      const ownership = assessOwnership({ state, ownerBound: observation.ownerBound ?? false });
      if (wanted === null && observation.ownerBound !== null) {
        if (ownership === "attention:OWNERSHIP_LOST") wanted = "OWNERSHIP_LOST";
        if (ownership === "attention:UNEXPECTED_BINDING") wanted = "UNEXPECTED_BINDING";
        if (desired === "absent" && state === "failed" && observation.ownerBound) wanted = "BOUND_AFTER_FAILURE";
      }
      if (plan === "revoke") await this.planRevoke(s, resolution.operationId, writes, passId);
      if (plan === "confirm-status") writes.push({ kind: "next-attempt", jobId: s.job.id, at: this.now() });
      if (plan === "operator-attention" && wanted === null) wanted = gate.code ?? "CREATE_RESOLVED_REVOKED";
    } else if (resolution.status === "failed") {
      // R2/R3: the pass CAS guarantees no transmission was journaled since the snapshot,
      // and a failed job can never journal another create (trigger).
      if (live.includes(s.job.status)) {
        writes.push(
          { kind: "job-status", jobId: s.job.id, to: "failed", from: live, errorCode: resolution.code },
          { kind: "profile-status", profileId: s.job.agent_profile_id, from: "provisioning", to: "failed" },
          { kind: "next-attempt", jobId: s.job.id, at: null },
          this.systemAudit(passId, { action: "provision.job.resolve", target: { type: "provisioning_job", id: s.job.id }, metadata: { state: "failed", code: resolution.code, transmissions: own.length } }),
        );
      }
    } else if (resolution.status === "attention") {
      wanted = resolution.code;
      writes.push({ kind: "delivery-mode", jobId: s.job.id, mode: "paused" }, { kind: "next-attempt", jobId: s.job.id, at: null });
    } else if (desired === "absent" && s.transmissions.length === 0 && s.version.nextSeq === 1 && s.job.status === "pending") {
      // Invariant J: nothing journaled means nothing can have reached the harness.
      // Cancelling (instead of R4's send-then-revoke) never sends a create for an
      // owner who is already suspended. Gated on next_seq = 1 at commit time.
      writes.push(
        { kind: "cancel-unsent", jobId: s.job.id },
        { kind: "profile-status", profileId: s.job.agent_profile_id, from: "provisioning", to: "revoked" },
        { kind: "next-attempt", jobId: s.job.id, at: null },
        this.systemAudit(passId, { action: "provision.job.cancel", target: { type: "provisioning_job", id: s.job.id }, metadata: { reason: "desired_absent_unsent" } }),
      );
      return { writes, resolution, plan: "none", attention: current };
    } else if (gate.blocked) {
      wanted = gate.code;
      this.blockedSchedule(s, gate.code, writes);
    } else {
      // R4: keep resending the same logical command, even if desired is absent.
      if (desired === "absent") writes.push({ kind: "profile-status", profileId: s.job.agent_profile_id, from: "provisioning", to: "revoked" });
      if (this.schedule(s, s.job.id, writes)) wanted = "RETRY_BUDGET_EXHAUSTED";
    }

    const attention = this.attentionWrite(s, s.job.id, current, wanted, writes, passId);
    return { writes, resolution, plan, attention };
  }

  /** R6: open the revoke job for a completed create (fixed command, nothing sent). */
  private async planRevoke(s: JobSnapshot, operationId: string, writes: PassWrite[], passId: string): Promise<void> {
    const open = s.siblings.some((j) => j.operation === "profile.revoke" && ["pending", "sending", "accepted", "completed"].includes(j.status));
    if (open) return;
    const payload = operationPayload({ operationId, profileId: s.job.agent_profile_id });
    const jobId = randomId("prv");
    writes.push(
      {
        kind: "open-revoke",
        jobId,
        userId: s.job.user_id,
        profileId: s.job.agent_profile_id,
        harnessId: s.job.harness_id,
        requestId: randomId("req"),
        idempotencyKey: randomId("idk"),
        targetOperationId: operationId,
        payloadJson: canonicalize(payload),
        payloadHash: await payloadHash("profile.revoke", payload),
      },
      this.systemAudit(passId, { action: "provision.revoke.request", target: { type: "provisioning_job", id: jobId }, metadata: { createJob: s.job.id, profile: s.job.agent_profile_id } }),
    );
  }

  private async decideRevoke(s: JobSnapshot): Promise<{ writes: PassWrite[]; resolution: ReturnType<typeof resolveRevokeJob>; plan: ReconciliationStep; attention: string | null; followUp?: string }> {
    const passId = randomId("rcn");
    const writes: PassWrite[] = [];
    const own = s.transmissions.filter((t) => t.operation === "profile.revoke");
    const resolution = resolveRevokeJob(own.map(resolutionInput));
    const gate = this.harnessGate(s, writes, passId);
    const create = s.siblings.find((j) => j.operation === "profile.create" && j.operation_id === s.command?.target_operation_id);
    const current = s.job.needs_attention === 1 ? s.job.attention_code : null;
    const live = ["pending", "sending", "accepted"];
    let wanted: string | null = null;
    let plan: ReconciliationStep = "none";

    if (resolution.status === "completed") {
      if (live.includes(s.job.status)) {
        writes.push(
          { kind: "job-status", jobId: s.job.id, to: "completed", from: ["sending", "accepted"], errorCode: null },
          { kind: "next-attempt", jobId: s.job.id, at: null },
          this.systemAudit(passId, { action: "provision.job.resolve", target: { type: "provisioning_job", id: s.job.id }, metadata: { state: "revoked", rule: "R5" } }),
        );
      }
      if (resolution.confirm && create) {
        plan = "confirm-status";
        writes.push({ kind: "next-attempt", jobId: create.id, at: this.now() });
      }
    } else if (resolution.status === "failed") {
      wanted = resolution.code;
      if (live.includes(s.job.status)) {
        writes.push(
          { kind: "job-status", jobId: s.job.id, to: "failed", from: live, errorCode: resolution.code },
          { kind: "next-attempt", jobId: s.job.id, at: null },
          this.systemAudit(passId, { action: "provision.job.resolve", target: { type: "provisioning_job", id: s.job.id }, metadata: { state: "failed", code: resolution.code, rule: "R5" } }),
        );
      }
    } else if (resolution.status === "attention") {
      wanted = resolution.code;
      plan = "operator-attention";
      writes.push({ kind: "delivery-mode", jobId: s.job.id, mode: "paused" }, { kind: "next-attempt", jobId: s.job.id, at: null });
    } else if (gate.blocked) {
      wanted = gate.code;
      plan = "operator-attention";
      this.blockedSchedule(s, gate.code, writes);
    } else if (resolution.resendCreate && !(create && live.includes(create.status))) {
      // OPERATION_IN_PROGRESS for a create Web already settled: an anomaly.
      wanted = "OPERATION_IN_PROGRESS";
      plan = "operator-attention";
    } else {
      plan = resolution.resendCreate ? "send-create" : "revoke";
      if (this.schedule(s, s.job.id, writes)) wanted = "RETRY_BUDGET_EXHAUSTED";
    }

    const attention = this.attentionWrite(s, s.job.id, current, wanted, writes, passId);
    return { writes, resolution, plan, attention, ...(create ? { followUp: create.id } : {}) };
  }
}
