/**
 * Web's provisioning state machine (PROVISIONING_PROTOCOL §13): what may be
 * concluded from a job's journal, and what to do next. Pure functions over
 * journal rows; the reconciler feeds them a primary-consistent snapshot.
 *
 * resolveCreateJob, planReconciliation and assessOwnership reproduce the
 * frozen create-resolution and responses fixtures exactly (the W1
 * conformance test). Nothing here treats elapsed
 * time, a missing answer or an exhausted retry budget as failure.
 */
import { ACCEPTANCE_HORIZON_SECONDS, errorDefinition, type OperationState } from "./protocol";

export type TransmissionOutcome =
  | { kind: "operation"; operationId: string; state: OperationState }
  | { kind: "refused"; code: string }
  | { kind: "uncertain" };

/** One journaled transmission of the job's own operation, as resolution sees it. */
export interface Transmission {
  issuedAt: number;
  expiresAt: number;
  outcome: TransmissionOutcome;
}

export type CreateResolution =
  | { status: "resolved"; operationId: string; state: OperationState }
  | { status: "failed"; code: string }
  | { status: "attention"; code: string }
  | { status: "unresolved" };

const classOf = (code: string) => errorDefinition(code)?.class;

/**
 * §13.2 R1–R3a over EVERY journaled transmission of a profile.create job. A
 * journaled transmission without a recorded answer must be passed in as
 * `uncertain` (§13.10: a journal row is not delivery).
 */
export function resolveCreateJob(transmissions: readonly Transmission[]): CreateResolution {
  // R1: an operation resolves the job; two different operation ids are an anomaly.
  const operations = transmissions.flatMap((t) => (t.outcome.kind === "operation" ? [t.outcome] : []));
  if (operations.length > 0) {
    const first = operations[0] as { operationId: string };
    if (operations.some((o) => o.operationId !== first.operationId)) return { status: "attention", code: "OPERATION_MISMATCH" };
    const latest = operations[operations.length - 1] as { operationId: string; state: OperationState };
    return { status: "resolved", operationId: latest.operationId, state: latest.state };
  }
  const refusals = transmissions.flatMap((t) => (t.outcome.kind === "refused" ? [{ ...t, code: t.outcome.code }] : []));
  if (refusals.some((r) => classOf(r.code) === "conflict")) return { status: "attention", code: "IDEMPOTENCY_CONFLICT" };
  if (refusals.some((r) => classOf(r.code) === undefined)) return { status: "attention", code: "UNKNOWN_REFUSAL" };
  // R2: payload refusals are final.
  const payloadRefusal = refusals.find((r) => classOf(r.code) === "payload");
  if (payloadRefusal) return { status: "failed", code: payloadRefusal.code };
  if (refusals.length === 0) return { status: "unresolved" };
  // R3a: signs of ledger discontinuity are never evidence.
  if (refusals.some((r) => r.code === "LEDGER_CONTINUITY_FAILED")) return { status: "attention", code: "LEDGER_CONTINUITY_FAILED" };
  // R3: open = uncertain, or refused only for this copy (protocol class, before the nonce).
  const open = transmissions.filter((t) => t.outcome.kind === "uncertain" || (t.outcome.kind === "refused" && classOf(t.outcome.code) === "protocol"));
  if (open.length > 0 && refusals.some((r) => r.code === "PROFILE_UNAVAILABLE")) {
    return { status: "attention", code: "PROFILE_UNAVAILABLE_WHILE_OPEN" };
  }
  const merits = refusals.filter((r) => classOf(r.code) === "merits" && r.code !== "PROFILE_UNAVAILABLE");
  const ruledOut = open.every((u) => merits.some((m) => m.issuedAt >= u.expiresAt + ACCEPTANCE_HORIZON_SECONDS));
  if (!ruledOut) return { status: "unresolved" };
  const latest = refusals.reduce((a, b) => (b.issuedAt >= a.issuedAt ? b : a));
  return { status: "failed", code: latest.code };
}

export type ReconciliationStep = "send-create" | "revoke" | "confirm-status" | "operator-attention" | "none";

/**
 * §13.3–§13.5 and §10.6: the next step for a create job. `harness` is
 * "retired" for any harness Web must send nothing to: a retirement record,
 * or a LEDGER_CONTINUITY_FAILED circuit break (§10.6 step 2).
 */
export function planReconciliation(resolution: CreateResolution, desired: "present" | "absent", harness: "active" | "retired" = "active"): ReconciliationStep {
  if (harness === "retired") {
    if (resolution.status === "failed") return "none";
    if (resolution.status === "resolved" && resolution.state === "revoked" && desired === "absent") return "none";
    if (resolution.status === "resolved" && resolution.state === "failed" && desired === "present") return "none";
    return "operator-attention";
  }
  switch (resolution.status) {
    case "unresolved":
      return "send-create";
    case "attention":
      return "operator-attention";
    case "failed":
      return "none";
    case "resolved":
      if (resolution.state === "completed") return desired === "absent" ? "revoke" : "none";
      if (resolution.state === "failed") return desired === "absent" ? "confirm-status" : "none";
      if (resolution.state === "revoked") return desired === "absent" ? "none" : "operator-attention";
      return "send-create";
  }
}

export type OwnershipAssessment = "bound" | "unbound" | "bound-informational" | "attention:OWNERSHIP_LOST" | "attention:UNEXPECTED_BINDING";

/** §13.1: `ownerBound` is current ownership. It raises or clears attention; it never moves state. */
export function assessOwnership(result: { state: OperationState; ownerBound: boolean }): OwnershipAssessment {
  if (result.state === "completed") return result.ownerBound ? "bound" : "attention:OWNERSHIP_LOST";
  if (result.state === "revoked") return result.ownerBound ? "attention:UNEXPECTED_BINDING" : "unbound";
  return result.ownerBound ? "bound-informational" : "unbound";
}

export type ObservedState = "unknown" | OperationState;

const RANK: Readonly<Record<ObservedState, number>> = { unknown: 0, pending: 1, profile_created: 2, completed: 3, revoked: 4, failed: -1 };

/** §13.1: observed state only moves forward (mirrored by a D1 trigger). */
export function isForwardObservation(from: ObservedState, to: ObservedState): boolean {
  if (from === to) return true;
  if (to === "failed") return from === "unknown" || from === "pending" || from === "profile_created";
  if (from === "failed") return false;
  return RANK[to] > RANK[from];
}

export type RevokeResolution =
  | { status: "completed"; confirm: boolean }
  | { status: "failed"; code: "OWNERSHIP_CHANGED" }
  | { status: "attention"; code: string }
  | { status: "unresolved"; resendCreate: boolean };

/**
 * §13.4 R5 over a revoke job's journal. Revoke is idempotent by operation, so
 * an uncertain transmission simply means "resend"; nothing here fails a
 * revoke by elapsed time.
 */
export function resolveRevokeJob(transmissions: readonly Transmission[]): RevokeResolution {
  if (transmissions.some((t) => t.outcome.kind === "operation" && t.outcome.state === "revoked")) return { status: "completed", confirm: false };
  const codes = transmissions.flatMap((t) => (t.outcome.kind === "refused" ? [t.outcome.code] : []));
  if (codes.includes("UNKNOWN_OPERATION")) return { status: "attention", code: "UNKNOWN_OPERATION" };
  if (codes.includes("OWNERSHIP_CHANGED")) return { status: "failed", code: "OWNERSHIP_CHANGED" };
  // NOT_REVOCABLE: nothing was bound; confirm with status that the operation is failed.
  if (codes.includes("NOT_REVOCABLE")) return { status: "completed", confirm: true };
  if (codes.includes("LEDGER_CONTINUITY_FAILED")) return { status: "attention", code: "LEDGER_CONTINUITY_FAILED" };
  if (codes.some((c) => classOf(c) !== "protocol" && classOf(c) !== "operation")) return { status: "attention", code: "UNEXPECTED_REFUSAL" };
  return { status: "unresolved", resendCreate: codes.includes("OPERATION_IN_PROGRESS") };
}

// ---------------------------------------------------------------------------
// Retry scheduling (§13.3 R4), kept apart from resolution
// ---------------------------------------------------------------------------

/** R4 backoff between automatic transmissions: 10 s, 30 s, 2 min, then every 15 min. */
export const RETRY_DELAYS_MS = [10_000, 30_000, 120_000] as const;
export const SLOW_RETRY_MS = 15 * 60_000;
/**
 * §13.3: after about 10 automatic transmissions without resolution the job
 * needs operator attention but stays unresolved and keeps reconciling at the
 * slow cadence. The budget gates escalation, never the outcome.
 */
export const AUTOMATIC_RETRY_BUDGET = 10;

export function retryDelayMs(automaticAttempts: number): number {
  return automaticAttempts >= 1 && automaticAttempts <= RETRY_DELAYS_MS.length ? (RETRY_DELAYS_MS[automaticAttempts - 1] as number) : automaticAttempts === 0 ? 0 : SLOW_RETRY_MS;
}

export function retryBudgetExhausted(automaticAttempts: number): boolean {
  return automaticAttempts >= AUTOMATIC_RETRY_BUDGET;
}
