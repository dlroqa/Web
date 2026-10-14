/**
 * Provisioning journal storage (migration 0003, PROVISIONING_PROTOCOL §13.10).
 *
 * Trusted, internal-only repository: no method takes a user id from request
 * input, and no HTTP route reaches it. Callers are the provisioning
 * coordinator (src/worker/provisioning/) and the operator service.
 *
 * Every state change is ONE D1 batch (a transaction):
 *   openJob        job + fixed command + delivery row (+ profile → provisioning) + audit
 *   claim          delivery lease CAS + journal row + job bookkeeping. Losing the
 *                  lease inserts nothing; only a returned claim may be sent.
 *   recordOutcome  outcome row + lease release
 *   recoverLeases  uncertain marks for rows of dead claims + lease clearing
 *   applyPass      a reconciliation decision. Its first statement is a CAS on
 *                  the journal version the pass read; every other statement is
 *                  gated on the pass token that CAS wrote, so a decision made
 *                  from a stale journal changes nothing.
 *
 * `snapshot` is the authoritative read: one batch of SELECTs (a single
 * consistent transaction) in a D1 session started with `first-primary`, so
 * it never reads a lagging replica (§13.10, r4).
 */
import type { AuditEvent } from "../audit/audit";
import { z } from "../../shared/zod";
import { auditRowValues } from "./audit";
import { type Clock, idSchema, parseRow, type RepositoryOptions, systemClock } from "./common";
import { guard } from "./errors";

// ---------------------------------------------------------------------------
// SQL (constant text; every value is bound)
// ---------------------------------------------------------------------------

const INSERT_JOB = `INSERT INTO provisioning_jobs
  (id, user_id, agent_profile_id, harness_id, operation, request_id, idempotency_key, request_hash, status, attempt_count, created_at, updated_at)
  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?9)`;

const INSERT_COMMAND = `INSERT INTO provisioning_commands
  (job_id, user_id, agent_profile_id, harness_id, protocol, operation, idempotency_key, target_operation_id, payload_json, payload_hash, created_at)
  SELECT ?1, ?2, ?3, ?4, 'LA-WEB-PROVISIONING/1', ?5, ?6, ?7, ?8, ?9, ?10
  WHERE EXISTS (SELECT 1 FROM provisioning_jobs WHERE id = ?1 AND status = 'pending')`;

const INSERT_DELIVERY = `INSERT INTO provisioning_deliveries (job_id, created_at, updated_at)
  SELECT ?1, ?2, ?2 WHERE EXISTS (SELECT 1 FROM provisioning_commands WHERE job_id = ?1)`;

const PROFILE_TO_PROVISIONING = `UPDATE agent_profiles
  SET status = 'provisioning', harness_id = ?2, updated_at = MAX(updated_at, ?3)
  WHERE id = ?1 AND status IN ('pending', 'failed') AND EXISTS (SELECT 1 FROM provisioning_commands WHERE job_id = ?4)
  RETURNING id`;

const INSERT_AUDIT_IF_COMMAND = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
  WHERE EXISTS (SELECT 1 FROM provisioning_commands WHERE job_id = ?13)`;

const CLAIM_LEASE = `UPDATE provisioning_deliveries
  SET lease_token = ?2, lease_holder = ?3, lease_until = ?4, next_seq = next_seq + 1,
      auto_attempts = auto_attempts + ?5, updated_at = MAX(updated_at, ?6)
  WHERE job_id = ?1 AND mode = 'active' AND (lease_until IS NULL OR lease_until <= ?6)
    AND EXISTS (
      SELECT 1 FROM provisioning_jobs j JOIN harnesses h ON h.id = j.harness_id
      WHERE j.id = ?1 AND h.status IN ('active', 'draining') AND h.provisioning_hold IS NULL
        AND NOT EXISTS (SELECT 1 FROM harness_retirements r WHERE r.harness_id = h.id)
        AND (?7 = 'profile.status' OR j.status IN ('pending', 'sending', 'accepted'))
        AND (?5 = 0 OR j.next_attempt_at IS NULL OR j.next_attempt_at <= ?6))
  RETURNING next_seq`;

const JOURNAL_TRANSMISSION = `INSERT INTO provisioning_transmissions
  (command_id, job_id, seq, harness_id, agent_profile_id, protocol, operation, target_operation_id, payload_hash,
   key_id, nonce_hash, issued_at, expires_at, lease_token, lease_holder, automatic, journaled_at)
  SELECT ?1, d.job_id, d.next_seq - 1, c.harness_id, c.agent_profile_id, c.protocol, ?3,
         CASE WHEN ?3 = c.operation THEN c.target_operation_id ELSE ?4 END,
         CASE WHEN ?3 = c.operation THEN c.payload_hash ELSE ?5 END,
         ?6, ?7, ?8, ?9, d.lease_token, d.lease_holder, ?10, ?11
  FROM provisioning_deliveries d JOIN provisioning_commands c ON c.job_id = d.job_id
  WHERE d.job_id = ?2 AND d.lease_token = ?12
  RETURNING seq, target_operation_id, payload_hash`;

const MARK_JOB_SENDING = `UPDATE provisioning_jobs
  SET status = CASE WHEN status = 'pending' THEN 'sending' ELSE status END,
      attempt_count = MIN(attempt_count + 1, 10), updated_at = MAX(updated_at, ?3)
  WHERE id = ?1 AND EXISTS (SELECT 1 FROM provisioning_transmissions WHERE command_id = ?2 AND operation <> 'profile.status')`;

const RECORD_ANSWER = `INSERT INTO provisioning_transmission_outcomes
  (command_id, disposition, outcome_kind, refusal_code, uncertain_reason, operation_id, operation_state, failure_code, owner_bound, principal_id, recorded_by, recorded_at)
  VALUES (?1, 'answered', ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
  ON CONFLICT (command_id, disposition) DO NOTHING`;

const RECORD_UNCERTAIN = `INSERT INTO provisioning_transmission_outcomes
  (command_id, disposition, uncertain_reason, recorded_by, recorded_at)
  SELECT ?1, 'uncertain', ?2, ?3, ?4
  WHERE EXISTS (SELECT 1 FROM provisioning_transmissions WHERE command_id = ?1)
    AND NOT EXISTS (SELECT 1 FROM provisioning_transmission_outcomes WHERE command_id = ?1)`;

const RELEASE_LEASE = `UPDATE provisioning_deliveries
  SET lease_token = NULL, lease_holder = NULL, lease_until = NULL, updated_at = MAX(updated_at, ?2)
  WHERE lease_token = ?1`;

const RECOVER_MARK_UNCERTAIN = `INSERT INTO provisioning_transmission_outcomes
  (command_id, disposition, uncertain_reason, recorded_by, recorded_at)
  SELECT t.command_id, 'uncertain', 'LEASE_EXPIRED', ?2, ?1
  FROM provisioning_transmissions t JOIN provisioning_deliveries d ON d.job_id = t.job_id
  WHERE NOT EXISTS (SELECT 1 FROM provisioning_transmission_outcomes o WHERE o.command_id = t.command_id)
    AND (d.lease_token IS NULL OR d.lease_token <> t.lease_token OR d.lease_until <= ?1)
  LIMIT ?3`;

const RECOVER_CLEAR_LEASES = `UPDATE provisioning_deliveries
  SET lease_token = NULL, lease_holder = NULL, lease_until = NULL, updated_at = MAX(updated_at, ?1)
  WHERE lease_until <= ?1`;

// Authoritative snapshot (first-primary session, one batch).
const SNAPSHOT_JOB = `SELECT * FROM provisioning_jobs WHERE id = ?1`;
const SNAPSHOT_COMMAND = `SELECT * FROM provisioning_commands WHERE job_id = ?1`;
const SNAPSHOT_DELIVERY = `SELECT * FROM provisioning_deliveries WHERE job_id = ?1`;
const SNAPSHOT_TRANSMISSIONS = `SELECT t.command_id, t.job_id, t.seq, t.harness_id, t.agent_profile_id, t.operation, t.target_operation_id,
       t.payload_hash, t.key_id, t.issued_at, t.expires_at, t.lease_token, t.automatic, t.journaled_at,
       a.outcome_kind, a.refusal_code, a.operation_id AS answer_operation_id, a.operation_state, a.failure_code,
       a.owner_bound, a.principal_id, a.recorded_at AS answered_at, u.uncertain_reason, u.recorded_at AS uncertain_at
  FROM provisioning_transmissions t
  LEFT JOIN provisioning_transmission_outcomes a ON a.command_id = t.command_id AND a.disposition = 'answered'
  LEFT JOIN provisioning_transmission_outcomes u ON u.command_id = t.command_id AND u.disposition = 'uncertain'
  WHERE t.job_id = ?1 OR t.job_id IN (
    SELECT c.job_id FROM provisioning_commands c JOIN provisioning_jobs j ON j.id = ?1
    WHERE c.operation = 'profile.revoke' AND c.agent_profile_id = j.agent_profile_id AND c.target_operation_id = j.operation_id)
  ORDER BY t.job_id = ?1 DESC, t.job_id, t.seq`;
const SNAPSHOT_CONTEXT = `SELECT p.status AS profile_status, p.updated_at AS profile_updated_at, u.status AS owner_status, u.updated_at AS owner_updated_at,
       h.status AS harness_status, h.provisioning_hold AS harness_hold,
       EXISTS (SELECT 1 FROM harness_retirements r WHERE r.harness_id = h.id) AS harness_retired
  FROM provisioning_jobs j
  JOIN agent_profiles p ON p.id = j.agent_profile_id
  JOIN user_profiles u ON u.id = j.user_id
  JOIN harnesses h ON h.id = j.harness_id
  WHERE j.id = ?1`;
const SNAPSHOT_SIBLINGS = `SELECT s.id, s.operation, s.status, s.operation_id, c.target_operation_id
  FROM provisioning_jobs s JOIN provisioning_jobs j ON j.id = ?1
  LEFT JOIN provisioning_commands c ON c.job_id = s.id
  WHERE s.agent_profile_id = j.agent_profile_id AND s.id <> ?1
  ORDER BY s.created_at, s.id`;
const SNAPSHOT_OUTCOME_COUNT = `SELECT COUNT(*) AS n FROM provisioning_transmission_outcomes o
  JOIN provisioning_transmissions t ON t.command_id = o.command_id WHERE t.job_id = ?1`;

// A reconciliation pass: CAS on the journal version, then gated writes.
const BEGIN_PASS = `UPDATE provisioning_deliveries
  SET reconcile_count = reconcile_count + 1, reconcile_token = ?4, last_reconciled_at = ?5, updated_at = MAX(updated_at, ?5)
  WHERE job_id = ?1 AND next_seq = ?2
    AND (SELECT COUNT(*) FROM provisioning_transmission_outcomes o JOIN provisioning_transmissions t ON t.command_id = o.command_id WHERE t.job_id = ?1) = ?3
  RETURNING job_id`;

const PASS_OBSERVE = `UPDATE provisioning_jobs
  SET operation_id = COALESCE(operation_id, ?4), principal_id = COALESCE(principal_id, ?5), observed_state = ?6,
      observed_owner_bound = ?7, observed_at = ?8, updated_at = MAX(updated_at, ?9)
  WHERE id = ?3 AND (operation_id IS NULL OR operation_id = ?4)
    AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_JOB_STATUS = `UPDATE provisioning_jobs
  SET status = ?4, error_code = COALESCE(?5, error_code),
      completed_at = CASE WHEN ?4 IN ('completed', 'failed', 'cancelled') THEN ?6 ELSE completed_at END,
      updated_at = MAX(updated_at, ?6)
  WHERE id = ?3 AND status IN (SELECT value FROM json_each(?7))
    AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_CANCEL_UNSENT = `UPDATE provisioning_jobs
  SET status = 'cancelled', completed_at = ?4, updated_at = MAX(updated_at, ?4)
  WHERE id = ?3 AND status = 'pending'
    AND NOT EXISTS (SELECT 1 FROM provisioning_transmissions WHERE job_id = ?3)
    AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2 AND next_seq = 1)`;

const PASS_ATTENTION = `UPDATE provisioning_jobs
  SET needs_attention = ?4, attention_code = ?5, updated_at = MAX(updated_at, ?6)
  WHERE id = ?3 AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_NEXT_ATTEMPT = `UPDATE provisioning_jobs SET next_attempt_at = ?4
  WHERE id = ?3 AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_DELIVERY_MODE = `UPDATE provisioning_deliveries SET mode = ?4, updated_at = MAX(updated_at, ?5)
  WHERE job_id = ?3 AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_PROFILE_STATUS = `UPDATE agent_profiles
  SET status = ?4, revocation_version = revocation_version + (CASE WHEN ?4 IN ('suspended', 'revoked') THEN 1 ELSE 0 END),
      updated_at = MAX(updated_at, ?5)
  WHERE id = ?3 AND status = ?6
    AND (?4 NOT IN ('provisioning', 'active') OR EXISTS (SELECT 1 FROM user_profiles WHERE id = agent_profiles.user_id AND status = 'active'))
    AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_HOLD_HARNESS = `UPDATE harnesses SET provisioning_hold = ?4, provisioning_hold_at = ?5
  WHERE id = ?3 AND provisioning_hold IS NULL
    AND EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_AUDIT = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  SELECT ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
  WHERE EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)`;

const PASS_INSERT_REVOKE_JOB = `INSERT INTO provisioning_jobs
  (id, user_id, agent_profile_id, harness_id, operation, request_id, idempotency_key, request_hash, status, attempt_count, created_at, updated_at)
  SELECT ?3, ?4, ?5, ?6, 'profile.revoke', ?7, ?8, ?9, 'pending', 0, ?10, ?10
  WHERE EXISTS (SELECT 1 FROM provisioning_deliveries WHERE job_id = ?1 AND reconcile_token = ?2)
    AND NOT EXISTS (SELECT 1 FROM provisioning_jobs WHERE agent_profile_id = ?5 AND operation = 'profile.revoke'
                      AND status IN ('pending', 'sending', 'accepted', 'completed'))`;

// Selection (drives scheduling only; a stale read can only delay work).
const SELECT_DUE = `SELECT j.id FROM provisioning_jobs j JOIN provisioning_deliveries d ON d.job_id = j.id
  WHERE j.status IN ('pending', 'sending', 'accepted') AND d.mode = 'active'
    AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= ?1) AND (d.lease_until IS NULL OR d.lease_until <= ?1)
  ORDER BY COALESCE(j.next_attempt_at, j.created_at), j.id LIMIT ?2`;

// R6, level-triggered: settled creates whose desired state is now absent
// and that still owe a revoke, or a status confirmation of a failed operation.
// Attention that the reconciler clears by itself (coordinator
// AUTO_CLEARABLE_ATTENTION) does not exclude a job: a completed operation
// whose ownership was lost is still revoked (§13.1).
const SELECT_ABSENT_OBLIGATIONS = `SELECT j.id FROM provisioning_jobs j
  JOIN provisioning_deliveries d ON d.job_id = j.id
  JOIN agent_profiles p ON p.id = j.agent_profile_id
  JOIN user_profiles u ON u.id = j.user_id
  WHERE j.operation = 'profile.create' AND d.mode = 'active'
    AND (j.needs_attention = 0 OR j.attention_code IN ('RETRY_BUDGET_EXHAUSTED', 'OWNERSHIP_LOST', 'HARNESS_HOLD', 'HARNESS_DISABLED'))
    AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= ?1)
    AND (p.status = 'revoked' OR u.status IN ('suspended', 'disabled'))
    AND (
      (j.status = 'completed' AND j.observed_state = 'completed' AND NOT EXISTS (
         SELECT 1 FROM provisioning_jobs r WHERE r.agent_profile_id = j.agent_profile_id AND r.operation = 'profile.revoke'
           AND r.status IN ('pending', 'sending', 'accepted', 'completed')))
      OR (j.status = 'failed' AND j.operation_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM provisioning_transmissions t
         JOIN provisioning_transmission_outcomes o ON o.command_id = t.command_id AND o.disposition = 'answered'
         WHERE t.job_id = j.id AND t.operation = 'profile.status' AND o.recorded_at >= MAX(p.updated_at, u.updated_at))))
  ORDER BY j.updated_at, j.id LIMIT ?2`;

const SELECT_LEGACY_JOBS = `SELECT j.id FROM provisioning_jobs j
  WHERE j.status IN ('pending', 'sending', 'accepted') AND j.needs_attention = 0
    AND NOT EXISTS (SELECT 1 FROM provisioning_commands c WHERE c.job_id = j.id)
  ORDER BY j.created_at, j.id LIMIT ?1`;

const FLAG_LEGACY_JOB = `UPDATE provisioning_jobs
  SET needs_attention = 1, attention_code = 'LEGACY_JOB_WITHOUT_COMMAND', updated_at = MAX(updated_at, ?2)
  WHERE id = ?1 AND needs_attention = 0 AND NOT EXISTS (SELECT 1 FROM provisioning_commands c WHERE c.job_id = ?1)
  RETURNING id`;

const SELECT_ATTENTION = `SELECT j.id, j.operation, j.status, j.attention_code, j.harness_id, j.agent_profile_id, j.user_id,
       j.observed_state, j.operation_id, j.updated_at, d.mode, COALESCE(d.next_seq, 1) - 1 AS transmissions
  FROM provisioning_jobs j LEFT JOIN provisioning_deliveries d ON d.job_id = j.id
  WHERE j.needs_attention = 1 AND (?1 IS NULL OR j.harness_id = ?1)
  ORDER BY j.updated_at DESC, j.id LIMIT ?2`;

const SELECT_TRANSMISSION_IDENTITY = `SELECT command_id, job_id, seq, operation, target_operation_id, payload_hash, key_id, issued_at, expires_at, lease_token, lease_holder
  FROM provisioning_transmissions WHERE command_id = ?1`;

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

const Hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const OperationId = z.string().regex(/^[0-9a-f]{32}$/);
const Code = z.string().regex(/^[A-Z0-9_]{1,64}$/);
const Ms = z.number().int().positive();
const Seconds = z.number().int().min(1_000_000_000).max(9_999_999_999);
const OperationStateSchema = z.enum(["pending", "profile_created", "completed", "failed", "revoked"]);
const ObservedStateSchema = z.enum(["unknown", "pending", "profile_created", "completed", "failed", "revoked"]);
const JobStatusSchema = z.enum(["pending", "sending", "accepted", "completed", "failed", "cancelled"]);

const JobRow = z.object({
  id: idSchema("prv"),
  user_id: idSchema("usr"),
  agent_profile_id: idSchema("agt"),
  harness_id: idSchema("hns"),
  operation: z.string(),
  request_id: idSchema("req"),
  idempotency_key: z.string(),
  request_hash: Hex64,
  status: JobStatusSchema,
  attempt_count: z.number().int().min(0).max(10),
  error_code: Code.nullable(),
  operation_id: OperationId.nullable(),
  principal_id: z.string().nullable(),
  observed_state: ObservedStateSchema,
  observed_owner_bound: z.number().int().min(0).max(1).nullable(),
  observed_at: Ms.nullable(),
  needs_attention: z.number().int().min(0).max(1),
  attention_code: Code.nullable(),
  next_attempt_at: Ms.nullable(),
  created_at: Ms,
  updated_at: Ms,
});

const CommandRow = z.object({
  job_id: idSchema("prv"),
  operation: z.enum(["profile.create", "profile.revoke"]),
  target_operation_id: OperationId.nullable(),
  payload_json: z.string(),
  payload_hash: Hex64,
  harness_id: idSchema("hns"),
  agent_profile_id: idSchema("agt"),
});

const DeliveryRow = z.object({
  job_id: idSchema("prv"),
  mode: z.enum(["active", "paused"]),
  next_seq: z.number().int().min(1),
  auto_attempts: z.number().int().min(0),
  reconcile_count: z.number().int().min(0),
  lease_token: z.string().nullable(),
  lease_holder: z.string().nullable(),
  lease_until: Ms.nullable(),
});

const TransmissionRow = z.object({
  command_id: idSchema("cmd"),
  job_id: idSchema("prv"),
  seq: z.number().int().min(1),
  harness_id: idSchema("hns"),
  agent_profile_id: idSchema("agt"),
  operation: z.enum(["profile.create", "profile.status", "profile.revoke"]),
  target_operation_id: OperationId.nullable(),
  payload_hash: Hex64,
  key_id: z.string(),
  issued_at: Seconds,
  expires_at: Seconds,
  lease_token: z.string(),
  automatic: z.number().int().min(0).max(1),
  journaled_at: Ms,
  outcome_kind: z.enum(["operation", "refused"]).nullable(),
  refusal_code: Code.nullable(),
  answer_operation_id: OperationId.nullable(),
  operation_state: OperationStateSchema.nullable(),
  failure_code: Code.nullable(),
  owner_bound: z.number().int().min(0).max(1).nullable(),
  principal_id: z.string().nullable(),
  answered_at: Ms.nullable(),
  uncertain_reason: Code.nullable(),
  uncertain_at: Ms.nullable(),
});

const ContextRow = z.object({
  profile_status: z.enum(["pending", "provisioning", "active", "failed", "suspended", "revoked"]),
  profile_updated_at: Ms,
  owner_status: z.enum(["pending", "active", "suspended", "disabled"]),
  owner_updated_at: Ms,
  harness_status: z.enum(["active", "draining", "disabled"]),
  harness_hold: Code.nullable(),
  harness_retired: z.number().int().min(0).max(1),
});

const SiblingRow = z.object({
  id: idSchema("prv"),
  operation: z.string(),
  status: JobStatusSchema,
  operation_id: OperationId.nullable(),
  target_operation_id: OperationId.nullable(),
});

export type JournalJob = z.output<typeof JobRow>;
export type JournalCommand = z.output<typeof CommandRow>;
export type JournalDelivery = z.output<typeof DeliveryRow>;
export type JournalContext = z.output<typeof ContextRow>;
export type JournalSibling = z.output<typeof SiblingRow>;

/** A journaled transmission with whatever Web recorded about it. */
export interface JournalTransmission {
  commandId: string;
  jobId: string;
  seq: number;
  harnessId: string;
  agentProfileId: string;
  operation: "profile.create" | "profile.status" | "profile.revoke";
  targetOperationId: string | null;
  payloadHash: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  automatic: boolean;
  journaledAt: number;
  /** The final §12.4 answer, or null: then the transmission is uncertain, whatever the reason. */
  answer:
    | { kind: "operation"; operationId: string; state: z.output<typeof OperationStateSchema>; failure: string | null; ownerBound: boolean; principalId: string; at: number }
    | { kind: "refused"; code: string; at: number }
    | null;
  uncertain: { reason: string; at: number } | null;
}

function toTransmission(row: unknown): JournalTransmission {
  const r = parseRow(TransmissionRow, row);
  let answer: JournalTransmission["answer"] = null;
  if (r.outcome_kind === "operation" && r.answer_operation_id && r.operation_state && r.principal_id !== null && r.owner_bound !== null && r.answered_at) {
    answer = { kind: "operation", operationId: r.answer_operation_id, state: r.operation_state, failure: r.failure_code, ownerBound: r.owner_bound === 1, principalId: r.principal_id, at: r.answered_at };
  } else if (r.outcome_kind === "refused" && r.refusal_code && r.answered_at) {
    answer = { kind: "refused", code: r.refusal_code, at: r.answered_at };
  }
  return {
    commandId: r.command_id,
    jobId: r.job_id,
    seq: r.seq,
    harnessId: r.harness_id,
    agentProfileId: r.agent_profile_id,
    operation: r.operation,
    targetOperationId: r.target_operation_id,
    payloadHash: r.payload_hash,
    keyId: r.key_id,
    issuedAt: r.issued_at,
    expiresAt: r.expires_at,
    automatic: r.automatic === 1,
    journaledAt: r.journaled_at,
    answer,
    uncertain: r.uncertain_reason && r.uncertain_at ? { reason: r.uncertain_reason, at: r.uncertain_at } : null,
  };
}

export interface JobSnapshot {
  job: JournalJob;
  command: JournalCommand | null;
  delivery: JournalDelivery | null;
  /** This job's journal, by seq (every row, answered or not). */
  transmissions: JournalTransmission[];
  /** For a create: transmissions of revoke jobs addressing its operation (observations only). */
  related: JournalTransmission[];
  context: JournalContext;
  siblings: JournalSibling[];
  /** The journal version this snapshot reasoned over (the pass CAS compares both). */
  version: { nextSeq: number; outcomes: number };
  /** D1 session bookmark of the read (null where the runtime does not provide one). */
  bookmark: string | null;
}

/** What a claim returns: the only thing a sender may sign and send (§13.10 step 5). */
export interface ClaimedTransmission {
  commandId: string;
  jobId: string;
  seq: number;
  operation: "profile.create" | "profile.status" | "profile.revoke";
  targetOperationId: string | null;
  payloadHash: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  leaseToken: string;
  leaseHolder: string;
}

export type RecordedAnswer =
  | { kind: "operation"; operationId: string; state: string; failure: string | null; ownerBound: boolean; principalId: string }
  | { kind: "refused"; code: string };

/** A write in a reconciliation pass, built by the coordinator. */
export type PassWrite =
  | { kind: "observe"; jobId: string; operationId: string; principalId: string; state: string; ownerBound: boolean | null; at: number }
  | { kind: "job-status"; jobId: string; to: string; from: readonly string[]; errorCode: string | null }
  | { kind: "cancel-unsent"; jobId: string }
  | { kind: "attention"; jobId: string; code: string | null }
  | { kind: "next-attempt"; jobId: string; at: number | null }
  | { kind: "delivery-mode"; jobId: string; mode: "active" | "paused" }
  | { kind: "profile-status"; profileId: string; from: string; to: string }
  | { kind: "hold-harness"; harnessId: string; code: string }
  | {
      kind: "open-revoke";
      jobId: string;
      userId: string;
      profileId: string;
      harnessId: string;
      requestId: string;
      idempotencyKey: string;
      targetOperationId: string;
      payloadJson: string;
      payloadHash: string;
    }
  | { kind: "audit"; event: AuditEvent };

export interface OpenJobInput {
  jobId: string;
  userId: string;
  agentProfileId: string;
  harnessId: string;
  operation: "profile.create" | "profile.revoke";
  requestId: string;
  idempotencyKey: string;
  targetOperationId: string | null;
  payloadJson: string;
  payloadHash: string;
  audit: AuditEvent;
}

export class ProvisioningJournalRepository {
  private readonly now: Clock;

  constructor(
    private readonly db: D1Database,
    options: RepositoryOptions = {},
  ) {
    this.now = options.now ?? systemClock;
  }

  /**
   * §13.10 steps 2–3: persist the job, its fixed logical command and its
   * delivery row together (and, for a create, move the profile to
   * provisioning on the job's harness), with the audit event. The command
   * triggers re-check ownership, owner status and harness eligibility.
   */
  async openJob(input: OpenJobInput): Promise<void> {
    const now = this.now();
    const statements = [
      this.db.prepare(INSERT_JOB).bind(input.jobId, input.userId, input.agentProfileId, input.harnessId, input.operation, input.requestId, input.idempotencyKey, input.payloadHash, now),
      this.db
        .prepare(INSERT_COMMAND)
        .bind(input.jobId, input.userId, input.agentProfileId, input.harnessId, input.operation, input.idempotencyKey, input.targetOperationId, input.payloadJson, input.payloadHash, now),
      this.db.prepare(INSERT_DELIVERY).bind(input.jobId, now),
    ];
    if (input.operation === "profile.create") {
      statements.push(this.db.prepare(PROFILE_TO_PROVISIONING).bind(input.agentProfileId, input.harnessId, now, input.jobId));
    }
    statements.push(this.db.prepare(INSERT_AUDIT_IF_COMMAND).bind(...auditRowValues(input.audit), input.jobId));
    await guard(() => this.db.batch(statements));
  }

  /**
   * §13.10 steps 4–5: claim the delivery lease and journal one transmission
   * in one batch. Null when another Worker holds a live lease, the delivery
   * is paused, the job may not send this operation, the harness may receive
   * nothing, or (automatic claims) the job is not due. Only a non-null
   * result may be signed and sent.
   */
  async claim(input: {
    jobId: string;
    commandId: string;
    operation: "profile.create" | "profile.status" | "profile.revoke";
    /** For a status poll: the operation it addresses and its payload hash. */
    statusTarget: { operationId: string; payloadHash: string } | null;
    keyId: string;
    nonceHash: string;
    issuedAt: number;
    expiresAt: number;
    leaseToken: string;
    leaseHolder: string;
    leaseUntil: number;
    automatic: boolean;
  }): Promise<ClaimedTransmission | null> {
    const now = this.now();
    const [, inserted] = await guard(() =>
      this.db.batch([
        this.db
          .prepare(CLAIM_LEASE)
          .bind(input.jobId, input.leaseToken, input.leaseHolder, input.leaseUntil, input.automatic ? 1 : 0, now, input.operation),
        this.db
          .prepare(JOURNAL_TRANSMISSION)
          .bind(
            input.commandId,
            input.jobId,
            input.operation,
            input.statusTarget?.operationId ?? null,
            input.statusTarget?.payloadHash ?? null,
            input.keyId,
            input.nonceHash,
            input.issuedAt,
            input.expiresAt,
            input.automatic ? 1 : 0,
            now,
            input.leaseToken,
          ),
        this.db.prepare(MARK_JOB_SENDING).bind(input.jobId, input.commandId, now),
      ]),
    );
    const row = inserted?.results[0] as { seq: number; target_operation_id: string | null; payload_hash: string } | undefined;
    if (!row) return null;
    return {
      commandId: input.commandId,
      jobId: input.jobId,
      seq: row.seq,
      operation: input.operation,
      targetOperationId: row.target_operation_id,
      payloadHash: row.payload_hash,
      keyId: input.keyId,
      issuedAt: input.issuedAt,
      expiresAt: input.expiresAt,
      leaseToken: input.leaseToken,
      leaseHolder: input.leaseHolder,
    };
  }

  /**
   * §13.10 step 7: persist the answer (final) or the uncertain mark, and
   * release the lease if this claim still holds it. Returns false when the
   * row already had an answer (answers are final), or, for an uncertain
   * mark, any outcome.
   */
  async recordOutcome(
    claim: Pick<ClaimedTransmission, "commandId" | "leaseToken">,
    outcome: RecordedAnswer | { kind: "uncertain"; reason: string },
    recordedBy: string,
  ): Promise<boolean> {
    const now = this.now();
    const write =
      outcome.kind === "uncertain"
        ? this.db.prepare(RECORD_UNCERTAIN).bind(claim.commandId, outcome.reason, recordedBy, now)
        : this.db
            .prepare(RECORD_ANSWER)
            .bind(
              claim.commandId,
              outcome.kind,
              outcome.kind === "refused" ? outcome.code : null,
              outcome.kind === "operation" ? outcome.operationId : null,
              outcome.kind === "operation" ? outcome.state : null,
              outcome.kind === "operation" ? outcome.failure : null,
              outcome.kind === "operation" ? (outcome.ownerBound ? 1 : 0) : null,
              outcome.kind === "operation" ? outcome.principalId : null,
              recordedBy,
              now,
            );
    const [result] = await guard(() => this.db.batch([write, this.db.prepare(RELEASE_LEASE).bind(claim.leaseToken, now)]));
    return (result?.meta.changes ?? 0) === 1;
  }

  /**
   * Lease recovery after a Worker died or stalled: every journaled row of a
   * claim that is no longer live, with nothing recorded, becomes uncertain
   * (never refused, never "not sent"), and expired leases are cleared.
   */
  async recoverLeases(recordedBy: string, limit = 500): Promise<number> {
    const now = this.now();
    const [marked] = await guard(() =>
      this.db.batch([
        this.db.prepare(RECOVER_MARK_UNCERTAIN).bind(now, recordedBy, Math.min(Math.max(limit, 1), 5000)),
        this.db.prepare(RECOVER_CLEAR_LEASES).bind(now),
      ]),
    );
    return marked?.meta.changes ?? 0;
  }

  async transmissionIdentity(commandId: string): Promise<Record<string, unknown> | null> {
    return guard(() => this.db.prepare(SELECT_TRANSMISSION_IDENTITY).bind(commandId).first());
  }

  /**
   * The authoritative read (§13.10 r4): one batch in a `first-primary`
   * session. Every decision that can conclude `failed`, cancel, retire or
   * revoke is made from this snapshot only.
   */
  async snapshot(jobId: string): Promise<JobSnapshot | null> {
    const session = this.primary();
    const results = await guard(() =>
      session.batch([
        session.prepare(SNAPSHOT_JOB).bind(jobId),
        session.prepare(SNAPSHOT_COMMAND).bind(jobId),
        session.prepare(SNAPSHOT_DELIVERY).bind(jobId),
        session.prepare(SNAPSHOT_TRANSMISSIONS).bind(jobId),
        session.prepare(SNAPSHOT_CONTEXT).bind(jobId),
        session.prepare(SNAPSHOT_SIBLINGS).bind(jobId),
        session.prepare(SNAPSHOT_OUTCOME_COUNT).bind(jobId),
      ]),
    );
    const [jobs, commands, deliveries, transmissions, contexts, siblings, counts] = results.map((r) => r.results);
    const jobRow = jobs?.[0];
    const contextRow = contexts?.[0];
    if (!jobRow || !contextRow) return null;
    const job = parseRow(JobRow, jobRow);
    const all = (transmissions ?? []).map(toTransmission);
    const delivery = deliveries?.[0] ? parseRow(DeliveryRow, deliveries[0]) : null;
    return {
      job,
      command: commands?.[0] ? parseRow(CommandRow, commands[0]) : null,
      delivery,
      transmissions: all.filter((t) => t.jobId === jobId),
      related: all.filter((t) => t.jobId !== jobId),
      context: parseRow(ContextRow, contextRow),
      siblings: (siblings ?? []).map((s) => parseRow(SiblingRow, s)),
      version: { nextSeq: delivery?.next_seq ?? 1, outcomes: Number((counts?.[0] as { n?: number } | undefined)?.n ?? 0) },
      bookmark: session.getBookmark(),
    };
  }

  /**
   * Apply one reconciliation decision for `gateJobId`. The first statement
   * succeeds only if the journal still has exactly `version`; all other
   * writes are gated on the token it wrote. Returns false (nothing changed)
   * when the journal moved since the snapshot: the caller re-reads.
   */
  async applyPass(gateJobId: string, version: JobSnapshot["version"], token: string, writes: readonly PassWrite[]): Promise<boolean> {
    const now = this.now();
    const gate = [gateJobId, token] as const;
    const statements = [this.db.prepare(BEGIN_PASS).bind(gateJobId, version.nextSeq, version.outcomes, token, now)];
    for (const w of writes) {
      switch (w.kind) {
        case "observe":
          statements.push(
            this.db.prepare(PASS_OBSERVE).bind(...gate, w.jobId, w.operationId, w.principalId, w.state, w.ownerBound === null ? null : w.ownerBound ? 1 : 0, w.at, now),
          );
          break;
        case "job-status":
          statements.push(this.db.prepare(PASS_JOB_STATUS).bind(...gate, w.jobId, w.to, w.errorCode, now, JSON.stringify(w.from)));
          break;
        case "cancel-unsent":
          statements.push(this.db.prepare(PASS_CANCEL_UNSENT).bind(...gate, w.jobId, now));
          break;
        case "attention":
          statements.push(this.db.prepare(PASS_ATTENTION).bind(...gate, w.jobId, w.code === null ? 0 : 1, w.code, now));
          break;
        case "next-attempt":
          statements.push(this.db.prepare(PASS_NEXT_ATTEMPT).bind(...gate, w.jobId, w.at));
          break;
        case "delivery-mode":
          statements.push(this.db.prepare(PASS_DELIVERY_MODE).bind(...gate, w.jobId, w.mode, now));
          break;
        case "profile-status":
          statements.push(this.db.prepare(PASS_PROFILE_STATUS).bind(...gate, w.profileId, w.to, now, w.from));
          break;
        case "hold-harness":
          statements.push(this.db.prepare(PASS_HOLD_HARNESS).bind(...gate, w.harnessId, w.code, now));
          break;
        case "open-revoke":
          statements.push(
            this.db
              .prepare(PASS_INSERT_REVOKE_JOB)
              .bind(...gate, w.jobId, w.userId, w.profileId, w.harnessId, w.requestId, w.idempotencyKey, w.payloadHash, now),
            this.db
              .prepare(INSERT_COMMAND)
              .bind(w.jobId, w.userId, w.profileId, w.harnessId, "profile.revoke", w.idempotencyKey, w.targetOperationId, w.payloadJson, w.payloadHash, now),
            this.db.prepare(INSERT_DELIVERY).bind(w.jobId, now),
          );
          break;
        case "audit":
          statements.push(this.db.prepare(PASS_AUDIT).bind(...gate, ...auditRowValues(w.event)));
          break;
      }
    }
    const [begin] = await guard(() => this.db.batch(statements));
    return (begin?.results.length ?? 0) === 1;
  }

  /** Unresolved jobs due for work (scheduling only; not authoritative). */
  async dueJobs(limit = 50): Promise<string[]> {
    const { results } = await guard(() => this.db.prepare(SELECT_DUE).bind(this.now(), Math.min(Math.max(limit, 1), 500)).all<{ id: string }>());
    return results.map((r) => r.id);
  }

  /** R6 level-triggered selection: settled creates that still owe a revoke or a confirmation. */
  async absentObligations(limit = 50): Promise<string[]> {
    const { results } = await guard(() =>
      this.db.prepare(SELECT_ABSENT_OBLIGATIONS).bind(this.now(), Math.min(Math.max(limit, 1), 500)).all<{ id: string }>(),
    );
    return results.map((r) => r.id);
  }

  /** Jobs created before migration 0003 have no fixed command and can never be sent; flag each once. */
  async flagLegacyJobs(limit = 50): Promise<string[]> {
    const { results } = await guard(() => this.db.prepare(SELECT_LEGACY_JOBS).bind(Math.min(Math.max(limit, 1), 500)).all<{ id: string }>());
    const flagged: string[] = [];
    for (const { id } of results) {
      const row = await guard(() => this.db.prepare(FLAG_LEGACY_JOB).bind(id, this.now()).first<{ id: string }>());
      if (row) flagged.push(row.id);
    }
    return flagged;
  }

  /** Operator view: jobs needing attention. Ids, states and codes only. */
  async attention(input: { harnessId?: string | null; limit?: number } = {}): Promise<Array<Record<string, unknown>>> {
    const { results } = await guard(() =>
      this.db
        .prepare(SELECT_ATTENTION)
        .bind(input.harnessId ?? null, Math.min(Math.max(input.limit ?? 50, 1), 200))
        .all<Record<string, unknown>>(),
    );
    return results;
  }

  /** A D1 session whose first read goes to the primary (§13.10 r4). */
  private primary(): D1DatabaseSession {
    return this.db.withSession("first-primary");
  }
}
