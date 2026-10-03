/**
 * Provisioning jobs: persistence for signed control commands.
 *
 * Idempotency contract (enforced atomically, never read-then-insert):
 *   same key + same request (hash, user, profile, harness, operation)
 *     → the existing job is returned (`created: false`)
 *   same key + anything different
 *     → IdempotencyConflictError
 * A unique partial index also allows at most one in-flight job per profile
 * and operation.
 */
import { z } from "../../shared/zod";
import { randomId } from "../utils/random";
import { type Clock, NullableTimestamp, parseRow, type RepositoryOptions, systemClock, Timestamp, idSchema } from "./common";
import { guard, IdempotencyConflictError, InvalidTransitionError, NotFoundError, UniqueConflictError } from "./errors";
import { PROVISIONING_OPERATIONS, type ProvisioningOperation } from "./json";

export const JOB_STATUSES = ["pending", "sending", "accepted", "completed", "failed", "cancelled"] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

/** Allowed status changes; mirrored by the provisioning_jobs_status_transition trigger. */
export const JOB_TRANSITIONS: Readonly<Record<JobStatus, readonly JobStatus[]>> = {
  pending: ["sending", "cancelled", "failed"],
  // sending → pending: a retryable transport failure, before any retry.
  sending: ["pending", "accepted", "completed", "failed"],
  accepted: ["completed", "failed"],
  completed: [],
  failed: [],
  cancelled: [],
};

export const TERMINAL_JOB_STATUSES: readonly JobStatus[] = ["completed", "failed", "cancelled"];
export const MAX_ATTEMPTS = 10;

const JobRow = z.object({
  id: idSchema("prv"),
  user_id: idSchema("usr"),
  agent_profile_id: idSchema("agt"),
  harness_id: idSchema("hns"),
  operation: z.enum(PROVISIONING_OPERATIONS),
  request_id: idSchema("req"),
  idempotency_key: z.string().min(16).max(128),
  request_hash: z.string().regex(/^[0-9a-f]{64}$/),
  status: z.enum(JOB_STATUSES),
  attempt_count: z.number().int().min(0).max(MAX_ATTEMPTS),
  error_code: z.string().max(64).nullable(),
  created_at: Timestamp,
  updated_at: Timestamp,
  completed_at: NullableTimestamp,
});

export interface ProvisioningJob {
  id: string;
  userId: string;
  agentProfileId: string;
  harnessId: string;
  operation: ProvisioningOperation;
  requestId: string;
  idempotencyKey: string;
  requestHash: string;
  status: JobStatus;
  attemptCount: number;
  errorCode: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
}

function toJob(row: unknown): ProvisioningJob {
  const r = parseRow(JobRow, row);
  return {
    id: r.id,
    userId: r.user_id,
    agentProfileId: r.agent_profile_id,
    harnessId: r.harness_id,
    operation: r.operation,
    requestId: r.request_id,
    idempotencyKey: r.idempotency_key,
    requestHash: r.request_hash,
    status: r.status,
    attemptCount: r.attempt_count,
    errorCode: r.error_code,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    completedAt: r.completed_at,
  };
}

export const NewJobSchema = z
  .object({
    userId: idSchema("usr"),
    agentProfileId: idSchema("agt"),
    harnessId: idSchema("hns"),
    operation: z.enum(PROVISIONING_OPERATIONS),
    requestId: idSchema("req"),
    idempotencyKey: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/),
    requestHash: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();
export type NewJob = z.input<typeof NewJobSchema>;

const ErrorCode = z.string().regex(/^[A-Z0-9_]{1,64}$/);

function sameRequest(job: ProvisioningJob, input: z.output<typeof NewJobSchema>): boolean {
  return (
    job.requestHash === input.requestHash &&
    job.userId === input.userId &&
    job.agentProfileId === input.agentProfileId &&
    job.harnessId === input.harnessId &&
    job.operation === input.operation
  );
}

export class ProvisioningJobRepository {
  private readonly now: Clock;

  constructor(
    private readonly db: D1Database,
    options: RepositoryOptions = {},
  ) {
    this.now = options.now ?? systemClock;
  }

  /**
   * Create a job, or return the existing job for the same idempotency key
   * and identical request. Throws IdempotencyConflictError when the key was
   * used for a different request, and UniqueConflictError when another job
   * for this profile/operation is already in flight.
   */
  async createOrGet(input: NewJob): Promise<{ job: ProvisioningJob; created: boolean }> {
    const job = NewJobSchema.parse(input);
    const now = this.now();
    const inserted = await guard(() =>
      this.db
        .prepare(
          `INSERT INTO provisioning_jobs
             (id, user_id, agent_profile_id, harness_id, operation, request_id, idempotency_key, request_hash,
              status, attempt_count, created_at, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?9)
           ON CONFLICT (idempotency_key) DO NOTHING
           RETURNING *`,
        )
        .bind(randomId("prv"), job.userId, job.agentProfileId, job.harnessId, job.operation, job.requestId, job.idempotencyKey, job.requestHash, now)
        .first(),
    );
    if (inserted) return { job: toJob(inserted), created: true };

    const existing = await this.getByIdempotencyKeyTrusted(job.idempotencyKey);
    if (!existing) {
      // The insert lost to a concurrent delete or similar; treat as a conflict.
      throw new UniqueConflictError("provisioning_jobs.idempotency_key");
    }
    if (!sameRequest(existing, job)) throw new IdempotencyConflictError();
    return { job: existing, created: false };
  }

  async getByIdempotencyKeyTrusted(idempotencyKey: string): Promise<ProvisioningJob | null> {
    const row = await guard(() =>
      this.db.prepare(`SELECT * FROM provisioning_jobs WHERE idempotency_key = ?1`).bind(idempotencyKey).first(),
    );
    return row ? toJob(row) : null;
  }

  async getByIdTrusted(jobId: string): Promise<ProvisioningJob | null> {
    const row = await guard(() => this.db.prepare(`SELECT * FROM provisioning_jobs WHERE id = ?1`).bind(jobId).first());
    return row ? toJob(row) : null;
  }

  /** A job only if it belongs to `userId` (status views). */
  async getForUser(jobId: string, userId: string): Promise<ProvisioningJob | null> {
    const row = await guard(() =>
      this.db.prepare(`SELECT * FROM provisioning_jobs WHERE id = ?1 AND user_id = ?2`).bind(jobId, userId).first(),
    );
    return row ? toJob(row) : null;
  }

  /** Most recent job for an owned profile, or null. */
  async latestForProfileOfUser(agentProfileId: string, userId: string): Promise<ProvisioningJob | null> {
    const row = await guard(() =>
      this.db
        .prepare(
          `SELECT * FROM provisioning_jobs WHERE agent_profile_id = ?1 AND user_id = ?2
           ORDER BY created_at DESC, id DESC LIMIT 1`,
        )
        .bind(agentProfileId, userId)
        .first(),
    );
    return row ? toJob(row) : null;
  }

  /**
   * Move a job to `to` atomically. Entering `sending` increments
   * attempt_count; terminal states set completed_at; `failed` needs an error
   * code.
   */
  async transitionTrusted(jobId: string, to: JobStatus, options: { errorCode?: string } = {}): Promise<ProvisioningJob> {
    const errorCode = options.errorCode === undefined ? null : ErrorCode.parse(options.errorCode);
    if (to === "failed" && errorCode === null) throw new InvalidTransitionError("provisioning_job", "unknown", "failed");
    const from = JOB_STATUSES.filter((s) => JOB_TRANSITIONS[s].includes(to));
    const now = this.now();
    const row = await guard(() =>
      this.db
        .prepare(
          `UPDATE provisioning_jobs
              SET status = ?1,
                  updated_at = ?2,
                  attempt_count = attempt_count + (CASE WHEN ?1 = 'sending' THEN 1 ELSE 0 END),
                  completed_at = CASE WHEN ?1 IN ('completed', 'failed', 'cancelled') THEN ?2 ELSE NULL END,
                  error_code = COALESCE(?3, error_code)
            WHERE id = ?4
              AND status IN (SELECT value FROM json_each(?5))
              AND (?1 <> 'sending' OR attempt_count < ?6)
           RETURNING *`,
        )
        .bind(to, now, errorCode, jobId, JSON.stringify(from), MAX_ATTEMPTS)
        .first(),
    );
    if (row) return toJob(row);
    const current = await this.getByIdTrusted(jobId);
    if (!current) throw new NotFoundError("provisioning_job");
    throw new InvalidTransitionError("provisioning_job", current.status, to);
  }
}
