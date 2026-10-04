/**
 * Durable audit storage and the recording policy.
 *
 * `AuditRecorder.required` is fail-closed: if the event cannot be stored the
 * operation must not proceed (INTERNAL_ERROR). Use it for operations whose
 * record is part of their security contract: administrative permission or
 * role changes, harness registration/disable, provisioning initiation,
 * account suspension, signing-key changes.
 *
 * `AuditRecorder.bestEffort` never fails the request: a storage failure is
 * logged together with the (already validated, secret-free) event so the
 * record survives in Workers Logs. Use it for high-volume or read-adjacent
 * events: login success/failure, origin rejections, rate-limit hits,
 * passkey/session listing.
 */
import { createAuditEvent, LogAuditSink, type AuditEvent, type AuditEventInput, type AuditSink } from "../audit/audit";
import { ApiError } from "../http/errors";
import type { Logger } from "../utils/log";
import { describeError } from "../utils/log";
import { z } from "../../shared/zod";
import { idSchema, parseRow } from "./common";
import { guard } from "./errors";
import { decodeJson, encodeJson, JSON_LIMITS, SecurityMetadataSchema } from "./json";

const DetailsSchema = z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()]));

const INSERT_AUDIT = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`;

/** The 12 values of one audit_events row, in column order (validated, size-bounded JSON). */
export function auditRowValues(event: AuditEvent): Array<string | number | null> {
  return [
    event.id,
    Date.parse(event.timestamp),
    event.actor.type,
    event.actor.type === "anonymous" ? null : event.actor.id,
    event.action,
    event.target?.type ?? null,
    event.target?.id ?? null,
    event.requestId,
    event.result,
    event.reason ?? null,
    encodeJson(SecurityMetadataSchema, event.security, JSON_LIMITS.securityMetadata),
    encodeJson(DetailsSchema, event.metadata, JSON_LIMITS.auditDetails),
  ];
}

export class D1AuditSink implements AuditSink {
  constructor(private readonly db: D1Database) {}

  async record(event: AuditEvent): Promise<void> {
    await guard(() =>
      this.db
        .prepare(INSERT_AUDIT)
        .bind(...auditRowValues(event))
        .run(),
    );
  }
}

export class AuditRecorder {
  private readonly fallback: LogAuditSink;

  constructor(
    private readonly sink: AuditSink,
    private readonly logger: Logger,
  ) {
    this.fallback = new LogAuditSink(logger);
  }

  /** Store the event or throw INTERNAL_ERROR; the caller must not proceed on failure. */
  async required(input: AuditEventInput): Promise<AuditEvent> {
    const event = createAuditEvent(input);
    try {
      await this.sink.record(event);
    } catch (error) {
      this.logger.error("audit.write_failed", { mode: "required", action: event.action, ...describeError(error) });
      await this.fallback.record(event);
      throw new ApiError("INTERNAL_ERROR", { logReason: "required audit write failed", cause: error });
    }
    return event;
  }

  /** Store the event in the background; failures are logged, never thrown. */
  bestEffort(input: AuditEventInput, waitUntil: (promise: Promise<unknown>) => void): AuditEvent {
    const event = createAuditEvent(input);
    waitUntil(
      this.sink.record(event).catch(async (error: unknown) => {
        this.logger.error("audit.write_failed", { mode: "best_effort", action: event.action, ...describeError(error) });
        await this.fallback.record(event);
      }),
    );
    return event;
  }
}

const AuditRow = z.object({
  id: idSchema("aud"),
  timestamp: z.number().int().positive(),
  actor_type: z.enum(["user", "admin", "system", "anonymous"]),
  actor_id: z.string().nullable(),
  action: z.string(),
  target_type: z.string().nullable(),
  target_id: z.string().nullable(),
  request_id: z.string(),
  result: z.enum(["success", "failure", "denied"]),
  reason: z.string().nullable(),
  security_metadata_json: z.string(),
  details_json: z.string(),
});

/** A stored event as shown in a user's security activity. */
export interface StoredAuditEvent {
  id: string;
  timestamp: number;
  action: string;
  result: "success" | "failure" | "denied";
  reason: string | null;
  targetType: string | null;
  targetId: string | null;
  requestId: string;
  country: string | null;
}

/** Read access to the audit log. */
export class AuditRepository {
  constructor(private readonly db: D1Database) {}

  /** Recent events the user performed (their security activity). */
  async listForUser(userId: string, limit = 50): Promise<StoredAuditEvent[]> {
    const { results } = await guard(() =>
      this.db
        .prepare(
          `SELECT * FROM audit_events WHERE actor_type = 'user' AND actor_id = ?1
           ORDER BY timestamp DESC, id DESC LIMIT ?2`,
        )
        .bind(userId, Math.min(Math.max(limit, 1), 100))
        .all(),
    );
    return results.map((row) => {
      const r = parseRow(AuditRow, row);
      const security = decodeJson(SecurityMetadataSchema, r.security_metadata_json);
      return {
        id: r.id,
        timestamp: r.timestamp,
        action: r.action,
        result: r.result,
        reason: r.reason,
        targetType: r.target_type,
        targetId: r.target_id,
        requestId: r.request_id,
        country: security.country ?? null,
      };
    });
  }

  /** Internal: count events from one keyed source hash since `since` ("same source"). */
  async countBySourceTrusted(sourceHash: string, since: number): Promise<number> {
    const row = await guard(() =>
      this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM audit_events
           WHERE json_extract(security_metadata_json, '$.sourceHash') = ?1 AND timestamp >= ?2`,
        )
        .bind(sourceHash, since)
        .first<{ n: number }>(),
    );
    return row?.n ?? 0;
  }
}
