/**
 * Storage for operator actions (used only by src/operator; the Worker never
 * imports this module).
 *
 * Each change is one D1 batch, which D1 runs as a transaction: the audit row
 * is inserted only if the same guard that the change uses still holds, so
 * the change and its audit record are written together or not at all.
 * All SQL is constant; values are bound.
 */
import type { AuditEvent } from "../audit/audit";
import { auditRowValues } from "./audit";
import { guard } from "./errors";

const INSERT_AUDIT_IF_USER_STATUS = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
  WHERE EXISTS (SELECT 1 FROM user_profiles WHERE id = ?13 AND status = ?14)`;

const UPDATE_USER_STATUS = `UPDATE user_profiles SET status = ?1, updated_at = ?2 WHERE id = ?3 AND status = ?4 RETURNING id`;

const INSERT_AUDIT = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`;

const COUNT_USER_SESSIONS = `SELECT COUNT(*) AS n FROM session WHERE "userId" = ?1`;
const DELETE_USER_SESSIONS = `DELETE FROM session WHERE "userId" = ?1 RETURNING id`;
const COUNT_ALL_SESSIONS = `SELECT COUNT(*) AS n FROM session`;
const DELETE_ALL_SESSIONS = `DELETE FROM session RETURNING id`;

const FIND_PASSKEY = `SELECT id, name, "credentialID" FROM passkey WHERE id = ?1 AND "userId" = ?2`;
const LIST_PASSKEYS = `SELECT id, name, "credentialID", "createdAt" FROM passkey WHERE "userId" = ?1 ORDER BY "createdAt"`;
const INSERT_AUDIT_IF_PASSKEY = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
  WHERE EXISTS (SELECT 1 FROM passkey WHERE id = ?13 AND "userId" = ?14)`;
const DELETE_PASSKEY = `DELETE FROM passkey WHERE id = ?1 AND "userId" = ?2 RETURNING id`;

const USER_AUTH_SUMMARY = `SELECT
  (SELECT json_group_array(DISTINCT "providerId") FROM account WHERE "userId" = ?1) AS providers,
  (SELECT COUNT(*) FROM passkey WHERE "userId" = ?1) AS passkeys,
  (SELECT COUNT(*) FROM session WHERE "userId" = ?1) AS sessions`;

export interface StoredPasskey {
  id: string;
  name: string | null;
  credentialID: string;
  createdAt?: string | null;
}

export class AdminRepository {
  constructor(private readonly db: D1Database) {}

  /** Change status `from` → `to` and record `event`, atomically. False if the status was no longer `from`. */
  async transitionWithAudit(event: AuditEvent, input: { userId: string; from: string; to: string; updatedAt: number }): Promise<boolean> {
    const [, update] = await guard(() =>
      this.db.batch([
        this.db.prepare(INSERT_AUDIT_IF_USER_STATUS).bind(...auditRowValues(event), input.userId, input.from),
        this.db.prepare(UPDATE_USER_STATUS).bind(input.to, input.updatedAt, input.userId, input.from),
      ]),
    );
    return update?.results.length === 1;
  }

  /** Record one audit event (used for refusals). Throws if it cannot be stored. */
  async recordAudit(event: AuditEvent): Promise<void> {
    await guard(() => this.db.prepare(INSERT_AUDIT).bind(...auditRowValues(event)).run());
  }

  async countUserSessions(authUserId: string): Promise<number> {
    return (await guard(() => this.db.prepare(COUNT_USER_SESSIONS).bind(authUserId).first<{ n: number }>()))?.n ?? 0;
  }

  /** Delete every session of one auth user and record `event`, atomically. Returns how many were deleted. */
  async deleteUserSessionsWithAudit(event: AuditEvent, authUserId: string): Promise<number> {
    const [, deleted] = await guard(() =>
      this.db.batch([this.db.prepare(INSERT_AUDIT).bind(...auditRowValues(event)), this.db.prepare(DELETE_USER_SESSIONS).bind(authUserId)]),
    );
    return deleted?.results.length ?? 0;
  }

  async countAllSessions(): Promise<number> {
    return (await guard(() => this.db.prepare(COUNT_ALL_SESSIONS).first<{ n: number }>()))?.n ?? 0;
  }

  /** Delete every session of every user and record `event`, atomically. */
  async deleteAllSessionsWithAudit(event: AuditEvent): Promise<number> {
    const [, deleted] = await guard(() => this.db.batch([this.db.prepare(INSERT_AUDIT).bind(...auditRowValues(event)), this.db.prepare(DELETE_ALL_SESSIONS)]));
    return deleted?.results.length ?? 0;
  }

  async findPasskey(passkeyId: string, authUserId: string): Promise<StoredPasskey | null> {
    return guard(() => this.db.prepare(FIND_PASSKEY).bind(passkeyId, authUserId).first<StoredPasskey>());
  }

  async listPasskeys(authUserId: string): Promise<StoredPasskey[]> {
    return (await guard(() => this.db.prepare(LIST_PASSKEYS).bind(authUserId).all<StoredPasskey>())).results;
  }

  /** Delete one passkey of one auth user and record `event`, atomically. False if it was already gone. */
  async deletePasskeyWithAudit(event: AuditEvent, passkeyId: string, authUserId: string): Promise<boolean> {
    const [, deleted] = await guard(() =>
      this.db.batch([
        this.db.prepare(INSERT_AUDIT_IF_PASSKEY).bind(...auditRowValues(event), passkeyId, authUserId),
        this.db.prepare(DELETE_PASSKEY).bind(passkeyId, authUserId),
      ]),
    );
    return deleted?.results.length === 1;
  }

  /** Sign-in methods and counts for one auth user (no emails or provider account ids). */
  async authSummary(authUserId: string): Promise<{ providers: string[]; passkeys: number; sessions: number }> {
    const row = await guard(() => this.db.prepare(USER_AUTH_SUMMARY).bind(authUserId).first<{ providers: string; passkeys: number; sessions: number }>());
    const providers = (JSON.parse(row?.providers ?? "[]") as unknown[]).filter((p): p is string => p === "google" || p === "github");
    return { providers, passkeys: row?.passkeys ?? 0, sessions: row?.sessions ?? 0 };
  }
}
