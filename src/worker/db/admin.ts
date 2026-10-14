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

// R6 (PROVISIONING_PROTOCOL §13.5): suspending or disabling an account makes
// the desired state of every profile "absent" in the same transaction. A
// revoked profile is terminal, so reactivation (or a create that completes
// late) can never make it usable again. This withdraws Web access only;
// harness bindings are revoked by the reconciler's revoke jobs, and a profile
// counts as unbound on the harness only once its revoke job completed.
const INSERT_AUDIT_IF_LIVE_PROFILES = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
  WHERE EXISTS (SELECT 1 FROM agent_profiles WHERE user_id = ?13 AND status <> 'revoked')
    AND EXISTS (SELECT 1 FROM user_profiles WHERE id = ?13 AND status IN ('suspended', 'disabled'))`;
const REVOKE_OWNER_PROFILES = `UPDATE agent_profiles
  SET status = 'revoked', revocation_version = revocation_version + 1, updated_at = MAX(updated_at, ?2)
  WHERE user_id = ?1 AND status <> 'revoked'
    AND EXISTS (SELECT 1 FROM user_profiles WHERE id = ?1 AND status IN ('suspended', 'disabled'))
  RETURNING id`;

const SELECT_HARNESS = `SELECT h.id, h.environment, h.status, h.provisioning_hold,
       (SELECT reason_code FROM harness_retirements r WHERE r.harness_id = h.id) AS retired_reason,
       (SELECT retired_harness_id FROM harness_replacements x WHERE x.replacement_harness_id = h.id) AS replaces,
       (SELECT COUNT(*) FROM provisioning_jobs j WHERE j.harness_id = h.id AND j.status IN ('pending', 'sending', 'accepted')) AS unresolved_jobs,
       (SELECT COUNT(*) FROM provisioning_jobs j WHERE j.harness_id = h.id AND j.needs_attention = 1) AS attention_jobs
  FROM harnesses h WHERE h.id = ?1`;
const DISABLE_HARNESS = `UPDATE harnesses SET status = 'disabled', updated_at = MAX(updated_at, ?2) WHERE id = ?1 RETURNING id`;
const INSERT_RETIREMENT = `INSERT INTO harness_retirements (harness_id, reason_code, retired_by, operation_id, retired_at) VALUES (?1, ?2, ?3, ?4, ?5)`;
const INSERT_REPLACEMENT = `INSERT INTO harness_replacements (replacement_harness_id, retired_harness_id, approved_by, operation_id, approved_at)
  VALUES (?1, ?2, ?3, ?4, ?5)`;
const INSERT_AUDIT_IF_HOLD = `INSERT INTO audit_events
  (id, timestamp, actor_type, actor_id, action, target_type, target_id, request_id, result, reason, security_metadata_json, details_json)
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
  WHERE EXISTS (SELECT 1 FROM harnesses WHERE id = ?13 AND provisioning_hold IS NOT NULL)
    AND NOT EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = ?13)`;
const RELEASE_HOLD = `UPDATE harnesses SET provisioning_hold = NULL, provisioning_hold_at = NULL
  WHERE id = ?1 AND provisioning_hold IS NOT NULL AND NOT EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = ?1)
  RETURNING id`;

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

export interface HarnessSummary {
  id: string;
  environment: string;
  status: string;
  provisioning_hold: string | null;
  retired_reason: string | null;
  replaces: string | null;
  unresolved_jobs: number;
  attention_jobs: number;
}

export class AdminRepository {
  constructor(private readonly db: D1Database) {}

  /**
   * Change status `from` → `to` and record `event`, atomically. False if the
   * status was no longer `from`. When `profilesEvent` is given (suspend,
   * disable), every non-revoked profile of the user is revoked in the same
   * transaction and that event records it (only if there were any).
   */
  async transitionWithAudit(
    event: AuditEvent,
    input: { userId: string; from: string; to: string; updatedAt: number },
    profilesEvent?: AuditEvent,
  ): Promise<{ changed: boolean; profilesRevoked: number }> {
    const statements = [
      this.db.prepare(INSERT_AUDIT_IF_USER_STATUS).bind(...auditRowValues(event), input.userId, input.from),
      this.db.prepare(UPDATE_USER_STATUS).bind(input.to, input.updatedAt, input.userId, input.from),
    ];
    if (profilesEvent) {
      statements.push(
        this.db.prepare(INSERT_AUDIT_IF_LIVE_PROFILES).bind(...auditRowValues(profilesEvent), input.userId),
        this.db.prepare(REVOKE_OWNER_PROFILES).bind(input.userId, input.updatedAt),
      );
    }
    const results = await guard(() => this.db.batch(statements));
    return { changed: results[1]?.results.length === 1, profilesRevoked: results[3]?.results.length ?? 0 };
  }

  async harnessSummary(harnessId: string): Promise<HarnessSummary | null> {
    return guard(() => this.db.prepare(SELECT_HARNESS).bind(harnessId).first<HarnessSummary>());
  }

  /** Disable and retire a harness id for good, with `event`, atomically (§10.6). */
  async retireHarnessWithAudit(event: AuditEvent, input: { harnessId: string; reasonCode: string; operatorId: string; operationId: string; at: number }): Promise<void> {
    await guard(() =>
      this.db.batch([
        this.db.prepare(INSERT_AUDIT).bind(...auditRowValues(event)),
        this.db.prepare(DISABLE_HARNESS).bind(input.harnessId, input.at),
        this.db.prepare(INSERT_RETIREMENT).bind(input.harnessId, input.reasonCode, input.operatorId, input.operationId, input.at),
      ]),
    );
  }

  /** Record that `replacementId` (a new, disabled harness) may replace the retired `retiredId`. */
  async approveReplacementWithAudit(event: AuditEvent, input: { replacementId: string; retiredId: string; operatorId: string; operationId: string; at: number }): Promise<void> {
    await guard(() =>
      this.db.batch([
        this.db.prepare(INSERT_AUDIT).bind(...auditRowValues(event)),
        this.db.prepare(INSERT_REPLACEMENT).bind(input.replacementId, input.retiredId, input.operatorId, input.operationId, input.at),
      ]),
    );
  }

  /** Lift a LEDGER_CONTINUITY_FAILED circuit break. False if there was none (or the harness is retired). */
  async releaseHoldWithAudit(event: AuditEvent, harnessId: string): Promise<boolean> {
    const [, released] = await guard(() =>
      this.db.batch([this.db.prepare(INSERT_AUDIT_IF_HOLD).bind(...auditRowValues(event), harnessId), this.db.prepare(RELEASE_HOLD).bind(harnessId)]),
    );
    return released?.results.length === 1;
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
