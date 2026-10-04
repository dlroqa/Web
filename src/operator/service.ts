/**
 * Operator service: the only supported way to change an account's status,
 * revoke a user's sessions, or remove a passkey on someone's behalf.
 *
 * Narrow by design: a fixed set of named operations, each with validated
 * inputs. There is no SQL passthrough, row editor, or role change, and no
 * HTTP route reaches this module (the Worker never imports src/operator).
 *
 * Every mutating operation:
 *   1. requires an operator actor (requireOperator)
 *   2. names its target by application user id (usr_…)
 *   3. checks the transition against USER_TRANSITIONS (also a DB trigger)
 *   4. runs as ONE D1 batch (a transaction, see db/admin.ts): the audit row
 *      and the change share a guard, so either both happen or neither does
 *   5. records an `admin.*` audit event with the operator's reason and the
 *      operation id; refusals are audited too (result "denied")
 *   6. returns a sanitized result: ids, statuses, counts. No email, no
 *      tokens, no credential ids.
 */
import { createAuditEvent, type AuditAction, type AuditEvent, type AuditEventInput } from "../worker/audit/audit";
import { passkeyAuditFields, passkeyFingerprint } from "../worker/auth/passkey-audit";
import { AdminRepository } from "../worker/db/admin";
import { idSchema } from "../worker/db/common";
import { USER_TRANSITIONS, UserRepository, type UserProfile, type UserStatus } from "../worker/db/users";
import { VerificationRepository } from "../worker/db/verifications";
import { randomId } from "../worker/utils/random";
import { requireMaintenanceActor, requireOperator, type Actor, type OperatorActor } from "./actors";

export type StatusOperation = "approve" | "suspend" | "reactivate" | "disable";

/** Each operation's allowed source states, target state, and audit action. */
export const STATUS_OPERATIONS: Readonly<Record<StatusOperation, { from: readonly UserStatus[]; to: UserStatus; action: AuditAction }>> = {
  approve: { from: ["pending"], to: "active", action: "admin.user.approve" },
  suspend: { from: ["active"], to: "suspended", action: "admin.user.suspend" },
  reactivate: { from: ["suspended"], to: "active", action: "admin.user.reactivate" },
  disable: { from: ["pending", "active", "suspended"], to: "disabled", action: "admin.user.disable" },
};

export type OperatorErrorCode = "INVALID_INPUT" | "NOT_FOUND" | "INVALID_TRANSITION" | "CONFLICT" | "CONFIRMATION_REQUIRED";

/** A refusal with a stable code and a message safe to print. */
export class OperatorError extends Error {
  override readonly name = "OperatorError";
  constructor(
    readonly code: OperatorErrorCode,
    message: string,
  ) {
    super(message);
  }
}

const UserId = idSchema("usr");
const OperationId = idSchema("op");
const PasskeyId = /^[A-Za-z0-9_-]{8,64}$/;
const EMAIL_LIKE = /[^\s@]+@[^\s@]+\.[^\s@]+/;

/** The operator's reason: 3–200 printable characters and no email addresses. */
export function validateReason(reason: unknown): string {
  if (typeof reason !== "string") throw new OperatorError("INVALID_INPUT", "a --reason is required");
  const trimmed = reason.trim();
  if (trimmed.length < 3 || trimmed.length > 200) throw new OperatorError("INVALID_INPUT", "the reason must be 3–200 characters");
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) throw new OperatorError("INVALID_INPUT", "the reason may not contain control characters");
  if (EMAIL_LIKE.test(trimmed)) throw new OperatorError("INVALID_INPUT", "do not put email addresses in the reason; use the usr_… id");
  return trimmed;
}

function validateUserId(userId: unknown): string {
  if (typeof userId !== "string" || !UserId.safeParse(userId).success) throw new OperatorError("INVALID_INPUT", "--user must be an application user id (usr_…)");
  return userId;
}

function validateOperationId(operationId: unknown): string {
  if (operationId === undefined) return randomId("op");
  if (typeof operationId !== "string" || !OperationId.safeParse(operationId).success) throw new OperatorError("INVALID_INPUT", "the operation id must look like op_…");
  return operationId;
}

export interface OperationInput {
  userId: string;
  reason: string;
  /** Generated when omitted; recorded as the audit event's request id. */
  operationId?: string;
}

export interface StatusChangeResult {
  operationId: string;
  auditEventId: string;
  userId: string;
  from: UserStatus;
  to: UserStatus;
}

export interface SanitizedUser {
  id: string;
  status: UserStatus;
  createdAt: string;
  updatedAt: string;
  providers: string[];
  passkeys: number;
  sessions: number;
}

export interface SanitizedPasskey {
  id: string;
  name: string | null;
  fingerprint: string | null;
  createdAt: string | null;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export class OperatorService {
  private readonly users: UserRepository;
  private readonly admin: AdminRepository;
  private readonly verifications: VerificationRepository;
  private readonly now: () => Date;

  constructor(db: D1Database, options: { now?: () => Date } = {}) {
    this.now = options.now ?? (() => new Date());
    this.users = new UserRepository(db, { now: () => this.now().getTime() });
    this.admin = new AdminRepository(db);
    this.verifications = new VerificationRepository(db);
  }

  private event(operator: OperatorActor, input: Omit<AuditEventInput, "actor">): AuditEvent {
    return createAuditEvent({ ...input, actor: { type: "admin", id: operator.operatorId } }, this.now);
  }

  /** Record a refused operation (fail closed: if this write fails, the error propagates). */
  private async recordDenial(operator: OperatorActor, input: Omit<AuditEventInput, "actor" | "result">): Promise<void> {
    await this.admin.recordAudit(this.event(operator, { ...input, result: "denied" }));
  }

  private async requireUser(operator: OperatorActor, action: AuditAction, userId: string, operationId: string, reason: string): Promise<UserProfile> {
    const user = await this.users.getById(userId);
    if (user) return user;
    await this.recordDenial(operator, { action, target: { type: "user", id: userId }, requestId: operationId, reason: "NOT_FOUND", metadata: { reason, channel: operator.channel } });
    throw new OperatorError("NOT_FOUND", `no application user ${userId}`);
  }

  /** approve / suspend / reactivate / disable: one atomic, audited transition. */
  async changeStatus(actor: Actor, operation: StatusOperation, input: OperationInput): Promise<StatusChangeResult> {
    const operator = requireOperator(actor);
    const spec = STATUS_OPERATIONS[operation];
    if (!spec) throw new OperatorError("INVALID_INPUT", "unknown operation");
    const userId = validateUserId(input.userId);
    const reason = validateReason(input.reason);
    const operationId = validateOperationId(input.operationId);
    const user = await this.requireUser(operator, spec.action, userId, operationId, reason);

    const from = user.status;
    if (!spec.from.includes(from) || !USER_TRANSITIONS[from].includes(spec.to)) {
      await this.recordDenial(operator, {
        action: spec.action,
        target: { type: "user", id: userId },
        requestId: operationId,
        reason: "CONFLICT",
        metadata: { reason, from, to: spec.to, channel: operator.channel },
      });
      throw new OperatorError("INVALID_TRANSITION", `cannot ${operation} a ${from} account`);
    }

    const event = this.event(operator, {
      action: spec.action,
      target: { type: "user", id: userId },
      requestId: operationId,
      result: "success",
      metadata: { reason, from, to: spec.to, channel: operator.channel },
    });
    const changed = await this.admin.transitionWithAudit(event, { userId, from, to: spec.to, updatedAt: Math.max(this.now().getTime(), user.createdAt) });
    if (!changed) {
      // The status changed between the read and the transaction; neither write happened.
      throw new OperatorError("CONFLICT", "the account changed concurrently; nothing was modified, retry");
    }
    return { operationId, auditEventId: event.id, userId, from, to: spec.to };
  }

  /** Delete every session of one user (incident response). Audited even when there were none. */
  async revokeUserSessions(actor: Actor, input: OperationInput): Promise<{ operationId: string; auditEventId: string; userId: string; revoked: number }> {
    const operator = requireOperator(actor);
    const userId = validateUserId(input.userId);
    const reason = validateReason(input.reason);
    const operationId = validateOperationId(input.operationId);
    const user = await this.requireUser(operator, "admin.user.sessions.revoke", userId, operationId, reason);
    const event = this.event(operator, {
      action: "admin.user.sessions.revoke",
      target: { type: "user", id: userId },
      requestId: operationId,
      result: "success",
      metadata: { reason, sessions: await this.admin.countUserSessions(user.authUserId), channel: operator.channel },
    });
    const revoked = await this.admin.deleteUserSessionsWithAudit(event, user.authUserId);
    return { operationId, auditEventId: event.id, userId, revoked };
  }

  /** Delete every session of every user (global incident). Requires explicit confirmation. */
  async revokeAllSessions(actor: Actor, input: { reason: string; confirm: boolean; operationId?: string }): Promise<{ operationId: string; auditEventId: string; revoked: number }> {
    const operator = requireOperator(actor);
    const reason = validateReason(input.reason);
    const operationId = validateOperationId(input.operationId);
    if (input.confirm !== true) throw new OperatorError("CONFIRMATION_REQUIRED", "revoking every user's sessions requires --yes");
    const event = this.event(operator, {
      action: "admin.sessions.revoke_all",
      requestId: operationId,
      result: "success",
      metadata: { reason, sessions: await this.admin.countAllSessions(), channel: operator.channel },
    });
    const revoked = await this.admin.deleteAllSessionsWithAudit(event);
    return { operationId, auditEventId: event.id, revoked };
  }

  /** Remove one passkey belonging to `userId`. */
  async removePasskey(actor: Actor, input: OperationInput & { passkeyId: string }): Promise<{ operationId: string; auditEventId: string; userId: string; passkeyId: string; fingerprint: string | null }> {
    const operator = requireOperator(actor);
    const userId = validateUserId(input.userId);
    const reason = validateReason(input.reason);
    const operationId = validateOperationId(input.operationId);
    if (typeof input.passkeyId !== "string" || !PasskeyId.test(input.passkeyId)) throw new OperatorError("INVALID_INPUT", "--passkey must be a passkey id");
    const user = await this.requireUser(operator, "admin.passkey.remove", userId, operationId, reason);
    const passkey = await this.admin.findPasskey(input.passkeyId, user.authUserId);
    if (!passkey) {
      // Another user's passkey is indistinguishable from a missing one.
      await this.recordDenial(operator, {
        action: "admin.passkey.remove",
        target: { type: "user", id: userId },
        requestId: operationId,
        reason: "NOT_FOUND",
        metadata: { reason, channel: operator.channel },
      });
      throw new OperatorError("NOT_FOUND", `no passkey ${input.passkeyId} for ${userId}`);
    }
    const fields = await passkeyAuditFields(passkey);
    const event = this.event(operator, {
      action: "admin.passkey.remove",
      target: fields.target,
      requestId: operationId,
      result: "success",
      metadata: { ...fields.metadata, user: userId, reason, channel: operator.channel },
    });
    if (!(await this.admin.deletePasskeyWithAudit(event, passkey.id, user.authUserId))) throw new OperatorError("CONFLICT", "the passkey was removed concurrently; nothing was modified");
    return { operationId, auditEventId: event.id, userId, passkeyId: passkey.id, fingerprint: (fields.metadata?.["fingerprint"] as string | null) ?? null };
  }

  /** Read-only: status and counts for one user. No email or provider account ids. */
  async describeUser(actor: Actor, userIdInput: string): Promise<SanitizedUser> {
    requireOperator(actor);
    const userId = validateUserId(userIdInput);
    const user = await this.users.getById(userId);
    if (!user) throw new OperatorError("NOT_FOUND", `no application user ${userId}`);
    return { id: user.id, status: user.status, createdAt: iso(user.createdAt), updatedAt: iso(user.updatedAt), ...(await this.admin.authSummary(user.authUserId)) };
  }

  /** Read-only: a user's passkeys by id, label, and fingerprint (no credential data). */
  async listPasskeys(actor: Actor, userIdInput: string): Promise<SanitizedPasskey[]> {
    requireOperator(actor);
    const userId = validateUserId(userIdInput);
    const user = await this.users.getById(userId);
    if (!user) throw new OperatorError("NOT_FOUND", `no application user ${userId}`);
    const passkeys = await this.admin.listPasskeys(user.authUserId);
    return Promise.all(passkeys.map(async (p) => ({ id: p.id, name: p.name, fingerprint: await passkeyFingerprint(p.credentialID), createdAt: p.createdAt ?? null })));
  }

  /** Delete up to `limit` expired verification rows (maintenance; operator or system). */
  async purgeExpiredVerifications(actor: Actor, input: { limit?: number } = {}): Promise<{ deleted: number; remainingExpired: number }> {
    requireMaintenanceActor(actor);
    const now = this.now();
    const deleted = await this.verifications.deleteExpired(now, input.limit ?? 100);
    return { deleted, remainingExpired: await this.verifications.countExpired(now) };
  }
}
