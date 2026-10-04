/**
 * Audit event contract.
 *
 * Events are built only through `createAuditEvent`, which validates them at
 * runtime. The shape is deliberately narrow so secrets have nowhere to hide:
 * actions come from a fixed list, ids must look like ids, and metadata is a
 * flat map of short scalar values whose keys may not look sensitive
 * (password, token, cookie, secret, …). A violation throws: it is a
 * programming error, caught by tests, not something to log around.
 *
 * Persistence: `D1AuditSink` (db/audit.ts) stores events in D1;
 * `LogAuditSink` writes structured log lines. `AuditRecorder` chooses
 * fail-closed or best-effort recording per operation.
 */
import { z } from "../../shared/zod";
import { isErrorCode, type ErrorCode } from "../../shared/errors";
import { SecurityMetadataSchema, type SecurityMetadata } from "../db/json";
import { isSensitiveKey, type Logger } from "../utils/log";
import { randomId } from "../utils/random";

export const AUDIT_ACTIONS = [
  "auth.login.success",
  "auth.login.failure",
  "auth.logout",
  "auth.passkey.add",
  "auth.passkey.remove",
  "auth.turnstile.failure",
  "auth.account.created",
  "auth.oauth.start",
  "auth.oauth.callback.failure",
  "auth.passkey.rename",
  "auth.passkey.login.failure",
  "auth.session.revoke",
  "auth.session.revoke_all",
  "account.profile.update",
  "session.revoke",
  "session.revoke_all",
  "profile.create.request",
  "profile.create.success",
  "profile.create.failure",
  "profile.update",
  "profile.disable",
  "profile.delete",
  "provision.signature.failure",
  "provision.replay.detected",
  "admin.harness.register",
  "admin.harness.disable",
  // Operator actions (trusted CLI only; see src/operator and docs/OPERATIONS.md).
  "admin.user.approve",
  "admin.user.suspend",
  "admin.user.reactivate",
  "admin.user.disable",
  "admin.user.sessions.revoke",
  "admin.sessions.revoke_all",
  "admin.passkey.remove",
  "security.origin.rejected",
  "security.ratelimit.exceeded",
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];
export type AuditActorType = "user" | "admin" | "system" | "anonymous";
export type AuditResult = "success" | "failure" | "denied";
export type AuditMetadataValue = string | number | boolean | null;

const SafeId = z.string().regex(/^[a-z]{2,8}_[a-z0-9]{8,64}$/, "ids must be prefixed random identifiers");
/**
 * Better Auth's own row ids (sessions, passkeys): opaque random strings,
 * never tokens or credential ids. Only these target types may use them.
 */
const AuthRowId = z.string().regex(/^[A-Za-z0-9_-]{8,64}$/, "auth row ids are opaque random identifiers");
const AUTH_ROW_TARGETS = new Set(["session", "passkey"]);
const MetadataKey = z
  .string()
  .regex(/^[a-z][a-zA-Z0-9]{0,39}$/)
  .refine((key) => !isSensitiveKey(key), "sensitive metadata key");
const MetadataValue = z.union([z.string().max(200), z.number().finite(), z.boolean(), z.null()]);

const AuditEventSchema = z
  .object({
    id: SafeId,
    timestamp: z.iso.datetime(),
    actor: z.discriminatedUnion("type", [
      z.object({ type: z.literal("user"), id: SafeId }).strict(),
      z.object({ type: z.literal("admin"), id: SafeId }).strict(),
      z.object({ type: z.literal("system"), id: z.string().regex(/^[a-z][a-z0-9-]{1,40}$/) }).strict(),
      z.object({ type: z.literal("anonymous") }).strict(),
    ]),
    action: z.enum(AUDIT_ACTIONS),
    target: z
      .object({ type: z.enum(["user", "agent_profile", "session", "passkey", "harness", "provisioning_job"]), id: z.string() })
      .strict()
      .refine((t) => (AUTH_ROW_TARGETS.has(t.type) ? AuthRowId : SafeId).safeParse(t.id).success, { path: ["id"], message: "invalid target id" })
      .optional(),
    requestId: SafeId,
    result: z.enum(["success", "failure", "denied"]),
    reason: z.custom<ErrorCode>(isErrorCode).optional(),
    metadata: z.record(MetadataKey, MetadataValue).refine((m) => Object.keys(m).length <= 20, "too many metadata keys"),
    security: SecurityMetadataSchema.default({}),
  })
  .strict();

export type AuditEvent = z.output<typeof AuditEventSchema>;

export interface AuditEventInput {
  actor: AuditEvent["actor"];
  action: AuditAction;
  target?: AuditEvent["target"];
  requestId: string;
  result: AuditResult;
  /** A stable error code explaining a failure or denial. */
  reason?: ErrorCode;
  metadata?: Record<string, AuditMetadataValue>;
  /** Keyed source hash and coarse location (see security/source-identity.ts). */
  security?: SecurityMetadata;
}

export class AuditContractError extends Error {
  override readonly name = "AuditContractError";
}

export function createAuditEvent(input: AuditEventInput, now: () => Date = () => new Date()): AuditEvent {
  const parsed = AuditEventSchema.safeParse({
    id: randomId("aud"),
    timestamp: now().toISOString(),
    metadata: {},
    ...input,
  });
  if (!parsed.success) {
    // Report paths only; the rejected values may be the secret.
    throw new AuditContractError(`invalid audit event: ${parsed.error.issues.map((i) => i.path.join(".")).join(", ")}`);
  }
  return parsed.data;
}

export interface AuditSink {
  record(event: AuditEvent): Promise<void>;
}

/** Phase 2 sink: one structured log line per event. */
export class LogAuditSink implements AuditSink {
  constructor(private readonly logger: Logger) {}

  async record(event: AuditEvent): Promise<void> {
    this.logger.info("audit", { audit: event });
  }
}
