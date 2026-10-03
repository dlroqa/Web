/**
 * Typed database errors.
 *
 * D1/SQLite error text never reaches clients. `mapD1Error` classifies a raw
 * failure into one of these types using the constraint or trigger name only;
 * `toApiError` turns them into stable API errors. Anything unrecognized is an
 * UnexpectedDbError, which becomes INTERNAL_ERROR.
 */
import { ApiError } from "../http/errors";

export abstract class DbError extends Error {}

/** A uniqueness constraint was violated (e.g. a duplicate auth_user_id). */
export class UniqueConflictError extends DbError {
  override readonly name = "UniqueConflictError";
  constructor(readonly constraint: string) {
    super(`unique constraint: ${constraint}`);
  }
}

/** Same idempotency key, different request: never a second job. */
export class IdempotencyConflictError extends DbError {
  override readonly name = "IdempotencyConflictError";
  constructor() {
    super("idempotency key reused with a different request");
  }
}

/** A provisioning nonce was presented twice. */
export class NonceReplayError extends DbError {
  override readonly name = "NonceReplayError";
  constructor() {
    super("nonce already recorded");
  }
}

export class InvalidTransitionError extends DbError {
  override readonly name = "InvalidTransitionError";
  constructor(
    readonly entity: string,
    readonly from: string,
    readonly to: string,
  ) {
    super(`invalid ${entity} transition ${from} -> ${to}`);
  }
}

export class NotFoundError extends DbError {
  override readonly name = "NotFoundError";
  constructor(readonly entity: string) {
    super(`${entity} not found`);
  }
}

/** A CHECK, foreign-key, or integrity trigger rejected the write. */
export class ConstraintViolationError extends DbError {
  override readonly name = "ConstraintViolationError";
  constructor(readonly kind: "check" | "foreign_key" | "immutable" | "append_only" | "revocation_decrease" | "not_null") {
    super(`constraint violation: ${kind}`);
  }
}

export class UnexpectedDbError extends DbError {
  override readonly name = "UnexpectedDbError";
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Classify a raw D1 error. Returns a DbError; never rethrows raw text. */
export function mapD1Error(error: unknown): DbError {
  if (error instanceof DbError) return error;
  const message = messageOf(error);
  const unique = /UNIQUE constraint failed: ([A-Za-z0-9_.]+(?:, [A-Za-z0-9_.]+)*)/.exec(message);
  if (unique) return new UniqueConflictError(unique[1] ?? "unknown");
  if (message.includes("invalid_status_transition")) return new InvalidTransitionError("row", "unknown", "unknown");
  if (message.includes("immutable_column")) return new ConstraintViolationError("immutable");
  if (message.includes("audit_events_append_only")) return new ConstraintViolationError("append_only");
  if (message.includes("revocation_version_decrease")) return new ConstraintViolationError("revocation_decrease");
  if (message.includes("FOREIGN KEY constraint failed")) return new ConstraintViolationError("foreign_key");
  if (message.includes("CHECK constraint failed")) return new ConstraintViolationError("check");
  if (message.includes("NOT NULL constraint failed")) return new ConstraintViolationError("not_null");
  return new UnexpectedDbError("database operation failed", { cause: error });
}

/** Run a D1 operation, converting failures into typed errors. */
export async function guard<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw mapD1Error(error);
  }
}

/** The client-facing form of a database error. Never includes SQL text. */
export function toApiError(error: DbError): ApiError {
  const logReason = `${error.name}: ${error.message}`.slice(0, 200);
  if (error instanceof NotFoundError) return new ApiError("NOT_FOUND", { logReason });
  if (error instanceof IdempotencyConflictError) return new ApiError("IDEMPOTENCY_CONFLICT", { logReason });
  if (error instanceof NonceReplayError) return new ApiError("REPLAY_DETECTED", { logReason });
  if (error instanceof InvalidTransitionError || error instanceof UniqueConflictError) {
    return new ApiError("CONFLICT", { logReason });
  }
  return new ApiError("INTERNAL_ERROR", { logReason });
}
