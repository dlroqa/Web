/**
 * Who is acting. Three kinds, never inferred from one another:
 *
 *   user      a signed-in end user. Built only from a Better Auth session in
 *             the Worker (Principal). Has no operator privileges, ever.
 *   operator  a trusted person running the operator CLI with credentials for
 *             the Cloudflare account that holds the database. Built only by
 *             the CLI entry point (main.ts); no HTTP route constructs one.
 *   system    an automated maintenance task (no human), e.g. cleanup.
 *
 * Operator privilege is never derived from an email address, hostname,
 * being the first account, knowing a URL, or anything the browser shows.
 * There is no admin identity system yet: an operator id is an accountable
 * label for the audit trail, and the real authorization boundary is access
 * to the Cloudflare account (see docs/SECURITY_MODEL.md, "Actors").
 */

export interface UserActor {
  kind: "user";
  userProfileId: string;
}

export interface OperatorActor {
  kind: "operator";
  operatorId: string;
  channel: "cli";
}

export interface SystemActor {
  kind: "system";
  component: string;
}

export type Actor = UserActor | OperatorActor | SystemActor;

/** Operator ids: `opr_` plus 8–32 lowercase letters/digits (the audit id format). Not an email. */
export const OPERATOR_ID_PATTERN = /^opr_[a-z0-9]{8,32}$/;

export class OperatorAuthorizationError extends Error {
  override readonly name = "OperatorAuthorizationError";
}

/** Build the operator actor for the CLI. Only main.ts/cli.ts call this. */
export function operatorActor(operatorId: string | undefined): OperatorActor {
  if (!operatorId || !OPERATOR_ID_PATTERN.test(operatorId)) {
    throw new OperatorAuthorizationError("an operator id (opr_…) is required");
  }
  return { kind: "operator", operatorId, channel: "cli" };
}

/** The operator acting, or OperatorAuthorizationError for any other actor. */
export function requireOperator(actor: Actor): OperatorActor {
  if (actor.kind !== "operator" || !OPERATOR_ID_PATTERN.test(actor.operatorId)) {
    throw new OperatorAuthorizationError("operator actions require an operator actor");
  }
  return actor;
}

/** Maintenance may run as an operator or as the system, never as a user. */
export function requireMaintenanceActor(actor: Actor): OperatorActor | SystemActor {
  if (actor.kind === "system") return actor;
  return requireOperator(actor);
}
