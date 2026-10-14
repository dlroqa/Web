/**
 * LA-WEB-PROVISIONING/1 r4 (docs/PROVISIONING_PROTOCOL.md): the parts W1
 * needs to fix a logical command and to reason about what the harness said.
 *
 * Ported from the test-only reference codec and checked against the frozen
 * fixtures by the W1 conformance test (workers project). No signing, no HTTP:
 * W1 has no transport (docs/PROVISIONING_W1.md). Pure functions only.
 */
import { toHex } from "../utils/crypto";

export const PROTOCOL = "LA-WEB-PROVISIONING/1";

/** v1 operations (§1). profile.disable/enable are never sent (§1 item 3). */
export const V1_OPERATIONS = ["profile.create", "profile.status", "profile.revoke"] as const;
export type V1Operation = (typeof V1_OPERATIONS)[number];

/** Operations a job's fixed command can have; status polls ride on the job they reconcile (§7). */
export type CommandOperation = Exclude<V1Operation, "profile.status">;

export const MAX_COMMAND_LIFETIME_SECONDS = 120;
/** Web's command lifetime (§7: SHOULD use 60). */
export const COMMAND_LIFETIME_SECONDS = 60;
export const MAX_CLOCK_SKEW_SECONDS = 30;
/** §13.2 R3: a transmission's acceptance horizon is expiresAt + 60 (Web clock). */
export const ACCEPTANCE_HORIZON_SECONDS = 2 * MAX_CLOCK_SKEW_SECONDS;
export const TEMPLATE = "assistant";

const idPattern = (prefix: string) => new RegExp(`^${prefix}_[a-z0-9]{8,60}$`);

/** §4.4, §4.5 field formats. */
export const PATTERNS = {
  commandId: idPattern("cmd"),
  jobId: idPattern("prv"),
  harnessId: idPattern("hns"),
  profileId: idPattern("agt"),
  subject: idPattern("usr"),
  keyId: /^[a-z0-9][a-z0-9._-]{2,63}$/,
  operationId: /^[0-9a-f]{32}$/,
  idempotencyKey: /^[A-Za-z0-9_-]{16,128}$/,
  issuer: /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::([1-9][0-9]{0,4}))?$/,
  principalId: /^[a-z0-9][a-z0-9_-]{0,63}$/,
  code: /^[A-Z0-9_]{1,64}$/,
} as const;

export function isValidIssuer(value: string): boolean {
  if (value.length > 256) return false;
  const match = PATTERNS.issuer.exec(value);
  return match !== null && (match[1] === undefined || Number(match[1]) <= 65535);
}

/** Unicode White_Space (Rust str::trim), not JavaScript String.prototype.trim (§8.1). */
const WHITE_SPACE = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
  0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);
const isControl = (cp: number) => cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f);

/** §8.1 displayName: NFC, 1–64 Unicode scalar values, no Cc, no leading/trailing White_Space. */
export function isValidDisplayName(value: string): boolean {
  const scalars = Array.from(value, (ch) => ch.codePointAt(0) as number);
  if (scalars.length < 1 || scalars.length > 64) return false;
  if (scalars.some((cp) => isControl(cp) || (cp >= 0xd800 && cp <= 0xdfff))) return false;
  if (WHITE_SPACE.has(scalars[0] as number) || WHITE_SPACE.has(scalars[scalars.length - 1] as number)) return false;
  // §4.6: Web MAY refuse unassigned code points in its own engine.
  if (/\p{Cn}/u.test(value)) return false;
  return value.normalize("NFC") === value;
}

// ---------------------------------------------------------------------------
// §5 canonical form (JCS restricted to the §4.3 value profile) and §9.1 hash
// ---------------------------------------------------------------------------

export type CanonicalValue = string | number | { readonly [key: string]: CanonicalValue };

function jcsString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const cp = ch.codePointAt(0) as number;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (cp === 0x08) out += "\\b";
    else if (cp === 0x09) out += "\\t";
    else if (cp === 0x0a) out += "\\n";
    else if (cp === 0x0c) out += "\\f";
    else if (cp === 0x0d) out += "\\r";
    else if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

/** UTF-16 code-unit order (RFC 8785 §3.2.3). */
const compareUtf16 = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** JCS of a value inside the §4.3 profile. Throws outside it. */
export function canonicalize(value: CanonicalValue): string {
  if (typeof value === "string") return jcsString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("only non-negative safe integers");
    return String(value);
  }
  return `{${Object.keys(value)
    .sort(compareUtf16)
    .map((key) => `${jcsString(key)}:${canonicalize(value[key] as CanonicalValue)}`)
    .join(",")}}`;
}

const encoder = new TextEncoder();

/** §9.1 payloadHash = SHA-256("LA-WEB-PROVISIONING/1" 0 "payload" 0 operation 0 ‖ JCS(payload)). Stored as request_hash. */
export async function payloadHash(operation: V1Operation, payload: CanonicalValue): Promise<string> {
  const prefix = encoder.encode(`${PROTOCOL}\u0000payload\u0000${operation}\u0000`);
  const body = encoder.encode(canonicalize(payload));
  const bytes = new Uint8Array(prefix.length + body.length);
  bytes.set(prefix, 0);
  bytes.set(body, prefix.length);
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

// Type aliases (not interfaces) so payloads are assignable to CanonicalValue.
export type CreatePayload = {
  displayName: string;
  idempotencyKey: string;
  issuer: string;
  profileId: string;
  subject: string;
  template: typeof TEMPLATE;
};

export type OperationPayload = {
  operationId: string;
  profileId: string;
};

export class InvalidPayloadError extends Error {
  override readonly name = "InvalidPayloadError";
  /** The §8 code the harness would answer; Web never signs such a payload. */
  constructor(readonly code: string) {
    super(`payload refused before signing: ${code}`);
  }
}

/** §8.1, validated exactly as the harness will validate it. */
export function createPayload(input: Omit<CreatePayload, "template">): CreatePayload {
  if (!PATTERNS.profileId.test(input.profileId)) throw new InvalidPayloadError("INVALID_PROFILE_ID");
  if (!isValidIssuer(input.issuer)) throw new InvalidPayloadError("INVALID_ISSUER");
  if (!PATTERNS.subject.test(input.subject)) throw new InvalidPayloadError("INVALID_SUBJECT");
  if (!isValidDisplayName(input.displayName)) throw new InvalidPayloadError("INVALID_DISPLAY_NAME");
  if (!PATTERNS.idempotencyKey.test(input.idempotencyKey)) throw new InvalidPayloadError("INVALID_IDEMPOTENCY_KEY");
  return { ...input, template: TEMPLATE };
}

/** §8.2, §8.3 */
export function operationPayload(input: OperationPayload): OperationPayload {
  if (!PATTERNS.operationId.test(input.operationId)) throw new InvalidPayloadError("INVALID_OPERATION_ID");
  if (!PATTERNS.profileId.test(input.profileId)) throw new InvalidPayloadError("INVALID_PROFILE_ID");
  return { operationId: input.operationId, profileId: input.profileId };
}

// ---------------------------------------------------------------------------
// §11 error registry (errors.json; the conformance test compares every field)
// ---------------------------------------------------------------------------

export type ErrorClass = "protocol" | "payload" | "admission" | "merits" | "operation" | "conflict" | "indeterminate";
export type CreateResolutionClass = "final" | "transmission-only" | "indeterminate" | "conflict" | "not-applicable";

export interface ErrorDefinition {
  code: string;
  http: number;
  class: ErrorClass;
  operations: readonly V1Operation[];
  createResolution: CreateResolutionClass;
}

const CREATE_RESOLUTION: Readonly<Record<ErrorClass, CreateResolutionClass>> = {
  protocol: "transmission-only",
  payload: "final",
  admission: "final",
  merits: "final",
  operation: "not-applicable",
  conflict: "conflict",
  indeterminate: "indeterminate",
};

const ALL = V1_OPERATIONS;
const CREATE: readonly V1Operation[] = ["profile.create"];
const BY_OPERATION: readonly V1Operation[] = ["profile.status", "profile.revoke"];
const REVOKE: readonly V1Operation[] = ["profile.revoke"];
const def = (code: string, http: number, cls: ErrorClass, operations: readonly V1Operation[]): ErrorDefinition => ({
  code,
  http,
  class: cls,
  operations,
  createResolution: CREATE_RESOLUTION[cls],
});

export const ERRORS: readonly ErrorDefinition[] = [
  def("METHOD_NOT_ALLOWED", 405, "protocol", ALL),
  def("UNSUPPORTED_MEDIA_TYPE", 415, "protocol", ALL),
  def("PAYLOAD_TOO_LARGE", 413, "protocol", ALL),
  def("MALFORMED_JSON", 400, "protocol", ALL),
  def("DUPLICATE_KEY", 400, "protocol", ALL),
  def("INVALID_JSON_VALUE", 400, "protocol", ALL),
  def("INVALID_ENVELOPE", 400, "protocol", ALL),
  def("UNSUPPORTED_PROTOCOL", 400, "protocol", ALL),
  def("UNKNOWN_FIELD", 400, "protocol", ALL),
  def("MISSING_FIELD", 400, "protocol", ALL),
  def("WRONG_PURPOSE", 400, "protocol", ALL),
  def("UNSUPPORTED_OPERATION", 400, "protocol", ALL),
  def("INVALID_FIELD", 400, "protocol", ALL),
  def("INVALID_LIFETIME", 400, "protocol", ALL),
  def("NON_CANONICAL", 400, "protocol", ALL),
  def("UNKNOWN_KEY", 401, "protocol", ALL),
  def("KEY_REVOKED", 401, "protocol", ALL),
  def("BAD_SIGNATURE", 401, "protocol", ALL),
  def("WRONG_AUDIENCE", 403, "protocol", ALL),
  def("NOT_YET_VALID", 401, "protocol", ALL),
  def("EXPIRED", 401, "protocol", ALL),
  def("REPLAY_DETECTED", 409, "indeterminate", ALL),
  def("NONCE_STORE_UNAVAILABLE", 503, "protocol", ALL),
  def("LEDGER_CONTINUITY_FAILED", 503, "protocol", ALL),
  def("INVALID_PROFILE_ID", 400, "payload", ALL),
  def("RESERVED_PROFILE_ID", 400, "payload", CREATE),
  def("INVALID_ISSUER", 400, "payload", CREATE),
  def("INVALID_SUBJECT", 400, "payload", CREATE),
  def("INVALID_DISPLAY_NAME", 400, "payload", CREATE),
  def("INVALID_TEMPLATE", 400, "payload", CREATE),
  def("INVALID_IDEMPOTENCY_KEY", 400, "payload", CREATE),
  def("INVALID_OPERATION_ID", 400, "payload", BY_OPERATION),
  def("UNAUTHENTICATED", 401, "admission", ALL),
  def("NOT_A_PROVISIONER", 403, "admission", ALL),
  def("CREDENTIAL_NOT_PROVISIONING_ONLY", 403, "admission", ALL),
  def("PROVISIONER_INACTIVE", 403, "admission", ALL),
  def("PROVISIONER_REVOKED", 403, "admission", ALL),
  def("PROFILE_OUTSIDE_CREDENTIAL", 403, "admission", CREATE),
  def("ISSUER_NOT_ALLOWED", 403, "merits", CREATE),
  def("TEMPLATE_NOT_ALLOWED", 403, "merits", CREATE),
  def("QUOTA_EXCEEDED", 403, "merits", CREATE),
  def("LEDGER_FULL", 403, "merits", CREATE),
  def("PROFILE_UNAVAILABLE", 409, "merits", CREATE),
  def("PRINCIPAL_INACTIVE", 409, "merits", CREATE),
  def("EXTERNAL_IDENTITY_CONFLICT", 409, "merits", CREATE),
  def("IDEMPOTENCY_CONFLICT", 409, "conflict", CREATE),
  def("UNKNOWN_OPERATION", 404, "operation", BY_OPERATION),
  def("OPERATION_IN_PROGRESS", 409, "operation", REVOKE),
  def("NOT_REVOCABLE", 409, "operation", REVOKE),
  def("OWNERSHIP_CHANGED", 409, "operation", REVOKE),
  def("STORAGE_UNAVAILABLE", 503, "indeterminate", ALL),
  def("STORAGE_CORRUPT", 503, "indeterminate", ALL),
  def("IDENTITY_UNAVAILABLE", 503, "indeterminate", ALL),
  def("INTERNAL_ERROR", 500, "indeterminate", ALL),
];

const BY_CODE = new Map(ERRORS.map((e) => [e.code, e]));

export function errorDefinition(code: string): ErrorDefinition | undefined {
  return BY_CODE.get(code);
}

/** §12.2: codes that may appear in result.failure of a `failed` operation. */
export const FAILURE_CODES = [
  "ISSUER_NOT_TRUSTED",
  "PRINCIPAL_INACTIVE",
  "EXTERNAL_IDENTITY_CONFLICT",
  "PROFILE_UNAVAILABLE",
  "OWNERSHIP_CHANGED",
  "PROVISIONER_REVOKED",
  "INVALID_TEMPLATE",
] as const;

export const OPERATION_STATES = ["pending", "profile_created", "completed", "failed", "revoked"] as const;
export type OperationState = (typeof OPERATION_STATES)[number];
export const TERMINAL_STATES: readonly OperationState[] = ["completed", "failed", "revoked"];

// ---------------------------------------------------------------------------
// §12.4 outcomes, as handed to the journal
// ---------------------------------------------------------------------------

/**
 * What one transmission produced, after §12.4 classification. A future
 * transport (W2) builds these from HTTP with the ported classifyResponse; in
 * W1 they come only from tests. `normalizeOutcome` re-checks every field, so a
 * caller cannot record something classifyResponse would call uncertain.
 */
export type ObservedOutcome =
  | {
      kind: "operation";
      operationId: string;
      state: OperationState;
      failure: string | null;
      ownerBound: boolean;
      principalId: string;
    }
  | { kind: "refused"; code: string }
  | { kind: "uncertain"; reason: string };

/** Reasons for an uncertain outcome that are not registry codes. */
export const UNCERTAIN_REASONS = ["TIMEOUT", "NETWORK_ERROR", "RESPONSE_INVALID", "RESPONSE_TOO_LARGE", "LEASE_EXPIRED"] as const;

/**
 * Apply the §12.4 rules that do not need the HTTP body: an indeterminate
 * code, an unregistered code, a code that never answers this operation, a
 * non-terminal create answer, or an inconsistent `failure` all become
 * `uncertain` (RESPONSE_INVALID), which never changes Web's view.
 */
export function normalizeOutcome(operation: V1Operation, outcome: ObservedOutcome, target: string | null): ObservedOutcome {
  const invalid: ObservedOutcome = { kind: "uncertain", reason: "RESPONSE_INVALID" };
  switch (outcome.kind) {
    case "uncertain":
      return PATTERNS.code.test(outcome.reason) ? outcome : invalid;
    case "refused": {
      const definition = errorDefinition(outcome.code);
      if (!definition || !definition.operations.includes(operation)) return invalid;
      if (definition.class === "indeterminate") return { kind: "uncertain", reason: definition.code };
      return { kind: "refused", code: definition.code };
    }
    case "operation": {
      if (!PATTERNS.operationId.test(outcome.operationId) || !PATTERNS.principalId.test(outcome.principalId)) return invalid;
      if (!(OPERATION_STATES as readonly string[]).includes(outcome.state)) return invalid;
      if ((outcome.state === "failed") !== (outcome.failure !== null)) return invalid;
      if (outcome.failure !== null && !(FAILURE_CODES as readonly string[]).includes(outcome.failure)) return invalid;
      if (operation === "profile.create" && !TERMINAL_STATES.includes(outcome.state)) return invalid;
      if (operation !== "profile.create" && outcome.operationId !== target) return invalid;
      if (operation === "profile.revoke" && outcome.state !== "revoked") return invalid;
      return { ...outcome };
    }
  }
}
