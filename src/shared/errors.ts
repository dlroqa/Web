/**
 * Stable API error codes. Clients branch on `code`, never on `message`.
 *
 * Messages are generic and safe to show to users; they never include input
 * values, internal addresses, SQL, stack traces, or secrets.
 */
export const ERROR_DEFINITIONS = {
  AUTH_REQUIRED: { status: 401, message: "Sign in to continue." },
  ACCOUNT_DISABLED: { status: 403, message: "This account is not active." },
  FORBIDDEN: { status: 403, message: "You do not have permission to do that." },
  NOT_FOUND: { status: 404, message: "Not found." },
  METHOD_NOT_ALLOWED: { status: 405, message: "Method not allowed." },
  INVALID_REQUEST: { status: 400, message: "The request is invalid." },
  UNSUPPORTED_MEDIA_TYPE: { status: 415, message: "Unsupported content type." },
  PAYLOAD_TOO_LARGE: { status: 413, message: "The request body is too large." },
  RATE_LIMITED: { status: 429, message: "Too many requests. Try again shortly." },
  TURNSTILE_FAILED: { status: 403, message: "Human verification failed. Please try again." },
  PROFILE_LIMIT_REACHED: { status: 409, message: "You have reached the agent limit." },
  HARNESS_UNAVAILABLE: { status: 503, message: "The agent service is unavailable." },
  PROVISIONING_FAILED: { status: 502, message: "Unable to create the agent profile." },
  PROVISIONING_TIMEOUT: { status: 504, message: "Creating the agent profile timed out." },
  SIGNATURE_FAILED: { status: 502, message: "Unable to create the agent profile." },
  REPLAY_DETECTED: { status: 409, message: "This request was already processed." },
  IDEMPOTENCY_CONFLICT: { status: 409, message: "This request conflicts with an earlier one." },
  INTERNAL_ERROR: { status: 500, message: "Something went wrong." },
} as const satisfies Record<string, { status: number; message: string }>;

export type ErrorCode = keyof typeof ERROR_DEFINITIONS;

/** A field-level validation problem. Contains a path and a code, never input. */
export interface ValidationIssue {
  path: string;
  code: string;
}

export interface ApiErrorBody {
  ok: false;
  error: {
    code: ErrorCode;
    message: string;
    issues?: ValidationIssue[];
  };
  requestId: string;
}

export interface ApiSuccessBody<T> {
  ok: true;
  data: T;
}

export type ApiResponseBody<T> = ApiSuccessBody<T> | ApiErrorBody;

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === "string" && Object.hasOwn(ERROR_DEFINITIONS, value);
}
