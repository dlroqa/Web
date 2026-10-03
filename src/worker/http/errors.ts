import { ERROR_DEFINITIONS, type ErrorCode, type ValidationIssue } from "../../shared/errors";

export interface ApiErrorOptions {
  /** Field-level problems safe to return (paths and codes only). */
  issues?: ValidationIssue[];
  /** Extra response headers, e.g. Retry-After. */
  headers?: Record<string, string>;
  /** Internal detail for logs only; never sent to the client. */
  logReason?: string;
  cause?: unknown;
}

/**
 * The only error type whose details reach a client. Anything else thrown in a
 * handler becomes a generic INTERNAL_ERROR.
 */
export class ApiError extends Error {
  override readonly name = "ApiError";
  readonly status: number;
  readonly issues: ValidationIssue[] | undefined;
  readonly headers: Record<string, string>;
  readonly logReason: string | undefined;

  constructor(
    readonly code: ErrorCode,
    options: ApiErrorOptions = {},
  ) {
    super(ERROR_DEFINITIONS[code].message, { cause: options.cause });
    this.status = ERROR_DEFINITIONS[code].status;
    this.issues = options.issues;
    this.headers = options.headers ?? {};
    this.logReason = options.logReason;
  }
}
