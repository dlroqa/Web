/**
 * Better Auth diagnostics routed through our redacting logger.
 *
 * Better Auth 1.7.7 supports two hooks, both used here (no patching):
 *
 *   logger.log(level, message, ...args)   every message Better Auth's own
 *       logger emits inside a request (its global logger delegates to the
 *       request's configured logger)
 *   onAPIError.onError(error, ctx)        every API error; when set, Better
 *       Auth does not log the error itself
 *
 * Messages are free text written by Better Auth and may, in some versions
 * or code paths, include values (codes, tokens, ids). They are reduced to a
 * bounded string with every long opaque run replaced, and extra arguments
 * are never logged: only their types (Errors: name only).
 */
import type { Logger } from "../utils/log";

/** Runs of 20+ token-ish characters: ids, codes, tokens, signatures. */
const OPAQUE_RUN = /[A-Za-z0-9_\-+/=.~%]{20,}/g;
const MAX_MESSAGE = 200;

export const OPAQUE_PLACEHOLDER = "[opaque]";

/** A Better Auth message with anything that could be a credential removed. */
export function sanitizeDiagnostic(message: unknown): string {
  if (typeof message !== "string") return typeof message;
  const flattened = message.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(OPAQUE_RUN, OPAQUE_PLACEHOLDER);
  return flattened.length > MAX_MESSAGE ? `${flattened.slice(0, MAX_MESSAGE)}…` : flattened;
}

function describeArg(arg: unknown): string {
  if (arg instanceof Error) return arg.name.slice(0, 40);
  if (arg === null) return "null";
  return Array.isArray(arg) ? "array" : typeof arg;
}

type BetterAuthLevel = "debug" | "info" | "warn" | "error";

/**
 * The `logger` option for Better Auth. `onFault` is called for error-level
 * messages: Better Auth logs at error level when it catches an unexpected
 * exception (e.g. the passkey plugin turns any non-API exception into a
 * generic 400 after logging it), so the gateway can still report the
 * request as INTERNAL_ERROR rather than as a client mistake.
 */
export function betterAuthLogger(logger: Logger, onFault?: () => void) {
  return {
    // "warn" is Better Auth's default; debug/info output is not needed in production.
    level: "warn" as const,
    disableColors: true,
    log(level: BetterAuthLevel, message: string, ...args: unknown[]) {
      if (level === "error") onFault?.();
      logger[level]("better_auth.log", { message: sanitizeDiagnostic(message), argTypes: args.slice(0, 5).map(describeArg) });
    },
  };
}

/** Status and code of a Better Auth APIError (or a plain error's name). */
export function describeAuthError(error: unknown): { status: string | null; code: string | null; errorName: string } {
  const status = typeof error === "object" && error !== null ? Reflect.get(error, "status") : undefined;
  const body = typeof error === "object" && error !== null ? Reflect.get(error, "body") : undefined;
  const code = typeof body === "object" && body !== null ? Reflect.get(body, "code") : undefined;
  const safeCode = typeof code === "string" && /^[A-Z0-9_]{1,64}$/.test(code) ? code : null;
  return {
    status: typeof status === "string" || typeof status === "number" ? String(status).slice(0, 40) : null,
    code: safeCode,
    errorName: error instanceof Error ? error.name.slice(0, 40) : typeof error,
  };
}

/** The `onAPIError.onError` option: one structured line, no message text. */
export function betterAuthErrorHandler(logger: Logger) {
  return (error: unknown) => {
    const described = describeAuthError(error);
    const level = described.status === "INTERNAL_SERVER_ERROR" || described.status === "500" || described.status === null ? "error" : "warn";
    logger[level]("better_auth.api_error", described);
  };
}
