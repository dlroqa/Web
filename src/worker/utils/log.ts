/**
 * Structured logging with mandatory redaction.
 *
 * Every log line is one JSON object passed through `redact`, which replaces
 * the values of sensitive keys and of values that look like credentials.
 * Do not log whole request headers or bodies; log the specific, safe fields
 * you need.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export const REDACTED = "[REDACTED]";

/**
 * Key fragments whose values are always redacted. Keys are compared after
 * lowercasing and removing `-` and `_`, so `Set-Cookie`, `private_key`, and
 * `privateKey` all match.
 */
const SENSITIVE_KEY_FRAGMENTS = [
  "authorization",
  "cookie",
  "password",
  "passwd",
  "passphrase",
  "secret",
  "token",
  "privatekey",
  "apikey",
  "signature",
  "credential",
  "sessionid",
  "csrf",
  "otp",
] as const;

/** Value shapes that are credentials regardless of their key. */
const SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /^\s*(bearer|basic)\s+\S+/i,
  /-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/, // JWT
];

const MAX_DEPTH = 6;
const MAX_ARRAY = 50;
const MAX_STRING = 2_000;

export function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[-_\s]/g, "");
  return SENSITIVE_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}

function redactString(value: string): string {
  if (SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
    return REDACTED;
  }
  return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…[truncated]` : value;
}

/** Return a deep copy of `value` that is safe to log. */
export function redact(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") return undefined;
  if (depth >= MAX_DEPTH) return "[Truncated]";
  if (value instanceof Error) {
    return { name: value.name, message: redactString(value.message) };
  }
  if (value instanceof Headers || value instanceof Request || value instanceof Response) {
    return `[${value.constructor.name}]`; // never log headers or bodies wholesale
  }
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY).map((item) => redact(item, depth + 1));
    if (value.length > MAX_ARRAY) items.push(`[+${value.length - MAX_ARRAY} more]`);
    return items;
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = isSensitiveKey(key) ? REDACTED : redact(item, depth + 1);
    }
    return out;
  }
  return "[Unserializable]";
}

export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
  /** A logger that adds `fields` to every line. */
  child(fields: Record<string, unknown>): Logger;
}

export function createLogger(base: Record<string, unknown> = {}): Logger {
  const write = (level: LogLevel, event: string, fields?: Record<string, unknown>) => {
    const line = redact({ level, event, timestamp: new Date().toISOString(), ...base, ...fields });
    const text = JSON.stringify(line);
    if (level === "error") console.error(text);
    else if (level === "warn") console.warn(text);
    else console.log(text);
  };
  return {
    debug: (event, fields) => write("debug", event, fields),
    info: (event, fields) => write("info", event, fields),
    warn: (event, fields) => write("warn", event, fields),
    error: (event, fields) => write("error", event, fields),
    child: (fields) => createLogger({ ...base, ...fields }),
  };
}

/** Summarize an unknown thrown value for logs without leaking its contents. */
export function describeError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return { errorName: error.name, errorMessage: redactString(error.message.slice(0, 500)) };
  }
  return { errorName: typeof error };
}
