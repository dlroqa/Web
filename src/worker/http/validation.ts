/**
 * Runtime validation of external input. TypeScript types are not validation.
 *
 * Error responses carry only issue paths and codes, never the offending input
 * or Zod's messages, so validation failures cannot reflect attacker content.
 */
import type { ValidationIssue } from "../../shared/errors";
import type { z } from "../../shared/zod";
import { UpstreamResponseTooLargeError, readBoundedText } from "../utils/fetch";
import { ApiError } from "./errors";

/** Default ceiling for JSON request bodies. Raise per route only with reason. */
export const DEFAULT_MAX_BODY_BYTES = 16 * 1024;

function toIssues(error: z.ZodError): ValidationIssue[] {
  return error.issues.slice(0, 20).map((issue) => ({
    path: issue.path.map(String).join(".") || "(root)",
    code: issue.code,
  }));
}

/** Validate an already-parsed value (e.g. from a database or upstream). */
export function parseWith<S extends z.ZodType>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new ApiError("INVALID_REQUEST", { issues: toIssues(result.error), logReason: "schema validation failed" });
  }
  return result.data;
}

function isJsonContentType(value: string | null): boolean {
  if (!value) return false;
  const [mediaType] = value.split(";");
  return mediaType?.trim().toLowerCase() === "application/json";
}

/**
 * Parse and validate a JSON request body: requires `Content-Type:
 * application/json`, enforces a byte limit while streaming, rejects malformed
 * JSON, then validates against `schema` (use `.strict()` objects for
 * security-sensitive input so unknown fields are rejected, not ignored).
 */
export async function parseJsonBody<S extends z.ZodType>(
  request: Request,
  schema: S,
  options: { maxBytes?: number } = {},
): Promise<z.output<S>> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!isJsonContentType(request.headers.get("content-type"))) {
    throw new ApiError("UNSUPPORTED_MEDIA_TYPE");
  }
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
    throw new ApiError("PAYLOAD_TOO_LARGE");
  }
  let text: string;
  try {
    text = await readBoundedText(request.body, maxBytes);
  } catch (error) {
    if (error instanceof UpstreamResponseTooLargeError) throw new ApiError("PAYLOAD_TOO_LARGE");
    throw new ApiError("INVALID_REQUEST", { logReason: "unreadable body", cause: error });
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ApiError("INVALID_REQUEST", { issues: [{ path: "(root)", code: "invalid_json" }] });
  }
  return parseWith(schema, value);
}

/** Validate URL search parameters (single-valued) against `schema`. */
export function parseQuery<S extends z.ZodType>(url: URL, schema: S): z.output<S> {
  const params: Record<string, string> = {};
  for (const [key, value] of url.searchParams) {
    if (Object.hasOwn(params, key)) {
      throw new ApiError("INVALID_REQUEST", { issues: [{ path: key, code: "duplicate_parameter" }] });
    }
    params[key] = value;
  }
  return parseWith(schema, params);
}
