import { ERROR_DEFINITIONS, type ApiErrorBody, type ErrorCode } from "../../shared/errors";
import type { AppConfig } from "../config/config";
import { applyApiHeaders } from "../security/headers";
import { ApiError } from "./errors";

/** What every API response needs to stamp its headers. */
export interface ResponseMeta {
  requestId: string;
  /** Absent only when configuration itself failed to load. */
  config: AppConfig | undefined;
  url: URL;
}

export function jsonOk<T>(data: T, meta: ResponseMeta, status = 200): Response {
  return applyApiHeaders(new Response(JSON.stringify({ ok: true, data }), { status }), meta.requestId, meta.config, meta.url);
}

/** Bare JSON (no envelope) for endpoints with a fixed public contract, e.g. /health. */
export function jsonRaw(body: unknown, meta: ResponseMeta, status = 200): Response {
  return applyApiHeaders(new Response(JSON.stringify(body), { status }), meta.requestId, meta.config, meta.url);
}

export function jsonError(error: ApiError | ErrorCode, meta: ResponseMeta): Response {
  const apiError = typeof error === "string" ? new ApiError(error) : error;
  const body: ApiErrorBody = {
    ok: false,
    error: {
      code: apiError.code,
      message: ERROR_DEFINITIONS[apiError.code].message,
      ...(apiError.issues && apiError.issues.length > 0 ? { issues: apiError.issues } : {}),
    },
    requestId: meta.requestId,
  };
  const response = new Response(JSON.stringify(body), { status: apiError.status });
  for (const [name, value] of Object.entries(apiError.headers)) {
    response.headers.set(name, value);
  }
  return applyApiHeaders(response, meta.requestId, meta.config, meta.url);
}
