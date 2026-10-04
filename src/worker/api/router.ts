/**
 * API routing. Every /api/* and /health request lands here and leaves as a
 * JSON response; nothing under /api can fall through to the SPA shell.
 *
 * Order matters: /health is answered first (public, read-only); then every
 * state-changing request must come from a trusted origin before any route
 * logic runs.
 */
import { createAuditEvent, LogAuditSink } from "../audit/audit";
import type { RequestContext } from "../http/context";
import { ApiError } from "../http/errors";
import { jsonRaw, type ResponseMeta } from "../http/responses";
import { checkOrigin, isStateChanging } from "../security/origin";
import { handleAuthRoute, isAuthPath } from "../auth/gateway";
import { handleAccountRoute, publicConfig } from "./security";

export function isApiPath(pathname: string): boolean {
  return pathname === "/health" || pathname === "/api" || pathname.startsWith("/api/");
}

export async function handleApi(ctx: RequestContext): Promise<Response> {
  const { request, url } = ctx;
  const meta: ResponseMeta = { requestId: ctx.requestId, config: ctx.config, url };

  if (url.pathname === "/health") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      throw new ApiError("METHOD_NOT_ALLOWED", { headers: { allow: "GET, HEAD" } });
    }
    // Deliberately minimal: no versions, bindings, or upstream details.
    return jsonRaw({ status: "ok" }, meta);
  }

  if (isStateChanging(request.method)) {
    const decision = checkOrigin(request, ctx.config.trustedOrigins);
    if (!decision.allowed) {
      const event = createAuditEvent({
        actor: { type: "anonymous" },
        action: "security.origin.rejected",
        requestId: ctx.requestId,
        result: "denied",
        reason: "FORBIDDEN",
        metadata: { method: request.method },
      });
      // Logged, not stored in D1: unauthenticated denials are high-volume and
      // must not let anyone drive unbounded database writes.
      ctx.waitUntil(new LogAuditSink(ctx.logger).record(event));
      throw new ApiError("FORBIDDEN", { logReason: `origin rejected: ${decision.reason}` });
    }
  }

  // Better Auth's endpoints, behind an allowlist gateway.
  if (isAuthPath(url.pathname)) return handleAuthRoute(ctx);

  if (url.pathname === "/api/config") {
    if (request.method !== "GET") throw new ApiError("METHOD_NOT_ALLOWED", { headers: { allow: "GET" } });
    return publicConfig(ctx);
  }

  const account = await handleAccountRoute(ctx);
  if (account) return account;

  // Agent-profile routes arrive in Phase 6.
  throw new ApiError("NOT_FOUND");
}
