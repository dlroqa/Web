/**
 * Account endpoints for the signed-in user:
 *
 *   GET    /api/config                      public sign-in options (no auth)
 *   GET    /api/session                     sign-in state probe for the SPA (always 200)
 *   GET    /api/me                          application identity
 *   GET    /api/security/methods            connected sign-in methods
 *   GET    /api/security/sessions           active sessions (no tokens)
 *   DELETE /api/security/sessions/:id       revoke one of the caller's sessions
 *   POST   /api/security/sessions/revoke-all   revoke every session, including this one
 *   GET    /api/security/passkeys           the caller's passkeys (no credential data)
 *   PATCH  /api/security/passkeys/:id       rename
 *   DELETE /api/security/passkeys/:id       remove (requires a fresh session)
 *   GET    /api/security/activity           the caller's audit trail
 *
 * Every lookup is scoped to the principal's own auth user id, so another
 * user's session or passkey id behaves exactly like one that does not exist
 * (404). Better Auth session tokens never leave the Worker: sessions are
 * addressed by their opaque id and revoked by token server-side.
 */
import { z } from "../../shared/zod";
import { AuditRepository } from "../db/audit";
import { NameSchema } from "../db/common";
import type { RequestContext } from "../http/context";
import { ApiError } from "../http/errors";
import { jsonOk, type ResponseMeta } from "../http/responses";
import { parseJsonBody } from "../http/validation";
import { enforceRateLimit } from "../security/rate-limit";
import { SESSION_FRESH_AGE_SECONDS } from "../auth/options";
import { passkeyAuditFields } from "../auth/passkey-audit";
import { createAuthServices, type AuthServices, type Principal } from "../auth/services";

const ACCOUNT_STATUSES = ["active", "pending"] as const;

/** Better Auth ids: opaque, but bounded and simple so they are safe in paths. */
const OpaqueId = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/);

function meta(ctx: RequestContext): ResponseMeta {
  return { requestId: ctx.requestId, config: ctx.config, url: ctx.url };
}

function opaqueId(value: string | undefined): string {
  const parsed = OpaqueId.safeParse(value);
  if (!parsed.success) throw new ApiError("NOT_FOUND");
  return parsed.data;
}

/** A short, safe description of a user agent string (never the raw value). */
export function describeUserAgent(userAgent: unknown): string {
  if (typeof userAgent !== "string" || userAgent.length === 0) return "Unknown device";
  const browser = /Edg\//.test(userAgent)
    ? "Edge"
    : /Firefox\//.test(userAgent)
      ? "Firefox"
      : /Chrome\//.test(userAgent)
        ? "Chrome"
        : /Safari\//.test(userAgent)
          ? "Safari"
          : "Browser";
  const os = /iPhone|iPad/.test(userAgent)
    ? "iOS"
    : /Android/.test(userAgent)
      ? "Android"
      : /Mac OS X/.test(userAgent)
        ? "macOS"
        : /Windows/.test(userAgent)
          ? "Windows"
          : /Linux/.test(userAgent)
            ? "Linux"
            : "Unknown OS";
  return `${browser} on ${os}`;
}

const time = (value: unknown): number | null => {
  if (value === null || value === undefined) return null;
  const ms = value instanceof Date ? value.getTime() : new Date(String(value)).getTime();
  return Number.isFinite(ms) ? ms : null;
};

async function adapterOf(s: AuthServices) {
  return (await s.auth.$context).internalAdapter;
}

interface PasskeyRow {
  id: string;
  name?: string | null;
  userId: string;
  deviceType?: string;
  backedUp?: boolean | number;
  createdAt?: Date | string | null;
  /** Used only to derive the audit fingerprint; never returned to the browser. */
  credentialID?: string | null;
}

async function ownPasskeys(s: AuthServices, principal: Principal): Promise<PasskeyRow[]> {
  const adapter = (await s.auth.$context).adapter;
  return adapter.findMany<PasskeyRow>({ model: "passkey", where: [{ field: "userId", value: principal.authUserId }], limit: 50 });
}

async function findOwnPasskey(s: AuthServices, principal: Principal, id: string): Promise<PasskeyRow> {
  const adapter = (await s.auth.$context).adapter;
  const row = await adapter.findOne<PasskeyRow>({
    model: "passkey",
    where: [
      { field: "id", value: id },
      { field: "userId", value: principal.authUserId },
    ],
  });
  if (!row) throw new ApiError("NOT_FOUND");
  return row;
}

/** A JSON response that also deletes the browser's session cookies. */
async function withSessionCookiesCleared(s: AuthServices, response: Response): Promise<Response> {
  for (const cookie of await s.expiredSessionCookies()) response.headers.append("set-cookie", cookie);
  return response;
}

function requireFresh(principal: Principal): void {
  if (Date.now() - principal.sessionCreatedAt >= SESSION_FRESH_AGE_SECONDS * 1000) {
    throw new ApiError("REAUTH_REQUIRED");
  }
}

const RenameBody = z.object({ name: NameSchema }).strict();

type Handler = (ctx: RequestContext, s: AuthServices, params: Record<string, string>) => Promise<Response>;

const handlers = {
  async me(ctx, s) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    const user = await s.users.getById(principal.userProfileId);
    if (!user) throw new ApiError("INTERNAL_ERROR", { logReason: "principal without profile" });
    return jsonOk({ id: user.id, displayName: user.displayName, status: user.status }, meta(ctx));
  },

  /**
   * Bootstrap probe: whether the browser is signed in, without a 401 (which
   * browsers log as an error) when it is not. Same fields as /api/me.
   */
  async session(ctx, s) {
    const principal = await s.currentPrincipal();
    if (!principal) return jsonOk({ signedIn: false }, meta(ctx));
    if (principal.status === "suspended" || principal.status === "disabled") {
      return jsonOk({ signedIn: false, blocked: true }, meta(ctx));
    }
    const user = await s.users.getById(principal.userProfileId);
    if (!user) throw new ApiError("INTERNAL_ERROR", { logReason: "principal without profile" });
    return jsonOk({ signedIn: true, me: { id: user.id, displayName: user.displayName, status: user.status } }, meta(ctx));
  },

  async methods(ctx, s) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const accounts = await (await adapterOf(s)).findAccounts(principal.authUserId);
    const providers = [...new Set(accounts.map((a) => a.providerId).filter((p) => p === "google" || p === "github"))];
    const passkeys = (await ownPasskeys(s, principal)).length;
    return jsonOk({ providers, passkeys }, meta(ctx));
  },

  async listSessions(ctx, s) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const sessions = await (await adapterOf(s)).listSessions(principal.authUserId, { onlyActiveSessions: true });
    const data = sessions
      .map((session) => ({
        id: session.id,
        device: describeUserAgent(session.userAgent),
        createdAt: time(session.createdAt),
        lastActiveAt: time(session.updatedAt),
        expiresAt: time(session.expiresAt),
        current: session.id === principal.sessionId,
      }))
      .sort((a, b) => (b.lastActiveAt ?? 0) - (a.lastActiveAt ?? 0));
    return jsonOk(data, meta(ctx));
  },

  async revokeSession(ctx, s, params) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
    const id = opaqueId(params["id"]);
    const adapter = await adapterOf(s);
    const target = (await adapter.listSessions(principal.authUserId)).find((session) => session.id === id);
    if (!target) throw new ApiError("NOT_FOUND");
    await adapter.deleteSession(target.token);
    const current = id === principal.sessionId;
    s.audit.bestEffort(
      {
        actor: { type: "user", id: principal.userProfileId },
        action: "auth.session.revoke",
        target: { type: "session", id },
        requestId: ctx.requestId,
        result: "success",
        metadata: { current },
        security: await s.securityMetadata(),
      },
      ctx.waitUntil,
    );
    const response = jsonOk({ revoked: true, current }, meta(ctx));
    // Revoking this browser's own session signs it out here too.
    return current ? withSessionCookiesCleared(s, response) : response;
  },

  async revokeAllSessions(ctx, s) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
    // Every session, including the caller's: "sign out everywhere".
    await (await adapterOf(s)).deleteUserSessions(principal.authUserId);
    s.audit.bestEffort(
      { actor: { type: "user", id: principal.userProfileId }, action: "auth.session.revoke_all", requestId: ctx.requestId, result: "success", security: await s.securityMetadata() },
      ctx.waitUntil,
    );
    // The caller's session is gone too, so this browser is signed out:
    // expire its cookies exactly as sign-out does.
    return withSessionCookiesCleared(s, jsonOk({ revoked: true, current: true }, meta(ctx)));
  },

  async listPasskeys(ctx, s) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const data = (await ownPasskeys(s, principal)).map((p) => ({
      id: p.id,
      name: p.name ?? null,
      deviceType: p.deviceType === "multiDevice" ? "synced" : "device-bound",
      backedUp: p.backedUp === true || p.backedUp === 1,
      createdAt: time(p.createdAt),
    }));
    return jsonOk(data, meta(ctx));
  },

  async renamePasskey(ctx, s, params) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
    const id = opaqueId(params["id"]);
    const { name } = await parseJsonBody(ctx.request, RenameBody);
    const existing = await findOwnPasskey(s, principal, id);
    const adapter = (await s.auth.$context).adapter;
    await adapter.update({
      model: "passkey",
      where: [
        { field: "id", value: id },
        { field: "userId", value: principal.authUserId },
      ],
      update: { name },
    });
    s.audit.bestEffort(
      {
        actor: { type: "user", id: principal.userProfileId },
        action: "auth.passkey.rename",
        requestId: ctx.requestId,
        result: "success",
        ...(await passkeyAuditFields({ ...existing, name })),
        security: await s.securityMetadata(),
      },
      ctx.waitUntil,
    );
    return jsonOk({ id, name }, meta(ctx));
  },

  async removePasskey(ctx, s, params) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
    const id = opaqueId(params["id"]);
    const existing = await findOwnPasskey(s, principal, id);
    requireFresh(principal);
    const adapter = (await s.auth.$context).adapter;
    await adapter.delete({
      model: "passkey",
      where: [
        { field: "id", value: id },
        { field: "userId", value: principal.authUserId },
      ],
    });
    s.audit.bestEffort(
      {
        actor: { type: "user", id: principal.userProfileId },
        action: "auth.passkey.remove",
        requestId: ctx.requestId,
        result: "success",
        ...(await passkeyAuditFields(existing)),
        security: await s.securityMetadata(),
      },
      ctx.waitUntil,
    );
    return jsonOk({ removed: true }, meta(ctx));
  },

  async activity(ctx, s) {
    const principal = await s.requirePrincipal(ACCOUNT_STATUSES);
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const events = await new AuditRepository(ctx.env.DB).listForUser(principal.userProfileId, 50);
    return jsonOk(
      events.map((e) => ({ id: e.id, timestamp: e.timestamp, action: e.action, result: e.result, country: e.country })),
      meta(ctx),
    );
  },
} satisfies Record<string, Handler>;

const ROUTES: ReadonlyArray<{ method: string; pattern: RegExp; handler: Handler }> = [
  { method: "GET", pattern: /^\/api\/me$/, handler: handlers.me },
  { method: "GET", pattern: /^\/api\/session$/, handler: handlers.session },
  { method: "GET", pattern: /^\/api\/security\/methods$/, handler: handlers.methods },
  { method: "GET", pattern: /^\/api\/security\/sessions$/, handler: handlers.listSessions },
  { method: "POST", pattern: /^\/api\/security\/sessions\/revoke-all$/, handler: handlers.revokeAllSessions },
  { method: "DELETE", pattern: /^\/api\/security\/sessions\/(?<id>[^/]+)$/, handler: handlers.revokeSession },
  { method: "GET", pattern: /^\/api\/security\/passkeys$/, handler: handlers.listPasskeys },
  { method: "PATCH", pattern: /^\/api\/security\/passkeys\/(?<id>[^/]+)$/, handler: handlers.renamePasskey },
  { method: "DELETE", pattern: /^\/api\/security\/passkeys\/(?<id>[^/]+)$/, handler: handlers.removePasskey },
  { method: "GET", pattern: /^\/api\/security\/activity$/, handler: handlers.activity },
];

/** Public, non-secret sign-in options for the login page. */
export function publicConfig(ctx: RequestContext): Response {
  const providers: string[] = [];
  if (ctx.config.auth) {
    const has = (name: "GOOGLE" | "GITHUB") => Reflect.get(ctx.env, `${name}_CLIENT_ID`) && Reflect.get(ctx.env, `${name}_CLIENT_SECRET`);
    if (has("GOOGLE")) providers.push("google");
    if (has("GITHUB")) providers.push("github");
  }
  return jsonOk(
    {
      signInAvailable: ctx.config.auth !== null,
      providers,
      passkeys: ctx.config.auth !== null,
      turnstileSiteKey: ctx.config.turnstileSiteKey,
    },
    meta(ctx),
  );
}

/** Route /api/me and /api/security/*; null when the path is not ours. */
export async function handleAccountRoute(ctx: RequestContext): Promise<Response | null> {
  const candidates = ROUTES.filter((route) => route.pattern.test(ctx.url.pathname));
  if (candidates.length === 0) return null;
  const route = candidates.find((r) => r.method === ctx.request.method);
  if (!route) throw new ApiError("METHOD_NOT_ALLOWED", { headers: { allow: candidates.map((r) => r.method).join(", ") } });
  const params = route.pattern.exec(ctx.url.pathname)?.groups ?? {};
  return route.handler(ctx, createAuthServices(ctx), params);
}
