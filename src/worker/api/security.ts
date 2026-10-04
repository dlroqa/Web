/**
 * Account endpoints for the signed-in user. Each route declares its access
 * level from src/shared/access.ts (the policy the browser's route gate also
 * uses); `handleAccountRoute` resolves the principal at that level before
 * any handler runs, so no handler checks status itself.
 *
 *   GET    /api/config                      public sign-in options (no auth)
 *   GET    /api/session                     sign-in state probe for the SPA (always 200)
 *   GET    /api/me                          application identity          (identity)
 *   PATCH  /api/me                          change display name           (active)
 *   GET    /api/account/overview            dashboard summary             (active)
 *   GET    /api/agents                      the caller's agent profiles, read-only (active)
 *   GET    /api/security/methods            connected sign-in methods     (active, as below)
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
import type { Access } from "../../shared/access";
import { z } from "../../shared/zod";
import { AgentProfileRepository } from "../db/agent-profiles";
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
const DisplayNameBody = z.object({ displayName: NameSchema }).strict();

type Handler = (ctx: RequestContext, s: AuthServices, params: Record<string, string>, principal: Principal) => Promise<Response>;

async function loadMe(s: AuthServices, principal: Principal) {
  const user = await s.users.getById(principal.userProfileId);
  if (!user) throw new ApiError("INTERNAL_ERROR", { logReason: "principal without profile" });
  return { id: user.id, displayName: user.displayName, status: user.status };
}

const handlers = {
  async me(ctx, s, _params, principal) {
    return jsonOk(await loadMe(s, principal), meta(ctx));
  },

  async updateMe(ctx, s, _params, principal) {
    await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
    const { displayName } = await parseJsonBody(ctx.request, DisplayNameBody);
    const user = await s.users.updateDisplayName(principal.userProfileId, displayName);
    s.audit.bestEffort(
      // The new name itself is not recorded (it is personal data, and shown on the profile).
      { actor: { type: "user", id: principal.userProfileId }, action: "account.profile.update", requestId: ctx.requestId, result: "success", metadata: { field: "displayName" }, security: await s.securityMetadata() },
      ctx.waitUntil,
    );
    return jsonOk({ id: user.id, displayName: user.displayName, status: user.status }, meta(ctx));
  },

  async overview(ctx, s, _params, principal) {
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const me = await loadMe(s, principal);
    const adapter = await adapterOf(s);
    const [accounts, passkeyRows, sessions, agents] = await Promise.all([
      adapter.findAccounts(principal.authUserId),
      ownPasskeys(s, principal),
      adapter.listSessions(principal.authUserId, { onlyActiveSessions: true }),
      new AgentProfileRepository(ctx.env.DB).forUser(principal.userProfileId).countLive(),
    ]);
    const current = sessions.find((session) => session.id === principal.sessionId);
    return jsonOk(
      {
        displayName: me.displayName,
        status: me.status,
        signIn: { providers: [...new Set(accounts.map((a) => a.providerId).filter((p) => p === "google" || p === "github"))], passkeys: passkeyRows.length },
        sessions: { active: sessions.length, currentExpiresAt: time(current?.expiresAt) },
        agents: { count: agents },
      },
      meta(ctx),
    );
  },

  async agents(ctx, s, _params, principal) {
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    // Read-only until provisioning ships: only the caller's own profiles, no harness or permission details.
    const profiles = await new AgentProfileRepository(ctx.env.DB).forUser(principal.userProfileId).list();
    return jsonOk(profiles.map((p) => ({ id: p.id, name: p.agentName, status: p.status, createdAt: p.createdAt })), meta(ctx));
  },

  async methods(ctx, s, _params, principal) {
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const accounts = await (await adapterOf(s)).findAccounts(principal.authUserId);
    const providers = [...new Set(accounts.map((a) => a.providerId).filter((p) => p === "google" || p === "github"))];
    const passkeys = (await ownPasskeys(s, principal)).length;
    return jsonOk({ providers, passkeys }, meta(ctx));
  },

  async listSessions(ctx, s, _params, principal) {
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

  async revokeSession(ctx, s, params, principal) {
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

  async revokeAllSessions(ctx, s, _params, principal) {
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

  async listPasskeys(ctx, s, _params, principal) {
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

  async renamePasskey(ctx, s, params, principal) {
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

  async removePasskey(ctx, s, params, principal) {
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

  async activity(ctx, s, _params, principal) {
    await enforceRateLimit(s.limiter, "read", { kind: "user", id: principal.userProfileId });
    const events = await new AuditRepository(ctx.env.DB).listForUser(principal.userProfileId, 50);
    return jsonOk(
      events.map((e) => ({ id: e.id, timestamp: e.timestamp, action: e.action, result: e.result, country: e.country })),
      meta(ctx),
    );
  },
} satisfies Record<string, Handler>;

/**
 * Bootstrap probe: whether the browser is signed in, without a 401 (which
 * browsers log as an error) when it is not. Same fields as /api/me; a
 * suspended or disabled account is reported as blocked, with its status.
 */
async function sessionProbe(ctx: RequestContext, s: AuthServices): Promise<Response> {
  const principal = await s.currentPrincipal();
  if (!principal) return jsonOk({ signedIn: false }, meta(ctx));
  if (principal.status === "suspended" || principal.status === "disabled") {
    return jsonOk({ signedIn: false, blocked: true, status: principal.status }, meta(ctx));
  }
  return jsonOk({ signedIn: true, me: await loadMe(s, principal) }, meta(ctx));
}

type ApiAccess = Exclude<Access, "public">;

/** Every account route and the access level it requires. */
export const ACCOUNT_ROUTES: ReadonlyArray<{ method: string; pattern: RegExp; access: ApiAccess; handler: Handler }> = [
  { method: "GET", pattern: /^\/api\/me$/, access: "identity", handler: handlers.me },
  { method: "PATCH", pattern: /^\/api\/me$/, access: "active", handler: handlers.updateMe },
  { method: "GET", pattern: /^\/api\/account\/overview$/, access: "active", handler: handlers.overview },
  { method: "GET", pattern: /^\/api\/agents$/, access: "active", handler: handlers.agents },
  { method: "GET", pattern: /^\/api\/security\/methods$/, access: "active", handler: handlers.methods },
  { method: "GET", pattern: /^\/api\/security\/sessions$/, access: "active", handler: handlers.listSessions },
  { method: "POST", pattern: /^\/api\/security\/sessions\/revoke-all$/, access: "active", handler: handlers.revokeAllSessions },
  { method: "DELETE", pattern: /^\/api\/security\/sessions\/(?<id>[^/]+)$/, access: "active", handler: handlers.revokeSession },
  { method: "GET", pattern: /^\/api\/security\/passkeys$/, access: "active", handler: handlers.listPasskeys },
  { method: "PATCH", pattern: /^\/api\/security\/passkeys\/(?<id>[^/]+)$/, access: "active", handler: handlers.renamePasskey },
  { method: "DELETE", pattern: /^\/api\/security\/passkeys\/(?<id>[^/]+)$/, access: "active", handler: handlers.removePasskey },
  { method: "GET", pattern: /^\/api\/security\/activity$/, access: "active", handler: handlers.activity },
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

/** Route the account API; null when the path is not ours. */
export async function handleAccountRoute(ctx: RequestContext): Promise<Response | null> {
  if (ctx.url.pathname === "/api/session") {
    if (ctx.request.method !== "GET") throw new ApiError("METHOD_NOT_ALLOWED", { headers: { allow: "GET" } });
    return sessionProbe(ctx, createAuthServices(ctx));
  }
  const candidates = ACCOUNT_ROUTES.filter((route) => route.pattern.test(ctx.url.pathname));
  if (candidates.length === 0) return null;
  const route = candidates.find((r) => r.method === ctx.request.method);
  if (!route) throw new ApiError("METHOD_NOT_ALLOWED", { headers: { allow: candidates.map((r) => r.method).join(", ") } });
  const params = route.pattern.exec(ctx.url.pathname)?.groups ?? {};
  const services = createAuthServices(ctx);
  const principal = await services.requirePrincipal(route.access);
  return route.handler(ctx, services, params, principal);
}
