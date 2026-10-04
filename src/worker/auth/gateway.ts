/**
 * /api/auth/* gateway in front of Better Auth.
 *
 * Only the endpoints Phase 4 needs are reachable; every other Better Auth
 * path is a 404. Each allowed endpoint gets its own policy (rate limit,
 * Turnstile, principal, input rebuilding) before Better Auth sees the
 * request, and its response is reduced to what the browser needs: no
 * session tokens, credential material, or provider error text.
 *
 *   POST /sign-in/social                      Turnstile, IP limit, rebuilt body
 *   GET  /callback/{google,github}            redirect target re-validated
 *   POST /sign-out
 *   GET  /passkey/generate-authenticate-options   IP limit
 *   POST /passkey/verify-authentication           IP limit, body bounded
 *   GET  /passkey/generate-register-options       principal, user limit
 *   POST /passkey/verify-registration             principal, user limit
 *
 * State-changing requests have already passed the router's exact-origin
 * check; Better Auth applies its own origin/CSRF checks as well.
 */
import { z } from "../../shared/zod";
import type { ErrorCode } from "../../shared/errors";
import type { RequestContext } from "../http/context";
import { ApiError } from "../http/errors";
import { jsonError } from "../http/responses";
import { applyApiHeaders } from "../security/headers";
import { enforceRateLimit } from "../security/rate-limit";
import { TurnstileVerifier } from "../security/turnstile";
import { readSecret } from "../config/secrets";
import { readBoundedText } from "../utils/fetch";
import { AUTH_BASE_PATH } from "./options";
import { createAuthServices, type AuthServices } from "./services";

/** Local pages a sign-in may return to. Anything else is rejected. */
export const RETURN_PATHS = ["/dashboard", "/agents", "/security", "/settings"] as const;
export const LOGIN_PATH = "/login";

/** Hosts a sign-in may send the browser to. */
const PROVIDER_AUTH_HOSTS: ReadonlySet<string> = new Set(["accounts.google.com", "github.com"]);

const MAX_AUTH_BODY_BYTES = 16 * 1024;

const SignInSocialBody = z
  .object({
    provider: z.enum(["google", "github"]),
    callbackURL: z.enum(RETURN_PATHS).default("/dashboard"),
    turnstileToken: z.string().min(1).max(2048),
  })
  .strict();

const PasskeyAuthBody = z.object({ response: z.record(z.string(), z.unknown()) }).strict();
const PasskeyRegisterBody = z
  .object({
    response: z.record(z.string(), z.unknown()),
    name: z.string().trim().min(1).max(80).optional(),
  })
  .strict();
const PasskeyRegisterQuery = z
  .object({
    name: z.string().trim().min(1).max(80).optional(),
    authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
  })
  .strict();

const ErrorParam = z.string().regex(/^[a-z0-9_]{1,64}$/i);

async function readJson(request: Request): Promise<unknown> {
  const type = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") throw new ApiError("UNSUPPORTED_MEDIA_TYPE");
  let text: string;
  try {
    text = await readBoundedText(request.body, MAX_AUTH_BODY_BYTES);
  } catch {
    throw new ApiError("PAYLOAD_TOO_LARGE");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError("INVALID_REQUEST", { issues: [{ path: "(root)", code: "invalid_json" }] });
  }
}

function parse<S extends z.ZodType>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new ApiError("INVALID_REQUEST", {
      issues: result.error.issues.slice(0, 10).map((i) => ({ path: i.path.map(String).join(".") || "(root)", code: i.code })),
    });
  }
  return result.data;
}

/** A copy of `original` pointed at `url` with a replacement JSON body. */
function rebuild(original: Request, url: URL, body?: unknown): Request {
  const headers = new Headers(original.headers);
  headers.delete("content-length");
  if (body !== undefined) headers.set("content-type", "application/json");
  return new Request(url, {
    method: original.method,
    headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

/** Copy only Set-Cookie (and optionally Location) from Better Auth's response. */
function finish(ctx: RequestContext, upstream: Response, body: unknown, options: { status?: number; location?: string } = {}): Response {
  const response = new Response(body === null ? null : JSON.stringify(body), { status: options.status ?? upstream.status });
  for (const cookie of upstream.headers.getSetCookie()) response.headers.append("set-cookie", cookie);
  if (options.location) response.headers.set("location", options.location);
  return applyApiHeaders(response, ctx.requestId, ctx.config, ctx.url);
}

/** Map a Better Auth error response to a stable code; its text is discarded. */
async function upstreamError(ctx: RequestContext, upstream: Response): Promise<Response> {
  let code: unknown;
  try {
    const parsed: unknown = JSON.parse(await readBoundedText(upstream.body, MAX_AUTH_BODY_BYTES));
    code = typeof parsed === "object" && parsed !== null ? Reflect.get(parsed, "code") : undefined;
  } catch {
    code = undefined;
  }
  const mapped: ErrorCode =
    upstream.status === 401
      ? "AUTH_REQUIRED"
      : upstream.status === 403 && code === "SESSION_NOT_FRESH"
        ? "REAUTH_REQUIRED"
        : upstream.status === 403
          ? "FORBIDDEN"
          : upstream.status === 429
            ? "RATE_LIMITED"
            : upstream.status >= 400 && upstream.status < 500
              ? "INVALID_REQUEST"
              : "INTERNAL_ERROR";
  ctx.logger.warn("auth.upstream_error", { status: upstream.status, code: typeof code === "string" ? code.slice(0, 64) : null, mapped });
  const response = jsonError(mapped, { requestId: ctx.requestId, config: ctx.config, url: ctx.url });
  for (const cookie of upstream.headers.getSetCookie()) response.headers.append("set-cookie", cookie);
  return response;
}

function clientAddress(ctx: RequestContext): string {
  return ctx.request.headers.get("cf-connecting-ip") ?? "unknown";
}

/**
 * Validate where Better Auth's callback redirect points: our origin and an
 * allowlisted page, otherwise the login page. Error codes are reduced to a
 * safe token.
 */
export function safeCallbackLocation(location: string | null, publicOrigin: string): { location: string; error: string | null } {
  const fallback = { location: `${publicOrigin}${LOGIN_PATH}?error=callback_failed`, error: "callback_failed" };
  if (!location) return fallback;
  let url: URL;
  try {
    url = new URL(location, publicOrigin);
  } catch {
    return fallback;
  }
  if (url.origin !== publicOrigin) return fallback;
  const error = url.searchParams.get("error");
  if (url.pathname === LOGIN_PATH || error !== null) {
    const code = error !== null && ErrorParam.safeParse(error).success ? error.toLowerCase() : "callback_failed";
    return { location: `${publicOrigin}${LOGIN_PATH}?error=${code}`, error: code };
  }
  if (!(RETURN_PATHS as readonly string[]).includes(url.pathname)) return fallback;
  return { location: `${publicOrigin}${url.pathname}`, error: null };
}

async function signInSocial(ctx: RequestContext, s: AuthServices): Promise<Response> {
  const body = parse(SignInSocialBody, await readJson(ctx.request));
  if (!s.providers.includes(body.provider)) throw new ApiError("INVALID_REQUEST", { issues: [{ path: "provider", code: "unavailable" }] });
  await enforceRateLimit(s.limiter, "login", { kind: "ip", address: clientAddress(ctx) });

  const turnstile = await new TurnstileVerifier({
    secret: readSecret(ctx.env, "TURNSTILE_SECRET"),
    environment: ctx.config.environment,
    expectedHostnames: ctx.config.turnstileHostnames,
    logger: ctx.logger,
  }).verify({ token: body.turnstileToken, expectedAction: "login", remoteIp: ctx.request.headers.get("cf-connecting-ip") ?? undefined, idempotencyKey: ctx.requestId });
  if (!turnstile.ok) throw new ApiError("TURNSTILE_FAILED", { logReason: `turnstile ${turnstile.reason}` });

  const upstream = await s.auth.handler(
    rebuild(ctx.request, ctx.url, {
      provider: body.provider,
      callbackURL: body.callbackURL,
      newUserCallbackURL: body.callbackURL,
      errorCallbackURL: LOGIN_PATH,
      disableRedirect: true,
    }),
  );
  if (!upstream.ok) return upstreamError(ctx, upstream);
  const result: unknown = await upstream.json();
  const target = typeof result === "object" && result !== null ? Reflect.get(result, "url") : undefined;
  let url: URL | null = null;
  try {
    url = typeof target === "string" ? new URL(target) : null;
  } catch {
    url = null;
  }
  if (!url || url.protocol !== "https:" || !PROVIDER_AUTH_HOSTS.has(url.hostname)) {
    ctx.logger.error("auth.oauth.unexpected_redirect", { provider: body.provider });
    throw new ApiError("INTERNAL_ERROR", { logReason: "unexpected provider authorization URL" });
  }
  ctx.logger.info("auth.oauth.start", { provider: body.provider });
  return finish(ctx, upstream, { ok: true, data: { url: url.href } }, { status: 200 });
}

async function oauthCallback(ctx: RequestContext, s: AuthServices, provider: string): Promise<Response> {
  await enforceRateLimit(s.limiter, "login", { kind: "ip", address: clientAddress(ctx) });
  const upstream = await s.auth.handler(ctx.request);
  const { location, error } = safeCallbackLocation(upstream.headers.get("location"), s.authConfig.publicOrigin);
  if (error) ctx.logger.warn("auth.oauth.callback.failure", { provider, error });
  await upstream.body?.cancel();
  return finish(ctx, upstream, null, { status: 302, location });
}

async function signOut(ctx: RequestContext, s: AuthServices): Promise<Response> {
  const principal = await s.currentPrincipal().catch(() => null);
  const upstream = await s.auth.handler(rebuild(ctx.request, ctx.url, {}));
  if (!upstream.ok) return upstreamError(ctx, upstream);
  if (principal) {
    s.audit.bestEffort(
      { actor: { type: "user", id: principal.userProfileId }, action: "auth.logout", requestId: ctx.requestId, result: "success", security: await s.securityMetadata() },
      ctx.waitUntil,
    );
  }
  await upstream.body?.cancel();
  return finish(ctx, upstream, { ok: true, data: { signedOut: true } });
}

async function passkeyAuthenticateOptions(ctx: RequestContext, s: AuthServices): Promise<Response> {
  await enforceRateLimit(s.limiter, "passkey_login", { kind: "ip", address: clientAddress(ctx) });
  const upstream = await s.auth.handler(rebuild(ctx.request, new URL(ctx.url.pathname, ctx.url)));
  if (!upstream.ok) return upstreamError(ctx, upstream);
  return finish(ctx, upstream, await upstream.json());
}

async function passkeyVerifyAuthentication(ctx: RequestContext, s: AuthServices): Promise<Response> {
  await enforceRateLimit(s.limiter, "passkey_login", { kind: "ip", address: clientAddress(ctx) });
  const body = parse(PasskeyAuthBody, await readJson(ctx.request));
  const upstream = await s.auth.handler(rebuild(ctx.request, ctx.url, body));
  if (!upstream.ok) {
    ctx.logger.warn("auth.passkey.login.failure", { status: upstream.status });
    return upstreamError(ctx, upstream);
  }
  // Better Auth's body includes the session (and its token): never sent on.
  await upstream.body?.cancel();
  return finish(ctx, upstream, { ok: true, data: { signedIn: true } });
}

async function passkeyRegisterOptions(ctx: RequestContext, s: AuthServices): Promise<Response> {
  const principal = await s.requirePrincipal(["active", "pending"]);
  await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
  const query = parse(PasskeyRegisterQuery, Object.fromEntries(ctx.url.searchParams));
  const url = new URL(ctx.url.pathname, ctx.url);
  if (query.name) url.searchParams.set("name", query.name);
  if (query.authenticatorAttachment) url.searchParams.set("authenticatorAttachment", query.authenticatorAttachment);
  const upstream = await s.auth.handler(rebuild(ctx.request, url));
  if (!upstream.ok) return upstreamError(ctx, upstream);
  return finish(ctx, upstream, await upstream.json());
}

async function passkeyVerifyRegistration(ctx: RequestContext, s: AuthServices): Promise<Response> {
  const principal = await s.requirePrincipal(["active", "pending"]);
  await enforceRateLimit(s.limiter, "security_write", { kind: "user", id: principal.userProfileId });
  const body = parse(PasskeyRegisterBody, await readJson(ctx.request));
  const upstream = await s.auth.handler(rebuild(ctx.request, ctx.url, body));
  if (!upstream.ok) return upstreamError(ctx, upstream);
  const created: unknown = await upstream.json();
  const id = typeof created === "object" && created !== null ? Reflect.get(created, "id") : undefined;
  s.audit.bestEffort(
    { actor: { type: "user", id: principal.userProfileId }, action: "auth.passkey.add", requestId: ctx.requestId, result: "success", security: await s.securityMetadata() },
    ctx.waitUntil,
  );
  return finish(ctx, upstream, { ok: true, data: { id: typeof id === "string" ? id : null } });
}

type Handler = (ctx: RequestContext, services: AuthServices) => Promise<Response>;

const ROUTES: ReadonlyArray<{ method: string; path: string; handler: Handler }> = [
  { method: "POST", path: "/sign-in/social", handler: signInSocial },
  { method: "GET", path: "/callback/google", handler: (c, s) => oauthCallback(c, s, "google") },
  { method: "GET", path: "/callback/github", handler: (c, s) => oauthCallback(c, s, "github") },
  { method: "POST", path: "/sign-out", handler: signOut },
  { method: "GET", path: "/passkey/generate-authenticate-options", handler: passkeyAuthenticateOptions },
  { method: "POST", path: "/passkey/verify-authentication", handler: passkeyVerifyAuthentication },
  { method: "GET", path: "/passkey/generate-register-options", handler: passkeyRegisterOptions },
  { method: "POST", path: "/passkey/verify-registration", handler: passkeyVerifyRegistration },
];

export function isAuthPath(pathname: string): boolean {
  return pathname === AUTH_BASE_PATH || pathname.startsWith(`${AUTH_BASE_PATH}/`);
}

export async function handleAuthRoute(ctx: RequestContext): Promise<Response> {
  const path = ctx.url.pathname.slice(AUTH_BASE_PATH.length);
  const matches = ROUTES.filter((route) => route.path === path);
  if (matches.length === 0) throw new ApiError("NOT_FOUND");
  const route = matches.find((r) => r.method === ctx.request.method);
  if (!route) throw new ApiError("METHOD_NOT_ALLOWED", { headers: { allow: matches.map((r) => r.method).join(", ") } });
  return route.handler(ctx, createAuthServices(ctx));
}
