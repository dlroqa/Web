/**
 * Per-request authentication services: the Better Auth instance (configured
 * from options.ts), the identity boundary, audit, and `requirePrincipal`.
 *
 * Better Auth runs only when this environment has an approved public origin
 * and a BETTER_AUTH_SECRET; otherwise every auth path is AUTH_UNAVAILABLE.
 */
import { betterAuth } from "better-auth";
import { readSecret } from "../config/secrets";
import { AuditRecorder, D1AuditSink } from "../db/audit";
import type { SecurityMetadata } from "../db/json";
import { UserRepository, type UserStatus } from "../db/users";
import type { RequestContext } from "../http/context";
import { ApiError } from "../http/errors";
import { CloudflareRateLimiter, type RateLimiter } from "../security/rate-limit";
import { securityMetadataFor } from "../security/source-identity";
import { describeError } from "../utils/log";
import { IdentityService, SESSION_ALLOWED_STATUSES } from "./identity";
import { betterAuthErrorHandler, betterAuthLogger } from "./logging";
import { buildAuthOptions, type OAuthClient, type SocialProviderId } from "./options";

const MIN_SECRET_LENGTH = 32;

const NO_PROVIDER_TOKENS = {
  accessToken: null,
  refreshToken: null,
  idToken: null,
  accessTokenExpiresAt: null,
  refreshTokenExpiresAt: null,
} as const;

/** The canonical authenticated caller, as application code sees it. */
export interface Principal {
  authUserId: string;
  userProfileId: string;
  status: UserStatus;
  sessionId: string;
  sessionCreatedAt: number;
}

function oauthClient(env: Env, provider: "GOOGLE" | "GITHUB"): OAuthClient | undefined {
  const clientId = readSecret(env, `${provider}_CLIENT_ID`);
  const clientSecret = readSecret(env, `${provider}_CLIENT_SECRET`);
  return clientId && clientSecret ? { clientId, clientSecret } : undefined;
}

/** Why this request's session creation was refused by account policy, if it was. */
export type SessionDenial = "ACCOUNT_DISABLED";

interface CookieDefinition {
  name: string;
  attributes: { path?: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; domain?: string };
}

/** A Set-Cookie value that deletes `cookie`, with the attributes it was set with. */
export function expiredCookie(cookie: CookieDefinition): string {
  const { path, secure, httpOnly, sameSite, domain } = cookie.attributes;
  const parts = [`${cookie.name}=`, "Max-Age=0", `Path=${path ?? "/"}`];
  if (domain) parts.push(`Domain=${domain}`);
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  if (sameSite) parts.push(`SameSite=${sameSite.charAt(0).toUpperCase()}${sameSite.slice(1).toLowerCase()}`);
  return parts.join("; ");
}

/** Login method recorded in audit metadata, from the Better Auth endpoint path. */
function loginMethod(path: string | undefined, providerParam: unknown): string {
  if (path?.startsWith("/passkey/")) return "passkey";
  if (path?.startsWith("/callback/") && (providerParam === "google" || providerParam === "github")) return providerParam;
  return "unknown";
}

export function createAuthServices(ctx: RequestContext) {
  const { env, config, logger, request } = ctx;
  const authConfig = config.auth;
  const secret = readSecret(env, "BETTER_AUTH_SECRET");
  if (!authConfig || !secret || secret.length < MIN_SECRET_LENGTH) {
    throw new ApiError("AUTH_UNAVAILABLE", { logReason: authConfig ? "BETTER_AUTH_SECRET missing or short" : "auth not configured" });
  }

  const limiter: RateLimiter = new CloudflareRateLimiter(env, logger);
  const users = new UserRepository(env.DB);
  const identity = new IdentityService(users, authConfig.signupPolicy, limiter);
  const audit = new AuditRecorder(new D1AuditSink(env.DB), logger);
  const sourceAddress = request.headers.get("cf-connecting-ip");
  let security: Promise<SecurityMetadata> | undefined;
  const securityMetadata = () => (security ??= securityMetadataFor(request, env).catch(() => ({})));
  // Set by the session.create hook when it refuses a sign-in for account
  // policy, so the gateway can report ACCOUNT_DISABLED instead of a failure.
  let sessionDenial: SessionDenial | null = null;
  // Set when Better Auth reports an unexpected internal error in this request.
  let internalFault = false;

  const google = oauthClient(env, "GOOGLE");
  const github = oauthClient(env, "GITHUB");
  const providers: SocialProviderId[] = [...(google ? (["google"] as const) : []), ...(github ? (["github"] as const) : [])];

  const auth = betterAuth(
    buildAuthOptions({
      database: env.DB,
      publicOrigin: authConfig.publicOrigin,
      passkeyRpId: authConfig.passkeyRpId,
      trustedOrigins: [...config.trustedOrigins],
      secret,
      google,
      github,
      backgroundTask: (promise) => ctx.waitUntil(promise),
      logger: betterAuthLogger(logger, () => {
        internalFault = true;
      }),
      onError: betterAuthErrorHandler(logger),
      databaseHooks: {
        // Sign-in is the only use of OAuth here, so provider tokens are not
        // kept at all (they would grant access to the user's provider account).
        account: {
          create: { before: async (account) => ({ data: { ...account, ...NO_PROVIDER_TOKENS } }) },
          update: { before: async (account) => ({ data: { ...account, ...NO_PROVIDER_TOKENS } }) },
        },
        session: {
          create: {
            // Every new session (OAuth or passkey) passes through here: resolve
            // or create the application profile, and refuse accounts that may
            // not sign in. A failure here fails the sign-in.
            before: async (session, endpoint) => {
              const authUser = await endpoint?.context.internalAdapter.findUserById(session.userId);
              const { user, created } = await identity.ensureProfile(session.userId, { name: authUser?.name, sourceAddress });
              if (created) {
                audit.bestEffort(
                  { actor: { type: "user", id: user.id }, action: "auth.account.created", requestId: ctx.requestId, result: "success", metadata: { status: user.status }, security: await securityMetadata() },
                  ctx.waitUntil,
                );
              }
              if (!SESSION_ALLOWED_STATUSES.includes(user.status)) {
                logger.warn("auth.login.denied", { userId: user.id, status: user.status });
                audit.bestEffort(
                  { actor: { type: "user", id: user.id }, action: "auth.login.failure", requestId: ctx.requestId, result: "denied", reason: "ACCOUNT_DISABLED", security: await securityMetadata() },
                  ctx.waitUntil,
                );
                sessionDenial = "ACCOUNT_DISABLED";
                return false;
              }
              return { data: session };
            },
            after: async (session, endpoint) => {
              const user = await users.getByAuthUserId(session.userId);
              if (!user) return;
              audit.bestEffort(
                {
                  actor: { type: "user", id: user.id },
                  action: "auth.login.success",
                  requestId: ctx.requestId,
                  result: "success",
                  metadata: { method: loginMethod(endpoint?.path, endpoint?.params?.["id"]) },
                  security: await securityMetadata(),
                },
                ctx.waitUntil,
              );
            },
          },
        },
      },
    }),
  );

  /** Resolve the caller from the session cookie, or null when not signed in. */
  async function currentPrincipal(): Promise<Principal | null> {
    let result: Awaited<ReturnType<typeof auth.api.getSession>>;
    try {
      result = await auth.api.getSession({ headers: request.headers });
    } catch (error) {
      logger.error("auth.session.lookup_failed", describeError(error));
      throw new ApiError("INTERNAL_ERROR", { logReason: "session lookup failed" });
    }
    if (!result) return null;
    const { user } = await identity.ensureProfile(result.user.id, { name: result.user.name, sourceAddress });
    return {
      authUserId: result.user.id,
      userProfileId: user.id,
      status: user.status,
      sessionId: result.session.id,
      sessionCreatedAt: new Date(result.session.createdAt).getTime(),
    };
  }

  /**
   * The authenticated caller, or an error: AUTH_REQUIRED without a valid
   * session; ACCOUNT_DISABLED for suspended/disabled accounts (whatever the
   * session says); ACCOUNT_PENDING when the route needs an active account.
   */
  async function requirePrincipal(allow: readonly UserStatus[] = ["active"]): Promise<Principal> {
    const principal = await currentPrincipal();
    if (!principal) throw new ApiError("AUTH_REQUIRED");
    if (principal.status === "suspended" || principal.status === "disabled") {
      throw new ApiError("ACCOUNT_DISABLED", { logReason: `status ${principal.status}` });
    }
    if (!allow.includes(principal.status)) throw new ApiError("ACCOUNT_PENDING");
    return principal;
  }

  /**
   * Set-Cookie values that delete the session cookies: the same names and
   * attributes Better Auth's own sign-out expires.
   */
  async function expiredSessionCookies(): Promise<string[]> {
    const { authCookies } = await auth.$context;
    return [authCookies.sessionToken, authCookies.sessionData, authCookies.dontRememberToken].map(expiredCookie);
  }

  return {
    auth,
    identity,
    users,
    audit,
    limiter,
    providers,
    authConfig,
    securityMetadata,
    currentPrincipal,
    requirePrincipal,
    expiredSessionCookies,
    /** The account-policy reason this request's sign-in was refused, if any. */
    sessionDenial: (): SessionDenial | null => sessionDenial,
    /** Whether Better Auth hit an unexpected internal error in this request. */
    internalFault: (): boolean => internalFault,
  };
}

export type AuthServices = ReturnType<typeof createAuthServices>;
