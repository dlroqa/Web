/**
 * Better Auth configuration, as one pure function.
 *
 * The Worker (auth.ts) and the schema tooling (scripts/auth-schema.ts and the
 * schema drift test) build their options here, so the schema checked in CI is
 * exactly the schema the Worker uses.
 *
 * Every default we override is listed in docs/AUTHENTICATION.md.
 */
import { passkey } from "@better-auth/passkey";
import type { BetterAuthOptions } from "better-auth";

export const AUTH_BASE_PATH = "/api/auth";
export const COOKIE_PREFIX = "lightagent";
/** Cookies are only ever needed by /api requests. */
export const AUTH_COOKIE_PATH = "/api";

export const SESSION_EXPIRES_IN_SECONDS = 7 * 24 * 60 * 60;
export const SESSION_UPDATE_AGE_SECONDS = 24 * 60 * 60;
/**
 * A session counts as "fresh" (recent authentication) for this long after
 * sign-in. Passkey registration and removal require a fresh session.
 */
export const SESSION_FRESH_AGE_SECONDS = 10 * 60;

/** Minimum identity scopes. Nothing beyond sign-in is ever requested. */
export const OAUTH_SCOPES = {
  google: ["openid", "email", "profile"],
  github: ["read:user", "user:email"],
} as const;

export type SocialProviderId = keyof typeof OAUTH_SCOPES;

export interface OAuthClient {
  clientId: string;
  clientSecret: string;
}

export interface AuthOptionsInput {
  database: BetterAuthOptions["database"];
  publicOrigin: string;
  passkeyRpId: string;
  trustedOrigins: readonly string[];
  secret: string;
  google?: OAuthClient | undefined;
  github?: OAuthClient | undefined;
  databaseHooks?: BetterAuthOptions["databaseHooks"];
  backgroundTask?: (promise: Promise<unknown>) => void;
  /** Routes Better Auth's diagnostics through our redacting logger (see logging.ts). */
  logger?: BetterAuthOptions["logger"];
  onError?: NonNullable<BetterAuthOptions["onAPIError"]>["onError"];
}

export function buildAuthOptions(input: AuthOptionsInput) {
  const secure = input.publicOrigin.startsWith("https://");
  const socialProviders: NonNullable<BetterAuthOptions["socialProviders"]> = {};
  if (input.google) {
    socialProviders.google = {
      clientId: input.google.clientId,
      clientSecret: input.google.clientSecret,
      disableDefaultScope: true,
      scope: [...OAUTH_SCOPES.google],
      // Do not fold in scopes granted to this client earlier.
      includeGrantedScopes: false,
      prompt: "select_account",
    };
  }
  if (input.github) {
    socialProviders.github = {
      clientId: input.github.clientId,
      clientSecret: input.github.clientSecret,
      disableDefaultScope: true,
      scope: [...OAUTH_SCOPES.github],
    };
  }

  return {
    appName: "Lightagent",
    baseURL: input.publicOrigin,
    basePath: AUTH_BASE_PATH,
    secret: input.secret,
    database: input.database,
    trustedOrigins: [...input.trustedOrigins],
    socialProviders,
    // No passwords, magic links, OTP, or anonymous accounts in Phase 4.
    emailAndPassword: { enabled: false },
    session: {
      expiresIn: SESSION_EXPIRES_IN_SECONDS,
      updateAge: SESSION_UPDATE_AGE_SECONDS,
      freshAge: SESSION_FRESH_AGE_SECONDS,
      // Every request is checked against D1, so a revoked session stops
      // working immediately (a cookie cache would keep it alive).
      cookieCache: { enabled: false },
    },
    account: {
      // OAuth tokens are not needed after sign-in; encrypt them at rest anyway.
      encryptOAuthTokens: true,
      accountLinking: {
        enabled: true,
        // Never merge identities automatically on sign-in, even on a
        // matching verified email. Linking is an explicit, authenticated action.
        disableImplicitLinking: true,
        allowDifferentEmails: false,
        requireLocalEmailVerified: true,
      },
    },
    plugins: [
      passkey({
        rpID: input.passkeyRpId,
        rpName: "Lightagent",
        origin: input.publicOrigin,
        authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
        // Registration needs an existing, fresh session: no passkey-first sign-up.
        registration: { requireSession: true },
      }),
    ],
    // The Worker enforces rate limits with Cloudflare bindings before requests
    // reach Better Auth; its in-memory limiter is per-isolate and unreliable.
    rateLimit: { enabled: false },
    advanced: {
      useSecureCookies: secure,
      cookiePrefix: COOKIE_PREFIX,
      defaultCookieAttributes: { httpOnly: true, sameSite: "lax", path: AUTH_COOKIE_PATH, secure },
      cookies: {
        // Only same-origin API calls need the session; Strict keeps it off
        // every cross-site request. (The OAuth state cookie stays Lax so it
        // survives the provider's redirect back.)
        session_token: { attributes: { sameSite: "strict", httpOnly: true, path: AUTH_COOKIE_PATH, secure } },
      },
      // Sessions do not record raw client IPs.
      ipAddress: { disableIpTracking: true },
      ...(input.backgroundTask ? { backgroundTasks: { handler: input.backgroundTask } } : {}),
    },
    onAPIError: {
      throw: false,
      // Provider and callback errors land on the login page with a code only.
      errorURL: `${input.publicOrigin}/login`,
      ...(input.onError ? { onError: input.onError } : {}),
    },
    ...(input.logger ? { logger: input.logger } : {}),
    telemetry: { enabled: false },
    ...(input.databaseHooks ? { databaseHooks: input.databaseHooks } : {}),
  } satisfies BetterAuthOptions;
}
