/**
 * Passkey sign-in verification: whether a request carries a live challenge,
 * decided before the authoritative limiter (M3b).
 *
 * Only a challenge issued by the options endpoint (after Turnstile and the
 * limiter) and not yet used may spend a limiter request. Every step mirrors
 * a check Better Auth makes afterwards, never a looser or stricter one:
 *
 *   1. the challenge cookie, under Better Auth's name for it, read with the
 *      parser Better Auth uses (better-call's: first occurrence wins,
 *      values URI-decoded);
 *   2. better-call's signed value, "<token>.<base64 HMAC-SHA-256>" under
 *      Better Auth's secret (getSignedCookie);
 *   3. a `verification` row for that token that has not expired, which is
 *      what consumeVerificationValue requires.
 *
 * Read-only: one SELECT through Better Auth's generic adapter. Not
 * internalAdapter.findVerificationValue, which deletes expired rows on every
 * call. The row's ceremony type, challenge and user, the WebAuthn assertion,
 * and the single-use consumption itself (DELETE … RETURNING) all remain
 * Better Auth's.
 */
import { parseCookies } from "better-call";
import type { AuthServices } from "./services";

/** The passkey plugin's challenge cookie (its `webAuthnChallengeCookie` default; not overridden in options.ts). */
export const PASSKEY_CHALLENGE_COOKIE = "better-auth-passkey";

export type PasskeyChallengeFailure = "missing" | "malformed" | "bad_signature" | "not_found" | "expired";

/** What the check needs from Better Auth. */
export interface ChallengeSource {
  /** Better Auth's name for the challenge cookie in this environment (prefix included). */
  cookieName: string;
  /** Better Auth's signing secret. */
  secret: string;
  /** The expiry of the challenge row for `token`; null when there is none. Must not write. */
  expiry(token: string): Promise<Date | null>;
}

const encoder = new TextEncoder();

/**
 * The token in a better-call signed cookie value, checked as getSignedCookie
 * checks it: a "." after at least one character, a 44-character base64
 * signature ending in "=", and a valid HMAC-SHA-256 of the token.
 */
export async function signedCookieToken(value: string, secret: string): Promise<{ token: string } | { failure: "malformed" | "bad_signature" }> {
  const dot = value.lastIndexOf(".");
  if (dot < 1) return { failure: "malformed" };
  const token = value.slice(0, dot);
  const signature = value.slice(dot + 1);
  if (signature.length !== 44 || !signature.endsWith("=")) return { failure: "malformed" };
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  } catch {
    return { failure: "malformed" };
  }
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return (await crypto.subtle.verify("HMAC", key, bytes, encoder.encode(token))) ? { token } : { failure: "bad_signature" };
}

/**
 * Why passkey verification cannot succeed, decided without the limiter;
 * null when Better Auth has to decide. Errors from the source (D1) propagate:
 * the caller refuses the request.
 */
export async function passkeyChallengeFailure(cookieHeader: string | null, source: ChallengeSource, now: number = Date.now()): Promise<PasskeyChallengeFailure | null> {
  const value = parseCookies(cookieHeader ?? "").get(source.cookieName);
  if (!value) return "missing";
  const signed = await signedCookieToken(value, source.secret);
  if ("failure" in signed) return signed.failure;
  const expiresAt = await source.expiry(signed.token);
  if (expiresAt === null) return "not_found";
  // Better Auth's comparison (`expiresAt < new Date()`), so an unreadable
  // date is left to Better Auth rather than refused here.
  if (expiresAt.getTime() < now) return "expired";
  return null;
}

/** The challenge source of a Better Auth instance: its cookie name, secret and a read-only row lookup. */
export async function betterAuthChallengeSource(auth: AuthServices["auth"]): Promise<ChallengeSource> {
  const { adapter, secret, createAuthCookie } = await auth.$context;
  return {
    cookieName: createAuthCookie(PASSKEY_CHALLENGE_COOKIE).name,
    secret,
    async expiry(token) {
      const row = await adapter.findOne<{ expiresAt: Date | string }>({ model: "verification", where: [{ field: "identifier", value: token }] });
      return row ? new Date(row.expiresAt) : null;
    },
  };
}
