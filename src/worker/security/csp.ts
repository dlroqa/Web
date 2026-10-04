/**
 * Content Security Policy.
 *
 * Documents get a fresh nonce per response. Production allows scripts only
 * from this origin or carrying that nonce, and styles only from this origin.
 * Development additionally lets nonce-carrying <style> elements through,
 * because Vite injects CSS at runtime (it stamps them with the nonce via the
 * `csp-nonce` meta tag). The development policy is never served by a
 * production build. Add third-party sources only alongside the feature that
 * needs them, and as narrowly as possible.
 */
import { randomBase64 } from "../utils/random";

export type CspMode = "production" | "development";

/**
 * Cloudflare Turnstile (login page): its script and challenge iframe. This is
 * the only third-party origin. OAuth sign-in is a top-level navigation to
 * Google/GitHub, which CSP does not govern, so no provider origin is listed.
 */
export const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";

/** Placeholder Vite writes into nonce attributes (vite.config.ts html.cspNonce). */
export const CSP_NONCE_PLACEHOLDER = "LIGHTAGENT_CSP_NONCE";

/** 128 bits from the platform CSPRNG, base64-encoded. One per document. */
export function generateNonce(): string {
  return randomBase64(16);
}

const NONCE_PATTERN = /^[A-Za-z0-9+/]{22}==$/;

export function documentCsp(nonce: string, mode: CspMode): string {
  if (!NONCE_PATTERN.test(nonce)) {
    throw new Error("invalid CSP nonce");
  }
  const directives: Array<[string, string[]]> = [
    ["default-src", ["'self'"]],
    ["base-uri", ["'self'"]],
    ["object-src", ["'none'"]],
    ["frame-ancestors", ["'none'"]],
    ["form-action", ["'self'"]],
    ["script-src", ["'self'", `'nonce-${nonce}'`, TURNSTILE_ORIGIN]],
    ["style-src", mode === "development" ? ["'self'", `'nonce-${nonce}'`] : ["'self'"]],
    ["img-src", ["'self'", "data:"]],
    ["font-src", ["'self'"]],
    ["connect-src", ["'self'"]],
    ["manifest-src", ["'self'"]],
    ["worker-src", ["'self'"]],
    ["frame-src", [TURNSTILE_ORIGIN]],
  ];
  return directives.map(([name, sources]) => `${name} ${sources.join(" ")}`).join("; ");
}

/**
 * Policy for JSON and other non-document responses: nothing may load, and the
 * response cannot be framed. Makes a JSON body inert if opened as a page.
 */
export const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
