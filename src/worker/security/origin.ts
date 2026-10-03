/**
 * Trusted-origin enforcement for state-changing requests (CSRF defense).
 *
 * The allowlist comes only from server configuration (TRUSTED_ORIGINS). The
 * request's Origin header is parsed, normalized, and compared for exact
 * equality with that set; substring, prefix, or suffix matching is never
 * used. A missing or opaque ("null") Origin on an unsafe method is rejected,
 * as is any request the browser labels cross-site. An empty allowlist rejects
 * everything (fail closed).
 */
import { ApiError } from "../http/errors";

export const SAFE_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);

export function isStateChanging(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

/** Normalize an Origin header value; undefined when it is not a usable origin. */
export function normalizeOriginHeader(value: string | null): string | undefined {
  if (value === null || value === "" || value === "null") return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
  // A real Origin header is scheme://host[:port] with nothing else.
  if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) return undefined;
  if (value.endsWith("/")) return undefined;
  return url.origin;
}

export type OriginDecision = { allowed: true; origin: string } | { allowed: false; reason: string };

export function checkOrigin(request: Request, trustedOrigins: ReadonlySet<string>): OriginDecision {
  if (trustedOrigins.size === 0) {
    return { allowed: false, reason: "no trusted origins configured" };
  }
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") {
    return { allowed: false, reason: "sec-fetch-site cross-site" };
  }
  const origin = normalizeOriginHeader(request.headers.get("origin"));
  if (origin === undefined) {
    return { allowed: false, reason: "missing or invalid origin" };
  }
  if (!trustedOrigins.has(origin)) {
    return { allowed: false, reason: "untrusted origin" };
  }
  return { allowed: true, origin };
}

/** Throw FORBIDDEN unless a state-changing request comes from a trusted origin. */
export function requireTrustedOrigin(request: Request, trustedOrigins: ReadonlySet<string>): void {
  if (!isStateChanging(request.method)) return;
  const decision = checkOrigin(request, trustedOrigins);
  if (!decision.allowed) {
    throw new ApiError("FORBIDDEN", { logReason: `origin rejected: ${decision.reason}` });
  }
}
