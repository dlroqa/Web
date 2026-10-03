/**
 * The one place response security headers are decided.
 *
 * Routes never set security headers themselves; they return a Response and
 * the router passes it through `applyApiHeaders` or `applyDocumentHeaders`.
 * Static /assets/* responses get their headers from public/_headers.
 */
import type { AppConfig } from "../config/config";
import { API_CSP, documentCsp, type CspMode } from "./csp";

export const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "browsing-topics=()",
  "camera=()",
  "display-capture=()",
  "geolocation=()",
  "gyroscope=()",
  "magnetometer=()",
  "microphone=()",
  "payment=()",
  "usb=()",
  // Passkeys (WebAuthn) are used by this origin only.
  "publickey-credentials-create=(self)",
  "publickey-credentials-get=(self)",
].join(", ");

function setCommon(headers: Headers, config: AppConfig | undefined, url: URL | undefined): void {
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", PERMISSIONS_POLICY);
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  // HSTS only over HTTPS and only where configured (production hostname
  // verification is a human checkpoint; 0 disables).
  if (config && config.hstsMaxAge > 0 && url?.protocol === "https:") {
    headers.set("strict-transport-security", `max-age=${config.hstsMaxAge}; includeSubDomains`);
  }
}

/** Headers for JSON API responses (and /health). */
export function applyApiHeaders(response: Response, requestId: string, config: AppConfig | undefined, url?: URL): Response {
  const out = new Response(response.body, response);
  const headers = out.headers;
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", API_CSP);
  headers.set("x-request-id", requestId);
  setCommon(headers, config, url);
  return out;
}

/** Headers for HTML documents. `nonce` must be the one written into the body. */
export function applyDocumentHeaders(
  response: Response,
  nonce: string,
  mode: CspMode,
  config: AppConfig | undefined,
  url: URL,
): Response {
  const out = new Response(response.body, response);
  const headers = out.headers;
  headers.set("content-type", "text/html; charset=utf-8");
  // Each document carries a unique nonce; it must never be cached or shared.
  headers.set("cache-control", "no-store");
  headers.delete("etag");
  headers.delete("last-modified");
  headers.set("content-security-policy", documentCsp(nonce, mode));
  setCommon(headers, config, url);
  return out;
}

/** Headers for non-document static files proxied by the Worker (e.g. /favicon.ico). */
export function applyStaticHeaders(response: Response, config: AppConfig | undefined, url: URL): Response {
  const out = new Response(response.body, response);
  out.headers.set("content-security-policy", API_CSP);
  setCommon(out.headers, config, url);
  return out;
}
