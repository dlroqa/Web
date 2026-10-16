# Security Model

This document describes the controls implemented in the control-plane Worker.
Agent access rules are in [AGENT_ACCESS_CONTROL.md](AGENT_ACCESS_CONTROL.md);
the signed provisioning protocol is [PROVISIONING_PROTOCOL.md](PROVISIONING_PROTOCOL.md)
(`LA-WEB-PROVISIONING/1`, candidate; not implemented in the Worker).

Status: Phase 4.5 (authentication hardening). Provisioning is not implemented yet.
Authentication details: [AUTHENTICATION.md](AUTHENTICATION.md).

## Trust boundaries

| Party | Trusted for |
|---|---|
| Browser / React UI | Nothing. Every input is validated server-side. |
| Authenticated user (Phase 4+) | Requests within their own account's permissions |
| Worker | The control plane: auth, authorization, policy, signing |
| Operator (CLI, Cloudflare account access) | Named account-administration commands only; every change audited ([OPERATIONS.md](OPERATIONS.md)) |
| Lightagent harness (Phase 7+) | Only properly signed commands; its responses are validated |
| Cloudflare Siteverify | Turnstile verdicts, after response validation |

## Actors

Three kinds of actor, never derived from one another
(`src/operator/actors.ts`):

| Actor | Built from | Privileges |
|---|---|---|
| `USER` | a Better Auth session, in the Worker (`requirePrincipal`) | own account only |
| `OPERATOR` | the operator CLI entry point, run by someone with access to the Cloudflare account | the named operator commands |
| `SYSTEM` | automated code | maintenance only |

- Operator privilege never comes from an email address, hostname, being the
  first account, knowing a URL, or frontend visibility. There is no admin
  role in the database and no admin HTTP route; the Worker never imports the
  operator module (a static test and a build-output test enforce this).
- Until an admin identity system exists, operator actions are trusted local
  operations. Their authorization boundary is Cloudflare account access, and
  the `opr_…` id is an accountable label in the audit trail. A future admin
  UI needs its own authenticated, separately reviewed operator identity.
- Operator services check the actor at runtime (`requireOperator`), so a user
  or system actor passed by mistake is refused before any read or write.

## Access policy (pages and APIs)

One policy, `src/shared/access.ts`, used by both sides:

| Level | Who | Pages | APIs |
|---|---|---|---|
| `public` | anyone | `/`, `/login` | `/api/config`, `/api/session`, sign-in endpoints |
| `identity` | signed in, `active` or `pending` | — | `GET /api/me` |
| `active` | approved accounts | `/dashboard`, `/agents`, `/security`, `/sessions`, `/settings`, and any unknown path | every other account API |

`decideAccess(level, status)` returns `allow`, `sign-in`, `pending`, or
`blocked` (suspended/disabled). The server's `requirePrincipal` maps those
to `AUTH_REQUIRED`, `ACCOUNT_PENDING`, and `ACCOUNT_DISABLED`; the browser's
route gate (`src/client/components/AccessGate.tsx`) maps them to the login
redirect, the approval screen, and the blocked screen. The browser gate is a
convenience: the document for every path is the same generic shell with no
account data, and every API behind a page enforces the policy itself.

The browser is never the authority for status, permissions, or session
validity. It renders nothing protected until `/api/session` has answered,
and any API response showing a lost session (401) or a status change (403)
moves the whole app to the matching screen. An expired session returns the
user to `/login?reason=expired` with a safe return path.

## Request routing

```text
/assets/*            → Workers Static Assets directly (content-hashed, immutable)
/api/*, /health      → Worker API router → JSON only
everything else      → Worker → index.html with a fresh CSP nonce, or a static file
```

- `assets.run_worker_first: ["/*", "!/assets/*"]` and
  `not_found_handling: "none"`: the Worker performs the SPA fallback itself, so
  every HTML document carries the CSP header. A missing file is a 404, never
  the SPA shell.
- `/api` paths can never return HTML: unknown API routes are a JSON 404
  regardless of `Accept`.
- In development only, Vite's extensionless module paths (`/@vite/client`,
  `/@react-refresh`, `/src/…`, `/node_modules/…`) pass through to Vite.

## Content Security Policy

Implemented in `src/worker/security/csp.ts` and `src/worker/site/document.ts`.

### Nonces

- 128 bits from `crypto.getRandomValues`, base64. A new nonce for **every**
  HTML response; never derived from time, counters, or `Math.random`.
- Vite writes the placeholder `LIGHTAGENT_CSP_NONCE` into the `nonce`
  attribute of the tags it emits (`html.cspNonce`). The Worker's
  `HTMLRewriter` replaces **only** existing `nonce` attributes with the
  per-response nonce. An unmarked inline script gets no nonce and is blocked.
- Nonce-bearing documents are `Cache-Control: no-store` with `ETag` and
  `Last-Modified` removed, so a nonce is never cached or reused.
- No inline JavaScript ships in production; a build test enforces it.

### Production document policy

```text
default-src 'self';
base-uri 'self';
object-src 'none';
frame-ancestors 'none';
form-action 'self';
script-src 'self' 'nonce-<per-response>' https://challenges.cloudflare.com;
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
manifest-src 'self';
worker-src 'self';
frame-src https://challenges.cloudflare.com
```

`https://challenges.cloudflare.com` (exact origin) is the only third-party
source, for the Turnstile script and challenge iframe on the login page. OAuth
sign-in is a top-level navigation to Google/GitHub, which CSP does not
govern, so no identity-provider origin is listed.

### Development document policy

Identical except `style-src 'self' 'nonce-<per-response>'`, because Vite
injects CSS as `<style>` elements at runtime (stamped with the nonce from the
`csp-nonce` meta tag). The mode is chosen at build time
(`import.meta.env.DEV`); a production build is always `"production"`, and a
build test asserts it.

### Non-document responses

API JSON, `/health`, and Worker-proxied static files get
`default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
so a JSON body opened directly as a page is inert.

### Adding sources

Third-party sources are added only with the feature that needs them, as
narrowly as possible (Turnstile, Phase 4). Never `*`, `'unsafe-eval'`,
global `'unsafe-inline'`, or bare schemes. Zod runs `jitless` so it never
probes `new Function`.

## Security headers

One policy in `src/worker/security/headers.ts`; routes never set security
headers themselves.

| Header | Value | Applies to |
|---|---|---|
| `Content-Security-Policy` | see above | documents, API, proxied files |
| `X-Content-Type-Options` | `nosniff` | all (assets via `public/_headers`) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | all |
| `Permissions-Policy` | sensors, camera, mic, geolocation, payment, USB, topics disabled; `publickey-credentials-{create,get}=(self)` for passkeys | Worker responses |
| `Cross-Origin-Opener-Policy` | `same-origin` | Worker responses |
| `Cross-Origin-Resource-Policy` | `same-origin` | all |
| `Cache-Control` | `no-store` for documents and API; `immutable` for hashed assets | |
| `Strict-Transport-Security` | `max-age=<HSTS_MAX_AGE>; includeSubDomains` only over HTTPS when `HSTS_MAX_AGE > 0` | Worker responses |

HSTS is **off** (`HSTS_MAX_AGE=0`) in every environment for now. `*.workers.dev`
is already HSTS-preloaded via the `.dev` TLD. Enable it for the production
custom hostname only after that hostname's HTTPS setup is verified (human
approval), starting with a short max-age. `X-Frame-Options` is not sent
(superseded by `frame-ancestors`).

## CSRF and origin validation

`src/worker/security/origin.ts`.

- The allowlist is `TRUSTED_ORIGINS` from wrangler `vars`, per environment.
  Entries must be bare origins; `https` is required except loopback `http` in
  development. Malformed configuration makes the Worker fail closed.
- Every state-changing `/api/*` request (anything except GET/HEAD/OPTIONS)
  must carry an `Origin` header that, after URL normalization, **exactly
  equals** an allowlisted origin. Missing, `null`, malformed, or
  untrusted origins, and any request with `Sec-Fetch-Site: cross-site`, get
  `403 FORBIDDEN` before routing, and an audit event is recorded.
- An empty allowlist (production today) rejects all state changes.
- JSON bodies require `Content-Type: application/json`, which blocks simple
  cross-site form posts as a second layer. Sessions (Phase 4) will use
  `SameSite=Lax`/`Strict` cookies as a third.

## Request IDs and errors

- Every request gets `req_<26 random base-36 chars>` (~134 bits) from the
  CSPRNG. Client-supplied request ids are ignored. Ids are returned in error
  bodies and the `X-Request-Id` header and included in every log line.
- Errors use stable codes (`src/shared/errors.ts`) and the envelope
  `{ ok: false, error: { code, message, issues? }, requestId }`. Only
  `ApiError` details reach clients; anything else becomes `INTERNAL_ERROR`
  with a generic message. Validation issues contain only a path and a code,
  never the rejected value.

## Input validation

`src/worker/http/validation.ts`, Zod via `src/shared/zod.ts`.

- `parseJsonBody(request, schema)` requires a JSON content type, enforces a
  16 KiB default limit while streaming (and via `Content-Length`), rejects
  malformed JSON and invalid UTF-8, then validates. Security-sensitive schemas
  use `.strict()`, so fields like `admin`, `userId`, or `permissions` are
  rejected rather than ignored.
- `parseQuery` rejects duplicated parameters.
- `parseWith` validates already-parsed data (D1 rows, upstream responses).

## Rate limiting

`src/worker/security/rate-limit.ts` (policies in `rate-limit-policies.ts`).

Two layers:

1. **Workers Rate Limiting bindings**, one per policy, limits in
   `wrangler.jsonc`. Per-location and eventually consistent; on staging
   (2026-10-15) they were observed **never to refuse** (25/25 sign-in starts
   and 30/30 passkey option requests from one IP in under a minute; upstream
   [cloudflare/workers-sdk#16097](https://github.com/cloudflare/workers-sdk/issues/16097)).
   A binding refusal is honoured; an approval proves nothing.
2. **Authoritative Durable Object counters** (`rate-limit-do.ts`, class
   `AuthRateLimiter`, binding `AUTH_RATE_LIMITER`) for the policies marked
   below. These make the admission decision.

| Policy | Binding | Limit | Authoritative | If the limiter fails | Applied to |
|---|---|---|---|---|---|
| login | `RL_LOGIN` | 20 / 60 s | **yes** (DO) | deny | OAuth start, OAuth callbacks (shared counter) |
| passkey_login | `RL_PASSKEY_LOGIN` | 20 / 60 s | **yes** (DO) | deny | passkey authenticate options + verification (shared counter) |
| signup | `RL_SIGNUP` | 10 / 60 s | **yes** (DO) | deny | creation of a new application profile |
| security_write | `RL_SECURITY_WRITE` | 20 / 60 s | no (binding only) | deny | profile name, passkey add/rename/remove, session revoke/revoke-all |
| read | `RL_READ` | 120 / 60 s | no (binding only) | allow (logged) | account and security reads |
| recovery | `RL_RECOVERY` | 3 / 60 s | no | deny | not used by any route yet |
| provision | `RL_PROVISION` | 5 / 60 s | no | deny | not used by any route yet (provisioning is not exposed) |

Policies marked "binding only" are **not effectively limited** while the
binding does not refuse. Before the application is public:
`security_write` must become authoritative (it is authenticated and keyed
per user, so the exposure is one account abusing itself, but it drives D1
writes and passkey ceremonies); `provision` and `recovery` must be
authoritative before any route uses them; `read` may stay binding-only
(fail-open by design). Administrative actions (`src/operator`) have no HTTP
route and are not rate limited.

**Authoritative counters.** One SQLite-backed Durable Object per counter:

- *Semantics*: exact rolling window (sliding log). A request is admitted when
  fewer than `limit` admissions happened in the preceding `period`; no
  interval of length `period` ever holds more than `limit` admissions.
  Refusals are not recorded, so retrying never extends a lockout.
  `Retry-After` is the time until the oldest admission expires (1 s to
  `period`).
- *Atomicity*: the count and insert are synchronous SQLite calls in one
  Durable Object event; concurrent requests for one key are serialized.
- *Durability*: no in-memory state; counts survive eviction and restarts.
- *Retention*: rows are expiry times (at most `limit` per counter); an alarm
  removes expired rows and deletes the object's storage once empty.
- *Keys*: object name `rl1:<environment>:<policy>:<kind>:<HMAC>`; the HMAC
  covers policy, kind and value under a key derived from
  `BETTER_AUTH_SECRET` (domain-separated), so names never contain an address
  or user id and cannot be precomputed. Objects store expiry times only.
  Rotating `BETTER_AUTH_SECRET` resets all counters.
- *Isolation*: each environment is its own Worker with its own namespace;
  policy and environment are also in every name.
- *Client identity*: only `CF-Connecting-IP` (set by Cloudflare's edge);
  `X-Forwarded-For` and similar are never read. IPv6 clients are keyed on
  their /64. A missing or malformed address is refused (`429`), not pooled.
- *Fail closed*: an unidentified client, a missing `AUTH_RATE_LIMITER`
  binding, or any Durable Object error (including a Workers Free daily
  quota refusal) refuses the request (`429 RATE_LIMITED`, `Retry-After` =
  period), before Better Auth or any D1 write. An unidentified client is
  refused before Turnstile too.

Order on the sign-in start: origin check → body validation → client
identity (unidentified: `429`) → Turnstile → login limiter (binding, then
Durable Object) → Better Auth. Turnstile runs first so that a request
without a valid token costs no Durable Object request or write and uses up
none of the client's allowance; a valid token is single-use and still has
to pass the limit. Requests that fail Turnstile are bounded only by the
Worker's own request limits; each costs one Siteverify call (5 s timeout,
bounded response) and nothing else. Passkey options
and verification, and the OAuth callbacks, are limited before Better Auth
runs (so no passkey challenge or verification row is written for a refused
request). The signup limit runs inside session creation, after the OAuth
exchange (already limited by `login`) and before the profile is created.

Binding keys remain `policy:kind:value` (the normalized address for IP
subjects). Exact quotas (e.g. profiles per user) are enforced in D1.

## Turnstile

`src/worker/security/turnstile.ts`. Attached to OAuth sign-in start
(`POST /api/auth/sign-in/social`, action `login`).

- Verification is server-side via Siteverify (5 s timeout, no redirects,
  response size bounded and schema-validated).
- Accepts a token only if `success` is true, the `hostname` is in
  `TURNSTILE_EXPECTED_HOSTNAMES`, the `action` equals the endpoint's expected
  action, and `challenge_ts` is within 5 minutes (plus 30 s skew). Reused
  tokens are rejected by Siteverify (`timeout-or-duplicate`).
- Fails closed when the secret or hostname list is missing, or Siteverify is
  unreachable or malformed.
- Cloudflare's test secrets, and any result flagged
  `result_with_testing_key`, are accepted **only** when
  `ENVIRONMENT=development`.
- Tokens and secrets are never logged.

## Logging and audit

- `src/worker/utils/log.ts`: one JSON line per event. All fields pass through
  `redact`, which masks values of keys containing `authorization`, `cookie`,
  `password`, `secret`, `token`, `privatekey`, `apikey`, `signature`,
  `credential`, `sessionid`, `csrf`, `otp` (after lowercasing and stripping
  `-`/`_`), masks bearer/JWT/PEM-shaped values under any key, never serializes
  `Headers`/`Request`/`Response`, and bounds depth and size. Whole headers or
  bodies are never logged; API access logs record method, path (no query),
  status, and duration.
- `src/worker/audit/audit.ts`: events are built only by `createAuditEvent`,
  which validates a fixed action list, prefixed random ids, stable error-code
  reasons, and flat scalar metadata whose keys may not look sensitive.
  Violations throw. Events are stored in D1 (Phase 3), with a keyed source
  hash in place of IPs.
- Better Auth's own diagnostics go through the same logger via its supported
  `logger` and `onAPIError.onError` hooks: sanitized message, no arguments,
  no error text ([AUTHENTICATION.md](AUTHENTICATION.md#better-auths-own-diagnostics)).
- Operator actions are written in the same transaction as the change they
  record (`src/worker/db/admin.ts`).

## Outbound requests

`src/worker/utils/fetch.ts`: every external call uses `fetchWithTimeout`
(default 5 s, max 30 s, combined with any caller signal), does not follow
redirects, and reads bodies with a size bound. Network errors are wrapped so
their details do not leak. No automatic retries.

## Secrets

Secrets are read only through `readSecret` (`src/worker/config/secrets.ts`),
never placed in `vars`, Vite env, or source, and never logged. Vite exposes
only `LIGHTAGENT_PUBLIC_*` variables to the client, and none exist. A build
test scans browser assets for secret names and key shapes.
