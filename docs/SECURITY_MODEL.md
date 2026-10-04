# Security Model

This document describes the controls implemented in the control-plane Worker.
Agent access rules are in [AGENT_ACCESS_CONTROL.md](AGENT_ACCESS_CONTROL.md);
the signed provisioning protocol will be in `PROVISIONING_PROTOCOL.md`.

Status: Phase 4 (authentication). Provisioning is not implemented yet.
Authentication details: [AUTHENTICATION.md](AUTHENTICATION.md).

## Trust boundaries

| Party | Trusted for |
|---|---|
| Browser / React UI | Nothing. Every input is validated server-side. |
| Authenticated user (Phase 4+) | Requests within their own account's permissions |
| Worker | The control plane: auth, authorization, policy, signing |
| Lightagent harness (Phase 7+) | Only properly signed commands; its responses are validated |
| Cloudflare Siteverify | Turnstile verdicts, after response validation |

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

`src/worker/security/rate-limit.ts`, Workers Rate Limiting bindings.

| Policy | Binding | Limit | If the limiter fails |
|---|---|---|---|
| login | `RL_LOGIN` | 10 / 60 s | deny |
| signup | `RL_SIGNUP` | 5 / 60 s | deny |
| recovery | `RL_RECOVERY` | 3 / 60 s | deny |
| provision | `RL_PROVISION` | 5 / 60 s | deny |
| read | `RL_READ` | 120 / 60 s | allow (logged) |
| passkey_login | `RL_PASSKEY_LOGIN` | 20 / 60 s | deny |
| security_write | `RL_SECURITY_WRITE` | 20 / 60 s | deny |

(`login` is 20 / 60 s and `signup` 10 / 60 s since Phase 4; see
[AUTHENTICATION.md](AUTHENTICATION.md) for where each policy is applied.)

Keys are `policy:kind:value` (user id preferred; IP only for unauthenticated
endpoints). Each environment uses its own namespace ids. Exceeding a limit
returns `429 RATE_LIMITED` with `Retry-After`. The binding is per-location and
eventually consistent, so it is abuse protection, not an exact quota.

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
  Violations throw. Phase 2 records audit events to logs; Phase 3 adds a D1
  sink behind the same interface. IP hashing is deferred to Phase 3 (it needs
  a keyed hash secret).

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
