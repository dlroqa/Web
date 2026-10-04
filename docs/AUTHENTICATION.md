# Authentication

Better Auth is the authentication authority. The Worker puts a narrow,
policy-enforcing gateway in front of it and keeps application identity,
ownership, and policy in our own schema.

## Versions (pinned exactly)

| Package | Version |
|---|---|
| `better-auth` | 1.7.7 |
| `@better-auth/passkey` | 1.7.7 (official plugin; WebAuthn via SimpleWebAuthn) |
| `@simplewebauthn/browser` | 13.3.0 (same version the plugin uses) |

Upgrade procedure:
1. Read the release notes for schema or behaviour changes.
2. Bump all three, keeping exact versions (a test fails if a range is used).
3. Run `npm run auth:schema -- check`. If it reports drift, run
   `npm run auth:schema -- generate`, review the SQL, and add it as a **new**
   migration.
4. Run `npm test`. The auth and passkey contract tests must pass.
5. Re-evaluate session storage: check the release notes and source for a
   supported hashed or opaque session-token mode, and review it before
   adopting it ([SESSION_STORAGE_SECURITY.md](SESSION_STORAGE_SECURITY.md)).
   Confirm `disableSessionRefresh` and `expiresIn` still mean an absolute
   lifetime.

## Identity model

```text
Better Auth user ("user" table, opaque id)
   │  user_profiles.auth_user_id (unique, no FK)
   ▼
user_profiles (usr_…, status)  ──►  agent ownership, policy, provisioning, audit
```

- Better Auth tables (`user`, `session`, `account`, `verification`,
  `passkey`) hold authentication data only (migration `0002`). Ownership,
  harness assignment, permissions, roles, and revocation state never go
  there.
- `IdentityService.ensureProfile` (`src/worker/auth/identity.ts`) is the single
  boundary. It runs in Better Auth's `session.create.before` hook (every
  OAuth or passkey sign-in) and again in `requirePrincipal`. It creates
  exactly one `user_profiles` row per auth user with one atomic
  `INSERT … ON CONFLICT (auth_user_id) DO NOTHING`; 10 concurrent first
  sign-ins produce one row. If it fails, the sign-in fails: no session exists
  without an application identity.
- Initial status comes from `SIGNUP_POLICY`: `open` → `active`; `approval` →
  `pending` until an operator activates the account. Development: `open`.
  Staging: `approval`. Production: `approval` (and sign-in is disabled until
  the hostname is approved).

### Principal

Route handlers never parse Better Auth objects. Each account route declares
an access level from the shared policy (`src/shared/access.ts`, also used by
the browser's route gate), and the router calls `requirePrincipal(access)`
before the handler runs, which returns:

```ts
{ authUserId, userProfileId, status, sessionId, sessionCreatedAt }
```

| Status | Session creation | `identity` routes (`GET /api/me`) | `active` routes (every other account API, passkey enrolment, all app pages) |
|---|---|---|---|
| `active` | allowed | allowed | allowed |
| `pending` | allowed | allowed (to learn its status) | `403 ACCOUNT_PENDING` (UI: approval screen) |
| `suspended` | **refused** | `403 ACCOUNT_DISABLED` | `403 ACCOUNT_DISABLED` (UI: blocked screen) |
| `disabled` | **refused** | `403 ACCOUNT_DISABLED` | `403 ACCOUNT_DISABLED` (UI: blocked screen) |

`GET /api/session` never errors: `{signedIn:false}`,
`{signedIn:false, blocked:true, status}`, or `{signedIn:true, me}`.
Since Phase 5, a pending account can no longer use `/api/security/*` or add
passkeys: everything except learning its own status waits for approval.

The application status is checked on **every** request, so a valid Better
Auth session never overrides suspension; deleting sessions is not required
to enforce it.

A refused sign-in has the same application error on every path:
`POST /api/auth/passkey/verify-authentication` returns
`403 ACCOUNT_DISABLED`, and the OAuth callback redirects to
`/login?error=account_disabled`. Better Auth reports the refusal as a
generic `UNABLE_TO_CREATE_SESSION` (500), so the session hook records the
reason for the request and the gateway maps it (`mapUpstreamError`). The
same Better Auth code without a recorded denial, and any request in which
Better Auth logged an internal error, stays `500 INTERNAL_ERROR`.

Status changes are made only through the audited operator CLI
([OPERATIONS.md](OPERATIONS.md)).

## Endpoints

### Better Auth (behind the gateway, `src/worker/auth/gateway.ts`)

Only these paths reach Better Auth; every other `/api/auth/*` path is 404.

| Endpoint | Policy |
|---|---|
| `POST /api/auth/sign-in/social` | exact Origin; **Turnstile** (action `login`); per-IP `login` limit; body rebuilt from `{provider, callbackURL ∈ allowlist, turnstileToken}`, so scopes, id tokens, and redirect URLs cannot be injected; the provider URL must be `https://accounts.google.com` or `https://github.com` |
| `GET /api/auth/callback/{google,github}` | per-IP `login` limit; Better Auth validates state + PKCE; the redirect target is re-validated (our origin, allowlisted page, or `/login?error=<code>`) |
| `POST /api/auth/sign-out` | exact Origin |
| `GET /api/auth/passkey/generate-authenticate-options` | per-IP `passkey_login` limit |
| `POST /api/auth/passkey/verify-authentication` | per-IP `passkey_login` limit; strict, bounded body; response reduced to `{signedIn:true}` (Better Auth's body contains the session token) |
| `GET /api/auth/passkey/generate-register-options` | principal (active/pending); per-user `security_write` limit; only `name` and `authenticatorAttachment` pass (`context` rejected: no passkey-first sign-up); Better Auth requires a **fresh** session |
| `POST /api/auth/passkey/verify-registration` | principal; per-user limit; strict body (`createSession` rejected); response reduced to `{id}` |

Better Auth error bodies are discarded and mapped to stable codes
(`ACCOUNT_DISABLED`, `AUTH_REQUIRED`, `REAUTH_REQUIRED`, `FORBIDDEN`,
`INVALID_REQUEST`, `RATE_LIMITED`, `INTERNAL_ERROR`). Better Auth's own text
never reaches the browser.

### Application (`src/worker/api/security.ts`)

| Endpoint | Notes |
|---|---|
| `GET /api/config` | public: `{signInAvailable, providers, passkeys, turnstileSiteKey}` |
| `GET /api/session` | always 200: `{signedIn:false}`, `{signedIn:false, blocked:true}`, or `{signedIn:true, me}` |
| `GET /api/me` | `{id, displayName, status}`; 401 without a session (identity) |
| `PATCH /api/me` | `{displayName}` (1–80 chars, no control characters); audited as `account.profile.update` without the value (active) |
| `GET /api/account/overview` | dashboard: `{displayName, status, signIn:{providers, passkeys}, sessions:{active, currentExpiresAt}, agents:{count}}` (active) |
| `GET /api/agents` | the caller's agent profiles `{id, name, status, createdAt}`, read-only; no harness or permission data (active) |
| `GET /api/security/*` (all below) | **active** accounts only |
| `GET /api/security/methods` | connected providers and passkey count |
| `GET /api/security/sessions` | the caller's sessions: `{id, device, createdAt, lastActiveAt, expiresAt, current}`; **no tokens, no IPs** |
| `DELETE /api/security/sessions/:id` | revoke one of the caller's sessions (others survive); revoking the current one also expires this browser's cookies |
| `POST /api/security/sessions/revoke-all` | revoke **all** of the caller's sessions, **including the current one**, and expire this browser's session cookies with the same names and attributes as sign-out (`Max-Age=0`); repeating it returns `401 AUTH_REQUIRED` and changes nothing; the UI returns to `/login` |
| `GET /api/security/passkeys` | `{id, name, deviceType, backedUp, createdAt}`; no credential id or public key |
| `PATCH /api/security/passkeys/:id` | rename (1–80 chars) |
| `DELETE /api/security/passkeys/:id` | requires a fresh session (`REAUTH_REQUIRED` otherwise) |
| `GET /api/security/activity` | the caller's audit events |

Every session and passkey lookup is scoped to the principal's auth user id;
another user's id returns the same 404 as a nonexistent one. Better Auth's
own list/revoke/delete endpoints are not exposed because they return session
tokens or credential data to the browser.

## OAuth

| Provider | Scopes | Notes |
|---|---|---|
| Google | `openid email profile` | `disableDefaultScope` + explicit list; `include_granted_scopes` off; `prompt=select_account`; PKCE S256; id_token verified against Google's JWKS |
| GitHub | `read:user user:email` | email verification status taken from GitHub's verified-email list |

No repository, organization, cloud, or admin scopes. **Provider tokens are
not stored**: `account.create/update.before` hooks null the access, refresh,
and ID tokens (token encryption is also enabled as defense in depth).

### Callback URLs (register exactly these)

| Environment | Google | GitHub |
|---|---|---|
| development | `http://localhost:5173/api/auth/callback/google` | `http://localhost:5173/api/auth/callback/github` |
| staging | `https://lightagent-control-staging.eddelaroca.workers.dev/api/auth/callback/google` | `https://lightagent-control-staging.eddelaroca.workers.dev/api/auth/callback/github` |
| production | not set (hostname not chosen) | not set |

Google allows several redirect URIs per client; GitHub OAuth apps allow one
callback URL, so use **separate GitHub OAuth apps** for development and
staging (and later production). Use separate Google clients per environment
too, so environments never share secrets.

### Account linking

`accountLinking.disableImplicitLinking = true`: signing in with a second
provider whose (even verified) email matches an existing user does **not**
merge the identities; the sign-in fails with `account_not_linked`. Explicit,
authenticated linking is not exposed in Phase 4. `allowDifferentEmails` is
off and `requireLocalEmailVerified` is on. A unique index on
`account(providerId, accountId)` makes it impossible for one provider identity
to belong to two users. Tests cover verified-email and unverified-email
takeover attempts.

## Passkeys

| Setting | Development | Staging | Production |
|---|---|---|---|
| `PASSKEY_RP_ID` | `localhost` | `lightagent-control-staging.eddelaroca.workers.dev` | unset (sign-in disabled) |
| Origin | `http://localhost:5173` | `https://lightagent-control-staging.eddelaroca.workers.dev` | unset |

- The RP id must equal the `PUBLIC_ORIGIN` hostname (config validation), never
  a parent domain or wildcard.
- Registration requires an authenticated, **fresh** session (created within
  10 minutes; `session.freshAge = 600`). Removal requires the same freshness
  in our endpoint. Passkey-first (anonymous) registration is disabled.
- `authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" }`.
- **Changing the RP id later** (e.g. moving staging or production to a custom
  domain) makes existing passkeys unusable on the new domain: WebAuthn
  credentials are bound to their RP id. Pick the production hostname before
  users enrol production passkeys. If a move is unavoidable, users must sign
  in with OAuth on the new domain and enrol new passkeys; old ones should be
  removed. A parent-domain RP id (`example.com` for `app.example.com`) would
  survive subdomain moves but widens which origins can use the credentials;
  that decision needs explicit approval.

## Sessions and cookies

| Cookie | Attributes |
|---|---|
| `lightagent.session_token` (`__Secure-lightagent.session_token` over HTTPS) | `HttpOnly`, `Secure` (HTTPS), **`SameSite=Strict`**, `Path=/api`, 24-hour max age |
| `lightagent.state`, passkey challenge cookie | `HttpOnly`, `Secure` (HTTPS), `SameSite=Lax`, `Path=/api` |

- Why two SameSite values: the OAuth state cookie must be sent on the
  provider's cross-site redirect back to `/api/auth/callback/*`, which
  requires `Lax`. The session cookie is only needed by same-origin `fetch`
  calls, so it is `Strict`. No cookie is `SameSite=None`.
- `Path=/api`: documents and assets never receive auth cookies. No `Domain`
  attribute (host-only).
- Sessions live in D1 and are checked on every request (`cookieCache`
  disabled), so revocation is immediate.
- Sign-in always creates a new session token; a pre-existing (planted) cookie
  is never adopted (fixation test).
- `session.ipAddress` is never filled (`disableIpTracking`; a CHECK constraint
  enforces it). Sessions keep the user agent, shown as a coarse "Browser on OS".
- Lifetime: **24 hours absolute** (`expiresIn: 86400`,
  `disableSessionRefresh: true`). Use never extends a session; after 24 hours
  the user signs in again. "Fresh" (recent authentication) = 10 minutes after
  sign-in.
- `session.token` is stored raw in D1 (Better Auth 1.7.7 has no hashed
  storage). This is accepted with mandatory compensating controls; see
  [SESSION_STORAGE_SECURITY.md](SESSION_STORAGE_SECURITY.md).

### Session revocation and `revocation_version`

Logout and session revocation only invalidate Better Auth sessions; they do
not touch any agent profile's `revocation_version`. The Worker checks the
session (and application status) on every request, which is sufficient
while agents are reached only through the Worker. When short-lived agent
tokens arrive ([AGENT_ACCESS_CONTROL.md §4.2](AGENT_ACCESS_CONTROL.md)), a
session revocation will bump `revocation_version` only when a token could
outlive the session (token lifetime > 0 and the revoked session issued it), or
when the user chooses "sign out everywhere".

## Turnstile

Used only at `POST /api/auth/sign-in/social` (OAuth start, which is also
sign-up), verified server-side before Better Auth runs. The OAuth redirect
and callback are not wrapped. Passkey sign-in has no Turnstile (it requires
possession of a registered credential and is IP rate limited). Authenticated
requests never see a challenge. The widget is rendered explicitly (action
`login`, `interaction-only` appearance).

| Environment | Site key | Secret |
|---|---|---|
| development | Cloudflare test key `1x00000000000000000000AA` | test secret (`.dev.vars`) |
| staging | staging widget (hostname-restricted) | `TURNSTILE_SECRET` Worker secret |
| production | unset | unset |

## Rate limits (Workers Rate Limiting bindings)

| Policy | Binding | Limit | Key | Applied to |
|---|---|---|---|---|
| `login` | `RL_LOGIN` | 20 / 60 s | client IP | OAuth start, OAuth callback |
| `passkey_login` | `RL_PASSKEY_LOGIN` | 20 / 60 s | client IP | passkey options + verification |
| `signup` | `RL_SIGNUP` | 10 / 60 s | client IP | creation of a new application profile only (returning users are never limited by it) |
| `security_write` | `RL_SECURITY_WRITE` | 20 / 60 s | user | passkey register/rename/remove, session revoke/revoke-all |
| `read` | `RL_READ` | 120 / 60 s | user | security reads |

Authenticated operations are keyed on the account, not the IP, so shared/NAT
users don't affect each other; only pre-authentication steps use the IP, with
limits generous enough for a household or office. Better Auth's own limiter
is disabled (it is in-memory per isolate).

## Audit events

Written through `AuditRecorder.bestEffort` to D1 (failures fall back to logs):
`auth.account.created`, `auth.login.success` (`method`: google/github/passkey),
`auth.login.failure` (account not allowed to sign in), `auth.logout`,
`auth.passkey.add`, `auth.passkey.rename`, `auth.passkey.remove`,
`auth.session.revoke`, `auth.session.revoke_all`. Operator actions are
`admin.*` events ([OPERATIONS.md](OPERATIONS.md)).

Targets identify *what* was acted on without credential material:

| Event | Target | Metadata |
|---|---|---|
| `auth.passkey.add/rename/remove`, `admin.passkey.remove` | `passkey` row id | `name` (the owner's label), `fingerprint` = `sha256:` + first 16 hex digits of SHA-256(credential id) |
| `auth.session.revoke` | `session` row id (never the token) | `current` |
| `admin.user.*` | `user` (`usr_…`) | `reason`, `from`, `to`, `channel` |

The fingerprint answers "which passkey was removed?". It correlates with
the authenticator's credential without storing the credential id itself;
public keys, counters, and assertion data are never recorded.

Logged only (unauthenticated, potentially high-volume): `auth.oauth.start`,
`auth.oauth.callback.failure` (with a sanitized error code),
`auth.passkey.login.failure`, Turnstile failures, rate-limit hits.

Never logged or stored: OAuth codes, access/refresh/id tokens, session
cookies or tokens, WebAuthn assertions/attestations/signatures, client
secrets, `BETTER_AUTH_SECRET`, Turnstile tokens. Tests scan captured logs,
audit rows, and responses for each of these.

### Better Auth's own diagnostics

Better Auth logs through two supported hooks, both wired to our redacting
logger (`src/worker/auth/logging.ts`); nothing is patched:

- `logger.log(level, message, …args)` → `better_auth.log` lines. The message
  is bounded to 200 characters with every run of 20 or more token-like
  characters replaced by `[opaque]`; extra arguments are recorded only as
  types (`Error`, `object`). Level `warn` (Better Auth's default).
- `onAPIError.onError` → `better_auth.api_error` with the error's status and
  code only. When this hook is set, Better Auth does not log API errors
  itself.

Better Auth's global logger delegates to these inside a request. Outside a
request (startup only) it can print fixed text such as adapter warnings,
with no request data. Expected failures (e.g. `account_not_linked`) appear as
`better_auth.log` at error level with the sanitized message; that is normal.
Production should keep the level at `warn`.

### Source hashing

Audit events carry `security.sourceHash` = HMAC-SHA256(`AUDIT_SOURCE_HMAC_KEY`,
`lightagent-audit-source:v1:<normalized IP>`) with key id `k1`, plus
`country` from Cloudflare. It is a correlation signal only ("same source"),
never identity, authentication, or authorization. Rotating the key
deliberately breaks correlation with earlier hashes; bump `SOURCE_KEY_ID` when
rotating. Without the secret, events carry no source hash.

## Secrets

| Secret | Development | Staging | Production |
|---|---|---|---|
| `BETTER_AUTH_SECRET` (≥ 32 chars) | `.dev.vars` | Worker secret | unset |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | `.dev.vars` | Worker secrets | unset |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | `.dev.vars` | Worker secrets | unset |
| `TURNSTILE_SECRET` | test secret | Worker secret | unset |
| `AUDIT_SOURCE_HMAC_KEY` | optional | Worker secret | unset |

Without `BETTER_AUTH_SECRET` (or with one shorter than 32 characters), every
auth endpoint returns `503 AUTH_UNAVAILABLE`. A provider with a missing
id/secret is simply not offered.

## Better Auth defaults intentionally overridden

| Option | Default | Ours | Why |
|---|---|---|---|
| `account.accountLinking.disableImplicitLinking` | false | **true** | no automatic identity merging |
| `account.encryptOAuthTokens` | false | true | defense in depth (tokens are also not stored) |
| account create/update hooks | — | null provider tokens | sign-in needs no provider API access |
| `socialProviders.*.disableDefaultScope` + `scope` | defaults | explicit minimal list | minimum scopes, documented |
| `google.includeGrantedScopes` | true | **false** | do not inherit earlier grants |
| `google.prompt` | none | `select_account` | explicit account choice |
| `emailAndPassword.enabled` | false | false (explicit) | no passwords |
| `session.cookieCache` | disabled | disabled (explicit) | immediate revocation |
| `session.expiresIn` | 7 days | **24 hours** | absolute lifetime for a control plane |
| `session.disableSessionRefresh` | false | **true** | use never extends a session |
| `session.freshAge` | 1 day | **10 minutes** | recent authentication for passkey changes |
| `advanced.cookiePrefix` | `better-auth` | `lightagent` | |
| `advanced.defaultCookieAttributes.path` | `/` | **`/api`** | narrow cookie scope |
| session cookie `sameSite` | `lax` | **`strict`** | not sent cross-site |
| `advanced.ipAddress.disableIpTracking` | false | **true** | no raw IPs in sessions |
| `rateLimit.enabled` | true in production | **false** | replaced by Cloudflare bindings |
| `telemetry.enabled` | (opt-in) | false (explicit) | no third-party calls |
| `onAPIError.errorURL` | Better Auth page | `/login` | errors land on our page with a code |
| `onAPIError.onError` | Better Auth logs the error | structured, code-only log | no free text from errors |
| `logger` | console, colored text | redacting adapter, level `warn` | one structured, sanitized line per message |
| passkey `registration.requireSession` | true | true (explicit) | no passkey-first sign-up |
| Endpoint surface | all routes | 7 routes via gateway | minimal attack surface |

## Staging validation (real providers)

Verified on staging on 2026-10-04 with the real Google and GitHub OAuth apps
and a real browser (details in [DEPLOYMENT.md](DEPLOYMENT.md)):

- Google (`openid email profile`) and GitHub (`read:user user:email`)
  sign-in; first sign-in is `pending` under `approval`; activation works.
- Passkey enrolment (fresh session required), sign-in resolving the same
  `usr_…` identity, removal; Better Auth's WebAuthn verification only.
- Session listing without tokens, single revoke, sign out everywhere
  (including the current session), cross-user ids → 404.
- Suspension: a still-valid session is denied (`403 ACCOUNT_DISABLED`), and
  fresh Google and passkey sign-ins are refused.
- Same-email Google/GitHub sign-in is **not** linked (`account_not_linked`).
- Provider access, refresh, and ID tokens are not persisted.
- CSP: zero violations; no Google/GitHub sources were added.
- Remaining: raw session tokens at rest
  ([SESSION_STORAGE_SECURITY.md](SESSION_STORAGE_SECURITY.md)); the
  pending-account gate on an active-only route is **deferred by design** to
  Phase 5 (no such route exists yet; covered by automated tests).
