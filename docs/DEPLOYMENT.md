# Deployment

## Environments

| Environment | Worker name | URL | Status |
|---|---|---|---|
| development | `lightagent-control` (local only) | `http://localhost:5173` | `npm run dev` |
| staging | `lightagent-control-staging` | <https://lightagent-control-staging.eddelaroca.workers.dev> | deployed |
| production | `lightagent-control-production` | — | **not deployed** (needs human approval) |

Each environment is a separate Worker with its own `ENVIRONMENT` var, and later
its own D1 database, secrets, OAuth callbacks, Turnstile widget, harness
registrations, and signing key. Production must never reuse staging or
development credentials.

## Deploying

The Cloudflare Vite plugin fixes the target environment **at build time**.
`wrangler deploy` then uses the generated `dist/lightagent_control/wrangler.json`.
Always build and deploy for the same environment:

```sh
rm -rf dist
CLOUDFLARE_ENV=staging npm run build
node -e 'console.log(require("./dist/lightagent_control/wrangler.json").name)'  # must print lightagent-control-staging
npx wrangler deploy --env staging --dry-run
npx wrangler deploy --env staging
```

Apply pending D1 migrations **before** deploying code that depends on them:

```sh
npm run db:migrate:staging        # wrangler d1 migrations apply DB --env staging --remote
```

Never run a production deploy from a build made without
`CLOUDFLARE_ENV=production`, and never without explicit approval.

## Cloudflare Workers Builds (staging)

Staging builds and validation run on Cloudflare's build machines, connected
to the Worker `lightagent-control-staging` (Settings → Builds). There are no
GitHub Actions for Web.

| Setting | Value |
|---|---|
| Repository / production branch | `dlroqa/Web` / `deploy/staging` |
| Builds for Preview branches | off |
| Root directory | `/` |
| Build variables | `CLOUDFLARE_ENV=staging`, `NODE_VERSION=22` |
| Build command | `npm run ci:cloudflare` |
| Deploy command | at rest: staging guard, then `npx wrangler deploy --env staging --dry-run`; only for an approved upload: staging guard, then `npx wrangler versions upload --env staging --message "…"` (never `wrangler deploy` without `--dry-run`) |

`npm run ci:cloudflare` runs, failing at the first error:

1. `protocol:verify` (`scripts/verify-frozen-protocol.mjs`, then the
   documented `sha256sum --check` of `MANIFEST.sha256`). `MANIFEST.json` must
   have the accepted compatibility digest (SHA-256 of its exact bytes, §15),
   fixture digest and specification hash. Every hashed file must match
   `MANIFEST.json`, and `MANIFEST.sha256` must be exactly the list
   `MANIFEST.json` implies. An edited checksum list cannot hide an edited fixture.
2. `typecheck`.
3. `npm test`: Worker/D1 (workerd), static, client and provisioning tests,
   including the crash/recovery matrix and the schedule simulation. The tests
   always use the development configuration with local bindings only:
   `vitest.config.ts` removes `CLOUDFLARE_ENV` and sets `remoteBindings: false`.
4. `build`, the only build, for `CLOUDFLARE_ENV=staging`.
5. `test:build`, on that build output. It also checks that a deployed-environment
   build keeps `preview_urls: false`.

The deploy command's guard refuses unless `dist/lightagent_control/wrangler.json`
names `lightagent-control-staging`, `ENVIRONMENT=staging`, `preview_urls: false`
and the staging `DB` (`lightagent-control-staging`,
`3cc0724d-fb83-4477-ac0f-5aee58606fdf`). Workers Builds sets the Worker name
from the connected Worker (`WRANGLER_CI_OVERRIDE_NAME`), so the guard is what
stops a non-staging build from reaching it. The dashboard field has a length
limit (about 512 characters): keep the command compact.

At rest, a push to `deploy/staging` only validates (dry run). During an
approved upload window it **uploads an inactive version** and never changes
traffic; the deploy command goes back to the dry run straight after.
Activation is a separate, approved, manual step:

```sh
npx wrangler versions deploy <version-id>@100% --name lightagent-control-staging --message "<approval reference>" --yes
```

Roll back the same way, with the previous version id. A version deploy also
syncs non-versioned settings (logpush, observability) from the local
`dist/lightagent_control/wrangler.json`, so run it from a staging build of the
same commit.

`preview_urls` is `false` for staging and production in `wrangler.jsonc`, and
off on the live staging Worker (per-version hostnames return 404). Every deploy
re-sends this setting, so it is set in configuration, not only in the dashboard.

### Durable Object classes and the upload-only workflow

`wrangler versions upload` refuses a Worker with a pending Durable Object
migration ("Durable Object migrations must be applied with `wrangler
deploy`"); the check runs before anything is uploaded, so the Builds
deploy command fails without changing anything. A migration can only be
applied by `wrangler deploy`, which also activates that version at 100%.
After a migration, Cloudflare blocks rollback to any version from before it.

So a new class is introduced in two approved steps:

1. **Carrier** (one-off `wrangler deploy`, separately approved): a version
   whose behaviour is the active version's, plus only the new class, its
   binding and migration (unused). It becomes the rollback baseline; the
   versions before it can no longer be rolled back to.
2. **Implementation** through the normal path: push to `deploy/staging`,
   Builds uploads an inactive version, separate approval to promote.
   Rollback = `versions deploy <carrier>@100%` (no lifecycle change between
   them, so it is allowed).

The `AuthRateLimiter` class (migration tag `v1-auth-rate-limiter`) has not
been applied to staging or production; see the log entry below.

## Staging smoke test

Run after every staging deploy:

1. `/`, `/login`, `/agents`, a deep `/agents/<id>` route, `/security`: 200 HTML,
   `no-store`, CSP nonce in the header equals every `nonce` attribute in the
   body, no `LIGHTAGENT_CSP_NONCE` placeholder left, and different nonces on
   repeated requests.
2. A real browser loads each route and a refreshed deep route with **zero CSP
   violations** and the app rendered.
3. `/health` is `{"status":"ok"}`; `POST /health` is 405.
4. `/api`, `/api/<unknown>` (even with `Accept: text/html`) are JSON 404s.
5. `POST /api/...` with a foreign, suffix-spoofed, or missing `Origin` is 403;
   with the staging origin it reaches routing.
6. Hashed JS is `immutable` + `nosniff`; a missing `/assets/*` file is 404.
7. No secrets, secret names, private addresses, or source maps in HTML/JS.
8. The production Worker URL is not deployed.

### 2026-10-03: Phase 1 baseline

Version `be912da5-c243-4ed4-bf0e-75d8a7251256`, deployed with
`wrangler deploy --env staging` from commit `d95266f`.

| Check | Result |
|---|---|
| `/`, `/login`, `/agents`, `/agents/agt_x`, `/security` | 200 `text/html`, SPA shell served (direct navigation/refresh works) |
| `/health` | 200 `{"status":"ok"}`, `no-store`, `nosniff` |
| `POST /health` | 405 |
| Unknown `/api/nope`, `/api/agent-profiles` | 404 JSON envelope, never HTML |
| Hashed JS `/assets/index-*.js` | 200 `text/javascript` |
| CSS | none in Phase 1 (no stylesheet emitted yet) |
| Source maps | none shipped |
| Secret scan of HTML + JS | no secrets, keys, tokens, private addresses, or env values (only React's own "dev environment" text) |
| Environment separation | Worker `lightagent-control-staging`, `ENVIRONMENT=staging`; production Worker URL returns 404 (not deployed) |
| Lightagent | not connected |

Baseline response headers before Phase 2 (Cloudflare edge headers omitted):

```text
/                      content-type: text/html
                       cache-control: public, max-age=0, must-revalidate
                       cf-cache-status: HIT
                       (no CSP, nosniff, Referrer-Policy, Permissions-Policy)
/health, /api/*        content-type: application/json; charset=utf-8
                       cache-control: no-store
                       x-content-type-options: nosniff
/assets/index-*.js     content-type: text/javascript
                       cache-control: public, max-age=0, must-revalidate
```

Issues found (all fixed in Phase 2, see below):

1. HTML documents carry no security headers.
2. A missing hashed asset (`/assets/nope.js`) returns the SPA HTML with 200
   instead of 404.
3. HTML is edge-cacheable; nonce-bearing documents must be `no-store`.

### 2026-10-03: Phase 2 security foundation

Version `37199da7-eff3-4eaa-9543-4be81a9fc9c5`, built with
`CLOUDFLARE_ENV=staging npm run build` and deployed with
`wrangler deploy --env staging` from commit `a05e4bd`. Bindings: `ASSETS`,
`RL_LOGIN`/`RL_SIGNUP`/`RL_RECOVERY`/`RL_PROVISION`/`RL_READ` (namespaces
2001–2005), staging `vars`. No secrets set. Lightagent not connected.

| Check | Result |
|---|---|
| Documents `/`, `/login`, `/agents`, `/agents/agt_x`, `/security` | 200, `no-store`, header nonce = body nonces, no placeholder |
| Nonce uniqueness | distinct per request |
| Real browser (Chromium, Playwright) on 5 routes + deep-route refresh | rendered, **0 CSP violations**, 0 console errors |
| `/health` / `POST /health` | 200 `{"status":"ok"}` / 405 |
| `/api`, `/api/nope` with `Accept: text/html` | JSON 404 with `requestId` |
| `POST /api/x` from `https://evil.example`, suffix-spoofed origin, no origin | 403 `FORBIDDEN` |
| `POST /api/x` from the staging origin | 404 (reached routing) |
| Hashed JS | 200, `public, max-age=31536000, immutable`, `nosniff` |
| Missing `/assets/nope.js`, `/favicon.ico` | 404 (Phase 1 issue fixed) |
| Secret / private-address scan, source maps | none |
| Production Worker | not deployed (404) |

Response headers after Phase 2:

```text
/ (document)   content-type: text/html; charset=utf-8
               cache-control: no-store
               content-security-policy: default-src 'self'; base-uri 'self'; object-src 'none';
                 frame-ancestors 'none'; form-action 'self'; script-src 'self' 'nonce-<random>';
                 style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self';
                 manifest-src 'self'; worker-src 'self'; frame-src 'none'
               cross-origin-opener-policy: same-origin
               cross-origin-resource-policy: same-origin
               permissions-policy: accelerometer=(), browsing-topics=(), camera=(), display-capture=(),
                 geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(),
                 publickey-credentials-create=(self), publickey-credentials-get=(self)
               referrer-policy: strict-origin-when-cross-origin
               x-content-type-options: nosniff
               x-request-id: req_<random>
/health, /api  content-type: application/json; charset=utf-8
               cache-control: no-store
               content-security-policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
               (+ same COOP, CORP, Permissions-Policy, Referrer-Policy, nosniff, x-request-id)
/assets/*.js   content-type: text/javascript
               cache-control: public, max-age=31536000, immutable
               cross-origin-resource-policy: same-origin
               referrer-policy: strict-origin-when-cross-origin
               x-content-type-options: nosniff
```

Not verifiable on staging yet: rate-limit bindings and Turnstile are not
attached to any endpoint (covered by unit tests; verified on staging when
login/signup/provisioning ship). HSTS is intentionally off.

### 2026-10-03: Phase 3 D1

- Created D1 databases `lightagent-control-dev`, `-staging`, and `-production`
  (ids in [DATABASE.md](DATABASE.md)) in the Worker's Cloudflare account. An
  unrelated pre-existing database in the account (`torvid`) was not touched.
- Applied `0001_initial.sql` to **staging only**: 6 STRICT tables, 11 indexes,
  9 triggers, `foreign_keys = 1`. Re-applying reports "No migrations to apply".
  Production has no migrations applied and no data.
- Deployed `main` (commit `f513ea2`) as version
  `146fffa5-578a-4b75-a5ac-51aa5fecf760`, with `DB` bound only to
  `lightagent-control-staging`.

Worker→D1 storage smoke: a temporary route on an unmerged branch
(`smoke/d1-staging`, commit `30f76e0`) was deployed briefly as version
`f0474181`. It was gated by a one-time random `SMOKE_TOKEN` staging secret
(404 without it), took no input, and ran a fixed sequence through the real
repositories. All 16 checks passed:

| Check | Result |
|---|---|
| duplicate `auth_user_id` → UniqueConflict | pass |
| new profile `pending`, revocation_version 1 | pass |
| cross-tenant read / rename / revoke → null / null / NotFound | pass |
| owner read | pass |
| `pending → active` rejected; `pending → provisioning → active` | pass |
| 10 concurrent revocation increments → 10 distinct values, final 11 | pass |
| suspension bumps revocation_version | pass |
| same idempotency key + same request → same job | pass |
| same key + different hash → IdempotencyConflict | pass |
| nonce replay detected | pass |
| audit event persisted and read back; UPDATE rejected (append-only) | pass |
| all smoke rows deleted (every table back to 0 rows) | pass |

Afterwards the secret was deleted (staging has **no** secrets), the branch was
deleted, `main` was redeployed (the bundle contains no smoke code), and
`/api/__smoke/d1` returns the normal JSON 404.

Post-teardown staging checks: documents serve per-request nonces that match
the header; `/health` ok; API 404s are JSON; foreign `Origin` POST → 403;
missing asset → 404; staging D1 has 0 rows; real-browser check on 5 routes
plus a deep refresh: **0 CSP violations**.

### 2026-10-04: Phase 4 authentication (pre-OAuth credentials)

- Applied `0002_better_auth.sql` to **staging** D1 (production: no migrations
  applied).
- Created Turnstile widget `lightagent-control-staging` (managed, domain
  `lightagent-control-staging.eddelaroca.workers.dev` only); site key
  `0x4AAAAAAFNMfAUq5o1WPhrX` in `wrangler.jsonc`.
- Staging Worker secrets installed (generated locally, never printed, files
  deleted): `TURNSTILE_SECRET`, `BETTER_AUTH_SECRET`, `AUDIT_SOURCE_HMAC_KEY`.
  Not yet set: `GOOGLE_CLIENT_ID/SECRET`, `GITHUB_CLIENT_ID/SECRET`.
- Deployed commit `65caa14` as version `c801ff2f-454a-4ae9-8d51-0e31752e34ba`
  (`SIGNUP_POLICY=approval`).

| Check | Result |
|---|---|
| `/api/config` | `signInAvailable: true`, `providers: []` (no OAuth secrets yet), staging site key |
| `/api/session` / `/api/me` signed out | `{signedIn:false}` / 401 `AUTH_REQUIRED` |
| Hidden Better Auth routes (`get-session`, `list-sessions`, `sign-up/email`) | 404 |
| Passkey authentication options | `rpId` = staging hostname, `userVerification: preferred` |
| Passkey registration options without a session | 401 |
| Social sign-in for an unconfigured provider | 400 |
| Foreign-origin sign-out | 403 |
| Document CSP | adds only `https://challenges.cloudflare.com` (script-src, frame-src) |
| Real browser: login (light/dark), protected-route redirects with `returnTo`, error-code messages, XSS in `?error=` | pass, **0 CSP violations, 0 console errors** |
| Production Worker | not deployed |

Pending (needs OAuth credentials): Google/GitHub sign-in, passkey enrolment
and sign-in, session revocation, and suspended-user checks in a real browser.

### 2026-10-04: Phase 4 validation with real OAuth providers

Secrets added to **staging only**: `GOOGLE_CLIENT_ID/SECRET` and
`GITHUB_CLIENT_ID/SECRET` (staging-only Google client and GitHub OAuth app,
callback URLs as in [AUTHENTICATION.md](AUTHENTICATION.md#callback-urls-register-exactly-these)).
Deployed version unchanged (`c801ff2f`, commit `65caa14`).

Method: a real Chromium on the operator's desktop with a throwaway profile
(deleted afterwards). The person signed in to Google/GitHub interactively; a
CDP monitor recorded console output, CSP violations, provider authorize URLs
(with `state`, `code`, and `code_challenge` redacted), and `Set-Cookie`
attributes (never values), and compared every `/api` JSON body against the
live session token without printing it. `wrangler tail` output was stored
with query strings and headers removed. Passkeys used Chromium's DevTools
virtual authenticator, so Better Auth's real WebAuthn verification ran
against the staging RP id. D1 was inspected with read-only queries.

| Check | Result |
|---|---|
| Google sign-in | authorize URL scopes exactly `openid email profile`, `prompt=select_account`, PKCE S256; consent showed name, email, picture only; `user` + `account` + `user_profiles` (`pending`) created |
| Pending account | valid session; `/api/me` reports `pending`; dashboard shows the approval notice; agent routes 404 (none exist yet) |
| Activation, then Google sign-in | dashboard without notice; same `usr_…` |
| GitHub sign-in (second account) | scopes exactly `read:user user:email`, PKCE S256; new identity `pending` |
| Same verified email via GitHub as an existing Google user | refused 4/4 with `account_not_linked`; no account attached, no user created |
| Provider tokens in D1 | `accessToken`, `refreshToken`, `idToken` NULL on both accounts |
| Recent auth | passkey registration on a > 10 min session → `403 REAUTH_REQUIRED` |
| Passkey add / remove / sign-in | Better Auth verification; counter advanced; same `usr_…` resolved; no new user |
| Sessions | listed without tokens; revoke one → that browser 401, other kept; sign out everywhere → 0 sessions (current included) |
| Cross-user | another user's session or passkey id → 404 (delete, rename) |
| Suspension | still-valid session → `403 ACCOUNT_DISABLED` everywhere, `/api/session` `blocked`; fresh Google and passkey sign-in refused, no session created |
| Cookies (observed) | session `HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=604800`, host-only; OAuth state and passkey challenge `HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=300`; no `SameSite=None`; nothing in localStorage, sessionStorage, or `document.cookie` |
| Session token in browser-readable JSON | 0 matches across every `/api` response |
| Worker logs and audit rows | no codes, tokens, cookies, WebAuthn data, secrets, or emails (32 patterns scanned) |
| CSP | 0 violations, 0 page errors in both browsers; no CSP change needed (redirects need none) |
| Production | no Worker, no secrets, no migrations applied |

Issues found (fixed in Phase 4.5): a suspended account's passkey sign-in
returned `500 INTERNAL_ERROR` instead of `403 ACCOUNT_DISABLED`; sign out
everywhere left the (now invalid) session cookie in the browser.

Staging test identities created: one Google user (now `active`) and one
GitHub user (kept `pending`); see [OPERATIONS.md](OPERATIONS.md#staging-test-accounts).

### 2026-10-04: main after the Phase 4.5 merge

`phase-4.5-auth-hardening` merged into `main` with a merge commit
(`0369ae2`, history kept), adding the 24-hour absolute session lifetime
(`expiresIn: 86400`, `disableSessionRefresh: true`). From `main`: typecheck,
488 tests, staging build, 10 build-output tests, Better Auth schema check,
`npm audit --omit=dev` (0 vulnerabilities). Deployed `main` as version
`04468849-d90a-4b6f-b9b6-448fa3c7ee2f`, tag `main-0369ae2`, message
`main 0369ae2 (Phase 4.5 merged)`.

Staging state: `usr_zabx…` active, `usr_bcv3…` pending, 0 sessions,
0 passkeys, 0 verification rows, no provider tokens, 0 agent profiles,
provisioning jobs, or harnesses. Production untouched.

### 2026-10-04: Phase 5 account and security UI (staging)

Branch `phase-5-account-ui` (from `main` `c9204a2`). Validated with version
`6371623d` (commit `aaa8d06`); now running `fd978898-93b3-429d-b911-28031ec98901`
(tag `phase5-4493cc1`, which only adds page titles to the status screens).
Before each deploy: typecheck, 516 tests, staging build, 10 build-output
tests; `npm audit --omit=dev` 0 vulnerabilities. No migration, secret, or
binding change.

Real browsers, two throwaway profiles (deleted afterwards), same monitoring
as Phase 4:

| Check | Result |
|---|---|
| Signed out, direct `/settings` | redirected to `/login?returnTo=%2Fsettings` |
| **User B (GitHub, pending)**: sign-in | identity established (same `usr_bcv3…`, no new user); approval screen |
| User B: `/api/me`, `/api/session` | `pending` |
| User B: every active API (overview, agents, security reads, display name, session revoke, revoke-all, passkey enrolment) | `403 ACCOUNT_PENDING` |
| User B: direct navigation to `/dashboard`, `/agents`, `/security`, `/sessions`, `/settings`, unknown path | only "Your account is awaiting approval"; no app navigation |
| **User A (Google, active)**: same paths | each page renders with navigation and its own title; unknown path → "Page not found"; `/` → dashboard |
| Dashboard data | display name, status, sign-in methods, session count and end time, agent count 0; no ids, tokens, or infrastructure |
| Security | sign-in methods, activity labels; passkey added and removed (audit rows with fingerprint) |
| Sessions | two sessions; one revoked from the list (audit target = session id); sign out everywhere → `/login?reason=signed-out`, cookie expired, stale cookies rejected |
| Settings | empty name rejected in the browser (no request); save → `200`; audit `account.profile.update` with `{field}` only |
| Session ended (revoked by the operator CLI) | "Check again" → `/login` with "Your session expired. Please sign in again." |
| Cookie | session cookie `Max-Age` = 24 h (`expires` = sign-in + 24 h) |
| Storage | nothing in localStorage, sessionStorage, or `document.cookie` |
| CSP / console | 0 violations, 0 page errors; the UI itself logged no console errors (all errors were deliberate negative probes) |
| Logs | none of 24 sensitive patterns (incl. display names) |
| Accessibility (login, real browser) | `lang`, one `main`, one `h1`, titled; all controls named, inputs labelled, decorative SVGs hidden; no target < 44 px; tab order matches layout with a 3 px focus outline; theme contrast ≥ 4.5:1 (text) in light and dark |
| Production | untouched (404) |

Final staging state: `usr_zabx…` active, `usr_bcv3…` pending, 0 sessions,
0 passkeys, 0 verification rows, no provider tokens, 0 agent profiles,
provisioning jobs, or harnesses; 43 audit rows, none with emails or tokens.

### 2026-10-14: W1 provisioning journal (local validation only)

Branch `w1/provisioning-journal` (from `l0/la-web-provisioning-r4`
`174e388`). **Nothing was deployed and no remote migration was applied.**

| Check | Result |
|---|---|
| `npm run check` | typecheck; 39 test files and 973 tests in the workers, static and client projects; build; 10 build-output tests: all pass |
| Protocol | `npm run protocol:fixtures -- check` and `sha256sum -c MANIFEST.sha256` pass; digest unchanged (`454066f8…a43`) |
| Migration 0003, Wrangler `--local` | applies to a fresh database (54 statements), and to a 0002 database holding data, preserving the rows |
| Staging build | `CLOUDFLARE_ENV=staging`: Worker `lightagent-control-staging`, D1 `lightagent-control-staging`, compatibility date `2026-10-01`, same bindings as before, no cron triggers; no W1 code in the bundle |
| `wrangler deploy --dry-run` | exits after listing bindings; no upload |

Before staging, three separate approvals are needed: applying 0003 to
staging, deploying, and the operator behaviour change (suspension revokes
profiles). See [PROVISIONING_W1.md](PROVISIONING_W1.md) §11.

### 2026-10-15: W1 on staging via Cloudflare Workers Builds (Gates A–B.3)

Each step had its own approval. Source: `deploy/staging` at `eb2dad8`
(W1 `11aca88` + Gate A.2 hardening). Production untouched (no Worker, no
migrations). No secret, cron trigger, signing key or harness was added.

| Step | Result |
|---|---|
| A / A.2: builds `53620073`, `d42eed99` | dry run only; `ci:cloudflare`: frozen r4 verified (`454066f8…a43`), typecheck, 41 files / 984 tests, staging build, 11 build-output tests; guard passed |
| B.1: migration 0003 | Time Travel bookmark `0000003b-00000000-00005105-14457601a18d55af4c0b484ad6d9da08` (02:14:53Z); export backup kept outside the repository (SHA-256 `63b04e6b…d5b6`, restore-tested); 0003 applied (54 statements); before/after row fingerprints identical; schema 18 tables, 38 triggers, 23 indexes; `foreign_key_check` empty, `quick_check` ok |
| B.2: Preview URLs | turned off on the live Worker (`previews_enabled: false`); per-version hostnames 404; workers.dev kept |
| B.2: upload, build `9181556d` | inactive version `91dc87aa-a156-45df-9296-81e2ad8a3106`; same test results; output byte-identical to the reviewed build; bindings identical to Phase 5 |
| B.3: activation | deployment `f8fcc91f-2749-4699-925c-5782b5a72dd5` at 08:39:11Z: `91dc87aa` 100%, Phase 5 `fd978898` 0% (rollback target). Bookmark before: `0000003f-00000000-00005105-dc4234e5fe3b5f48eb1ff2e4376bb5b6` |

Staging smoke test after activation:

| Check | Result |
|---|---|
| Documents (`/`, `/login`, `/agents`, deep `/agents/<id>`, `/security`, `/dashboard`) | 200, `no-store`, header nonce = every body nonce, no placeholder, fresh per request; headless Chromium: rendered, 0 CSP violations, signed-out visitors land on `/login` |
| API | `/health` ok; `POST /health` 405 + `Allow`; `/api*` JSON 404 even for HTML; `/api/agents` signed out → 401; foreign-origin and Origin-less writes → 403 |
| Auth | `/api/config`: Google, GitHub, passkeys, staging Turnstile key; invalid Turnstile token refused; real Google sign-in by the operator: dashboard, Agents and Security load, no CSP errors (`auth.login.success` + `auth.logout` audited, 0 sessions left) |
| D1 | fingerprints unchanged by activation; statuses 1 active / 1 pending; all provisioning, harness and agent-profile tables empty |
| Worker | `fetch` handler only, cron `[]`, observability logs and traces on |

Open findings (not regressions; separate follow-up):

- **Login rate limiting did not trigger live.** 78 social sign-in attempts
  from one IP in about two minutes (burst, then paced over 60 s) were all
  allowed by `RL_LOGIN` (20 / 60 s) and refused by Turnstile. W1 changed no
  rate-limit code or binding. Live rate limiting had never been verified on
  staging. Cloudflare documents the binding as permissive and eventually
  consistent. Turnstile still gates every sign-in. Investigate with the
  Worker logs (`ratelimit.*`). SECURITY_MODEL.md's table (login 10, signup 5)
  also differs from `wrangler.jsonc` (20, 10).
- Browsers log `/favicon.ico` 404 (no favicon is shipped) and a
  Permissions-Policy warning for `browsing-topics` (an opt-out the browser no
  longer recognizes). Both cosmetic.

Operator: from now on only the W1 operator (`eb2dad8` or later) may run
against staging. `suspend`/`disable` revoke Web-side agent profiles, and
`reactivate` does not restore them. Lightagent-side revocation is not
implemented (W2).

### 2026-10-15: Authoritative rate limiter (carrier live; implementation uploaded inactive)

The login rate-limit finding: the Workers Rate Limiting bindings on staging
never refused (controlled test from one IP at SJC: 25/25 sign-in starts with
an invalid Turnstile token and 30/30 passkey option requests, all allowed;
`wrangler tail` showed every request reaching Turnstile with no
`ratelimit.*` line). Code order and bindings were correct. Matches the open
upstream issue cloudflare/workers-sdk#16097.

Fix: SQLite-backed Durable Object counters (`AuthRateLimiter`, binding
`AUTH_RATE_LIMITER`) decide `login`, `passkey_login` and `signup`; see
[SECURITY_MODEL.md](SECURITY_MODEL.md#rate-limiting). `wrangler.jsonc`
declares the binding and migration for development, staging and
production. As of this section (2026-10-15) nothing was deployed; see the
C2 and U1 records below.

Hosted validation (no upload): Workers Builds build
`7b9b69c0-3d49-4562-a31e-c52b911febff` on `deploy/staging` = `f6ab94b`, deploy
command switched to the guard + `wrangler deploy --env staging --dry-run`:
r4 verified, 44 files / 1037 tests, 11 build-output tests, dry run with
`AUTH_RATE_LIMITER` listed. Live state unchanged (W1 `91dc87aa` 100%).

#### Carrier runbook (prepared; each step needs its own approval)

The carrier is `0b9528e`: W1 plus the unused class, binding and migration.
Its staging Worker bundle is the W1 bundle plus the appended class and one
export name; every other module, the client assets and all generated
configuration except `durable_objects`/`migrations` are identical, and no
code references `AUTH_RATE_LIMITER`. The migration mechanism is the legacy
`migrations` array (`new_sqlite_classes`): the declarative `exports` field
would make every later `wrangler versions upload` fail and cannot be undone.

Branch `deploy/staging-carrier` is at exactly `0b9528e`. Commit `91c9f65`
(parent `0b9528e`) adds only `scripts/deploy-carrier.mjs`, its `.d.mts` and
`tests/static/deploy-carrier.test.ts` (the same files are on this branch).
The script is the deploy command; it refuses unless the source digest of
every other tracked file is `0b9528e`'s (`8b211653…1e5a`), no tracked file
is modified, the Builds branch is `deploy/staging-carrier`, the generated
configuration is the staging Worker/D1 with Preview URLs off and exactly
the `AUTH_RATE_LIMITER` binding and `v1-auth-rate-limiter` migration, the
bundle exports the class without using it, and the live deployment is
exactly `91dc87aa` at 100%. Without `--deploy` it only dry-runs.

Builds settings (Settings → Builds, Production tab). The rule throughout:
**the deploy command is changed before the branch, and is never mutating
while the branch is `deploy/staging`.**

| Phase | Production branch | Deploy command |
|---|---|---|
| now | `deploy/staging` | guard + `npx wrangler deploy --env staging --dry-run` |
| C1 hosted carrier dry run | `deploy/staging-carrier` | `node scripts/deploy-carrier.mjs` |
| C2 carrier deploy | `deploy/staging-carrier` | `node scripts/deploy-carrier.mjs --deploy` |
| C3 restore | `deploy/staging` | guard + `npx wrangler deploy --env staging --dry-run` |
| later: inactive upload | `deploy/staging` | guard + `npx wrangler versions upload --env staging --message "…"` |

C1. Set the deploy command, save; then set the production branch, save.
   (If the branch change starts a build of `0b9528e`, its deploy step fails:
   the script is not in that commit. Nothing is deployed.) Push `91c9f65` to
   `deploy/staging-carrier` (fast-forward): Builds runs `ci:cloudflare`
   (43 files / 1016 tests locally) and the script's dry run. Check the log:
   `carrier verified`, `AUTH_RATE_LIMITER`, `--dry-run: exiting now.`; and
   the account: 10 versions, `91dc87aa` 100%.
C2. Before: D1 Time Travel bookmark; `wrangler deployments status --env
   staging` shows `91dc87aa` 100%. Set the deploy command to `… --deploy`,
   save, then **Retry** the C1 build (same commit; retry uses the current
   settings). The script re-checks everything, runs `wrangler deploy`, and
   prints the new deployment. A second run refuses (W1 no longer at 100%).
C3. Immediately: deploy command back to the dry-run guard, save; then the
   production branch back to `deploy/staging`, save. Delete nothing.

After C2: the carrier version is the only rollback target. Cloudflare
blocks rollback to `91dc87aa`, `fd978898` and every earlier version
(Durable Object lifecycle change).

Carrier smoke test (C2 → C3, before anything else): `deployments status`
(carrier 100%), `versions view` lists `AUTH_RATE_LIMITER`, dashboard shows
the `AuthRateLimiter` namespace with no objects; documents `/`, `/login`,
`/agents`, `/agents/<id>`, `/security`, `/dashboard` 200 `no-store`, header
nonce = body nonces, headless Chromium 0 CSP violations; `/health` ok,
`POST /health` 405, `/api*` JSON 404, signed-out `/api/agents` 401,
foreign-origin and Origin-less writes 403; `/api/config` unchanged; one
invalid-Turnstile sign-in start → 403 `TURNSTILE_FAILED`; one passkey
options request → 200; operator's real Google sign-in → dashboard, Agents,
Security, session cookie `__Secure-…; HttpOnly; SameSite=Strict`, logout,
0 sessions; optionally a passkey sign-in; D1 schema 18/38/23 and row
fingerprints equal to the bookmark; `wrangler tail` during all of it: no
exceptions, no Durable Object invocations.

Carrier failure (fix forward; no rollback to W1 exists):
- Deploy step fails before `wrangler deploy` (any `REFUSING`): nothing
  changed; restore settings (C3), investigate.
- `wrangler deploy` fails: check `deployments status`. If `91dc87aa` is
  still 100%, nothing activated (the migration is applied only with a
  successful upload); restore settings and investigate.
- Carrier live but a smoke check fails: first compare with W1 behaviour
  (the request code is W1's). Fix forward with a new version of the
  carrier source plus the fix, through the normal upload-only path (no
  migration is pending any more), then `versions deploy`. Only if the class
  itself must go: a further `deleted_classes` migration via `wrangler
  deploy` (deletes the namespace; still no route back to pre-carrier
  versions).

Then, separately approved: implementation upload (`f6ab94b`, inactive),
promotion with `versions deploy <id>@100%`, the controlled 21-attempt
check, and rollback = `versions deploy <carrier-id>@100%`.

#### 2026-10-16: C2 carrier deployed (signed off)

Builds `16e805f6-c412-4cb8-bffc-b5828638c31c` (retry of C1 build `f4fa1a48`
with `--deploy`) on `deploy/staging-carrier` = `91c9f65`: version
`7750a63c-fd3d-424e-a2c7-feb062cd4633` at 100% (deployment
`d2b7c623-53af-4cf2-b756-6e6f17e0678b`, 00:40:40Z). Migration
`v1-auth-rate-limiter` applied; namespace `AuthRateLimiter` (SQLite) with no
objects. D1 bookmark before: `00000046-00000000-00005105-d03ac6be2e4b4743f661cc70002af4f5`.
Builds settings restored (C3). Smoke test: 18/18 HTTP checks, 0 CSP
violations, D1 unchanged, 0 Durable Object calls; operator: 0 CSP
violations in authenticated use, session cookie `HttpOnly; Secure;
SameSite=Strict; Path=/api`, Google sign-in, account pages, logout.

**Staging rollback baseline: `7750a63c`.** `91dc87aa`, `fd978898` and older
can no longer be rolled back to.

#### 2026-10-16: U1 implementation uploaded inactive (closed)

Deploy command switched to the guard + `npx wrangler versions upload --env
staging --message "f6ab94b DO limiter"` (459 characters; checked byte for
byte), then **Retry** of hosted validation build `7b9b69c0` on
`deploy/staging` = `f6ab94b`: Builds `64136c60`.

| | |
|---|---|
| Implementation version | `0fbd01ba-e5cd-44b5-9513-6c85c723c7e4` (#22, 02:39:02Z, message `f6ab94b DO limiter`), **0%** |
| Active version | carrier `7750a63c-fd3d-424e-a2c7-feb062cd4633`, **100%** (deployment `d2b7c623` unchanged) |
| Bundle | all 11 uploaded modules equal a local `CLOUDFLARE_ENV=staging` build of `f6ab94b` (ignoring `//#region` source paths) |
| Bindings | staging `DB` `3cc0724d-…`, `AUTH_RATE_LIMITER` → `AuthRateLimiter`, `RL_*` 2001–2007, existing secrets; migration tag still `v1-auth-rate-limiter` |
| Durable Objects | 0 objects (no request reaches the new limiter) |
| Preview URLs | `previews_enabled: false`; version and `deploy-staging` alias hostnames 404 |
| D1 / production | no pending migrations; no production Worker |

The pipeline passed (the upload runs only after `ci:cloudflare` and the
guard succeed); the Builds `64136c60` log was not reviewed, so its r4 digest
and test counts are not recorded here (hosted validation of the same commit,
`7b9b69c0`: r4 verified, 44 files / 1037 tests, 11 build tests).

Settings restored (R1): deploy command back to the guard + `npx wrangler
deploy --env staging --dry-run` (429 characters; checked byte for byte),
production branch `deploy/staging`, build command `npm run ci:cloudflare`,
`CLOUDFLARE_ENV=staging`, `NODE_VERSION=22`, Builds for Preview branches off.

Next, separately approved (P1): `npx wrangler versions deploy
0fbd01ba-e5cd-44b5-9513-6c85c723c7e4@100% --name lightagent-control-staging
--message "<approval reference>" --yes`, from a staging build of `f6ab94b`;
rollback: the same with `7750a63c-fd3d-424e-a2c7-feb062cd4633@100%`.
