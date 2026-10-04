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
