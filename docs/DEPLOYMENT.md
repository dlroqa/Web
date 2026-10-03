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
