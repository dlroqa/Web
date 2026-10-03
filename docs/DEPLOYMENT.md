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

Run after every staging deploy (see the checklist in this section's log).

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

Issues found, fixed in Phase 2:

1. HTML documents carry no security headers.
2. A missing hashed asset (`/assets/nope.js`) returns the SPA HTML with 200
   instead of 404.
3. HTML is edge-cacheable; nonce-bearing documents must be `no-store`.
