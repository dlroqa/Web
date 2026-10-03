# lightagent-control

Identity and provisioning control plane for the
[Lightagent](../Lightagent) agent harness. It runs as one Cloudflare Worker that
serves a React/Vite UI from Workers Static Assets and a same-origin API under
`/api/*`.

The browser never talks to a Lightagent harness and never holds a Lightagent
credential. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/AGENT_ACCESS_CONTROL.md](docs/AGENT_ACCESS_CONTROL.md).

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Lightagent analysis ([CURRENT_ARCHITECTURE.md](CURRENT_ARCHITECTURE.md)) | done |
| 1 | Cloudflare scaffold (React, Vite, Worker, Static Assets) | done |
| 2 | Security foundation ([docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)) | done |
| 3 | D1 schema and repositories | next |

## Requirements

- Node.js 22+
- npm 11 for adding/changing dependencies (`npx npm@11 install …`). npm 10.9
  crashes resolving this dependency tree; `npm ci` with npm 10 works on the
  committed lockfile.
- Install scripts are allowlisted in `package.json` (`allowScripts`): only
  `esbuild` and `workerd` may run them.

## Commands

```sh
npm ci            # install from the lockfile
npm run dev       # Vite dev server with the Worker running in workerd
npm run typecheck # client, worker, and tooling projects
npm test          # Vitest inside workerd (unit + security tests)
npm run build     # client assets + Worker bundle into dist/
npm run test:build  # checks on dist/ (no inline JS, no secrets, production CSP)
npm run check     # typecheck + test + build + test:build
npm run cf-typegen  # regenerate worker-configuration.d.ts after editing wrangler.jsonc
```

Routing: hashed files under `/assets/*` are served directly by Workers Static
Assets. Everything else runs the Worker: `/api/*` and `/health` return JSON,
and other paths get the SPA document with a per-response CSP nonce (see
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)).

Tests run inside workerd via `@cloudflare/vitest-pool-workers`. Its bundled
runtime only supports compatibility dates up to 2026-08-22, so
`vitest.config.ts` pins that date for tests; deployed Workers use
`wrangler.jsonc`'s date and are covered by staging smoke tests.

## Environments

`wrangler.jsonc` defines `development` (top level), `staging`, and
`production`. Only public, non-secret values belong in `vars`. Secrets are set
per environment with `wrangler secret put <NAME> --env <env>` and, locally, in
a gitignored `.dev.vars` (see `.dev.vars.example`). Deployment is documented in
`docs/DEPLOYMENT.md` (Phase 2+).
