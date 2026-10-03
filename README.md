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
| 2 | Security foundation | next |

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
npm test          # Vitest
npm run build     # client assets + Worker bundle into dist/
npm run check     # typecheck + test + build
npm run cf-typegen  # regenerate worker-configuration.d.ts after editing wrangler.jsonc
```

Routing: `/api/*` and `/health` run the Worker; every other path is a static
asset with `index.html` as the SPA fallback (`wrangler.jsonc` → `assets`).

## Environments

`wrangler.jsonc` defines `development` (top level), `staging`, and
`production`. Only public, non-secret values belong in `vars`. Secrets are set
per environment with `wrangler secret put <NAME> --env <env>` and, locally, in
a gitignored `.dev.vars` (see `.dev.vars.example`). Deployment is documented in
`docs/DEPLOYMENT.md` (Phase 2+).
