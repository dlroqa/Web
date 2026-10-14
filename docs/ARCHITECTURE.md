# Architecture

`lightagent-control` is the identity and control plane for Lightagent. It
authenticates users, owns account and agent-profile records, enforces
authorization, and sends signed provisioning commands to registered Lightagent
harnesses. It never runs agents and never holds inference credentials.

| Plane | Owner | Responsibility |
|---|---|---|
| Identity / control | this repo (Cloudflare Worker + D1) | Auth, sessions, authorization, policy, provisioning, audit |
| Agent execution | Lightagent harness | Agent loop, tools, memory, RAG, MCP, per-profile isolation |
| Inference | Lightweight / model router | Model serving |

## Conceptual model

```text
┌─────────────────────────────┐
│          USER               │
└─────────────┬───────────────┘
              │ HTTPS
              ▼
┌─────────────────────────────┐
│      React / Vite UI        │
│      Cloudflare Assets      │
└─────────────┬───────────────┘
              │ same origin
              ▼
┌─────────────────────────────┐
│      Cloudflare Worker      │
│                             │
│ Auth                        │
│ Authorization               │
│ Turnstile                   │
│ Rate limiting               │
│ Policy                      │
│ Audit                       │
│ Provisioning                │
└─────────────┬───────────────┘
              │
              ├────────► D1
              │
              │ Signed HTTPS
              ▼
┌─────────────────────────────┐
│ Lightagent Control Gateway  │
│                             │
│ Signature verification      │
│ Replay protection           │
│ Idempotency                 │
│ Provisioning policy         │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│       Lightagent Core       │
│                             │
│ User sandbox                │
│ Memory                      │
│ RAG                         │
│ MCP                         │
│ Tools                       │
│ Agent runtime               │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Lightweight / Model Router  │
└─────────────────────────────┘
```

## Deployment

One Cloudflare Worker serves both the static React build (Workers Static
Assets) and the API. Requests to `/api/*` and `/health` run the Worker first;
all other paths are served as assets with SPA fallback. Frontend and API share
one origin, so no CORS is needed.

## Agent access (future path)

Version 1 ends at provisioning (`Ready`). The path for users to actually use an
agent is designed in [AGENT_ACCESS_CONTROL.md](AGENT_ACCESS_CONTROL.md):

```text
User → authenticated Worker → authorization check → owned active agent
     → signed invocation → Lightagent tenant gateway → profile-bound run
```

The browser never talks to a Lightagent harness and never holds a Lightagent
credential. The Worker runs a single ownership/status/capability guard for
every agent-profile route, and the harness binds each run to the profile named
in the signed command, never to a caller-supplied profile.

## Code layout

```text
src/client/   React SPA (no secrets; talks only to same-origin /api)
src/worker/   Worker entry, api, security, db (repositories), audit, site
src/worker/provisioning/  W1 provisioning coordination (D1 only; no transport, not routed)
src/shared/   Schemas, types, and error codes shared by both sides
migrations/   D1 migrations (the only way the schema changes)
tests/        unit, integration, security, contracts
```

## Persistence

Each environment has its own D1 database bound as `DB`. All SQL lives in
`src/worker/db/` repositories using prepared statements. User-facing code
reaches agent profiles only through `forUser(userId)`, which scopes every
query to the owner. Status machines, the monotonic `revocation_version`,
immutable ownership, and append-only audit rows are enforced by both the
repositories and database triggers. See [DATABASE.md](DATABASE.md).

Provisioning coordination (W1) keeps a durable, append-only D1 journal of
every transmission before it could be sent, and resolves jobs conservatively
from a primary-consistent read of that journal. See
[PROVISIONING_W1.md](PROVISIONING_W1.md). Nothing is sent to any harness yet.
