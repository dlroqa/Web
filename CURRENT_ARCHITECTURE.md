# Current Lightagent Architecture (Phase 0 analysis)

Snapshot of `../Lightagent` at commit `7d95232` (branch `master`, clean tree),
analysed on 2026-10-03 before any changes. No Lightagent code was modified to
produce this document.

## 1. Language and runtime

- Rust workspace, edition 2024, MSRV 1.98, version 0.4.1.
- Async runtime: tokio. HTTP server: axum 0.8. HTTP client: reqwest + rustls.
- TLS/crypto provider: **`ring`** (pinned to avoid cmake/aws-lc). `ring`
  already provides Ed25519 verification, so the provisioning verifier needs
  **no new crypto dependency**.
- Hard dependency policy (`Cargo.toml`, enforced by `scripts/check-deps.sh`):
  no cmake, no OpenSSL, no libclang, no polars/tonic/sqlx; storage uses
  rusqlite (bundled) or flat files.
- Web UI: separate React 19 + Vite 6 + TypeScript SPA in `frontend/`, served
  same-origin by `lightagent serve --web-root`.

## 2. Crates

| Crate | Responsibility |
|---|---|
| `lightagent-core` | Agent loop, events, `AgentProfile`/`ProfileStore`, `Config`/`ConfigStore`, permissions, limits, paths |
| `lightagent-tools` | Tool registry, schema validation, risk classes, approvals, workspace confinement, built-ins |
| `lightagent-store` | Per-profile sessions, messages, run metadata |
| `lightagent-api` | axum HTTP + SSE API, static Web UI serving, bearer auth (`auth.rs`) |
| `lightagent-memory` | Durable per-profile memory (`<profile>/memory/memories.jsonl`) |
| `lightagent-rag` | Per-profile lexical/semantic index (`<profile>/rag/index.jsonl`), optional Qdrant/Infinity |
| `lightagent-mcp` | MCP client (stdio / streamable HTTP) |
| `lightagent-acp` | ACP editor-integration server |
| `lightagent-extensions` | Skill/MCP/persona bundles |
| `lightagent-runtime` | Optional placement/control client for providers |
| `lightagent-provider-lightweight` | OpenAI-compatible HTTP/SSE provider adapter |
| `lightagent` | CLI, TUI, `serve` wiring (`src/serve.rs`), setup |

## 3. HTTP API (`crates/lightagent-api/src/lib.rs`)

Routes: `/health`, `/api/lightagent/v1/{tools,provider,skills,profiles,settings,
runs,runs/{id},runs/{id}/events,runs/{id}/cancel,sessions,sessions/search,
sessions/{id},sessions/{id}/attachments,approvals,approvals/{run}}`, and a
static-file fallback.

There is **no control/provisioning endpoint** today.

## 4. Authentication (`lightagent-api/src/auth.rs`, `lightagent/src/serve.rs`)

- Loopback bind → `AuthConfig::open()` (no auth at all).
- Non-loopback bind → requires `--key-env`; **one** bearer key, granted
  `Scope::Admin` (all scopes). Constant-time comparison.
- There is no notion of end users, tenants, or per-user credentials. The API
  key holder is the single operator.

## 5. Profiles (existing isolation primitive)

`lightagent-core/src/profile.rs`: a profile is an isolated agent identity under
`<LIGHTAGENT_HOME>/profiles/<id>/` (`profile.json`, `SOUL.md`, `config.json`,
`.env`, `sessions/`, `memory/`, `rag/`, `workspace/`, `skills/`, `extensions/`,
`approvals.jsonl`, `history.jsonl`, `logs/`, `cache/`). Directories 0700,
secret files 0600.

- `ProfileId` validation `^[a-z0-9][a-z0-9_-]{0,63}$` is the path-isolation
  boundary. **Note:** control-plane IDs like `agt_…` are compatible (lowercase,
  digits, `_`).
- `ProfileStore::{scaffold, create, save, load, list, delete, active,
  set_active}`. `create` refuses to overwrite an existing profile, which is a
  natural idempotency anchor.
- `AgentProfile` fields: `id, name, description, persona, routing, toolsets,
  approval_policy, limits`.

**This is the adapter target for Phase 10:** provisioning should call
`ProfileStore::create` (wrapped), not reimplement profile storage.

## 6. Configuration

- Global typed `Config` at `<home>/config.json` (`ConfigStore`): inference,
  agent limits, security, web, MCP, memory, RAG, tools, extensions, runtime,
  subagents, platform (Jev/Qdrant/Infinity/Open Terminal).
- `ProfileHandle::config_file()` (per-profile `config.json`) is declared but
  **not loaded anywhere** — tool/MCP/web enablement is global today.
- Secrets: `SecretRef` (env-var reference) or owner-only files in
  `<home>/secrets/`.

## 7. Tools, MCP, permissions

- Permission levels `auto` / `ask` / `block`, by risk class
  (`docs/permissions.md`). Mutating/executable tools ask on every call;
  privileged tools always block. Evaluated at the executor boundary.
- `tools.enabled` / `tools.allow_terminal` / `mcp.enabled` / `web.*` are
  **global** switches. `tools.workspace` defaults to the per-profile
  `workspace/` but, **if set globally, is shared by all profiles.**
- MCP servers are configured globally and namespaced `mcp.<server>.<tool>`.

## 8. Memory and RAG storage

Flat JSONL files under each profile directory (`memory/memories.jsonl`,
`rag/index.jsonl`). Optional remote Qdrant collections are configured globally.

## 9. Tests and CI

- `scripts/check.sh` = `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace`, frontend build, version/deps/secrets checks.
- `.github/workflows/check.yml`: matrix check (macOS/Windows/Linux), Open
  Terminal live contract, Web UI render (Playwright), paired Lightweight E2E,
  Qdrant+Infinity contract, package smoke.
- Baseline `cargo test --workspace` result: see §11.

## 10. Integration findings and gaps (relevant to the control plane)

1. **No multi-tenancy in the run/session API.** `serve` binds sessions to the
   single *active* profile, and `POST /runs` accepts a caller-chosen
   `profile`. With one admin key this is fine for a single operator, but it
   means the existing API **must not** be exposed to end users as-is: any key
   holder can address any profile. Per-user access to provisioned agents needs
   a separate, later design (per-profile scoped credentials or a tenant-aware
   gateway). Out of scope for V1 provisioning; documented as a blocker for
   "Open Lightagent".
2. **Tool/MCP enablement is global**, not per profile. A newly provisioned
   profile inherits whatever the operator enabled globally (e.g. terminal,
   MCP). For least-privilege multi-user operation, provisioning must record a
   permission ceiling per profile, and Lightagent must enforce it at execution
   time. Until that enforcement exists, operators of a multi-user harness must
   keep `tools.allow_terminal`, `tools.enabled`, and `mcp.enabled` off globally
   (Checkpoint G).
3. **Global `tools.workspace` override breaks workspace isolation** between
   profiles if set. Multi-user harnesses must leave it unset.
4. **Existing profile isolation is good** for memory, RAG, sessions,
   workspace, skills, and history (path-derived from a validated id).
5. **Verifier can be built on `ring`** (already in the lockfile) with no
   dependency-policy violation. Nonce/idempotency storage can use a small file
   or rusqlite store under `<home>/control/`.
6. The provisioning endpoint should be a **new, separately bound module**
   (e.g. a `control` module or crate) mounted only when an operator configures
   trusted public keys, so default behaviour and all existing contracts are
   unchanged.

## 11. Baseline test results

`cargo test --workspace` at `7d95232` (local, Linux x86_64, cargo 1.98.1):

```text
38 test suites · 385 passed · 0 failed · 2 ignored (live-service contracts)
```

This is the protected contract. Every later Lightagent change must keep it
green and pass `scripts/check.sh` (fmt, clippy `-D warnings`, deps, secrets).
Working tree confirmed unchanged after the run.
