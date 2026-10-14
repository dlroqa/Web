# Agent Access Control

Status: **design, Version 1 establishes the contract and data model; remote
multi-tenant execution is implemented in a later phase.**

This document defines how an authenticated user reaches *their own* Lightagent
agent, and nobody else's. It closes gap 1 from `CURRENT_ARCHITECTURE.md`:
the existing Lightagent run/session API is single-operator (one admin key,
caller-selected `profile`) and must never be exposed to end users.

## 1. Required paths

Version 1 (implemented):

```text
User → authenticated Worker → owned profile → signed provisioning → Ready
```

Future (designed now, enabled later):

```text
User → authenticated Worker → authorization check → owned active agent
     → signed invocation → Lightagent tenant gateway → profile-bound run
```

Nothing in Version 1 may require the future path to expose Lightagent, its
operator API, or any Lightagent credential to the browser.

## 2. Ownership model

```text
user_profiles (status)
 └── agent_profiles (user_id, status, harness_id, revocation_version, permissions)
       └── on harness: profiles/<agent_profile.id>/
             ├── sessions/    conversation history
             ├── memory/
             ├── rag/
             ├── workspace/
             └── (control grants held outside the profile dir, see §7)
```

- Every agent profile has exactly one owner: `agent_profiles.user_id`.
- The owner is **always** derived server-side from the authenticated session.
  The browser never supplies `user_id`, owner identity, harness, permissions,
  or profile directory.
- `agent_profiles.id` (`agt_…`, random) is also the Lightagent `ProfileId`
  (it satisfies `^[a-z0-9][a-z0-9_-]{0,63}$`). Random IDs supplement, never
  replace, the ownership check.

## 3. Authorization rule for every agent request

Every Worker route that reads, modifies, or invokes an agent profile runs the
same guard, in this order, and fails closed:

| # | Check | Failure |
|---|---|---|
| 1 | Valid server-side session | `401 AUTH_REQUIRED` |
| 2 | `user_profiles.status = 'active'` | `403 ACCOUNT_DISABLED` |
| 3 | Profile exists **and** `agent_profiles.user_id = session.user_id` (single query, both predicates) | `404 NOT_FOUND` |
| 4 | `agent_profiles.status = 'active'` (for invocation; reads allow any status) | `409 AGENT_UNAVAILABLE` |
| 5 | Required capability is in the role's permissions **and** in the profile's granted permissions | `403 FORBIDDEN` |
| 6 | Harness assigned to the profile is `active` | `503 HARNESS_UNAVAILABLE` |

Rules:

- Check 3 returns **404, not 403**, for another user's profile, so existence
  is not disclosed (IDOR resistance).
- The lookup is always `WHERE id = ?1 AND user_id = ?2`. A profile is never
  fetched by id alone and checked afterwards.
- Implemented once (`requireOwnedProfile(ctx, profileId, capability)`) and used
  by every profile route; route handlers receive the already-authorized row.

## 4. Future invocation API

### 4.1 Chosen design: Worker-mediated invocation (default)

```text
POST /api/agent-profiles/:id/runs          start a run (body: { message, sessionId? })
GET  /api/agent-profiles/:id/runs/:runId/events   SSE, proxied by the Worker
POST /api/agent-profiles/:id/runs/:runId/cancel
GET  /api/agent-profiles/:id/sessions
GET  /api/agent-profiles/:id/sessions/:sessionId
POST /api/agent-profiles/:id/approvals/:runId
```

(`POST /api/agent-profiles/:id/chat` may be offered as a convenience alias of
`runs`.)

Flow per request:

1. Worker runs the §3 guard.
2. Worker builds a signed **invocation command** using the same Ed25519
   control protocol as provisioning (`docs/PROVISIONING_PROTOCOL.md`), with
   `operation: "agent.invoke"` (or `agent.sessions.read`, `agent.cancel`, …)
   and claims:

   ```json
   {
     "version": 1,
     "operation": "agent.invoke",
     "audience": "hns_…",
     "subject": { "userId": "usr_…", "profileId": "agt_…" },
     "revocationVersion": 3,
     "permissions": { "chat": true, "memory": true, "rag": true, "mcp": false },
     "issuedAt": 1791063000,
     "expiresAt": 1791063060
   }
   ```

3. Worker sends it to the harness's **tenant gateway**, a new Lightagent
   endpoint separate from the operator API (e.g. `/v1/tenant/runs`).
4. The tenant gateway verifies signature, timestamp, nonce, `audience` (its
   own harness id), and `revocationVersion`, then runs **only** against
   `subject.profileId`. It ignores any `profile`, `cwd`, model base URL, or
   permission fields from anywhere else.
5. Responses and SSE events are schema-validated by the Worker before being
   relayed. The Worker never relays raw upstream errors or addresses.

Why this is the default: the harness stays off the public internet (reachable
only from the Worker over HTTPS, Tunnel, or a private overlay), the browser
holds only its normal session cookie, and revocation is enforced on every
request by the Worker *and* the harness.

### 4.2 Permitted alternative: short-lived scoped agent token

Allowed only if a later requirement (e.g. latency of long SSE streams through
the Worker) justifies it, and only under all of these constraints:

- Issued by the Worker after the §3 guard, via
  `POST /api/agent-profiles/:id/access-token`.
- Ed25519-signed by the Worker; claims: `aud` (harness id), `sub` (profile id),
  `uid`, `scope` (e.g. `agent:chat`), `gen` (revocation version), `jti`,
  `exp` ≤ 5 minutes. Not refreshable without a new Worker request.
- Delivered in the response body for in-memory use only; never stored in
  `localStorage`, `sessionStorage`, IndexedDB, or a readable cookie.
- Accepted **only** by the tenant gateway (which re-verifies everything in
  §4.1 step 4), never by the operator API.
- The tenant gateway endpoint is then exposed through a dedicated hostname
  with its own CSP/CORS allowlisting the control-plane origin only.

### 4.3 Prohibited

- Exposing the Lightagent operator API (`/api/lightagent/v1/*`) to users.
- Giving the browser a permanent, long-lived, or operator-scoped Lightagent
  credential, API key, or `--key-env` value.
- Any route where the browser chooses the harness, endpoint URL, profile
  directory, `cwd`, or permission set.
- A generic proxy (`/api/proxy?url=…`, `/api/agent/:id/raw/*`).

## 5. Lightagent-side requirements (later integration phase)

Made in the Lightagent repository as a separate, additive phase:

1. A **tenant gateway** module, mounted only when trusted control public keys
   are configured. Default `lightagent serve` behaviour is unchanged.
2. Runs started through it bind to the signed `subject.profileId`; it never
   consults the *active* profile and never accepts a caller-chosen profile.
3. Sessions are read via `SessionStore::at_profile(handle(profile_id))`.
4. A **per-profile permission ceiling** (§7) is enforced at tool-execution time,
   intersected with the global config: effective = global ∩ profile ceiling.
5. The operator API key keeps working for the operator; tenant credentials can
   never reach operator routes.

## 6. Multiple harnesses

- `agent_profiles.harness_id` is the single source of truth for placement.
  The Worker resolves the endpoint from the admin-controlled `harnesses`
  table; users never supply it (SSRF protection).
- Every signed command carries `audience = harness_id`. A command captured for
  harness A is rejected by harness B even within its validity window.
- Each harness trusts only the control-plane public keys configured by its
  operator; a compromised harness cannot mint commands for others (it holds no
  private key).
- Harness selection (capacity, region, affinity) is a Worker concern behind the
  `ProvisioningTransport` / harness-selection interfaces. V1: one configured
  harness.

## 7. Tenant isolation requirements

| Resource | Requirement |
|---|---|
| Conversation history | Stored under `profiles/<agt>/sessions/`. Gateway reads only the signed profile's store. Session IDs are only valid within their profile; a foreign session id returns 404. |
| Memory | `profiles/<agt>/memory/`. No cross-profile memory search or reflection. |
| RAG | `profiles/<agt>/rag/`. Remote vector stores (Qdrant) must use a per-profile collection or a mandatory `profile_id` filter applied server-side, never a shared unfiltered collection. |
| Workspace/files | `profiles/<agt>/workspace/`. A global `tools.workspace` override is forbidden on multi-tenant harnesses (startup check). Uploads go to the profile's own session attachments. |
| Tools | Effective permission = global config ∩ profile ceiling, evaluated at execution time. Defaults: chat/memory/rag allowed; web policy-dependent; terminal, global filesystem, admin denied. |
| MCP | Denied by default. Grants are per profile and per server, recorded by the control plane, and require Checkpoint G. Shared MCP servers must not carry one user's credentials into another user's run. |
| Secrets | Per-profile secrets (if ever) live in the profile's owner-only `.env`/secret refs. Operator inference keys are never exposed to profiles or users. |
| Control grants | Held under `<home>/control/profiles/<agt>.json`, **outside** the profile directory, so agent tools cannot edit their own ceiling. |

## 8. Revocation

The control plane keeps `agent_profiles.revocation_version` (integer). Every
signed invocation carries it; the harness stores the highest generation seen
per profile and rejects lower ones.

| Event | Worker (immediate) | Harness |
|---|---|---|
| User suspended / disabled | §3 check 2 fails on every request; all sessions revoked; every owned profile's generation bumped | Signed `profile.disable` sent for each profile; in-flight runs cancelled; later commands with old generation rejected |
| Profile disabled / revoked | Status ≠ `active` → check 4 fails; generation bumped | Signed `profile.disable` / `profile.revoke`; runs cancelled; data retained per retention policy |
| Session revoked | Session invalid → check 1 fails. Worker-proxied streams for that session are closed. Scoped tokens (§4.2) expire within ≤ 5 min; generation bump if immediate cut-off is required | No change needed under §4.1 |
| Agent moved to another harness | Status `migrating` (no invocation); old harness gets `profile.disable`; new harness gets `profile.create`/import; `harness_id` updated; generation bumped | Old harness rejects all later commands (audience + generation); new harness accepts only after provisioning succeeds |

Revocation never relies on the browser discarding something.

For **provisioning**, [PROVISIONING_PROTOCOL.md](PROVISIONING_PROTOCOL.md)
(`LA-WEB-PROVISIONING/1`) supersedes the harness column above: v1 has no
`profile.disable`/`profile.enable` and carries no `revocationVersion`.
Harness access is removed by an irreversible `profile.revoke` of the
create operation (§13.5 there). `revocation_version` remains a Web-side
value for the future invocation path.

## 9. Version 1 obligations

Version 1 does not ship invocation, but it must:

- Put the §3 guard in one function and use it for every `/api/agent-profiles/*`
  route (read, update, delete, status).
- Include in the D1 schema: `user_profiles.status`, `agent_profiles.user_id`,
  `.status`, `.harness_id`, `.revocation_version` (starts at 1, only
  increases), and `.permissions_json` (granted ceiling). Done in Phase 3; see
  [DATABASE.md](DATABASE.md). When a profile was disabled is recorded in the
  audit log rather than a `disabled_at` column.
- Include `audience` (harness id) in the signed provisioning payload.
- Store the per-profile permission ceiling chosen by server policy at creation.
- Ship the mandatory tests in §10 that apply to existing routes.

## 10. Mandatory contract tests

V1 (existing routes) and future (invocation routes, marked †). All must pass
before the corresponding feature ships.

- **IDOR-01** User A `GET /api/agent-profiles/{B's id}` → 404, no data.
- **IDOR-02** User A `PATCH` / `DELETE` B's profile → 404; B's row unchanged.
- **IDOR-03** User A `GET …/{B's id}/status` → 404.
- **IDOR-04** Random / guessed / sequential-looking ids → 404, same response
  shape and timing class as a real foreign id.
- **IDOR-05** Body or query containing `userId`, `ownerId`, `harnessId`,
  `permissions`, `admin` → rejected by strict schema (400) and never applied.
- **AUTHZ-01** Suspended user → 403 `ACCOUNT_DISABLED` on every profile route.
- **AUTHZ-02** Unauthenticated → 401 on every profile route.
- **AUTHZ-03**† Invoke non-`active` profile → 409, no upstream call made.
- **XTEN-01**† User A invokes B's profile id → 404, no upstream call made.
- **XTEN-02**† Signed command for profile X cannot read profile Y's sessions,
  memory, RAG, or workspace (harness-side test).
- **XTEN-03**† Foreign `sessionId` under own profile → 404.
- **XTEN-04**† Command with `audience` of harness A rejected by harness B.
- **REV-01**† Command with stale `revocationVersion` rejected after disable.
- **REV-02**† Revoked session cannot start or continue a proxied run.
- **REV-03**† Expired scoped token (§4.2) rejected by the tenant gateway.
- **ISO-01**† Tool ceiling: profile without `shell` cannot run `terminal.run`
  even when globally enabled.
- **ISO-02**† Harness refuses to start tenant mode with a global
  `tools.workspace` override.
