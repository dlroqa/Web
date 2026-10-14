# Database (Cloudflare D1)

The control plane's persistent state lives in D1 (SQLite). The schema is
defined only by numbered migrations in `migrations/`, accessed only through the
repositories in `src/worker/db/`, and guarded twice: by repository
validation and by the database itself (CHECK constraints, foreign keys, and
triggers).

## Environments

Each environment has its own database. Bindings are per environment in
`wrangler.jsonc` (`d1_databases` is not inherited), and every environment uses
the binding name `DB`. Database ids are identifiers, not secrets.

| Environment | Database | Database id | Bound to |
|---|---|---|---|
| development | `lightagent-control-dev` | `773b82f0-29e6-446e-9d26-6394d0837596` | top-level config (`npm run dev` uses a local simulation of it) |
| staging | `lightagent-control-staging` | `3cc0724d-fb83-4477-ac0f-5aee58606fdf` | `env.staging` only |
| production | `lightagent-control-production` | `581f46bc-733c-4d9f-87c9-a5bb90716986` | `env.production` only; empty, no migrations applied yet |

Staging never points at production, and development never points at either.
All three live in the Cloudflare account that owns the Worker.

## Migrations

```sh
npx wrangler d1 migrations create DB <description>        # new numbered file
npm run db:migrate:local                                   # local dev database
npm run db:migrate:staging                                 # staging (remote)
npx wrangler d1 migrations apply DB --env production --remote   # production: human approval required
```

Rules:

- Schema changes are **only** made through migrations: no dashboard edits and
  no ad-hoc `d1 execute` DDL as the normal workflow.
- An applied migration is never edited. Fix forward with a new file.
- Files are applied in filename order (`0001_…`, `0002_…`, `0003_…`) and recorded in
  `d1_migrations`; re-applying is a no-op.
- Tests apply the real migration files to a fresh D1 (`tests/helpers/apply-migrations.ts`).
- Applied files are hash-locked (`tests/static/migrations.test.ts`).
- Migrations must be backwards compatible with the deployed Worker (expand,
  deploy, then contract in a later migration).

## Conventions

- Identifiers: prefixed random strings from the CSPRNG (`usr_`, `agt_`, `hns_`,
  `prv_`, `aud_`, `req_`), ~134 bits. Never sequential, never used as the
  authorization mechanism.
- Timestamps: `INTEGER` Unix epoch milliseconds (UTC).
- Tables are `STRICT` (wrong types are rejected, not coerced).
- Foreign keys are enforced (`PRAGMA foreign_keys = 1` in D1) with
  `ON DELETE RESTRICT`: deleting an owner with dependent rows fails.
- Every user-controlled text column has a length limit at both layers.
- JSON columns have a Zod schema (`src/worker/db/json.ts`), are validated
  before writing and after reading, and have a size CHECK.

## Schema

```text
user_profiles 1 ──< agent_profiles >── 0..1 harnesses
      │                  │                    │
      └──────< provisioning_jobs >────────────┘
provisioning_nonces   (standalone, keyed by nonce hash)
audit_events          (standalone, append-only; actor/target ids are not FKs)
```

### `user_profiles`

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | `usr_…` |
| `auth_user_id` | TEXT UNIQUE NOT NULL | Opaque id from the auth system (Better Auth, Phase 4). 1–255 chars, no format assumed. Immutable. |
| `display_name` | TEXT NULL | 1–80 chars, no control characters |
| `status` | TEXT | `pending` · `active` · `suspended` · `disabled` |
| `created_at`, `updated_at` | INTEGER | |

### `agent_profiles`

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | `agt_…`; also the Lightagent `ProfileId` on the harness |
| `user_id` | TEXT NOT NULL → `user_profiles.id` | Canonical owner. Immutable. |
| `agent_name` | TEXT | 1–80 chars |
| `status` | TEXT | see state machine |
| `harness_id` | TEXT NULL → `harnesses.id` | Required for `provisioning`/`active`/`suspended` (CHECK) |
| `revocation_version` | INTEGER ≥ 1 | Starts at **1**; only increases (trigger) |
| `permissions_json` | TEXT | Server-chosen ceiling `{chat, memory, rag, web, mcp, shell, admin:false}`; `admin` can never be true |
| `created_at`, `updated_at`, `last_seen_at` | INTEGER | |

Indexes: `(user_id, created_at)`, `(harness_id)` (partial).

### `harnesses` (administrator-controlled)

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | `hns_…` |
| `name` | TEXT UNIQUE | 1–80 chars |
| `environment` | TEXT | `development` · `staging` · `production`; immutable. A Worker only selects harnesses of its own environment. |
| `endpoint` | TEXT | Absolute `https://` URL (`http://` only for development), no credentials/query/fragment, ≤ 2048. Administrator input only, never from users (SSRF). |
| `key_id` | TEXT | Id of the control-plane signing key this harness trusts |
| `public_key` | TEXT NULL | The harness's own Ed25519 public key (base64) for verifying signed harness responses, reserved until that protocol is defined |
| `status` | TEXT | `active` · `draining` · `disabled`; registered as `disabled` |
| `capabilities_json` | TEXT | `{protocolVersions, operations, region?, maxProfiles?}`, ≤ 2048 bytes |
| `created_at`, `updated_at`, `last_seen_at` | INTEGER | |

No private keys, signing secrets, or overlay-network (Netmaker/Tailscale)
credentials are stored. A test asserts no such column exists.

### `provisioning_jobs`

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | `prv_…` |
| `user_id`, `agent_profile_id`, `harness_id` | TEXT FKs | Immutable |
| `operation` | TEXT | `profile.create` · `profile.disable` · `profile.enable` · `profile.revoke`. Provisioning v1 ([PROVISIONING_PROTOCOL.md](PROVISIONING_PROTOCOL.md)) sends only `profile.create` and `profile.revoke` (plus unrecorded `profile.status` polls) |
| `request_id` | TEXT | `req_…` of the originating API request (propagated to Lightagent) |
| `idempotency_key` | TEXT **UNIQUE** | 16–128 chars `[A-Za-z0-9_-]` |
| `request_hash` | TEXT | Lowercase hex SHA-256 of the canonical command payload (`payloadHash`, PROVISIONING_PROTOCOL §9.1) |
| `status` | TEXT | see state machine |
| `attempt_count` | INTEGER 0–10 | Legacy counter. The W1 journal increments it per transmission, saturating at 10; it gates nothing. The transmission count is the journal itself ([PROVISIONING_W1.md](PROVISIONING_W1.md) §7) |
| `error_code` | TEXT NULL | Stable code `[A-Z0-9_]{1,64}`; required when `failed` |
| `created_at`, `updated_at`, `completed_at` | INTEGER | `completed_at` is set iff the status is terminal (CHECK) |

Indexes: unique partial `(agent_profile_id, operation) WHERE status IN
('pending','sending','accepted')` (one in-flight job per profile and
operation), `(user_id, created_at)`, `(agent_profile_id, created_at)`.

Migration 0003 adds `operation_id`, `principal_id`, `observed_state`
(forward-only, trigger), `observed_owner_bound`, `observed_at`,
`needs_attention` + `attention_code`, and `next_attempt_at`.

### Provisioning journal (migration 0003)

Full design, invariants and concurrency argument:
[PROVISIONING_W1.md](PROVISIONING_W1.md).

| Table | Rows | Mutability |
|---|---|---|
| `provisioning_commands` | the fixed logical command of a job (canonical payload, `payload_hash = request_hash`) | none: no update, no delete |
| `provisioning_deliveries` | lease, `next_seq`, `auto_attempts`, `mode`, reconcile bookkeeping | counters move forward by one; no delete |
| `provisioning_transmissions` | one row per transmission, journaled before it can be sent | none: append-only |
| `provisioning_transmission_outcomes` | one `uncertain` mark and/or one `answered` record per transmission | insert-only; an answer is final |
| `harness_retirements`, `harness_replacements` | operator records (§10.6) | append-only |

`harnesses` gains `provisioning_hold` / `provisioning_hold_at` (the
LEDGER_CONTINUITY_FAILED circuit breaker). A retired harness stays
`disabled`, and its id can never be deleted or reused.

Authoritative reconciliation reads use a D1 session started with
`first-primary`, in one batch; decisions are applied with a compare-and-swap
on the journal version they read.

### `provisioning_nonces`

`nonce_hash` (PK, SHA-256 hex of `nonce:v1:<nonce>`), `created_at`,
`expires_at` (index). Plaintext nonces are never stored.

### `audit_events` (append-only)

| Column | Notes |
|---|---|
| `id` | `aud_…` |
| `timestamp` | ms |
| `actor_type`, `actor_id` | `user`/`admin`/`system`/`anonymous`; `actor_id` NULL iff anonymous |
| `action` | From the fixed list in `src/worker/audit/audit.ts` |
| `target_type`, `target_id` | Both or neither |
| `request_id` | |
| `result` | `success` · `failure` · `denied` |
| `reason` | Stable error code |
| `security_metadata_json` | `{sourceHash?, sourceKeyId?, country?}`, ≤ 512 bytes. Never a raw IP. |
| `details_json` | Flat scalar map, keys validated as non-sensitive, ≤ 4096 bytes |

Indexes: by time, actor, target, request id, and source hash. An `UPDATE`
trigger rejects every modification.

## Ownership

User-facing code never queries agent profiles by id alone:

```ts
const owned = new AgentProfileRepository(env.DB).forUser(session.userId);
await owned.get(profileId);      // WHERE id = ?1 AND user_id = ?2
await owned.rename(profileId, name);
await owned.revoke(profileId);
```

`OwnedAgentProfiles` adds `user_id = ?` to every statement, so another user's
profile and a nonexistent one return the same result (`null` or
`NotFoundError`), which maps to a 404 (no enumeration). Methods that ignore
ownership are suffixed `Trusted` (`getByIdTrusted`, `transitionTrusted`,
`incrementRevocationVersionTrusted`) or `Admin` (`registerAdmin`,
`setStatusAdmin`) so they stand out in review. They are for internal
provisioning and future admin code only. Provisioning jobs have the same
split (`getForUser` vs `getByIdTrusted`).

## State machines

Transitions are atomic conditional `UPDATE … WHERE status IN (allowed
sources) RETURNING *`. A missing row gives `NotFoundError`, a disallowed
transition `InvalidTransitionError`. A trigger enforces the same table
directly in the database; tests check every pair against both layers.

```text
agent_profiles
  pending      → provisioning | revoked
  provisioning → active | failed
  failed       → provisioning | revoked
  active       → suspended | revoked
  suspended    → active | revoked
  revoked      → (terminal)
  (pending → active is impossible)

user_profiles
  pending   → active | disabled
  active    → suspended | disabled
  suspended → active | disabled
  disabled  → (terminal)

provisioning_jobs
  pending  → sending | cancelled | failed
  sending  → pending (retryable transport failure) | accepted | completed | failed
  accepted → completed | failed
  completed, failed, cancelled → (terminal)
```

Migration 0003 adds `provisioning → revoked` to `agent_profiles`: the
desired state can become absent while a create is unresolved (suspension,
user revocation; PROVISIONING_PROTOCOL §13.5, §13.7). Two guards come with it:

- a profile whose owner is `suspended` or `disabled` can never enter
  `provisioning` or `active`;
- a profile's `harness_id` never changes once set.

Of two concurrent conflicting transitions, exactly one succeeds.

## Revocation version

- Starts at `1` (`INITIAL_REVOCATION_VERSION`).
- Incremented atomically in SQL (`revocation_version = revocation_version + 1`
  in a single `UPDATE … RETURNING`), never read-then-write. Twenty-five
  concurrent increments yield 25 distinct values.
- Transitions to `suspended` or `revoked` bump it in the same statement.
- `incrementRevocationVersionTrusted` covers the other triggers: harness
  migration, security-sensitive permission changes, and security
  invalidation.
- A trigger rejects any decrease.

Signed commands carry this value; harnesses reject commands with an older
one ([AGENT_ACCESS_CONTROL.md §8](AGENT_ACCESS_CONTROL.md)).

## Idempotency

`ProvisioningJobRepository.createOrGet` runs one
`INSERT … ON CONFLICT (idempotency_key) DO NOTHING RETURNING *`:

- **Inserted:** a new job (`created: true`).
- **Key exists, same request** (request hash, user, profile, harness,
  operation): the existing job is returned (`created: false`). A retry never
  creates a second job.
- **Key exists, anything different:** `IdempotencyConflictError` →
  `409 IDEMPOTENCY_CONFLICT`.

Ten concurrent calls with one key produce exactly one job. A second,
different in-flight job for the same profile and operation hits the unique
partial index (`409 CONFLICT`).

## Errors

`mapD1Error` classifies D1 failures by constraint or trigger name
(`UniqueConflictError`, `InvalidTransitionError`, `ConstraintViolationError`,
`UnexpectedDbError`, …). The Worker's error handler converts any `DbError`
with `toApiError`:

| Error | API code |
|---|---|
| `NotFoundError` | 404 `NOT_FOUND` |
| `IdempotencyConflictError` | 409 `IDEMPOTENCY_CONFLICT` |
| `NonceReplayError` | 409 `REPLAY_DETECTED` |
| `InvalidTransitionError`, `UniqueConflictError` | 409 `CONFLICT` |
| anything else | 500 `INTERNAL_ERROR` |

Responses never contain SQL text, table or column names, or paths; the
sanitized class and constraint name go to logs only.

## Audit persistence

`D1AuditSink` stores validated events. `AuditRecorder` chooses the policy:

| Mode | On write failure | Use for |
|---|---|---|
| `required` | request fails with `INTERNAL_ERROR`; event also logged | administrative permission/role changes, harness registration/disable, provisioning initiation, account suspension/deletion, signing-key changes |
| `bestEffort` | request continues; failure and the event are logged | login success/failure, session listing, passkey listing, profile reads |

Unauthenticated denials (origin rejections, rate-limit hits) are logged only,
not stored in D1, so anonymous traffic cannot drive unbounded writes.

### Source identity (keyed IP hashing)

`security_metadata_json.sourceHash` = HMAC-SHA256(`AUDIT_SOURCE_HMAC_KEY`,
`source:v1:<normalized CF-Connecting-IP>`), with `sourceKeyId` (`k1`). Equal
hashes under one key id mean "same source" (`countBySourceTrusted`); without
the key, hashes cannot be reversed (an unkeyed hash of the small IPv4 space
could be). Raw IPs are never stored. The secret is **not set** in any
environment yet. When unset, events carry no source hash. To enable, generate
32+ random bytes, base64-encode them, and run
`wrangler secret put AUDIT_SOURCE_HMAC_KEY --env <env>`. On rotation, bump
`SOURCE_KEY_ID`.

## Retention

| Data | Retention (proposed) | Mechanism |
|---|---|---|
| `provisioning_nonces` | until `expires_at` (≤ 10 min after issue) | `NonceRepository.purgeExpired` in bounded batches; Cron Trigger scheduling deferred until provisioning ships |
| `verification` (Better Auth) | until `expiresAt` (OAuth state, passkey challenges: minutes) | Better Auth deletes consumed rows; abandoned ones are removed by `VerificationRepository.deleteExpired` (bounded, only ISO-text expiries in the past), run with `npm run operator -- purge-verifications`; scheduling deferred |
| `session` (Better Auth) | until expiry or revocation | Better Auth; incident revocation via the operator CLI |
| `provisioning_jobs` | terminal jobs 90 days | future scheduled cleanup |
| `audit_events` | 1 year; then delete in batches (deletes are allowed, updates are not) | future scheduled cleanup; account deletion follows the policy in the directive (§74) |
| `user_profiles`, `agent_profiles` | life of the account; revoked profiles kept for audit until account deletion | account-deletion flow (future) |

## Better Auth tables (migration 0002)

`0002_better_auth.sql` holds Better Auth 1.7.7's core schema plus the passkey
plugin, generated from the Worker's exact options
(`npm run auth:schema -- generate`) and then reviewed. `tests/static/auth-schema.test.ts`
proves the committed schema satisfies the pinned version.

| Table | Purpose | Review hardening |
|---|---|---|
| `user` | auth identity (name, email, emailVerified, image) | length limits |
| `session` | session token (unique, **stored raw**: see [SESSION_STORAGE_SECURITY.md](SESSION_STORAGE_SECURITY.md)), expiry, user agent | `ipAddress` must be NULL/'' (no raw IPs) |
| `account` | provider identity (`providerId`, `accountId`) | **unique (providerId, accountId)**; providers limited to google/github; `password` must be NULL |
| `verification` | OAuth state, passkey challenges | size limits |
| `passkey` | WebAuthn credentials | **unique credentialID**; size limits |

They are not STRICT (Better Auth uses the `date` column type). Foreign keys
cascade from `user`. Application tables reference the auth user only through
`user_profiles.auth_user_id` (opaque text, unique, no FK); see
[AUTHENTICATION.md](AUTHENTICATION.md) for the lifecycle.

Applied migrations are locked: `tests/static/migrations.test.ts` records each
applied file's SHA-256 and fails if one changes.

## Operator writes

Account-status changes, operator session revocation, and operator passkey
removal go through `AdminRepository` (`src/worker/db/admin.ts`), used only by
the operator CLI ([OPERATIONS.md](OPERATIONS.md)). Each is one D1 `batch`
(a transaction): an `INSERT … SELECT … WHERE EXISTS (<guard>)` for the audit
row and the change itself guarded by the same condition, so the change and
its `admin.*` audit event are stored together or not at all. The
`user_profiles_status_transition` trigger still enforces the state machine
underneath. Direct `UPDATE user_profiles` through `wrangler d1 execute` is no
longer an operational procedure.

## Staging data

Staging holds two controlled test identities (`usr_zabx…` active, `usr_bcv3…`
pending; see [OPERATIONS.md](OPERATIONS.md#staging-test-accounts)). Staging
data is never copied to production.
