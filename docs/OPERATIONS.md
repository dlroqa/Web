# Operations

Account administration is done with the **operator CLI**. Editing D1
directly (`wrangler d1 execute … UPDATE user_profiles …`) is no longer the
normal workflow: it skips transition checks and leaves no audit record.

## Actors

| Actor | Who | Built from | Can |
|---|---|---|---|
| `USER` | a signed-in end user | a Better Auth session, in the Worker | their own profile, sessions, passkeys |
| `OPERATOR` | a trusted person with Cloudflare account access | the CLI entry point (`src/operator/main.ts`) | the operator commands below |
| `SYSTEM` | an automated task | code (no human) | maintenance only (e.g. expired-verification purge) |

- A user never has operator privileges. Operator privilege isn't derived
  from an email address, hostname, being the first account, knowing a URL, or
  anything the browser shows.
- There is **no admin web UI or admin HTTP endpoint**. The Worker never
  imports `src/operator`. A static test and a build-output test enforce this,
  and a test checks that `/api/admin/*` and `/api/operator/*` are 404 for a
  signed-in active user.
- There is no admin identity system yet. The **authorization boundary is
  access to the Cloudflare account** that holds the D1 database (the
  operator's own `wrangler login`). The operator id (`opr_…`) names who acted
  in the audit trail; it is a label, not authentication. Keep account
  membership small and API tokens scoped.
- The operator id is **never built in**: each run needs `--operator opr_…` or
  `LIGHTAGENT_OPERATOR_ID` from the operator's own trusted environment (e.g.
  their shell profile), otherwise the CLI refuses. Each person uses their own
  id. (`opr_claudecodeagent` appears in the staging audit trail for the
  Phase 4.5 verification run only.)

## Running it

```bash
npx wrangler whoami                         # the Cloudflare account must be the one holding the database
export LIGHTAGENT_OPERATOR_ID=opr_yourname  # or pass --operator opr_…
npm run operator -- show-user --env staging --user usr_…
```

The CLI connects to the environment's real D1 through Wrangler's remote
bindings. It binds **only** that database, and nothing else. `--env staging`
is required. **Production is refused** until production launch is approved.

| Command | Effect | Audit action |
|---|---|---|
| `show-user --user usr_…` | status, sign-in methods, passkey/session counts (no email) | — |
| `list-passkeys --user usr_…` | passkey ids, labels, credential fingerprints | — |
| `approve --user usr_… --reason "…"` | `pending → active` | `admin.user.approve` |
| `suspend --user usr_… --reason "…"` | `active → suspended` | `admin.user.suspend` |
| `reactivate --user usr_… --reason "…"` | `suspended → active` | `admin.user.reactivate` |
| `disable --user usr_… --reason "…"` | `pending/active/suspended → disabled` (final) | `admin.user.disable` |
| `revoke-sessions --user usr_… --reason "…"` | delete all of one user's sessions | `admin.user.sessions.revoke` |
| `revoke-all-sessions --reason "…" --yes` | delete **every** session (incident) | `admin.sessions.revoke_all` |
| `remove-passkey --user usr_… --passkey <id> --reason "…"` | delete one passkey of that user | `admin.passkey.remove` |
| `purge-verifications [--limit N]` | delete up to N (≤ 500) expired verification rows | — (maintenance) |

Every change:

- names its target by **application user id** (`usr_…`), never by email
- is checked against the status state machine (the same rules as the
  database trigger)
- runs as **one D1 transaction** that writes the change and its audit event
  together, or neither
- records the operator id, the reason, an operation id (`op_…`, used as the
  audit request id), and `channel: "cli"`
- audits refusals (invalid transition, unknown user or passkey) as
  `result: "denied"`
- prints a sanitized JSON result: ids, statuses, counts. No email, tokens,
  or credential ids.

Reasons must be 3–200 characters, with no control characters and **no email
addresses** (the CLI rejects them; refer to people by `usr_…`).

### What suspension does and doesn't do

Suspending an account blocks it on the next request, whatever sessions it
has (`requirePrincipal` checks status every time), and blocks new sign-ins.
It does **not** delete sessions. Use `revoke-sessions` too if the sessions
themselves may be compromised.

## Procedures

**Approve a new account.** Find the `usr_…` id (from the user, or from the
`auth.account.created` audit event), check it with `show-user`, then run
`approve`.

**Suspected account compromise.** `suspend`, then `revoke-sessions`, both
with the same `--operation op_…` if you want them grouped. After contact,
the user signs in again with OAuth and reviews their passkeys. Remove any
unknown passkey with `remove-passkey`, then `reactivate`.

**Suspected session-token exposure (incident).**

1. `revoke-all-sessions --yes --reason "…"` ends every session immediately.
2. If `BETTER_AUTH_SECRET` may be exposed too: `wrangler secret put
   BETTER_AUTH_SECRET --env staging` with a new value. All cookie signatures
   become invalid.
3. Record the incident in the deployment log.

See [SESSION_STORAGE_SECURITY.md](SESSION_STORAGE_SECURITY.md).

**Expired verification rows.** `purge-verifications`. Only rows whose
`expiresAt` is in the past are deleted, in bounded batches; unexpired OAuth
state and passkey challenges are never touched. There's no schedule yet; run
it occasionally, or add a Cron Trigger later.

## Staging test accounts

| User | Status | Purpose |
|---|---|---|
| `usr_zabxoac7k6jmhzthjkumy65ve3` (Google) | `active` | controlled test account used for OAuth, passkey, session, and suspension tests |
| `usr_bcv3sksuuvfcvqot70orqbch49` (GitHub) | `pending` (**keep pending**) | controlled pending identity for testing active-only routes in Phase 5 |

These are staging-only test identities. **Don't copy them, or any other
staging data, to production.**
