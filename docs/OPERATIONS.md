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
| `provisioning-attention [--harness hns_…] [--limit N]` | provisioning jobs that need an operator: ids, states, codes only | — |
| `retire-harness --harness hns_… --code CODE --reason "…" --yes` | disable and **retire** a harness id for good (CODE: `LEDGER_CONTINUITY_FAILED`, `LEDGER_LOST`, `DECOMMISSIONED`) | `admin.harness.retire` |
| `approve-harness-replacement --retired hns_… --replacement hns_… --reason "…" --yes` | allow a new, still-disabled harness to replace a retired one | `admin.harness.replacement.approve` |
| `release-harness-hold --harness hns_… --reason "…"` | lift the LEDGER_CONTINUITY_FAILED circuit break | `admin.harness.hold.release` |

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

**Agent profiles (migration 0003).** In the same transaction, `suspend` and
`disable` move every non-revoked agent profile of the user to `revoked`, and
record `admin.user.profiles.revoke`. The result reports `profilesRevoked`.

- **This is permanent.** `reactivate` restores the account but **not** its
  profiles, because harness revocation is irreversible
  (PROVISIONING_PROTOCOL §13.5). The user creates new profiles.
- **It withdraws Web access, not the harness binding.** The provisioning
  reconciler later opens a revoke job for each completed create. A profile
  counts as unbound on the harness only once that revoke job has completed.
  A create whose outcome is still unknown is first resent to learn its
  operation id. Nothing is sent to any harness yet: there is no transport.

### Provisioning attention, harness retirement and replacement

Run `provisioning-attention` to see what needs an operator.

- **A paused job keeps its whole history and is never failed automatically.**
  The codes are explained in
  [PROVISIONING_W1.md](PROVISIONING_W1.md) §7.
- **There is no "resume" command yet.** Those decisions depend on evidence
  from the harness operator.

**`LEDGER_CONTINUITY_FAILED`.** The first such answer puts a hold on the
harness, and nothing more is sent to it. Then:

1. Ask the harness operator for the §10.6 continuity check result.
2. If the ledger is intact for **this same harness id**, run
   `release-harness-hold`. The job that saw the refusal stays in attention,
   because the refusal is never treated as evidence.
3. If the provisioning history is lost, retire the id (next procedure).

**Retiring a harness id.** Run `retire-harness … --code LEDGER_LOST --yes`.
This is irreversible:

- The id never serves again, and is never deleted or reused.
- Its unresolved creates stay unresolved (`HARNESS_RETIRED`). They are never
  failed, revoked, moved or resent.

**Approving a replacement.** All of the following are required before
`approve-harness-replacement`:

1. The replacement is registered with a **new** id, and is still `disabled`.
2. The harness operator confirms that the new id's ledger was initialized
   explicitly for that id (§10.6), and that the new gateway is not the old
   ledger under a new name.
3. For every profile of the retired id listed by
   `provisioning-attention --harness <retired>`, record the migration or
   recovery decision in the incident record, by `agt_`/`prv_` id. Old creates
   are **never** resent to the new id: its ledger does not know their keys,
   so a resend would create a second profile and binding.
4. A second person reviews the record.

Then run `approve-harness-replacement --retired … --replacement … --yes`,
and activate the harness. Activation of a harness at a retired harness's
endpoint is refused by the database until the approval exists. The approval
moves nothing: users on the retired id get new profiles on the replacement
through the normal flow.

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
