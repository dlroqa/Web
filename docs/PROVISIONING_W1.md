# Web W1: durable provisioning journal and lifecycle foundation

W1 implements the D1 side of `LA-WEB-PROVISIONING/1` r4 (frozen; digest
`454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43`). It adds
durable, crash-recoverable **coordination only**:

- No signer, no key, no transport, no route, no Cron Trigger and no harness
  contact exist.
- Nothing W1 adds is imported by the Worker entry or any route, so the
  deployed bundle does not contain it (checked: the staging build has no W1
  symbols).
- The specification is normative. Where Web's existing schema differed from
  r4, W1 adapts Web additively and never changes the protocol.

| | |
|---|---|
| Base | `l0/la-web-provisioning-r4` at `174e3881b7655260790cf0e419e0a9baba25441d` (frozen r4 acceptance) |
| Branch | `w1/provisioning-journal` (local; the repository has no remote) |
| Migration | `migrations/0003_provisioning_journal.sql`, local D1 only. **Not applied to staging or production** |
| Code | `src/worker/provisioning/` (pure protocol + lifecycle, coordinator), `src/worker/db/provisioning-journal.ts` (all journal SQL), operator additions |

## 1. What is implemented, what is a test double, what is deferred

| Capability | Status |
|---|---|
| Append-only D1 journal, fixed logical command, lease, outcomes (§13.10) | **Implemented** (migration 0003 + repository) |
| Write-before-send ordering (RC6, invariant J) | **Implemented**: `claim` journals in the lease batch; `deliverOnce` sends only a claim's result |
| Create resolution R1–R3a, plan, ownership (§13.1–§13.3) | **Implemented**, checked against every `create-resolution.json` and `responses.json` vector |
| Revoke resolution R5 (§13.4) | **Implemented** over injected outcomes |
| Primary-consistent reconciliation reads (§13.10 r4) | **Implemented**: `first-primary` session + one-batch snapshot + journal-version CAS on every decision |
| Suspension (R6), harness retirement, circuit breaker (§10.6) | **Implemented** (D1 state + operator CLI) |
| Error registry, payload hash, JCS, display-name rule | **Implemented** (production port; registry equals `errors.json`) |
| Harness responses | **Test double**: `FakeHarness` (PR #26 semantics + r3 fence + durable nonces) and `JournalCheckingTransport` in `tests/helpers/provisioning.ts` |
| HTTP classification (`classifyResponse` port), Ed25519 signer, `fetchWithTimeout` transport, Access service token | **Deferred to W2** |
| Cron Trigger / `scheduled` handler running `reconcileDue` | **Deferred to W2** (the method exists and is tested) |
| Operator resume tooling for paused jobs; per-profile migration records | **Deferred** (W2/W3; see §9) |

## 2. Schema (migration 0003)

| Object | Kind | Purpose |
|---|---|---|
| `provisioning_commands` | new, **immutable** | The fixed logical command per job: operation, harness, profile, owner, idempotency key, canonical `payload_json`, `payload_hash` (= `provisioning_jobs.request_hash`), revoke target |
| `provisioning_deliveries` | new, constrained mutable | Lease (`lease_token`, `lease_holder`, `lease_until`), `next_seq`, `auto_attempts`, `mode` (`active`/`paused`), reconcile bookkeeping |
| `provisioning_transmissions` | new, **append-only** | One row per transmission: `command_id`, `seq`, `harness_id`, `agent_profile_id`, `protocol`, `operation`, `target_operation_id`, `payload_hash`, `key_id`, `nonce_hash`, `issued_at`/`expires_at` (Unix seconds), lease identity, `automatic`, `journaled_at` |
| `provisioning_transmission_outcomes` | new, **insert-only** | At most one `uncertain` mark and one `answered` record per transmission |
| `harness_retirements`, `harness_replacements` | new, append-only | Operator records (§10.6) |
| `provisioning_jobs` | +columns | `operation_id`, `principal_id`, `observed_state`, `observed_owner_bound`, `observed_at`, `needs_attention`, `attention_code`, `next_attempt_at` (§16.1 #4) |
| `harnesses` | +columns | `provisioning_hold`, `provisioning_hold_at` (circuit breaker) |
| `agent_profiles_status_transition` | trigger replaced | Adds `provisioning → revoked` (§13.7, §16.1 #4). All old transitions unchanged |
| new profile triggers | guards | A suspended/disabled owner's profile cannot enter `provisioning`/`active`; harness placement is permanent |

Existing rows are untouched. New job columns default to "nothing observed"
(`observed_state = 'unknown'`, no attention, no schedule).

## 3. Database invariants

Every trigger below raises a fixed message that `mapD1Error` turns into
`ProvisioningGuardError(reason)`. Each one is attacked with raw SQL in
`tests/db/provisioning-journal.test.ts`.

| # | Invariant | Enforced by |
|---|---|---|
| D1 | A command restates its job exactly (owner, profile, harness, operation, key, `payload_hash = request_hash`), and its JSON names the same profile, subject, key and operation | `provisioning_commands_match_job` |
| D2 | A create is fixed only for an **active** owner's own `pending`/`failed` profile, on an active, unheld, unretired harness compatible with the profile's placement, with no other unresolved or completed create for the profile | `provisioning_commands_create_allowed` |
| D3 | A revoke addresses an operation id that a create of that profile on that harness returned; never on a retired harness | `provisioning_commands_revoke_allowed` |
| D4 | Commands never change and are never deleted; their jobs cannot be deleted | `provisioning_commands_immutable`, `…_no_delete`, FK `RESTRICT` |
| D5 | Only the current lease holder journals, with exactly `next_seq − 1`, for an `active` delivery | `provisioning_transmissions_admissible` |
| D6 | A transmission of the command's own operation carries the fixed payload hash and needs a **non-terminal** job; a status poll addresses the job's known operation id; harness and profile are the command's | `provisioning_transmissions_identity` |
| D7 | Nothing is journaled for a disabled, held or retired harness | `provisioning_transmissions_harness_available` |
| D8 | Transmissions and outcomes are never updated or deleted; deliveries are never deleted | `…_append_only_*`, `provisioning_deliveries_no_delete` |
| D9 | An answer is final; no uncertain mark after an answer; a late answer after an uncertain mark is allowed | PK `(command_id, disposition)`, `provisioning_outcomes_answer_final` |
| D10 | A create answer is terminal; a revoke answer is `revoked`; status/revoke answers name the addressed operation | `provisioning_outcomes_consistent` |
| D11 | `next_seq` and `auto_attempts` move by 0 or 1; a new `seq` always comes with a new lease | `provisioning_deliveries_monotonic` |
| D12 | `observed_state` only moves forward; `operation_id`/`principal_id` are learned once | `provisioning_jobs_observed_forward`, `provisioning_jobs_operation_fixed` |
| D13 | Nonce hashes are unique journal-wide; `(job_id, seq)` unique; `command_id` primary key | constraints |
| D14 | A retired harness stays disabled, its row cannot be deleted or its id reused; a harness at a retired harness's endpoint cannot be activated without an operator replacement approval | `harnesses_retired_stay_disabled`, FK, PK, `harnesses_replacement_gate` |
| D15 | Lifetime `1 ≤ expires_at − issued_at ≤ 120`; Unix-second and millisecond columns are range-checked | `CHECK` |

### Immutable facts versus mutable bookkeeping

- **Evidence is immutable.** The command and every transmission row cannot be
  updated at all. An outcome is an insert-only row; an answer cannot be
  replaced or withdrawn.
- **Bookkeeping is mutable but narrow.** Lease, sequence counter, mode and
  scheduling live on the delivery row and the job, under the D11 trigger.
  Losing them loses no evidence: a transmission without an answer is
  uncertain whatever the bookkeeping says (§13.2).

### Why the invariants hold under concurrency

D1 runs each batch as one transaction, serialized on the primary.

- **One claim, one row.** The claim's `UPDATE` is a compare-and-swap on the
  lease (`lease_until IS NULL OR lease_until <= now`). The journal `INSERT …
  SELECT … WHERE lease_token = ?` inserts only for the winner. Of N
  concurrent claims, one inserts; the others insert nothing and send nothing
  (test: 8 concurrent Workers).
- **No conclusion from a stale journal.** Every reconciliation pass starts
  its batch with `BEGIN_PASS`, a CAS that requires `next_seq` and the outcome
  count to equal the snapshot's. Every other write in the pass is gated on
  the random pass token that CAS wrote. If any transmission or outcome was
  added after the snapshot, the whole pass is a no-op and is re-run (test: a
  failure conclusion raced by a new claim is not applied).
- **No send after a conclusion.** D6 forbids journaling a create once its job
  is terminal. So after `failed` commits, no transmission of the job can
  exist that the conclusion did not see.

## 4. Logical command identity (§9.1)

- **Fixed once.** `openCreateJob` builds the §8.1 payload from the owner's
  profile, the session user id (subject), Web's issuer and a server-generated
  idempotency key. It refuses a display name the harness would refuse, before
  writing anything. It then computes `payloadHash`, and in **one batch**
  inserts the job (`request_hash = payloadHash`), the command (canonical
  `payload_json`), the delivery row, the profile's move to `provisioning` on
  that harness, and the audit event.
- **Never recomputed from mutable rows.** A rename after the job exists does
  not change the payload (tested).
- **What each retry renews.** The journal `INSERT` takes `payload_hash`,
  harness and profile from the command row, never from the caller. A retry
  renews `command_id`, nonce, `issued_at`, `expires_at` and `seq`, and keeps
  the payload byte-identical (tested over three retries).
- **Nonces.** 32 CSPRNG bytes in base64url, held only in the sending
  Worker's memory. The journal stores `SHA-256("nonce:v1:" ‖ nonce)`.
- **Secrets.** `payload_json` holds no secret: ids, the issuer, the display
  name, the template and the idempotency key, all of which the harness
  receives in clear. No key material, token or credential is stored. `key_id`
  is a reference, and tests use the placeholder `w1-test-only-key`.

## 5. Write before send and leases (RC6)

`deliverOnce` = `claim` → `transport.send(claim)` → `record` → `reconcileJob`.

- A sender receives only what `claim` returns, and that exists only after
  the lease and the journal row committed together.
- The test transport re-reads D1 on every send and fails if the row is
  missing.
- A transport exception is recorded as `uncertain` (`NETWORK_ERROR`).
- **Lease = coordination, not safety.** `LEASE_MS` is 30 s, longer than a
  10 s send plus the outcome write.
  - An expired lease can be reclaimed. `recoverLeases` marks every row of a
    dead or superseded claim `uncertain` (`LEASE_EXPIRED`), never refused or
    "not sent", and clears expired leases in the same batch.
  - A stalled Worker may still send and later record its answer. Both rows
    are reasoned over; the harness's idempotency makes them one operation.
  - Recording releases the lease only if this claim still holds it.

## 6. Primary-consistent reconciliation

`ProvisioningJournalRepository.snapshot` is the only authoritative read. It
reads in one D1 `batch` (one consistent transaction) on
`db.withSession("first-primary")`. It covers:

- the job, the command and the delivery row;
- every transmission with its outcomes, plus related revoke transmissions;
- the profile, owner and harness context, including retirement;
- sibling jobs and the outcome count.

It returns the session bookmark. Decisions that can conclude `failed`,
cancel, flag, revoke or pause use only this snapshot, and apply only through
the journal-version CAS (§3). Selection queries (`dueJobs`,
`absentObligations`) only pick work, so they are not restricted (§13.10: a
stale selection can only delay).

Test evidence: a database proxy whose unconstrained `SELECT`s on the journal
throw, while sessions work. A full pass, including a `failed` conclusion,
succeeds through it, and every session constraint is `first-primary`.
Local D1 has no replicas, so this proves the read path, not replica lag
itself.

## 7. Attempts, scheduling and escalation are separate

| Concern | Where | Rule |
|---|---|---|
| Delivery attempts | the journal (`next_seq − 1`), unbounded | every transmission is a row |
| Legacy `attempt_count` | `provisioning_jobs` (CHECK 0–10 kept) | now **saturates** at 10 (`MIN(attempt_count + 1, 10)`) and gates nothing |
| Retry scheduling | `next_attempt_at` | R4: 10 s, 30 s, 2 min, then every 15 min |
| Retry budget | `auto_attempts` (automatic sends only) | at 10: attention `RETRY_BUDGET_EXHAUSTED`, slow cadence, **job stays unresolved** (§13.3) |
| Reconciliation passes | `reconcile_count`, `last_reconciled_at` | bookkeeping only |
| Operator escalation | `needs_attention` + `attention_code`; delivery `mode = 'paused'` | see below |
| Logical outcome | `provisioning_jobs.status`, `observed_state` | only §13.2 / §13.4 move it |

The legacy `MAX_ATTEMPTS` path in `ProvisioningJobRepository.transitionTrusted`
is unchanged and unused by W1.

**Attention codes.**

- *Cleared by the reconciler when the condition goes away:*
  `RETRY_BUDGET_EXHAUSTED`, `OWNERSHIP_LOST`, `HARNESS_HOLD`,
  `HARNESS_DISABLED`.
- *Operator-only (paused where sending must stop):*
  - from §13.2: `PROFILE_UNAVAILABLE_WHILE_OPEN`, `LEDGER_CONTINUITY_FAILED`,
    `IDEMPOTENCY_CONFLICT`, `OPERATION_MISMATCH`, `UNKNOWN_REFUSAL`;
  - from §13.4: `UNKNOWN_OPERATION`, `OWNERSHIP_CHANGED`;
  - Web-side: `STATE_REGRESSION`, `UNEXPECTED_BINDING`,
    `BOUND_AFTER_FAILURE`, `CREATE_RESOLVED_REVOKED`, `HARNESS_RETIRED`,
    `LEGACY_JOB_WITHOUT_COMMAND`, `OPERATION_IN_PROGRESS`.
- **A paused job is still tracked.** It keeps its non-terminal status and its
  whole journal, and `provisioning-attention` lists it. It is never failed
  and never deleted. Only an operator decision moves it.

### Mapping to D1 job status (§13.7)

| Situation | Job status |
|---|---|
| Opened, nothing journaled | `pending` |
| First transmission | `sending`, kept while unresolved (§13.7 allows `sending`) |
| R1 completed | `completed` |
| R1 revoked | `completed` |
| R1 failed, R2, R3 | `failed` + `error_code` |
| Desired absent with nothing journaled | `cancelled` (see §8) |

`accepted` is never entered by W1. Create answers are terminal (P4), and a
status answer that would regress is an anomaly.

## 8. Suspension (R6) and harness retirement (§10.6)

**Suspend or disable** (operator `suspend`/`disable`). The batch that changes
the account status also does the following:

- It revokes every non-revoked profile of the user, `provisioning → revoked`
  included, and writes `admin.user.profiles.revoke` when there were any.
  `revoked` is terminal, so a create that completes late, or a reactivation,
  can never make a profile usable again. Reactivated users create new
  profiles (§13.5).
- This is **requested** revocation: Web access is withdrawn at once.
  **Observed** revocation is a completed revoke job, with the create's
  `observed_state = 'revoked'`. W1 never claims a binding was removed because
  D1 changed.

The reconciler then drives each create of that user. `desired` is computed
from the profile and owner status, so a lost event cannot hide an obligation
(level-triggered).

| Create state | W1 action |
|---|---|
| Nothing journaled | `cancelled`. Invariant J: nothing can exist on the harness. This additive rule replaces R4's send-then-revoke only when the journal is provably empty, gated on `next_seq = 1` at commit |
| Unresolved, operation id unknown | R4 keeps resending the **same** create to learn the id. A revoke cannot be fixed without it (D3) |
| Completed (late or not, `ownerBound` either way) | A revoke job with a fixed `{operationId, profileId}` command is opened, once, and stays `pending` (W1 sends nothing). The profile stays `revoked` |
| R1 `failed` with a known id | `confirm-status` is planned (a status poll becomes due) |
| Ended `failed` by a refusal | nothing to revoke (no id, §13.5) |

**Retirement** (operator `retire-harness … --yes`):

- One audited batch disables the harness and records the retirement.
- From then on, nothing is claimed for it (D7). No new command can be fixed
  for it (D2, D3).
- Its unresolved creates stay unresolved, with attention `HARNESS_RETIRED`
  and delivery paused. Nothing is failed, moved, revoked or replayed.
- The id can never be deleted, re-registered or re-activated.

**Circuit breaker.**

- The first journaled `LEDGER_CONTINUITY_FAILED` answer sets
  `harnesses.provisioning_hold`. From then on no job can journal anything for
  that harness.
- The job that saw it needs attention (R3a) and is paused. Other jobs get
  `HARNESS_HOLD`, which clears by itself after release.
- `release-harness-hold` lifts the hold. Jobs whose own journal holds the
  refusal stay in attention, because R3a never treats it as evidence.

**Replacement.** A replacement gets a **new** id by ordinary registration
(disabled). A harness at a retired endpoint cannot be activated until
`approve-harness-replacement --retired … --replacement … --yes` records the
operator's approval. The approval moves nothing: no job, command or profile
follows, and old creates are never resent to the new id (§10.6 step 4). The
operator approval requirements are in [OPERATIONS.md](OPERATIONS.md).

## 9. Crash and retry recovery matrix

Every row is a deterministic test in `tests/provisioning/coordinator.test.ts`
unless marked.

| Failure point | Durable state afterwards | Recovery | Can it end `failed` wrongly? |
|---|---|---|---|
| Before the claim batch commits | no journal row | next claim | no: nothing journaled, nothing sent |
| After commit, before send | row with no outcome, lease held | lease expiry → `uncertain` (`LEASE_EXPIRED`); resend | no: open until a later merits refusal passes its horizon |
| During send (never arrived) | row, no outcome | as above | no |
| After send, before the answer write | row, no outcome; harness executed | resend returns the recorded operation (R1) | no |
| Success answer lost | `uncertain` (`TIMEOUT`) | resend → same operation, one binding | no |
| Refusal answer lost | `uncertain` | resend; R3 needs a post-horizon merits refusal | no |
| Stalled Worker past its lease | two rows, both reasoned over | either answer resolves | no |
| Reconciler raced by a new claim | pass CAS fails, nothing written | pass re-reads | no |
| Retry budget exhausted | unresolved + `RETRY_BUDGET_EXHAUSTED` | slow cadence continues | no |
| Indeterminate code (`REPLAY_DETECTED`, `STORAGE_*`) | stored as `uncertain` | resend | no |
| `LEDGER_CONTINUITY_FAILED` / `PROFILE_UNAVAILABLE` while open | attention, paused | operator | no |
| Random schedules (80, seed `0x57a10001`) | invariant S checked after draining every delayed copy | — | 0 violations (`tests/provisioning/simulation.test.ts`) |

A mutation check confirms the simulation detects unsafe rules. Weakening the
R3 horizon test (`m.issuedAt >= u.issuedAt`) makes it fail on invariant S at
schedule 30. The mutation was reverted.

## 10. Security

- **Who can call it.** Every new service and repository method is internal.
  No route, no browser path and no Worker-entry import reaches
  `src/worker/provisioning/` or the journal repository. Static tests enforce
  this, and also that the provisioning code has no `fetch`, no
  `subtle.sign`/`importKey`, no `env.` and no secret names.
- **Owner checks.**
  - `openCreateJob` reaches the profile only through
    `AgentProfileRepository.forUser(userId)`, so another user's profile is
    `NotFound`.
  - The owner, the harness and the profile's placement are re-checked by D2.
  - A profile's harness never changes once set, so there is no cross-harness
    substitution. Transmissions take harness and profile from the command
    row (D6).
- **Values never taken from a request.** The issuer is a server parameter.
  The endpoint, key, owner, permissions, model URL and callback never come
  from a request, and W1 has no request path at all.
- **Audit.** Every change is audited in the same batch as the change:
  - opening a job: `provision.job.open`;
  - resolutions, cancellations, attention, revoke requests and harness holds:
    `provision.*`, actor `system:provisioning-reconciler`;
  - suspension profile revocation, retirement, replacement approval and hold
    release: `admin.*`.

  Metadata holds ids, states and codes only, never payloads, display names,
  idempotency keys, nonces or emails.
- **Unchanged.** Better Auth, sessions, CSP, origin checks, Turnstile and
  rate limits are untouched.

## 11. Rollout and rollback

- **Deployment needs an approval.** Applying 0003 to staging
  (`npm run db:migrate:staging`, remote) and to production each need an
  explicit approval. W1 applied it only to local D1, in workerd tests and
  in Wrangler `--local` runs, both fresh and upgraded from a 0002 database
  holding data.
- **Order.** Apply the migration first. Then deploy any later code that
  uses it. The current Worker bundle does not use 0003, so the two are
  independent.
- **Effect on running code.** On staging today the migration adds empty
  tables and columns with neutral defaults. Existing rows are unchanged. The
  replaced profile trigger keeps every previous transition. The new guards
  only refuse states that no current code path produces.
- **Rollback.**
  - Code: redeploy the previous Worker. No W1 code is in the bundle.
  - Schema: D1 has no down migrations. While the journal is empty, a forward
    migration 0004 can drop the new tables and triggers and restore the
    original `agent_profiles_status_transition`. ALTERed columns stay and are
    harmless.
  - Once any transmission exists, its rows must never be removed (A6).
  - D1 Time Travel restores a database to a point before the migration, as a
    last resort and only while no transmission exists.
- **Operator behavior change.** `suspend` and `disable` now revoke the
  user's profiles (R6), and `reactivate` no longer restores them. Approve
  this together with the migration.

## 12. Remaining risks and later work

- **W2.**
  - The `classifyResponse` port and HTTPS transport (`fetchWithTimeout`,
    8 KiB, `redirect: "manual"`).
  - The Ed25519 signer (secret `PROVISIONING_SIGNING_KEY`), and the
    `PROVISIONING_ISSUER` variable. W1 takes the issuer as a parameter.
  - A Cron Trigger running `reconcileDue`.
  - Access service tokens.
  - Restricting `HarnessCapabilitiesSchema`/`PROVISIONING_OPERATIONS` to the
    v1 set. Stored capability JSON may still list `profile.disable`, so the
    schema was not narrowed. Commands are limited to create/revoke by CHECK.
- **Operator tooling for paused jobs.** W1 lists them and records why. It has
  no "resume"/"acknowledge" command, because those decisions (for example
  after `PROFILE_UNAVAILABLE_WHILE_OPEN`) depend on harness-side evidence.
- **Display-name policy.** The §8.1 rule is enforced when a job is opened.
  Profile creation and rename still allow 1–80 UTF-16 units (§16.1 #5), so
  such a profile cannot be provisioned until renamed.
- **Duplicated attention list.** The auto-clearable codes appear in the
  coordinator and in one selection query. Keep them in sync.
- **Unsigned responses and forged answers** remain the accepted r4 residual
  risks (§12.1).
- **Replica lag is not exercised locally.** The read path is proven; lag
  itself is not.
- **Per-profile migration decisions** for a retired harness are recorded
  outside D1 (OPERATIONS.md). A structured record is later work.
