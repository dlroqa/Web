-- Migration 0003: durable provisioning journal (Web W1).
--
-- Implements the D1 side of LA-WEB-PROVISIONING/1 r4 §13.10 (write before
-- send, RC6), the job columns of §16.1 item 4, the suspension path, and
-- harness retirement (§10.6). Additive: 0001 and 0002 are never edited. No
-- existing row is rewritten; existing jobs simply have no fixed command and
-- can never be delivered (docs/PROVISIONING_W1.md, "Legacy jobs").
--
-- Units: protocol stamps (issued_at, expires_at) are Unix SECONDS, exactly as
-- signed (§4.4); every other *_at / *_until column is epoch MILLISECONDS like
-- the rest of the schema. CHECKs bound both, so a unit mix-up is rejected.
--
-- Layering:
--   provisioning_commands              the fixed logical command (immutable)
--   provisioning_deliveries            mutable delivery bookkeeping (lease,
--                                      sequence, mode); narrowly constrained
--   provisioning_transmissions         one row per transmission (immutable)
--   provisioning_transmission_outcomes what Web learned about a transmission
--                                      (insert-only; an answer is final)
--   harness_retirements, harness_replacements   append-only operator records
--
-- Every trigger message below is mapped to a typed error in db/errors.ts.

-- ---------------------------------------------------------------------------
-- provisioning_jobs: observation, attention and scheduling columns (§16.1 #4).
-- attempt_count keeps its 0–10 CHECK and now only saturates (it no longer
-- gates anything); the unbounded transmission count is the journal itself.
-- ---------------------------------------------------------------------------
ALTER TABLE provisioning_jobs ADD COLUMN operation_id TEXT
  CHECK (operation_id IS NULL OR (length(operation_id) = 32 AND operation_id NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE provisioning_jobs ADD COLUMN principal_id TEXT
  CHECK (principal_id IS NULL OR (length(principal_id) BETWEEN 1 AND 64 AND principal_id NOT GLOB '*[^a-z0-9_-]*' AND substr(principal_id, 1, 1) GLOB '[a-z0-9]'));
-- Last harness-reported operation state (§13.1). Forward only (trigger below).
ALTER TABLE provisioning_jobs ADD COLUMN observed_state TEXT NOT NULL DEFAULT 'unknown'
  CHECK (observed_state IN ('unknown', 'pending', 'profile_created', 'completed', 'failed', 'revoked')
         AND (observed_state = 'unknown' OR operation_id IS NOT NULL));
-- Current ownership as last reported (§12.2): may move either way; never moves state.
ALTER TABLE provisioning_jobs ADD COLUMN observed_owner_bound INTEGER
  CHECK (observed_owner_bound IS NULL OR observed_owner_bound IN (0, 1));
ALTER TABLE provisioning_jobs ADD COLUMN observed_at INTEGER
  CHECK (observed_at IS NULL OR observed_at > 1000000000000);
ALTER TABLE provisioning_jobs ADD COLUMN needs_attention INTEGER NOT NULL DEFAULT 0
  CHECK (needs_attention IN (0, 1));
ALTER TABLE provisioning_jobs ADD COLUMN attention_code TEXT
  CHECK ((attention_code IS NULL) = (needs_attention = 0)
         AND (attention_code IS NULL OR (length(attention_code) BETWEEN 1 AND 64 AND attention_code NOT GLOB '*[^A-Z0-9_]*')));
ALTER TABLE provisioning_jobs ADD COLUMN next_attempt_at INTEGER
  CHECK (next_attempt_at IS NULL OR next_attempt_at > 1000000000000);

CREATE INDEX provisioning_jobs_due ON provisioning_jobs (next_attempt_at)
  WHERE status IN ('pending', 'sending', 'accepted');
CREATE INDEX provisioning_jobs_attention ON provisioning_jobs (harness_id, updated_at)
  WHERE needs_attention = 1;
CREATE INDEX provisioning_jobs_by_harness ON provisioning_jobs (harness_id, created_at);

-- The harness-assigned operation id and principal are learned once (R1).
CREATE TRIGGER provisioning_jobs_operation_fixed
BEFORE UPDATE OF operation_id, principal_id ON provisioning_jobs
WHEN (OLD.operation_id IS NOT NULL AND NEW.operation_id IS NOT OLD.operation_id)
  OR (OLD.principal_id IS NOT NULL AND NEW.principal_id IS NOT OLD.principal_id)
BEGIN
  SELECT RAISE(ABORT, 'immutable_column');
END;

-- §13.1: unknown → pending → profile_created → completed → revoked, and
-- unknown | pending | profile_created → failed. Never backwards.
CREATE TRIGGER provisioning_jobs_observed_forward
BEFORE UPDATE OF observed_state ON provisioning_jobs
WHEN NEW.observed_state IS NOT OLD.observed_state AND NOT (
     (NEW.observed_state = 'failed' AND OLD.observed_state IN ('unknown', 'pending', 'profile_created'))
  OR (NEW.observed_state <> 'failed' AND OLD.observed_state <> 'failed' AND
      (CASE NEW.observed_state WHEN 'pending' THEN 1 WHEN 'profile_created' THEN 2 WHEN 'completed' THEN 3 WHEN 'revoked' THEN 4 ELSE 0 END)
    > (CASE OLD.observed_state WHEN 'pending' THEN 1 WHEN 'profile_created' THEN 2 WHEN 'completed' THEN 3 WHEN 'revoked' THEN 4 ELSE 0 END))
)
BEGIN
  SELECT RAISE(ABORT, 'observed_state_regression');
END;

-- ---------------------------------------------------------------------------
-- agent_profiles: the suspension path (§16.1 #4, §13.5, §13.7).
-- New transition provisioning → revoked: desired state becomes absent while a
-- create is unresolved (suspension, user revocation). A revoked profile is
-- terminal, so a create that completes late can never make it active again.
-- ---------------------------------------------------------------------------
DROP TRIGGER agent_profiles_status_transition;
CREATE TRIGGER agent_profiles_status_transition
BEFORE UPDATE OF status ON agent_profiles
WHEN NEW.status IS NOT OLD.status AND NOT (
     (OLD.status = 'pending'      AND NEW.status IN ('provisioning', 'revoked'))
  OR (OLD.status = 'provisioning' AND NEW.status IN ('active', 'failed', 'revoked'))
  OR (OLD.status = 'failed'       AND NEW.status IN ('provisioning', 'revoked'))
  OR (OLD.status = 'active'       AND NEW.status IN ('suspended', 'revoked'))
  OR (OLD.status = 'suspended'    AND NEW.status IN ('active', 'revoked'))
)
BEGIN
  SELECT RAISE(ABORT, 'invalid_status_transition');
END;

-- A suspended or disabled owner's profile can never (re)enter provisioning or active.
CREATE TRIGGER agent_profiles_owner_must_be_active
BEFORE UPDATE OF status ON agent_profiles
WHEN NEW.status IS NOT OLD.status AND NEW.status IN ('provisioning', 'active')
  AND EXISTS (SELECT 1 FROM user_profiles WHERE id = NEW.user_id AND status IN ('suspended', 'disabled'))
BEGIN
  SELECT RAISE(ABORT, 'owner_not_active');
END;

-- A profile's harness placement is permanent once made (§10.6 #4, §13.6):
-- no silent move or replay of a profile onto another harness id.
CREATE TRIGGER agent_profiles_harness_fixed
BEFORE UPDATE OF harness_id ON agent_profiles
WHEN OLD.harness_id IS NOT NULL AND NEW.harness_id IS NOT OLD.harness_id
BEGIN
  SELECT RAISE(ABORT, 'immutable_column');
END;

-- ---------------------------------------------------------------------------
-- harnesses: circuit breaker, retirement, replacement (§10.6).
-- harnesses.status keeps its CHECK; a retired harness is `disabled` plus a
-- harness_retirements row, as §10.6 step 2 anticipates.
-- ---------------------------------------------------------------------------
-- Set by the reconciler on LEDGER_CONTINUITY_FAILED; cleared only by an operator.
ALTER TABLE harnesses ADD COLUMN provisioning_hold TEXT
  CHECK (provisioning_hold IS NULL OR (length(provisioning_hold) BETWEEN 1 AND 64 AND provisioning_hold NOT GLOB '*[^A-Z0-9_]*'));
ALTER TABLE harnesses ADD COLUMN provisioning_hold_at INTEGER
  CHECK ((provisioning_hold IS NULL) = (provisioning_hold_at IS NULL) AND (provisioning_hold_at IS NULL OR provisioning_hold_at > 1000000000000));

CREATE TABLE harness_retirements (
  harness_id   TEXT    NOT NULL PRIMARY KEY REFERENCES harnesses (id) ON DELETE RESTRICT,
  reason_code  TEXT    NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 64 AND reason_code NOT GLOB '*[^A-Z0-9_]*'),
  retired_by   TEXT    NOT NULL CHECK (retired_by GLOB 'opr_[a-z0-9]*' AND length(retired_by) BETWEEN 12 AND 36),
  operation_id TEXT    NOT NULL CHECK (operation_id GLOB 'op_[a-z0-9]*' AND length(operation_id) BETWEEN 11 AND 64),
  retired_at   INTEGER NOT NULL CHECK (retired_at > 1000000000000)
) STRICT;

CREATE TRIGGER harness_retirements_require_disabled
BEFORE INSERT ON harness_retirements
WHEN NOT EXISTS (SELECT 1 FROM harnesses WHERE id = NEW.harness_id AND status = 'disabled')
BEGIN
  SELECT RAISE(ABORT, 'harness_not_disabled');
END;

CREATE TRIGGER harness_retirements_append_only_update
BEFORE UPDATE ON harness_retirements
BEGIN
  SELECT RAISE(ABORT, 'harness_record_append_only');
END;

CREATE TRIGGER harness_retirements_append_only_delete
BEFORE DELETE ON harness_retirements
BEGIN
  SELECT RAISE(ABORT, 'harness_record_append_only');
END;

-- A retired harness id never serves again (its row cannot be deleted either:
-- harness_retirements references it with ON DELETE RESTRICT).
CREATE TRIGGER harnesses_retired_stay_disabled
BEFORE UPDATE OF status ON harnesses
WHEN NEW.status <> 'disabled' AND EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'harness_retired');
END;

-- An operator's explicit approval that `replacement_harness_id` (a NEW id)
-- replaces a retired one, with the per-profile decisions recorded outside D1
-- (docs/OPERATIONS.md). It moves nothing: no job, command or profile follows.
CREATE TABLE harness_replacements (
  replacement_harness_id TEXT    NOT NULL PRIMARY KEY REFERENCES harnesses (id) ON DELETE RESTRICT,
  retired_harness_id     TEXT    NOT NULL REFERENCES harness_retirements (harness_id) ON DELETE RESTRICT,
  approved_by            TEXT    NOT NULL CHECK (approved_by GLOB 'opr_[a-z0-9]*' AND length(approved_by) BETWEEN 12 AND 36),
  operation_id           TEXT    NOT NULL CHECK (operation_id GLOB 'op_[a-z0-9]*' AND length(operation_id) BETWEEN 11 AND 64),
  approved_at            INTEGER NOT NULL CHECK (approved_at > 1000000000000),
  CHECK (replacement_harness_id <> retired_harness_id)
) STRICT;

CREATE TRIGGER harness_replacements_valid
BEFORE INSERT ON harness_replacements
WHEN EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = NEW.replacement_harness_id)
  OR NOT EXISTS (
       SELECT 1 FROM harnesses n JOIN harnesses o ON o.id = NEW.retired_harness_id
       WHERE n.id = NEW.replacement_harness_id AND n.status = 'disabled' AND n.environment = o.environment)
BEGIN
  SELECT RAISE(ABORT, 'replacement_invalid');
END;

CREATE TRIGGER harness_replacements_append_only_update
BEFORE UPDATE ON harness_replacements
BEGIN
  SELECT RAISE(ABORT, 'harness_record_append_only');
END;

CREATE TRIGGER harness_replacements_append_only_delete
BEFORE DELETE ON harness_replacements
BEGIN
  SELECT RAISE(ABORT, 'harness_record_append_only');
END;

-- A harness registered at a retired harness's endpoint (the same gateway that
-- lost its ledger) receives no work until an operator approves it as a replacement.
CREATE TRIGGER harnesses_replacement_gate
BEFORE UPDATE OF status ON harnesses
WHEN NEW.status IN ('active', 'draining') AND OLD.status = 'disabled'
  AND EXISTS (SELECT 1 FROM harness_retirements r JOIN harnesses h ON h.id = r.harness_id
              WHERE h.endpoint = NEW.endpoint AND h.id <> NEW.id)
  AND NOT EXISTS (SELECT 1 FROM harness_replacements WHERE replacement_harness_id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'replacement_not_approved');
END;

-- ---------------------------------------------------------------------------
-- provisioning_commands: the fixed logical command of one job (§9.1, §13.10
-- step 3). Written once, in the same batch as the job; never updated or
-- deleted. payload_json is the JCS form whose payloadHash is the job's
-- request_hash, so a retry can never change the payload (a rename does not
-- reach it). Holds no secret: ids, the issuer, the display name, the template
-- and the idempotency key, all of which go to the harness in clear anyway.
-- ---------------------------------------------------------------------------
CREATE TABLE provisioning_commands (
  job_id              TEXT    NOT NULL PRIMARY KEY REFERENCES provisioning_jobs (id) ON DELETE RESTRICT,
  user_id             TEXT    NOT NULL REFERENCES user_profiles (id) ON DELETE RESTRICT,
  agent_profile_id    TEXT    NOT NULL REFERENCES agent_profiles (id) ON DELETE RESTRICT,
  harness_id          TEXT    NOT NULL REFERENCES harnesses (id) ON DELETE RESTRICT,
  protocol            TEXT    NOT NULL CHECK (protocol = 'LA-WEB-PROVISIONING/1'),
  operation           TEXT    NOT NULL CHECK (operation IN ('profile.create', 'profile.revoke')),
  idempotency_key     TEXT    NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key NOT GLOB '*[^A-Za-z0-9_-]*'),
  -- The create operation a revoke addresses (§8.3); NULL for a create.
  target_operation_id TEXT             CHECK (target_operation_id IS NULL OR (length(target_operation_id) = 32 AND target_operation_id NOT GLOB '*[^0-9a-f]*')),
  payload_json        TEXT    NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 4096 AND json_valid(payload_json)),
  payload_hash        TEXT    NOT NULL CHECK (length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
  created_at          INTEGER NOT NULL CHECK (created_at > 1000000000000),
  CHECK ((operation = 'profile.revoke') = (target_operation_id IS NOT NULL))
) STRICT;

CREATE INDEX provisioning_commands_by_profile ON provisioning_commands (agent_profile_id);

-- The command must restate its job exactly, and its payload must name the
-- same profile, subject, key and operation as the relational rows.
CREATE TRIGGER provisioning_commands_match_job
BEFORE INSERT ON provisioning_commands
WHEN NOT EXISTS (
  SELECT 1 FROM provisioning_jobs j
  WHERE j.id = NEW.job_id AND j.status = 'pending'
    AND j.user_id = NEW.user_id AND j.agent_profile_id = NEW.agent_profile_id AND j.harness_id = NEW.harness_id
    AND j.operation = NEW.operation AND j.idempotency_key = NEW.idempotency_key AND j.request_hash = NEW.payload_hash)
  OR json_extract(NEW.payload_json, '$.profileId') IS NOT NEW.agent_profile_id
  OR (NEW.operation = 'profile.create' AND (
        json_extract(NEW.payload_json, '$.subject') IS NOT NEW.user_id
     OR json_extract(NEW.payload_json, '$.idempotencyKey') IS NOT NEW.idempotency_key))
  OR (NEW.operation = 'profile.revoke' AND json_extract(NEW.payload_json, '$.operationId') IS NOT NEW.target_operation_id)
BEGIN
  SELECT RAISE(ABORT, 'command_mismatch');
END;

-- Authorization that must hold when a create is fixed: the owner is active
-- (suspension blocks new provisioning), owns the profile, the profile can be
-- provisioned on this harness, no other create for it is unresolved or
-- succeeded (§13.3, §13.6), and the harness is active, unretired and unheld.
CREATE TRIGGER provisioning_commands_create_allowed
BEFORE INSERT ON provisioning_commands
WHEN NEW.operation = 'profile.create' AND (
     NOT EXISTS (SELECT 1 FROM user_profiles WHERE id = NEW.user_id AND status = 'active')
  OR NOT EXISTS (SELECT 1 FROM agent_profiles WHERE id = NEW.agent_profile_id AND user_id = NEW.user_id
                   AND status IN ('pending', 'failed') AND (harness_id IS NULL OR harness_id = NEW.harness_id))
  OR NOT EXISTS (SELECT 1 FROM harnesses WHERE id = NEW.harness_id AND status = 'active' AND provisioning_hold IS NULL)
  OR EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = NEW.harness_id)
  OR EXISTS (SELECT 1 FROM provisioning_jobs WHERE agent_profile_id = NEW.agent_profile_id AND operation = 'profile.create'
               AND id <> NEW.job_id AND status IN ('pending', 'sending', 'accepted', 'completed'))
)
BEGIN
  SELECT RAISE(ABORT, 'provisioning_not_allowed');
END;

-- A revoke addresses an operation id that a create of the same profile on the
-- same harness actually returned (§13.4: revocation depends on a known id),
-- and is never fixed for a retired harness (§10.6 step 3).
CREATE TRIGGER provisioning_commands_revoke_allowed
BEFORE INSERT ON provisioning_commands
WHEN NEW.operation = 'profile.revoke' AND (
     NOT EXISTS (SELECT 1 FROM provisioning_jobs WHERE agent_profile_id = NEW.agent_profile_id AND harness_id = NEW.harness_id
                   AND operation = 'profile.create' AND operation_id = NEW.target_operation_id)
  OR EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = NEW.harness_id)
)
BEGIN
  SELECT RAISE(ABORT, 'provisioning_not_allowed');
END;

CREATE TRIGGER provisioning_commands_immutable
BEFORE UPDATE ON provisioning_commands
BEGIN
  SELECT RAISE(ABORT, 'command_immutable');
END;

CREATE TRIGGER provisioning_commands_no_delete
BEFORE DELETE ON provisioning_commands
BEGIN
  SELECT RAISE(ABORT, 'command_immutable');
END;

-- ---------------------------------------------------------------------------
-- provisioning_deliveries: mutable delivery bookkeeping, one row per command.
-- This is coordination, not evidence: the lease only stops two Workers from
-- duplicating effort. Safety rests on the journal (§13.10).
--   mode     active: may be claimed when due; paused: operator attention,
--            nothing is sent until an operator resumes it
--   next_seq the sequence number the next transmission will get
-- ---------------------------------------------------------------------------
CREATE TABLE provisioning_deliveries (
  job_id             TEXT    NOT NULL PRIMARY KEY REFERENCES provisioning_commands (job_id) ON DELETE RESTRICT,
  mode               TEXT    NOT NULL DEFAULT 'active' CHECK (mode IN ('active', 'paused')),
  next_seq           INTEGER NOT NULL DEFAULT 1 CHECK (next_seq >= 1),
  -- Automatic (scheduled) transmissions; the retry budget counts these.
  auto_attempts      INTEGER NOT NULL DEFAULT 0 CHECK (auto_attempts >= 0),
  reconcile_count    INTEGER NOT NULL DEFAULT 0 CHECK (reconcile_count >= 0),
  -- Random per reconciliation pass. A pass first sets it with a compare-and-
  -- swap on the journal version it read, and gates every other write on it,
  -- so a decision is applied only if the journal is still what it reasoned over.
  reconcile_token    TEXT             CHECK (reconcile_token IS NULL OR (length(reconcile_token) BETWEEN 22 AND 64 AND reconcile_token NOT GLOB '*[^A-Za-z0-9_-]*')),
  last_reconciled_at INTEGER          CHECK (last_reconciled_at IS NULL OR last_reconciled_at > 1000000000000),
  lease_token        TEXT             CHECK (lease_token IS NULL OR (length(lease_token) BETWEEN 22 AND 64 AND lease_token NOT GLOB '*[^A-Za-z0-9_-]*')),
  lease_holder       TEXT             CHECK (lease_holder IS NULL OR (length(lease_holder) BETWEEN 1 AND 64 AND lease_holder NOT GLOB '*[^a-z0-9._:-]*')),
  lease_until        INTEGER          CHECK (lease_until IS NULL OR lease_until > 1000000000000),
  created_at         INTEGER NOT NULL CHECK (created_at > 1000000000000),
  updated_at         INTEGER NOT NULL CHECK (updated_at >= created_at),
  CHECK ((lease_token IS NULL) = (lease_until IS NULL) AND (lease_token IS NULL) = (lease_holder IS NULL))
) STRICT;

CREATE INDEX provisioning_deliveries_leased ON provisioning_deliveries (lease_until) WHERE lease_until IS NOT NULL;

CREATE TRIGGER provisioning_deliveries_fresh
BEFORE INSERT ON provisioning_deliveries
WHEN NEW.next_seq <> 1 OR NEW.auto_attempts <> 0 OR NEW.lease_token IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'delivery_bookkeeping');
END;

-- Counters only move forward, one transmission at a time; a new sequence
-- number always comes with a new lease (the claim that journals it).
CREATE TRIGGER provisioning_deliveries_monotonic
BEFORE UPDATE ON provisioning_deliveries
WHEN NEW.job_id IS NOT OLD.job_id
  OR NEW.next_seq NOT IN (OLD.next_seq, OLD.next_seq + 1)
  OR NEW.auto_attempts NOT IN (OLD.auto_attempts, OLD.auto_attempts + 1)
  OR NEW.reconcile_count < OLD.reconcile_count
  OR NEW.created_at IS NOT OLD.created_at
  OR (NEW.next_seq = OLD.next_seq + 1 AND (NEW.lease_token IS NULL OR NEW.lease_token IS OLD.lease_token))
BEGIN
  SELECT RAISE(ABORT, 'delivery_bookkeeping');
END;

CREATE TRIGGER provisioning_deliveries_no_delete
BEFORE DELETE ON provisioning_deliveries
BEGIN
  SELECT RAISE(ABORT, 'journal_append_only');
END;

-- ---------------------------------------------------------------------------
-- provisioning_transmissions: the journal (§13.10). One row per signed
-- request that could ever reach a harness, inserted in the same batch as the
-- delivery claim and BEFORE any byte is sent (invariant J). Never updated,
-- never deleted. The plaintext nonce is never stored, only its hash.
-- ---------------------------------------------------------------------------
CREATE TABLE provisioning_transmissions (
  command_id          TEXT    NOT NULL PRIMARY KEY CHECK (command_id GLOB 'cmd_[a-z0-9]*' AND length(command_id) BETWEEN 12 AND 64),
  job_id              TEXT    NOT NULL REFERENCES provisioning_deliveries (job_id) ON DELETE RESTRICT,
  seq                 INTEGER NOT NULL CHECK (seq >= 1),
  harness_id          TEXT    NOT NULL REFERENCES harnesses (id) ON DELETE RESTRICT,
  agent_profile_id    TEXT    NOT NULL REFERENCES agent_profiles (id) ON DELETE RESTRICT,
  protocol            TEXT    NOT NULL CHECK (protocol = 'LA-WEB-PROVISIONING/1'),
  operation           TEXT    NOT NULL CHECK (operation IN ('profile.create', 'profile.status', 'profile.revoke')),
  -- The operation a status or revoke addresses; NULL for a create.
  target_operation_id TEXT             CHECK (target_operation_id IS NULL OR (length(target_operation_id) = 32 AND target_operation_id NOT GLOB '*[^0-9a-f]*')),
  payload_hash        TEXT    NOT NULL CHECK (length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
  -- Reference to the Web signing key (§4.4 keyId); never key material.
  key_id              TEXT    NOT NULL CHECK (length(key_id) BETWEEN 3 AND 64 AND key_id NOT GLOB '*[^a-z0-9._-]*' AND substr(key_id, 1, 1) GLOB '[a-z0-9]'),
  nonce_hash          TEXT    NOT NULL UNIQUE CHECK (length(nonce_hash) = 64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
  issued_at           INTEGER NOT NULL CHECK (issued_at BETWEEN 1000000000 AND 9999999999),
  expires_at          INTEGER NOT NULL CHECK (expires_at BETWEEN 1000000000 AND 9999999999),
  lease_token         TEXT    NOT NULL,
  lease_holder        TEXT    NOT NULL,
  automatic           INTEGER NOT NULL CHECK (automatic IN (0, 1)),
  journaled_at        INTEGER NOT NULL CHECK (journaled_at > 1000000000000),
  UNIQUE (job_id, seq),
  CHECK (expires_at - issued_at BETWEEN 1 AND 120),
  CHECK ((operation = 'profile.create') = (target_operation_id IS NULL))
) STRICT;

CREATE INDEX provisioning_transmissions_by_harness ON provisioning_transmissions (harness_id, journaled_at);

-- Only the current lease holder journals, with the next sequence number, for
-- the command's own harness and profile. A transmission of the command's own
-- operation carries the fixed payload hash (retries never change the logical
-- command) and needs a non-terminal job (nothing is re-sent after Web
-- concluded); a status poll addresses the job's known operation id. Nothing
-- is journaled for a paused delivery or a retired, held or disabled harness.
CREATE TRIGGER provisioning_transmissions_admissible
BEFORE INSERT ON provisioning_transmissions
WHEN NOT EXISTS (
  SELECT 1 FROM provisioning_deliveries d
  WHERE d.job_id = NEW.job_id AND d.mode = 'active'
    AND d.lease_token = NEW.lease_token AND d.lease_holder = NEW.lease_holder AND d.next_seq = NEW.seq + 1)
BEGIN
  SELECT RAISE(ABORT, 'journal_lease_required');
END;

CREATE TRIGGER provisioning_transmissions_identity
BEFORE INSERT ON provisioning_transmissions
WHEN NOT EXISTS (
  SELECT 1 FROM provisioning_commands c JOIN provisioning_jobs j ON j.id = c.job_id
  WHERE c.job_id = NEW.job_id AND c.harness_id = NEW.harness_id AND c.agent_profile_id = NEW.agent_profile_id
    AND (
      (NEW.operation = c.operation AND NEW.payload_hash = c.payload_hash AND NEW.target_operation_id IS c.target_operation_id
        AND j.status IN ('pending', 'sending', 'accepted'))
      OR (NEW.operation = 'profile.status' AND NEW.target_operation_id = COALESCE(j.operation_id, c.target_operation_id))
    ))
BEGIN
  SELECT RAISE(ABORT, 'payload_mismatch');
END;

CREATE TRIGGER provisioning_transmissions_harness_available
BEFORE INSERT ON provisioning_transmissions
WHEN NOT EXISTS (SELECT 1 FROM harnesses WHERE id = NEW.harness_id AND status IN ('active', 'draining') AND provisioning_hold IS NULL)
  OR EXISTS (SELECT 1 FROM harness_retirements WHERE harness_id = NEW.harness_id)
BEGIN
  SELECT RAISE(ABORT, 'harness_unavailable');
END;

CREATE TRIGGER provisioning_transmissions_append_only_update
BEFORE UPDATE ON provisioning_transmissions
BEGIN
  SELECT RAISE(ABORT, 'journal_append_only');
END;

CREATE TRIGGER provisioning_transmissions_append_only_delete
BEFORE DELETE ON provisioning_transmissions
BEGIN
  SELECT RAISE(ABORT, 'journal_append_only');
END;

-- ---------------------------------------------------------------------------
-- provisioning_transmission_outcomes: what Web learned about a transmission.
-- At most one `uncertain` mark (timeout, network error, invalid or
-- indeterminate answer, or lease recovery after a crash) and at most one
-- `answered` record (§12.4 operation or refusal). An answer is final; a late
-- answer after an uncertain mark is allowed (more information), never the
-- reverse. A transmission with no answer is uncertain for resolution
-- whatever rows exist (§13.2). Insert-only.
-- ---------------------------------------------------------------------------
CREATE TABLE provisioning_transmission_outcomes (
  command_id       TEXT    NOT NULL REFERENCES provisioning_transmissions (command_id) ON DELETE RESTRICT,
  disposition      TEXT    NOT NULL CHECK (disposition IN ('uncertain', 'answered')),
  outcome_kind     TEXT             CHECK (outcome_kind IS NULL OR outcome_kind IN ('operation', 'refused')),
  -- §11 refusal code (registry-validated by the Worker before insert).
  refusal_code     TEXT             CHECK (refusal_code IS NULL OR (length(refusal_code) BETWEEN 1 AND 64 AND refusal_code NOT GLOB '*[^A-Z0-9_]*')),
  -- Why the transmission is uncertain: TIMEOUT, NETWORK_ERROR, RESPONSE_INVALID, LEASE_EXPIRED, or an indeterminate code.
  uncertain_reason TEXT             CHECK (uncertain_reason IS NULL OR (length(uncertain_reason) BETWEEN 1 AND 64 AND uncertain_reason NOT GLOB '*[^A-Z0-9_]*')),
  operation_id     TEXT             CHECK (operation_id IS NULL OR (length(operation_id) = 32 AND operation_id NOT GLOB '*[^0-9a-f]*')),
  operation_state  TEXT             CHECK (operation_state IS NULL OR operation_state IN ('pending', 'profile_created', 'completed', 'failed', 'revoked')),
  failure_code     TEXT             CHECK (failure_code IS NULL OR (length(failure_code) BETWEEN 1 AND 64 AND failure_code NOT GLOB '*[^A-Z0-9_]*')),
  owner_bound      INTEGER          CHECK (owner_bound IS NULL OR owner_bound IN (0, 1)),
  principal_id     TEXT             CHECK (principal_id IS NULL OR (length(principal_id) BETWEEN 1 AND 64 AND principal_id NOT GLOB '*[^a-z0-9_-]*')),
  recorded_by      TEXT    NOT NULL CHECK (length(recorded_by) BETWEEN 1 AND 64 AND recorded_by NOT GLOB '*[^a-z0-9._:-]*'),
  recorded_at      INTEGER NOT NULL CHECK (recorded_at > 1000000000000),
  PRIMARY KEY (command_id, disposition),
  CHECK ((disposition = 'uncertain') = (uncertain_reason IS NOT NULL)),
  CHECK ((disposition = 'answered') = (outcome_kind IS NOT NULL)),
  CHECK ((outcome_kind = 'refused') = (refusal_code IS NOT NULL)),
  CHECK ((outcome_kind = 'operation') = (operation_id IS NOT NULL)),
  CHECK ((operation_id IS NULL) = (operation_state IS NULL) AND (operation_id IS NULL) = (owner_bound IS NULL) AND (operation_id IS NULL) = (principal_id IS NULL)),
  CHECK ((operation_state IS 'failed') = (failure_code IS NOT NULL))
) STRICT;

CREATE TRIGGER provisioning_outcomes_answer_final
BEFORE INSERT ON provisioning_transmission_outcomes
WHEN NEW.disposition = 'uncertain'
  AND EXISTS (SELECT 1 FROM provisioning_transmission_outcomes WHERE command_id = NEW.command_id AND disposition = 'answered')
BEGIN
  SELECT RAISE(ABORT, 'journal_answer_final');
END;

-- Consistency of an operation answer with what was sent (§12.2, §12.4): a
-- create answer is terminal; a revoke answer is `revoked`; status and revoke
-- answers name the operation they addressed.
CREATE TRIGGER provisioning_outcomes_consistent
BEFORE INSERT ON provisioning_transmission_outcomes
WHEN NEW.outcome_kind = 'operation' AND NOT EXISTS (
  SELECT 1 FROM provisioning_transmissions t
  WHERE t.command_id = NEW.command_id AND (
       (t.operation = 'profile.create' AND NEW.operation_state IN ('completed', 'failed', 'revoked'))
    OR (t.operation = 'profile.status' AND NEW.operation_id = t.target_operation_id)
    OR (t.operation = 'profile.revoke' AND NEW.operation_id = t.target_operation_id AND NEW.operation_state = 'revoked')))
BEGIN
  SELECT RAISE(ABORT, 'outcome_inconsistent');
END;

CREATE TRIGGER provisioning_outcomes_append_only_update
BEFORE UPDATE ON provisioning_transmission_outcomes
BEGIN
  SELECT RAISE(ABORT, 'journal_append_only');
END;

CREATE TRIGGER provisioning_outcomes_append_only_delete
BEFORE DELETE ON provisioning_transmission_outcomes
BEGIN
  SELECT RAISE(ABORT, 'journal_append_only');
END;
