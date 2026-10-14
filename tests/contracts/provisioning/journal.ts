/**
 * RC6 reference transmission journal (TEST-ONLY). It shows the protocol-level
 * D1 constraints of PROVISIONING_PROTOCOL §13.10 running on real D1 in workerd.
 *
 * Tables are prefixed `l0_ref_` and created inside one test file's isolated
 * storage. This is not a migration: the eventual schema is an additive
 * migration 0003 or later, reviewed separately. It builds on the existing
 * `provisioning_jobs` row (one delivery row per job, FK to it).
 */
import { sha256Hex, toBase64Url, type Transmission, utf8 } from "./reference";

export const JOURNAL_DDL = [
  `CREATE TABLE IF NOT EXISTS l0_ref_delivery (
     job_id       TEXT    NOT NULL PRIMARY KEY REFERENCES provisioning_jobs (id) ON DELETE RESTRICT,
     payload_json TEXT    NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 8192),
     payload_hash TEXT    NOT NULL CHECK (length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
     desired      TEXT    NOT NULL CHECK (desired IN ('present', 'absent')),
     next_seq     INTEGER NOT NULL DEFAULT 1 CHECK (next_seq >= 1),
     lease_token  TEXT,
     lease_until  INTEGER,
     CHECK ((lease_token IS NULL) = (lease_until IS NULL))
   ) STRICT`,
  `CREATE TABLE IF NOT EXISTS l0_ref_transmissions (
     command_id      TEXT    NOT NULL PRIMARY KEY CHECK (command_id GLOB 'cmd_[a-z0-9]*' AND length(command_id) BETWEEN 12 AND 64),
     job_id          TEXT    NOT NULL REFERENCES l0_ref_delivery (job_id) ON DELETE RESTRICT,
     seq             INTEGER NOT NULL CHECK (seq >= 1),
     harness_id      TEXT    NOT NULL,
     operation       TEXT    NOT NULL CHECK (operation IN ('profile.create', 'profile.status', 'profile.revoke')),
     payload_hash    TEXT    NOT NULL,
     key_id          TEXT    NOT NULL,
     nonce_hash      TEXT    NOT NULL UNIQUE CHECK (length(nonce_hash) = 64),
     issued_at       INTEGER NOT NULL,
     expires_at      INTEGER NOT NULL,
     lease_token     TEXT    NOT NULL,
     state           TEXT    NOT NULL CHECK (state IN ('journaled', 'answered', 'uncertain')),
     outcome_kind    TEXT    CHECK (outcome_kind IN ('operation', 'refused')),
     outcome_code    TEXT    CHECK (outcome_code IS NULL OR outcome_code NOT GLOB '*[^A-Z0-9_]*'),
     operation_id    TEXT    CHECK (operation_id IS NULL OR (length(operation_id) = 32 AND operation_id NOT GLOB '*[^0-9a-f]*')),
     operation_state TEXT,
     UNIQUE (job_id, seq),
     CHECK (expires_at > issued_at AND expires_at - issued_at <= 120),
     CHECK ((state = 'answered') = (outcome_kind IS NOT NULL))
   ) STRICT`,
  // The logical command is fixed: every transmission carries the job's payload hash.
  `CREATE TRIGGER IF NOT EXISTS l0_ref_transmissions_payload
   BEFORE INSERT ON l0_ref_transmissions
   WHEN NEW.payload_hash IS NOT (SELECT payload_hash FROM l0_ref_delivery WHERE job_id = NEW.job_id)
   BEGIN SELECT RAISE(ABORT, 'payload_mismatch'); END`,
  // A recorded answer is final; identity columns never change.
  `CREATE TRIGGER IF NOT EXISTS l0_ref_transmissions_final
   BEFORE UPDATE ON l0_ref_transmissions
   WHEN OLD.state = 'answered'
     OR NEW.command_id IS NOT OLD.command_id OR NEW.job_id IS NOT OLD.job_id OR NEW.seq IS NOT OLD.seq
     OR NEW.payload_hash IS NOT OLD.payload_hash OR NEW.nonce_hash IS NOT OLD.nonce_hash
     OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
     OR (OLD.state = 'uncertain' AND NEW.state = 'journaled')
   BEGIN SELECT RAISE(ABORT, 'journal_immutable'); END`,
  // The journal is append-only: a row that may describe a sent command is never removed.
  `CREATE TRIGGER IF NOT EXISTS l0_ref_transmissions_append_only
   BEFORE DELETE ON l0_ref_transmissions
   BEGIN SELECT RAISE(ABORT, 'journal_append_only'); END`,
] as const;

const JOURNAL_DROP = [
  `DROP TABLE IF EXISTS l0_ref_transmissions`,
  `DROP TABLE IF EXISTS l0_ref_delivery`,
] as const;

export interface JournaledTransmission {
  commandId: string;
  seq: number;
  /** Plaintext nonce: held only in the sending Worker's memory, never stored. */
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  leaseToken: string;
}

export type RecordedOutcome =
  | { kind: "operation"; operationId: string; state: string }
  | { kind: "refused"; code: string };

const randomToken = (bytes = 16) => toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
const randomCommandId = () => `cmd_${Array.from(crypto.getRandomValues(new Uint8Array(26)), (b) => "0123456789abcdefghijklmnopqrstuvwxyz"[b % 36]).join("")}`;

export class ReferenceJournal {
  constructor(private readonly db: D1Database) {}

  async install(): Promise<void> {
    await this.db.batch(JOURNAL_DDL.map((sql) => this.db.prepare(sql)));
  }

  async uninstall(): Promise<void> {
    await this.db.batch(JOURNAL_DROP.map((sql) => this.db.prepare(sql)));
  }

  /** Step 2–3: persist the fixed logical command and the desired state with the job. */
  async open(jobId: string, payloadJson: string, desired: "present" | "absent"): Promise<string> {
    const payloadHash = await sha256Hex(utf8(payloadJson));
    await this.db
      .prepare(`INSERT INTO l0_ref_delivery (job_id, payload_json, payload_hash, desired) VALUES (?1, ?2, ?3, ?4)`)
      .bind(jobId, payloadJson, payloadHash, desired)
      .run();
    return payloadHash;
  }

  async setDesired(jobId: string, desired: "present" | "absent"): Promise<void> {
    await this.db.prepare(`UPDATE l0_ref_delivery SET desired = ?2 WHERE job_id = ?1`).bind(jobId, desired).run();
  }

  /**
   * Steps 4–5: claim the job's delivery lease and journal one transmission in
   * ONE D1 batch (a transaction). Returns null if another Worker holds the
   * lease. Only a non-null result may be signed and sent (step 6).
   */
  async journal(
    jobId: string,
    options: { now: number; leaseSeconds: number; harnessId: string; keyId: string; operation?: string; lifetime?: number; payloadHash?: string },
  ): Promise<JournaledTransmission | null> {
    const leaseToken = randomToken();
    const nonce = randomToken(32);
    const commandId = randomCommandId();
    const issuedAt = options.now;
    const expiresAt = options.now + (options.lifetime ?? 60);
    const nonceHash = await sha256Hex(utf8(`nonce:v1:${nonce}`));
    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE l0_ref_delivery SET lease_token = ?2, lease_until = ?3, next_seq = next_seq + 1
           WHERE job_id = ?1 AND (lease_until IS NULL OR lease_until <= ?4)`,
        )
        .bind(jobId, leaseToken, options.now + options.leaseSeconds, options.now),
      this.db
        .prepare(
          `INSERT INTO l0_ref_transmissions
             (command_id, job_id, seq, harness_id, operation, payload_hash, key_id, nonce_hash, issued_at, expires_at, lease_token, state)
           SELECT ?1, job_id, next_seq - 1, ?2, ?3, COALESCE(?4, payload_hash), ?5, ?6, ?7, ?8, lease_token, 'journaled'
           FROM l0_ref_delivery WHERE job_id = ?9 AND lease_token = ?10`,
        )
        .bind(commandId, options.harnessId, options.operation ?? "profile.create", options.payloadHash ?? null, options.keyId, nonceHash, issuedAt, expiresAt, jobId, leaseToken),
    ]);
    if ((results[1]?.meta.changes ?? 0) !== 1) return null;
    const row = await this.db.prepare(`SELECT seq FROM l0_ref_transmissions WHERE command_id = ?1`).bind(commandId).first<{ seq: number }>();
    return { commandId, seq: row?.seq ?? 0, nonce, issuedAt, expiresAt, leaseToken };
  }

  /** Step 7: record the observed answer and release the lease, atomically. */
  async recordAnswer(t: JournaledTransmission, outcome: RecordedOutcome): Promise<boolean> {
    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE l0_ref_transmissions
           SET state = 'answered', outcome_kind = ?2, outcome_code = ?3, operation_id = ?4, operation_state = ?5
           WHERE command_id = ?1 AND state IN ('journaled', 'uncertain')`,
        )
        .bind(
          t.commandId,
          outcome.kind,
          outcome.kind === "refused" ? outcome.code : null,
          outcome.kind === "operation" ? outcome.operationId : null,
          outcome.kind === "operation" ? outcome.state : null,
        ),
      this.db
        .prepare(`UPDATE l0_ref_delivery SET lease_token = NULL, lease_until = NULL WHERE lease_token = ?1`)
        .bind(t.leaseToken),
    ]);
    return (results[0]?.meta.changes ?? 0) === 1;
  }

  /** Step 7, uncertain branch: timeout, network error, invalid or indeterminate answer. */
  async markUncertain(t: JournaledTransmission): Promise<void> {
    await this.db.batch([
      this.db.prepare(`UPDATE l0_ref_transmissions SET state = 'uncertain' WHERE command_id = ?1 AND state = 'journaled'`).bind(t.commandId),
      this.db.prepare(`UPDATE l0_ref_delivery SET lease_token = NULL, lease_until = NULL WHERE lease_token = ?1`).bind(t.leaseToken),
    ]);
  }

  /** Lease recovery after a Worker died: its journaled rows become uncertain, never refused. */
  async recoverExpiredLeases(now: number): Promise<number> {
    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE l0_ref_transmissions SET state = 'uncertain'
           WHERE state = 'journaled' AND lease_token IN (SELECT lease_token FROM l0_ref_delivery WHERE lease_until <= ?1)`,
        )
        .bind(now),
      this.db.prepare(`UPDATE l0_ref_delivery SET lease_token = NULL, lease_until = NULL WHERE lease_until <= ?1`).bind(now),
    ]);
    return results[0]?.meta.changes ?? 0;
  }

  /** Step 8 input: every journaled transmission, in order. Journaled and uncertain rows are uncertain. */
  async transmissions(jobId: string): Promise<Transmission[]> {
    const { results } = await this.db
      .prepare(
        `SELECT state, issued_at, expires_at, outcome_kind, outcome_code, operation_id, operation_state
         FROM l0_ref_transmissions WHERE job_id = ?1 ORDER BY seq`,
      )
      .bind(jobId)
      .all<{
        state: string; issued_at: number; expires_at: number; outcome_kind: string | null; outcome_code: string | null;
        operation_id: string | null; operation_state: string | null;
      }>();
    return results.map((r) => ({
      issuedAt: r.issued_at,
      expiresAt: r.expires_at,
      outcome:
        r.state !== "answered"
          ? { kind: "uncertain" as const }
          : r.outcome_kind === "operation"
            ? { kind: "operation" as const, operationId: r.operation_id as string, state: r.operation_state as never }
            : { kind: "refused" as const, code: r.outcome_code as string },
    }));
  }

  async rows(jobId: string): Promise<Array<{ seq: number; state: string; payload_hash: string; command_id: string }>> {
    const { results } = await this.db
      .prepare(`SELECT seq, state, payload_hash, command_id FROM l0_ref_transmissions WHERE job_id = ?1 ORDER BY seq`)
      .bind(jobId)
      .all<{ seq: number; state: string; payload_hash: string; command_id: string }>();
    return results;
  }
}
