/**
 * Authoritative rate-limit counters: one SQLite-backed Durable Object per
 * counter key (policy + subject), named by `counterName` in rate-limit.ts.
 *
 * Semantics: an exact rolling window (sliding log). A request at time t is
 * admitted when fewer than `limit` admissions happened in (t - period, t],
 * i.e. fewer than `limit` stored expiries are later than t;
 * so no interval of length `period` ever holds more than `limit`
 * admissions, including across what a fixed window would call a boundary.
 * Refused requests are not recorded, so retrying never extends a lockout,
 * and the table never holds more than `limit` rows.
 *
 * Atomicity: `admit` reads and writes SQLite synchronously, with no await
 * between the count and the insert, and a Durable Object runs one event at
 * a time; concurrent requests for one key are therefore serialized and
 * cannot both take the last slot.
 *
 * Durability: there is no in-memory state; every decision is made from
 * SQLite, so an evicted or restarted object continues with the same counts.
 *
 * Retention: each row is the expiry time of one admission. An admission
 * schedules the cleanup alarm only when none is scheduled (every scheduled
 * alarm is re-armed or ends in a full cleanup, so one per busy period is
 * enough); the alarm removes expired rows, re-arms itself at the latest
 * remaining expiry, and once none remain deletes the object's storage
 * entirely. An early or repeated alarm only ever removes expired rows, and
 * a lost alarm is re-armed by the next admission. Admission decisions never
 * depend on the alarm: `admitAt` removes expired rows itself.
 *
 * Cost (billed per row written; `setAlarm` counts as one): an admission is
 * one INSERT plus, later, one DELETE; a refusal writes nothing; alarms add
 * about one `setAlarm` per period while a counter is busy.
 *
 * Privacy: the object stores expiry times only. Its name is an HMAC of the
 * subject (see rate-limit.ts), never an address or user id.
 */
import { DurableObject } from "cloudflare:workers";

export interface Admission {
  allowed: boolean;
  /** Seconds until a slot frees up (0 when allowed). */
  retryAfterSeconds: number;
}

/** Bounds on what a caller may ask for; a bad argument is a bug, not a decision. */
const MAX_LIMIT = 1000;
const MAX_PERIOD_SECONDS = 3600;

const SCHEMA = "CREATE TABLE IF NOT EXISTS admissions (expires_at INTEGER NOT NULL)";

/**
 * The admission decision against `sql` at time `now` (ms). Exported so tests
 * can drive it with a fixed clock against real Durable Object storage.
 */
export function admitAt(sql: SqlStorage, limit: number, periodSeconds: number, now: number): Admission {
  sql.exec(SCHEMA);
  sql.exec("DELETE FROM admissions WHERE expires_at <= ?", now);
  const row = sql.exec<{ n: number; next: number | null }>("SELECT COUNT(*) AS n, MIN(expires_at) AS next FROM admissions").one();
  if (row.n >= limit) {
    const freesAt = row.next ?? now;
    return { allowed: false, retryAfterSeconds: Math.min(periodSeconds, Math.max(1, Math.ceil((freesAt - now) / 1000))) };
  }
  sql.exec("INSERT INTO admissions (expires_at) VALUES (?)", now + periodSeconds * 1000);
  return { allowed: true, retryAfterSeconds: 0 };
}

/** The storage an admission and its cleanup use (a Durable Object's own storage). */
export type CounterStorage = Pick<DurableObjectStorage, "sql" | "getAlarm" | "setAlarm" | "deleteAll">;

/**
 * One admission decision at time `now` (ms), and the cleanup alarm if none
 * is scheduled. Exported so tests can drive it with a fixed clock.
 */
export async function admitAndSchedule(storage: CounterStorage, limit: number, periodSeconds: number, now: number): Promise<Admission> {
  const decision = admitAt(storage.sql, limit, periodSeconds, now);
  if (decision.allowed && (await storage.getAlarm()) === null) await storage.setAlarm(now + periodSeconds * 1000);
  return decision;
}

/**
 * The alarm's work at time `now` (ms): remove expired admissions; re-arm at
 * the latest remaining expiry, or with none left drop the object's storage.
 */
export async function cleanupAt(storage: CounterStorage, now: number): Promise<void> {
  storage.sql.exec(SCHEMA);
  storage.sql.exec("DELETE FROM admissions WHERE expires_at <= ?", now);
  const latest = storage.sql.exec<{ latest: number | null }>("SELECT MAX(expires_at) AS latest FROM admissions").one().latest;
  if (latest === null) await storage.deleteAll();
  else await storage.setAlarm(latest);
}

export class AuthRateLimiter extends DurableObject<Env> {
  /** One admission decision for this counter. */
  async admit(limit: number, periodSeconds: number): Promise<Admission> {
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) throw new RangeError("invalid limit");
    if (!Number.isInteger(periodSeconds) || periodSeconds < 1 || periodSeconds > MAX_PERIOD_SECONDS) throw new RangeError("invalid period");
    return admitAndSchedule(this.ctx.storage, limit, periodSeconds, Date.now());
  }

  /** Remove expired admissions; re-arm, or with none left drop the object's storage. */
  override async alarm(): Promise<void> {
    await cleanupAt(this.ctx.storage, Date.now());
  }
}
