/**
 * Maintenance of Better Auth's `verification` table (OAuth state, passkey
 * challenges). Better Auth deletes a row when it is consumed; rows from
 * abandoned flows stay until something removes them. Expired rows are
 * useless (Better Auth rejects them) but accumulate.
 *
 * `deleteExpired` is the cleanup primitive: bounded, expiry-based, and it
 * never touches an unexpired row. Scheduling it is deferred; operators run
 * it with `npm run operator -- purge-verifications`.
 */
import { guard } from "./errors";

export const MAX_PURGE_BATCH = 500;

export class VerificationRepository {
  constructor(private readonly db: D1Database) {}

  /**
   * Delete at most `limit` rows whose expiry is before `now`; returns how
   * many were deleted. Better Auth stores `expiresAt` as ISO-8601 text, so
   * only text values are compared: a row in any other format is never
   * treated as expired.
   */
  async deleteExpired(now: Date, limit = 100): Promise<number> {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), MAX_PURGE_BATCH);
    const { results } = await guard(() =>
      this.db
        .prepare(
          `DELETE FROM verification WHERE id IN (
             SELECT id FROM verification
             WHERE typeof("expiresAt") = 'text' AND "expiresAt" < ?1
             ORDER BY "expiresAt" LIMIT ?2
           ) RETURNING id`,
        )
        .bind(now.toISOString(), bounded)
        .all(),
    );
    return results.length;
  }

  /** How many rows are expired as of `now` (for reporting). */
  async countExpired(now: Date): Promise<number> {
    const row = await guard(() =>
      this.db
        .prepare(`SELECT COUNT(*) AS n FROM verification WHERE typeof("expiresAt") = 'text' AND "expiresAt" < ?1`)
        .bind(now.toISOString())
        .first<{ n: number }>(),
    );
    return row?.n ?? 0;
  }
}
