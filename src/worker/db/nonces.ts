/**
 * Provisioning nonce registry. Only SHA-256 hashes are stored. Recording a
 * nonce that already exists throws NonceReplayError, so a nonce can be
 * issued (or accepted) at most once while its record is retained.
 *
 * Retention: rows are needed only until expires_at (command validity plus
 * clock-skew margin). `purgeExpired` deletes older rows in bounded batches;
 * scheduling it (Cron Trigger) is deferred until provisioning ships.
 */
import { sha256Hex } from "../utils/crypto";
import { type Clock, type RepositoryOptions, systemClock } from "./common";
import { guard, mapD1Error, NonceReplayError, UniqueConflictError } from "./errors";

export const MAX_NONCE_TTL_MS = 10 * 60 * 1000;

export function hashNonce(nonce: string): Promise<string> {
  return sha256Hex(`nonce:v1:${nonce}`);
}

export class NonceRepository {
  private readonly now: Clock;

  constructor(
    private readonly db: D1Database,
    options: RepositoryOptions = {},
  ) {
    this.now = options.now ?? systemClock;
  }

  /** Record a nonce once. Throws NonceReplayError if it was seen before. */
  async recordOnce(nonce: string, expiresAt: number): Promise<void> {
    const now = this.now();
    if (!(expiresAt > now) || expiresAt - now > MAX_NONCE_TTL_MS) {
      throw new RangeError("nonce expiry must be in the future and within MAX_NONCE_TTL_MS");
    }
    const nonceHash = await hashNonce(nonce);
    try {
      await this.db
        .prepare(`INSERT INTO provisioning_nonces (nonce_hash, created_at, expires_at) VALUES (?1, ?2, ?3)`)
        .bind(nonceHash, now, expiresAt)
        .run();
    } catch (error) {
      const mapped = mapD1Error(error);
      throw mapped instanceof UniqueConflictError ? new NonceReplayError() : mapped;
    }
  }

  async isRecorded(nonce: string): Promise<boolean> {
    const nonceHash = await hashNonce(nonce);
    const row = await guard(() =>
      this.db.prepare(`SELECT 1 AS present FROM provisioning_nonces WHERE nonce_hash = ?1`).bind(nonceHash).first(),
    );
    return row !== null;
  }

  /** Delete up to `batchSize` expired records; returns how many were removed. */
  async purgeExpired(batchSize = 500): Promise<number> {
    const result = await guard(() =>
      this.db
        .prepare(
          `DELETE FROM provisioning_nonces WHERE nonce_hash IN (
             SELECT nonce_hash FROM provisioning_nonces WHERE expires_at < ?1 ORDER BY expires_at LIMIT ?2)`,
        )
        .bind(this.now(), Math.min(Math.max(batchSize, 1), 5000))
        .run(),
    );
    return result.meta.changes;
  }
}
