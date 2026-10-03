/**
 * Application user profiles. `authUserId` is the auth system's opaque id.
 *
 * The id used here always comes from the server-side session (Phase 4); no
 * method takes a user id from request input.
 */
import { z } from "../../shared/zod";
import { randomId } from "../utils/random";
import { type Clock, NameSchema, parseRow, type RepositoryOptions, systemClock, Timestamp, idSchema } from "./common";
import { guard, InvalidTransitionError, NotFoundError } from "./errors";

export const USER_STATUSES = ["pending", "active", "suspended", "disabled"] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

/** Allowed status changes; mirrored by the user_profiles_status_transition trigger. */
export const USER_TRANSITIONS: Readonly<Record<UserStatus, readonly UserStatus[]>> = {
  pending: ["active", "disabled"],
  active: ["suspended", "disabled"],
  suspended: ["active", "disabled"],
  disabled: [],
};

const UserRow = z.object({
  id: idSchema("usr"),
  auth_user_id: z.string().min(1).max(255),
  display_name: z.string().max(80).nullable(),
  status: z.enum(USER_STATUSES),
  created_at: Timestamp,
  updated_at: Timestamp,
});

export interface UserProfile {
  id: string;
  authUserId: string;
  displayName: string | null;
  status: UserStatus;
  createdAt: number;
  updatedAt: number;
}

function toUser(row: unknown): UserProfile {
  const r = parseRow(UserRow, row);
  return {
    id: r.id,
    authUserId: r.auth_user_id,
    displayName: r.display_name,
    status: r.status,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

const AuthUserId = z.string().min(1).max(255);

export class UserRepository {
  private readonly now: Clock;

  constructor(
    private readonly db: D1Database,
    options: RepositoryOptions = {},
  ) {
    this.now = options.now ?? systemClock;
  }

  /** Create the application profile for a newly authenticated identity. */
  async create(input: { authUserId: string; displayName?: string | null }): Promise<UserProfile> {
    const authUserId = AuthUserId.parse(input.authUserId);
    const displayName = input.displayName == null ? null : NameSchema.parse(input.displayName);
    const now = this.now();
    const row = await guard(() =>
      this.db
        .prepare(
          `INSERT INTO user_profiles (id, auth_user_id, display_name, status, created_at, updated_at)
           VALUES (?1, ?2, ?3, 'pending', ?4, ?4) RETURNING *`,
        )
        .bind(randomId("usr"), authUserId, displayName, now)
        .first(),
    );
    return toUser(row);
  }

  async getById(userId: string): Promise<UserProfile | null> {
    const row = await guard(() => this.db.prepare(`SELECT * FROM user_profiles WHERE id = ?1`).bind(userId).first());
    return row ? toUser(row) : null;
  }

  async getByAuthUserId(authUserId: string): Promise<UserProfile | null> {
    const row = await guard(() =>
      this.db.prepare(`SELECT * FROM user_profiles WHERE auth_user_id = ?1`).bind(authUserId).first(),
    );
    return row ? toUser(row) : null;
  }

  /** Change the caller's own display name (`userId` from the session). */
  async updateDisplayName(userId: string, displayName: string | null): Promise<UserProfile> {
    const name = displayName === null ? null : NameSchema.parse(displayName);
    const row = await guard(() =>
      this.db
        .prepare(`UPDATE user_profiles SET display_name = ?1, updated_at = ?2 WHERE id = ?3 RETURNING *`)
        .bind(name, this.now(), userId)
        .first(),
    );
    if (!row) throw new NotFoundError("user");
    return toUser(row);
  }

  /** Move a user to `to` if the current status allows it (atomic). */
  async transition(userId: string, to: UserStatus): Promise<UserProfile> {
    const from = (Object.keys(USER_TRANSITIONS) as UserStatus[]).filter((s) => USER_TRANSITIONS[s].includes(to));
    const row = await guard(() =>
      this.db
        .prepare(
          `UPDATE user_profiles SET status = ?1, updated_at = ?2
           WHERE id = ?3 AND status IN (SELECT value FROM json_each(?4)) RETURNING *`,
        )
        .bind(to, this.now(), userId, JSON.stringify(from))
        .first(),
    );
    if (row) return toUser(row);
    const current = await this.getById(userId);
    if (!current) throw new NotFoundError("user");
    throw new InvalidTransitionError("user", current.status, to);
  }
}
