/**
 * Agent profiles.
 *
 * Two entry points, deliberately separate:
 *
 * - `forUser(userId)` returns an OwnedAgentProfiles bound to one owner. Every
 *   query it runs includes `user_id = ?`, so a profile id belonging to
 *   someone else behaves exactly like an id that does not exist (null), with
 *   no way to forget the ownership check. User-facing routes use only this.
 * - The `*Trusted` methods on AgentProfileRepository act on any profile by id.
 *   They exist for internal provisioning and admin code that has already
 *   established authority, and are named so that use stands out in review.
 *
 * Status changes are atomic conditional UPDATEs checked against
 * PROFILE_TRANSITIONS (and again by a database trigger). Transitions to
 * `suspended` or `revoked` increment revocation_version in the same statement.
 */
import { z } from "../../shared/zod";
import { randomId } from "../utils/random";
import { type Clock, NameSchema, NullableTimestamp, parseRow, type RepositoryOptions, systemClock, Timestamp, idSchema } from "./common";
import { guard, InvalidTransitionError, NotFoundError } from "./errors";
import { AgentPermissionsSchema, decodeJson, DEFAULT_AGENT_PERMISSIONS, encodeJson, JSON_LIMITS, type AgentPermissions } from "./json";

export const PROFILE_STATUSES = ["pending", "provisioning", "active", "failed", "suspended", "revoked"] as const;
export type ProfileStatus = (typeof PROFILE_STATUSES)[number];

/** Allowed status changes; mirrored by the agent_profiles_status_transition trigger. */
export const PROFILE_TRANSITIONS: Readonly<Record<ProfileStatus, readonly ProfileStatus[]>> = {
  pending: ["provisioning", "revoked"],
  // → revoked: desired state became absent while a create is unresolved (migration 0003, §13.5).
  provisioning: ["active", "failed", "revoked"],
  failed: ["provisioning", "revoked"],
  active: ["suspended", "revoked"],
  suspended: ["active", "revoked"],
  revoked: [],
};

/** Entering these states invalidates previously signed commands. */
export const REVOKING_STATUSES: readonly ProfileStatus[] = ["suspended", "revoked"];

/** The revocation_version every profile starts with. */
export const INITIAL_REVOCATION_VERSION = 1;

/** Per-user cap on profiles that are not revoked (also enforced by the service). */
export const MAX_PROFILES_PER_USER = 10;

const ProfileRow = z.object({
  id: idSchema("agt"),
  user_id: idSchema("usr"),
  agent_name: z.string().min(1).max(80),
  status: z.enum(PROFILE_STATUSES),
  harness_id: idSchema("hns").nullable(),
  revocation_version: z.number().int().min(INITIAL_REVOCATION_VERSION),
  permissions_json: z.string(),
  created_at: Timestamp,
  updated_at: Timestamp,
  last_seen_at: NullableTimestamp,
});

export interface AgentProfile {
  id: string;
  userId: string;
  agentName: string;
  status: ProfileStatus;
  harnessId: string | null;
  revocationVersion: number;
  permissions: AgentPermissions;
  createdAt: number;
  updatedAt: number;
  lastSeenAt: number | null;
}

function toProfile(row: unknown): AgentProfile {
  const r = parseRow(ProfileRow, row);
  return {
    id: r.id,
    userId: r.user_id,
    agentName: r.agent_name,
    status: r.status,
    harnessId: r.harness_id,
    revocationVersion: r.revocation_version,
    permissions: decodeJson(AgentPermissionsSchema, r.permissions_json),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    lastSeenAt: r.last_seen_at,
  };
}

function sourcesFor(to: ProfileStatus): ProfileStatus[] {
  return PROFILE_STATUSES.filter((from) => PROFILE_TRANSITIONS[from].includes(to));
}

/**
 * One conditional UPDATE: applies only if the row exists, matches the owner
 * filter (when given), and is in a status allowed to move to `to`.
 */
const TRANSITION_SQL = `
  UPDATE agent_profiles
     SET status = ?1,
         updated_at = ?2,
         revocation_version = revocation_version + (CASE WHEN ?1 IN ('suspended', 'revoked') THEN 1 ELSE 0 END),
         harness_id = COALESCE(?3, harness_id)
   WHERE id = ?4
     AND status IN (SELECT value FROM json_each(?5))
     AND (?6 IS NULL OR user_id = ?6)
  RETURNING *`;

export class AgentProfileRepository {
  private readonly now: Clock;

  constructor(
    private readonly db: D1Database,
    options: RepositoryOptions = {},
  ) {
    this.now = options.now ?? systemClock;
  }

  /** Repository scoped to one owner. `userId` must come from the session. */
  forUser(userId: string): OwnedAgentProfiles {
    return new OwnedAgentProfiles(this.db, userId, this.now, this);
  }

  /** Internal/admin only: fetch any profile by id, without an ownership check. */
  async getByIdTrusted(profileId: string): Promise<AgentProfile | null> {
    const row = await guard(() => this.db.prepare(`SELECT * FROM agent_profiles WHERE id = ?1`).bind(profileId).first());
    return row ? toProfile(row) : null;
  }

  /**
   * Internal/admin only: move a profile to `to`. `harnessId` is required when
   * entering `provisioning` without an assigned harness.
   */
  async transitionTrusted(profileId: string, to: ProfileStatus, options: { harnessId?: string } = {}): Promise<AgentProfile> {
    return this.applyTransition(profileId, to, null, options.harnessId ?? null);
  }

  /** @internal Shared by the owned and trusted paths. */
  async applyTransition(profileId: string, to: ProfileStatus, ownerId: string | null, harnessId: string | null): Promise<AgentProfile> {
    const row = await guard(() =>
      this.db
        .prepare(TRANSITION_SQL)
        .bind(to, this.now(), harnessId, profileId, JSON.stringify(sourcesFor(to)), ownerId)
        .first(),
    );
    if (row) return toProfile(row);
    const current = await guard(() =>
      this.db
        .prepare(`SELECT status FROM agent_profiles WHERE id = ?1 AND (?2 IS NULL OR user_id = ?2)`)
        .bind(profileId, ownerId)
        .first<{ status: string }>(),
    );
    if (!current) throw new NotFoundError("agent_profile");
    throw new InvalidTransitionError("agent_profile", current.status, to);
  }

  /**
   * Atomically increment revocation_version and return the new value. Used
   * for harness moves, permission changes, and security invalidation.
   */
  async incrementRevocationVersionTrusted(profileId: string): Promise<number> {
    const row = await guard(() =>
      this.db
        .prepare(
          `UPDATE agent_profiles SET revocation_version = revocation_version + 1, updated_at = ?1
           WHERE id = ?2 RETURNING revocation_version`,
        )
        .bind(this.now(), profileId)
        .first<{ revocation_version: number }>(),
    );
    if (!row) throw new NotFoundError("agent_profile");
    return row.revocation_version;
  }

  /** Record harness-reported activity. */
  async markSeenTrusted(profileId: string, at: number): Promise<void> {
    await guard(() =>
      this.db
        .prepare(`UPDATE agent_profiles SET last_seen_at = MAX(COALESCE(last_seen_at, 0), ?1) WHERE id = ?2`)
        .bind(at, profileId)
        .run(),
    );
  }
}

/** Agent profiles of exactly one owner. */
export class OwnedAgentProfiles {
  constructor(
    private readonly db: D1Database,
    readonly userId: string,
    private readonly now: Clock,
    private readonly repository: AgentProfileRepository,
  ) {}

  /** Create a `pending` profile with the server-chosen permission ceiling. */
  async create(input: { agentName: string; permissions?: AgentPermissions }): Promise<AgentProfile> {
    const agentName = NameSchema.parse(input.agentName);
    const permissions = encodeJson(AgentPermissionsSchema, input.permissions ?? DEFAULT_AGENT_PERMISSIONS, JSON_LIMITS.permissions);
    const now = this.now();
    const row = await guard(() =>
      this.db
        .prepare(
          `INSERT INTO agent_profiles (id, user_id, agent_name, status, revocation_version, permissions_json, created_at, updated_at)
           VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?6) RETURNING *`,
        )
        .bind(randomId("agt"), this.userId, agentName, INITIAL_REVOCATION_VERSION, permissions, now)
        .first(),
    );
    return toProfile(row);
  }

  /** The profile if it exists AND belongs to this owner; otherwise null. */
  async get(profileId: string): Promise<AgentProfile | null> {
    const row = await guard(() =>
      this.db.prepare(`SELECT * FROM agent_profiles WHERE id = ?1 AND user_id = ?2`).bind(profileId, this.userId).first(),
    );
    return row ? toProfile(row) : null;
  }

  async list(options: { includeRevoked?: boolean; limit?: number } = {}): Promise<AgentProfile[]> {
    const limit = Math.min(Math.max(options.limit ?? 50, 1), 100);
    const { results } = await guard(() =>
      this.db
        .prepare(
          `SELECT * FROM agent_profiles WHERE user_id = ?1 AND (?2 = 1 OR status <> 'revoked')
           ORDER BY created_at DESC, id LIMIT ?3`,
        )
        .bind(this.userId, options.includeRevoked ? 1 : 0, limit)
        .all(),
    );
    return results.map(toProfile);
  }

  /** Profiles that count toward MAX_PROFILES_PER_USER. */
  async countLive(): Promise<number> {
    const row = await guard(() =>
      this.db
        .prepare(`SELECT COUNT(*) AS n FROM agent_profiles WHERE user_id = ?1 AND status <> 'revoked'`)
        .bind(this.userId)
        .first<{ n: number }>(),
    );
    return row?.n ?? 0;
  }

  /** Rename an owned, non-revoked profile. Null if not found or not owned. */
  async rename(profileId: string, agentName: string): Promise<AgentProfile | null> {
    const name = NameSchema.parse(agentName);
    const row = await guard(() =>
      this.db
        .prepare(
          `UPDATE agent_profiles SET agent_name = ?1, updated_at = ?2
           WHERE id = ?3 AND user_id = ?4 AND status <> 'revoked' RETURNING *`,
        )
        .bind(name, this.now(), profileId, this.userId)
        .first(),
    );
    return row ? toProfile(row) : null;
  }

  /**
   * Revoke an owned profile (pending, failed, active, or suspended). Bumps
   * revocation_version. NotFoundError if missing or not owned.
   */
  async revoke(profileId: string): Promise<AgentProfile> {
    return this.repository.applyTransition(profileId, "revoked", this.userId, null);
  }
}
