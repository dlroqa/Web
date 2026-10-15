/**
 * The one boundary between authentication (Better Auth) and the application
 * identity (user_profiles).
 *
 *   Better Auth user id ──► user_profiles.auth_user_id ──► usr_… (ownership, policy)
 *
 * `ensureProfile` is called at session creation and on every authenticated
 * request; it is idempotent and safe under concurrency. The auth user id it
 * receives always comes from Better Auth's server-side session, never from
 * the browser.
 */
import { ACCESS_STATUSES } from "../../shared/access";
import type { SignupPolicy } from "../config/config";
import { UserRepository, type UserProfile, type UserStatus } from "../db/users";
import { enforceRateLimit, type RateLimiter } from "../security/rate-limit";

/** Statuses that may hold a session at all (suspended/disabled may not): the `identity` access level. */
export const SESSION_ALLOWED_STATUSES: readonly UserStatus[] = ACCESS_STATUSES.identity;

/** Maximum stored display name; longer provider names are truncated. */
const DISPLAY_NAME_MAX = 80;

/** Turn a provider-supplied name into a safe display name, or null. */
export function toDisplayName(name: unknown): string | null {
  if (typeof name !== "string") return null;
  const cleaned = name.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (cleaned.length === 0) return null;
  return Array.from(cleaned).slice(0, DISPLAY_NAME_MAX).join("");
}

export interface EnsureProfileResult {
  user: UserProfile;
  created: boolean;
}

export class IdentityService {
  constructor(
    private readonly users: UserRepository,
    private readonly signupPolicy: SignupPolicy,
    private readonly limiter: RateLimiter,
  ) {}

  /**
   * Resolve (or create exactly once) the application profile for an
   * authenticated Better Auth user. `sourceAddress` keys the account
   * initialization rate limit.
   */
  async ensureProfile(authUserId: string, options: { name?: unknown; sourceAddress?: string | null } = {}): Promise<EnsureProfileResult> {
    const existing = await this.users.getByAuthUserId(authUserId);
    if (existing) return { user: existing, created: false };
    // Only creation is rate limited (per source); returning users never are.
    await enforceRateLimit(this.limiter, "signup", { kind: "ip", address: options.sourceAddress ?? null });
    return this.users.createIfAbsent({
      authUserId,
      displayName: toDisplayName(options.name),
      initialStatus: this.signupPolicy === "open" ? "active" : "pending",
    });
  }
}
