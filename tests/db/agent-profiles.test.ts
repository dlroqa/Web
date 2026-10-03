import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import {
  INITIAL_REVOCATION_VERSION,
  PROFILE_STATUSES,
  PROFILE_TRANSITIONS,
  type ProfileStatus,
} from "../../src/worker/db/agent-profiles";
import { ConstraintViolationError, InvalidTransitionError, NotFoundError } from "../../src/worker/db/errors";
import { DEFAULT_AGENT_PERMISSIONS } from "../../src/worker/db/json";
import { randomId } from "../../src/worker/utils/random";
import { db, newHarness, newUser, profiles } from "../helpers/db";

async function twoTenants() {
  const [alice, bob] = await Promise.all([newUser(), newUser()]);
  const bobsProfile = await profiles().forUser(bob.id).create({ agentName: "Bob's agent" });
  return { alice, bob, bobsProfile };
}

describe("creating profiles", () => {
  it("starts pending, unplaced, at the baseline revocation version, least privilege", async () => {
    const user = await newUser();
    const profile = await profiles().forUser(user.id).create({ agentName: "  My Lightagent " });
    expect(profile).toMatchObject({
      userId: user.id,
      agentName: "My Lightagent",
      status: "pending",
      harnessId: null,
      revocationVersion: INITIAL_REVOCATION_VERSION,
      permissions: DEFAULT_AGENT_PERMISSIONS,
    });
    expect(INITIAL_REVOCATION_VERSION).toBe(1);
    expect(profile.id).toMatch(/^agt_[a-z0-9]{26}$/);
    expect(profile.permissions.admin).toBe(false);
    expect(profile.permissions.mcp).toBe(false);
    expect(profile.permissions.shell).toBe(false);
  });

  it("can never be granted admin", async () => {
    const user = await newUser();
    const attempt = profiles().forUser(user.id).create({ agentName: "x", permissions: { ...DEFAULT_AGENT_PERMISSIONS, admin: true as false } });
    await expect(attempt).rejects.toBeInstanceOf(ConstraintViolationError);
  });

  it.each([
    ["empty", ""],
    ["whitespace", "   "],
    ["too long", "x".repeat(81)],
    ["control characters", "bad\u0000name"],
  ])("rejects a %s name", async (_label, name) => {
    const user = await newUser();
    await expect(profiles().forUser(user.id).create({ agentName: name })).rejects.toBeInstanceOf(ZodError);
  });

  it("stores SQL and HTML payloads as inert data", async () => {
    const user = await newUser();
    const owned = profiles().forUser(user.id);
    for (const name of ["'); DROP TABLE agent_profiles; --", "<script>alert(1)</script>", "x' OR '1'='1"]) {
      const profile = await owned.create({ agentName: name });
      expect((await owned.get(profile.id))?.agentName).toBe(name);
    }
    const tables = await db().prepare(`SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'agent_profiles'`).first<{ n: number }>();
    expect(tables?.n).toBe(1);
  });

  it("rejects an oversized name at the database too", async () => {
    const user = await newUser();
    await expect(
      db()
        .prepare(`INSERT INTO agent_profiles (id, user_id, agent_name, permissions_json, created_at, updated_at) VALUES (?1, ?2, ?3, '{}', 1, 1)`)
        .bind(randomId("agt"), user.id, "x".repeat(81))
        .run(),
    ).rejects.toThrow(/CHECK/);
  });
});

describe("cross-tenant isolation (IDOR)", () => {
  it("User A cannot read User B's profile", async () => {
    const { alice, bobsProfile } = await twoTenants();
    expect(await profiles().forUser(alice.id).get(bobsProfile.id)).toBeNull();
  });

  it("another user's id and a nonexistent id look identical", async () => {
    const { alice, bobsProfile } = await twoTenants();
    const owned = profiles().forUser(alice.id);
    expect(await owned.get(bobsProfile.id)).toStrictEqual(await owned.get(randomId("agt")));
    const foreign = await owned.revoke(bobsProfile.id).catch((e: unknown) => e);
    const missing = await owned.revoke(randomId("agt")).catch((e: unknown) => e);
    expect(foreign).toBeInstanceOf(NotFoundError);
    expect(missing).toBeInstanceOf(NotFoundError);
    expect(String(foreign)).toBe(String(missing));
  });

  it("User A cannot rename User B's profile", async () => {
    const { alice, bob, bobsProfile } = await twoTenants();
    expect(await profiles().forUser(alice.id).rename(bobsProfile.id, "pwned")).toBeNull();
    expect((await profiles().forUser(bob.id).get(bobsProfile.id))?.agentName).toBe("Bob's agent");
  });

  it("User A cannot revoke User B's profile", async () => {
    const { alice, bob, bobsProfile } = await twoTenants();
    await expect(profiles().forUser(alice.id).revoke(bobsProfile.id)).rejects.toBeInstanceOf(NotFoundError);
    const after = await profiles().forUser(bob.id).get(bobsProfile.id);
    expect(after?.status).toBe("pending");
    expect(after?.revocationVersion).toBe(1);
  });

  it("User A's list never contains User B's profiles", async () => {
    const { alice, bob, bobsProfile } = await twoTenants();
    await profiles().forUser(alice.id).create({ agentName: "Alice's" });
    const aliceList = await profiles().forUser(alice.id).list({ includeRevoked: true });
    expect(aliceList.every((p) => p.userId === alice.id)).toBe(true);
    expect(aliceList.map((p) => p.id)).not.toContain(bobsProfile.id);
    expect((await profiles().forUser(bob.id).list()).map((p) => p.id)).toEqual([bobsProfile.id]);
  });

  it("ownership cannot be reassigned, even by a raw UPDATE", async () => {
    const { alice, bobsProfile } = await twoTenants();
    await expect(
      db().prepare(`UPDATE agent_profiles SET user_id = ?1 WHERE id = ?2`).bind(alice.id, bobsProfile.id).run(),
    ).rejects.toThrow(/immutable_column/);
  });
});

describe("status transitions", () => {
  async function profileIn(status: ProfileStatus) {
    const user = await newUser();
    const harness = await newHarness();
    const repo = profiles();
    let profile = await repo.forUser(user.id).create({ agentName: "t" });
    const path: Record<ProfileStatus, ProfileStatus[]> = {
      pending: [],
      provisioning: ["provisioning"],
      active: ["provisioning", "active"],
      failed: ["provisioning", "failed"],
      suspended: ["provisioning", "active", "suspended"],
      revoked: ["revoked"],
    };
    for (const step of path[status]) {
      profile = await repo.transitionTrusted(profile.id, step, { harnessId: harness.id });
    }
    return { user, harness, profile };
  }

  const pairs = PROFILE_STATUSES.flatMap((from) => PROFILE_STATUSES.filter((to) => to !== from).map((to) => [from, to] as const));

  it.each(pairs)("%s → %s follows the transition table", async (from, to) => {
    const { harness, profile } = await profileIn(from);
    const attempt = profiles().transitionTrusted(profile.id, to, { harnessId: harness.id });
    if (PROFILE_TRANSITIONS[from].includes(to)) {
      await expect(attempt).resolves.toMatchObject({ status: to });
    } else {
      await expect(attempt).rejects.toBeInstanceOf(InvalidTransitionError);
    }
  });

  it.each(pairs)("the database trigger agrees for %s → %s", async (from, to) => {
    const { harness, profile } = await profileIn(from);
    // Assign the harness too, so only the transition trigger can object.
    const raw = db()
      .prepare(`UPDATE agent_profiles SET status = ?1, harness_id = COALESCE(harness_id, ?3) WHERE id = ?2`)
      .bind(to, profile.id, harness.id)
      .run();
    if (PROFILE_TRANSITIONS[from].includes(to)) {
      await expect(raw).resolves.toBeDefined();
    } else {
      await expect(raw).rejects.toThrow(/invalid_status_transition/);
    }
  });

  it("pending → active is impossible", async () => {
    expect(PROFILE_TRANSITIONS.pending).not.toContain("active");
  });

  it("provisioning requires a harness", async () => {
    const user = await newUser();
    const profile = await profiles().forUser(user.id).create({ agentName: "t" });
    await expect(profiles().transitionTrusted(profile.id, "provisioning")).rejects.toBeInstanceOf(ConstraintViolationError);
  });

  it("concurrent conflicting transitions: exactly one wins", async () => {
    const { profile } = await profileIn("provisioning");
    const results = await Promise.allSettled([
      profiles().transitionTrusted(profile.id, "active"),
      profiles().transitionTrusted(profile.id, "failed"),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  });
});

describe("revocation version", () => {
  it("increments atomically under concurrency", async () => {
    const user = await newUser();
    const profile = await profiles().forUser(user.id).create({ agentName: "t" });
    const versions = await Promise.all(Array.from({ length: 25 }, () => profiles().incrementRevocationVersionTrusted(profile.id)));
    expect(new Set(versions).size).toBe(25);
    expect(Math.max(...versions)).toBe(26);
    expect((await profiles().getByIdTrusted(profile.id))?.revocationVersion).toBe(26);
  });

  it("is bumped by suspension and revocation in the same statement", async () => {
    const user = await newUser();
    const harness = await newHarness();
    const repo = profiles();
    const created = await repo.forUser(user.id).create({ agentName: "t" });
    await repo.transitionTrusted(created.id, "provisioning", { harnessId: harness.id });
    expect((await repo.transitionTrusted(created.id, "active")).revocationVersion).toBe(1);
    expect((await repo.transitionTrusted(created.id, "suspended")).revocationVersion).toBe(2);
    expect((await repo.transitionTrusted(created.id, "active")).revocationVersion).toBe(2);
    expect((await repo.forUser(user.id).revoke(created.id)).revocationVersion).toBe(3);
  });

  it("can never decrease, even by a raw UPDATE", async () => {
    const user = await newUser();
    const profile = await profiles().forUser(user.id).create({ agentName: "t" });
    await profiles().incrementRevocationVersionTrusted(profile.id);
    await expect(
      db().prepare(`UPDATE agent_profiles SET revocation_version = 1 WHERE id = ?1`).bind(profile.id).run(),
    ).rejects.toThrow(/revocation_version_decrease/);
  });

  it("of an unknown profile is NotFound", async () => {
    await expect(profiles().incrementRevocationVersionTrusted(randomId("agt"))).rejects.toBeInstanceOf(NotFoundError);
  });
});
