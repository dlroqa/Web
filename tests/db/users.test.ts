import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { InvalidTransitionError, NotFoundError, UniqueConflictError } from "../../src/worker/db/errors";
import { USER_STATUSES, USER_TRANSITIONS } from "../../src/worker/db/users";
import { randomId } from "../../src/worker/utils/random";
import { db, newUser, users } from "../helpers/db";

describe("UserRepository", () => {
  it("creates a pending profile keyed by an opaque auth user id", async () => {
    const authUserId = "Opaque/Id:With-Any_Format.123";
    const user = await users().create({ authUserId, displayName: "Ada" });
    expect(user).toMatchObject({ authUserId, displayName: "Ada", status: "pending" });
    expect(user.id).toMatch(/^usr_[a-z0-9]{26}$/);
    expect(await users().getByAuthUserId(authUserId)).toEqual(user);
  });

  it("allows one profile per auth user id", async () => {
    const authUserId = randomId("auth");
    await users().create({ authUserId });
    await expect(users().create({ authUserId })).rejects.toBeInstanceOf(UniqueConflictError);
  });

  it("bounds display names and auth ids", async () => {
    await expect(users().create({ authUserId: randomId("a"), displayName: "x".repeat(81) })).rejects.toBeInstanceOf(ZodError);
    await expect(users().create({ authUserId: "x".repeat(256) })).rejects.toBeInstanceOf(ZodError);
  });

  it("updates only the given user's display name", async () => {
    const [a, b] = await Promise.all([newUser(), newUser()]);
    await users().updateDisplayName(a.id, "Alice");
    expect((await users().getById(b.id))?.displayName).toBeNull();
    await expect(users().updateDisplayName(randomId("usr"), "x")).rejects.toBeInstanceOf(NotFoundError);
  });

  const pairs = USER_STATUSES.flatMap((from) => USER_STATUSES.filter((to) => to !== from).map((to) => [from, to] as const));
  it.each(pairs)("status %s → %s follows the transition table (repository and trigger)", async (from, to) => {
    const user = await newUser();
    const path = { pending: [], active: ["active"], suspended: ["active", "suspended"], disabled: ["disabled"] } as const;
    for (const step of path[from]) await users().transition(user.id, step);
    const allowed = USER_TRANSITIONS[from].includes(to);
    const attempt = users().transition(user.id, to);
    if (allowed) await expect(attempt).resolves.toMatchObject({ status: to });
    else await expect(attempt).rejects.toBeInstanceOf(InvalidTransitionError);
    if (!allowed) {
      await expect(db().prepare(`UPDATE user_profiles SET status = ?1 WHERE id = ?2`).bind(to, user.id).run()).rejects.toThrow(/invalid_status_transition/);
    }
  });

  it("auth_user_id is immutable", async () => {
    const user = await newUser();
    await expect(db().prepare(`UPDATE user_profiles SET auth_user_id = 'other' WHERE id = ?1`).bind(user.id).run()).rejects.toThrow(/immutable_column/);
  });
});
