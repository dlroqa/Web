/**
 * Operator service and CLI: audited, atomic, operator-only account changes.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OperatorAuthorizationError, operatorActor, type Actor } from "../../src/operator/actors";
import { parseArgs, runOperatorCommand } from "../../src/operator/cli";
import { OperatorError, OperatorService, validateReason } from "../../src/operator/service";
import { UserRepository, type UserStatus } from "../../src/worker/db/users";
import { VerificationRepository } from "../../src/worker/db/verifications";
import { randomId } from "../../src/worker/utils/random";
import { FakeProviders, get, identity, send, signIn, type Identity } from "../helpers/auth";
import { CookieJar } from "../helpers/cookies";

const OPERATOR = operatorActor("opr_testoperator1");
const REASON = "verified by support ticket 1234";
let providers: FakeProviders;

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "info").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  providers = new FakeProviders().install();
});

afterEach(() => {
  providers.restore();
  vi.restoreAllMocks();
});

async function newUser(status: UserStatus = "pending"): Promise<string> {
  const users = new UserRepository(env.DB);
  const user = await users.create({ authUserId: randomId("au"), displayName: "Someone" });
  if (status === "active" || status === "suspended" || status === "disabled") await users.transition(user.id, status === "disabled" ? "disabled" : "active");
  if (status === "suspended") await users.transition(user.id, "suspended");
  return user.id;
}

async function statusOf(userId: string): Promise<UserStatus | undefined> {
  return (await new UserRepository(env.DB).getById(userId))?.status;
}

async function auditFor(requestId: string) {
  const { results } = await env.DB.prepare(`SELECT * FROM audit_events WHERE request_id = ?1`).bind(requestId).all<Record<string, unknown>>();
  return results;
}

async function signedInUser(): Promise<{ who: Identity; jar: CookieJar; userId: string; authUserId: string }> {
  const who = identity("google");
  const jar = new CookieJar();
  await signIn(providers, who, jar);
  const row = await env.DB.prepare(`SELECT p.id, p.auth_user_id FROM user_profiles p JOIN "user" u ON u.id = p.auth_user_id WHERE u.email = ?1`)
    .bind(who.email)
    .first<{ id: string; auth_user_id: string }>();
  if (!row) throw new Error("no profile");
  return { who, jar, userId: row.id, authUserId: row.auth_user_id };
}

async function insertPasskey(authUserId: string, name: string): Promise<string> {
  const id = randomId("pk").replace("_", "");
  await env.DB.prepare(
    `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt", aaguid)
     VALUES (?1, ?2, 'cHVibGljLWtleQ', ?3, ?4, 0, 'singleDevice', 0, 'internal', ?5, NULL)`,
  )
    .bind(id, name, authUserId, randomId("cred"), new Date().toISOString())
    .run();
  return id;
}

describe("status operations", () => {
  it.each([
    ["approve", "pending", "active", "admin.user.approve"],
    ["suspend", "active", "suspended", "admin.user.suspend"],
    ["reactivate", "suspended", "active", "admin.user.reactivate"],
    ["disable", "active", "disabled", "admin.user.disable"],
    ["disable", "pending", "disabled", "admin.user.disable"],
  ] as const)("%s: %s → %s, in one transaction with an %s audit event", async (operation, from, to, action) => {
    const userId = await newUser(from);
    const operationId = randomId("op");
    const result = await new OperatorService(env.DB).changeStatus(OPERATOR, operation, { userId, reason: REASON, operationId });
    expect(result).toMatchObject({ operationId, userId, from, to });
    expect(await statusOf(userId)).toBe(to);

    const rows = await auditFor(operationId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: result.auditEventId, actor_type: "admin", actor_id: "opr_testoperator1", action, target_type: "user", target_id: userId, result: "success", reason: null });
    expect(JSON.parse(String(rows[0]?.["details_json"]))).toEqual({ reason: REASON, from, to, channel: "cli" });
  });

  it.each([
    ["approve", "active"],
    ["approve", "suspended"],
    ["suspend", "pending"],
    ["reactivate", "active"],
    ["approve", "disabled"],
    ["reactivate", "disabled"],
  ] as const)("rejects %s on a %s account, changes nothing, and audits the refusal", async (operation, from) => {
    const userId = await newUser(from);
    const operationId = randomId("op");
    await expect(new OperatorService(env.DB).changeStatus(OPERATOR, operation, { userId, reason: REASON, operationId })).rejects.toMatchObject({ code: "INVALID_TRANSITION" });
    expect(await statusOf(userId)).toBe(from);
    const rows = await auditFor(operationId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ result: "denied", reason: "CONFLICT", target_id: userId });
  });

  it("an unknown user is NOT_FOUND (audited), and malformed input is rejected before any write", async () => {
    const service = new OperatorService(env.DB);
    const operationId = randomId("op");
    const ghost = randomId("usr");
    await expect(service.changeStatus(OPERATOR, "approve", { userId: ghost, reason: REASON, operationId })).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(await auditFor(operationId)).toHaveLength(1);

    const before = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_events`).first<{ n: number }>();
    await expect(service.changeStatus(OPERATOR, "approve", { userId: "someone@example.test", reason: REASON })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(service.changeStatus(OPERATOR, "approve", { userId: await newUser(), reason: "ok" })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(service.changeStatus(OPERATOR, "approve", { userId: await newUser(), reason: "requested by a.person@example.test" })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(service.changeStatus(OPERATOR, "approve", { userId: await newUser(), reason: REASON, operationId: "not-an-id" })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    const after = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_events`).first<{ n: number }>();
    expect(after?.n).toBe(before?.n);
  });

  it("is atomic: if the audit row cannot be written, the status does not change", async () => {
    const userId = await newUser("pending");
    await env.DB.exec(`CREATE TRIGGER test_fail_admin_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'admin.user.approve' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;`);
    try {
      await expect(new OperatorService(env.DB).changeStatus(OPERATOR, "approve", { userId, reason: REASON })).rejects.toThrow();
    } finally {
      await env.DB.exec(`DROP TRIGGER test_fail_admin_audit;`);
    }
    expect(await statusOf(userId)).toBe("pending");
  });

  it("validateReason trims and enforces bounds", () => {
    expect(validateReason("  fine reason  ")).toBe("fine reason");
    expect(() => validateReason("x".repeat(201))).toThrow(OperatorError);
    expect(() => validateReason("tab\there")).toThrow(OperatorError);
    expect(() => validateReason(undefined)).toThrow(OperatorError);
  });
});

describe("operator authorization", () => {
  const user: Actor = { kind: "user", userProfileId: "usr_abcdefgh1234" };
  const system: Actor = { kind: "system", component: "cleanup" };

  it("an ordinary user (or the system) cannot invoke operator functions; nothing changes, nothing is written", async () => {
    const userId = await newUser("pending");
    const service = new OperatorService(env.DB);
    const before = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_events`).first<{ n: number }>();
    for (const actor of [user, system]) {
      await expect(service.changeStatus(actor, "approve", { userId, reason: REASON })).rejects.toBeInstanceOf(OperatorAuthorizationError);
      await expect(service.revokeUserSessions(actor, { userId, reason: REASON })).rejects.toBeInstanceOf(OperatorAuthorizationError);
      await expect(service.removePasskey(actor, { userId, reason: REASON, passkeyId: "abcdefgh1234" })).rejects.toBeInstanceOf(OperatorAuthorizationError);
      await expect(service.describeUser(actor, userId)).rejects.toBeInstanceOf(OperatorAuthorizationError);
    }
    await expect(service.purgeExpiredVerifications(user)).rejects.toBeInstanceOf(OperatorAuthorizationError);
    // A forged operator object with a malformed id is not an operator either.
    await expect(service.changeStatus({ kind: "operator", operatorId: "admin@example.test", channel: "cli" }, "approve", { userId, reason: REASON })).rejects.toBeInstanceOf(OperatorAuthorizationError);
    expect(await statusOf(userId)).toBe("pending");
    const after = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_events`).first<{ n: number }>();
    expect(after?.n).toBe(before?.n);
  });

  it("operator ids are opr_ labels, never emails", () => {
    expect(() => operatorActor(undefined)).toThrow(OperatorAuthorizationError);
    expect(() => operatorActor("someone@example.test")).toThrow(OperatorAuthorizationError);
    expect(() => operatorActor("opr_ab")).toThrow(OperatorAuthorizationError);
    expect(operatorActor("opr_eddelaroca").operatorId).toBe("opr_eddelaroca");
  });

  it("no HTTP route reaches operator functions, even for an active signed-in user", async () => {
    const { jar, userId } = await signedInUser();
    for (const path of ["/api/admin", `/api/admin/users/${userId}/approve`, "/api/operator", `/api/operator/approve`, "/api/admin/sessions/revoke-all", "/api/users/approve"]) {
      expect((await send("POST", path, jar, { userId, reason: REASON })).status).toBe(404);
      expect((await get(path, jar)).status).toBe(404);
    }
  });
});

describe("sessions and passkeys", () => {
  it("revoke-sessions ends every session of one user only, and is audited", async () => {
    const target = await signedInUser();
    const second = new CookieJar();
    await signIn(providers, target.who, second);
    const bystander = await signedInUser();

    const result = await new OperatorService(env.DB).revokeUserSessions(OPERATOR, { userId: target.userId, reason: REASON });
    expect(result.revoked).toBe(2);
    expect((await get("/api/me", target.jar)).status).toBe(401);
    expect((await get("/api/me", second)).status).toBe(401);
    expect((await get("/api/me", bystander.jar)).status).toBe(200);
    const [row] = await auditFor(result.operationId);
    expect(row).toMatchObject({ action: "admin.user.sessions.revoke", target_id: target.userId, result: "success" });
    expect(JSON.parse(String(row?.["details_json"]))).toMatchObject({ sessions: 2 });
  });

  it("revoke-all-sessions requires explicit confirmation, then ends every session", async () => {
    const a = await signedInUser();
    const service = new OperatorService(env.DB);
    await expect(service.revokeAllSessions(OPERATOR, { reason: REASON, confirm: false })).rejects.toMatchObject({ code: "CONFIRMATION_REQUIRED" });
    expect((await get("/api/me", a.jar)).status).toBe(200);
    const result = await service.revokeAllSessions(OPERATOR, { reason: REASON, confirm: true });
    expect(result.revoked).toBeGreaterThanOrEqual(1);
    expect((await get("/api/me", a.jar)).status).toBe(401);
    expect((await env.DB.prepare(`SELECT COUNT(*) AS n FROM session`).first<{ n: number }>())?.n).toBe(0);
    expect((await auditFor(result.operationId))[0]).toMatchObject({ action: "admin.sessions.revoke_all", target_type: null });
  });

  it("remove-passkey deletes only the named passkey of the named user, with an audited fingerprint", async () => {
    const owner = await signedInUser();
    const other = await signedInUser();
    const keep = await insertPasskey(owner.authUserId, "Keep me");
    const remove = await insertPasskey(owner.authUserId, "staging-virtual-3");
    const foreign = await insertPasskey(other.authUserId, "Not yours");
    const service = new OperatorService(env.DB);

    const listed = await service.listPasskeys(OPERATOR, owner.userId);
    expect(listed.map((p) => p.name).sort()).toEqual(["Keep me", "staging-virtual-3"]);
    expect(JSON.stringify(listed)).not.toMatch(/credentialID|publicKey|cHVibGljLWtleQ/);

    // Another user's passkey id behaves exactly like a missing one.
    await expect(service.removePasskey(OPERATOR, { userId: owner.userId, passkeyId: foreign, reason: REASON })).rejects.toMatchObject({ code: "NOT_FOUND" });
    const result = await service.removePasskey(OPERATOR, { userId: owner.userId, passkeyId: remove, reason: "unusable test credential" });
    expect(result.fingerprint).toMatch(/^sha256:[0-9a-f]{16}$/);

    const ids = (await env.DB.prepare(`SELECT id FROM passkey`).all<{ id: string }>()).results.map((r) => r.id);
    expect(ids).toContain(keep);
    expect(ids).toContain(foreign);
    expect(ids).not.toContain(remove);
    const [row] = await auditFor(result.operationId);
    expect(row).toMatchObject({ action: "admin.passkey.remove", target_type: "passkey", target_id: remove, actor_type: "admin" });
    expect(JSON.parse(String(row?.["details_json"]))).toEqual({ name: "staging-virtual-3", fingerprint: result.fingerprint, user: owner.userId, reason: "unusable test credential", channel: "cli" });
  });

  it("show-user returns status and counts without email or provider account ids", async () => {
    const { who, userId } = await signedInUser();
    const described = await new OperatorService(env.DB).describeUser(OPERATOR, userId);
    expect(described).toMatchObject({ id: userId, status: "active", providers: ["google"], passkeys: 0, sessions: 1 });
    expect(JSON.stringify(described)).not.toContain(who.email);
    expect(JSON.stringify(described)).not.toContain(who.sub);
  });
});

describe("expired verification cleanup", () => {
  async function insertVerification(expiresAt: string | number): Promise<string> {
    const id = randomId("ver");
    const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO verification (id, identifier, value, "expiresAt", "createdAt", "updatedAt") VALUES (?1, ?2, '{}', ?3, ?4, ?4)`)
      .bind(id, randomId("ident"), expiresAt, now)
      .run();
    return id;
  }

  it("deletes only expired rows, in bounded batches, and never unexpired or non-ISO rows", async () => {
    await env.DB.exec(`DELETE FROM verification`);
    const past = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
    const expired = await Promise.all([1, 2, 3].map((m) => insertVerification(past(m))));
    const live = await insertVerification(new Date(Date.now() + 5 * 60_000).toISOString());
    const numeric = await insertVerification(1); // not ISO text: never treated as expired

    const repo = new VerificationRepository(env.DB);
    expect(await repo.countExpired(new Date())).toBe(3);
    expect(await repo.deleteExpired(new Date(), 2)).toBe(2);
    expect(await repo.deleteExpired(new Date(), 2)).toBe(1);
    expect(await repo.deleteExpired(new Date(), 2)).toBe(0);
    const remaining = (await env.DB.prepare(`SELECT id FROM verification`).all<{ id: string }>()).results.map((r) => r.id);
    expect(remaining.sort()).toEqual([live, numeric].sort());
    for (const id of expired) expect(remaining).not.toContain(id);
  });

  it("the operator purge reports what it removed", async () => {
    await env.DB.exec(`DELETE FROM verification`);
    await insertVerification(new Date(Date.now() - 60_000).toISOString());
    const result = await new OperatorService(env.DB).purgeExpiredVerifications({ kind: "system", component: "cleanup" }, { limit: 10 });
    expect(result).toEqual({ deleted: 1, remainingExpired: 0 });
  });
});

describe("operator CLI", () => {
  function io() {
    const out: string[] = [];
    const err: string[] = [];
    return { out, err, sink: { out: (t: string) => void out.push(t), err: (t: string) => void err.push(t) } };
  }

  it("approve prints a sanitized JSON result", async () => {
    const userId = await newUser("pending");
    const { out, sink } = io();
    const code = await runOperatorCommand(parseArgs(["approve", "--user", userId, "--reason", REASON]), env.DB, sink, "opr_testoperator1");
    expect(code).toBe(0);
    const parsed = JSON.parse(out.join("")) as { ok: boolean; result: { from: string; to: string } };
    expect(parsed).toMatchObject({ ok: true, result: { userId, from: "pending", to: "active" } });
  });

  it("refuses without an operator id, and reports invalid transitions as errors", async () => {
    const userId = await newUser("active");
    const missing = io();
    expect(await runOperatorCommand(parseArgs(["approve", "--user", userId, "--reason", REASON]), env.DB, missing.sink, undefined)).toBe(1);
    expect(JSON.parse(missing.err.join(""))).toMatchObject({ ok: false, error: { code: "FORBIDDEN" } });
    const invalid = io();
    expect(await runOperatorCommand(parseArgs(["approve", "--user", userId, "--reason", REASON]), env.DB, invalid.sink, "opr_testoperator1")).toBe(1);
    expect(JSON.parse(invalid.err.join(""))).toMatchObject({ ok: false, error: { code: "INVALID_TRANSITION" } });
  });

  it("rejects unknown commands and options (no passthrough)", () => {
    expect(() => parseArgs(["approve", "--sql", "DELETE FROM user_profiles"])).toThrow(OperatorError);
    expect(() => parseArgs(["approve", "--user"])).toThrow(OperatorError);
  });

  it("an unknown command fails without touching the database", async () => {
    const { err, sink } = io();
    expect(await runOperatorCommand(parseArgs(["exec"]), env.DB, sink, "opr_testoperator1")).toBe(1);
    expect(err.join("")).toContain("unknown command");
  });
});
