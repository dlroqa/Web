import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuditEventInput, AuditSink } from "../../src/worker/audit/audit";
import { AuditContractError } from "../../src/worker/audit/audit";
import { AuditRecorder, AuditRepository, D1AuditSink } from "../../src/worker/db/audit";
import { ApiError } from "../../src/worker/http/errors";
import { hashSource, securityMetadataFor, SOURCE_KEY_ID, SourceKeyError, decodeSourceKey } from "../../src/worker/security/source-identity";
import { createLogger } from "../../src/worker/utils/log";
import { randomBase64, randomId } from "../../src/worker/utils/random";
import { db, newUser } from "../helpers/db";
import { testEnv } from "../helpers/worker";

afterEach(() => vi.restoreAllMocks());

const quiet = () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "log").mockImplementation(() => {});
};

function input(userId: string, overrides: Partial<AuditEventInput> = {}): AuditEventInput {
  return {
    actor: { type: "user", id: userId },
    action: "profile.create.request",
    target: { type: "agent_profile", id: randomId("agt") },
    requestId: randomId("req"),
    result: "success",
    metadata: { retried: false, attempt: 1 },
    ...overrides,
  };
}

const failingSink: AuditSink = { record: () => Promise.reject(new Error("D1_ERROR: database is locked")) };
const KEY = randomBase64(32);

describe("D1 audit persistence", () => {
  it("stores validated events and reads them back per user", async () => {
    const user = await newUser();
    const recorder = new AuditRecorder(new D1AuditSink(db()), createLogger());
    const event = await recorder.required(input(user.id, { security: { country: "SE" } }));
    const [stored] = await new AuditRepository(db()).listForUser(user.id);
    expect(stored).toMatchObject({ id: event.id, action: "profile.create.request", result: "success", country: "SE", requestId: event.requestId });
    const row = await db().prepare(`SELECT details_json FROM audit_events WHERE id = ?1`).bind(event.id).first<{ details_json: string }>();
    expect(JSON.parse(row?.details_json ?? "")).toEqual({ retried: false, attempt: 1 });
  });

  it("never lets one user's activity appear in another's", async () => {
    const [a, b] = await Promise.all([newUser(), newUser()]);
    const recorder = new AuditRecorder(new D1AuditSink(db()), createLogger());
    await recorder.required(input(a.id));
    expect(await new AuditRepository(db()).listForUser(b.id)).toEqual([]);
  });

  it("is append-only", async () => {
    const user = await newUser();
    const event = await new AuditRecorder(new D1AuditSink(db()), createLogger()).required(input(user.id));
    await expect(db().prepare(`UPDATE audit_events SET result = 'failure' WHERE id = ?1`).bind(event.id).run()).rejects.toThrow(/append_only/);
  });

  it("refuses sensitive fields before anything is written", async () => {
    const user = await newUser();
    const recorder = new AuditRecorder(new D1AuditSink(db()), createLogger());
    for (const key of ["password", "sessionToken", "cookie", "turnstileToken", "privateKey", "authorization", "oauthAccessToken", "signingSecret"]) {
      await expect(recorder.required(input(user.id, { metadata: { [key]: "x" } }))).rejects.toBeInstanceOf(AuditContractError);
    }
    expect(await new AuditRepository(db()).listForUser(user.id)).toEqual([]);
  });

  it("rejects raw IPs in security metadata", async () => {
    const user = await newUser();
    const recorder = new AuditRecorder(new D1AuditSink(db()), createLogger());
    await expect(recorder.required(input(user.id, { security: { sourceHash: "203.0.113.9" } as never }))).rejects.toBeInstanceOf(AuditContractError);
  });

  it("the database bounds details size", async () => {
    await expect(
      db()
        .prepare(`INSERT INTO audit_events (id, timestamp, actor_type, action, request_id, result, details_json) VALUES (?1, 1, 'anonymous', 'x', 'req_x', 'success', ?2)`)
        .bind(randomId("aud"), JSON.stringify({ x: "y".repeat(5000) }))
        .run(),
    ).rejects.toThrow(/CHECK/);
  });
});

describe("AuditRecorder failure policy", () => {
  it("required: a failed write fails closed with a generic INTERNAL_ERROR", async () => {
    quiet();
    const error = await new AuditRecorder(failingSink, createLogger()).required(input(randomId("usr"))).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("INTERNAL_ERROR");
    expect((error as ApiError).message).not.toContain("D1_ERROR");
  });

  it("bestEffort: a failed write never throws and the event still reaches the logs", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation((line: string) => void lines.push(line));
    const pending: Promise<unknown>[] = [];
    const event = new AuditRecorder(failingSink, createLogger()).bestEffort(input(randomId("usr")), (p) => pending.push(p));
    await Promise.all(pending);
    expect(lines.some((line) => line.includes(event.id))).toBe(true);
  });
});

describe("source identity", () => {
  it("hashes the same address identically and different addresses differently", async () => {
    const key = decodeSourceKey(KEY);
    expect(await hashSource("203.0.113.9", key)).toBe(await hashSource(" 203.0.113.9 ", key));
    expect(await hashSource("203.0.113.9", key)).not.toBe(await hashSource("203.0.113.10", key));
    expect(await hashSource("2001:DB8::1", key)).toBe(await hashSource("2001:db8::1", key));
  });

  it("depends on the key, so hashes cannot be reversed without it", async () => {
    expect(await hashSource("203.0.113.9", decodeSourceKey(KEY))).not.toBe(await hashSource("203.0.113.9", decodeSourceKey(randomBase64(32))));
  });

  it("rejects short or malformed keys", () => {
    expect(() => decodeSourceKey(randomBase64(8))).toThrow(SourceKeyError);
    expect(() => decodeSourceKey("not base64!!")).toThrow(SourceKeyError);
  });

  it("produces a keyed hash, never the raw IP, and nothing when the key is unset", async () => {
    const request = new Request("https://x.test", { headers: { "cf-connecting-ip": "203.0.113.9" } });
    const withKey = await securityMetadataFor(request, { ...testEnv(), AUDIT_SOURCE_HMAC_KEY: KEY } as Env);
    expect(withKey.sourceHash).toMatch(/^[0-9a-f]{64}$/);
    expect(withKey.sourceKeyId).toBe(SOURCE_KEY_ID);
    expect(JSON.stringify(withKey)).not.toContain("203.0.113.9");
    expect(await securityMetadataFor(request, testEnv())).toEqual({});
  });

  it("supports 'same source detected' queries", async () => {
    const user = await newUser();
    const sourceHash = await hashSource("198.51.100.7", decodeSourceKey(KEY));
    const recorder = new AuditRecorder(new D1AuditSink(db()), createLogger());
    const since = Date.now() - 1000;
    await recorder.required(input(user.id, { security: { sourceHash, sourceKeyId: SOURCE_KEY_ID } }));
    await recorder.required(input(user.id, { security: { sourceHash, sourceKeyId: SOURCE_KEY_ID } }));
    expect(await new AuditRepository(db()).countBySourceTrusted(sourceHash, since)).toBe(2);
  });
});
