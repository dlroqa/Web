import { describe, expect, it, vi } from "vitest";
import {
  ConstraintViolationError,
  IdempotencyConflictError,
  InvalidTransitionError,
  mapD1Error,
  NonceReplayError,
  NotFoundError,
  toApiError,
  UnexpectedDbError,
  UniqueConflictError,
} from "../../src/worker/db/errors";
import { jsonError } from "../../src/worker/http/responses";
import { createWorker } from "../../src/worker/index";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { testEnv } from "../helpers/worker";
import { db } from "../helpers/db";

async function rawFailure(sql: string, ...binds: unknown[]): Promise<unknown> {
  return db().prepare(sql).bind(...binds).run().then(
    () => undefined,
    (error: unknown) => error,
  );
}

describe("mapD1Error", () => {
  it("classifies real D1 failures by constraint, not by echoing them", async () => {
    await db().prepare(`INSERT OR IGNORE INTO user_profiles (id, auth_user_id, status, created_at, updated_at) VALUES ('usr_mapping00001', 'mapping-test', 'pending', 1, 1)`).run();
    const unique = mapD1Error(await rawFailure(`INSERT INTO user_profiles (id, auth_user_id, status, created_at, updated_at) VALUES ('usr_mapping00002', 'mapping-test', 'pending', 1, 1)`));
    expect(unique).toBeInstanceOf(UniqueConflictError);
    expect((unique as UniqueConflictError).constraint).toBe("user_profiles.auth_user_id");
    expect(mapD1Error(await rawFailure(`INSERT INTO user_profiles (id, auth_user_id, status, created_at, updated_at) VALUES ('bad', 'x', 'pending', 1, 1)`))).toBeInstanceOf(ConstraintViolationError);
    expect(mapD1Error(await rawFailure(`UPDATE user_profiles SET status = 'suspended' WHERE id = 'usr_mapping00001'`))).toBeInstanceOf(InvalidTransitionError);
    expect(mapD1Error(await rawFailure(`SELECT * FROM no_such_table`))).toBeInstanceOf(UnexpectedDbError);
  });

  it.each([
    [new NotFoundError("agent_profile"), "NOT_FOUND"],
    [new IdempotencyConflictError(), "IDEMPOTENCY_CONFLICT"],
    [new NonceReplayError(), "REPLAY_DETECTED"],
    [new InvalidTransitionError("agent_profile", "pending", "active"), "CONFLICT"],
    [new UniqueConflictError("user_profiles.auth_user_id"), "CONFLICT"],
    [new ConstraintViolationError("check"), "INTERNAL_ERROR"],
    [new UnexpectedDbError("D1_ERROR: no such table: secrets at /home/x"), "INTERNAL_ERROR"],
  ] as const)("%s → %s", (error, code) => {
    expect(toApiError(error).code).toBe(code);
  });

  it("API responses for database errors contain no SQL, table names, or paths", async () => {
    const raw = mapD1Error(new Error("D1_ERROR: UNIQUE constraint failed: user_profiles.auth_user_id: SQLITE_CONSTRAINT /var/db"));
    const response = jsonError(toApiError(raw), { requestId: "req_test", config: undefined, url: new URL("https://x.test") });
    const text = await response.text();
    expect(text).not.toMatch(/D1_ERROR|SQLITE|user_profiles|auth_user_id|\/var/);
    expect(JSON.parse(text)).toMatchObject({ ok: false, error: { code: "CONFLICT" }, requestId: "req_test" });
  });

  it("an unexpected database failure inside a request becomes INTERNAL_ERROR with a request id", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const env = testEnv({
      ASSETS: {
        fetch: () => Promise.reject(new UnexpectedDbError("D1_ERROR: no such column: password_hash")),
        connect: () => {
          throw new Error("unused");
        },
      },
    });
    const worker = createWorker({ cspMode: "production" });
    const ctx = createExecutionContext();
    const response = await worker.fetch(new Request("http://localhost:5173/agents"), env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain("password_hash");
    vi.restoreAllMocks();
  });
});
