import { env, evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { admitAt, type AuthRateLimiter } from "../../src/worker/security/rate-limit-do";
import { randomId } from "../../src/worker/utils/random";

const T0 = Date.UTC(2026, 9, 15, 12, 0, 0);

/** A fresh, uniquely named counter object. */
const counter = () => env.AUTH_RATE_LIMITER.getByName(randomId("test-counter"));

/** Run `admitAt` against the object's real SQLite storage with a fixed clock. */
function at(stub: DurableObjectStub<AuthRateLimiter>, now: number, limit = 20, period = 60) {
  return runInDurableObject(stub, (_instance, state) => admitAt(state.storage.sql, limit, period, now));
}

const rows = (stub: DurableObjectStub<AuthRateLimiter>) =>
  runInDurableObject(stub, (_instance, state) => {
    const table = state.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'admissions'").one().n;
    return table === 0 ? null : state.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM admissions").one().n;
  });

describe("admitAt (rolling window, fixed clock)", () => {
  it("admits exactly `limit` requests, then refuses with the time until a slot frees", async () => {
    const stub = counter();
    for (let i = 0; i < 20; i += 1) expect(await at(stub, T0 + i * 1000)).toEqual({ allowed: true, retryAfterSeconds: 0 });
    // The oldest admission (T0) frees its slot at T0 + 60 s.
    expect(await at(stub, T0 + 20_000)).toEqual({ allowed: false, retryAfterSeconds: 40 });
    expect(await at(stub, T0 + 59_001)).toEqual({ allowed: false, retryAfterSeconds: 1 });
  });

  it("rolls over one slot at a time, exactly one period after each admission", async () => {
    const stub = counter();
    for (let i = 0; i < 20; i += 1) await at(stub, T0 + i * 1000);
    expect((await at(stub, T0 + 59_999)).allowed).toBe(false);
    expect((await at(stub, T0 + 60_000)).allowed).toBe(true); // T0's slot
    expect((await at(stub, T0 + 60_000)).allowed).toBe(false); // T0+1s not yet free
    expect((await at(stub, T0 + 61_000)).allowed).toBe(true);
  });

  it("allows no burst across a fixed-window boundary", async () => {
    const stub = counter();
    for (let i = 0; i < 20; i += 1) await at(stub, T0 + 59_000);
    // A fixed 60 s window would reset at T0 + 60 s; the rolling window does not.
    expect((await at(stub, T0 + 60_001)).allowed).toBe(false);
    expect((await at(stub, T0 + 119_000)).allowed).toBe(true);
  });

  it("does not record refusals: retrying neither extends the lockout nor grows storage", async () => {
    const stub = counter();
    for (let i = 0; i < 20; i += 1) await at(stub, T0);
    for (let i = 0; i < 200; i += 1) expect((await at(stub, T0 + 100 * i)).allowed).toBe(false);
    expect(await rows(stub)).toBe(20);
    expect((await at(stub, T0 + 60_000)).allowed).toBe(true);
  });

  it("caps Retry-After at the period even if the clock moved backwards", async () => {
    const stub = counter();
    for (let i = 0; i < 3; i += 1) await at(stub, T0, 3);
    expect(await at(stub, T0 - 600_000, 3)).toEqual({ allowed: false, retryAfterSeconds: 60 });
  });
});

describe("AuthRateLimiter object", () => {
  it("serializes concurrent requests for one key: exactly `limit` are admitted", async () => {
    const stub = counter();
    const results = await Promise.all(Array.from({ length: 50 }, () => stub.admit(20, 60)));
    expect(results.filter((r) => r.allowed)).toHaveLength(20);
    expect(results.filter((r) => !r.allowed).every((r) => r.retryAfterSeconds >= 1 && r.retryAfterSeconds <= 60)).toBe(true);
  });

  it("keeps its counts across eviction (state is only in SQLite)", async () => {
    const stub = counter();
    for (let i = 0; i < 20; i += 1) expect((await stub.admit(20, 60)).allowed).toBe(true);
    await evictDurableObject(stub);
    expect((await stub.admit(20, 60)).allowed).toBe(false);
    expect(await rows(stub)).toBe(20);
  });

  it("schedules cleanup; an early alarm keeps live admissions, an expired one deletes everything", async () => {
    const stub = counter();
    await stub.admit(5, 60);
    const scheduled = await runInDurableObject(stub, (_i, state) => state.storage.getAlarm());
    expect(scheduled).toBeGreaterThan(Date.now() + 50_000);

    // The test helper runs the alarm now, before the admission has expired.
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await rows(stub)).toBe(1);
    expect(await runInDurableObject(stub, (_i, state) => state.storage.getAlarm())).toBe(scheduled);

    // Once every admission has expired, the alarm removes the object's storage.
    await runInDurableObject(stub, (_i, state) => state.storage.sql.exec("UPDATE admissions SET expires_at = 0"));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await rows(stub)).toBeNull();
    expect(await runInDurableObject(stub, (_i, state) => state.storage.getAlarm())).toBeNull();
    // …and the counter works again afterwards.
    expect((await stub.admit(5, 60)).allowed).toBe(true);
  });

  it("stores no identifier, only expiry times", async () => {
    const stub = counter();
    await stub.admit(5, 60);
    const columns = await runInDurableObject(stub, (_i, state) =>
      state.storage.sql.exec<{ name: string }>("SELECT name FROM pragma_table_info('admissions')").toArray().map((c) => c.name),
    );
    expect(columns).toEqual(["expires_at"]);
  });

  it("rejects nonsensical arguments instead of deciding", async () => {
    const stub = counter();
    for (const [limit, period] of [[0, 60], [1.5, 60], [20, 0], [20, 7200], [Number.NaN, 60]] as const) {
      await expect(runInDurableObject(stub, (instance) => instance.admit(limit, period))).rejects.toThrow(/invalid/);
    }
  });
});
