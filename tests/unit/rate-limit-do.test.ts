import { env, evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { admitAndSchedule, admitAt, cleanupAt, MIN_CLEANUP_INTERVAL_MS, type AuthRateLimiter, type CounterStorage } from "../../src/worker/security/rate-limit-do";
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

const alarmOf = (stub: DurableObjectStub<AuthRateLimiter>) => runInDurableObject(stub, (_i, state) => state.storage.getAlarm());

/**
 * The object's real storage, metered: SQL rows written as SQLite reports
 * them (each cursor's `rowsWritten`), and `setAlarm` / `deleteAll` calls.
 * Cloudflare bills `setAlarm` as one row written; `deleteAll` is counted
 * here but its billing cannot be measured locally.
 */
function metered(storage: DurableObjectStorage) {
  const cursors: { rowsWritten: number }[] = [];
  const calls = { setAlarm: 0, deleteAll: 0 };
  const counted: CounterStorage = {
    sql: {
      exec: (query: string, ...bindings: SqlStorageValue[]) => {
        const cursor = storage.sql.exec(query, ...bindings);
        cursors.push(cursor);
        return cursor;
      },
    } as unknown as SqlStorage,
    getAlarm: (options) => storage.getAlarm(options),
    setAlarm: (time, options) => ((calls.setAlarm += 1), storage.setAlarm(time, options)),
    deleteAll: (options) => ((calls.deleteAll += 1), storage.deleteAll(options)),
  };
  const meter = () => {
    const rowsWritten = cursors.reduce((n, c) => n + c.rowsWritten, 0);
    return { rowsWritten, setAlarm: calls.setAlarm, deleteAll: calls.deleteAll, billableWrites: rowsWritten + calls.setAlarm };
  };
  return { storage: counted, meter };
}

/** An in-memory sliding log: the specification `admitAt` must match exactly. */
function referenceLimiter(limit: number, periodSeconds: number) {
  const expiries: number[] = [];
  return (now: number) => {
    const live = expiries.filter((e) => e > now);
    expiries.splice(0, expiries.length, ...live);
    if (live.length >= limit) {
      return { allowed: false, retryAfterSeconds: Math.min(periodSeconds, Math.max(1, Math.ceil((Math.min(...live) - now) / 1000))) };
    }
    expiries.push(now + periodSeconds * 1000);
    return { allowed: true, retryAfterSeconds: 0 };
  };
}

/** Deterministic pseudo-random steps (LCG), so a failing run can be replayed. */
function steps(seed: number) {
  let x = seed;
  return (max: number) => ((x = (x * 1103515245 + 12345) % 2 ** 31), x % (max + 1));
}

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
    const scheduled = await alarmOf(stub);
    expect(scheduled).toBeGreaterThan(Date.now() + 50_000);

    // The test helper runs the alarm now, before the admission has expired:
    // it keeps the row and re-arms no sooner than the minimum interval.
    const before = Date.now();
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await rows(stub)).toBe(1);
    expect(await alarmOf(stub)).toBeGreaterThanOrEqual(Math.max(scheduled ?? 0, before + MIN_CLEANUP_INTERVAL_MS));

    // Once every admission has expired, the alarm removes the object's storage.
    await runInDurableObject(stub, (_i, state) => state.storage.sql.exec("UPDATE admissions SET expires_at = 0"));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await rows(stub)).toBeNull();
    expect(await alarmOf(stub)).toBeNull();
    // …and the counter works again afterwards.
    expect((await stub.admit(5, 60)).allowed).toBe(true);
    expect(await alarmOf(stub)).not.toBeNull();
  });

  it("schedules one alarm until it fires, not one per admission; then re-arms no sooner than the interval", async () => {
    const stub = counter();
    await stub.admit(5, 60);
    const first = await alarmOf(stub);
    for (let i = 0; i < 4; i += 1) await stub.admit(5, 60);
    expect(await alarmOf(stub)).toBe(first);
    expect(await rows(stub)).toBe(5);
    // When it fires, the alarm re-arms no earlier than the latest
    // admission's expiry and no sooner than the minimum interval.
    const before = Date.now();
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const latest = await runInDurableObject(stub, (_i, state) => state.storage.sql.exec<{ m: number }>("SELECT MAX(expires_at) AS m FROM admissions").one().m);
    const rearmed = await alarmOf(stub);
    expect(rearmed).toBeGreaterThanOrEqual(latest);
    expect(rearmed).toBeGreaterThanOrEqual(before + MIN_CLEANUP_INTERVAL_MS);
    expect(rearmed).toBeLessThanOrEqual(Date.now() + MIN_CLEANUP_INTERVAL_MS);
  });

  it("keeps its alarm across eviction, and the alarm still cleans up afterwards", async () => {
    const stub = counter();
    await stub.admit(5, 60);
    const scheduled = await alarmOf(stub);
    await evictDurableObject(stub);
    expect(await alarmOf(stub)).toBe(scheduled);
    expect(await rows(stub)).toBe(1);
    await runInDurableObject(stub, (_i, state) => state.storage.sql.exec("UPDATE admissions SET expires_at = 0"));
    await evictDurableObject(stub);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await rows(stub)).toBeNull();
  });

  it("re-arms a lost alarm on the next admission; decisions never depend on the alarm", async () => {
    const stub = counter();
    for (let i = 0; i < 3; i += 1) await stub.admit(3, 60);
    await runInDurableObject(stub, (_i, state) => state.storage.deleteAlarm());
    expect(await alarmOf(stub)).toBeNull();
    // Without an alarm the limit still holds (admitAt removes expired rows itself)…
    expect((await stub.admit(3, 60)).allowed).toBe(false);
    expect(await alarmOf(stub)).toBeNull(); // a refusal schedules nothing
    // …and the next admission re-arms cleanup.
    await runInDurableObject(stub, (_i, state) => state.storage.sql.exec("UPDATE admissions SET expires_at = 0"));
    expect((await stub.admit(3, 60)).allowed).toBe(true);
    expect(await alarmOf(stub)).not.toBeNull();
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

describe("storage writes (measured with SQLite's own row counts)", () => {
  // Far enough ahead that no alarm scheduled by these tests fires on its own.
  const BASE_TIME = Date.now() + 86_400_000;

  it("a refusal writes nothing and schedules nothing", async () => {
    const stub = counter();
    const result = await runInDurableObject(stub, async (_i, state) => {
      for (let i = 0; i < 3; i += 1) await admitAndSchedule(state.storage, 3, 60, BASE_TIME + i);
      const { storage, meter } = metered(state.storage);
      for (let i = 0; i < 50; i += 1) expect((await admitAndSchedule(storage, 3, 60, BASE_TIME + 1000 + i)).allowed).toBe(false);
      return meter();
    });
    expect(result).toEqual({ rowsWritten: 0, setAlarm: 0, deleteAll: 0, billableWrites: 0 });
  });

  it("an admission is one INSERT (plus the alarm only when none is scheduled); its expiry is one DELETE", async () => {
    const stub = counter();
    const [fresh, busy, expired] = await runInDurableObject(stub, async (_i, state) => {
      const first = metered(state.storage);
      await admitAndSchedule(first.storage, 20, 60, BASE_TIME);
      const second = metered(state.storage);
      await admitAndSchedule(second.storage, 20, 60, BASE_TIME + 1000);
      const third = metered(state.storage);
      await admitAndSchedule(third.storage, 20, 60, BASE_TIME + 61_000); // the first two have expired
      return [first.meter(), second.meter(), third.meter()];
    });
    // A new counter: CREATE TABLE (2 rows of schema) + INSERT, and the alarm.
    expect(fresh).toEqual({ rowsWritten: 3, setAlarm: 1, deleteAll: 0, billableWrites: 4 });
    expect(busy).toEqual({ rowsWritten: 1, setAlarm: 0, deleteAll: 0, billableWrites: 1 });
    expect(expired).toEqual({ rowsWritten: 3, setAlarm: 0, deleteAll: 0, billableWrites: 3 });
  });

  it.each([
    ["paced at the limit (one request per second)", 1, 1000, 1000],
    ["irregular bursts, overlapping windows", 7, 0, 4000],
    ["slow, with idle gaps longer than the period", 11, 2000, 90_000],
  ])("matches the exact sliding window and stays within the write budget: %s", async (_label, seed, minStep, maxStep) => {
    const LIMIT = 20;
    const PERIOD = 60;
    const DURATION = 15 * 60_000;
    const stub = counter();
    const result = await runInDurableObject(stub, async (_i, state) => {
      const { storage, meter } = metered(state.storage);
      const reference = referenceLimiter(LIMIT, PERIOD);
      const next = steps(seed);
      let now = BASE_TIME;
      let admissions = 0;
      let refusals = 0;
      let alarms = 0;
      let lastAdmission = 0;
      let lastAlarm = 0;
      const runDueAlarm = async (at: number) => {
        const due = await state.storage.getAlarm();
        if (due !== null && due <= at) {
          alarms += 1;
          lastAlarm = due;
          await cleanupAt(storage, due);
        }
      };
      while (now < BASE_TIME + DURATION) {
        await runDueAlarm(now);
        const decision = await admitAndSchedule(storage, LIMIT, PERIOD, now);
        expect(decision).toEqual(reference(now));
        if (decision.allowed) {
          admissions += 1;
          lastAdmission = now;
        } else refusals += 1;
        now += minStep + next(maxStep - minStep);
      }
      // Then idle until the alarms have removed everything.
      for (let i = 0; i < 10 && (await state.storage.getAlarm()) !== null; i += 1) await runDueAlarm(Number.MAX_SAFE_INTEGER);
      const left = state.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'admissions'").one().n;
      return { ...meter(), admissions, refusals, alarms, lastAdmission, lastAlarm, alarmLeft: await state.storage.getAlarm(), tableLeft: left };
    });
    expect(result.admissions).toBeGreaterThan(0);
    expect(result.alarmLeft).toBeNull();
    expect(result.tableLeft).toBe(0);
    // Nothing is kept longer than the minimum interval past the last expiry.
    expect(result.lastAlarm).toBeLessThanOrEqual(result.lastAdmission + PERIOD * 1000 + MIN_CLEANUP_INTERVAL_MS);
    // Every admission is one INSERT and one DELETE; each counter lifetime
    // (ended by deleteAll) adds the 2-row CREATE TABLE.
    expect(result.rowsWritten).toBe(2 * result.admissions + 2 * result.deleteAll);
    // Every alarm either re-arms (one setAlarm) or ends a lifetime with
    // deleteAll; every lifetime starts with one setAlarm by its first
    // admission. With all lifetimes ended, setAlarm calls = alarms run.
    expect(result.setAlarm).toBe(result.alarms);
    // A re-arm needs an admission since the alarm was set, so there are
    // never more setAlarm calls than admissions: never more writes than
    // before F1 (one setAlarm per admission), whatever the traffic.
    expect(result.setAlarm).toBeLessThanOrEqual(result.admissions);
    // Alarms of one counter lifetime are at least the minimum interval apart
    // after the first; per lifetime at most 3 more than its span allows.
    expect(result.alarms).toBeLessThanOrEqual(3 * result.deleteAll + Math.ceil(DURATION / MIN_CLEANUP_INTERVAL_MS));
  }, 60_000);

  // Steady traffic, one request every `gap` seconds against 20 / 60 s, for
  // 15 minutes, then idle. Exact counts, worked out by hand, compared with
  // the scheme before F1 (setAlarm on every admission, the alarm only firing
  // once the counter is idle) and with re-arming at the latest expiry
  // without a minimum interval:
  //
  //   gap 45 s (20 admissions, one lifetime): alarms at 60 s, then 360,
  //     660, and 960 s (cleanup): rowsWritten 42, setAlarm 4, alarms 4.
  //     Before F1: rowsWritten 42, setAlarm 20, alarms 1. Without the
  //     interval: setAlarm 20, alarms 20.
  //   gap 90 s (10 admissions, a lifetime each): rowsWritten 40,
  //     setAlarm 10, alarms 10, deleteAll 10, as before F1.
  it.each([
    [45, { admissions: 20, rowsWritten: 42, setAlarm: 4, alarms: 4, deleteAll: 1 }],
    [90, { admissions: 10, rowsWritten: 40, setAlarm: 10, alarms: 10, deleteAll: 10 }],
  ])("sparse traffic (one request every %i s): exact writes and alarms", async (gap, expected) => {
    const stub = counter();
    const result = await runInDurableObject(stub, async (_i, state) => {
      const { storage, meter } = metered(state.storage);
      const reference = referenceLimiter(20, 60);
      let alarms = 0;
      let admissions = 0;
      const runDueAlarm = async (at: number) => {
        const due = await state.storage.getAlarm();
        if (due !== null && due <= at) {
          alarms += 1;
          await cleanupAt(storage, due);
        }
      };
      for (let now = BASE_TIME; now < BASE_TIME + 15 * 60_000; now += gap * 1000) {
        await runDueAlarm(now);
        const decision = await admitAndSchedule(storage, 20, 60, now);
        expect(decision).toEqual(reference(now));
        if (decision.allowed) admissions += 1;
      }
      for (let i = 0; i < 10 && (await state.storage.getAlarm()) !== null; i += 1) await runDueAlarm(Number.MAX_SAFE_INTEGER);
      const { rowsWritten, setAlarm, deleteAll } = meter();
      return { admissions, rowsWritten, setAlarm, alarms, deleteAll };
    });
    expect(result).toEqual(expected);
  }, 60_000);

  it("a counter busy at its limit costs under two billable writes per admission (before F1: about three)", async () => {
    const stub = counter();
    const result = await runInDurableObject(stub, async (_i, state) => {
      const { storage, meter } = metered(state.storage);
      let now = BASE_TIME;
      let admissions = 0;
      // One request per second for 10 minutes against 20 / 60 s: 200 admissions.
      for (let i = 0; i < 600; i += 1, now += 1000) {
        const due = await state.storage.getAlarm();
        if (due !== null && due <= now) await cleanupAt(storage, due);
        if ((await admitAndSchedule(storage, 20, 60, now)).allowed) admissions += 1;
      }
      return { ...meter(), admissions };
    });
    expect(result.admissions).toBe(200);
    expect(result.deleteAll).toBe(0);
    // 2 (CREATE TABLE) + 200 INSERT + the DELETEs of the 180 already expired.
    expect(result.rowsWritten).toBe(2 + 200 + 180);
    // Armed at 60 s; alarms at 60 s and 360 s re-arm (the next, 660 s, is
    // after the run): 3 setAlarm calls in 10 minutes.
    expect(result.setAlarm).toBe(3);
    expect(result.billableWrites / result.admissions).toBeLessThan(2);
  }, 60_000);
});
