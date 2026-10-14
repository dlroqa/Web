/**
 * LA-WEB-PROVISIONING/1 shared fixtures, executed inside workerd (the Worker
 * runtime), so Ed25519, SHA-256, UTF-8 and Unicode normalization are the ones
 * the Worker will use. Fixtures: protocol/la-web-provisioning-1/. Spec:
 * docs/PROVISIONING_PROTOCOL.md.
 */
import { describe, expect, it } from "vitest";
import commandsInvalidText from "../../protocol/la-web-provisioning-1/commands-invalid.json?raw";
import commandsValidText from "../../protocol/la-web-provisioning-1/commands-valid.json?raw";
import resolutionText from "../../protocol/la-web-provisioning-1/create-resolution.json?raw";
import errorsText from "../../protocol/la-web-provisioning-1/errors.json?raw";
import executionDeadlineText from "../../protocol/la-web-provisioning-1/execution-deadline.json?raw";
import ledgerContinuityText from "../../protocol/la-web-provisioning-1/ledger-continuity.json?raw";
import orderingText from "../../protocol/la-web-provisioning-1/ordering-model.json?raw";
import keysText from "../../protocol/la-web-provisioning-1/keys.json?raw";
import redeliveryText from "../../protocol/la-web-provisioning-1/redelivery.json?raw";
import responsesText from "../../protocol/la-web-provisioning-1/responses.json?raw";
import {
  ACCEPTANCE_HORIZON_SECONDS,
  assessOwnership,
  canonicalize,
  checkExecutionDeadline,
  checkLedgerContinuity,
  type ContinuityInput,
  type CanonicalValue,
  classifyResponse,
  type Command,
  ERRORS,
  FAILURE_CODES,
  fromBase64Url,
  fromHex,
  isValidDisplayName,
  isValidRedelivery,
  OPERATION_STATES,
  type Operation,
  parseStrictJson,
  payloadHash,
  type OrderingScenario,
  planReconciliation,
  PROTOCOL,
  RULE_SETS,
  simulateOrdering,
  type RaceAttempt,
  type RaceScenario,
  resolveCreateJob,
  simulateCreateRace,
  SIGNING_CONTEXT,
  toBase64Url,
  toHex,
  type Transmission,
  utf8,
  verifyCommand,
  type VerifierState,
} from "./provisioning/reference";

interface Vector {
  id: string;
  verifier: string;
  now: number;
  seenNonces: string[];
  bodyHex: string;
  bodyText?: string;
  expect: { ok: true } | { ok: false; code: string; http: number };
  detail?: {
    command: Record<string, CanonicalValue>;
    canonicalJson: string;
    signingInputHex: string;
    signature: string;
    signedBy: string;
    payloadHash: string;
  };
}

const keys = JSON.parse(keysText) as {
  keys: Array<{ name: string; keyId: string; seedHex: string; publicKey: string; publicKeyHex: string }>;
  verifierStates: Record<string, Omit<VerifierState, "now" | "seenNonces">>;
  constants: { signingContextHex: string };
};
const valid = (JSON.parse(commandsValidText) as { vectors: Vector[] }).vectors;
const invalid = (JSON.parse(commandsInvalidText) as { vectors: Vector[] }).vectors;
const redelivery = JSON.parse(redeliveryText) as {
  logicalCommands: Array<{ operation: Operation; payloadHash: string; transmissions: string[] }>;
  notARedelivery: { command: Record<string, CanonicalValue>; payloadHash: string };
  vectors: Vector[];
};
const responses = (JSON.parse(responsesText) as { vectors: Array<{ id: string; request: string; httpStatus: number; body: string; expect: unknown }> }).vectors;
const resolution = (JSON.parse(resolutionText) as { cases: Array<{ id: string; transmissions: Transmission[]; expect: unknown }> }).cases;
const registry = JSON.parse(errorsText) as { errors: unknown; operationFailureCodes: unknown; operationStates: unknown };

/** The command a valid vector sent, as Web would hold it. */
const sent = (id: string): Command => {
  const v = valid.find((x) => x.id === id);
  return { ...v?.detail?.command, signature: v?.detail?.signature } as unknown as Command;
};

const stateFor = (v: Vector): VerifierState => {
  const base = keys.verifierStates[v.verifier];
  if (!base) throw new Error(`unknown verifier ${v.verifier}`);
  return { ...base, now: v.now, seenNonces: v.seenNonces };
};

/** A Web-Crypto-only check that does not use the reference signing helpers. */
async function independentlyVerified(publicKey: string, signature: string, canonicalJson: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", fromBase64Url(publicKey) as Uint8Array, { name: "Ed25519" }, false, ["verify"]);
  const message = new Uint8Array([...utf8(`${PROTOCOL}\u0000provisioning-command\u0000`), ...utf8(canonicalJson)]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, fromBase64Url(signature) as Uint8Array, message);
}

describe("LA-WEB-PROVISIONING/1 keys", () => {
  it.each(keys.keys)("$name: public key matches its seed (workerd Ed25519)", async (k) => {
    const pkcs8 = fromHex(`302e020100300506032b657004220420${k.seedHex}`);
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    const jwk = (await crypto.subtle.exportKey("jwk", key)) as { x?: string };
    expect(jwk.x).toBe(k.publicKey);
    expect(toHex(fromBase64Url(k.publicKey) as Uint8Array)).toBe(k.publicKeyHex);
  });

  it("states the signing context bytes", () => {
    expect(keys.constants.signingContextHex).toBe(toHex(SIGNING_CONTEXT));
    expect(keys.constants.signingContextHex).toBe("4c412d5745422d50524f564953494f4e494e472f310070726f766973696f6e696e672d636f6d6d616e6400");
  });
});

describe("valid commands", () => {
  it.each([...valid, ...redelivery.vectors.filter((v) => v.expect.ok)])("$id verifies", async (v) => {
    const body = fromHex(v.bodyHex);
    if (v.bodyText !== undefined) expect(toHex(utf8(v.bodyText))).toBe(v.bodyHex);
    const result = await verifyCommand(body, stateFor(v));
    expect(result).toMatchObject({ ok: true });

    const detail = v.detail;
    if (!detail) throw new Error("valid vectors carry detail");
    expect(canonicalize(detail.command)).toBe(detail.canonicalJson);
    expect(toHex(new Uint8Array([...SIGNING_CONTEXT, ...utf8(detail.canonicalJson)]))).toBe(detail.signingInputHex);
    // The wire body is the canonical form of the command plus its signature.
    expect(canonicalize({ ...detail.command, signature: detail.signature })).toBe(new TextDecoder().decode(body));
    // Ed25519 is deterministic: re-signing in workerd reproduces the fixture signature.
    const seed = keys.keys.find((k) => k.name === detail.signedBy)?.seedHex as string;
    const key = await crypto.subtle.importKey("pkcs8", fromHex(`302e020100300506032b657004220420${seed}`), { name: "Ed25519" }, false, ["sign"]);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, fromHex(detail.signingInputHex)));
    expect(toBase64Url(signature)).toBe(detail.signature);
    const publicKey = keys.keys.find((k) => k.name === detail.signedBy)?.publicKey as string;
    expect(await independentlyVerified(publicKey, detail.signature, detail.canonicalJson)).toBe(true);
    expect(await payloadHash(detail.command.operation as Operation, detail.command.payload as CanonicalValue)).toBe(detail.payloadHash);
  });
});

describe("invalid commands", () => {
  it.each([...invalid, ...redelivery.vectors.filter((v) => !v.expect.ok)])("$id → $expect.code", async (v) => {
    if (v.bodyText !== undefined) expect(toHex(utf8(v.bodyText))).toBe(v.bodyHex);
    const result = await verifyCommand(fromHex(v.bodyHex), stateFor(v));
    expect(v.expect.ok).toBe(false);
    expect(result).toEqual({ ok: false, code: (v.expect as { code: string }).code });
    const registered = ERRORS.find((e) => e.code === (v.expect as { code: string }).code);
    expect(registered?.http).toBe((v.expect as { http: number }).http);
  });

  it("covers every mandatory negative category", () => {
    const codes = new Set(invalid.map((v) => (v.expect as { code: string }).code));
    for (const code of [
      "DUPLICATE_KEY", "UNKNOWN_FIELD", "INVALID_JSON_VALUE", "INVALID_FIELD", "MALFORMED_JSON", "NON_CANONICAL",
      "BAD_SIGNATURE", "WRONG_AUDIENCE", "WRONG_PURPOSE", "UNKNOWN_KEY", "KEY_REVOKED", "EXPIRED", "NOT_YET_VALID",
      "PAYLOAD_TOO_LARGE", "INVALID_DISPLAY_NAME", "UNSUPPORTED_OPERATION", "REPLAY_DETECTED", "UNSUPPORTED_PROTOCOL",
    ]) {
      expect(codes, code).toContain(code);
    }
    const ids = invalid.map((v) => v.id);
    for (const id of [
      "duplicate-top-level", "duplicate-nested", "display-name-65", "display-name-81", "forbidden-profile-disable",
      "forbidden-profile-enable", "forbidden-payload-permissions", "forbidden-payload-workspace-path",
      "forbidden-payload-model-url", "cross-harness-a-to-b", "key-rotated-away", "oversized-8193",
    ]) {
      expect(ids).toContain(id);
    }
  });

  it("parses what JSON.parse silently accepts as a duplicate", () => {
    const text = '{"a":1,"a":2}';
    expect(JSON.parse(text)).toEqual({ a: 2 });
    expect(parseStrictJson(utf8(text))).toEqual({ ok: false, code: "DUPLICATE_KEY" });
  });

  it("counts display names in Unicode scalar values, not UTF-16 units", () => {
    expect("🤖".repeat(64).length).toBe(128);
    expect(isValidDisplayName("🤖".repeat(64))).toBe(true);
    expect(isValidDisplayName("🤖".repeat(65))).toBe(false);
  });
});

describe("redelivery", () => {
  const byId = (id: string) => redelivery.vectors.find((v) => v.id === id);
  const asCommand = (v: Vector | undefined) => ({ ...v?.detail?.command, signature: v?.detail?.signature }) as unknown as Command;

  it.each(redelivery.logicalCommands)("$operation transmissions keep one logical identity", async (logical) => {
    const [first, ...rest] = logical.transmissions.map(byId);
    for (const t of [first, ...rest]) expect(t?.detail?.payloadHash).toBe(logical.payloadHash);
    for (const later of rest) expect(isValidRedelivery(asCommand(first), asCommand(later))).toBe(true);
  });

  it("a changed payload under the same key is not a redelivery", async () => {
    const changed = redelivery.notARedelivery;
    expect(await payloadHash("profile.create", changed.command.payload as CanonicalValue)).toBe(changed.payloadHash);
    expect(changed.payloadHash).not.toBe(redelivery.logicalCommands[0]?.payloadHash);
  });
});

describe("responses", () => {
  it.each(responses)("$id", (r) => {
    const outcome = classifyResponse(r.httpStatus, utf8(r.body), sent(r.request));
    const ownership = outcome.kind === "operation" ? { ownership: assessOwnership(outcome.result) } : {};
    expect({ ...outcome, ...ownership }).toEqual(r.expect);
  });

  it("accepts every ownerBound value with every state (RC2)", () => {
    const command = sent("valid-status-basic");
    for (const state of OPERATION_STATES) {
      for (const ownerBound of [true, false]) {
        const body = JSON.stringify({
          protocol: PROTOCOL, commandId: command.commandId, audience: command.audience, operation: command.operation,
          result: {
            operationId: (command.payload as { operationId: string }).operationId, state, failure: state === "failed" ? "INVALID_TEMPLATE" : null,
            principalId: "ext-0", profileId: command.payload.profileId, template: "assistant", ownerBound, createdUnix: 1791000001, updatedUnix: 1791000001,
          },
        });
        expect(classifyResponse(200, utf8(body), command).kind, `${state}/${ownerBound}`).toBe("operation");
      }
    }
  });
});

describe("create resolution", () => {
  it.each(resolution)("$id", (c) => {
    const resolved = resolveCreateJob(c.transmissions);
    expect(resolved).toEqual(c.expect);
    expect({
      present: planReconciliation(resolved, "present"),
      absent: planReconciliation(resolved, "absent"),
      retiredPresent: planReconciliation(resolved, "present", "retired"),
      retiredAbsent: planReconciliation(resolved, "absent", "retired"),
    }).toEqual(
      (c as unknown as { plan: unknown }).plan,
    );
  });

  it("never turns exhausted retries into failed", () => {
    const timeouts: Transmission[] = Array.from({ length: 1000 }, (_, i) => ({
      issuedAt: 1_791_000_000 + i * 600,
      expiresAt: 1_791_000_060 + i * 600,
      outcome: { kind: "uncertain" },
    }));
    expect(resolveCreateJob(timeouts)).toEqual({ status: "unresolved" });
  });
});

describe("execution deadline (§10 step 14)", () => {
  const fixture = JSON.parse(executionDeadlineText) as {
    deadlineCases: Array<{ id: string; lockAcquiredAt: number; executionDeadline: number; fence: number; expect: string }>;
    races: Array<{ id: string; scenario: Omit<RaceScenario, "executionDeadlineCheck">; withExecutionDeadline: unknown; withoutExecutionDeadline: unknown }>;
  };
  const command = sent("valid-create-basic");

  it.each(fixture.deadlineCases)("$id → $expect", (c) => {
    expect(c.executionDeadline).toBe(command.expiresAt + 30);
    expect(checkExecutionDeadline(command, c.lockAcquiredAt, c.fence)).toBe(c.expect);
  });

  it.each(fixture.races)("$id", (r) => {
    expect(simulateCreateRace({ ...r.scenario, executionDeadlineCheck: true })).toEqual(r.withExecutionDeadline);
    expect(simulateCreateRace({ ...r.scenario, executionDeadlineCheck: false })).toEqual(r.withoutExecutionDeadline);
    expect((r.withExecutionDeadline as { unsafe: boolean }).unsafe).toBe(false);
  });

  it("the lock-wait race is unsafe exactly when step 14 is missing", () => {
    const race = fixture.races.find((r) => r.id === "lock-wait-race");
    expect((race?.withoutExecutionDeadline as { unsafe: boolean }).unsafe).toBe(true);
  });

  it("never lets Web conclude failed while an operation exists, over random schedules", () => {
    // Deterministic PRNG (mulberry32) so failures reproduce.
    let seed = 0x5eed_2026;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (max: number) => Math.floor(rand() * (max + 1));
    const T0 = 1_791_000_000;
    let unsafeWithout = 0;
    for (let run = 0; run < 20_000; run += 1) {
      const skew = int(60) - 30;
      let issuedAt = T0;
      const drafts = Array.from({ length: 1 + int(3) }, () => {
        issuedAt += int(4) === 0 ? 0 : int(250);
        const admittedAt = int(9) === 0 ? null : issuedAt + skew + int(160);
        return { issuedAt, expiresAt: issuedAt + 60, admittedAt, wait: int(3) === 0 ? int(400) : int(5), hold: int(120), lost: int(1) === 0, crash: int(9) === 0 };
      });
      // Serialize lock acquisition, as the ledger lock does.
      let lockFreeAt = -Infinity;
      const attempts: RaceAttempt[] = drafts
        .map((d, i) => ({ d, i }))
        .sort((a, b) => ((a.d.admittedAt ?? Infinity) + a.d.wait) - ((b.d.admittedAt ?? Infinity) + b.d.wait))
        .map(({ d, i }) => {
          if (d.admittedAt === null) return { i, a: { issuedAt: d.issuedAt, expiresAt: d.expiresAt, admittedAt: null, responseLost: d.lost } };
          const lockAcquiredAt = Math.max(d.admittedAt + d.wait, lockFreeAt + 1);
          lockFreeAt = lockAcquiredAt + d.hold;
          return { i, a: { issuedAt: d.issuedAt, expiresAt: d.expiresAt, admittedAt: d.admittedAt, lockAcquiredAt, releasedAt: lockFreeAt, responseLost: d.lost, crashAfterRecord: d.crash } };
        })
        .sort((x, y) => x.i - y.i)
        .map(({ a }) => a);
      const from = T0 + int(600);
      const scenario = { attempts, quotaAvailable: int(2) === 0 ? [] : ([[from, from + int(600)]] as Array<[number, number]>) };
      const safe = simulateCreateRace({ ...scenario, executionDeadlineCheck: true });
      if (safe.unsafe) throw new Error(`unsafe schedule with step 14: ${JSON.stringify(scenario)}`);
      if (simulateCreateRace({ ...scenario, executionDeadlineCheck: false }).unsafe) unsafeWithout += 1;
    }
    expect(unsafeWithout).toBeGreaterThan(0);
    expect(ACCEPTANCE_HORIZON_SECONDS).toBe(60);
  });
});

describe("ordering model (§13.2, RC5, RC6)", () => {
  const fixture = JSON.parse(orderingText) as {
    ruleSets: unknown;
    scenarios: Array<{ id: string; scenario: OrderingScenario; results: Record<string, { unsafe: boolean }> }>;
  };

  it("uses the reference rule sets", () => {
    expect(fixture.ruleSets).toEqual(JSON.parse(JSON.stringify(RULE_SETS)));
  });

  it.each(fixture.scenarios)("$id reproduces under every rule set", (s) => {
    for (const [name, rules] of Object.entries(RULE_SETS)) {
      expect(JSON.parse(JSON.stringify(simulateOrdering(s.scenario, rules))), name).toEqual(s.results[name]);
    }
    // r3 is unsafe only on the RC7 recovery scenarios; r4 (this revision) is safe on all.
    expect(s.results.r4?.unsafe, "r4 must be safe").toBe(false);
  });

  it("each counterexample is defeated by exactly the r3 rule it targets", () => {
    const unsafe = (id: string) =>
      Object.entries(fixture.scenarios.find((s) => s.id === id)?.results ?? {}).filter(([, r]) => r.unsafe).map(([name]) => name).sort();
    expect(unsafe("backward-step-while-waiting")).toEqual(["r2", "r3-without-fence"]);
    expect(unsafe("fence-visible-only-after-unlock")).toEqual(["r2", "r3-fence-durable-only-after-unlock", "r3-without-fence", "reviewProposal"]);
    expect(unsafe("duplicate-of-refused-command-after-restart")).toEqual(["r2", "r3-without-durable-nonces", "reviewProposal"]);
    expect(unsafe("duplicate-after-clock-purge-and-rollback")).toEqual(["r2", "r3-nonces-discarded-by-clock", "reviewProposal"]);
    expect(unsafe("pre-nonce-refusal-then-duplicate")).toEqual(["r2", "r3-protocol-refusals-final", "reviewProposal"]);
    expect(unsafe("unjournaled-transmission")).toEqual(["r2", "r3-without-journal"]);
  });

  it("RC7: r4 resolves ledger discontinuity, and each r4 layer is needed somewhere", () => {
    const results = (id: string) => fixture.scenarios.find((s) => s.id === id)?.results ?? {};
    const unsafe = (id: string) => Object.entries(results(id)).filter(([, r]) => r.unsafe).map(([name]) => name);
    // r3's restore rule loses; every r4 rule set is safe on the canonical case (two independent layers).
    for (const id of ["fresh-ledger-retained-identity", "ledger-restored-older-than-identity"]) {
      expect(unsafe(id), id).toContain("r3");
      expect(unsafe(id).filter((n) => n.startsWith("r4")), id).toEqual([]);
    }
    // Only the harness's continuity check stops a fresh ledger that answers on quota.
    expect(unsafe("fresh-ledger-quota-refusal").filter((n) => n.startsWith("r4"))).toEqual(["r4-without-continuity-check"]);
    // Partial nonce or fence restores are excluded by the restore's fence raise.
    for (const id of ["nonces-restored-alone", "fence-restored-alone"]) {
      expect(unsafe(id).filter((n) => n.startsWith("r3") || n.startsWith("r4")).sort(), id).toEqual(["r3-without-fence", "r4-restore-without-fence-raise"]);
    }
    expect(unsafe("consistent-restore-of-all-stores")).toEqual([]);
    expect(unsafe("identity-restored-older-than-ledger")).toEqual([]);
    // Fail closed, no duplicate binding, no removed binding, never failed.
    const r4 = results("fresh-ledger-retained-identity").r4 as unknown as {
      failedClosed: boolean; binding: { createdBy: number } | null; web: { status: string }; answers: string[];
    };
    expect(r4.failedClosed).toBe(true);
    expect(r4.binding).toEqual({ createdBy: 0 });
    expect(r4.answers).toEqual(["OPERATION:completed", "LEDGER_CONTINUITY_FAILED"]);
    expect(r4.web).toEqual({ status: "attention", code: "LEDGER_CONTINUITY_FAILED" });
  });

  /**
   * Seeded randomized schedules. Assumptions (all within what r3 permits or
   * must survive): 1–4 transmissions of one job, lifetime 60 s, gaps 0–250 s
   * (overlapping windows and out-of-order arrival included); 0–2 copies per
   * transmission (loss and duplication), arrival delays up to 400 s, lock
   * waits up to 300 s, lock holds up to 200 s (completion after expiry);
   * harness clock offset ±30 s plus up to two steps of ±90 s (rollback while
   * waiting); restarts (queued calls die, non-durable state lost);
   * housekeeping; a key trusted only later; quota windows; crashes after
   * record; lost answers; unjournaled sends (only matter without RC6).
   * Not modelled: forged responses (§12.1), harness compromise, several
   * ledgers behind one harness id (excluded by assumption A1).
   */
  it("finds no unsafe schedule under r3, and counterexamples without each rule", () => {
    const SEED = 0x7a3c_2026;
    const RUNS = 30_000;
    let state = SEED;
    const rand = () => {
      state = (state + 0x6d2b79f5) | 0;
      let t = Math.imul(state ^ (state >>> 15), 1 | state);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (max: number) => Math.floor(rand() * (max + 1));
    const T0 = 1_791_000_000;
    const unsafe: Record<string, number> = Object.fromEntries(Object.keys(RULE_SETS).map((k) => [k, 0]));
    let firstR3Failure: OrderingScenario | null = null;
    for (let run = 0; run < RUNS; run += 1) {
      let issued = T0;
      const transmissions = Array.from({ length: 1 + int(3) }, () => {
        // A third of the gaps put the next transmission at the previous one's horizon (R3's case).
        const kind = int(2);
        issued += kind === 0 ? int(30) : kind === 1 ? 120 + int(10) : int(250);
        return { issuedAt: issued, expiresAt: issued + 60, journaled: int(3) !== 0 };
      });
      const drafts = transmissions.flatMap((tx, transmission) =>
        Array.from({ length: int(4) === 0 ? 0 : int(2) === 0 ? 2 : 1 }, (_, copy) => {
          const arrivesAt = tx.issuedAt + (int(3) === 0 ? int(400) : int(20));
          return {
            transmission, arrivesAt, desired: arrivesAt + (int(2) === 0 ? int(300) : int(5)), holdFor: 1 + (int(4) === 0 ? int(200) : int(3)),
            answerToWeb: copy === 0 && int(2) !== 0, crashAfterRecord: int(9) === 0,
          };
        }),
      );
      let lockFree = -Infinity;
      const deliveries = drafts
        .map((d, i) => ({ d, i }))
        .sort((a, b) => a.d.desired - b.d.desired || a.i - b.i)
        .map(({ d, i }) => {
          const lockAt = Math.max(d.desired, lockFree);
          lockFree = lockAt + d.holdFor;
          return { i, delivery: { transmission: d.transmission, arrivesAt: d.arrivesAt, lockAt, holdFor: d.holdFor, answerToWeb: d.answerToWeb, crashAfterRecord: d.crashAfterRecord } };
        })
        .sort((a, b) => a.i - b.i)
        .map(({ delivery }) => delivery);
      const harnessClock: Array<{ from: number; offset: number }> = [{ from: -Infinity, offset: int(60) - 30 }];
      for (let step = int(2); step > 0; step -= 1) harnessClock.push({ from: T0 + int(600), offset: int(180) - 90 });
      harnessClock.sort((a, b) => a.from - b.from);
      const a = T0 + int(700);
      const scenario: OrderingScenario = {
        transmissions,
        deliveries,
        harnessClock,
        quota: [[[0, Number.MAX_SAFE_INTEGER]], [[a, a + int(400)]], [[a, Number.MAX_SAFE_INTEGER]]][int(2)] as Array<[number, number]>,
        ...(int(4) === 0 ? { keyTrustedFrom: T0 + int(300) } : {}),
        restarts: int(2) === 0 ? [T0 + int(900)] : [],
        housekeeping: Array.from({ length: int(2) }, () => T0 + int(900)),
      };
      for (const [name, rules] of Object.entries(RULE_SETS)) {
        if (simulateOrdering(scenario, rules).unsafe) {
          unsafe[name] = (unsafe[name] as number) + 1;
          if (name === "r3" && firstR3Failure === null) firstR3Failure = scenario;
        }
      }
    }
    const summary = `ordering model: seed 0x${SEED.toString(16)}, ${RUNS} schedules, unsafe per rule set ${JSON.stringify(unsafe)}`;
    console.info(summary);
    if (firstR3Failure) throw new Error(`unsafe r3 schedule: ${JSON.stringify(firstR3Failure)}`);
    expect(unsafe.r3).toBe(0);
    expect(unsafe.r4).toBe(0);
    // The wall-clock check bounds normal execution; safety rests on the fence (§13.2 proof).
    expect(unsafe["r3-without-wall-clock-deadline"]).toBe(0);
    for (const name of ["r2", "reviewProposal", "r3-protocol-refusals-final", "r3-without-journal"]) {
      expect(unsafe[name], `${name} (${summary})`).toBeGreaterThan(0);
    }
  });

  /**
   * Focused hazard families, because the fence and nonce counterexamples need
   * narrow coincidences that broad schedules rarely produce.
   * - lock-wait: u admitted, then waits; t issued at u's horizon (0–4 s
   *   after) and refused on the merits; the harness is 20–30 s behind and
   *   steps back 1–10 s around t; u takes the lock at, or up to 3 s after,
   *   t's release (another process, fence persistence race); quota frees after t.
   * - duplicate: one transmission refused on the merits, then a copy of the
   *   same bytes arrives 5–80 s later after a restart and/or a forward clock
   *   jump with housekeeping followed by a return; quota frees in between.
   */
  it("finds no unsafe hazard under r3, and counterexamples for the fence and nonce rules", () => {
    const SEED = 0x5afe_0003;
    const RUNS = 25_000;
    let state = SEED;
    const rand = () => {
      state = (state + 0x6d2b79f5) | 0;
      let t = Math.imul(state ^ (state >>> 15), 1 | state);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (max: number) => Math.floor(rand() * (max + 1));
    const T0 = 1_791_000_000;
    const FOREVER = Number.MAX_SAFE_INTEGER;
    const counts = { lockWait: {} as Record<string, number>, duplicate: {} as Record<string, number> };
    for (const name of Object.keys(RULE_SETS)) {
      counts.lockWait[name] = 0;
      counts.duplicate[name] = 0;
    }
    for (let run = 0; run < RUNS; run += 1) {
      const offset = -20 - int(10);
      const tIssued = T0 + 120 + int(4);
      const tArrive = tIssued + int(3);
      const tHold = 1 + int(1);
      const uLock = tArrive + tHold + int(3);
      const lockWait: OrderingScenario = {
        transmissions: [{ issuedAt: T0, expiresAt: T0 + 60 }, { issuedAt: tIssued, expiresAt: tIssued + 60 }],
        deliveries: [
          { transmission: 0, arrivesAt: T0 + int(10), lockAt: uLock, answerToWeb: false },
          { transmission: 1, arrivesAt: tArrive, lockAt: tArrive, holdFor: tHold },
        ],
        harnessClock: [{ from: 0, offset }, { from: tArrive + int(3), offset: offset - 1 - int(9) }],
        quota: [[tArrive + 1, FOREVER]],
      };
      const jump = int(1) === 0;
      const restart = !jump || int(1) === 0;
      const dupAt = T0 + 5 + int(75);
      const duplicate: OrderingScenario = {
        transmissions: [{ issuedAt: T0, expiresAt: T0 + 60 }],
        deliveries: [
          { transmission: 0, arrivesAt: T0 + 1 },
          { transmission: 0, arrivesAt: dupAt, answerToWeb: false },
        ],
        harnessClock: jump ? [{ from: 0, offset: 0 }, { from: T0 + 2, offset: 90 + int(60) }, { from: dupAt - 1, offset: 0 }] : [{ from: 0, offset: 0 }],
        housekeeping: jump ? [T0 + 3] : [],
        restarts: restart ? [T0 + 2 + int(Math.max(0, dupAt - T0 - 3))] : [],
        quota: [[T0 + 3, FOREVER]],
      };
      for (const [name, rules] of Object.entries(RULE_SETS)) {
        if (simulateOrdering(lockWait, rules).unsafe) counts.lockWait[name] = (counts.lockWait[name] as number) + 1;
        if (simulateOrdering(duplicate, rules).unsafe) counts.duplicate[name] = (counts.duplicate[name] as number) + 1;
      }
    }
    const summary = `hazards: seed 0x${SEED.toString(16)}, ${RUNS} per family, unsafe ${JSON.stringify(counts)}`;
    console.info(summary);
    expect(counts.lockWait.r3, summary).toBe(0);
    expect(counts.lockWait.r4, summary).toBe(0);
    expect(counts.duplicate.r4, summary).toBe(0);
    expect(counts.duplicate.r3, summary).toBe(0);
    for (const name of ["r2", "reviewProposal", "r3-without-fence", "r3-fence-durable-only-after-unlock"]) {
      expect(counts.lockWait[name], `${name}: ${summary}`).toBeGreaterThan(0);
    }
    for (const name of ["r2", "reviewProposal", "r3-without-durable-nonces", "r3-nonces-discarded-by-clock"]) {
      expect(counts.duplicate[name], `${name}: ${summary}`).toBeGreaterThan(0);
    }
  });
});

describe("ledger continuity (A9, §10.6)", () => {
  const fixture = JSON.parse(ledgerContinuityText) as { cases: Array<{ id: string; input: ContinuityInput; expect: unknown }> };

  it.each(fixture.cases)("$id", (c) => {
    expect(checkLedgerContinuity(c.input)).toEqual(c.expect);
  });

  it("never serves from absence, and serves only stamped, consistent ledgers", () => {
    const serving = fixture.cases.filter((c) => (c.expect as { serve: boolean }).serve).map((c) => c.id);
    expect(serving.sort()).toEqual(["consistent", "initialized-empty", "pending-operation-without-records"]);
  });

  /**
   * Seeded recovery schedules. Assumptions: u (and sometimes a duplicate copy)
   * may complete, crash after record, or be refused; one recovery restores a
   * random non-empty subset of {ledger, identity, nonces, fence} at a random
   * time, with a fence restored to 0 or an older value; clock offset ±30 s
   * with up to one ±60 s step; 1–3 later resends at or after the horizon;
   * quota windows. Not modelled: forged answers, operator reassignment.
   */
  it("finds no unsafe recovery schedule under r4, and counterexamples without each r4 layer", () => {
    const SEED = 0x0a90_0004;
    const RUNS = 25_000;
    let state = SEED;
    const rand = () => {
      state = (state + 0x6d2b79f5) | 0;
      let t = Math.imul(state ^ (state >>> 15), 1 | state);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (max: number) => Math.floor(rand() * (max + 1));
    const T0 = 1_791_000_000;
    const FOREVER = Number.MAX_SAFE_INTEGER;
    const STORES = ["ledger", "identity", "nonces", "fence"] as const;
    const unsafe: Record<string, number> = Object.fromEntries(Object.keys(RULE_SETS).map((k) => [k, 0]));
    let firstR4Failure: OrderingScenario | null = null;
    for (let run = 0; run < RUNS; run += 1) {
      const resends = 1 + int(2);
      const transmissions = [{ issuedAt: T0, expiresAt: T0 + 60 }];
      for (let i = 0; i < resends; i += 1) {
        const issuedAt = T0 + 120 + int(300) + i * 130;
        transmissions.push({ issuedAt, expiresAt: issuedAt + 60 });
      }
      const deliveries: OrderingScenario["deliveries"][number][] = [
        { transmission: 0, arrivesAt: T0 + 1 + int(10), answerToWeb: false, crashAfterRecord: int(4) === 0 },
      ];
      if (int(3) === 0) deliveries.push({ transmission: 0, arrivesAt: T0 + 20 + int(200), answerToWeb: false });
      for (let i = 1; i <= resends; i += 1) {
        const tx = transmissions[i] as { issuedAt: number };
        deliveries.push({ transmission: i, arrivesAt: tx.issuedAt + int(5) });
      }
      // Serialize lock acquisitions in arrival order, as the ledger lock does.
      let lockFree = -Infinity;
      const ordered = deliveries.map((d, i) => ({ d, i })).sort((a, b) => a.d.arrivesAt - b.d.arrivesAt || a.i - b.i);
      for (const { d } of ordered) {
        const lockAt = Math.max(d.arrivesAt, lockFree);
        (d as { lockAt?: number }).lockAt = lockAt;
        lockFree = lockAt + 1;
      }
      const restore = STORES.filter(() => int(1) === 0);
      if (restore.length === 0) restore.push(STORES[int(3)] as (typeof STORES)[number]);
      const harnessClock: Array<{ from: number; offset: number }> = [{ from: 0, offset: int(60) - 30 }];
      if (int(1) === 0) harnessClock.push({ from: T0 + int(500), offset: int(120) - 60 });
      harnessClock.sort((a, b) => a.from - b.from);
      const q = T0 + int(500);
      const scenario: OrderingScenario = {
        transmissions,
        deliveries,
        harnessClock,
        recoveries: [{ at: T0 + 30 + int(250), restore, fenceTo: int(1) === 0 ? 0 : T0 + int(60) }],
        quota: [[[0, FOREVER]], [[0, q]], [[q, FOREVER]]][int(2)] as Array<[number, number]>,
      };
      for (const [name, rules] of Object.entries(RULE_SETS)) {
        if (simulateOrdering(scenario, rules).unsafe) {
          unsafe[name] = (unsafe[name] as number) + 1;
          if (name === "r4" && firstR4Failure === null) firstR4Failure = scenario;
        }
      }
    }
    const summary = `recovery: seed 0x${SEED.toString(16)}, ${RUNS} schedules, unsafe per rule set ${JSON.stringify(unsafe)}`;
    console.info(summary);
    if (firstR4Failure) throw new Error(`unsafe r4 schedule: ${JSON.stringify(firstR4Failure)}`);
    expect(unsafe.r4, summary).toBe(0);
    // The restore's fence raise needs a narrow duplicate/clock hazard: covered by the
    // deterministic fixtures nonces-restored-alone and fence-restored-alone.
    for (const name of ["r3", "r4-without-continuity-check"]) {
      expect(unsafe[name], `${name}: ${summary}`).toBeGreaterThan(0);
    }
  });
});

describe("error registry", () => {
  it("matches the reference", () => {
    expect(registry.errors).toEqual(JSON.parse(JSON.stringify(ERRORS)));
    expect(registry.operationFailureCodes).toEqual([...FAILURE_CODES]);
    expect(registry.operationStates).toEqual([...OPERATION_STATES]);
  });

  it("uses uppercase codes that fit provisioning_jobs.error_code", () => {
    for (const e of ERRORS) expect(e.code).toMatch(/^[A-Z0-9_]{1,64}$/);
    for (const code of FAILURE_CODES) expect(code).toMatch(/^[A-Z0-9_]{1,64}$/);
  });
});
