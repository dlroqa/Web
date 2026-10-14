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
import keysText from "../../protocol/la-web-provisioning-1/keys.json?raw";
import redeliveryText from "../../protocol/la-web-provisioning-1/redelivery.json?raw";
import responsesText from "../../protocol/la-web-provisioning-1/responses.json?raw";
import {
  ACCEPTANCE_HORIZON_SECONDS,
  assessOwnership,
  canonicalize,
  checkExecutionDeadline,
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
  PROTOCOL,
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
    expect(resolveCreateJob(c.transmissions)).toEqual(c.expect);
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
    deadlineCases: Array<{ id: string; lockAcquiredAt: number; executionDeadline: number; expect: string }>;
    races: Array<{ id: string; scenario: Omit<RaceScenario, "executionDeadlineCheck">; withExecutionDeadline: unknown; withoutExecutionDeadline: unknown }>;
  };
  const command = sent("valid-create-basic");

  it.each(fixture.deadlineCases)("$id → $expect", (c) => {
    expect(c.executionDeadline).toBe(command.expiresAt + 30);
    expect(checkExecutionDeadline(command, c.lockAcquiredAt)).toBe(c.expect);
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
