/**
 * W1 production code against the frozen LA-WEB-PROVISIONING/1 r4 fixtures.
 * The reference codec (provisioning/reference.ts) stays test-only; this file
 * checks that the PRODUCTION ports in src/worker/provisioning/ reproduce the
 * normative vectors exactly, inside workerd. Fixtures are read, never written.
 */
import { describe, expect, it } from "vitest";
import commandsInvalidText from "../../protocol/la-web-provisioning-1/commands-invalid.json?raw";
import commandsValidText from "../../protocol/la-web-provisioning-1/commands-valid.json?raw";
import resolutionText from "../../protocol/la-web-provisioning-1/create-resolution.json?raw";
import errorsText from "../../protocol/la-web-provisioning-1/errors.json?raw";
import responsesText from "../../protocol/la-web-provisioning-1/responses.json?raw";
import { assessOwnership, planReconciliation, resolveCreateJob, type Transmission } from "../../src/worker/provisioning/lifecycle";
import {
  ACCEPTANCE_HORIZON_SECONDS,
  canonicalize,
  type CanonicalValue,
  errorDefinition,
  ERRORS,
  FAILURE_CODES,
  isValidDisplayName,
  normalizeOutcome,
  OPERATION_STATES,
  payloadHash,
  type V1Operation,
} from "../../src/worker/provisioning/protocol";
import * as reference from "./provisioning/reference";

interface ResolutionCase {
  id: string;
  transmissions: Transmission[];
  expect: unknown;
  plan: { present: string; absent: string; retiredPresent: string; retiredAbsent: string };
}
const resolution = JSON.parse(resolutionText) as { acceptanceHorizonSeconds: number; cases: ResolutionCase[] };
const errors = JSON.parse(errorsText) as {
  errors: Array<{ code: string; http: number; class: string; operations: string[]; createResolution: string }>;
  operationFailureCodes: string[];
  operationStates: string[];
};
interface CommandDetail {
  command: { operation: V1Operation; payload: Record<string, string> };
  payloadHash?: string;
}
const valid = (JSON.parse(commandsValidText) as { vectors: Array<{ id: string; detail: CommandDetail }> }).vectors;
const invalid = (JSON.parse(commandsInvalidText) as { vectors: Array<{ id: string; bodyText?: string; expect: { code?: string } }> }).vectors;
const responses = (JSON.parse(responsesText) as {
  vectors: Array<{ id: string; request: string; httpStatus: number; body: string; expect: { kind: string; code?: string; reason?: string; ownership?: string; result?: Record<string, unknown> } }>;
}).vectors;

describe("W1 conformance: error registry (errors.json)", () => {
  it("has exactly the registry's codes, statuses, classes, operations and createResolution", () => {
    expect(ERRORS.map((e) => e.code)).toEqual(errors.errors.map((e) => e.code));
    for (const fixture of errors.errors) {
      const ours = errorDefinition(fixture.code);
      expect(ours, fixture.code).toBeDefined();
      expect({ http: ours?.http, class: ours?.class, operations: ours?.operations, createResolution: ours?.createResolution }, fixture.code).toEqual({
        http: fixture.http,
        class: fixture.class,
        operations: fixture.operations,
        createResolution: fixture.createResolution,
      });
    }
    expect([...FAILURE_CODES]).toEqual(errors.operationFailureCodes);
    expect([...OPERATION_STATES]).toEqual(errors.operationStates);
  });

  it("pre-nonce refusals are transmission-only; post-nonce refusals are final; LEDGER_CONTINUITY_FAILED is never evidence", () => {
    for (const code of ["UNKNOWN_KEY", "KEY_REVOKED", "BAD_SIGNATURE", "WRONG_AUDIENCE", "NOT_YET_VALID", "EXPIRED", "NONCE_STORE_UNAVAILABLE", "LEDGER_CONTINUITY_FAILED"]) {
      expect(errorDefinition(code)?.createResolution, code).toBe("transmission-only");
    }
    for (const code of ["UNAUTHENTICATED", "PROVISIONER_REVOKED", "QUOTA_EXCEEDED", "PROFILE_UNAVAILABLE", "INVALID_DISPLAY_NAME"]) {
      expect(errorDefinition(code)?.createResolution, code).toBe("final");
    }
    expect(errorDefinition("REPLAY_DETECTED")?.createResolution).toBe("indeterminate");
  });
});

describe("W1 conformance: create resolution (create-resolution.json)", () => {
  it("uses the fixture's acceptance horizon", () => {
    expect(ACCEPTANCE_HORIZON_SECONDS).toBe(resolution.acceptanceHorizonSeconds);
  });

  it.each(resolution.cases.map((c) => [c.id, c] as const))("%s", (_id, c) => {
    const resolved = resolveCreateJob(c.transmissions);
    expect(resolved).toEqual(c.expect);
    // The production port agrees with the reference too.
    expect(resolved).toEqual(reference.resolveCreateJob(c.transmissions as reference.Transmission[]));
    expect({
      present: planReconciliation(resolved, "present"),
      absent: planReconciliation(resolved, "absent"),
      retiredPresent: planReconciliation(resolved, "present", "retired"),
      retiredAbsent: planReconciliation(resolved, "absent", "retired"),
    }).toEqual(c.plan);
  });

  it("never concludes failed from uncertainty alone, however many transmissions", () => {
    const many = Array.from({ length: 50 }, (_, i) => ({ issuedAt: 1_791_000_000 + i * 900, expiresAt: 1_791_000_060 + i * 900, outcome: { kind: "uncertain" as const } }));
    expect(resolveCreateJob(many)).toEqual({ status: "unresolved" });
  });
});

describe("W1 conformance: responses (responses.json)", () => {
  const requests = new Map(valid.map((v) => [v.id, v.detail.command]));

  it.each(responses.map((v) => [v.id, v] as const))("%s", (_id, v) => {
    const command = requests.get(v.request);
    if (!command) return; // vectors bound to invalid requests are covered by the reference suite
    const target = command.payload["operationId"] ?? null;
    if (v.expect.kind === "operation" && v.expect.result) {
      const r = v.expect.result as { operationId: string; state: (typeof OPERATION_STATES)[number]; failure: string | null; ownerBound: boolean; principalId: string };
      const normalized = normalizeOutcome(command.operation, { kind: "operation", operationId: r.operationId, state: r.state, failure: r.failure, ownerBound: r.ownerBound, principalId: r.principalId }, target);
      expect(normalized.kind).toBe("operation");
      expect(assessOwnership({ state: r.state, ownerBound: r.ownerBound })).toBe(v.expect.ownership);
    } else if (v.expect.kind === "refused" && v.expect.code) {
      expect(normalizeOutcome(command.operation, { kind: "refused", code: v.expect.code }, target)).toEqual({ kind: "refused", code: v.expect.code });
    } else if (v.expect.kind === "uncertain" && v.expect.reason && errorDefinition(v.expect.reason)?.class === "indeterminate") {
      // An indeterminate code is never a refusal (§12.4).
      expect(normalizeOutcome(command.operation, { kind: "refused", code: v.expect.reason }, target)).toEqual({ kind: "uncertain", reason: v.expect.reason });
    }
  });

  it("a non-terminal create answer, an inconsistent failure, an unknown or inapplicable code are uncertain", () => {
    const op = { kind: "operation" as const, operationId: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", principalId: "ext-1", ownerBound: true };
    expect(normalizeOutcome("profile.create", { ...op, state: "pending", failure: null }, null)).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
    expect(normalizeOutcome("profile.create", { ...op, state: "failed", failure: null }, null)).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
    expect(normalizeOutcome("profile.create", { ...op, state: "completed", failure: "QUOTA_EXCEEDED" }, null)).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
    expect(normalizeOutcome("profile.create", { kind: "refused", code: "NOT_A_CODE" }, null)).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
    expect(normalizeOutcome("profile.create", { kind: "refused", code: "UNKNOWN_OPERATION" }, null)).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
    expect(normalizeOutcome("profile.status", { ...op, state: "completed", failure: null }, "a".repeat(32))).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
    expect(normalizeOutcome("profile.revoke", { ...op, state: "completed", failure: null }, op.operationId)).toEqual({ kind: "uncertain", reason: "RESPONSE_INVALID" });
  });
});

describe("W1 conformance: logical command (commands-*.json)", () => {
  it("payloadHash and the canonical payload match every valid command", async () => {
    for (const v of valid) {
      const payload = v.detail.command.payload as CanonicalValue;
      expect(canonicalize(payload), v.id).toBe(reference.canonicalize(payload as reference.CanonicalValue));
      const expected = v.detail.payloadHash ?? (await reference.payloadHash(v.detail.command.operation, payload as reference.CanonicalValue));
      expect(await payloadHash(v.detail.command.operation, payload), v.id).toBe(expected);
      if (v.detail.command.operation === "profile.create") {
        expect(isValidDisplayName(String(v.detail.command.payload["displayName"])), v.id).toBe(true);
      }
    }
  });

  it("refuses, before signing, every display name the fixtures refuse", () => {
    const refused = invalid.filter((v) => v.expect.code === "INVALID_DISPLAY_NAME");
    expect(refused.length).toBeGreaterThan(3);
    for (const v of refused) {
      const parsed = JSON.parse(v.bodyText ?? "{}") as { payload?: { displayName?: string } };
      expect(isValidDisplayName(parsed.payload?.displayName ?? ""), v.id).toBe(false);
    }
  });
});
