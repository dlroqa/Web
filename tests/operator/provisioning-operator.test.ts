/**
 * W1 operator commands: harness retirement, replacement approval, hold
 * release and the attention list. Every change is audited (denials too) and
 * output is sanitized: ids, states and codes, never payloads or emails.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { parseArgs, runOperatorCommand } from "../../src/operator/cli";
import { OperatorService } from "../../src/operator/service";
import { randomId } from "../../src/worker/utils/random";
import { activeHarness, coordinator, openCreate, TEST_KEY_ID } from "../helpers/provisioning";

const OPERATOR_ID = "opr_testoperator1";
const OPERATOR = { kind: "operator", operatorId: OPERATOR_ID, channel: "cli" } as const;
const REASON = "W1 operator test";

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, sink: { out: (t: string) => void out.push(t), err: (t: string) => void err.push(t) } };
}

const audit = async (requestId: string) =>
  (await env.DB.prepare(`SELECT action, result, reason, target_id, details_json FROM audit_events WHERE request_id = ?1 ORDER BY timestamp`).bind(requestId).all<Record<string, unknown>>()).results;

describe("provisioning operator commands", () => {
  it("retire-harness requires a reason code and --yes, then retires once, audited", async () => {
    const harness = await activeHarness();
    const noYes = io();
    expect(await runOperatorCommand(parseArgs(["retire-harness", "--harness", harness.id, "--code", "LEDGER_LOST", "--reason", REASON]), env.DB, noYes.sink, OPERATOR_ID)).toBe(1);
    expect(JSON.parse(noYes.err.join(""))).toMatchObject({ error: { code: "CONFIRMATION_REQUIRED" } });
    const badCode = io();
    expect(await runOperatorCommand(parseArgs(["retire-harness", "--harness", harness.id, "--code", "WHATEVER", "--reason", REASON, "--yes"]), env.DB, badCode.sink, OPERATOR_ID)).toBe(1);

    const operationId = randomId("op");
    const ok = io();
    expect(await runOperatorCommand(parseArgs(["retire-harness", "--harness", harness.id, "--code", "LEDGER_LOST", "--reason", REASON, "--yes", "--operation", operationId]), env.DB, ok.sink, OPERATOR_ID)).toBe(0);
    expect(JSON.parse(ok.out.join(""))).toMatchObject({ ok: true, result: { harnessId: harness.id, operationId } });
    const [event] = await audit(operationId);
    expect(event).toMatchObject({ action: "admin.harness.retire", result: "success", target_id: harness.id });
    expect(JSON.parse(String(event?.["details_json"]))).toMatchObject({ code: "LEDGER_LOST", from: "active", channel: "cli" });

    const again = randomId("op");
    expect(await new OperatorService(env.DB).retireHarness(OPERATOR, { harnessId: harness.id, reasonCode: "LEDGER_LOST", reason: REASON, confirm: true, operationId: again }).catch((e: { code: string }) => e.code)).toBe("CONFLICT");
    expect(await audit(again)).toMatchObject([{ action: "admin.harness.retire", result: "denied", reason: "CONFLICT" }]);
  });

  it("approve-harness-replacement only links a disabled new id to a retired one", async () => {
    const service = new OperatorService(env.DB);
    const old = await activeHarness();
    const replacement = await activeHarness();
    await expect(service.approveHarnessReplacement(OPERATOR, { retiredHarnessId: old.id, replacementHarnessId: replacement.id, reason: REASON, confirm: true })).rejects.toMatchObject({ code: "CONFLICT" }); // old not retired
    await service.retireHarness(OPERATOR, { harnessId: old.id, reasonCode: "DECOMMISSIONED", reason: REASON, confirm: true });
    await expect(service.approveHarnessReplacement(OPERATOR, { retiredHarnessId: old.id, replacementHarnessId: replacement.id, reason: REASON, confirm: true })).rejects.toMatchObject({ code: "CONFLICT" }); // replacement active
    const { harnesses } = await import("../helpers/db");
    await harnesses().setStatusAdmin(replacement.id, "disabled");
    await expect(service.approveHarnessReplacement(OPERATOR, { retiredHarnessId: old.id, replacementHarnessId: replacement.id, reason: REASON, confirm: false })).rejects.toMatchObject({ code: "CONFIRMATION_REQUIRED" });
    await expect(service.approveHarnessReplacement(OPERATOR, { retiredHarnessId: old.id, replacementHarnessId: replacement.id, reason: REASON, confirm: true })).resolves.toMatchObject({ retiredHarnessId: old.id });
  });

  it("release-harness-hold refuses when there is no hold; provisioning-attention lists ids and codes only", async () => {
    const service = new OperatorService(env.DB);
    const harness = await activeHarness();
    await expect(service.releaseHarnessHold(OPERATOR, { harnessId: harness.id, reason: REASON })).rejects.toMatchObject({ code: "CONFLICT" });

    const c = coordinator();
    const { jobId, harness: h } = await openCreate(c);
    const t = await c.claim(jobId, { keyId: TEST_KEY_ID, automatic: false });
    if (!t) throw new Error("claim");
    await c.record(t, { kind: "refused", code: "LEDGER_CONTINUITY_FAILED" });
    await c.reconcileJob(jobId);
    const { out, sink } = io();
    expect(await runOperatorCommand(parseArgs(["provisioning-attention", "--harness", h.id]), env.DB, sink, OPERATOR_ID)).toBe(0);
    const printed = out.join("");
    const parsed = JSON.parse(printed) as { result: { harness: Record<string, unknown>; jobs: Array<Record<string, unknown>> } };
    expect(parsed.result.harness).toMatchObject({ id: h.id, provisioning_hold: "LEDGER_CONTINUITY_FAILED", unresolved_jobs: 1, attention_jobs: 1 });
    expect(parsed.result.jobs).toMatchObject([{ id: jobId, attention_code: "LEDGER_CONTINUITY_FAILED", mode: "paused", transmissions: 1 }]);
    expect(printed).not.toMatch(/payload|displayName|idempotency|nonce|@/);
    await expect(service.releaseHarnessHold(OPERATOR, { harnessId: h.id, reason: REASON })).resolves.toMatchObject({ harnessId: h.id });
  });

  it("only operators can run provisioning commands", async () => {
    const service = new OperatorService(env.DB);
    const harness = await activeHarness();
    await expect(service.retireHarness({ kind: "user", userProfileId: "usr_someone000000" }, { harnessId: harness.id, reasonCode: "LEDGER_LOST", reason: REASON, confirm: true })).rejects.toThrow(/operator/);
    await expect(service.provisioningAttention({ kind: "system", component: "cleanup" })).rejects.toThrow(/operator/);
  });
});
