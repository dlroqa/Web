import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditContractError, createAuditEvent, LogAuditSink, type AuditEventInput } from "../../src/worker/audit/audit";
import { createLogger } from "../../src/worker/utils/log";

afterEach(() => vi.restoreAllMocks());

const base: AuditEventInput = {
  actor: { type: "user", id: "usr_abcdef123456" },
  action: "profile.create.request",
  target: { type: "agent_profile", id: "agt_abcdef123456" },
  requestId: "req_abcdef123456",
  result: "success",
};

describe("createAuditEvent", () => {
  it("builds a complete, timestamped event with a random id", () => {
    const event = createAuditEvent({ ...base, metadata: { harnessCount: 1, retried: false } }, () => new Date("2026-10-03T12:00:00Z"));
    expect(event).toMatchObject({ ...base, timestamp: "2026-10-03T12:00:00.000Z", metadata: { harnessCount: 1, retried: false } });
    expect(event.id).toMatch(/^aud_[a-z0-9]{26}$/);
  });

  it.each(["password", "token", "sessionToken", "cookie", "clientSecret", "privateKey", "signature", "authorization", "apiKey"])(
    "rejects sensitive metadata key %s",
    (key) => {
      expect(() => createAuditEvent({ ...base, metadata: { [key]: "x" } })).toThrow(AuditContractError);
    },
  );

  it("rejects nested metadata and long strings", () => {
    expect(() => createAuditEvent({ ...base, metadata: { nested: { a: 1 } as unknown as string } })).toThrow(AuditContractError);
    expect(() => createAuditEvent({ ...base, metadata: { note: "x".repeat(201) } })).toThrow(AuditContractError);
  });

  it("rejects unknown actions, extra fields, and non-id identifiers", () => {
    expect(() => createAuditEvent({ ...base, action: "anything" as AuditEventInput["action"] })).toThrow(AuditContractError);
    expect(() => createAuditEvent({ ...base, actor: { type: "user", id: "alice@example.com" } })).toThrow(AuditContractError);
    expect(() => createAuditEvent({ ...base, ...({ headers: { cookie: "x" } } as object) })).toThrow(AuditContractError);
  });

  it("does not echo the rejected value in the error", () => {
    try {
      createAuditEvent({ ...base, metadata: { note: "s3cr3t-value".repeat(30) } });
    } catch (error) {
      expect(String(error)).not.toContain("s3cr3t");
    }
  });

  it("only accepts stable error codes as reasons", () => {
    expect(createAuditEvent({ ...base, result: "denied", reason: "FORBIDDEN" }).reason).toBe("FORBIDDEN");
    expect(() => createAuditEvent({ ...base, reason: "something bad" as "FORBIDDEN" })).toThrow(AuditContractError);
  });
});

describe("LogAuditSink", () => {
  it("records events as structured log lines", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => void lines.push(line));
    await new LogAuditSink(createLogger()).record(createAuditEvent(base));
    expect(JSON.parse(lines[0] ?? "")).toMatchObject({ event: "audit", audit: { action: "profile.create.request" } });
  });
});
