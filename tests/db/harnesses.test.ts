import { describe, expect, it } from "vitest";
import { ConstraintViolationError } from "../../src/worker/db/errors";
import { normalizeHarnessEndpoint } from "../../src/worker/db/harnesses";
import { randomId } from "../../src/worker/utils/random";
import { db, harnesses } from "../helpers/db";

const base = {
  environment: "staging" as const,
  endpoint: "https://harness.example.test/",
  keyId: "cf-staging-2026-10",
  capabilities: { protocolVersions: [1], operations: ["profile.create" as const] },
};

describe("HarnessRepository", () => {
  it("registers harnesses disabled, with validated capabilities", async () => {
    const harness = await harnesses().registerAdmin({ ...base, name: randomId("h") });
    expect(harness).toMatchObject({ status: "disabled", endpoint: "https://harness.example.test", publicKey: null });
    expect(harness.capabilities).toEqual(base.capabilities);
  });

  it("lists only active harnesses of the requested environment", async () => {
    const staging = await harnesses().registerAdmin({ ...base, name: randomId("h") });
    await harnesses().setStatusAdmin(staging.id, "active");
    const dev = await harnesses().registerAdmin({ ...base, name: randomId("h"), environment: "development" });
    await harnesses().setStatusAdmin(dev.id, "active");
    const listed = (await harnesses().listActive("staging")).map((h) => h.id);
    expect(listed).toContain(staging.id);
    expect(listed).not.toContain(dev.id);
  });

  it.each([
    ["http outside development", "http://harness.example.test", "staging"],
    ["credentials", "https://user:pass@harness.example.test", "staging"],
    ["query", "https://harness.example.test/?x=1", "staging"],
    ["fragment", "https://harness.example.test/#a", "staging"],
    ["not a url", "harness", "staging"],
    ["file scheme", "file:///etc/passwd", "development"],
  ] as const)("rejects endpoints with %s", (_label, endpoint, environment) => {
    expect(() => normalizeHarnessEndpoint(endpoint, environment)).toThrow(ConstraintViolationError);
  });

  it("allows http only for development harnesses", () => {
    expect(normalizeHarnessEndpoint("http://127.0.0.1:8735", "development")).toBe("http://127.0.0.1:8735");
  });

  it("rejects unknown or oversized capability data", async () => {
    await expect(
      harnesses().registerAdmin({ ...base, name: randomId("h"), capabilities: { ...base.capabilities, shell: true } as never }),
    ).rejects.toBeInstanceOf(ConstraintViolationError);
    await expect(
      harnesses().registerAdmin({ ...base, name: randomId("h"), capabilities: { ...base.capabilities, region: "x".repeat(40) } }),
    ).rejects.toBeInstanceOf(ConstraintViolationError);
  });

  it("the database also refuses non-https endpoints and oversized capabilities", async () => {
    const insert = (endpoint: string, capabilities: string) =>
      db()
        .prepare(`INSERT INTO harnesses (id, name, environment, endpoint, key_id, capabilities_json, created_at, updated_at) VALUES (?1, ?2, 'production', ?3, 'k', ?4, 1, 1)`)
        .bind(randomId("hns"), randomId("h"), endpoint, capabilities)
        .run();
    await expect(insert("http://harness.example.test", "{}")).rejects.toThrow(/CHECK/);
    await expect(insert("https://harness.example.test", JSON.stringify({ x: "y".repeat(3000) }))).rejects.toThrow(/CHECK/);
  });

  it("has no column for private keys or network credentials", async () => {
    const { results } = await db().prepare(`SELECT name FROM pragma_table_info('harnesses')`).all<{ name: string }>();
    const columns = results.map((r) => r.name);
    expect(columns.some((c) => /private|secret|token|password|credential/i.test(c))).toBe(false);
  });
});
