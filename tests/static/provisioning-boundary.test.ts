/**
 * W1 boundaries (docs/PROVISIONING_W1.md): the provisioning foundation is
 * durable D1 coordination only. No transport, signer, route, schedule or
 * secret exists, and the migration is additive.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : /\.tsx?$/.test(name) ? [path] : [];
  });
}

const provisioning = sources("src/worker/provisioning");
const text = (file: string) => readFileSync(file, "utf8");

describe("W1 provisioning boundary", () => {
  it("has no network transport, signer or secret in the provisioning code", () => {
    expect(provisioning.length).toBeGreaterThan(0);
    for (const file of [...provisioning, "src/worker/db/provisioning-journal.ts"]) {
      const source = text(file);
      expect(source, file).not.toMatch(/\bfetch(WithTimeout)?\s*\(/);
      expect(source, file).not.toMatch(/subtle\.(sign|importKey|generateKey)\b/);
      expect(source, file).not.toMatch(/PROVISIONING_SIGNING_KEY|CF-Access-Client|\benv\./);
      expect(source, file).not.toMatch(/implements\s+ProvisioningTransport/);
    }
  });

  it("is not reachable from any HTTP route or the browser", () => {
    const offenders = [...sources("src/worker/api"), ...sources("src/worker/auth"), ...sources("src/worker/site"), ...sources("src/client"), "src/worker/index.ts"].filter((file) =>
      /provisioning\/|provisioning-journal/.test(text(file)),
    );
    expect(offenders).toEqual([]);
  });

  it("adds no scheduled handler, cron trigger or provisioning variable to the deployed Worker", () => {
    expect(text("src/worker/index.ts")).not.toMatch(/\bscheduled\b/);
    const wrangler = text("wrangler.jsonc");
    expect(wrangler).not.toMatch(/"triggers"|"crons"/);
    expect(wrangler).not.toMatch(/PROVISIONING_/);
  });

  it("migration 0003 is additive: it drops no table and replaces only the profile transition trigger", () => {
    const sql = text("migrations/0003_provisioning_journal.sql");
    expect(sql).not.toMatch(/DROP\s+TABLE|DELETE\s+FROM|ALTER\s+TABLE\s+\w+\s+(DROP|RENAME)/i);
    expect([...sql.matchAll(/DROP\s+TRIGGER\s+(\w+)/gi)].map((m) => m[1])).toEqual(["agent_profiles_status_transition"]);
    for (const match of sql.matchAll(/ALTER\s+TABLE\s+(\w+)\s+(\w+)/gi)) expect(`${match[1]} ${match[2]}`).toMatch(/ ADD$/);
  });
});
