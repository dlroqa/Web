import { env } from "cloudflare:test";
import { AgentProfileRepository } from "../../src/worker/db/agent-profiles";
import { HarnessRepository, type Harness } from "../../src/worker/db/harnesses";
import { UserRepository, type UserProfile } from "../../src/worker/db/users";
import { randomId } from "../../src/worker/utils/random";

export const db = (): D1Database => env.DB;
export const users = () => new UserRepository(db());
export const profiles = () => new AgentProfileRepository(db());
export const harnesses = () => new HarnessRepository(db());

/** Storage is shared across tests, so every fixture uses fresh random ids. */
export async function newUser(): Promise<UserProfile> {
  return users().create({ authUserId: randomId("auth") });
}

export async function newHarness(): Promise<Harness> {
  return harnesses().registerAdmin({
    name: `harness ${randomId("h")}`,
    environment: "development",
    endpoint: "https://harness.example.test",
    keyId: "cf-dev-2026-10",
    capabilities: { protocolVersions: [1], operations: ["profile.create"] },
  });
}

export async function rowCount(table: string): Promise<number> {
  const allowed = ["user_profiles", "agent_profiles", "harnesses", "provisioning_jobs", "provisioning_nonces", "audit_events"];
  if (!allowed.includes(table)) throw new Error("unknown table");
  const row = await db().prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>();
  return row?.n ?? 0;
}
