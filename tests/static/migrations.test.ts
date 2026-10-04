/**
 * Applied migrations are immutable. Their hashes are recorded here when they
 * are first applied to a shared database; editing one fails this test. Fix
 * forward with a new numbered migration instead.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const APPLIED: Record<string, string> = {
  "0001_initial.sql": "1c4aea5e476992524174e94f0afc1155cb2a3889b49f36867dfd3d1c0ee62785",
  "0002_better_auth.sql": "b32ac3f7926ca4d697aa8c31c03377afa42e96a567136379e13aaa7e72071f17",
};

describe("migration history", () => {
  const files = readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort();

  it("is a contiguous, numbered sequence", () => {
    files.forEach((file, index) => expect(file).toMatch(new RegExp(`^${String(index + 1).padStart(4, "0")}_[a-z0-9_]+\\.sql$`)));
  });

  it.each(Object.entries(APPLIED))("%s is unchanged since it was applied", (file, hash) => {
    expect(createHash("sha256").update(readFileSync(`migrations/${file}`)).digest("hex")).toBe(hash);
  });
});
