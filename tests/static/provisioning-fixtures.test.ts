/**
 * The LA-WEB-PROVISIONING/1 fixture set is reproducible and its manifest is
 * exact: regenerating from the reference codec gives the committed bytes,
 * every hash in MANIFEST.json and MANIFEST.sha256 matches the file on disk,
 * and no Worker or client code depends on the test-only reference.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildFixtureFiles, buildManifest, FIXTURE_DIR, SPEC_PATH } from "../../tools/provisioning-fixtures";

const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
const NOT_IN_MANIFEST = new Set(["MANIFEST.json", "MANIFEST.sha256", "ACCEPTANCE.md"]);

describe("LA-WEB-PROVISIONING/1 fixtures", () => {
  it("are byte-for-byte what the generator produces", async () => {
    const files = await buildFixtureFiles();
    const all = new Map([...files, ...(await buildManifest(files, readFileSync(SPEC_PATH)))]);
    for (const [path, content] of all) {
      expect(readFileSync(path, "utf8"), `${path} is stale; run npm run protocol:fixtures -- write`).toBe(content);
    }
  }, 60_000);

  it("lists every fixture file in the manifest", () => {
    const manifest = JSON.parse(readFileSync(join(FIXTURE_DIR, "MANIFEST.json"), "utf8")) as { files: Array<{ path: string }> };
    const onDisk = readdirSync(FIXTURE_DIR).filter((f) => !NOT_IN_MANIFEST.has(f)).map((f) => `${FIXTURE_DIR}/${f}`).sort();
    expect(manifest.files.map((f) => f.path)).toEqual(onDisk);
  });

  it("lists every fixture id in the manifest, once", () => {
    const manifest = JSON.parse(readFileSync(join(FIXTURE_DIR, "MANIFEST.json"), "utf8")) as { fixtureIds: Record<string, string[]> };
    for (const [path, ids] of Object.entries(manifest.fixtureIds)) {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
      const onDisk = Object.values(parsed)
        .filter((value): value is Array<{ id?: unknown }> => Array.isArray(value))
        .flatMap((list) => list.flatMap((item) => (item && typeof item.id === "string" ? [item.id] : [])));
      expect(ids, path).toEqual(onDisk);
      expect(new Set(ids).size, path).toBe(ids.length);
    }
  });

  it("has hashes that match the files", () => {
    const manifest = JSON.parse(readFileSync(join(FIXTURE_DIR, "MANIFEST.json"), "utf8")) as {
      specification: { path: string; sha256: string; bytes: number };
      files: Array<{ path: string; sha256: string; bytes: number }>;
      fixtureDigest: string;
    };
    for (const entry of [manifest.specification, ...manifest.files]) {
      const bytes = readFileSync(entry.path);
      expect(sha256(bytes), entry.path).toBe(entry.sha256);
      expect(bytes.length, entry.path).toBe(entry.bytes);
    }
    expect(manifest.fixtureDigest).toBe(sha256(manifest.files.map((f) => `${f.sha256}  ${f.path}\n`).join("")));
    for (const line of readFileSync(join(FIXTURE_DIR, "MANIFEST.sha256"), "utf8").trimEnd().split("\n")) {
      const [hash, path] = line.split("  ");
      expect(sha256(readFileSync(path as string)), path).toBe(hash);
    }
  });

  it("are not reachable from Worker or client code", () => {
    const sources = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? sources(join(dir, e.name)) : /\.(ts|tsx)$/.test(e.name) ? [join(dir, e.name)] : [],
      );
    for (const file of sources("src")) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/tests\/contracts|provisioning-fixtures|la-web-provisioning-1/);
    }
  });
});
