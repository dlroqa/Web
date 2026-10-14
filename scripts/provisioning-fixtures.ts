/**
 * Usage (via `npm run protocol:fixtures -- <mode>`):
 *   write  regenerate protocol/la-web-provisioning-1/ from the reference codec
 *   check  exit 1 unless the committed fixtures and manifest are current
 * Prints the compatibility digest (SHA-256 of MANIFEST.json).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { buildFixtureFiles, buildManifest, compatibilityDigest, FIXTURE_DIR, SPEC_PATH } from "../tools/provisioning-fixtures";

const mode = process.argv[2];
if (mode !== "write" && mode !== "check") {
  console.error("usage: npm run protocol:fixtures -- write|check");
  process.exit(2);
}

const files = await buildFixtureFiles();
const manifest = await buildManifest(files, readFileSync(SPEC_PATH));
const all = new Map([...files, ...manifest]);
let stale = 0;
for (const [path, content] of all) {
  let current: string | null = null;
  try {
    current = readFileSync(path, "utf8");
  } catch {
    current = null;
  }
  if (current === content) continue;
  if (mode === "write") writeFileSync(path, content);
  else {
    console.error(`stale: ${path}`);
    stale += 1;
  }
}
console.log(`compatibility digest: ${await compatibilityDigest(manifest.get(`${FIXTURE_DIR}/MANIFEST.json`) as string)}`);
if (stale > 0) process.exit(1);
