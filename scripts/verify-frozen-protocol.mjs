/**
 * Verifies the frozen LA-WEB-PROVISIONING/1 r4 bytes (`npm run protocol:verify`).
 *
 * The compatibility digest is the SHA-256 of MANIFEST.json's exact bytes
 * (PROVISIONING_PROTOCOL §15; ACCEPTANCE.md "Frozen revision"). MANIFEST.json
 * pins the specification and every fixture file, so this checks, in order:
 *   1. MANIFEST.json has the accepted compatibility digest;
 *   2. it records the accepted fixture digest and specification hash;
 *   3. every file it lists has exactly that SHA-256 and length;
 *   4. its fixtureDigest is the digest of its own file list;
 *   5. MANIFEST.sha256 is exactly the list MANIFEST.json implies, so the
 *      `sha256sum --check` that follows cannot be satisfied by an edited list.
 * Plain Node, no dependencies: it runs before anything is installed or built.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const FROZEN_R4 = {
  compatibilityDigest: "454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43",
  fixtureDigest: "bfd171db27c03321227bec1a0e40325bad295b2a228cf02294b3a1e3a87d6e4b",
  specificationSha256: "5f65a623aa467ec940d2942583a821b6dd23bf7b9221ccaa8e3e72fc4687b36a",
};
const DIR = "protocol/la-web-provisioning-1";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

const manifestBytes = readFileSync(`${DIR}/MANIFEST.json`);
const manifestDigest = sha256(manifestBytes);
check(manifestDigest === FROZEN_R4.compatibilityDigest, `MANIFEST.json digest ${manifestDigest} is not the accepted r4 digest`);

const manifest = JSON.parse(manifestBytes.toString("utf8"));
check(manifest.fixtureDigest === FROZEN_R4.fixtureDigest, "MANIFEST.json fixtureDigest is not the accepted r4 value");
check(manifest.specification?.sha256 === FROZEN_R4.specificationSha256, "MANIFEST.json specification hash is not the accepted r4 value");

const entries = [manifest.specification, ...manifest.files];
for (const entry of entries) {
  const bytes = readFileSync(entry.path);
  check(sha256(bytes) === entry.sha256, `${entry.path}: SHA-256 differs from MANIFEST.json`);
  check(bytes.length === entry.bytes, `${entry.path}: length differs from MANIFEST.json`);
}
check(sha256(manifest.files.map((f) => `${f.sha256}  ${f.path}\n`).join("")) === manifest.fixtureDigest, "fixtureDigest does not match the file list");

const expectedSums = [...entries, { path: `${DIR}/MANIFEST.json`, sha256: manifestDigest }].map((e) => `${e.sha256}  ${e.path}\n`).join("");
check(readFileSync(`${DIR}/MANIFEST.sha256`, "utf8") === expectedSums, "MANIFEST.sha256 is not exactly the list MANIFEST.json implies");

if (failures.length > 0) {
  for (const failure of failures) console.error(`FAILED: ${failure}`);
  process.exit(1);
}
console.log(`LA-WEB-PROVISIONING/1 r4 verified: compatibility digest ${manifestDigest}, ${entries.length} hashed files`);
