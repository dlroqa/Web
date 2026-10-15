/**
 * One-time staging "carrier" deployment of the AuthRateLimiter Durable Object
 * class (DEPLOYMENT.md, "Durable Object classes and the upload-only workflow").
 *
 * A new Durable Object class can only be created by `wrangler deploy`, which
 * also activates the version, and Cloudflare then blocks rollback to every
 * earlier version. So this refuses unless, after `npm run ci:cloudflare`:
 *   1. the checkout is the reviewed carrier source: every tracked file
 *      except this script's own three files is exactly commit 0b9528e
 *      (one digest over `git ls-tree -r`; works in a shallow clone), and no
 *      tracked file is modified;
 *   2. in Workers Builds, the branch is deploy/staging-carrier;
 *   3. the generated dist/lightagent_control/wrangler.json is the staging
 *      Worker, its D1, Preview URLs off, and exactly the AUTH_RATE_LIMITER
 *      binding and v1-auth-rate-limiter migration;
 *   4. the bundle exports AuthRateLimiter and never uses the binding (the
 *      carrier changes no request handling);
 *   5. the live deployment is exactly W1 91dc87aa at 100% (so a second run,
 *      after the carrier is live, refuses).
 * Default is `wrangler deploy --dry-run`; only `--deploy` deploys.
 */
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const CARRIER = {
  commit: "0b9528e",
  sourceDigest: "8b2116531786d50437d106d04bef9e49adf8702a0918ed8da3e29068d15b1e5a",
  branch: "deploy/staging-carrier",
  worker: "lightagent-control-staging",
  databaseId: "3cc0724d-fb83-4477-ac0f-5aee58606fdf",
  liveVersion: "91dc87aa-a156-45df-9296-81e2ad8a3106",
  ownFiles: ["scripts/deploy-carrier.mjs", "scripts/deploy-carrier.d.mts", "tests/static/deploy-carrier.test.ts"],
};

/** SHA-256 over sorted `git ls-tree -r` lines ("mode type id\tpath"), without this script's files. */
export function sourceDigest(lsTree) {
  const lines = lsTree
    .split("\n")
    .filter((line) => line !== "" && !CARRIER.ownFiles.includes(line.slice(line.indexOf("\t") + 1)))
    .sort((a, b) => (a.slice(a.indexOf("\t")) < b.slice(b.indexOf("\t")) ? -1 : 1));
  return createHash("sha256").update(`${lines.join("\n")}\n`).digest("hex");
}

/** Problems with the generated Wrangler configuration (empty when it is the carrier). */
export function configProblems(c) {
  const problems = [];
  const db = (c.d1_databases ?? []).find((b) => b.binding === "DB") ?? {};
  if (c.name !== CARRIER.worker) problems.push(`name is ${c.name}`);
  if (c.vars?.ENVIRONMENT !== "staging") problems.push("ENVIRONMENT is not staging");
  if (c.preview_urls !== false) problems.push("preview_urls is not false");
  if (db.database_name !== CARRIER.worker || db.database_id !== CARRIER.databaseId) problems.push("DB is not the staging D1");
  if (JSON.stringify(c.durable_objects?.bindings) !== '[{"name":"AUTH_RATE_LIMITER","class_name":"AuthRateLimiter"}]') problems.push("Durable Object bindings differ");
  if (JSON.stringify(c.migrations) !== '[{"tag":"v1-auth-rate-limiter","new_sqlite_classes":["AuthRateLimiter"]}]') problems.push("migrations differ");
  return problems;
}

/** Problems with the Worker bundle (empty when it carries the class without using it). */
export function bundleProblems(source) {
  const problems = [];
  if (!/^export \{[^}]*\bAuthRateLimiter\b[^}]*\};?$/m.test(source)) problems.push("AuthRateLimiter is not exported");
  if (source.includes("AUTH_RATE_LIMITER")) problems.push("the bundle uses AUTH_RATE_LIMITER");
  return problems;
}

/** Problems with `wrangler deployments status --json` (empty when W1 is exactly at 100%). */
export function liveProblems(status) {
  const versions = status?.versions ?? [];
  return versions.length === 1 && versions[0].version_id === CARRIER.liveVersion && versions[0].percentage === 100
    ? []
    : [`live deployment is not ${CARRIER.liveVersion} at 100%`];
}

function wrangler(args, capture) {
  const result = spawnSync("npx", ["wrangler", ...args], { stdio: ["ignore", capture ? "pipe" : "inherit", "inherit"], encoding: "utf8" });
  if (result.status !== 0) throw new Error(`wrangler ${args[0]} failed (exit ${result.status})`);
  return result.stdout;
}

function main(argv) {
  const deploy = argv.includes("--deploy");
  const git = (...args) => execFileSync("git", args, { encoding: "utf8" });
  const refuse = [];

  const digest = sourceDigest(git("ls-tree", "-r", "--full-tree", "HEAD"));
  if (digest !== CARRIER.sourceDigest) refuse.push(`source is not carrier ${CARRIER.commit} (digest ${digest})`);
  if (git("status", "--porcelain", "--untracked-files=no").trim() !== "") refuse.push("tracked files are modified");
  if (process.env.WORKERS_CI === "1" && process.env.WORKERS_CI_BRANCH !== CARRIER.branch) refuse.push(`branch is ${process.env.WORKERS_CI_BRANCH}`);
  refuse.push(...configProblems(JSON.parse(readFileSync("dist/lightagent_control/wrangler.json", "utf8"))));
  refuse.push(...bundleProblems(readFileSync("dist/lightagent_control/index.js", "utf8")));
  if (refuse.length === 0) refuse.push(...liveProblems(JSON.parse(wrangler(["deployments", "status", "--env", "staging", "--json"], true))));

  if (refuse.length > 0) {
    for (const reason of refuse) console.error(`REFUSING: ${reason}`);
    process.exit(1);
  }
  console.log(`carrier verified: ${CARRIER.commit} source, staging config, unused class, W1 live (commit ${process.env.WORKERS_CI_COMMIT_SHA ?? "local"})`);

  if (!deploy) {
    wrangler(["deploy", "--env", "staging", "--dry-run"], false);
    return;
  }
  wrangler(["deploy", "--env", "staging", "--message", `carrier ${CARRIER.commit} build ${process.env.WORKERS_CI_BUILD_UUID ?? "local"}`], false);
  const after = JSON.parse(wrangler(["deployments", "status", "--env", "staging", "--json"], true));
  console.log(`carrier deployed: ${JSON.stringify(after.versions)}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`REFUSING: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}
