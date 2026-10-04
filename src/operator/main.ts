/**
 * Operator CLI entry point (Node): `npm run operator -- <command> --env staging …`
 *
 * Connects to the environment's real D1 database through Wrangler's remote
 * bindings, using the Cloudflare credentials of the person running it
 * (`wrangler login`). That account access is the authorization boundary;
 * the operator id names who acted in the audit trail.
 *
 * Production is refused until production launch is approved.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getPlatformProxy, unstable_readConfig } from "wrangler";
import { parseArgs, runOperatorCommand, USAGE } from "./cli";
import { OperatorError } from "./service";

const ALLOWED_ENVIRONMENTS = new Set(["staging"]);

async function main(): Promise<number> {
  const io = { out: (t: string) => process.stdout.write(`${t}\n`), err: (t: string) => process.stderr.write(`${t}\n`) };
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    io.err(error instanceof OperatorError ? error.message : String(error));
    io.err(USAGE);
    return 2;
  }
  if (!args.command || args.command === "help") {
    io.out(USAGE);
    return args.command ? 0 : 2;
  }
  const environment = args.flags["env"];
  if (environment === "production") {
    io.err(JSON.stringify({ ok: false, error: { code: "FORBIDDEN", message: "operator commands against production are disabled until production launch is approved" } }));
    return 1;
  }
  if (!environment || !ALLOWED_ENVIRONMENTS.has(environment)) {
    io.err(JSON.stringify({ ok: false, error: { code: "INVALID_INPUT", message: "--env staging is required" } }));
    return 2;
  }

  // Only the environment's D1 binding, marked remote. Nothing else is bound.
  const config = unstable_readConfig({ config: "wrangler.jsonc", env: environment });
  const database = (config.d1_databases as Array<{ binding: string; database_name?: string; database_id?: string }>).find((d) => d.binding === "DB");
  if (!database?.database_id) {
    io.err(JSON.stringify({ ok: false, error: { code: "INVALID_INPUT", message: `no DB binding for ${environment}` } }));
    return 1;
  }
  const dir = mkdtempSync(join(tmpdir(), "lightagent-operator-"));
  const configPath = join(dir, "wrangler.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      name: `lightagent-operator-${environment}`,
      compatibility_date: "2026-08-22",
      d1_databases: [{ binding: "DB", database_name: database.database_name, database_id: database.database_id, remote: true }],
    }),
  );
  const proxy = await getPlatformProxy<{ DB: D1Database }>({ configPath, persist: false, remoteBindings: true });
  try {
    io.err(`environment: ${environment} (database ${database.database_name})`);
    return await runOperatorCommand(args, proxy.env.DB, io, process.env["LIGHTAGENT_OPERATOR_ID"]);
  } finally {
    await proxy.dispose();
    rmSync(dir, { recursive: true, force: true });
  }
}

process.exitCode = await main();
