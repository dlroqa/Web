/**
 * Better Auth schema tooling (Node only).
 *
 * Builds an in-memory SQLite database from our committed migrations, then
 * asks the pinned Better Auth version, using the Worker's exact options,
 * what it would still need. Used to generate a reviewable migration and,
 * in tests, to prove the committed schema matches Better Auth's.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { getMigrations } from "better-auth/db/migration";
import { buildAuthOptions } from "../src/worker/auth/options";

export const MIGRATIONS_DIR = "migrations";

/** Apply committed migrations (optionally only those named before `stopBefore`). */
export function databaseFromMigrations(stopBefore?: string): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => /^\d{4}_.+\.sql$/.test(f)).sort();
  for (const file of files) {
    if (stopBefore !== undefined && file >= stopBefore) break;
    db.exec(readFileSync(join(MIGRATIONS_DIR, file), "utf8"));
  }
  return db;
}

/** The Worker's Better Auth options with placeholder (non-secret) values. */
export function schemaOptions(db: DatabaseSync) {
  return buildAuthOptions({
    database: db,
    publicOrigin: "https://schema.invalid",
    passkeyRpId: "schema.invalid",
    trustedOrigins: ["https://schema.invalid"],
    secret: "schema-generation-placeholder-not-a-secret",
    google: { clientId: "placeholder", clientSecret: "placeholder" },
    github: { clientId: "placeholder", clientSecret: "placeholder" },
  });
}

export async function pendingAuthSchema(db: DatabaseSync) {
  return getMigrations(schemaOptions(db), { throwOnUnsafe: false });
}
