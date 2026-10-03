import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";

// Applying is idempotent (tracked in d1_migrations), so every test file can
// call it; only the first run per database changes anything.
const migrations: unknown = Reflect.get(env, "TEST_MIGRATIONS");
if (!Array.isArray(migrations)) throw new Error("TEST_MIGRATIONS binding missing");
await applyD1Migrations(env.DB, migrations as D1Migration[]);
