/**
 * Usage (via `npm run auth:schema -- <mode>`):
 *   generate  print the SQL Better Auth needs on top of migrations before 0002
 *   check     exit 1 unless all committed migrations satisfy Better Auth
 */
import { databaseFromMigrations, pendingAuthSchema } from "../tools/auth-schema";

const mode = process.argv[2];
if (mode === "generate") {
  const plan = await pendingAuthSchema(databaseFromMigrations("0002"));
  process.stdout.write(`${await plan.compileMigrations()}\n`);
} else if (mode === "check") {
  const plan = await pendingAuthSchema(databaseFromMigrations());
  const pending = [...plan.toBeCreated, ...plan.toBeAdded].map((t) => `${t.table}: ${Object.keys(t.fields).join(", ")}`);
  const problems = [...pending, ...plan.toBeAddedIndexes.map((i) => `index ${i.name}`), ...plan.unsafeChanges, ...plan.schemaProblems];
  if (problems.length > 0) {
    process.stderr.write(`Better Auth schema drift:\n${problems.join("\n")}\n`);
    process.exit(1);
  }
  process.stdout.write("Better Auth schema matches committed migrations.\n");
} else {
  process.stderr.write("usage: auth-schema generate|check\n");
  process.exit(2);
}
