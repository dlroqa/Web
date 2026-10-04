/**
 * Source checks for the repository layer: SQL text must be constant, with
 * every dynamic value passed through bind(). Interpolating into SQL is how
 * injection happens, so it is forbidden outright in src/.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : path.endsWith(".ts") ? [path] : [];
  });
}

// The operator CLI follows the same rules: its SQL lives in src/worker/db/admin.ts.
const files = [...sourceFiles("src/worker"), ...sourceFiles("src/operator")];

describe("SQL construction", () => {
  it("never interpolates into SQL template literals", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|PRAGMA)\b[^`]*`/gi)) {
        if (match[0].includes("${")) offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("never builds SQL by string concatenation or uses exec()", () => {
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      // prepare() takes a literal, or a SCREAMING_CASE constant defined in the
      // same file as an uninterpolated SQL literal; never an expression.
      for (const match of text.matchAll(/\.prepare\(\s*([^`"'\s][^)]*)\)/g)) {
        const name = (match[1] ?? "").trim();
        expect(name, `${file}: prepare(${name})`).toMatch(/^[A-Z][A-Z0-9_]*$/);
        const definition = new RegExp(`const ${name} = \`[^\`$]*\`;`).test(text);
        expect(definition, `${file}: ${name} must be a constant SQL literal`).toBe(true);
      }
      expect(text, file).not.toMatch(/["'`]\s*\+\s*\w+\s*\+\s*["'`][^;]*\b(WHERE|VALUES|SET)\b/i);
      expect(text, file).not.toMatch(/\bdb\.exec\(/); // D1 exec() runs unparameterized SQL
    }
  });

  it("keeps SQL inside the db layer", () => {
    const outside = files.filter((f) => !f.includes("/db/") && /\.prepare\(/.test(readFileSync(f, "utf8")));
    expect(outside).toEqual([]);
  });
});
