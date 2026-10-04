/**
 * The operator module is reachable only from the CLI: nothing the Worker
 * serves may import it (directly or through src/shared or src/client).
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : /\.tsx?$/.test(name) ? [path] : [];
  });
}

describe("operator boundary", () => {
  it("no Worker, client, or shared source imports src/operator", () => {
    const offenders = ["src/worker", "src/client", "src/shared"]
      .flatMap(sources)
      .filter((file) => /from\s+["'][^"']*\boperator\//.test(readFileSync(file, "utf8")) || /import\(\s*["'][^"']*\boperator\//.test(readFileSync(file, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("the operator CLI refuses production", () => {
    const main = readFileSync("src/operator/main.ts", "utf8");
    expect(main).toMatch(/const ALLOWED_ENVIRONMENTS = new Set\(\["staging"\]\)/);
    expect(main).toMatch(/environment === "production"/);
  });
});
