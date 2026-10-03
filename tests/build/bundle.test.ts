/**
 * Checks on the production build in dist/. Run `npm run build` first
 * (`npm run check` does both).
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

const CLIENT = "dist/client";
const WORKER = "dist/lightagent_control/index.js";

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

beforeAll(() => {
  if (!existsSync(join(CLIENT, "index.html")) || !existsSync(WORKER)) {
    throw new Error("dist/ is missing: run `npm run build` before `npm run test:build`");
  }
});

describe("client document", () => {
  const html = () => readFileSync(join(CLIENT, "index.html"), "utf8");

  it("contains no inline executable JavaScript", () => {
    const scripts = [...html().matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts.length).toBeGreaterThan(0);
    for (const [, attributes = "", body = ""] of scripts) {
      expect(attributes, "every script must load from a file").toMatch(/\bsrc="\/assets\/[^"]+\.js"/);
      expect(body.trim()).toBe("");
    }
  });

  it("has no inline event handlers or javascript: URLs", () => {
    expect(html()).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html()).not.toMatch(/javascript:/i);
  });

  it("uses the nonce placeholder only inside nonce attributes", () => {
    const text = html();
    const total = text.split("LIGHTAGENT_CSP_NONCE").length - 1;
    const inAttributes = [...text.matchAll(/nonce="LIGHTAGENT_CSP_NONCE"/g)].length;
    expect(total).toBeGreaterThan(0);
    expect(inAttributes).toBe(total);
  });

  it("does not ship a CSP <meta> that could conflict with the header policy", () => {
    expect(html()).not.toMatch(/http-equiv=["']?content-security-policy/i);
  });
});

describe("browser-delivered assets", () => {
  it("ship no source maps", () => {
    expect(files(CLIENT).filter((f) => f.endsWith(".map"))).toEqual([]);
    for (const file of files(CLIENT).filter((f) => f.endsWith(".js"))) {
      expect(readFileSync(file, "utf8")).not.toContain("sourceMappingURL");
    }
  });

  it("contain no secrets, secret names, or private addresses", () => {
    const forbidden = [
      /BETTER_AUTH_SECRET|TURNSTILE_SECRET|CLIENT_SECRET|SIGNING_PRIVATE_KEY/,
      /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
      /\bsk-[A-Za-z0-9]{16,}/,
      /\bghp_[A-Za-z0-9]{20,}/,
      /\bAKIA[0-9A-Z]{16}\b/,
      /\b0x4AAAAAAA[A-Za-z0-9_-]{10,}/, // Turnstile secret key shape
      /\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b/,
      /\.dev\.vars/,
      /TRUSTED_ORIGINS|HSTS_MAX_AGE/,
    ];
    // .assetsignore is the upload-exclusion list (it names .dev.vars to keep it out); it is never served.
    for (const file of files(CLIENT).filter((f) => !f.endsWith(".assetsignore"))) {
      const text = readFileSync(file, "utf8");
      for (const pattern of forbidden) {
        expect(pattern.test(text), `${file} matches ${pattern}`).toBe(false);
      }
    }
  });

  it("include the static security headers file and nothing from local env", () => {
    expect(readFileSync(join(CLIENT, "_headers"), "utf8")).toContain("X-Content-Type-Options: nosniff");
    expect(existsSync(join(CLIENT, ".dev.vars"))).toBe(false);
  });
});

describe("worker bundle", () => {
  it("is built with the production CSP mode", () => {
    const bundle = readFileSync(WORKER, "utf8");
    expect(bundle).toMatch(/cspMode:\s*"production"/);
    expect(bundle).not.toMatch(/cspMode:\s*"development"/);
  });

  it("never emits unsafe CSP keywords in code", () => {
    // Source comments survive bundling; only executable lines matter.
    const code = readFileSync(WORKER, "utf8")
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\/\*|\*)/.test(line))
      .join("\n");
    expect(code).not.toMatch(/unsafe-eval|unsafe-inline|unsafe-hashes/);
  });
});
