/**
 * The P2 bounded live-test script, run offline against a stand-in curl that
 * answers as staging should with M3 active. Pins its fixed request count
 * (50), the stop at the first unexpected response (including the 429 that
 * would mean a rejected request reached the limiter), the client identity
 * check, the request budget, and that it carries no credential. Nothing
 * reaches the network.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPT = "scripts/p2-bounded-tests.sh";
const H = "https://lightagent-control-staging.eddelaroca.workers.dev";

// LIMIT_OPTIONS=n / LIMIT_VERIFY=n make the n-th request to that endpoint a
// 429, as if the limiter ran before Turnstile or before the challenge check.
const CURL = String.raw`#!/usr/bin/env bash
url= method=GET origin= cookie=
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method=$2; shift;;
    -H) case "$2" in origin:*) origin=$2;; cookie:*) cookie=$2;; esac; shift;;
    -w|--data|--max-time|-o) shift;;
    https://*) url=$1;;
  esac
  shift
done
echo "$method $url" >> "$STATE/requests"
H=https://lightagent-control-staging.eddelaroca.workers.dev
count() { grep -c " $1" "$STATE/requests"; }
case "$url" in
  https://www.cloudflare.com/cdn-cgi/trace) printf 'fl=1\nip=%s\nts=1\n' "$CLIENT_IP" ;;
  "$H/api/auth/passkey/generate-authenticate-options")
    if [ "$method" != POST ]; then printf 405
    elif [ "$origin" != "origin: $H" ]; then printf 403
    elif [ "$(count "$url")" = "$LIMIT_OPTIONS" ]; then printf 429
    else printf 403; fi ;;
  "$H/api/auth/passkey/verify-authentication")
    if [ "$origin" != "origin: $H" ]; then printf 403
    elif [ "$(count "$url")" = "$LIMIT_VERIFY" ]; then printf 429
    else printf 400; fi ;;
  "$H/api/auth/sign-in/social") printf 403 ;;
  "$H/api/auth/callback/google?code=x") printf '302 %s' "$H/login?error=state_not_found" ;;
  "$H/api/auth/callback/google?code=x&state=y") printf '302 %s' "$H/login?error=state_mismatch" ;;
  *) printf 000; exit 6 ;;
esac
`;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p2-script-"));
  writeFileSync(join(dir, "curl"), CURL);
  writeFileSync(join(dir, "sleep"), "#!/bin/sh\nexit 0\n");
  chmodSync(join(dir, "curl"), 0o755);
  chmodSync(join(dir, "sleep"), 0o755);
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function run(env: Record<string, string> = {}, script = SCRIPT): { status: number | null; stdout: string; staging: string[] } {
  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    timeout: 20_000,
    env: {
      ...process.env,
      PATH: `${dir}:${process.env["PATH"] ?? ""}`,
      STATE: dir,
      CLIENT_IP: "192.0.2.7",
      EXPECT_IP: "192.0.2.7",
      LIMIT_OPTIONS: "0",
      LIMIT_VERIFY: "0",
      ...env,
    },
  });
  const requests = readFileSync(join(dir, "requests"), "utf8").split("\n");
  return { status: result.status, stdout: result.stdout, staging: requests.filter((line) => line.includes(` ${H}/`)) };
}

describe("scripts/p2-bounded-tests.sh", () => {
  it("sends the fixed 50 requests in order and reports 50", () => {
    const { status, stdout, staging } = run();
    expect(status).toBe(0);
    for (const step of ["S1 ok", "S2 ok", "S3 ok: 21 x 403", "S4 ok: 21 x 400", "S5 ok", "S6 ok", "S7 ok"]) expect(stdout).toContain(step);
    expect(stdout.trim().split("\n").at(-1)).toBe("DONE: 50 requests");
    expect(staging).toHaveLength(50);
    const count = (prefix: string) => staging.filter((line) => line.startsWith(prefix)).length;
    expect(count(`GET ${H}/api/auth/passkey/generate-authenticate-options`)).toBe(1);
    expect(count(`POST ${H}/api/auth/passkey/generate-authenticate-options`)).toBe(23);
    expect(count(`POST ${H}/api/auth/passkey/verify-authentication`)).toBe(23);
    expect(count(`POST ${H}/api/auth/sign-in/social`)).toBe(1);
    expect(count(`GET ${H}/api/auth/callback/google`)).toBe(2);
  });

  it("stops when an invalid-token options request is rate limited (it reached the limiter)", () => {
    // Options requests: S1 (GET), S2 (2), then S3; the 21st of S3 is the 24th.
    const { status, stdout, staging } = run({ LIMIT_OPTIONS: "24" });
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: S3 attempt 21: HTTP 429 (expected 403 TURNSTILE_FAILED)  (requests sent: 24)");
    expect(stdout).not.toContain("S4");
    expect(staging).toHaveLength(24);
  });

  it("stops when a verification without a challenge is rate limited (it reached the limiter)", () => {
    const { status, stdout, staging } = run({ LIMIT_VERIFY: "21" });
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: S4 attempt 21: HTTP 429 (expected 400)  (requests sent: 45)");
    expect(staging).toHaveLength(45);
  });

  it("sends nothing to staging from an unexpected client address", () => {
    const { status, stdout, staging } = run({ EXPECT_IP: "198.51.100.1" });
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: client IPv4 is 192.0.2.7, expected 198.51.100.1  (requests sent: 0)");
    expect(staging).toHaveLength(0);
  });

  it("stops before exceeding its request budget", () => {
    const source = readFileSync(SCRIPT, "utf8");
    expect(source).toContain("\nMAX_REQUESTS=50\n");
    const reduced = join(dir, "budget-10.sh");
    writeFileSync(reduced, source.replace("\nMAX_REQUESTS=50\n", "\nMAX_REQUESTS=10\n"));
    const { status, stdout, staging } = run({}, reduced);
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: request budget of 10 reached  (requests sent: 10)");
    expect(staging).toHaveLength(10);
  });

  it("never sends a request from inside a command substitution", () => {
    expect(readFileSync(SCRIPT, "utf8")).not.toMatch(/\$\(\s*req\b/);
  });

  it("carries no credential: only the literal invalid token and an unsigned, made-up challenge", () => {
    const source = readFileSync(SCRIPT, "utf8");
    expect([...source.matchAll(/"turnstileToken":"([^"]*)"/g)].map((m) => m[1])).toEqual(["invalid", "invalid", "invalid", "invalid"]);
    expect(source).toContain("FORGED=p2-forged-token.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    expect(source).toContain("MALFORMED=p2-malformed-token\n");
    expect(source).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/); // no JWT
    expect(source).not.toMatch(/0x4AAAA|1x0000|2x0000|3x0000/); // no Turnstile keys or test secrets
    expect(source).not.toMatch(/session_token|lightagent\.state=|authorization:/i); // no session, state or bearer
  });
});
