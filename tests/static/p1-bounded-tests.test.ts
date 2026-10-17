/**
 * The P1 bounded live-test script, run offline against a stand-in curl that
 * answers as staging did on 2026-10-17. Pins the request count it reports
 * (counted inside $(…) subshells, the P1 run reported 1 for 46), the stop
 * at the first unexpected response, the client identity check and the
 * request budget. Nothing reaches the network.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPT = "scripts/p1-bounded-tests.sh";
const H = "https://lightagent-control-staging.eddelaroca.workers.dev";

// FAIL_OPTIONS=n turns the n-th passkey options request into a 503.
const CURL = String.raw`#!/usr/bin/env bash
url= hdr=0
while [ $# -gt 0 ]; do
  case "$1" in -w|-X|-H|--data|--max-time|-o) shift;; -D) hdr=1; shift;; https://*) url=$1;; esac
  shift
done
echo "$url" >> "$STATE/requests"
H=https://lightagent-control-staging.eddelaroca.workers.dev
case "$url" in
  https://www.cloudflare.com/cdn-cgi/trace) printf 'fl=1\nip=%s\nts=1\n' "$CLIENT_IP" ;;
  "$H/api/auth/sign-in/social") printf 403 ;;
  "$H/api/auth/callback/google?code=x") printf '302 %s' "$H/login?error=state_not_found" ;;
  "$H/api/auth/callback/google?code=x&state=y") printf '302 %s' "$H/login?error=state_mismatch" ;;
  "$H/api/auth/passkey/generate-authenticate-options")
    n=$(grep -c generate-authenticate-options "$STATE/requests")
    if [ "$n" = "$FAIL_OPTIONS" ]; then printf 503
    elif [ $hdr = 1 ]; then printf 'HTTP/2 429 \r\nretry-after: 54\r\ncontent-type: application/json\r\n\r\n'
    else printf 200; fi ;;
  "$H/api/auth/passkey/verify-authentication") printf 429 ;;
  *) printf 000; exit 6 ;;
esac
`;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p1-script-"));
  writeFileSync(join(dir, "curl"), CURL);
  writeFileSync(join(dir, "sleep"), "#!/bin/sh\nexit 0\n");
  chmodSync(join(dir, "curl"), 0o755);
  chmodSync(join(dir, "sleep"), 0o755);
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function run(env: Record<string, string> = {}, script = SCRIPT): { status: number | null; stdout: string; staging: number } {
  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    timeout: 20_000,
    env: {
      ...process.env,
      PATH: `${dir}:${process.env["PATH"] ?? ""}`,
      STATE: dir,
      CLIENT_IP: "192.0.2.7",
      EXPECT_IP: "192.0.2.7",
      FAIL_OPTIONS: "0",
      ...env,
    },
  });
  const requests = readFileSync(join(dir, "requests"), "utf8").split("\n");
  return { status: result.status, stdout: result.stdout, staging: requests.filter((url) => url.startsWith(H)).length };
}

describe("scripts/p1-bounded-tests.sh", () => {
  it("sends the fixed 46 requests and reports 46", () => {
    const { status, stdout, staging } = run();
    expect(status).toBe(0);
    expect(stdout).toContain("T3 ok: 20 x 200, then 429 Retry-After 54");
    expect(stdout).toContain("T5 ok: 200 after the window moved");
    expect(stdout.trim().split("\n").at(-1)).toBe("DONE: 46 requests");
    expect(staging).toBe(46);
  });

  it("stops at the first unexpected response and reports the requests actually sent", () => {
    const { status, stdout, staging } = run({ FAIL_OPTIONS: "5" });
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: T3 request 5: HTTP 503 (expected 200)  (requests sent: 28)");
    expect(stdout).not.toContain("T4");
    expect(staging).toBe(28);
  });

  it("sends nothing to staging from an unexpected client address", () => {
    const { status, stdout, staging } = run({ EXPECT_IP: "198.51.100.1" });
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: client IPv4 is 192.0.2.7, expected 198.51.100.1  (requests sent: 0)");
    expect(staging).toBe(0);
  });

  it("stops before exceeding its request budget", () => {
    const source = readFileSync(SCRIPT, "utf8");
    expect(source).toContain("\nMAX_REQUESTS=49\n");
    const reduced = join(dir, "budget-10.sh");
    writeFileSync(reduced, source.replace("\nMAX_REQUESTS=49\n", "\nMAX_REQUESTS=10\n"));
    const { status, stdout, staging } = run({}, reduced);
    expect(status).toBe(1);
    expect(stdout).toContain("STOP: request budget of 10 reached  (requests sent: 10)");
    expect(staging).toBe(10);
  });

  it("never sends a request from inside a command substitution", () => {
    expect(readFileSync(SCRIPT, "utf8")).not.toMatch(/\$\(\s*req\b/);
  });
});
