/**
 * The P2 bounded live-test sequence (scripts/p2-bounded-tests.sh), replayed
 * request for request through the Worker with M3: every request is invalid,
 * so none may reach the authoritative limiter (Durable Object). The rate-limit
 * bindings approve everything here, as the live ones do (workers-sdk#16097),
 * so the Durable Object is the only limiter that could have counted them.
 *
 * The live run cannot attribute account-wide Durable Object analytics to its
 * own requests; this test is the endpoint-level evidence for zero admissions,
 * and the script's "never 429 on the 21st request" checks are the live one.
 */
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthRateLimiter } from "../../src/worker/security/rate-limit-do";
import { FakeProviders } from "../helpers/auth";
import { BASE, call, testEnv } from "../helpers/worker";

const approveAll: RateLimit = { limit: async () => ({ success: true }) };
// Development (HTTP): no __Secure- prefix; staging's name is __Secure-lightagent.better-auth-passkey.
const CHALLENGE = "lightagent.better-auth-passkey";
const FORGED = "p2-forged-token.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const MALFORMED = "p2-malformed-token";
const IP = "198.51.100.222";

let providers: FakeProviders;
beforeEach(() => {
  for (const level of ["log", "info", "warn", "error"] as const) vi.spyOn(console, level).mockImplementation(() => undefined);
  providers = new FakeProviders().install();
  providers.turnstile = "fail";
});
afterEach(() => {
  providers.restore();
  vi.restoreAllMocks();
});

/** The real namespace, recording every admission attempt. */
function countingNamespace(): { namespace: DurableObjectNamespace<AuthRateLimiter>; calls: string[] } {
  const calls: string[] = [];
  const namespace = {
    getByName: (name: string) => {
      calls.push(name);
      return env.AUTH_RATE_LIMITER.getByName(name);
    },
  } as unknown as DurableObjectNamespace<AuthRateLimiter>;
  return { namespace, calls };
}

describe("P2 bounded sequence (invalid requests only)", () => {
  it("gets the script's expected answers and never reaches the Durable Object", async () => {
    const { namespace, calls } = countingNamespace();
    const environment = testEnv({ RL_LOGIN: approveAll, RL_PASSKEY_LOGIN: approveAll, RL_SIGNUP: approveAll, AUTH_RATE_LIMITER: namespace });
    const json = { "content-type": "application/json", "cf-connecting-ip": IP };
    const send = (path: string, init: RequestInit) => call(path, init, { env: environment });
    const options = "/api/auth/passkey/generate-authenticate-options";
    const verify = "/api/auth/passkey/verify-authentication";
    const statuses: number[] = [];
    const record = async (response: Response) => {
      statuses.push(response.status);
      await response.body?.cancel();
      return response;
    };

    // S1
    expect((await record(await send(options, { headers: { "cf-connecting-ip": IP } }))).status).toBe(405);
    // S2
    expect((await record(await send(options, { method: "POST", headers: { ...json, origin: "https://evil.example" }, body: '{"turnstileToken":"invalid"}' }))).status).toBe(403);
    expect((await record(await send(options, { method: "POST", headers: json, body: '{"turnstileToken":"invalid"}' }))).status).toBe(403);
    // S3
    for (let i = 0; i < 21; i += 1) {
      expect((await record(await send(options, { method: "POST", headers: { ...json, origin: BASE }, body: '{"turnstileToken":"invalid"}' }))).status).toBe(403);
    }
    // S4
    for (let i = 0; i < 21; i += 1) {
      expect((await record(await send(verify, { method: "POST", headers: { ...json, origin: BASE }, body: '{"response":{}}' }))).status).toBe(400);
    }
    // S5
    for (const value of [FORGED, MALFORMED]) {
      expect((await record(await send(verify, { method: "POST", headers: { ...json, origin: BASE, cookie: `${CHALLENGE}=${value}` }, body: '{"response":{}}' }))).status).toBe(400);
    }
    // S6
    expect((await record(await send("/api/auth/sign-in/social", { method: "POST", headers: { ...json, origin: BASE }, body: '{"provider":"google","turnstileToken":"invalid"}' }))).status).toBe(403);
    // S7
    const noState = await send("/api/auth/callback/google?code=x", { headers: { "cf-connecting-ip": IP } });
    statuses.push(noState.status);
    expect(noState.headers.get("location")).toBe(`${BASE}/login?error=state_not_found`);
    const noCookie = await send("/api/auth/callback/google?code=x&state=y", { headers: { "cf-connecting-ip": IP } });
    statuses.push(noCookie.status);
    expect(noCookie.headers.get("location")).toBe(`${BASE}/login?error=state_mismatch`);

    expect(statuses).toHaveLength(50);
    expect(statuses).not.toContain(429);
    // Only the 21 options requests with an origin and S6 reach Siteverify.
    expect(providers.outbound.filter((o) => o.includes("/turnstile/v0/siteverify"))).toHaveLength(22);
    expect(calls).toEqual([]);
  }, 30_000);
});
