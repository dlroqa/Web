/**
 * The passkey verification pre-check (M3b) in isolation: the signed-cookie
 * format is pinned against better-call's own signer, and each decision
 * against a stand-in challenge source.
 */
import { parseCookies, serializeSignedCookie } from "better-call";
import { describe, expect, it, vi } from "vitest";
import { passkeyChallengeFailure, signedCookieToken, type ChallengeSource } from "../../src/worker/auth/passkey-challenge";

const SECRET = "unit-test-secret-0123456789abcdef0123456789";
const NAME = "lightagent.better-auth-passkey";
const NOW = Date.parse("2026-10-17T12:00:00Z");

/** The cookie value a browser sends back after better-call set it (URI-decoded by the parser). */
async function signed(token: string, secret = SECRET): Promise<string> {
  const header = await serializeSignedCookie(NAME, token, secret);
  return parseCookies(header.split(";")[0] ?? "").get(NAME) ?? "";
}

function source(rows: Record<string, Date> = {}): ChallengeSource & { lookups: string[] } {
  const lookups: string[] = [];
  return {
    cookieName: NAME,
    secret: SECRET,
    lookups,
    async expiry(token) {
      lookups.push(token);
      return rows[token] ?? null;
    },
  };
}

describe("signedCookieToken", () => {
  it("accepts a value signed by better-call and returns its token", async () => {
    expect(await signedCookieToken(await signed("abcDEF123"), SECRET)).toEqual({ token: "abcDEF123" });
  });

  it("refuses a value signed with another secret", async () => {
    expect(await signedCookieToken(await signed("abcDEF123", "another-secret-0123456789abcdef0123456"), SECRET)).toEqual({ failure: "bad_signature" });
  });

  it("refuses a different token under a genuine signature", async () => {
    const value = await signed("abcDEF123");
    expect(await signedCookieToken(`abcDEF124${value.slice(value.lastIndexOf("."))}`, SECRET)).toEqual({ failure: "bad_signature" });
  });

  it.each([
    ["no separator", "abcDEF123"],
    ["empty token", `.${"A".repeat(43)}=`],
    ["short signature", `abc.${"A".repeat(42)}=`],
    ["long signature", `abc.${"A".repeat(44)}=`],
    ["no padding", `abc.${"A".repeat(44)}`],
    ["not base64", `abc.${"!".repeat(43)}=`],
  ])("refuses a malformed value (%s), as getSignedCookie does", async (_label, value) => {
    expect(await signedCookieToken(value, SECRET)).toEqual({ failure: "malformed" });
  });
});

describe("passkeyChallengeFailure", () => {
  it("passes a live challenge to Better Auth", async () => {
    const s = source({ tok1: new Date(NOW + 60_000) });
    expect(await passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("tok1"))}`, s, NOW)).toBeNull();
    expect(s.lookups).toEqual(["tok1"]);
  });

  it("refuses a missing cookie and never looks anything up", async () => {
    const s = source();
    expect(await passkeyChallengeFailure(null, s, NOW)).toBe("missing");
    expect(await passkeyChallengeFailure("other=1", s, NOW)).toBe("missing");
    expect(await passkeyChallengeFailure(`${NAME}=`, s, NOW)).toBe("missing");
    expect(s.lookups).toEqual([]);
  });

  it("refuses a forged value without a database lookup", async () => {
    const s = source({ tok1: new Date(NOW + 60_000) });
    expect(await passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("tok1", "another-secret-0123456789abcdef0123456"))}`, s, NOW)).toBe("bad_signature");
    expect(await passkeyChallengeFailure(`${NAME}=tok1`, s, NOW)).toBe("malformed");
    expect(s.lookups).toEqual([]);
  });

  it("refuses a challenge with no row, or one that has expired", async () => {
    const s = source({ old: new Date(NOW - 1) });
    expect(await passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("gone"))}`, s, NOW)).toBe("not_found");
    expect(await passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("old"))}`, s, NOW)).toBe("expired");
  });

  it("uses Better Auth's expiry comparison: expiring exactly now, or an unreadable date, is left to Better Auth", async () => {
    const s = source({ edge: new Date(NOW), odd: new Date(Number.NaN) });
    expect(await passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("edge"))}`, s, NOW)).toBeNull();
    expect(await passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("odd"))}`, s, NOW)).toBeNull();
  });

  it("reads the first of two cookies with the challenge's name, as better-call does", async () => {
    const s = source({ live: new Date(NOW + 60_000) });
    const live = encodeURIComponent(await signed("live"));
    const forged = encodeURIComponent(await signed("live", "another-secret-0123456789abcdef0123456"));
    expect(await passkeyChallengeFailure(`${NAME}=${live}; ${NAME}=${forged}`, s, NOW)).toBeNull();
    expect(await passkeyChallengeFailure(`${NAME}=${forged}; ${NAME}=${live}`, s, NOW)).toBe("bad_signature");
  });

  it("lets a lookup failure propagate, so the caller refuses the request", async () => {
    const s: ChallengeSource = { cookieName: NAME, secret: SECRET, expiry: vi.fn(async () => Promise.reject(new Error("D1_ERROR"))) };
    await expect(passkeyChallengeFailure(`${NAME}=${encodeURIComponent(await signed("tok1"))}`, s, NOW)).rejects.toThrow("D1_ERROR");
  });
});
