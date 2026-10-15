import { describe, expect, it } from "vitest";
import { rateLimitAddress } from "../../src/worker/security/client-address";

const from = (headers: Record<string, string>) => rateLimitAddress(new Request("https://example.test/", { headers }));
const ip = (value: string) => from({ "cf-connecting-ip": value });

describe("rateLimitAddress", () => {
  it("uses a valid IPv4 CF-Connecting-IP as is", () => {
    expect(ip("203.0.113.9")).toBe("203.0.113.9");
    expect(ip(" 203.0.113.9 ")).toBe("203.0.113.9");
  });

  it("keys IPv6 clients on their /64, whatever the spelling", () => {
    const key = "2001:db8:1:2::/64";
    expect(ip("2001:db8:1:2::1")).toBe(key);
    expect(ip("2001:0DB8:0001:0002:ffff:ffff:ffff:ffff")).toBe(key);
    expect(ip("2001:db8:1:2:a:b:c:d")).toBe(key);
    expect(ip("2001:db8:1:3::1")).not.toBe(key);
    expect(ip("::1")).toBe("0:0:0:0::/64");
    expect(ip("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
  });

  it("treats IPv4-mapped IPv6 as the IPv4 address", () => {
    expect(ip("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(ip("::ffff:cb00:7109")).toBe("203.0.113.9");
  });

  it("returns null for a missing or malformed address instead of a shared bucket", () => {
    expect(from({})).toBeNull();
    for (const bad of [
      "",
      "unknown",
      "203.0.113.256",
      "203.0.113",
      "203.0.113.9:443",
      "203.0.113.9, 198.51.100.1",
      "2001:db8::1::2",
      "2001:db8:1:2:3:4:5:6:7",
      "2001:db8::g",
      "fe80::1%eth0",
      "[2001:db8::1]",
      "1".repeat(65),
    ]) {
      expect(ip(bad), bad).toBeNull();
    }
  });

  it("never reads client-controlled forwarding headers", () => {
    const spoof = { "x-forwarded-for": "198.51.100.1", "x-real-ip": "198.51.100.2", "true-client-ip": "198.51.100.3", forwarded: "for=198.51.100.4" };
    expect(from(spoof)).toBeNull();
    expect(from({ ...spoof, "cf-connecting-ip": "203.0.113.9" })).toBe("203.0.113.9");
  });
});
