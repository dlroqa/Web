import { describe, expect, it } from "vitest";
import { ACCESS_STATUSES, decideAccess, isReturnPath, PAGE_ACCESS, pageAccess, RETURN_PATHS } from "../../src/shared/access";

describe("shared access policy", () => {
  it("decides every access level for every status", () => {
    const statuses = [null, "pending", "active", "suspended", "disabled"] as const;
    const table = Object.fromEntries((["public", "identity", "active"] as const).map((access) => [access, statuses.map((s) => decideAccess(access, s))]));
    expect(table).toEqual({
      public: ["allow", "allow", "allow", "allow", "allow"],
      identity: ["sign-in", "allow", "allow", "blocked", "blocked"],
      active: ["sign-in", "pending", "allow", "blocked", "blocked"],
    });
  });

  it("application pages need an active account; only / and /login are public", () => {
    expect(PAGE_ACCESS).toEqual({ "/": "public", "/login": "public", "/dashboard": "active", "/agents": "active", "/security": "active", "/sessions": "active", "/settings": "active" });
    expect(pageAccess("/nonexistent")).toBe("active");
    expect(pageAccess("/agents/agt_x")).toBe("active");
    expect(pageAccess("/__proto__")).toBe("active");
    expect(ACCESS_STATUSES.identity).toEqual(["active", "pending"]);
  });

  it("return paths are exactly the signed-in pages", () => {
    expect([...RETURN_PATHS].sort()).toEqual(["/agents", "/dashboard", "/security", "/sessions", "/settings"]);
    expect(isReturnPath("/login")).toBe(false);
    expect(isReturnPath("https://evil.example/dashboard")).toBe(false);
    expect(isReturnPath("//evil.example")).toBe(false);
    expect(isReturnPath(null)).toBe(false);
  });
});
