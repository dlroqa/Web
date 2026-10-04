/**
 * The one access policy, shared by the server (requirePrincipal, API routes)
 * and the browser (route gate). The server is the authority: the browser
 * uses the same rules only to choose what to render, and every API behind a
 * page enforces them again.
 *
 *   public    anyone (/, /login)
 *   identity  any signed-in account allowed to hold a session (active or
 *             pending): enough to learn one's own status and sign out
 *   active    an approved account: every application page and its APIs
 *
 * Suspended and disabled accounts are blocked everywhere, whatever session
 * they hold; pending accounts get the approval screen on `active` pages.
 */

export const ACCOUNT_STATUSES = ["pending", "active", "suspended", "disabled"] as const;
export type AccountStatus = (typeof ACCOUNT_STATUSES)[number];

export type Access = "public" | "identity" | "active";

/** Which statuses each signed-in access level admits. */
export const ACCESS_STATUSES: Readonly<Record<Exclude<Access, "public">, readonly AccountStatus[]>> = {
  identity: ["active", "pending"],
  active: ["active"],
};

/** What a caller with `status` (null: not signed in) gets for `access`. */
export type AccessDecision = "allow" | "sign-in" | "pending" | "blocked";

export function decideAccess(access: Access, status: AccountStatus | null): AccessDecision {
  if (access === "public") return "allow";
  if (status === null) return "sign-in";
  if (status === "suspended" || status === "disabled") return "blocked";
  return ACCESS_STATUSES[access].includes(status) ? "allow" : "pending";
}

/** Application pages and their access level. */
export const PAGE_ACCESS = {
  "/": "public",
  "/login": "public",
  "/dashboard": "active",
  "/agents": "active",
  "/security": "active",
  "/sessions": "active",
  "/settings": "active",
} as const satisfies Record<string, Access>;

export type PagePath = keyof typeof PAGE_ACCESS;

/** Signed-in pages a sign-in may return to (also the OAuth callback allowlist). */
export const RETURN_PATHS = (Object.keys(PAGE_ACCESS) as PagePath[]).filter((path) => PAGE_ACCESS[path] !== "public") as Array<
  Exclude<PagePath, "/" | "/login">
>;
export type ReturnPath = (typeof RETURN_PATHS)[number];

/** The access level of any SPA path. Unknown paths need an active account (no content leaks). */
export function pageAccess(path: string): Access {
  if (Object.hasOwn(PAGE_ACCESS, path)) return PAGE_ACCESS[path as PagePath];
  return "active";
}

export function isReturnPath(value: string | null | undefined): value is ReturnPath {
  return typeof value === "string" && (RETURN_PATHS as readonly string[]).includes(value);
}
