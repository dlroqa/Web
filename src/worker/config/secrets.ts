/**
 * Access to Worker Secrets.
 *
 * Secrets are set with `wrangler secret put` (or a gitignored .dev.vars) and
 * are not declared in wrangler.jsonc until the feature that needs them ships,
 * so they are read by name and validated here instead of being typed on `Env`.
 * Secret values must never be logged, returned, or placed in `vars`.
 */

export type SecretName =
  | "TURNSTILE_SECRET"
  | "BETTER_AUTH_SECRET"
  | "GOOGLE_CLIENT_ID"
  | "GOOGLE_CLIENT_SECRET"
  | "GITHUB_CLIENT_ID"
  | "GITHUB_CLIENT_SECRET"
  | "LIGHTAGENT_SIGNING_PRIVATE_KEY"
  | "AUDIT_SOURCE_HMAC_KEY";

/** The secret's value, or undefined when it is unset or empty. */
export function readSecret(env: Env, name: SecretName): string | undefined {
  const value: unknown = Reflect.get(env, name);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
