/**
 * Validated public configuration.
 *
 * Values come from wrangler `vars` (never from requests). Parsing is strict:
 * a malformed value makes the Worker fail closed with INTERNAL_ERROR rather
 * than silently trusting something unexpected.
 */
import { z } from "../../shared/zod";

export type Environment = "development" | "staging" | "production";

export interface AppConfig {
  environment: Environment;
  /** Exact, normalized origins allowed to make state-changing requests. */
  trustedOrigins: ReadonlySet<string>;
  /** 0 disables HSTS. */
  hstsMaxAge: number;
  /** Hostnames a Turnstile token may have been solved on. */
  turnstileHostnames: ReadonlySet<string>;
}

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Normalize one configured origin, requiring it to be exactly an origin
 * (scheme + host + optional port; no path, query, credentials, or fragment).
 */
export function normalizeConfiguredOrigin(raw: string, environment: Environment): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError("TRUSTED_ORIGINS contains an invalid URL");
  }
  // Paths, credentials, queries, and fragments are not origins.
  if (url.pathname !== "/" || url.search || url.hash || url.username || url.password || url.origin === "null") {
    throw new ConfigError("TRUSTED_ORIGINS entries must be bare origins");
  }
  const isLoopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol === "https:") return url.origin;
  if (url.protocol === "http:" && isLoopback && environment === "development") return url.origin;
  throw new ConfigError("TRUSTED_ORIGINS must use https (http only for loopback in development)");
}

const csv = (value: string): string[] =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

const RawConfigSchema = z.object({
  ENVIRONMENT: z.enum(["development", "staging", "production"]),
  TRUSTED_ORIGINS: z.string(),
  HSTS_MAX_AGE: z.string().regex(/^\d{1,9}$/),
  TURNSTILE_EXPECTED_HOSTNAMES: z.string(),
});

export function loadConfig(env: Env): AppConfig {
  const parsed = RawConfigSchema.safeParse({
    ENVIRONMENT: env.ENVIRONMENT,
    TRUSTED_ORIGINS: env.TRUSTED_ORIGINS,
    HSTS_MAX_AGE: env.HSTS_MAX_AGE,
    TURNSTILE_EXPECTED_HOSTNAMES: env.TURNSTILE_EXPECTED_HOSTNAMES,
  });
  if (!parsed.success) {
    throw new ConfigError(`invalid configuration: ${parsed.error.issues.map((i) => i.path.join(".")).join(", ")}`);
  }
  const raw = parsed.data;
  const environment = raw.ENVIRONMENT;
  const trustedOrigins = new Set(csv(raw.TRUSTED_ORIGINS).map((o) => normalizeConfiguredOrigin(o, environment)));
  const turnstileHostnames = new Set(
    csv(raw.TURNSTILE_EXPECTED_HOSTNAMES).map((host) => {
      const lower = host.toLowerCase();
      if (!HOSTNAME.test(lower) && !(environment === "development" && lower === "127.0.0.1")) {
        throw new ConfigError("TURNSTILE_EXPECTED_HOSTNAMES contains an invalid hostname");
      }
      return lower;
    }),
  );
  return {
    environment,
    trustedOrigins,
    hstsMaxAge: Number(raw.HSTS_MAX_AGE),
    turnstileHostnames,
  };
}
