import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  // The real migration files, applied to the test D1 before any test runs.
  const migrations = await readD1Migrations("./migrations");

  return {
    test: {
      projects: [
        {
          // Runs inside workerd, so HTMLRewriter, Web Crypto, D1, and bindings
          // are real. @cloudflare/vitest-pool-workers 0.22 (latest) bundles
          // workerd 2026-08-22, older than wrangler.jsonc's compatibility_date,
          // so tests pin the newest date that runtime supports. Deployed Workers
          // keep the configured date; staging smoke tests cover the real
          // runtime. Remove this override when the pool ships a newer workerd.
          plugins: [
            cloudflareTest({
              wrangler: { configPath: "./wrangler.jsonc" },
              miniflare: {
                compatibilityDate: "2026-08-22",
                bindings: {
                  TEST_MIGRATIONS: migrations,
                  // Test-only placeholders, not credentials. Provider endpoints
                  // are stubbed in tests; Turnstile uses Cloudflare's public
                  // always-pass test secret (accepted only in development).
                  BETTER_AUTH_SECRET: "test-only-better-auth-secret-0123456789abcdef",
                  GOOGLE_CLIENT_ID: "test-google-client-id",
                  GOOGLE_CLIENT_SECRET: "test-google-client-secret",
                  GITHUB_CLIENT_ID: "test-github-client-id",
                  GITHUB_CLIENT_SECRET: "test-github-client-secret",
                  TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
                },
              },
            }),
          ],
          test: {
            name: "workers",
            // Integration tests run full OAuth/passkey flows (RSA keys, D1).
            testTimeout: 20_000,
            include: ["tests/{unit,security,db,integration,contracts,operator}/**/*.test.ts"],
            setupFiles: ["./tests/helpers/apply-migrations.ts"],
          },
        },
        {
          // Client components rendered with react-dom/server: route gate, escaping, API client.
          test: { name: "client", include: ["tests/client/**/*.test.tsx"], environment: "node" },
        },
        {
          // Source-level checks that need the filesystem (no build required).
          test: { name: "static", include: ["tests/static/**/*.test.ts"], environment: "node" },
        },
        {
          // Inspects the production build in dist/ (run after `npm run build`).
          test: { name: "build", include: ["tests/build/**/*.test.ts"], environment: "node" },
        },
      ],
    },
  };
});
