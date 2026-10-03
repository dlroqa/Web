import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        // Runs inside workerd, so HTMLRewriter, Web Crypto, and bindings are real.
        // @cloudflare/vitest-pool-workers 0.22 (latest) bundles workerd
        // 2026-08-22, older than wrangler.jsonc's compatibility_date, so tests
        // pin the newest date that runtime supports. Deployed Workers keep the
        // configured date; staging smoke tests cover the real runtime. Remove
        // this override when the pool ships a newer workerd.
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: { compatibilityDate: "2026-08-22" },
          }),
        ],
        test: {
          name: "workers",
          include: ["tests/{unit,security,integration,contracts}/**/*.test.ts"],
        },
      },
      {
        // Inspects the production build in dist/ (run after `npm run build`).
        test: {
          name: "build",
          include: ["tests/build/**/*.test.ts"],
          environment: "node",
        },
      },
    ],
  },
});
