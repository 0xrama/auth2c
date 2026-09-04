/**
 * Vitest configuration for the Auth2C Worker integration tests.
 *
 * Uses @cloudflare/vitest-pool-workers so tests run inside the Workers runtime
 * with a real (miniflare) D1 binding — transaction/batch/RETURNING/race
 * semantics are exercised for real, not mocked.
 *
 * D1 migrations are read from disk here (in Node) and exposed to tests via the
 * `TEST_MIGRATIONS` binding; each test file applies them through `applyD1Migrations`
 * in its own `beforeAll`.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Migrations live at the repository root (shared with `wrangler d1 migrations`).
const migrationsPath = path.join(__dirname, "..", "..", "migrations");

export default defineConfig(async () => {
  const migrations = await readD1Migrations(migrationsPath);
  return {
    plugins: [
      cloudflareTest({
        // Test-only wrangler config: defines the D1 binding. Production
        // The deployment-oriented wrangler.jsonc is intentionally avoided.
        wrangler: { configPath: "./wrangler.test.jsonc" },
        miniflare: {
          // Test-only binding carrying the parsed migrations array.
          bindings: { TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      pool: "cloudflare",
      // Each test file is its own isolate; passWithNoTests is kept so a freshly
      // cloned repo without these files still builds.
      include: ["test/**/*.test.ts"],
    },
  };
});
