import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig, devices } from "@playwright/test";

const configDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(configDir, "../..");
const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const apiBaseUrl = "http://127.0.0.1:18002";

export default defineConfig({
  testDir: "./test/e2e",
  reporter: "html",
  use: {
    baseURL: "http://127.0.0.1:3199",
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  webServer: [
    {
      command: "sh ./scripts/run-investigation-e2e-api.sh",
      cwd: workspaceRoot,
      env: {
        ...process.env,
        AEGISCUDO_API_BIND_ADDR: "127.0.0.1:18002",
        DATABASE_URL:
          process.env.DATABASE_URL ?? "postgres://aegiscudo:aegiscudo@127.0.0.1:15432/aegiscudo",
      },
      name: "Aegiscudo API",
      stderr: "pipe",
      stdout: "pipe",
      timeout: 5 * 60 * 1000,
      url: `${apiBaseUrl}/healthz`,
      reuseExistingServer: false,
    },
    {
      command: "pnpm exec next dev --hostname 127.0.0.1 --port 3199",
      cwd: configDir,
      env: {
        ...process.env,
        AEGISCUDO_API_BASE_URL: apiBaseUrl,
        NEXT_PUBLIC_AEGISCUDO_API_BASE_URL: apiBaseUrl,
        NEXT_PUBLIC_AEGISCUDO_TENANT_ID: tenantId,
      },
      name: "Command Center",
      stderr: "pipe",
      stdout: "pipe",
      timeout: 2 * 60 * 1000,
      url: "http://127.0.0.1:3199",
      reuseExistingServer: false,
    },
  ],
});