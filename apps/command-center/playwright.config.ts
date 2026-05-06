import { defineConfig, devices } from "@playwright/test";

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
  webServer: {
    command: "pnpm exec next dev --hostname 127.0.0.1 --port 3199",
    url: "http://127.0.0.1:3199",
    reuseExistingServer: false,
  },
});