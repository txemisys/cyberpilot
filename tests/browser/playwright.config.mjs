import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "**/*.spec.mjs",
  fullyParallel: false,
  // Shared LAB development server and PostgreSQL: avoid concurrent spec interference.
  workers: 1,
  retries: 1,
  timeout: 90_000,
  // Server-side LAB readbacks may compile routes lazily; retain strict assertions.
  expect: { timeout: 20_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
