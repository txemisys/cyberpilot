import { test, expect } from "@playwright/test";

test("LAB customer journey: account, organization, findings, playbooks and report", async ({ page }) => {
  const id = Date.now().toString(36);
  const email = `browser-${id}@cyberpilot.local`;
  const orgName = `Browser Pilot ${id}`;

  await page.goto("/login");
  await expect(page.getByText("Local Lab access")).toBeVisible();
  await page.getByLabel("Name").fill("Browser Pilot Owner");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("BrowserPilotOnly-2026!");
  await page.getByRole("button", { name: "Create Lab account" }).click();

  await expect(page.getByRole("heading", { name: "Security workspace" })).toBeVisible();
  await page.getByRole("link", { name: "Create an organization" }).click();
  await page.getByLabel("Organization name").fill(orgName);
  await page.getByRole("button", { name: "Create organization" }).click();

  await expect(page.getByRole("button", { name: "Start Microsoft 365 Lab" })).toBeVisible();
  await page.getByRole("button", { name: "Start Microsoft 365 Lab" }).click();
  await expect(page.getByRole("button", { name: "Re-evaluate lab" })).toBeVisible();
  await page.getByRole("button", { name: "Re-evaluate lab" }).click();

  await expect(page.getByRole("heading", { name: "Top actions" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Remediation playbooks" })).toBeVisible();
  await expect(page.locator(".priority-list a[href^='#']").first()).toBeVisible();
  const target = await page.locator(".priority-list a[href^='#']").first().getAttribute("href");
  await page.locator(".priority-list a[href^='#']").first().click();
  await expect(page).toHaveURL(new RegExp(`${target?.replace("#", "#")}$`));

  await page.goto(page.url().split("#")[0].replace(/\\/$/, "") + "/report");
  await expect(page.locator(".executive-report")).toBeVisible();
  await expect(page.getByText("LAB", { exact: true }).first()).toBeVisible();
});
