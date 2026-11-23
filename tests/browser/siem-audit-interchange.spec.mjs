import { test, expect } from "@playwright/test";
test("SIEM offline audit interchange remains tenant-scoped and never sends events",
async ({ page }) => {
  const stamp = Date.now().toString(36);
  await page.goto("/login");
  await page.getByLabel("Name").fill("SIEM Offline Reviewer");
  await page.getByLabel("Email").fill("siem-offline-" + stamp + "@cyberpilot.local");
  await page.getByLabel("Password").fill("SiemLab2026!");
  await page.getByRole("button", { name: "Create Lab account" }).click();
  await expect(page.getByRole("heading", { name: "Security workspace" }))
    .toBeVisible({ timeout: 30000 });
  await page.getByRole("link", { name: "Create an organization" }).click();
  await page.getByLabel("Organization name").fill("SIEM LAB " + stamp);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/, { timeout: 30000 });
  const root = new URL(page.url()).pathname.replace(/\/$/, "");
  await page.goto(root + "/siem-audit");
  await expect(page.getByRole("heading", { name: "Exportación de auditoría SIEM" }))
    .toBeVisible({ timeout: 30000 });
  await expect(page.getByText("ningún evento se envió a un SIEM", { exact: false }))
    .toBeVisible({ timeout: 30000 });
  await page.getByRole("combobox", { name: "Formato" }).selectOption("CSV");
  await page.getByRole("button", { name: "Preparar exportación manual" }).click();
  await expect(page.getByRole("textbox", { name: "Archivo SIEM exportable" }))
    .toHaveValue(/"eventId","occurredAt"/);
  await expect(page.getByText("no se ha transmitido a ningún destinatario", {
    exact: false })).toBeVisible();
  const auditUrl = root.replace("/organizations/", "/api/organizations/") +
    "/siem-audit?mode=capabilities";
  const response = await page.request.get(auditUrl);
  expect(response.ok()).toBe(true);
  const data = await response.json();
  expect(data.data.directSplunkDelivery).toBe(false);
  expect(data.data.directSentinelDelivery).toBe(false);
  expect(data.data.directDatadogDelivery).toBe(false);
});
