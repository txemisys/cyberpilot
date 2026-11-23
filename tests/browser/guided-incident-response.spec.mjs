import { test, expect } from "@playwright/test";

test("five guided incident response playbooks persist in LAB without provider writes",
async ({ page }) => {
  const stamp = Date.now().toString(36);
  await page.goto("/login");
  await page.getByLabel("Name").fill("Incident Reviewer");
  await page.getByLabel("Email").fill("incident-review-" + stamp + "@cyberpilot.local");
  await page.getByLabel("Password").fill("IncidentLab2026!");
  await page.getByRole("button", { name: "Create Lab account" }).click();
  await expect(page.getByRole("heading", { name: "Security workspace" })).toBeVisible();
  await page.getByRole("link", { name: "Create an organization" }).click();
  await page.getByLabel("Organization name").fill("Incident LAB " + stamp);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("button", { name: "Start Microsoft 365 Lab" }))
    .toBeVisible({ timeout: 30000 });
  await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/, { timeout: 30000 });
  const root = new URL(page.url()).pathname.replace(/\/$/, "");
  await page.goto(root + "/guided-incidents");
  await expect(page.getByRole("heading", { name: "Respuesta a incidentes" })).toBeVisible();
  await expect(page.getByText("Solo flujos guiados", { exact: false })).toBeVisible();
  const playbooks = [
    ["COMPROMISED_ACCOUNT", "Cuenta comprometida"],
    ["PHISHING_CAMPAIGN", "Phishing reportado"],
    ["RANSOMWARE", "Cifrado reportado"],
    ["LOST_DEVICE", "Dispositivo extraviado"],
    ["PAYMENT_FRAUD", "Cambio bancario reportado"],
  ];
  for (const [type, title] of playbooks) {
    await page.locator("select").selectOption(type);
    await page.getByLabel("Título").fill(title + " " + stamp);
    await page.getByLabel("Referencia de afectación (sin secretos)")
      .fill("object-" + type.toLowerCase());
    await page.getByRole("button", { name: "Crear caso offline" }).click();
    await expect(page.getByRole("status")).toContainText(
      "no se ejecutó ninguna acción en el proveedor");
    await expect(page.getByRole("heading", { name: title + " " + stamp })).toBeVisible();
    await expect(page.getByText("Contención técnica demostrada: NO", { exact: false }))
      .toBeVisible();
  }
  await page.getByRole("button", { name: "Iniciar triage" }).click();
  await expect(page.getByText("Estado: TRIAGE", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Preparar CSV" }).click();
  await expect(page.getByLabel("Expediente exportado")).toContainText("incidentId,type,stepId");
  await page.reload();
  await expect(page.getByRole("button", { name: /Cambio bancario reportado/ }))
    .toBeVisible();
});
