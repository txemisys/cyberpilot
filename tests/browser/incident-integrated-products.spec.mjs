import { test, expect } from "@playwright/test";

test("incident response integrates persisted evidence, assets and remediation without LIVE writes",
async ({ page }) => {
  const stamp = Date.now().toString(36);
  await page.goto("/login");
  await page.getByLabel("Name").fill("Integrated Incident Reviewer");
  await page.getByLabel("Email").fill("integration-" + stamp + "@cyberpilot.local");
  await page.getByLabel("Password").fill("IncidentLab2026!");
  await page.getByRole("button", { name: "Create Lab account" }).click();
  await expect(page.getByRole("heading", { name: "Security workspace" }))
    .toBeVisible({ timeout: 30000 });
  await page.getByRole("link", { name: "Create an organization" }).click();
  await page.getByLabel("Organization name").fill("Incident Integration " + stamp);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/, {
    timeout: 30000,
  });
  const root = new URL(page.url()).pathname.replace(/\/$/, "");
  await page.goto(root + "/guided-incidents");
  await expect(page.getByRole("heading", { name: "Respuesta a incidentes" }))
    .toBeVisible({ timeout: 30000 });
  await page.getByRole("textbox", { name: "Título" })
    .fill("Credential incident " + stamp);
  await page.getByRole("textbox", { name: /Referencia de afectación/ })
    .fill("principal-" + stamp);
  await page.getByRole("button", { name: "Crear caso offline" }).click();
  await expect(page.getByRole("status"))
    .toContainText("no se ejecutó ninguna acción en el proveedor");
  await page.goto(root + "/incident-triage");
  await expect(page.getByRole("button", {
    name: new RegExp("Credential incident " + stamp),
  })).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", {
    name: new RegExp("Credential incident " + stamp),
  }).click();
  const paths = [
    ["evidence", "Integración de evidencias del incidente",
      "Correlacionar registros seleccionados"],
    ["assets", "Impacto del incidente sobre activos",
      "Revisar impacto sobre inventario y OSV"],
    ["remediation", "Remediación supervisada del incidente",
      "Evaluar aprobaciones, evidencias y bloqueos"],
  ];
  for (const [kind, heading, action] of paths) {
    const href = await page.locator("nav[aria-label='Integraciones del incidente']")
      .locator("a[href$='/" + kind + "']").getAttribute("href");
    expect(href).toBeTruthy();
    await page.goto(href);
    await expect(page.getByRole("heading", { name: heading }))
      .toBeVisible({ timeout: 30000 });
    if (kind === "remediation") {
      await page.getByRole("button", {
        name: "Consultar playbook y revisión del caso",
      }).click();
      await expect(page.getByRole("status"))
        .toContainText("Ninguna acción enviada");
    }
    await expect(page.getByRole("button", { name: action })).toBeVisible();
    await page.goto(root + "/incident-triage");
    await page.getByRole("button", {
      name: new RegExp("Credential incident " + stamp),
    }).click();
  }
});
