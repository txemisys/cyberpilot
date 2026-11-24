import { test, expect } from "@playwright/test";

test("unified incident timeline, SLA and escalation planning remain offline",
  async ({ page }) => {
    const stamp = Date.now().toString(36);
    await page.goto("/login");
    await page.getByLabel("Name").fill("Operational Timeline QA");
    await page.getByLabel("Email").fill(
      "timeline-" + stamp + "@cyberpilot.local");
    await page.getByLabel("Password").fill("TimelineLab2026!");
    await page.getByRole("button", { name: "Create Lab account" }).click();
    await expect(page.getByRole("heading", {
      name: "Security workspace",
    })).toBeVisible({ timeout: 30000 });
    await page.getByRole("link", {
      name: "Create an organization",
    }).click();
    await page.getByLabel("Organization name")
      .fill("Timeline Organization " + stamp);
    await page.getByRole("button", { name: "Create organization" }).click();
    await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/,
      { timeout: 30000 });
    const root = new URL(page.url()).pathname.replace(/\/$/, "");
    await page.goto(root + "/guided-incidents");
    await page.getByRole("textbox", { name: "Título" }).fill(
      "Operational audit " + stamp);
    await page.getByRole("textbox", {
      name: /Referencia de afectación/,
    }).fill("principal-" + stamp);
    await page.getByRole("button", { name: "Crear caso offline" }).click();
    await expect(page.getByRole("status"))
      .toContainText("no se ejecutó ninguna acción en el proveedor");

    const list = await page.request.get(root.replace(
      "/organizations/", "/api/organizations/") + "/guided-incidents");
    expect(list.ok()).toBeTruthy();
    const body = await list.json();
    const incident = body.data.cases.find(x =>
      x.title === "Operational audit " + stamp);
    expect(incident?.id).toBeTruthy();

    await page.goto(root + "/incident-operational-timeline");
    await expect(page.getByRole("heading", {
      name: "Línea temporal operativa del incidente",
    })).toBeVisible();
    await page.getByLabel("Identificador del incidente").fill(incident.id);
    await page.getByRole("button", {
      name: "Reconciliar eventos",
    }).click();
    await expect(page.getByRole("status"))
      .toContainText("eventos coincidentes", { timeout: 30000 });
    await expect(page.getByText("Digest de página:", { exact: false }))
      .toBeVisible();
    await expect(page.getByText("Evidencia insuficiente").first())
      .toBeVisible();

    await page.goto(root + "/incident-operational-sla");
    await expect(page.getByRole("heading", {
      name: "Tiempos y SLA internos de respuesta",
    })).toBeVisible();
    await page.getByLabel("ID del incidente").fill(incident.id);
    await page.getByRole("button", {
      name: "Calcular observabilidad interna",
    }).click();
    await expect(page.getByRole("status"))
      .toContainText("REVIEW_REQUIRED", { timeout: 30000 });
    await expect(page.getByText("desconocido.", { exact: false }))
      .toBeVisible();

    await page.goto(root + "/incident-operational-escalations");
    await expect(page.getByRole("heading", {
      name: "Coordinación de escalados internos",
    })).toBeVisible();
    await page.getByLabel("Incidente", { exact: true }).fill(incident.id);
    await page.getByRole("button", {
      name: "Previsualizar escalados",
    }).click();
    await expect(page.getByRole("heading", {
      name: "Plan propuesto · solo interno",
    })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(
      "La política no ha seleccionado trabajos", { exact: false }))
      .toBeVisible();
    await expect(page.getByText("No se notificará a terceros", {
      exact: false,
    })).toHaveCount(0);
  });
