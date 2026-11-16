import { test, expect } from "@playwright/test";

/**
 * Runs against the isolated LAB account and PostgreSQL instance started by
 * lab-browser.yml. Never targets a customer organization or external tenant.
 * Every state assertion is based on the actual page/API, not fixture reports.
 */
test("Baseline: persist, reload, submit, follow up, technically review and reopen", async ({ page }) => {
  const suffix = Date.now().toString(36) +
    "-" + Math.random().toString(36).slice(2, 8);
  const orgName = "Baseline Acceptance " + suffix;
  await page.goto("/login");
  await expect(page.getByText("Local Lab access")).toBeVisible();
  await page.getByLabel("Name").fill("Baseline LAB Reviewer");
  await page.getByLabel("Email")
    .fill("baseline-browser-" + suffix + "@cyberpilot.local");
  await page.getByLabel("Password").fill("BaselineLABOnly-2026!");
  await page.getByRole("button", { name: "Create Lab account" }).click();
  await expect(page.getByRole("heading", {
    name: "Security workspace",
  })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("link", { name: "Create an organization" }).click();
  await page.getByLabel("Organization name").fill(orgName);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("button", {
    name: "Start Microsoft 365 Lab",
  })).toBeVisible();
  const orgUrl = new URL(page.url()).pathname.replace(/\/$/, "");
  expect(orgUrl).toMatch(/^\/organizations\/[^/]+$/);

  // A deliberately negative declaration yields a reviewable follow-up
  // without implying a verified technical finding.
  await page.goto(orgUrl + "/baseline");
  await expect(page.getByRole("heading", {
    name: /Baseline de seguridad/,
  })).toBeVisible();
  const noAnswer = page.getByRole("radio", {
    name: "No", exact: true,
  }).first();
  await noAnswer.check();
  await expect(noAnswer).toBeChecked();
  await expect(page.getByText("Cambios locales sin guardar")).toBeVisible();
  await page.getByRole("button", { name: "Guardar borrador" }).click();
  await expect(page.getByText(/Borrador persistido/)).toBeVisible();
  await expect(page.getByText(/Revisión: 1/)).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Cargar último" }).click();
  await expect(page.getByText("Se ha recuperado la revisión guardada."))
    .toBeVisible();
  await expect(page.getByRole("radio", { name: "No", exact: true }).first())
    .toBeChecked();
  await expect(page.getByText(/Estado: DRAFT/)).toBeVisible();

  await page.getByRole("button", { name: "Presentar diagnóstico" }).click();
  await expect(page.getByText(/Diagnóstico declarativo presentado/))
    .toBeVisible();
  await expect(page.getByText(/Estado: SUBMITTED/)).toBeVisible();
  await expect(page.getByText(/Revisión: 2/)).toBeVisible();
  await expect(page.getByRole("button", {
    name: "Presentar diagnóstico",
  })).toBeDisabled();
  await page.getByRole("button", { name: "Ver historial" }).click();
  await expect(page.getByText(/Historial cronológico auditado/))
    .toBeVisible();
  await expect(page.getByRole("option", { name: /v2.*SUBMIT/ }))
    .toBeAttached();

  await page.goto(orgUrl + "/baseline/actions");
  await expect(page.getByRole("heading", {
    name: "Seguimiento de acciones de mejora",
  })).toBeVisible();
  await page.getByRole("button", {
    name: "Crear acciones desde diagnóstico presentado",
  }).click();
  await expect(page.getByText(/Acciones propuestas desde/)).toBeVisible();
  await page.getByRole("button", { name: "Consultar acciones" }).click();
  await expect(page.getByText(/Acciones declarativas recuperadas/))
    .toBeVisible();
  const firstAction = page.getByRole("button", {
    name: /(?:HIGH|MEDIUM|LOW|CRITICAL).*OPEN/,
  }).first();
  await expect(firstAction).toBeVisible();
  await firstAction.click();
  await expect(page.getByText(/Remediación verificada:/)).toBeVisible();
  const followUpSection = page.getByRole("button", {
    name: "Guardar seguimiento",
  }).locator("xpath=ancestor::section[1]");
  await followUpSection.getByLabel("Estado").selectOption("IN_PROGRESS");
  await followUpSection.getByRole("button", {
    name: "Guardar seguimiento",
  }).click();
  await expect(page.getByText(/Seguimiento actualizado con auditoría/))
    .toBeVisible();
  await followUpSection.getByRole("button", { name: "Ver auditoría" }).click();
  await expect(followUpSection.getByText(/IN_PROGRESS/).last())
    .toBeVisible();

  // Technical review is linked to the immutable SUBMIT revision, not
  // to the mutable draft or a fabricated customer signature.
  await page.goto(orgUrl + "/baseline/reviews");
  await expect(page.getByRole("heading", {
    name: "Revisiones técnicas y aceptación de desarrollo",
  })).toBeVisible();
  await page.getByLabel("Revisión de Baseline presentada").fill("2");
  await page.getByRole("button", { name: "Abrir revisión técnica" }).click();
  await expect(page.getByText(/Revisión de desarrollo iniciada/)).toBeVisible();
  await expect(page.getByText(/Controles técnicamente validados:/))
    .toBeVisible();
  await expect(page.getByText(/Incidencias: 0/)).toBeVisible();
  await page.getByRole("button", { name: "Empezar" }).click();
  await expect(page.getByText(/Estado técnico actualizado y auditado/))
    .toBeVisible();
  await page.getByRole("button", { name: "Completar revisión interna" }).click();
  await expect(page.getByText(/Aceptación técnica interna registrada/))
    .toBeVisible();
  await expect(page.getByText(/TECHNICALLY_REVIEWED/).first())
    .toBeVisible();
  await page.getByRole("button", { name: "Historial" }).click();
  await expect(page.getByText(/COMPLETE/).first()).toBeVisible();

  await page.goto(orgUrl + "/baseline");
  await page.getByRole("button", { name: "Cargar último" }).click();
  await expect(page.getByText(/Estado: SUBMITTED/)).toBeVisible();
  await page.getByRole("button", { name: "Reabrir" }).click();
  await expect(page.getByText(/Revisión reabierta para edición/))
    .toBeVisible();
  await expect(page.getByText(/Estado: DRAFT/)).toBeVisible();
  await expect(page.getByRole("radio", {
    name: "No", exact: true,
  }).first()).toBeChecked();
  await page.getByRole("button", { name: "Ver historial" }).click();
  await expect(page.getByText(/Historial cronológico auditado/))
    .toBeVisible();
  await expect(page.getByRole("option", { name: /v2.*SUBMIT/ }))
    .toBeAttached();
});
