import { test, expect } from "@playwright/test";

test("forensic casebooks, selected-case correlation and internal shift briefing",
  async ({ page }) => {
    const stamp = Date.now().toString(36);
    await page.goto("/login");
    await page.getByLabel("Name").fill("Incident Forensic Lab");
    await page.getByLabel("Email").fill(
      "forensic-" + stamp + "@cyberpilot.local");
    await page.getByLabel("Password").fill("ForensicLab2026!");
    await page.getByRole("button", { name: "Create Lab account" }).click();
    await expect(page.getByRole("heading", {
      name: "Security workspace",
    })).toBeVisible({ timeout: 30000 });
    await page.getByRole("link", {
      name: "Create an organization",
    }).click();
    await page.getByLabel("Organization name").fill(
      "Forensic Browser " + stamp);
    await page.getByRole("button", {
      name: "Create organization",
    }).click();
    await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/,
      { timeout: 30000 });
    const root = new URL(page.url()).pathname.replace(/\/$/, "");
    await page.goto(root + "/guided-incidents");
    for (const label of ["first", "second"]) {
      await page.getByRole("textbox", { name: "Título" }).fill(
        "Correlated " + label + " " + stamp);
      await page.getByRole("textbox", {
        name: /Referencia de afectación/,
      }).fill("principal-" + label + "-" + stamp);
      await page.getByRole("button", {
        name: "Crear caso offline",
      }).click();
      await expect(page.getByRole("status"))
        .toContainText("no se ejecutó ninguna acción en el proveedor");
    }
    const api = root.replace("/organizations/", "/api/organizations/");
    const response = await page.request.get(api + "/guided-incidents");
    expect(response.ok()).toBeTruthy();
    const listed = await response.json();
    const incidents = ["first", "second"].map(label =>
      listed.data.cases.find(item =>
        item.title === "Correlated " + label + " " + stamp)?.id);
    expect(incidents[0]).toBeTruthy();
    expect(incidents[1]).toBeTruthy();

    await page.goto(root + "/incident-operational-timeline");
    await page.getByLabel("Identificador del incidente")
      .fill(incidents[0]);
    await page.getByRole("button", {
      name: "Reconciliar eventos",
    }).click();
    await expect(page.getByText("Auditoría forense del historial", {
      exact: false,
    })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText("Plan de investigación interno", {
      exact: false,
    })).toBeVisible();

    await page.goto(root + "/incident-crosscase-correlation");
    await expect(page.getByRole("heading", {
      name: "Correlación supervisada entre incidentes",
    })).toBeVisible();
    await page.getByLabel("Incidente 1").fill(incidents[0]);
    await page.getByLabel("Incidente 2").fill(incidents[1]);
    await page.getByRole("button", {
      name: "Examinar coincidencias",
    }).click();
    await expect(page.getByRole("heading", {
      name: "Candidatos de relación",
    })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(
      "No representan compromisos confirmados.", { exact: false,
    })).toBeVisible();

    await page.goto(root + "/incident-shift-briefing");
    await expect(page.getByRole("heading", {
      name: "Briefing de relevo del incidente",
    })).toBeVisible();
    await page.getByLabel("Identificador de incidente")
      .fill(incidents[0]);
    await page.getByLabel("Inicio del turno")
      .fill("2026-11-24T13:00");
    await page.getByLabel("Fin del turno")
      .fill("2026-11-24T14:00");
    await page.getByRole("button", {
      name: "Generar briefing",
    }).click();
    await expect(page.getByRole("heading", {
      name: "Estado al relevo",
    })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(
      "La aceptación NO está registrada.", { exact: false,
    })).toBeVisible();
    await expect(page.getByText(
      "Ninguna acción de proveedor se ha ejecutado.", { exact: false,
    })).toBeVisible();
  });
