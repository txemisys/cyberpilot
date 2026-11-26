import { test, expect } from "@playwright/test";

test("6V–6X durable investigations, correlation and shift coordination stay offline",
  async ({ page }) => {
    const stamp = Date.now().toString(36);
    await page.goto("/login");
    await page.getByLabel("Name").fill("Coordination Lab");
    await page.getByLabel("Email").fill(
      "coordination-" + stamp + "@cyberpilot.local");
    await page.getByLabel("Password").fill("CoordinationLab2026!");
    await page.getByRole("button", { name: "Create Lab account" }).click();
    await expect(page.getByRole("heading", {
      name: "Security workspace",
    })).toBeVisible({ timeout: 30000 });
    await page.getByRole("link", {
      name: "Create an organization",
    }).click();
    await page.getByLabel("Organization name").fill(
      "Coordination Lab " + stamp);
    await page.getByRole("button", {
      name: "Create organization",
    }).click();
    await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/,
      { timeout: 30000 });
    const root = new URL(page.url()).pathname.replace(/\/$/, "");
    await page.goto(root + "/guided-incidents");
    for (const label of ["primary", "secondary"]) {
      await page.getByRole("textbox", { name: "Título" })
        .fill("Coordination " + label + " " + stamp);
      await page.getByRole("textbox", {
        name: /Referencia de afectación/,
      }).fill("principal-" + label + "-" + stamp);
      await page.getByRole("button", { name: "Crear caso offline" }).click();
      await expect(page.getByRole("status")).toContainText(
        "no se ejecutó ninguna acción en el proveedor");
    }
    const api = root.replace("/organizations/", "/api/organizations/");
    const response = await page.request.get(api + "/guided-incidents");
    expect(response.ok()).toBeTruthy();
    const listed = await response.json();
    const ids = ["primary", "secondary"].map(label =>
      listed.data.cases.find(item =>
        item.title === "Coordination " + label + " " + stamp)?.id);
    expect(ids[0]).toBeTruthy();
    expect(ids[1]).toBeTruthy();

    await page.goto(root + "/incident-persisted-investigations");
    await expect(page.getByRole("heading", {
      name: "Investigaciones persistentes",
    })).toBeVisible();
    await page.getByLabel("ID del incidente").fill(ids[0]);
    await page.getByRole("button", {
      name: "Crear investigación desde el estado actual",
    }).click();
    await expect(page.getByText(
      "Investigación interna creada. Sin acciones externas.",
      { exact: true },
    )).toBeVisible({ timeout: 30000 });
    await expect(page.getByRole("heading", {
      name: /Investigación work-/,
    })).toBeVisible();
    await expect(page.getByText("El cierre interno no acredita contención"))
      .toBeVisible();

    await page.goto(root + "/incident-persisted-correlations");
    await expect(page.getByRole("heading", {
      name: "Hipótesis de correlación persistentes",
    })).toBeVisible();
    await page.getByLabel("Incidente 1").fill(ids[0]);
    await page.getByLabel("Incidente 2").fill(ids[1]);
    await page.getByRole("button", {
      name: "Crear tablero revisable",
    }).click();
    await expect(page.getByRole("heading", {
      name: /Tablero corr-/,
    })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(
      "La verificación de proveedor es desconocida.",
    )).toBeVisible();

    await page.goto(root + "/incident-persisted-shift-handoffs");
    await expect(page.getByRole("heading", {
      name: "Relevos persistentes de incidentes",
    })).toBeVisible();
    await page.getByLabel("Incidente", { exact: true }).fill(ids[0]);
    await page.getByLabel("Usuario entrante").fill("same-or-foreign-user");
    await page.getByLabel("Inicio").fill("2026-11-26T07:00");
    await page.getByLabel("Fin").fill("2026-11-26T09:00");
    await page.getByRole("button", {
      name: "Preparar relevo interno",
    }).click();
    await expect(page.getByText(
      "SHIFT_HANDOFF_RECIPIENT_NOT_AUTHORIZED", { exact: true },
    )).toBeVisible({ timeout: 30000 });
    const prohibited = await page.request.delete(
      api + "/incident-integrations/persisted-shift-handoffs");
    expect(prohibited.status()).toBe(405);
  });
