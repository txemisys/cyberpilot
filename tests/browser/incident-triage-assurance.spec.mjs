import { test,expect } from "@playwright/test";
test("incident triage prioritizes a persisted LAB case without provider writes",
async ({page})=>{
  const stamp=Date.now().toString(36);
  await page.goto("/login");
  await page.getByLabel("Name").fill("Triage Offline Reviewer");
  await page.getByLabel("Email").fill("triage-"+stamp+"@cyberpilot.local");
  await page.getByLabel("Password").fill("TriageLab2026!");
  await page.getByRole("button",{name:"Create Lab account"}).click();
  await expect(page.getByRole("heading",{name:"Security workspace"}))
    .toBeVisible({timeout:30000});
  await page.getByRole("link",{name:"Create an organization"}).click();
  await page.getByLabel("Organization name").fill("Triage LAB "+stamp);
  await page.getByRole("button",{name:"Create organization"}).click();
  await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/,{timeout:30000});
  const root=new URL(page.url()).pathname.replace(/\/$/,"");
  await page.goto(root+"/guided-incidents");
  await expect(page.getByRole("heading",{name:"Respuesta a incidentes"}))
    .toBeVisible({timeout:30000});
  await page.getByRole("textbox",{name:"Título"}).fill("Suspicious admin "+stamp);
  await page.getByRole("textbox",{name:/Referencia de afectación/})
    .fill("principal-"+stamp);
  await page.getByRole("button",{name:"Crear caso offline"}).click();
  await expect(page.getByRole("status"))
    .toContainText("no se ejecutó ninguna acción en el proveedor");
  await page.goto(root+"/incident-triage");
  await expect(page.getByRole("heading",{name:"Triage por SLA y evidencia"}))
    .toBeVisible({timeout:30000});
  await expect(page.getByRole("button",{name:/Suspicious admin/}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("sin acciones contra proveedores",{
    exact:false})).toBeVisible();
  await page.getByRole("button",{name:/Suspicious admin/}).click();
  await expect(page.getByRole("heading",{name:"Suspicious admin "+stamp}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("Auditoría íntegra: sí",{
    exact:false})).toBeVisible();
  await page.getByRole("button",{name:"Preparar tablero exportable"}).click();
  await expect(page.getByRole("textbox",{name:"Exportación de triage"}))
    .toHaveValue(/cyberpilot.incident.triage.board.v1/);
});
