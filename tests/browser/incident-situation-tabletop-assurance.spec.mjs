import {test,expect} from "@playwright/test";
test("incident response situation, tabletop and assurance within authenticated LAB",
async ({page})=>{
  const stamp=Date.now().toString(36);
  await page.goto("/login");
  await page.getByLabel("Name").fill("Situation Assurance Reviewer");
  await page.getByLabel("Email").fill("situation-"+stamp+"@cyberpilot.local");
  await page.getByLabel("Password").fill("SituationLab2026!");
  await page.getByRole("button",{name:"Create Lab account"}).click();
  await expect(page.getByRole("heading",{name:"Security workspace"}))
    .toBeVisible({timeout:30000});
  await page.getByRole("link",{name:"Create an organization"}).click();
  await page.getByLabel("Organization name").fill("Situation Lab "+stamp);
  await page.getByRole("button",{name:"Create organization"}).click();
  await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/,
    {timeout:30000});
  const root=new URL(page.url()).pathname.replace(/\/$/,"");
  await page.goto(root+"/guided-incidents");
  await expect(page.getByRole("heading",{name:"Respuesta a incidentes"}))
    .toBeVisible({timeout:30000});
  await page.getByRole("textbox",{name:"Título"})
    .fill("Assurance incident "+stamp);
  await page.getByRole("textbox",{name:/Referencia de afectación/})
    .fill("principal-"+stamp);
  await page.getByRole("button",{name:"Crear caso offline"}).click();
  await expect(page.getByRole("status"))
    .toContainText("no se ejecutó ninguna acción en el proveedor");
  await page.goto(root+"/incident-situation");
  await expect(page.getByRole("heading",{name:"Sala de situación de incidentes"}))
    .toBeVisible({timeout:30000});
  await page.getByLabel("Incidente a coordinar")
    .selectOption({index:1});
  await page.getByRole("button",{name:"Analizar situación multifuente"}).click();
  await expect(page.getByRole("heading",{name:/Prioridad P/}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("contención real demostrada: NO",{
    exact:false})).toBeVisible();
  await page.goto(root+"/incident-tabletop");
  await expect(page.getByRole("heading",{
    name:"Simulador de respuesta a incidentes"})).toBeVisible();
  await page.getByRole("button",{name:"Generar y evaluar ejercicio offline"}).click();
  await expect(page.getByRole("heading",{name:/Escenario: P/}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("Contención real demostrada: NO",{
    exact:false})).toBeVisible();
  await page.goto(root+"/incident-assurance");
  await expect(page.getByRole("heading",{
    name:"Preparación y aseguramiento de incidentes"})).toBeVisible();
  await page.getByLabel("Incidente a auditar")
    .selectOption({index:1});
  await page.getByRole("button",{name:"Revisar controles y evidencias"}).click();
  await expect(page.getByRole("heading",{name:/Decisión: /}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("Contención externa: NO",{
    exact:false})).toBeVisible();
});
