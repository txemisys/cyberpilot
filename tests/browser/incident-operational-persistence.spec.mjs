import {test,expect} from "@playwright/test";
test("persistent situation reviews, training sessions and assurance handoffs stay offline",
async ({page})=>{
  const stamp=Date.now().toString(36);
  await page.goto("/login");
  await page.getByLabel("Name").fill("Operational Incident Reviewer");
  await page.getByLabel("Email").fill("operations-"+stamp+"@cyberpilot.local");
  await page.getByLabel("Password").fill("OperationalLab2026!");
  await page.getByRole("button",{name:"Create Lab account"}).click();
  await expect(page.getByRole("heading",{name:"Security workspace"}))
    .toBeVisible({timeout:30000});
  await page.getByRole("link",{name:"Create an organization"}).click();
  await page.getByLabel("Organization name").fill("Operational Lab "+stamp);
  await page.getByRole("button",{name:"Create organization"}).click();
  await expect(page).toHaveURL(/\/organizations\/[^/]+\/?$/,{timeout:30000});
  const root=new URL(page.url()).pathname.replace(/\/$/,"");
  await page.goto(root+"/guided-incidents");
  await page.getByRole("textbox",{name:"Título"})
    .fill("Operations response "+stamp);
  await page.getByRole("textbox",{name:/Referencia de afectación/})
    .fill("principal-"+stamp);
  await page.getByRole("button",{name:"Crear caso offline"}).click();
  await expect(page.getByRole("status"))
    .toContainText("no se ejecutó ninguna acción en el proveedor");
  await page.goto(root+"/incident-situation-reviews");
  await expect(page.getByRole("heading",{
    name:"Expedientes de sala de situación"})).toBeVisible();
  await page.getByLabel("Incidente",{exact:true}).selectOption({index:1});
  await page.getByRole("button",{name:"Crear expediente de revisión"}).click();
  await expect(page.getByRole("heading",{name:/Expediente review-/}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("Fuentes no observadas")).toBeVisible();
  await page.getByRole("button",{name:"Iniciar revisión"}).click();
  await expect(page.getByRole("heading",{name:"Hallazgos del revisor"}))
    .toBeVisible();
  await page.reload();
  await page.getByLabel("Incidente",{exact:true}).selectOption({index:1});
  await expect(page.getByRole("button",{name:/review-.*IN_REVIEW/}))
    .toBeVisible({timeout:30000});
  await page.goto(root+"/incident-tabletop-sessions");
  await expect(page.getByRole("heading",{
    name:"Sesiones tabletop auditables"})).toBeVisible();
  await page.getByRole("button",{name:"Persistir nueva sesión"}).click();
  await expect(page.getByRole("heading",{name:/COMPROMISED_ACCOUNT/}))
    .toBeVisible({timeout:30000});
  await page.getByLabel("Justificación")
    .fill("Simulated unknown requiring manual analysis");
  await page.getByRole("button",{name:"Registrar decisión simulada"}).click();
  await expect(page.getByText("aceptada (ACCEPTED)",{exact:false}))
    .toBeVisible({timeout:30000});
  await page.reload();
  await expect(page.getByRole("button",{name:/Ejercicio de respuesta al incidente/}))
    .toBeVisible({timeout:30000});
  await page.goto(root+"/incident-assurance-handoffs");
  await expect(page.getByRole("heading",{
    name:"Asignaciones y escalados de aseguramiento"})).toBeVisible();
  await page.getByLabel("Incidente",{exact:true}).selectOption({index:1});
  await page.getByRole("button",{name:"Crear tablero de seguimiento"}).click();
  await expect(page.getByRole("heading",{name:/Aseguramiento interno: ACTIVE/}))
    .toBeVisible({timeout:30000});
  await expect(page.getByText("Proveedor contenido")).toBeVisible();
  await expect(page.getByText("PROPOSED_NOT_DISPATCHED",{exact:false}).first())
    .toBeVisible();
});
