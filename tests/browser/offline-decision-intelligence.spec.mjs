import {test,expect} from "@playwright/test";
/**
 * Actual PostgreSQL-backed offline experience: the UI only observes
 * authenticated org-local records; no Microsoft/Google/Exposure LIVE.
 */
test("offline SME triage, SLA and historical assessment journey",async({page})=>{
 const id=Date.now().toString(36)+"-"+
   Math.random().toString(36).slice(2,7);
 await page.goto("/login");
 await expect(page.getByText("Local Lab access")).toBeVisible();
 await page.getByLabel("Name").fill("Offline Decision Reviewer");
 await page.getByLabel("Email").fill("offline-decisions-"+id+
  "@cyberpilot.local");
 await page.getByLabel("Password").fill("OfflineDecisionOnly-2026!");
 await page.getByRole("button",{name:"Create Lab account"}).click();
 await expect(page.getByRole("heading",{
   name:"Security workspace"})).toBeVisible({timeout:30000});
 await page.getByRole("link",{name:"Create an organization"}).click();
 await page.getByLabel("Organization name").fill("Offline Decision "+id);
 await page.getByRole("button",{name:"Create organization"}).click();
 await expect(page.getByRole("button",{
   name:"Start Microsoft 365 Lab"})).toBeVisible();
 const root=new URL(page.url()).pathname.replace(/\/$/,"");
 expect(root).toMatch(/^\/organizations\/[^/]+$/);

 // No fake findings need be created: a new organization has no
 // authenticated security posture, and reports must say so.
 await page.goto(root+"/evidence-decisions");
 await expect(page.getByRole("heading",{
  name:"Cola de revisión y procedencia de fuentes"})).toBeVisible();
 await page.getByRole("button",{
  name:"Actualizar revisión de evidencias"}).click();
 await expect(page.getByText(
  "Procedencia y decisiones reconciliadas desde PostgreSQL."))
  .toBeVisible();
 await expect(page.getByText(/NO_DATA|REVIEW_REQUIRED|BLOCKED/)).toBeVisible();
 await page.getByRole("button",{name:"EXPORT"}).click();
 await expect(page.getByText("No emitir conclusiones de seguridad",
  {exact:false})).toBeVisible();

 await page.goto(root+"/offline-sla");
 await expect(page.getByRole("heading",{
  name:"Plazos y escalados internos de acciones"})).toBeVisible();
 await page.getByRole("button",{name:"Evaluar seguimiento"}).click();
 await expect(page.getByText(
  "Plazos internos calculados desde los eventos persistidos."))
  .toBeVisible();
 await page.getByRole("button",{name:"CALENDAR"}).click();
 await expect(page.getByText(
  "no incorpora cambios estacionales automáticos.",
  {exact:false})).toBeVisible();
 await page.getByRole("button",{name:"INTEGRITY"}).click();
 await expect(page.getByText("Operaciones externas realizadas:",
  {exact:false})).toBeVisible();

 await page.goto(root+"/offline-trends");
 await expect(page.getByRole("heading",{
  name:"Comparación conservadora de evaluaciones"})).toBeVisible();
 await page.getByRole("button",{
  name:"Consultar historial PostgreSQL"}).click();
 await expect(page.getByText(
  "Historial reconstruido desde snapshots v2 y eventos de acciones."))
  .toBeVisible();
 await page.getByRole("button",{name:"INTEGRITY"}).click();
 await expect(page.getByText("Modelo v1 modificado:",
  {exact:false})).toBeVisible();
 await expect(page.getByText("Mejora de seguridad certificada:",
  {exact:false})).toBeVisible();

 const endpoint=root.replace("/organizations/","/api/organizations/");
 for(const path of ["evidence-decisions","offline-sla","offline-trends"]){
  const response=await page.request.get(endpoint+"/"+path);
  expect(response.ok()).toBe(true);
  const result=await response.json();
  expect(result.providerCalls).toBe(0);
  expect(result.report.organizationId).toBeTruthy();
  expect(typeof result.report.reportDigest).toBe("string");
 }
 const csv=await page.request.get(
  endpoint+"/offline-trends?format=CSV");
 expect(csv.ok()).toBe(true);
 expect((await csv.json()).v1Writes).toBe(0);
});
