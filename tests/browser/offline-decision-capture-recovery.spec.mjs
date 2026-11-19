import{test,expect}from "@playwright/test";

/**
 * Real LAB PostgreSQL persistence, no real external customer tenant.
 * Covers decision -> audited case -> snapshot -> artifact integrity
 * rehearsal. A rehearsal is NOT a database backup restoration.
 */
test("integrated offline case, persisted report and recovery integrity",
 async({page})=>{
 const suffix=Date.now().toString(36)+"-"+
 Math.random().toString(36).slice(2,7);
 await page.goto("/login");
 await expect(page.getByText("Local Lab access")).toBeVisible();
 await page.getByLabel("Name").fill("Offline Recovery Operator");
 await page.getByLabel("Email").fill("offline-recovery-"+suffix+
 "@cyberpilot.local");
 await page.getByLabel("Password").fill("OfflineRecovery-2026!");
 await page.getByRole("button",{name:"Create Lab account"}).click();
 await expect(page.getByRole("heading",{
 name:"Security workspace",
 })).toBeVisible({timeout:30000});
 await page.getByRole("link",{name:"Create an organization"}).click();
 await page.getByLabel("Organization name").fill("Recovery LAB "+suffix);
 await page.getByRole("button",{name:"Create organization"}).click();
 await expect(page.getByRole("button",{
 name:"Start Microsoft 365 Lab",
 })).toBeVisible();
 const root=new URL(page.url()).pathname.replace(/\/$/,"");
 expect(root).toMatch(/^\/organizations\/[^/]+$/);
 await page.getByRole("button",{
 name:"Start Microsoft 365 Lab"}).click();
 await expect(page.getByRole("button",{
 name:"Re-evaluate lab"})).toBeVisible();
 await page.getByRole("button",{name:"Re-evaluate lab"}).click();
 await expect(page.getByRole("heading",{name:"Top actions"})).toBeVisible();

 await page.goto(root+"/decision-cases");
 await expect(page.getByRole("heading",{
 name:"Casos auditados derivados de evidencia",
 })).toBeVisible();
 await page.getByRole("button",{name:"Consultar casos"}).click();
 await expect(page.getByText(
 "Casos reconciliados con las fuentes persistidas.")).toBeVisible();
 await page.getByRole("button",{
 name:"Crear desde decisión actual"}).click();
 await expect(page.getByText(
 "Se muestran solo decisiones del tenant actual.")).toBeVisible();
 const decision=page.getByRole("combobox",{name:"Decisión"});
 await expect(decision.locator("option").nth(1)).toBeAttached();
 await decision.selectOption({index:1});
 await page.getByRole("button",{name:"Crear caso auditado"}).click();
 await expect(page.getByText(
 "Caso creado; no se ha realizado remediación técnica.")).toBeVisible();
 await page.getByRole("button",{name:"BOARD",exact:true}).click();
 const caseRow=page.locator("ol li button").first();
 await expect(caseRow).toBeVisible();
 await caseRow.click();
 await expect(page.getByText(
 "Remediación técnica independiente: NO.")).toBeVisible();
 await page.getByRole("button",{name:/Registrar revisión 2/}).click();
 await expect(page.getByText(
 "Transición CAS auditada, sin ejecución externa.")).toBeVisible();
 await page.reload();
 await page.getByRole("button",{name:"Consultar casos"}).click();
 await expect(page.getByText(
 "Casos reconciliados con las fuentes persistidas.")).toBeVisible();

 await page.goto(root+"/offline-captures");
 await expect(page.getByRole("heading",{
 name:"Histórico inmutable de informes y procedencia",
 })).toBeVisible();
 await page.getByRole("button",{name:"Consultar cortes"}).click();
 await expect(page.getByText(
 "Inventario persistido reconciliado con PostgreSQL.")).toBeVisible();
 await page.getByRole("button",{name:"Crear corte",exact:true}).click();
 await page.getByRole("button",{name:"Guardar corte auditado"}).click();
 await expect(page.getByText(
 "Corte preservado con digest; no se ha generado certificación."))
 .toBeVisible();
 await page.reload();
 await page.getByRole("button",{name:"Consultar cortes"}).click();
 await expect(page.getByText(
 "Inventario persistido reconciliado con PostgreSQL.")).toBeVisible();

 await page.goto(root+"/offline-recovery");
 await expect(page.getByRole("heading",{
 name:"Ensayo de recuperación de informes persistidos",
 })).toBeVisible();
 await page.getByRole("button",{name:"Consultar ensayos"}).click();
 await page.getByRole("button",{
 name:"Evaluar matriz de capturas"}).click();
 await expect(page.getByText(
 "Origen y disponibilidad reconciliados.")).toBeVisible();
 await page.getByRole("button",{
 name:"Registrar ensayo con selección"}).click();
 await expect(page.getByText(
 "Ensayo de artefactos registrado sin restauración SQL.")).toBeVisible();
 await expect(page.getByText("Bloqueados")).toBeVisible();
 await page.getByRole("button",{name:"RUNS",exact:true}).click();
 const run=page.locator("ol li button").first();
 await expect(run).toBeVisible();
 await run.click();
 await expect(page.getByText(
 "Restauraciones reales de base de datos: 0.")).toBeVisible();

 const api=root.replace("/organizations/","/api/organizations/");
 for(const endpoint of ["decision-cases","offline-captures",
 "offline-recovery"]){
 const response=await page.request.get(api+"/"+endpoint);
 expect(response.ok()).toBe(true);
 const body=await response.json();
 expect(body.providerCalls).toBe(0);
 }
 const stored=await page.request.get(
 api+"/offline-recovery?mode=LIST");
 const runs=(await stored.json()).data;
 expect(runs.summary.total).toBeGreaterThanOrEqual(1);
 expect(runs.entries[0].report.actualDatabaseRestoreExecuted).toBe(false);
});
