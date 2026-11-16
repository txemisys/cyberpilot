import {test,expect} from "@playwright/test";

/**
 * Isolated LAB browser journey. No real Microsoft/Google/Exposure tenant
 * is contacted; the test uses real auth, app, Prisma and PostgreSQL.
 * Verifies create/action/reload/executive without claiming a live finding.
 */
test("SME no-tenant workflow: LAB findings → risk → CAS action → executive",async({page})=>{
  const suffix=Date.now().toString(36)+"-"+
    Math.random().toString(36).slice(2,7);
  await page.goto("/login");
  await expect(page.getByText("Local Lab access")).toBeVisible();
  await page.getByLabel("Name").fill("SME Offline Reviewer");
  await page.getByLabel("Email")
    .fill("integrated-offline-"+suffix+"@cyberpilot.local");
  await page.getByLabel("Password").fill("IntegratedLABOnly-2026!");
  await page.getByRole("button",{name:"Create Lab account"}).click();
  await expect(page.getByRole("heading",{
    name:"Security workspace",
  })).toBeVisible({timeout:30000});
  await page.getByRole("link",{name:"Create an organization"}).click();
  await page.getByLabel("Organization name")
    .fill("Integrated Offline "+suffix);
  await page.getByRole("button",{name:"Create organization"}).click();
  await expect(page.getByRole("button",{
    name:"Start Microsoft 365 Lab",
  })).toBeVisible();
  const root=new URL(page.url()).pathname.replace(/\/$/,"");
  expect(root).toMatch(/^\/organizations\/[^/]+$/);
  await page.getByRole("button",{
    name:"Start Microsoft 365 Lab",
  }).click();
  await expect(page.getByRole("button",{
    name:"Re-evaluate lab",
  })).toBeVisible();
  await page.getByRole("button",{name:"Re-evaluate lab"}).click();
  await expect(page.getByRole("heading",{
    name:"Top actions",
  })).toBeVisible();

  // Actual persisted LAB finding rows must reach the integrated register.
  await page.goto(root+"/integrated-risks");
  await expect(page.getByRole("heading",{
    name:"Registro integrado de riesgos y evidencias",
  })).toBeVisible();
  await page.getByRole("button",{
    name:"Actualizar desde PostgreSQL",
  }).click();
  await expect(page.getByText(
    "Se han reconciliado registros persistidos de la organización.",
  )).toBeVisible();
  await expect(page.getByText(
    "Una evaluación v2 sintética sigue siendo",
    {exact:false},
  )).toBeVisible();
  await page.getByRole("button",{name:"Riesgos",exact:true}).click();
  const riskButton=page.locator("button").filter({
    has:page.locator("strong"),
  }).filter({hasText:/CRITICAL|HIGH|MEDIUM|LOW|INFO/}).first();
  await expect(riskButton).toBeVisible();
  await riskButton.click();
  await expect(page.getByText(
    "Riesgo resuelto de forma independiente: NO.",
  )).toBeVisible();

  // A risk-action is bound to an actually persisted finding, not to a
  // free-form fabricated ID sent by the browser.
  await page.goto(root+"/integrated-actions");
  await expect(page.getByRole("heading",{
    name:"Seguimiento de riesgos de la pyme",
  })).toBeVisible();
  await page.getByRole("button",{
    name:"Consultar acciones",
  }).click();
  await expect(page.getByText(
    "Registro de seguimiento actualizado desde PostgreSQL.",
  )).toBeVisible();
  await page.getByRole("button",{
    name:"Añadir riesgo existente",
  }).click();
  await expect(page.getByText(
    "Riesgos abiertos listados desde registros persistidos.",
  )).toBeVisible();
  const eligible=page.getByRole("combobox", {name:"Riesgo"});
  await expect(eligible.locator("option").nth(1)).toBeAttached();
  await eligible.selectOption({index:1});
  await page.getByRole("button",{
    name:"Crear seguimiento auditado",
  }).click();
  await expect(page.getByText(
    "Acción persistida. Ningún control ha sido remediado.",
  )).toBeVisible();
  await page.reload();
  await page.getByRole("button",{
    name:"Consultar acciones",
  }).click();
  await expect(page.getByText(
    "Registro de seguimiento actualizado desde PostgreSQL.",
  )).toBeVisible();
  await page.getByRole("button",{name:"Seguimiento"}).click();
  const actionButton=page.locator("section").filter({
    has:page.getByRole("heading",{name:"Acciones y estados"}),
  }).getByRole("button").filter({
    hasText:/./,
  }).first();
  await expect(actionButton).toBeVisible();
  // The first button inside the action list is the persisted title.
  const actionTitle=page.locator("ul li button").filter({
    hasText:/./,
  }).first();
  await actionTitle.click();
  await expect(page.getByText(
    "Remediación independiente verificada: NO.",
  )).toBeVisible();
  await page.getByRole("button",{
    name:/Registrar transición v1 → v2/,
  }).click();
  await expect(page.getByText(
    "Cambio registrado con auditoría y CAS.",
    {exact:false},
  )).toBeVisible();

  await page.goto(root+"/integrated-executive");
  await expect(page.getByRole("heading",{
    name:"Estado de riesgos, cobertura y seguimiento",
  })).toBeVisible();
  await page.getByRole("button",{
    name:"Generar informe desde PostgreSQL",
  }).click();
  await expect(page.getByText(
    "Panel reconstruido desde los registros persistidos.",
  )).toBeVisible();
  await expect(page.getByText(
    "Este valor no es CyberScore v1",
    {exact:false},
  )).toBeVisible();
  await page.getByRole("button",{
    name:"Seguimiento",exact:true,
  }).click();
  await expect(page.getByRole("heading",{
    name:"Estado operativo de acciones",
  })).toBeVisible();
  await expect(page.getByText(
    "no desde este informe inmutable.",
    {exact:false},
  )).toBeVisible();

  // The export route must remain read only and explicitly safe.
  const exportResponse=await page.request.get(
    root.replace("/organizations/","/api/organizations/")+
    "/integrated-executive?format=JSON",
  );
  expect(exportResponse.ok()).toBe(true);
  const payload=await exportResponse.json();
  expect(payload.externalProviderCalls).toBe(0);
  expect(payload.legacyScoreChanged).toBe(false);
  expect(payload.acceptedCustomerRisk).toBe(false);
  expect(payload.independentlyVerifiedRemediation).toBe(false);
  const exported=JSON.parse(payload.artifact.content);
  expect(exported.organizationId).toBeTruthy();
  expect(exported.customerCertificationGranted).toBe(false);
  expect(exported.historicalCyberScoreRewritten).toBe(false);
});
