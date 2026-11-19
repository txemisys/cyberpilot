import{describe,it,expect}from "vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}
 from "./integrated-risk-engine";
import{buildOfflineCapturePayload,sealOfflineCapture}
 from "./offline-report-capture-domain";
import{
 defaultRecoveryRehearsalPolicy,validateRecoveryPolicy,
 buildOfflineRecoveryRehearsal,verifyRecoveryRehearsal,
 createRecoveryRemediationPlan,compareRecoveryRehearsals,
 exportRecoveryRehearsal,
}from "./offline-recovery-rehearsal-domain";
const at="2026-11-19T14:00:00.000Z";
function report(){
 const input:IntegratedRiskInput={
 organizationId:"org-test",evaluatedAt:"2026-11-19T12:00:00.000Z",
 evidence:[],findings:[],assessments:[],declaredActions:[],
 sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},
 countOfRecords:{evidence:0,findings:0,assessments:0,declaredActions:0},
 };
 return buildIntegratedRiskDigest(input);
}
function capture(){
 return sealOfflineCapture({
 id:"capture-one",actorUserId:"member-one",
 createdAt:"2026-11-19T13:00:00.000Z",
 payload:buildOfflineCapturePayload({
 organizationId:"org-test",kind:"INTEGRATED_RISKS",
 capturedAt:"2026-11-19T13:00:00.000Z",
 report:report(),
 }),
 });
}
function policy(){
 return{
 ...defaultRecoveryRehearsalPolicy(),
 requiredKinds:["INTEGRATED_RISKS"] as Array<"INTEGRATED_RISKS">,
 requireCrossReportBindings:false,
 };
}
function rehearsal(time=at){
 return buildOfflineRecoveryRehearsal({
 organizationId:"org-test",executedAt:time,
 captures:[capture()],policy:policy(),
 });
}
describe("offline report integrity rehearsals",()=>{
 it("validates policy and rejects duplicate kinds",()=>{
 const valid=policy();
 expect(validateRecoveryPolicy(valid)).toEqual([]);
 valid.requiredKinds=["INTEGRATED_RISKS","INTEGRATED_RISKS"];
 expect(validateRecoveryPolicy(valid)).toContain("REQUIRED_KINDS_INVALID");
 });
 it("verifies a valid local read-only artifact without claiming SQL restoration",()=>{
 const value=rehearsal();
 expect(value.status).toBe("PASS");
 expect(value.overview.reportsReplayedReadOnly).toBe(1);
 expect(value.overview.databaseRestoreOperations).toBe(0);
 expect(value.actualDatabaseRestoreExecuted).toBe(false);
 expect(value.customerLiveAcceptanceAllowed).toBe(false);
 expect(verifyRecoveryRehearsal(value,"org-test").valid).toBe(true);
 });
 it("never upgrades unknown LIVE authorization and DB restore gates",()=>{
 const value=rehearsal();
 expect(value.gates.find(x=>x.id==="LIVE_AUTHORIZATION")?.status)
 .toBe("NOT_VERIFIED");
 expect(value.gates.find(x=>x.id==="DATABASE_RESTORE")?.status)
 .toBe("NOT_VERIFIED");
 expect(value.operatorDevelopmentAcceptanceAllowed).toBe(true);
 expect(value.customerLiveAcceptanceAllowed).toBe(false);
 });
 it("blocks missing required report kinds by default",()=>{
 const result=buildOfflineRecoveryRehearsal({
 organizationId:"org-test",executedAt:at,
 captures:[capture()],policy:defaultRecoveryRehearsalPolicy(),
 });
 expect(result.status).toBe("BLOCKED");
 expect(result.overview.missingRequiredKinds).toBe(3);
 expect(result.issues.some(x=>x.includes("SOURCE_PRESENT"))).toBe(true);
 });
 it("fails closed for cross-organization archived records",()=>{
 const wrong=capture();wrong.organizationId="other-org";
 expect(()=>buildOfflineRecoveryRehearsal({
 organizationId:"org-test",executedAt:at,
 captures:[wrong],policy:policy(),
 })).toThrow("CROSS_TENANT");
 });
 it("detects expired archives under bounded retention policy",()=>{
 const value=buildOfflineRecoveryRehearsal({
 organizationId:"org-test",
 executedAt:"2027-01-01T14:00:00.000Z",
 captures:[capture()],policy:policy(),
 });
 expect(value.status).toBe("BLOCKED");
 expect(value.gates.find(x=>x.id==="CAPTURE_AGE")?.status).toBe("BLOCK");
 });
 it("detects altered source checksums without pretending successful replay",()=>{
 const bad=capture();
 bad.payloadDigest="a".repeat(64);
 const value=buildOfflineRecoveryRehearsal({
 organizationId:"org-test",executedAt:at,
 captures:[bad],policy:policy(),
 });
 expect(value.status).toBe("BLOCKED");
 expect(value.overview.reportsReplayedReadOnly).toBe(0);
 expect(value.overview.payloadIntegrityFailures).toBe(1);
 });
 it("does not issue LIVE consent from a remediation plan",()=>{
 const blocked=buildOfflineRecoveryRehearsal({
 organizationId:"org-test",executedAt:at,
 captures:[capture()],policy:defaultRecoveryRehearsalPolicy(),
 });
 const plan=createRecoveryRemediationPlan(blocked);
 expect(plan.remainingBlockers).toBeGreaterThan(0);
 expect(plan.technicalRemediationAutomaticallyPerformed).toBe(false);
 expect(plan.legalConsentGenerated).toBe(false);
 expect(plan.steps.find(x=>x.gate==="LIVE_AUTHORIZATION")
 ?.requiresCustomerTenantAuthorization).toBe(true);
 });
 it("compares local gates without claiming a production database restore",()=>{
 const first=rehearsal();
 const second=rehearsal("2026-11-19T15:00:00.000Z");
 const diff=compareRecoveryRehearsals(first,second);
 expect(diff.dataRecoveryVerifiedInProduction).toBe(false);
 expect(diff.actualProviderDataRestored).toBe(false);
 });
 it("exports locally bounded JSON CSV and Markdown",()=>{
 const value=rehearsal();
 const json=exportRecoveryRehearsal(value,"JSON");
 expect(JSON.parse(json.content).overview.providerCalls).toBe(0);
 expect(exportRecoveryRehearsal(value,"CSV").content)
 .toContain("DATABASE_RESTORE");
 expect(exportRecoveryRehearsal(value,"MARKDOWN").content)
 .toContain("No LIVE customer security certification");
 });
 it("rejects forged successful restoration claims",()=>{
 const value=rehearsal();
 value.actualDatabaseRestoreExecuted=true as false;
 expect(verifyRecoveryRehearsal(value).errors)
 .toContain("FALSE_RECOVERY_OR_SECURITY_CLAIM");
 });
});
