import{describe,it,expect}from"vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}from"./integrated-risk-engine";
import{buildOfflineCapturePayload,sealOfflineCapture}from"./offline-report-capture-domain";
import{defaultRecoveryRehearsalPolicy}from"./offline-recovery-rehearsal-domain";
import{buildRecoveryFaultMatrix,verifyRecoveryFaultMatrix,buildRecoveryDevelopmentAcceptance,exportRecoveryFaultMatrix}from"./offline-recovery-fault-matrix";
const at="2026-11-23T10:00:00.000Z";
function setup(){
 const input:IntegratedRiskInput={organizationId:"org-test",evaluatedAt:at,evidence:[],findings:[],assessments:[],declaredActions:[],sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},countOfRecords:{evidence:0,findings:0,assessments:0,declaredActions:0}};
 const report=buildIntegratedRiskDigest(input);
 const payload=buildOfflineCapturePayload({organizationId:"org-test",kind:"INTEGRATED_RISKS",capturedAt:at,report});
 return sealOfflineCapture({id:"capture-one",actorUserId:"member-one",createdAt:at,payload});
}
function matrix(){
 const policy={...defaultRecoveryRehearsalPolicy(),requiredKinds:["INTEGRATED_RISKS"] as Array<"INTEGRATED_RISKS">,requireCrossReportBindings:false};
 return buildRecoveryFaultMatrix({organizationId:"org-test",executedAt:"2026-11-23T12:00:00.000Z",captures:[setup()],policy});
}
describe("fault injection is local JSON integrity, never PostgreSQL restore",()=>{
 it("captures a checked baseline with explicit unknown SQL and LIVE gates",()=>{
  const m=matrix();
  expect(m.baselineStatus).toBe("PASS");
  expect(m.actualSqlRestoreExecuted).toBe(false);
  expect(m.sqlRecoveryGate).toBe("NOT_VERIFIED");
  expect(m.liveAuthorizationGate).toBe("NOT_VERIFIED");
  expect(m.providerCalls).toBe(0);
  expect(verifyRecoveryFaultMatrix(m,"org-test").valid).toBe(true);
 });
 it("detects checksum tampering and tenant substitutions",()=>{
  const m=matrix();
  expect(m.faults.find(x=>x.fault==="PAYLOAD_CHECKSUM_TAMPER")?.detected).toBe(true);
  expect(m.faults.find(x=>x.fault==="FOREIGN_TENANT_SUBSTITUTION")?.detected).toBe(true);
 });
 it("cannot promote a LIVE or SQL recovery acceptance from JSON rehearsal",()=>{
  const result=buildRecoveryDevelopmentAcceptance(matrix());
  expect(result.sqlRestoreGate).toBe("NOT_VERIFIED");
  expect(result.liveTenantGate).toBe("NOT_VERIFIED");
  expect(result.productionRecoveryProven).toBe(false);
  expect(result.CyberScoreV1Modified).toBe(false);
 });
 it("rejects non-tenant captures and false SQL claim mutations",()=>{
  const c=setup();c.organizationId="foreign-org";
  expect(()=>buildRecoveryFaultMatrix({organizationId:"org-test",executedAt:at,captures:[c]})).toThrow();
  const m=matrix();m.actualSqlRestoreExecuted=true as false;
  expect(verifyRecoveryFaultMatrix(m,"org-test").valid).toBe(false);
 });
 it("exports conservative acceptance and rejects tampered digest",()=>{
  const m=matrix();
  expect(exportRecoveryFaultMatrix(m,"MARKDOWN").content).toContain("NOT VERIFIED");
  m.digest="0".repeat(64);
  expect(()=>exportRecoveryFaultMatrix(m,"CSV")).toThrow();
 });
});
