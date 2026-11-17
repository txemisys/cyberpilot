import{describe,it,expect}from "vitest";
import{buildIntegratedRiskDigest,type IntegratedRiskInput}from
 "./integrated-risk-engine";
import{buildEvidenceDecisionReport,verifyEvidenceDecisionReport,
 filterEvidenceDecisions,compareEvidenceDecisionReports,
 exportEvidenceDecisions}from "./evidence-decision-engine";
import{planEvidenceReviewSprint,summarizeEvidenceReviewBacklog}from
 "./evidence-review-sprint";
const at="2026-11-17T08:00:00.000Z";
function fixture():IntegratedRiskInput{
 return{
  organizationId:"org-test",evaluatedAt:at,
  evidence:[{id:"evidence-one",organizationId:"org-test",
   source:"BASELINE",domain:"BACKUP",
   controlId:"BACKUP_TEST",scope:"org",
   state:"DECLARED",observedAt:null,
   createdAt:at,details:{}},
  {id:"evidence-two",organizationId:"org-test",
   source:"ASSETS",domain:"ENDPOINT",
   controlId:"PATCH",scope:"device-01",
   state:"ERROR",observedAt:null,
   createdAt:at,details:{}}],
  findings:[{id:"finding-one",organizationId:"org-test",
   ruleId:"BACKUP_TEST",key:"backup-tenant",
   severity:"HIGH",status:"OPEN",title:"Backup unverified",
   description:"Manual declaration only",lastSeenAt:at,evidence:null}],
  assessments:[],declaredActions:[],
  sourceLimits:{evidence:10,findings:10,assessments:10,declaredActions:10},
  countOfRecords:{evidence:2,findings:1,assessments:0,declaredActions:0},
 };
}
function report(){
 return buildEvidenceDecisionReport(buildIntegratedRiskDigest(fixture()));
}
describe("offline evidence decisions",()=>{
 it("preserves declared state and demands technical proof",()=>{
  const value=report();
  expect(value.organizationId).toBe("org-test");
  expect(value.externalTenantAuthenticated).toBe(false);
  expect(value.automaticallyResolvedFindings).toBe(false);
  expect(value.decisions.some(x=>x.code==="REVIEW_DECLARATION")).toBe(true);
  expect(value.decisions.some(x=>x.code==="REQUEST_TECHNICAL_PROOF")).toBe(true);
  expect(value.decisions.some(x=>x.code==="REVIEW_ERROR")).toBe(true);
  expect(value.totals.unresolvedRisks).toBe(1);
  expect(verifyEvidenceDecisionReport(value,"org-test").valid).toBe(true);
 });
 it("refuses modified severity or false certification",()=>{
  const value=report();
  value.decisions[0]!.priority="P3";
  expect(verifyEvidenceDecisionReport(value).valid).toBe(false);
  expect(verifyEvidenceDecisionReport(value,"different").errors)
   .toContain("TENANT_MISMATCH");
 });
 it("supports safe pagination and filtering",()=>{
  const value=report();
  const page=filterEvidenceDecisions(value,{
   priority:["P0","P1"],limit:2,offset:0,
  });
  expect(page.items.length).toBeLessThanOrEqual(2);
  expect(page.noDataIsHealthy).toBe(false);
  expect(()=>filterEvidenceDecisions(value,{limit:201})).toThrow();
 });
 it("does not infer change from disappearance of a decision",()=>{
  const first=report();
  const next=fixture();next.evaluatedAt="2026-11-17T09:00:00.000Z";
  next.findings[0]!.status="RESOLVED";
  const second=buildEvidenceDecisionReport(buildIntegratedRiskDigest(next));
  const comparison=compareEvidenceDecisionReports(first,second);
  expect(comparison.absentDecisionIndicatesRemediation).toBe(false);
 });
 it("plans a bounded local work sprint without execution",()=>{
  const result=planEvidenceReviewSprint({
   report:report(),startAt:at,capacity:7,
   sourceLimit:2,domainLimit:2,
  });
  expect(result.planned.reduce((n,x)=>n+x.estimatedUnits,0))
   .toBeLessThanOrEqual(7);
  expect(result.actualRemediationVerified).toBe(false);
  expect(result.unidentifiedCustomerProof).toBe(true);
  expect(result.deferred.length).toBeGreaterThan(0);
 });
 it("identifies source-specific debt and safe export metadata",()=>{
  const value=report();
  const backlog=summarizeEvidenceReviewBacklog(value);
  expect(backlog.customerSecurityVerified).toBe(false);
  expect(backlog.sourceSummary.length).toBe(2);
  const csv=exportEvidenceDecisions(value,"CSV");
  expect(csv.content).toContain("REQUEST_TECHNICAL_PROOF");
  expect(JSON.parse(exportEvidenceDecisions(value,"JSON").content)
   .complianceCertified).toBe(false);
 });
 it("quarantines missing source coverage from bounded read",()=>{
  const input=fixture();input.countOfRecords.evidence=20;
  const value=buildEvidenceDecisionReport(buildIntegratedRiskDigest(input));
  expect(value.outcome).toBe("BLOCKED");
  expect(value.decisions.some(x=>x.code==="QUARANTINE")).toBe(true);
 });
});
