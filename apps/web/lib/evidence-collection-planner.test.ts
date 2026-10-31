import {describe,expect,it} from "vitest";
import {buildEvidenceCollectionPlan,deriveEvidenceCollectionInstruction,evidenceCollectionPlanCsv,evidenceCollectionPlanText} from "./evidence-collection-planner";
import {buildReconciliationPortfolio,reconcileFinding,reconciliationCsv,reconciliationText} from "./remediation-reconciliation";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
const date=(day:string)=>new Date(day+"T12:00:00Z");
const action=(status:string):ReviewAction=>({
 id:"action-1",title:"Require administrator MFA",status,
 mode:"GUIDED",createdAt:date("2026-01-01"),
 approvedAt:date("2026-01-02"),startedAt:date("2026-01-03"),
 completedAt:status==="SUCCEEDED"||status==="VERIFIED"?date("2026-01-05"):null,
 verifiedAt:status==="VERIFIED"?date("2026-01-06"):null,
 steps:["Enable policy"],verification:["Inspect fresh MFA evidence"],
 acknowledgedSteps:new Set(),
});
const signal=(source:ReviewEvidence["source"],day="2026-01-02"):ReviewEvidence=>({
 id:source,source,category:"IDENTITY",summary:"MFA",
 capturedAt:date(day),lastObservedAt:source==="OBSERVED"?date(day):null,
});
const finding=(values:Partial<ReviewFinding>={}):ReviewFinding=>({
 id:"finding-1",title:"Administrator MFA disabled",
 description:"Administrator identities require MFA.",
 severity:"HIGH",status:"OPEN",firstSeenAt:date("2026-01-01"),
 lastSeenAt:date("2026-01-05"),resolvedAt:null,
 evidence:[],actions:[],...values,
});
describe("Evidence collection preparation",()=>{
 it("does not infer evidence from missing control identifier matches",()=>{
  const result=deriveEvidenceCollectionInstruction(finding());
  expect(result.state).toBe("unavailable");
  expect(result.needsNewObservation).toBe(true);
  expect(result.instructions.length).toBeGreaterThan(5);
 });
 it("treats declarations as distinct from independent observations",()=>{
  const result=deriveEvidenceCollectionInstruction(finding({
   evidence:[signal("DECLARED")],
  }));
  expect(result.state).toBe("declared-only");
  expect(result.observedRecordIds).toHaveLength(0);
  expect(result.cautions.join(" ")).toContain("cannot independently verify");
 });
 it("identifies unknown source records requiring investigation",()=>{
  const result=deriveEvidenceCollectionInstruction(finding({
   evidence:[signal("ERROR")],
  }));
  expect(result.state).toBe("inconclusive");
  expect(result.inconclusiveRecordIds).toHaveLength(1);
 });
 it("requires a fresh observation after completed remediation",()=>{
  const result=deriveEvidenceCollectionInstruction(finding({
   evidence:[signal("OBSERVED")],actions:[action("SUCCEEDED")],
  }));
  expect(result.state).toBe("needs-refresh");
  expect(result.observationAt).toEqual(date("2026-01-02"));
  expect(result.latestWorkAt).toEqual(date("2026-01-05"));
 });
 it("does not automatically claim an observed control is effective",()=>{
  const result=deriveEvidenceCollectionInstruction(finding({
   evidence:[signal("OBSERVED","2026-01-08")],
   actions:[action("SUCCEEDED")],
  }));
  expect(result.state).toBe("available");
  expect(result.purpose).toContain("Check whether");
 });
 it("counts critical and high needs independently",()=>{
  const report=buildEvidenceCollectionPlan([
   finding({id:"critical",severity:"CRITICAL"}),
   finding({id:"high",severity:"HIGH"}),
   finding({id:"low",severity:"LOW",evidence:[signal("OBSERVED")]}),
  ]);
  expect(report.total).toBe(3);
  expect(report.affectedCritical).toBe(1);
  expect(report.affectedHigh).toBe(1);
  expect(report.available).toBe(1);
 });
 it("produces source-limited text and formula-safe CSV",()=>{
  const report=buildEvidenceCollectionPlan([
   finding({title:'=HYPERLINK("unsafe")'}),
  ]);
  expect(evidenceCollectionPlanText(report)).toContain("does not trigger a provider scan");
  const csv=evidenceCollectionPlanCsv(report);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
describe("Remediation outcome reconciliation",()=>{
 it("reports unaddressed open findings without inventing a workflow",()=>{
  expect(reconcileFinding(finding())[0]).toMatchObject({
   outcome:"unaddressed",actionId:null,needsReviewer:true,
  });
 });
 it("keeps verified actions distinct from open finding state",()=>{
  const [result]=reconcileFinding(finding({actions:[action("VERIFIED")]}));
  expect(result?.outcome).toBe("verified-but-open");
  expect(result?.verifiedAt).toEqual(date("2026-01-06"));
 });
 it("distinguishes a resolved finding from verified linked remediation",()=>{
  const [result]=reconcileFinding(finding({
   status:"RESOLVED",resolvedAt:date("2026-01-10"),
  }));
  expect(result?.outcome).toBe("resolved-separately");
 });
 it("recognizes completed-but-unverified operations",()=>{
  const [result]=reconcileFinding(finding({
   evidence:[signal("OBSERVED")],actions:[action("SUCCEEDED")],
  }));
  expect(result?.outcome).toBe("completed-not-verified");
  expect(result?.warnings.join(" ")).toContain("does not follow");
 });
 it("identifies failed work independently of findings",()=>{
  const [result]=reconcileFinding(finding({actions:[action("FAILED")]}));
  expect(result?.outcome).toBe("failed-work");
 });
 it("does not consider aligned record states a certification",()=>{
  const [result]=reconcileFinding(finding({
   status:"RESOLVED",resolvedAt:date("2026-01-10"),
   actions:[action("VERIFIED")],
  }));
  expect(result?.outcome).toBe("aligned-verified");
  expect(result?.warnings.join(" ")).toContain("does not independently certify");
 });
 it("summarizes multiple reconciliation rows by priority",()=>{
  const portfolio=buildReconciliationPortfolio([
   finding({id:"f1",actions:[action("VERIFIED")]}),
   finding({id:"f2",actions:[action("SUCCEEDED")]}),
   finding({id:"f3"}),
  ]);
  expect(portfolio.total).toBe(3);
  expect(portfolio.verifiedOpen).toBe(1);
  expect(portfolio.completedNotVerified).toBe(1);
  expect(portfolio.affectedFindings).toBe(3);
  expect(portfolio.entries[0]?.outcome).toBe("verified-but-open");
 });
 it("exports safe reconciled outcomes without original evidence payloads",()=>{
  const portfolio=buildReconciliationPortfolio([
   finding({title:'=HYPERLINK("unsafe")'}),
  ]);
  const csv=reconciliationCsv(portfolio);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv.startsWith("\uFEFF")).toBe(true);
  expect(reconciliationText(portfolio)).toContain("REMEDIATION OUTCOME RECONCILIATION");
 });
});
