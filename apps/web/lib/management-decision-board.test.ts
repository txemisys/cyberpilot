import {describe,expect,it} from "vitest";
import {
 buildManagementDecisions,buildManagementDecisionBoard,
 managementDecisionsCsv,managementDecisionsText,
} from "./management-decision-board";
import {assessClosureReadiness,buildClosureReadinessPortfolio,closureReadinessCsv} from "./closure-readiness";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";

const d=(day:string)=>new Date(day+"T12:00:00Z");
const observed=(kind:ReviewEvidence["source"],day="2026-01-02"):ReviewEvidence=>({
 id:kind,source:kind,category:"IDENTITY",summary:"Admin MFA",
 capturedAt:d(day),lastObservedAt:kind==="OBSERVED"?d(day):null,
});
const action=(status:string):ReviewAction=>({
 id:"action",title:"Require administrator MFA",status,mode:"GUIDED",
 createdAt:d("2026-01-01"),approvedAt:d("2026-01-02"),
 startedAt:d("2026-01-03"),
 completedAt:status==="SUCCEEDED"?d("2026-01-04"):null,
 verifiedAt:status==="VERIFIED"?d("2026-01-06"):null,
 steps:["Enable policy","Test sign-in"],verification:["Collect new identity signal"],
 acknowledgedSteps:new Set([0]),
});
const finding=(overrides:Partial<ReviewFinding>={}):ReviewFinding=>({
 id:"finding",title:"Admin MFA disabled",description:"Privileged account risk",
 severity:"CRITICAL",status:"OPEN",firstSeenAt:d("2026-01-01"),
 lastSeenAt:d("2026-01-05"),resolvedAt:null,
 evidence:[],actions:[],...overrides,
});
describe("SME management decisions",()=>{
 it("recommends investigation when no remediation exists",()=>{
  const [item]=buildManagementDecisions(finding());
  expect(item).toMatchObject({
   category:"investigation",priority:"urgent",actionId:null,
  });
  expect(item?.successCriteria.length).toBeGreaterThan(0);
 });
 it("does not call acknowledged work verified",()=>{
  const source=finding({
   actions:[{...action("APPROVED"),acknowledgedSteps:new Set([0,1])}],
  });
  const [item]=buildManagementDecisions(source);
  expect(item?.category).toBe("verification");
  expect(item?.recommendedAction).toContain("observation");
  expect(item?.verificationAt).toBeNull();
 });
 it("uses real finding urgency and aggregates decision categories",()=>{
  const board=buildManagementDecisionBoard([
   finding({id:"critical",actions:[action("SUCCEEDED")]}),
   finding({id:"low",severity:"LOW",actions:[action("PROPOSED")]}),
  ]);
  expect(board.summary.total).toBe(2);
  expect(board.summary.affectedFindings).toBe(2);
  expect(board.summary.urgent).toBe(1);
  expect(board.items[0]?.findingId).toBe("critical");
 });
 it("exports spreadsheet-safe CSV and text agenda",()=>{
  const board=buildManagementDecisionBoard([
   finding({title:'=HYPERLINK("unsafe")'}),
  ]);
  const csv=managementDecisionsCsv(board.items);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv.startsWith("\uFEFF")).toBe(true);
  expect(managementDecisionsText(board.items)).toContain("SECURITY OPERATIONS DECISION BOARD");
 });
});
describe("Finding closure-readiness gates",()=>{
 it("evaluates exactly eight recorded checks",()=>{
  const result=assessClosureReadiness(finding());
  expect(result.gates).toHaveLength(8);
  expect(result.notMet).toBeGreaterThan(0);
  expect(result.gates.find(x=>x.id==="finding-closure")?.result).toBe("not-met");
 });
 it("requires observed evidence and never accepts declaration as independent verification",()=>{
  const result=assessClosureReadiness(finding({
   evidence:[observed("DECLARED")],
  }));
  expect(result.gates.find(x=>x.id==="evidence-quality")?.result).toBe("not-met");
  expect(result.lastObservationAt).toBeNull();
 });
 it("requires human review even with a recent observation",()=>{
  const result=assessClosureReadiness(finding({
   evidence:[observed("OBSERVED","2026-01-07")],
   actions:[action("SUCCEEDED")],
  }));
  expect(result.gates.find(x=>x.id==="fresh-observation")?.result).toBe("needs-review");
  expect(result.gates.find(x=>x.id==="evidence-quality")?.result).toBe("needs-review");
  expect(result.gates.find(x=>x.id==="workflow-verification")?.result).toBe("not-met");
 });
 it("retains finding resolution as human review rather than automatic security certification",()=>{
  const result=assessClosureReadiness(finding({
   status:"RESOLVED",resolvedAt:d("2026-01-08"),
   evidence:[observed("OBSERVED","2026-01-07")],
   actions:[action("VERIFIED")],
  }));
  expect(result.gates.find(x=>x.id==="finding-closure")?.result).toBe("needs-review");
  expect(result.gates.find(x=>x.id==="workflow-verification")?.result).toBe("met");
 });
 it("summarizes missing gates without mutating source findings",()=>{
  const input=[finding(),finding({id:"low",severity:"LOW"})];
  const before=input.map(x=>x.id);
  const report=buildClosureReadinessPortfolio(input);
  expect(report.findings).toBe(2);
  expect(report.blocked).toBe(2);
  expect(input.map(x=>x.id)).toEqual(before);
 });
 it("escapes spreadsheet formulas in the closure matrix",()=>{
  const report=buildClosureReadinessPortfolio([finding({title:"=BAD()"})]);
  const csv=closureReadinessCsv(report.items);
  expect(csv).toContain("'=BAD()");
  expect(csv).toContain("Missing requirements");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
