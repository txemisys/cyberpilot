import {describe,expect,it} from "vitest";
import {buildEvidenceGapReport,classifyFindingEvidenceGap,exportEvidenceGaps} from "./evidence-gap-report";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
const date=(day:string)=>new Date(day+"T12:00:00Z");
const work=(completedAt:Date|null=null):ReviewAction=>({
 id:"a",title:"Fix admin policy",status:"APPROVED",mode:"GUIDED",
 createdAt:date("2026-01-01"),approvedAt:date("2026-01-01"),
 startedAt:null,completedAt,verifiedAt:null,
 steps:["Fix policy"],verification:["Observe control"],
 acknowledgedSteps:new Set(),
});
const signal=(state:ReviewEvidence["source"],day="2026-01-02"):ReviewEvidence=>({
 id:state,source:state,category:"IDENTITY",summary:"Review",
 capturedAt:date(day),lastObservedAt:date(day),
});
const finding=(evidence:ReviewEvidence[]=[],actions:ReviewAction[]=[]):ReviewFinding=>({
 id:"finding",title:"Admin MFA",description:"Identity risk",severity:"HIGH",
 status:"OPEN",firstSeenAt:date("2026-01-01"),lastSeenAt:date("2026-01-03"),
 resolvedAt:null,evidence,actions,
});
describe("Evidence gap classification",()=>{
 it("reports missing matched evidence without inferring a failed security control",()=>{
  const result=classifyFindingEvidenceGap(finding());
  expect(result.kind).toBe("unmatched");
  expect(result.description).toContain("No evidence is linked");
 });
 it("recognizes declaration-only evidence",()=>{
  const result=classifyFindingEvidenceGap(finding([signal("DECLARED")]));
  expect(result.kind).toBe("declaration-only");
  expect(result.observedCount).toBe(0);
  expect(result.declaredCount).toBe(1);
 });
 it("separates error and unknown signals from observed ones",()=>{
  const result=classifyFindingEvidenceGap(finding([signal("ERROR"),signal("UNKNOWN")]));
  expect(result.kind).toBe("inconclusive");
  expect(result.erroredCount).toBe(2);
 });
 it("detects observations made before remediation was completed",()=>{
  const result=classifyFindingEvidenceGap(
   finding([signal("OBSERVED","2026-01-02")],[work(date("2026-01-05"))]));
  expect(result.kind).toBe("observation-old");
 });
 it("does not claim a fresh observation means verified security",()=>{
  const result=classifyFindingEvidenceGap(finding([signal("OBSERVED")]));
  expect(result.kind).toBe("observation-current");
  expect(result.nextStep).toContain("Review");
 });
 it("recognizes work needing verification even when observed evidence exists",()=>{
  const item={...work(),status:"SUCCEEDED"};
  const result=classifyFindingEvidenceGap(finding([signal("OBSERVED")],[item]));
  expect(result.kind).toBe("unresolved-after-work");
 });
 it("orders gaps by actionability and risk rather than incidental source order",()=>{
  const older={...finding([signal("OBSERVED")],[work(date("2026-01-05"))]),id:"old"};
  const missing={...finding(),id:"missing"};
  const report=buildEvidenceGapReport([missing,older]);
  expect(report.items.map(x=>x.findingId)).toEqual(["old","missing"]);
  expect(report.summary.requiresAttention).toBe(2);
  expect(report.summary.observationOld).toBe(1);
 });
 it("exports safe CSV with concrete evidence dates and no execution payloads",()=>{
  const report=buildEvidenceGapReport([
   {...finding(),title:'=HYPERLINK("malicious")'},
  ]);
  const csv=exportEvidenceGaps(report.items);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv).toContain("Finding last seen UTC");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
