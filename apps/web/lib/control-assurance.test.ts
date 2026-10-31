import {describe,expect,it} from "vitest";
import {assessControlAssurance,buildControlAssurancePortfolio,exportControlAssuranceCsv} from "./control-assurance";
import {buildControlChronology,filterControlChronology} from "./control-chronology";
import {buildEvidenceSourceCoverage} from "./evidence-source-coverage";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
const d=(x:string)=>new Date(x+"T12:00:00Z");
const finding=(evidence:ReviewEvidence[]=[],actions:ReviewAction[]=[]):ReviewFinding=>({
 id:"f1",title:"Admin MFA",description:"Identity control",severity:"CRITICAL",status:"OPEN",
 firstSeenAt:d("2026-01-01"),lastSeenAt:d("2026-01-03"),resolvedAt:null,
 evidence,actions,
});
const evidence=(source:ReviewEvidence["source"],when:string):ReviewEvidence=>({
 id:source,source,category:"IDENTITY",summary:source,
 capturedAt:d(when),lastObservedAt:source==="OBSERVED"?d(when):null,
});
const action=(status:string,completedAt:Date|null):ReviewAction=>({
 id:"a1",title:"Enable MFA",status,mode:"GUIDED",createdAt:d("2026-01-01"),
 approvedAt:d("2026-01-02"),startedAt:d("2026-01-03"),
 completedAt,verifiedAt:null,steps:["Configure MFA"],
 verification:["Observe enforced MFA"],acknowledgedSteps:new Set([0]),
});
describe("Control assurance from actual records",()=>{
 it("identifies declaration-only provenance without claiming successful security",()=>{
  const result=assessControlAssurance(finding([evidence("DECLARED","2026-01-02")]));
  expect(result.level).toBe("declaration-only");
  expect(result.verifiedWorkflows).toBe(0);
 });
 it("requires fresh observations when recorded work follows available evidence",()=>{
  const result=assessControlAssurance(finding(
   [evidence("OBSERVED","2026-01-02")],[action("SUCCEEDED",d("2026-01-05"))]));
  expect(result.decision).toBe("request-observation");
  expect(result.observedAfterWork).toBe(false);
  expect(result.limitations.join(" ")).toContain("predates");
 });
 it("does not claim an observed result is proof of remediation",()=>{
  const result=assessControlAssurance(finding(
   [evidence("OBSERVED","2026-01-06")],[action("SUCCEEDED",d("2026-01-05"))]));
  expect(result.level).toBe("observed-after-work");
  expect(result.verifiedWorkflows).toBe(0);
  expect(result.decision).toBe("inspect-change");
 });
 it("keeps verified workflow state separate from an open finding",()=>{
  const result=assessControlAssurance(finding([],[
   {...action("VERIFIED",d("2026-01-05")),verifiedAt:d("2026-01-06")},
  ]));
  expect(result.level).toBe("verified-record");
  expect(result.findingStatus).toBe("OPEN");
  expect(result.limitations.join(" ")).toContain("remains open");
 });
 it("does not mutate input while ranking and exporting",()=>{
  const items=[finding(),{...finding(),id:"f2",severity:"LOW"}];
  const before=items.map(x=>x.id);
  const portfolio=buildControlAssurancePortfolio(items);
  expect(portfolio.summary.assessed).toBe(2);
  expect(items.map(x=>x.id)).toEqual(before);
  const csv=exportControlAssuranceCsv(portfolio.controls);
  expect(csv).toContain("Finding status");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
describe("Evidence and remediation chronology",()=>{
 it("orders all recorded dated events descending and separates provenance",()=>{
  const sample=finding([evidence("OBSERVED","2026-01-06")],[
   action("SUCCEEDED",d("2026-01-05")),
  ]);
  const history=buildControlChronology(sample);
  expect(history.observationAfterWork).toBe(true);
  expect(history.events[0]?.at).toEqual(d("2026-01-06"));
  expect(filterControlChronology(history,"workflow").every(x=>x.provenance==="workflow")).toBe(true);
  expect(filterControlChronology(history,"evidence").every(x=>x.evidenceId!==null)).toBe(true);
 });
 it("reports missing post-remediation evidence without inventing observation",()=>{
  const history=buildControlChronology(finding([],[
   action("SUCCEEDED",d("2026-01-05")),
  ]));
  expect(history.workAfterObservation).toBe(true);
  expect(history.lastObservationAt).toBeNull();
  expect(history.warnings.join(" ")).toContain("no dated observed");
 });
});
describe("Source coverage report",()=>{
 it("groups records by provenance and month without treating declarations as observation",()=>{
  const report=buildEvidenceSourceCoverage([finding([
   evidence("OBSERVED","2026-01-06"),evidence("DECLARED","2026-01-07"),
  ]),{...finding(),id:"f2"}]);
  expect(report.findings).toBe(2);
  expect(report.matchedFindings).toBe(1);
  expect(report.unmatchedFindings).toBe(1);
  expect(report.sourceSummaries.find(x=>x.source==="OBSERVED")?.records).toBe(1);
  expect(report.recordingMonths[0]?.month).toBe("2026-01");
 });
});
