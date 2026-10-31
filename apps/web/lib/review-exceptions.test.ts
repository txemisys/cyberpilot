import {describe,expect,it} from "vitest";
import {
 collectFindingReviewExceptions,buildReviewExceptionRegister,exportExceptionRegister,
} from "./review-exceptions";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
const d=(day:string)=>new Date(day+"T12:00:00Z");
const action=(status:string):ReviewAction=>({
 id:"action-1",title:"Require MFA",status,mode:"GUIDED",
 createdAt:d("2026-01-01"),approvedAt:d("2026-01-02"),
 startedAt:d("2026-01-03"),completedAt:status==="SUCCEEDED"?d("2026-01-05"):null,
 verifiedAt:status==="VERIFIED"?d("2026-01-06"):null,
 steps:["Configure MFA"],verification:["Read new identity evidence"],
 acknowledgedSteps:new Set(),
});
const finding=(options:Partial<ReviewFinding>={}):ReviewFinding=>({
 id:"finding-1",title:"Admin MFA missing",description:"Privileged sign-in risk",
 severity:"HIGH",status:"OPEN",firstSeenAt:d("2026-01-01"),
 lastSeenAt:d("2026-01-03"),resolvedAt:null,evidence:[],actions:[],...options,
});
const evidence=(source:ReviewEvidence["source"]):ReviewEvidence=>({
 id:source,source,category:"IDENTITY",summary:"MFA",
 capturedAt:d("2026-01-02"),lastObservedAt:source==="OBSERVED"?d("2026-01-02"):null,
});
describe("Security review exception register",()=>{
 it("flags verified action with an open finding without auto resolving it",()=>{
  const exceptions=collectFindingReviewExceptions(
   finding({actions:[action("VERIFIED")]}));
  expect(exceptions.some(x=>x.kind==="open-after-verification")).toBe(true);
 });
 it("flags resolved findings with no linked verified remediation",()=>{
  const exceptions=collectFindingReviewExceptions(
   finding({status:"RESOLVED",resolvedAt:d("2026-01-09")}));
  expect(exceptions.some(x=>x.kind==="resolved-without-verification")).toBe(true);
 });
 it("identifies evidence older than recorded remediation work",()=>{
  const exceptions=collectFindingReviewExceptions(finding({
   evidence:[evidence("OBSERVED")],actions:[action("SUCCEEDED")],
  }));
  expect(exceptions.some(x=>x.kind==="work-newer-than-observation")).toBe(true);
  expect(exceptions.some(x=>x.kind==="completed-without-evidence")).toBe(true);
 });
 it("does not imply declarations are observed security outcomes",()=>{
  const exceptions=collectFindingReviewExceptions(
   finding({evidence:[evidence("DECLARED")]}));
  expect(exceptions.some(x=>x.kind==="declared-only")).toBe(true);
 });
 it("distinguishes proposed work and approved work without progress",()=>{
  const proposal=collectFindingReviewExceptions(
   finding({actions:[action("PROPOSED")]}));
  expect(proposal.some(x=>x.kind==="incomplete-approval")).toBe(true);
  const approved=collectFindingReviewExceptions(
   finding({actions:[action("APPROVED")]}));
  expect(approved.some(x=>x.kind==="workflow-without-progress")).toBe(true);
 });
 it("counts distinct affected findings and evidence review flags",()=>{
  const register=buildReviewExceptionRegister([
   finding({id:"one",actions:[action("PROPOSED")]}),
   finding({id:"two",evidence:[evidence("ERROR")]}),
  ]);
  expect(register.affectedFindings).toBe(2);
  expect(register.count).toBeGreaterThanOrEqual(2);
  expect(register.reviewEvidence).toBeGreaterThanOrEqual(1);
 });
 it("sorts by priority while retaining source data",()=>{
  const input=[
   finding({id:"low",severity:"LOW"}),
   finding({id:"critical",severity:"CRITICAL"}),
  ];
  const before=input.map(x=>x.id);
  const register=buildReviewExceptionRegister(input);
  expect(register.items[0]?.findingId).toBe("critical");
  expect(input.map(x=>x.id)).toEqual(before);
 });
 it("escapes spreadsheet formulas and includes reasoning in export",()=>{
  const register=buildReviewExceptionRegister([
   finding({title:'=HYPERLINK("unsafe")'}),
  ]);
  const csv=exportExceptionRegister(register.items);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv).toContain("Recommendation");
  expect(csv).toContain("Context");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
