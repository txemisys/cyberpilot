import {describe,expect,it} from "vitest";
import {
 inspectDigestQuality,summarizeDigestQuality,buildDigestQualityReview,
} from "./remediation-work-digest-quality";
import {buildDigest,parseDigestConfig,type DigestWork} from "./remediation-work-digest";
const NOW=new Date("2026-11-01T12:00:00Z");
const date=(days:number)=>new Date(NOW.getTime()+days*86400000);
function task(patch:Partial<DigestWork>={}):DigestWork{
 return {
  id:"work_alpha",title:"Review access",status:"IN_PROGRESS",priority:"NORMAL",
  assigneeUserId:"user_alpha",assigneeName:"Alice",dueAt:date(10),
  createdAt:date(-10),updatedAt:date(-1),findingTitle:"Finding",
  findingSeverity:"MEDIUM",checklist:[{completedAt:date(-2)}],
  evidenceLinks:[{unlinkedAt:null}],handoffs:[],...patch,
 };
}
function report(work:DigestWork[],limit=30){
 return buildDigest(work,parseDigestConfig({maxItems:limit}),NOW);
}
describe("digest hygiene diagnostics",()=>{
 it("recognizes a well-documented active task",()=>{
  const result=inspectDigestQuality(report([task()]).priorities[0]!);
  expect(result.issues).toEqual([]);
 });
 it("flags missing owners independently of other issues",()=>{
  const result=inspectDigestQuality(report([task({
   assigneeUserId:null,assigneeName:null,
  })]).priorities[0]!);
  expect(result.issues).toContain("MISSING_OWNER");
  expect(result.severity).toBe("HIGH");
 });
 it("flags missing target dates",()=>{
  const result=inspectDigestQuality(report([task({dueAt:null})]).priorities[0]!);
  expect(result.issues).toContain("MISSING_TARGET");
 });
 it("flags stale updates",()=>{
  const result=inspectDigestQuality(report([task({
   updatedAt:date(-40),
  })]).priorities[0]!);
  expect(result.issues).toContain("STALE_UPDATE");
 });
 it("flags absent checklists",()=>{
  const result=inspectDigestQuality(report([task({checklist:[]})]).priorities[0]!);
  expect(result.issues).toContain("NO_CHECKLIST");
 });
 it("flags absent evidence links",()=>{
  const result=inspectDigestQuality(report([task({
   evidenceLinks:[],
  })]).priorities[0]!);
  expect(result.issues).toContain("NO_EVIDENCE_REFERENCE");
 });
 it("flags pending handoff decisions",()=>{
  const result=inspectDigestQuality(report([task({
   handoffs:[{status:"REQUESTED",expiresAt:date(3)}],
  })]).priorities[0]!);
  expect(result.issues).toContain("OPEN_HANDOFF");
  expect(result.severity).toBe("HIGH");
 });
 it("counts independent work hygiene issues",()=>{
  const result=summarizeDigestQuality(report([
   task({id:"work_good"}),task({id:"work_noowner",assigneeUserId:null,assigneeName:null}),
  ]).priorities);
  expect(result).toMatchObject({inspected:2,withIssues:1,clean:1});
 });
 it("does not confuse preview completeness with inventory coverage",()=>{
  const result=buildDigestQualityReview(report([
   task({id:"work_a"}),task({id:"work_b"}),
  ],1));
  expect(result.coverage.completeForEntireInventory).toBe(false);
  expect(result.coverage.omitted).toBe(1);
 });
 it("reports complete previews only when no records omitted",()=>{
  expect(buildDigestQualityReview(report([task()])).coverage.completeForEntireInventory)
   .toBe(true);
 });
 it("does not identify operational hygiene as security certification",()=>{
  expect(buildDigestQualityReview(report([task()])).disclaimer)
   .toMatch(/not independent evidence assessment/);
 });
});
