import {describe,expect,it} from "vitest";
import {
 reviewEvidenceReference,prioritizeEvidenceReferences,
 summarizeReferenceReview,groupReviewsByAssignee,type ReferenceTriageRow
} from "./work-evidence-triage";
const now=new Date("2026-10-31T12:00:00Z");
const row=(id:string,overrides:Partial<ReferenceTriageRow>={}):ReferenceTriageRow=>({
 linkId:id,workItemId:"work00001",findingId:"find00001",
 workStatus:"IN_PROGRESS",assignedUserId:"user00001",reason:"Review MFA observation",
 linkedAt:new Date("2026-10-30"),unlinkedAt:null,
 finding:{ruleId:"MFA",key:"mfa",status:"OPEN"},
 evidence:{
  id:"evid00001",organizationId:"tenant0001",controlId:"MFA",
  domain:"identity",scope:"tenant",state:"OBSERVED",source:"lab",
  observedAt:new Date("2026-10-30"),createdAt:now,updatedAt:now
 },...overrides
});
describe("evidence reference triage",()=>{
 it("never claims a linked observation verifies security",()=>{
  const result=reviewEvidenceReference(row("link00001"),now);
  expect(result.canBeUsedAsEvidence).toBe(false);
  expect(result.severity).toBe("INFORMATION");
 });
 it("identifies completed human work against open findings",()=>{
  const result=reviewEvidenceReference(row("link00001",{workStatus:"DONE"}),now);
  expect(result.severity).toBe("URGENT");
  expect(result.issues).toContain("WORK_DONE_UNVERIFIED");
 });
 it("reports mismatched controls and source errors",()=>{
  const e=row("link00001").evidence;
  const result=reviewEvidenceReference(row("link00001",{
   evidence:{...e,controlId:"OTHER",state:"ERROR"}
  }),now);
  expect(result.issues).toContain("CONTROL_MISMATCH");
  expect(result.issues).toContain("EVIDENCE_ERROR");
 });
 it("retains detached references as historical rather than active",()=>{
  const result=reviewEvidenceReference(row("link00001",{unlinkedAt:now}),now);
  expect(result.isActive).toBe(false);
  expect(result.issues).toContain("REFERENCE_DETACHED");
 });
 it("sorts urgent reviews before informational links",()=>{
  const sorted=prioritizeEvidenceReferences([
   row("link00001"),row("link00002",{workStatus:"DONE"})
  ],now);
  expect(sorted.map(x=>x.linkId)).toEqual(["link00002","link00001"]);
 });
 it("counts risk types without asserting verification",()=>{
  const results=prioritizeEvidenceReferences([
   row("link00001"),row("link00002",{workStatus:"DONE"})
  ],now);
  expect(summarizeReferenceReview(results)).toMatchObject({
   total:2,urgent:1,information:1,workDoneButFindingOpen:1
  });
 });
 it("groups review loads by assignee with distinct work items",()=>{
  const results=prioritizeEvidenceReferences([
   row("link00001"),row("link00002",{workStatus:"DONE"}),
   row("link00003",{assignedUserId:null,workItemId:"work00002",workStatus:"DONE"})
  ],now);
  expect(groupReviewsByAssignee(results)).toEqual([
   {assigneeUserId:"UNASSIGNED",workItems:1,references:1,urgent:1,review:0},
   {assigneeUserId:"user00001",workItems:1,references:2,urgent:1,review:0}
  ]);
 });
});
