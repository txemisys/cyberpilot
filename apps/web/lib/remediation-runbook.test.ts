import {describe,expect,it} from "vitest";
import {assessRunbookReadiness,normalizeRunbookSteps,runbookPlainText,type ActionRunbook} from "./remediation-runbook";
const sample:ActionRunbook={
 id:"action-1",title:"Require MFA",summary:"Protect administrators",
 status:"APPROVED",mode:"GUIDED",severity:"HIGH",
 findingTitle:"Admin MFA absent",findingStatus:"OPEN",
 instructions:["Enable MFA","Test sign-in"],verification:["Fetch fresh identity evidence"],
 acknowledgedSteps:new Set([0]),
 createdAt:new Date("2026-01-01T00:00:00Z"),approvedAt:new Date("2026-01-02T00:00:00Z"),
 startedAt:null,completedAt:null,verifiedAt:null,
};
describe("SME remediation runbook",()=>{
 it("safely normalizes non-string and empty JSON instructions",()=>{
  expect(normalizeRunbookSteps(["a",null,1,"",{}, "b"])).toEqual(["a","b"]);
  expect(normalizeRunbookSteps({steps:["fake"]})).toEqual([]);
 });
 it("calculates actionable progress without implying verification",()=>{
  expect(assessRunbookReadiness(sample)).toMatchObject({
   completed:1,total:2,remaining:1,percentage:50,nextStep:1,
   verified:false,needsEvidence:false,stage:"approved",
  });
 });
 it("requires fresh evidence after all guided work is acknowledged",()=>{
  expect(assessRunbookReadiness({...sample,acknowledgedSteps:new Set([0,1])})).toMatchObject({
   completed:2,remaining:0,nextStep:null,needsEvidence:true,stage:"awaiting-evidence",
  });
 });
 it("does not equate a successful execution with verification",()=>{
  expect(assessRunbookReadiness({...sample,status:"SUCCEEDED",mode:"AUTOMATED"})).toMatchObject({
   verified:false,needsEvidence:true,stage:"awaiting-evidence",
  });
 });
 it("requires both verified workflow state and timestamp to claim verification",()=>{
  expect(assessRunbookReadiness({...sample,status:"VERIFIED"}).verified).toBe(false);
  expect(assessRunbookReadiness({
   ...sample,status:"VERIFIED",verifiedAt:new Date("2026-01-05T00:00:00Z"),
  }).verified).toBe(true);
 });
 it("produces an actionable printable text document without modifying source",()=>{
  const before=sample.acknowledgedSteps.size;
  const text=runbookPlainText(sample);
  expect(text).toContain("1. [x] Enable MFA");
  expect(text).toContain("2. [ ] Test sign-in");
  expect(text).toContain("1. [ ] Fetch fresh identity evidence");
  expect(text).toContain("does not establish");
  expect(sample.acknowledgedSteps.size).toBe(before);
 });
});
