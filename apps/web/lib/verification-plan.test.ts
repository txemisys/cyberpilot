import {describe,expect,it} from "vitest";
import {buildVerificationPlan,createFindingVerificationTasks,renderVerificationPlanText} from "./verification-plan";
import type {ReviewFinding,ReviewAction} from "./finding-evidence-review";
const date=(day:string)=>new Date(day+"T12:00:00Z");
const action=(status:string):ReviewAction=>({
 id:"remediation-1",title:"Protect administrators",status,mode:"GUIDED",
 createdAt:date("2026-01-01"),approvedAt:null,startedAt:null,
 completedAt:null,verifiedAt:null,steps:["Enable MFA","Test login"],
 verification:["Review fresh identity evidence"],acknowledgedSteps:new Set(),
});
const finding=(actions:ReviewAction[]=[]):ReviewFinding=>({
 id:"finding-1",title:"Admin MFA absent",description:"Identity control",
 severity:"CRITICAL",status:"OPEN",
 firstSeenAt:date("2026-01-01"),lastSeenAt:date("2026-01-02"),
 resolvedAt:null,evidence:[],actions,
});
describe("Verification plan derivation",()=>{
 it("creates an investigation task for findings without remediation",()=>{
  const [task]=createFindingVerificationTasks(finding());
  expect(task).toMatchObject({
   status:"needs-investigation",actionId:null,severity:"CRITICAL",
   actionable:true,
  });
  expect(task?.successCriteria).toHaveLength(4);
 });
 it("requires approval for proposed work",()=>{
  const [task]=createFindingVerificationTasks(finding([action("PROPOSED")]));
  expect(task?.status).toBe("pending-approval");
  expect(task?.prerequisites.join(" ")).toContain("approval");
 });
 it("continues the first outstanding guided step",()=>{
  const item={...action("APPROVED"),acknowledgedSteps:new Set([0])};
  const [task]=createFindingVerificationTasks(finding([item]));
  expect(task?.status).toBe("perform-work");
  expect(task?.suggestedNextStep).toContain("Test login");
 });
 it("never treats completed steps as verified security",()=>{
  const item={...action("APPROVED"),acknowledgedSteps:new Set([0,1])};
  const [task]=createFindingVerificationTasks(finding([item]));
  expect(task?.status).toBe("collect-evidence");
  expect(task?.warnings.join(" ")).toContain("do not verify");
  expect(task?.verifiedAt).toBeNull();
 });
 it("flags a completed execution for fresh evidence",()=>{
  const item={...action("SUCCEEDED"),completedAt:date("2026-01-04")};
  const [task]=createFindingVerificationTasks(finding([item]));
  expect(task?.status).toBe("collect-evidence");
 });
 it("recognizes verified timestamp only with verified workflow status",()=>{
  const item={...action("VERIFIED"),verifiedAt:date("2026-01-05")};
  const [task]=createFindingVerificationTasks(finding([item]));
  expect(task?.status).toBe("complete");
  expect(task?.actionable).toBe(false);
  expect(task?.verifiedAt).toEqual(date("2026-01-05"));
  const [withoutTimestamp]=createFindingVerificationTasks(
   finding([{...item,verifiedAt:null}]));
  expect(withoutTimestamp?.status).not.toBe("complete");
 });
 it("reviews resolution separately from workflow verification",()=>{
  const item={...finding([action("APPROVED")]),status:"RESOLVED"};
  expect(createFindingVerificationTasks(item)[0]?.status).toBe("review-closure");
 });
 it("flags an observation that predates recorded work",()=>{
  const item={...action("APPROVED"),completedAt:date("2026-01-05")};
  const sample=finding([item]);
  sample.evidence=[{
   id:"signal",source:"OBSERVED",category:"IDENTITY",
   capturedAt:date("2026-01-02"),lastObservedAt:date("2026-01-02"),
   summary:"MFA",
  }];
  const [task]=createFindingVerificationTasks(sample);
  expect(task?.status).toBe("collect-evidence");
  expect(task?.warnings.join(" ")).toContain("predates");
 });
 it("prioritizes work by readiness then severity and finding identity",()=>{
  const plans=buildVerificationPlan([
   {...finding([action("PROPOSED")]),id:"proposal"},
   {...finding([action("SUCCEEDED")]),id:"verify",severity:"LOW"},
  ]);
  expect(plans.items[0]?.findingId).toBe("verify");
  expect(plans.pendingApproval).toBe(1);
  expect(plans.collectEvidence).toBe(1);
  expect(plans.highestPriority?.findingId).toBe("verify");
 });
 it("does not modify source findings or acknowledged progress",()=>{
  const source=finding([action("APPROVED")]);
  const before=source.actions[0]?.acknowledgedSteps.size;
  buildVerificationPlan([source]);
  expect(source.actions[0]?.acknowledgedSteps.size).toBe(before);
 });
 it("serializes all tasks and checklist criteria for offline handoff",()=>{
  const plan=buildVerificationPlan([finding([action("SUCCEEDED")])]);
  const output=renderVerificationPlanText(plan);
  expect(output).toContain("EVIDENCE VERIFICATION PLAN");
  expect(output).toContain("Review fresh identity evidence");
  expect(output).toContain("not step acknowledgements");
 });
});
