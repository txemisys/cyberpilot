import { describe, expect, it } from "vitest";
import { buildRemediationActivityTimeline, buildRemediationMilestones, summarizeRemediationActivity } from "./remediation-activity";
const date=(day:string)=>new Date(day+"T10:00:00Z");
const event=(id:string,action:string,resourceId:string|null,day:string)=>({
 id,action,resourceId,occurredAt:date(day),actorType:"USER",metadata:{unsafe:"hidden"},
});
describe("SME remediation history and provenance",()=>{
 it("renders only known tenant action ids and does not expose metadata",()=>{
  const input=[
   event("a","remediation.approved","owned","2026-10-20"),
   event("b","remediation.guided_step_attested","foreign","2026-10-21"),
   event("c","remediation.guided_step_attested","owned","2026-10-22"),
  ];
  const result=buildRemediationActivityTimeline(input,new Set(["owned"]));
  expect(result.map(x=>x.id)).toEqual(["c","a"]);
  expect(result[0]?.description).toContain("not yet verified");
  expect(JSON.stringify(result)).not.toContain("hidden");
  expect(result.every(x=>x.remediationId==="owned")).toBe(true);
 });
 it("uses neutral descriptions for unknown audit events",()=>{
  const [row]=buildRemediationActivityTimeline([event("unknown","remediation.new_action","owned","2026-10-20")],new Set(["owned"]));
  expect(row?.title).toBe("Action activity recorded");
  expect(row?.description).not.toContain("verified");
 });
 it("counts independent event categories but never claims verification from acknowledged steps",()=>{
  const events=[
   event("a","remediation.approved","owned","2026-10-18"),
   event("b","remediation.guided_step_attested","owned","2026-10-19"),
   event("c","remediation.execution_started","owned","2026-10-20"),
   event("d","remediation.verified","owned","2026-10-21"),
  ];
  const rows=buildRemediationActivityTimeline(events,new Set(["owned"]));
  expect(summarizeRemediationActivity(rows)).toEqual({
   total:4,approvals:1,guidedSteps:1,executions:1,verifications:1,other:0,mostRecentAt:date("2026-10-21"),
  });
 });
 it("distinguishes recorded stages from verified security",()=>{
  const stages=buildRemediationMilestones({
   status:"SUCCEEDED",createdAt:date("2026-10-20"),approvedAt:date("2026-10-21"),
   startedAt:date("2026-10-22"),completedAt:date("2026-10-23"),verifiedAt:null,
  });
  expect(stages).toHaveLength(5);
  expect(stages[3]?.label).toBe("Work recorded");
  expect(stages[4]?.verified).toBe(false);
  expect(stages[4]?.occurredAt).toBeNull();
 });
 it("requires verified status as well as a verification timestamp",()=>{
  const stages=buildRemediationMilestones({
   status:"VERIFIED",createdAt:date("2026-10-20"),approvedAt:null,
   startedAt:null,completedAt:null,verifiedAt:date("2026-10-24"),
  });
  expect(stages[4]?.verified).toBe(true);
  expect(stages[4]?.occurredAt).toEqual(date("2026-10-24"));
 });
 it("keeps historical evidence inputs immutable",()=>{
  const input=[event("a","remediation.approved","owned","2026-10-20")];
  const original=JSON.stringify(input);
  buildRemediationActivityTimeline(input,new Set(["owned"]));
  expect(JSON.stringify(input)).toBe(original);
 });
});
