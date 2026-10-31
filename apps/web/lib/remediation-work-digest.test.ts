import {describe,expect,it} from "vitest";
import {parseDigestConfig,evaluateDigestWork,buildDigest,type DigestWork} from "./remediation-work-digest";
const NOW=new Date("2026-11-01T12:00:00Z");
const day=(n:number)=>new Date(NOW.getTime()+n*86400000);
function work(patch:Partial<DigestWork>={}):DigestWork{
 return {id:"work_alpha",title:"Review access",status:"IN_PROGRESS",priority:"NORMAL",
  assigneeUserId:"user_alpha",assigneeName:"Alice",dueAt:day(20),
  createdAt:day(-40),updatedAt:day(-1),findingTitle:"Access control",
  findingSeverity:"MEDIUM",checklist:[{completedAt:day(-2)}],
  evidenceLinks:[{unlinkedAt:null}],handoffs:[],...patch};
}
const config=(raw:Record<string,unknown>={})=>parseDigestConfig(raw);
const decide=(patch:Partial<DigestWork>={},raw:Record<string,unknown>={})=>
 evaluateDigestWork(work(patch),NOW,config(raw).days);
describe("digest parameter validation",()=>{
 it("defaults to 14 days of personal work",()=>{
  expect(config()).toEqual({scope:"MINE",days:14,includeClosed:false,maxItems:30});
 });
 it.each([null,undefined,42,[],false,"query"])("rejects invalid body %s",v=>{
  expect(()=>parseDigestConfig(v)).toThrow();
 });
 it("rejects arbitrary fields",()=>expect(()=>config({organizationId:"foreign"})).toThrow());
 it.each(["MINE","TEAM","UNASSIGNED"])("accepts scope %s",scope=>
  expect(config({scope}).scope).toBe(scope));
 it.each(["INVALID",null,0,{}])("rejects invalid scope %s",scope=>
  expect(()=>config({scope})).toThrow());
 it.each([7,14,30,60,90])("accepts duration %s",days=>
  expect(config({days}).days).toBe(days));
 it.each([0,-1,8,100,"14",null])("rejects invalid duration %s",days=>
  expect(()=>config({days})).toThrow());
 it.each([1,10,20,30,50,100])("accepts preview limit %s",maxItems=>
  expect(config({maxItems}).maxItems).toBe(maxItems));
 it.each([0,-1,101,1.5,NaN,"20",null])("rejects preview limit %s",maxItems=>
  expect(()=>config({maxItems})).toThrow());
 it("accepts explicit inclusion of completed work",()=>
  expect(config({includeClosed:true}).includeClosed).toBe(true));
 it.each([null,0,"false",{},[]])("rejects nonboolean closed flag %s",includeClosed=>
  expect(()=>config({includeClosed})).toThrow());
});
describe("digest signals from actual work records",()=>{
 it("recognizes missed target dates",()=>{
  expect(decide({dueAt:day(-3)}).reasons).toContain("OVERDUE");
 });
 it("counts whole overdue days",()=>{
  expect(decide({dueAt:day(-3)}).daysOverdue).toBe(3);
 });
 it("does not invent overdue dates for undated work",()=>{
  expect(decide({dueAt:null}).daysOverdue).toBeNull();
 });
 it("recognizes upcoming work due inside the horizon",()=>{
  expect(decide({dueAt:day(14)}).reasons).toContain("DUE_WITHIN_WINDOW");
 });
 it("does not flag work due beyond the horizon",()=>{
  expect(decide({dueAt:day(15)}).reasons).not.toContain("DUE_WITHIN_WINDOW");
 });
 it("respects 7-day horizon",()=>{
  expect(decide({dueAt:day(8)},{days:7}).reasons).not.toContain("DUE_WITHIN_WINDOW");
 });
 it("identifies blocked work",()=>{
  expect(decide({status:"BLOCKED"}).reasons).toContain("BLOCKED");
 });
 it("identifies urgent priority",()=>{
  expect(decide({priority:"URGENT"}).reasons).toContain("URGENT");
 });
 it("identifies unassigned work",()=>{
  expect(decide({assigneeUserId:null,assigneeName:null}).reasons).toContain("UNASSIGNED");
 });
 it("detects stale work after 14 days",()=>{
  expect(decide({updatedAt:day(-14)}).reasons).toContain("STALE");
 });
 it("does not label work stale after only 13 days",()=>{
  expect(decide({updatedAt:day(-13)}).reasons).not.toContain("STALE");
 });
 it("does not create negative inactivity with future timestamps",()=>{
  expect(decide({updatedAt:day(2)}).daysIdle).toBe(0);
 });
 it("distinguishes linked evidence from unlinked evidence",()=>{
  expect(decide({evidenceLinks:[{unlinkedAt:day(-1)}]}).activeEvidence).toBe(0);
 });
 it("flags missing active evidence references",()=>{
  expect(decide({evidenceLinks:[]}).reasons).toContain("MISSING_EVIDENCE_LINK");
 });
 it("does not treat an evidence link as verification",()=>{
  expect(decide().reasons).not.toContain("MISSING_EVIDENCE_LINK");
 });
 it("flags missing checklist",()=>{
  expect(decide({checklist:[]}).reasons).toContain("CHECKLIST_GAP");
 });
 it("flags incomplete checklist",()=>{
  expect(decide({checklist:[{completedAt:null}]}).reasons).toContain("CHECKLIST_GAP");
 });
 it("counts checklist completion",()=>{
  expect(decide()).toMatchObject({checklistDone:1,checklistTotal:1});
 });
 it("identifies pending handoffs",()=>{
  expect(decide({handoffs:[{status:"REQUESTED",expiresAt:null}]}).pendingHandoffs).toBe(1);
 });
 it("ignores accepted handoffs",()=>{
  expect(decide({handoffs:[{status:"ACCEPTED",expiresAt:null}]}).pendingHandoffs).toBe(0);
 });
 it("ignores cancelled handoffs",()=>{
  expect(decide({handoffs:[{status:"CANCELLED",expiresAt:null}]}).pendingHandoffs).toBe(0);
 });
 it("does not escalate completed work",()=>{
  expect(decide({status:"DONE",dueAt:day(-20),priority:"URGENT"}).reasons).toEqual([]);
 });
 it("does not escalate cancelled work",()=>{
  expect(decide({status:"CANCELLED"}).weight).toBe(0);
 });
 it("preserves actual task ownership display",()=>{
  expect(decide().owner).toBe("Alice");
 });
 it("uses unassigned when no name exists",()=>{
  expect(decide({assigneeName:null}).owner).toBe("Unassigned");
 });
 it("combines overlapping independent signals",()=>{
  const result=decide({status:"BLOCKED",priority:"URGENT",dueAt:day(-5),
   assigneeUserId:null,updatedAt:day(-30),checklist:[],evidenceLinks:[],
   handoffs:[{status:"REQUESTED",expiresAt:null}]});
  expect(result.reasons).toContain("OVERDUE");
  expect(result.reasons).toContain("BLOCKED");
  expect(result.reasons).toContain("PENDING_HANDOFF");
  expect(result.weight).toBeGreaterThan(100);
 });
 it("does not mutate source records",()=>{
  const source=work();const before=JSON.stringify(source);
  evaluateDigestWork(source,NOW,14);
  expect(JSON.stringify(source)).toBe(before);
 });
});
describe("digest aggregation and truthful previews",()=>{
 const records=[
  work({id:"work_one",status:"BLOCKED",dueAt:day(-4)}),
  work({id:"work_two",priority:"URGENT",assigneeUserId:null,evidenceLinks:[]}),
  work({id:"work_three",status:"DONE"}),
  work({id:"work_four",checklist:[],updatedAt:day(-40)}),
 ];
 it("preserves full count despite preview limit",()=>{
  const result=buildDigest(records,config({maxItems:1}),NOW);
  expect(result.summary.total).toBe(4);
  expect(result.priorities).toHaveLength(1);
  expect(result.coverage.excludedFromPreview).toBe(3);
 });
 it("counts closed work separately",()=>{
  const result=buildDigest(records,config(),NOW);
  expect(result.summary).toMatchObject({open:3,closed:1,total:4});
 });
 it("counts overlapping reasons independently",()=>{
  const result=buildDigest(records,config(),NOW);
  expect(result.summary.blocked).toBe(1);
  expect(result.summary.urgent).toBe(1);
  expect(result.summary.unassigned).toBe(1);
 });
 it("does not count closed task as overdue",()=>{
  expect(buildDigest(records,config(),NOW).summary.overdue).toBe(1);
 });
 it("does not count closed task as urgent",()=>{
  expect(buildDigest(records,config(),NOW).summary.urgent).toBe(1);
 });
 it("prioritizes complex blocked overdue work",()=>{
  expect(buildDigest(records,config(),NOW).priorities[0]?.id).toBe("work_one");
 });
 it("reports every matching item in the summary",()=>{
  expect(buildDigest(records,config(),NOW).summary.total).toBe(records.length);
 });
 it("maintains total conservation",()=>{
  const sum=buildDigest(records,config(),NOW).summary;
  expect(sum.open+sum.closed).toBe(sum.total);
 });
 it("describes actionable categories not imaginary execution",()=>{
  const result=buildDigest(records,config(),NOW);
  expect(result.followUps.find(x=>x.kind==="BLOCKED")?.recommendation).toMatch(/Resolve/);
 });
 it("does not invent a notification schedule",()=>{
  expect(buildDigest(records,config(),NOW).disclaimer).toMatch(/not a scheduled notification/);
 });
 it("reports snapshot time explicitly",()=>{
  expect(buildDigest(records,config(),NOW).generatedAt).toBe(NOW.toISOString());
 });
 it("returns an empty fully defined report",()=>{
  const result=buildDigest([],config(),NOW);
  expect(result.summary.total).toBe(0);
  expect(result.priorities).toHaveLength(0);
 });
 it("sorts tied items deterministically by ID",()=>{
  const result=buildDigest([
   work({id:"work_z"}),work({id:"work_a"}),
  ],config(),NOW);
  expect(result.priorities.map(x=>x.id)).toEqual(["work_a","work_z"]);
 });
});
