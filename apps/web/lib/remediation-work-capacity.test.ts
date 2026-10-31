import {describe,expect,it} from "vitest";
import {
 parseCapacityConfig,scoreCapacityWork,summarizeMemberLoad,buildCapacityReport,
 type CapacityWork,type CapacityMember,
} from "./remediation-work-capacity";
const NOW=new Date("2026-11-01T12:00:00Z");
const day=(n:number)=>new Date(NOW.getTime()+n*86400000);
const alice:CapacityMember={userId:"user_alice",name:"Alice",role:"ADMIN"};
const bob:CapacityMember={userId:"user_bob",name:"Bob",role:"MEMBER"};
function work(patch:Partial<CapacityWork>={}):CapacityWork{
 return {id:"work_alpha",title:"Review access",status:"IN_PROGRESS",priority:"NORMAL",
  assigneeUserId:"user_alice",dueAt:day(20),updatedAt:day(-1),
  findingSeverity:"MEDIUM",checklist:[{completedAt:day(-1)}],handoffs:[],...patch};
}
const config=(raw:Record<string,unknown>={})=>parseCapacityConfig(raw);
const score=(patch:Partial<CapacityWork>={},horizon=14)=>
 scoreCapacityWork(work(patch),NOW,horizon);
const bad=(raw:unknown)=>expect(()=>parseCapacityConfig(raw)).toThrow();
describe("capacity input validation",()=>{
 it("uses cautious default limits",()=>expect(config()).toEqual({
  scope:"TEAM",sort:"ATTENTION",includeClosed:false,horizonDays:14,maxTasks:10,
 }));
 it.each([null,undefined,42,[],false,"bad"])("rejects invalid object %s",bad);
 it("rejects unknown properties",()=>bad({organizationId:"foreign"}));
 it.each(["TEAM","MINE"])("accepts scope %s",scope=>
  expect(config({scope}).scope).toBe(scope));
 it.each(["OTHER",null,1,{},false])("rejects scope %s",scope=>bad({scope}));
 it.each(["ATTENTION","OVERDUE","ACTIVE","MEMBER"])("accepts sorting %s",sort=>
  expect(config({sort}).sort).toBe(sort));
 it.each(["OTHER",null,1,false,{}])("rejects sort %s",sort=>bad({sort}));
 it.each([7,14,30,60])("accepts horizon %s",horizonDays=>
  expect(config({horizonDays}).horizonDays).toBe(horizonDays));
 it.each([0,-1,1,8,31,90,"14",null])("rejects horizon %s",horizonDays=>
  bad({horizonDays}));
 it.each([1,5,10,20,50])("accepts preview size %s",maxTasks=>
  expect(config({maxTasks}).maxTasks).toBe(maxTasks));
 it.each([0,-1,51,1.5,NaN,"10",null])("rejects preview size %s",maxTasks=>
  bad({maxTasks}));
 it("supports explicit includeClosed true",()=>
  expect(config({includeClosed:true}).includeClosed).toBe(true));
 it.each([null,1,0,"false",{}])("rejects invalid closed flag %s",includeClosed=>
  bad({includeClosed}));
});
describe("real work attention scoring",()=>{
 it("keeps ordinary open work without invented signals",()=>{
  expect(score().attentionPoints).toBe(0);
 });
 it("preserves recorded target dates",()=>{
  expect(score().dueAt).toBe(day(20).toISOString());
 });
 it("recognizes actual missed targets",()=>{
  expect(score({dueAt:day(-3)}).reasons).toContain("OVERDUE");
 });
 it("does not label a future date overdue",()=>{
  expect(score({dueAt:day(1)}).reasons).not.toContain("OVERDUE");
 });
 it("does not fabricate a target when missing",()=>{
  expect(score({dueAt:null}).daysUntilDue).toBeNull();
 });
 it("flags approaching target within the selected horizon",()=>{
  expect(score({dueAt:day(14)}).reasons).toContain("DUE_SOON");
 });
 it("excludes day 15 from 14 day horizon",()=>{
  expect(score({dueAt:day(15)}).reasons).not.toContain("DUE_SOON");
 });
 it("recognizes blocked work independently",()=>{
  expect(score({status:"BLOCKED"}).reasons).toContain("BLOCKED");
 });
 it("recognizes urgent priority",()=>{
  expect(score({priority:"URGENT"}).reasons).toContain("URGENT");
 });
 it("recognizes tasks without progress updates",()=>{
  expect(score({updatedAt:day(-30)}).reasons).toContain("STALE");
 });
 it("does not flag 13 days of inactivity",()=>{
  expect(score({updatedAt:day(-13)}).reasons).not.toContain("STALE");
 });
 it("recognizes unresolved handoffs",()=>{
  expect(score({handoffs:[{status:"REQUESTED"}]}).reasons).toContain("HANDOFF");
 });
 it("ignores accepted handoff requests",()=>{
  expect(score({handoffs:[{status:"ACCEPTED"}]}).reasons).not.toContain("HANDOFF");
 });
 it("recognizes missing checklist",()=>{
  expect(score({checklist:[]}).reasons).toContain("CHECKLIST_GAP");
 });
 it("recognizes incomplete checklist",()=>{
  expect(score({checklist:[{completedAt:null}]}).reasons).toContain("CHECKLIST_GAP");
 });
 it("does not mark completed work urgent",()=>{
  expect(score({status:"DONE",priority:"URGENT"}).reasons).toEqual([]);
 });
 it("does not mark cancelled work overdue",()=>{
  expect(score({status:"CANCELLED",dueAt:day(-100)}).attentionPoints).toBe(0);
 });
 it("adds critical severity attention only for active work",()=>{
  expect(score({findingSeverity:"CRITICAL"}).attentionPoints).toBe(15);
  expect(score({findingSeverity:"CRITICAL",status:"DONE"}).attentionPoints).toBe(0);
 });
 it("never changes source data",()=>{
  const item=work();const original=JSON.stringify(item);
  scoreCapacityWork(item,NOW,14);
  expect(JSON.stringify(item)).toBe(original);
 });
});
describe("member workloads and organization conservation",()=>{
 const items=[
  work({id:"work_one",dueAt:day(-5)}),
  work({id:"work_two",priority:"URGENT"}),
  work({id:"work_three",assigneeUserId:"user_bob",status:"BLOCKED"}),
  work({id:"work_four",assigneeUserId:null}),
  work({id:"work_five",assigneeUserId:"former_user",status:"DONE"}),
 ];
 it("counts active work for each current member",()=>{
  const result=buildCapacityReport(items,[alice,bob],config(),NOW);
  expect(result.members.find(item=>item.id==="user_alice")?.active).toBe(2);
  expect(result.members.find(item=>item.id==="user_bob")?.active).toBe(1);
 });
 it("tracks tasks with no owner in a separate bucket",()=>{
  const result=buildCapacityReport(items,[alice,bob],config(),NOW);
  expect(result.unassigned.assigned).toBe(2);
 });
 it("does not silently drop tasks assigned to former members",()=>{
  const result=buildCapacityReport(items,[alice,bob],config(),NOW);
  expect(result.summary.tasks).toBe(5);
  expect(result.summary.unassigned).toBe(2);
 });
 it("conserves active and closed tasks",()=>{
  const sum=buildCapacityReport(items,[alice,bob],config(),NOW).summary;
  expect(sum.active+sum.closed).toBe(sum.tasks);
 });
 it("conserves assigned and unassigned buckets",()=>{
  const sum=buildCapacityReport(items,[alice,bob],config(),NOW).summary;
  expect(sum.assigned+sum.unassigned).toBe(sum.tasks);
 });
 it("does not misclassify closed work as overdue",()=>{
  const sum=buildCapacityReport(items,[alice,bob],config(),NOW).summary;
  expect(sum.overdue).toBe(1);
 });
 it("sums urgency across all member buckets",()=>{
  expect(buildCapacityReport(items,[alice,bob],config(),NOW).summary.urgent).toBe(1);
 });
 it("sorts by most active tasks",()=>{
  const result=buildCapacityReport(items,[alice,bob],config({sort:"ACTIVE"}),NOW);
  expect(result.members[0]?.id).toBe("user_alice");
 });
 it("sorts by overdue count",()=>{
  const result=buildCapacityReport(items,[alice,bob],config({sort:"OVERDUE"}),NOW);
  expect(result.members[0]?.id).toBe("user_alice");
 });
 it("sorts members alphabetically",()=>{
  const result=buildCapacityReport(items,[bob,alice],config({sort:"MEMBER"}),NOW);
  expect(result.members.map(item=>item.name)).toEqual(["Alice","Bob"]);
 });
 it("shows a bounded task preview without hiding summary records",()=>{
  const result=buildCapacityReport(items,[alice,bob],config({maxTasks:1}),NOW);
  expect(result.members.find(item=>item.id==="user_alice")?.tasks).toHaveLength(1);
  expect(result.summary.tasks).toBe(5);
 });
 it("retains member role from actual membership",()=>{
  expect(buildCapacityReport(items,[alice,bob],config(),NOW).members
   .find(item=>item.id==="user_alice")?.role).toBe("ADMIN");
 });
 it("maintains an honest bounded coverage contract",()=>{
  expect(buildCapacityReport(items,[alice,bob],config(),NOW).coverage)
   .toMatchObject({complete:true,taskLimit:2000,memberLimit:500});
 });
 it("does not present workload as actual hours",()=>{
  expect(buildCapacityReport(items,[alice,bob],config(),NOW).disclaimer)
   .toMatch(/not working hours/);
 });
 it("handles a team with no members",()=>{
  const result=buildCapacityReport([],[],config(),NOW);
  expect(result.summary.members).toBe(0);
  expect(result.summary.minActive).toBe(0);
 });
 it("handles members with no tasks",()=>{
  const result=buildCapacityReport([], [alice],config(),NOW);
  expect(result.members[0]?.active).toBe(0);
  expect(result.summary.maxActive).toBe(0);
 });
 it("does not mutate input team ordering",()=>{
  const original=[bob,alice];
  buildCapacityReport(items,original,config(),NOW);
  expect(original.map(item=>item.userId)).toEqual(["user_bob","user_alice"]);
 });
});
