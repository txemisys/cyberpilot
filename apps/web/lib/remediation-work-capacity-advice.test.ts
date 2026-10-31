import {describe,expect,it} from "vitest";
import {buildCapacityReport,parseCapacityConfig,type CapacityWork,type CapacityMember} from "./remediation-work-capacity";
import {buildCapacityAdvice,memberCapacityRecommendations} from "./remediation-work-capacity-advice";
const NOW=new Date("2026-11-01T12:00:00.000Z");
const day=(n:number)=>new Date(NOW.getTime()+n*86400000);
const alice:CapacityMember={userId:"user_alice",name:"Alice",role:"ADMIN"};
const bob:CapacityMember={userId:"user_bob",name:"Bob",role:"MEMBER"};
function task(patch:Partial<CapacityWork>={}):CapacityWork{
 return {id:"work_alpha",title:"Review access",status:"TODO",priority:"NORMAL",
  assigneeUserId:"user_alice",dueAt:day(20),updatedAt:day(-1),
  findingSeverity:"MEDIUM",checklist:[{completedAt:NOW}],handoffs:[],...patch};
}
function report(items:CapacityWork[]=[]){
 return buildCapacityReport(items,[alice,bob],parseCapacityConfig({}),NOW);
}
describe("capacity follow-up guidance based on recorded work",()=>{
 it("does not manufacture advice for an empty team",()=>{
  expect(buildCapacityAdvice(report()).recommendations).toHaveLength(0);
 });
 it("identifies overdue clusters from persisted dates",()=>{
  const result=buildCapacityAdvice(report([
   task({id:"work_one",dueAt:day(-3)}),
  ]));
  expect(result.recommendations.some(item=>item.signal==="OVERDUE_CLUSTER")).toBe(true);
 });
 it("uses high severity after three overdue tasks",()=>{
  const result=buildCapacityAdvice(report([
   task({id:"work_one",dueAt:day(-1)}),
   task({id:"work_two",dueAt:day(-2)}),
   task({id:"work_three",dueAt:day(-3)}),
  ]));
  expect(result.recommendations.find(item=>item.signal==="OVERDUE_CLUSTER")?.severity).toBe("HIGH");
 });
 it("identifies blockers independent of deadlines",()=>{
  const result=buildCapacityAdvice(report([task({status:"BLOCKED"})]));
  expect(result.recommendations.some(item=>item.signal==="BLOCKER_CLUSTER")).toBe(true);
 });
 it("flags multiple blockers for higher attention",()=>{
  const result=buildCapacityAdvice(report([
   task({id:"work_one",status:"BLOCKED"}),
   task({id:"work_two",status:"BLOCKED"}),
  ]));
  expect(result.recommendations.find(item=>item.signal==="BLOCKER_CLUSTER")?.severity).toBe("HIGH");
 });
 it("flags pending handoffs without transferring ownership",()=>{
  const result=buildCapacityAdvice(report([
   task({handoffs:[{status:"REQUESTED"}]}),
  ]));
  expect(result.recommendations.some(item=>item.signal==="HANDOFF_BACKLOG")).toBe(true);
 });
 it("does not flag accepted handoffs",()=>{
  const result=buildCapacityAdvice(report([
   task({handoffs:[{status:"ACCEPTED"}]}),
  ]));
  expect(result.recommendations.some(item=>item.signal==="HANDOFF_BACKLOG")).toBe(false);
 });
 it("tracks work without an eligible recorded owner",()=>{
  const result=buildCapacityAdvice(report([
   task({assigneeUserId:null}),
  ]));
  expect(result.recommendations.find(item=>item.signal==="UNASSIGNED")?.count).toBe(1);
 });
 it("tracks former-member ownership in the unassigned bucket",()=>{
  const result=buildCapacityAdvice(report([
   task({assigneeUserId:"former_member"}),
  ]));
  expect(result.recommendations.some(item=>item.signal==="UNASSIGNED")).toBe(true);
 });
 it("does not create reassignment automatically",()=>{
  const result=buildCapacityAdvice(report([
   task({assigneeUserId:null}),
  ]));
  expect(result.disclaimer).toMatch(/not automatic reassignment/);
 });
 it("spots significant member task-count imbalance",()=>{
  const tasks=Array.from({length:6},(_,i)=>task({id:`work_${i}`}));
  expect(buildCapacityAdvice(report(tasks)).recommendations
   .some(item=>item.signal==="LOAD_SKEW")).toBe(true);
 });
 it("does not invent workload skew for balanced task counts",()=>{
  const result=buildCapacityAdvice(report([
   task({id:"work_one"}),task({id:"work_two",assigneeUserId:"user_bob"}),
  ]));
  expect(result.recommendations.some(item=>item.signal==="LOAD_SKEW")).toBe(false);
 });
 it("retains data completeness in the recommendation result",()=>{
  expect(buildCapacityAdvice(report()).coverage.complete).toBe(true);
 });
 it("does not confuse task counts with actual effort",()=>{
  expect(buildCapacityAdvice(report()).disclaimer).toMatch(/human judgement/);
 });
 it("does not modify member workload input",()=>{
  const model=report([task({status:"BLOCKED"})]);
  const original=JSON.stringify(model);
  buildCapacityAdvice(model);
  expect(JSON.stringify(model)).toBe(original);
 });
 it("sorts high severity signals before normal severity",()=>{
  const model=report([
   task({id:"one",dueAt:day(-1),status:"BLOCKED"}),
   task({id:"two",dueAt:day(-2),status:"BLOCKED"}),
  ]);
  const result=buildCapacityAdvice(model);
  const levels=result.recommendations.map(item=>item.severity);
  expect(levels.indexOf("NORMAL")).toBe(-1);
 });
 it("keeps the exact snapshot timestamp",()=>{
  expect(buildCapacityAdvice(report()).generatedAt).toBe(NOW.toISOString());
 });
 it("can inspect a single member without needing a live service",()=>{
  const model=report([task({status:"BLOCKED"})]);
  expect(memberCapacityRecommendations(model.members.find(item=>item.id==="user_alice")!)
   .some(item=>item.signal==="BLOCKER_CLUSTER")).toBe(true);
 });
});
