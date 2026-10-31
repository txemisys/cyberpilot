import {describe,expect,it} from "vitest";
import {
 parsePlanningOptions,workPoints,planningScore,comparePlanningWork,
 isOpen,isDueWithin,planAssignments,
 type PlanningWork,type PlanningMember,type PlanningDataset,
} from "./remediation-assignment-planner";
const NOW=new Date("2026-11-01T12:00:00.000Z");
const alice:PlanningMember={userId:"alice_001",name:"Alice",role:"ADMIN",email:"alice@example.test"};
const bob:PlanningMember={userId:"bob_00001",name:"Bob",role:"MEMBER",email:"bob@example.test"};
const carol:PlanningMember={userId:"carol_001",name:"Carol",role:"MEMBER",email:"carol@example.test"};
function item(override:Partial<PlanningWork>={}):PlanningWork{
 return {
  id:"work_001",title:"Update security settings",revision:1,
  status:"TODO",priority:"NORMAL",assigneeUserId:null,dueAt:null,
  updatedAt:NOW,findingSeverity:"MEDIUM",findingTitle:"Control gap",
  remediationStatus:"PROPOSED",...override,
 };
}
function dataset(items:PlanningWork[]=[],members:PlanningMember[]=[alice,bob]):PlanningDataset{
 return {items,members,truncated:false};
}
function options(overrides:Record<string,unknown>={}){
 return parsePlanningOptions(overrides);
}
function invalid(value:unknown){
 expect(()=>parsePlanningOptions(value)).toThrow();
}
describe("planning input boundary",()=>{
 it("provides conservative defaults",()=>{
  expect(options()).toMatchObject({
   horizonDays:30,scope:"UNASSIGNED",capacityPoints:20,
   maxMoves:50,preserveOwners:true,includeBlocked:false,settings:[],
  });
 });
 it.each([null,[],42,false,"scenario",undefined])("rejects non-object input",invalid);
 it("rejects unknown keys",()=>invalid({skipAuthorization:true}));
 it.each([1,6,8,31,91,365,0,-1,12.3,"30",null])(
  "rejects unsupported horizon %s",horizonDays=>invalid({horizonDays}));
 it.each([7,14,30,60,90])("accepts horizon %s",horizonDays=>{
  expect(options({horizonDays}).horizonDays).toBe(horizonDays);
 });
 it.each(["OPEN","ASSIGNED","ALL","",null,3])(
  "rejects invalid scope %s",scope=>invalid({scope}));
 it.each(["UNASSIGNED","ALL_OPEN"])("accepts scope %s",scope=>{
  expect(options({scope}).scope).toBe(scope);
 });
 it.each([-1,1001,1.5,"20",null,NaN,Infinity])(
  "rejects invalid capacity %s",capacityPoints=>invalid({capacityPoints}));
 it.each([0,-1,51,1.5,"10",null])(
  "rejects invalid move count %s",maxMoves=>invalid({maxMoves}));
 it.each([0,1,50,1000])("accepts capacity %s",capacityPoints=>{
  expect(options({capacityPoints}).capacityPoints).toBe(capacityPoints);
 });
 it.each([1,20,50])("accepts move count %s",maxMoves=>{
  expect(options({maxMoves}).maxMoves).toBe(maxMoves);
 });
 it.each([null,"yes",0,1])("rejects non-boolean blocked flag %s",includeBlocked=>{
  invalid({includeBlocked});
 });
 it.each([null,"yes",0,1])("rejects non-boolean preservation %s",preserveOwners=>{
  invalid({preserveOwners});
 });
 it("rejects non-array settings",()=>invalid({settings:{}}));
 it("rejects non-object member setting",()=>invalid({settings:[null]}));
 it("rejects invalid member ID",()=>invalid({
  settings:[{userId:"x",available:true,capacityPoints:5}],
 }));
 it("rejects duplicate member entries",()=>invalid({
  settings:[
   {userId:alice.userId,available:true,capacityPoints:10},
   {userId:alice.userId,available:false,capacityPoints:20},
  ],
 }));
 it("rejects unknown per-member properties",()=>invalid({
  settings:[{userId:alice.userId,available:true,capacityPoints:10,admin:true}],
 }));
 it("rejects missing availability",()=>invalid({
  settings:[{userId:alice.userId,capacityPoints:10}],
 }));
 it("rejects invalid per-member capacity",()=>invalid({
  settings:[{userId:alice.userId,capacityPoints:-2,available:true}],
 }));
 it("inherits default capacity in member override",()=>{
  expect(options({capacityPoints:33,settings:[{
   userId:alice.userId,available:true,
  }]}).settings[0]?.capacityPoints).toBe(33);
 });
});
describe("work priority and horizon ranking",()=>{
 it("adds finding severity to human work priority",()=>{
  expect(workPoints(item({priority:"URGENT",findingSeverity:"CRITICAL"})).toBe(9);
 });
 it("does not equate high severity with completed work",()=>{
  expect(workPoints(item({priority:"LOW",findingSeverity:"HIGH"}))).toBe(3);
 });
 it("assigns fallback severity when unknown",()=>{
  expect(workPoints(item({findingSeverity:"UNKNOWN"}))).toBe(3);
 });
 it("recognizes open human work",()=>{
  expect(isOpen(item({status:"TODO"}))).toBe(true);
  expect(isOpen(item({status:"IN_PROGRESS"}))).toBe(true);
  expect(isOpen(item({status:"BLOCKED"}))).toBe(true);
 });
 it("excludes completed and cancelled work",()=>{
  expect(isOpen(item({status:"DONE"}))).toBe(false);
  expect(isOpen(item({status:"CANCELLED"}))).toBe(false);
 });
 it("includes undated tasks in the horizon",()=>{
  expect(isDueWithin(item(),NOW)).toBe(true);
 });
 it("excludes future-dated work beyond the cutoff",()=>{
  expect(isDueWithin(item({dueAt:new Date("2027-01-01")}),NOW)).toBe(false);
 });
 it("includes boundary date",()=>{
  expect(isDueWithin(item({dueAt:NOW}),NOW)).toBe(true);
 });
 it("prioritizes overdue tasks over otherwise identical tasks",()=>{
  const overdue=item({dueAt:new Date("2026-10-01")});
  const future=item({dueAt:new Date("2026-11-10")});
  expect(planningScore(overdue,NOW)).toBeGreaterThan(planningScore(future,NOW));
 });
 it("ranks urgent over lower priority",()=>{
  expect(planningScore(item({priority:"URGENT"}),NOW)).toBeGreaterThan(
   planningScore(item({priority:"LOW"}),NOW));
 });
 it("discounts blocked work without silently dropping it",()=>{
  expect(planningScore(item({status:"BLOCKED"}),NOW)).toBeLessThan(
   planningScore(item({status:"TODO"}),NOW));
 });
 it("orders by stable IDs on a complete tie",()=>{
  const a=item({id:"work_aaa"}),b=item({id:"work_bbb"});
  expect(comparePlanningWork(a,b,NOW)).toBeLessThan(0);
 });
});
describe("bounded planning behavior",()=>{
 it("assigns a single task to the first available member",()=>{
  const result=planAssignments(dataset([item()]),options(),NOW);
  expect(result.proposedMoves).toBe(1);
  expect(result.allocations[0]).toMatchObject({
   action:"ASSIGN",proposedUserId:alice.userId,revision:1,
  });
 });
 it("does not fabricate a security verification",()=>{
  const result=planAssignments(dataset([item()]),options(),NOW);
  expect(result.notes.join(" ")).toMatch(/verification state/);
 });
 it("respects zero capacity",()=>{
  const result=planAssignments(dataset([item()]),options({capacityPoints:0}),NOW);
  expect(result.allocations[0]?.action).toBe("UNPLACED");
  expect(result.proposedMoves).toBe(0);
 });
 it("respects unavailable members",()=>{
  const result=planAssignments(dataset([item()]),options({
   settings:[{userId:alice.userId,available:false,capacityPoints:20}],
  }),NOW);
  expect(result.allocations[0]?.proposedUserId).toBe(bob.userId);
 });
 it("rejects settings that reference a foreign user",()=>{
  expect(()=>planAssignments(dataset([item()]),options({
   settings:[{userId:"foreign001",available:true,capacityPoints:100}],
  }),NOW)).toThrow(/non-member/);
 });
 it("does not move an owned task in unassigned-only mode",()=>{
  const result=planAssignments(dataset([
   item({assigneeUserId:alice.userId}),
  ]),options(),NOW);
  expect(result.considered).toBe(0);
  expect(result.proposedMoves).toBe(0);
 });
 it("keeps an owner with preservation enabled",()=>{
  const result=planAssignments(dataset([
   item({assigneeUserId:alice.userId}),
  ]),options({scope:"ALL_OPEN"}),NOW);
  expect(result.allocations[0]).toMatchObject({
   action:"KEEP",proposedUserId:alice.userId,
  });
 });
 it("may rebalance when preservation is disabled",()=>{
  const result=planAssignments(dataset([
   item({id:"work_101",priority:"URGENT",assigneeUserId:alice.userId}),
   item({id:"work_102",priority:"HIGH",assigneeUserId:alice.userId}),
  ]),options({scope:"ALL_OPEN",preserveOwners:false}),NOW);
  expect(result.allocations.some(row=>row.proposedUserId===bob.userId)).toBe(true);
 });
 it("excludes blocked by default",()=>{
  const result=planAssignments(dataset([item({status:"BLOCKED"})]),options(),NOW);
  expect(result.considered).toBe(0);
 });
 it("includes blocked when explicitly selected",()=>{
  const result=planAssignments(dataset([item({status:"BLOCKED"})]),
   options({includeBlocked:true}),NOW);
  expect(result.considered).toBe(1);
 });
 it("does not plan completed work",()=>{
  const result=planAssignments(dataset([item({status:"DONE"})]),options(),NOW);
  expect(result.totalOpenWork).toBe(0);
 });
 it("does not plan cancelled work",()=>{
  const result=planAssignments(dataset([item({status:"CANCELLED"})]),options(),NOW);
  expect(result.totalOpenWork).toBe(0);
 });
 it("excludes tasks outside the horizon",()=>{
  const result=planAssignments(dataset([
   item({dueAt:new Date("2027-01-01")}),
  ]),options({horizonDays:7}),NOW);
  expect(result.excluded).toBe(1);
 });
 it("prefers members with smaller relative loads",()=>{
  const result=planAssignments(dataset([
   item({id:"work_current",assigneeUserId:alice.userId,priority:"URGENT"}),
   item({id:"work_new"}),
  ]),options(),NOW);
  expect(result.allocations[0]?.proposedUserId).toBe(bob.userId);
 });
 it("respects the maximum number of proposed moves",()=>{
  const result=planAssignments(dataset([
   item({id:"work_101"}),item({id:"work_102"}),item({id:"work_103"}),
  ]),options({maxMoves:1}),NOW);
  expect(result.proposedMoves).toBe(1);
  expect(result.unplaced).toBe(2);
 });
 it("does not overallocate a member past scenario capacity",()=>{
  const result=planAssignments(dataset([
   item({id:"work_101"}),item({id:"work_102"}),item({id:"work_103"}),
  ]),options({capacityPoints:3}),NOW);
  expect(result.members.every(person=>person.plannedPoints<=3)).toBe(true);
 });
 it("uses explicit per-person capacity",()=>{
  const result=planAssignments(dataset([item()]),options({
   settings:[{userId:alice.userId,available:true,capacityPoints:0}],
  }),NOW);
  expect(result.allocations[0]?.proposedUserId).toBe(bob.userId);
 });
 it("reports existing and planned points independently",()=>{
  const result=planAssignments(dataset([
   item({id:"work_owned",assigneeUserId:alice.userId}),
   item({id:"work_new"}),
  ]),options(),NOW);
  expect(result.members.find(person=>person.userId===alice.userId)?.existingPoints).toBe(3);
  expect(result.members.reduce((sum,person)=>sum+person.plannedPoints,0)).toBe(6);
 });
 it("reports partial inventory prominently",()=>{
  const input=dataset([item()]);
  const result=planAssignments({...input,truncated:true},options(),NOW);
  expect(result.coverage.truncated).toBe(true);
  expect(result.coverage.reason).toMatch(/partial/);
 });
 it("preserves audit revision in every proposed change",()=>{
  const result=planAssignments(dataset([item({revision:17})]),options(),NOW);
  expect(result.allocations[0]?.revision).toBe(17);
 });
 it("generates a fixed cutoff from the supplied clock",()=>{
  const result=planAssignments(dataset(),options({horizonDays:7}),NOW);
  expect(result.cutoff).toBe(new Date(NOW.getTime()+7*86400000).toISOString());
 });
 it("reports zero capacity without division by zero",()=>{
  const result=planAssignments(dataset(),options({capacityPoints:0}),NOW);
  expect(result.members[0]?.utilizationPercent).toBeNull();
 });
 it("works with no members and no tasks",()=>{
  const result=planAssignments(dataset([],[]),options(),NOW);
  expect(result.allocations).toEqual([]);
  expect(result.members).toEqual([]);
  expect(result.proposedMoves).toBe(0);
 });
 it("does not claim capacity can establish professional availability",()=>{
  const result=planAssignments(dataset(),options(),NOW);
  expect(result.notes.join(" ")).toMatch(/not measured working hours/);
 });
});
