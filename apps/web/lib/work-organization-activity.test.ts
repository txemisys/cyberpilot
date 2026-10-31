import {describe,expect,it} from "vitest";
import {
 parseFeedFilter,feedSince,countFeedConcerns,
 groupFeedByWork,serializeFeedDigest,type FeedRow
} from "./work-organization-activity";
import {HistoryInputError} from "./work-audit-history";
const now=new Date("2026-10-31T12:00:00.000Z");
function row(id:string,overrides:Partial<FeedRow>={}):FeedRow{
 return {
  id,workItemId:"clwork12345",kind:"UPDATED",occurredAt:now,
  actorUserId:"actor12345",comment:"Updated human work coordination",
  actor:{name:"Operator",email:"operator@example.org"},
  workItem:{
   title:"Review conditional access",
   status:"IN_PROGRESS",
   finding:{title:"MFA gap",status:"OPEN",severity:"HIGH"}
  },...overrides
 };
}
describe("organization activity feed boundaries",()=>{
 it("defaults to a bounded 30-day window",()=>{
  expect(parseFeedFilter({})).toEqual({
   workItemId:null,actorUserId:null,kind:null,days:30,limit:25
  });
 });
 it("supports only explicitly documented durations",()=>{
  expect(parseFeedFilter({days:"7"}).days).toBe(7);
  expect(parseFeedFilter({days:"30"}).days).toBe(30);
  expect(parseFeedFilter({days:"90"}).days).toBe(90);
  for(const days of ["0","1","365","-7",null,30,{},[]])
   expect(()=>parseFeedFilter({days})).toThrow(HistoryInputError);
 });
 it("limits page size to small preset values",()=>{
  for(const value of ["10","25","50","100"])
   expect(parseFeedFilter({limit:value}).limit).toBe(Number(value));
  for(const value of ["0","9","101","1000","2.5",null,25])
   expect(()=>parseFeedFilter({limit:value})).toThrow();
 });
 it("rejects unknown query fields including tenant impersonation",()=>{
  for(const key of ["organizationId","tenantId","userId","role","verified"]){
   expect(()=>parseFeedFilter({[key]:"override"})).toThrow();
  }
 });
 it("accepts legitimate event kinds",()=>{
  for(const kind of ["CREATED","UPDATED","COMMENTED","REOPENED"]){
   expect(parseFeedFilter({kind}).kind).toBe(kind);
  }
  expect(parseFeedFilter({kind:"ALL"}).kind).toBeNull();
 });
 it("rejects security-status claims as audit kinds",()=>{
  for(const kind of ["VERIFIED","RESOLVED","SUCCESS","FAILED","SECRET"])
   expect(()=>parseFeedFilter({kind})).toThrow();
 });
 it("validates user and work filters",()=>{
  expect(parseFeedFilter({work:"clwork12345",actor:"actor12345"}))
   .toMatchObject({workItemId:"clwork12345",actorUserId:"actor12345"});
  expect(()=>parseFeedFilter({work:"../outside"})).toThrow();
  expect(()=>parseFeedFilter({actor:"../../tenant"})).toThrow();
 });
 it("calculates fixed UTC time windows",()=>{
  expect(feedSince(now,7).toISOString()).toBe("2026-10-24T12:00:00.000Z");
  expect(feedSince(now,30).toISOString()).toBe("2026-10-01T12:00:00.000Z");
 });
});
describe("organization-wide operational concerns",()=>{
 it("never treats an empty feed as a successful scan",()=>{
  expect(countFeedConcerns([])).toMatchObject({
   total:0,comments:0,updates:0,distinctTasks:0,
   completedWorkOpenFindings:0
  });
 });
 it("counts comments and updates separately",()=>{
  const result=countFeedConcerns([
   row("clevent001"),
   row("clevent002",{kind:"COMMENTED"}),
   row("clevent003",{kind:"REOPENED"})
  ]);
  expect(result).toMatchObject({
   total:3,comments:1,updates:2,distinctTasks:1
  });
 });
 it("flags completed work whose security finding remains open",()=>{
  const completed=row("clevent001",{
   workItem:{title:"Review MFA",status:"DONE",
    finding:{title:"MFA gap",status:"OPEN",severity:"HIGH"}}
  });
  expect(countFeedConcerns([completed]).completedWorkOpenFindings).toBe(1);
  expect(countFeedConcerns([completed]).disclaimer).toContain("do not verify controls");
 });
 it("does not flag already resolved findings as open",()=>{
  const resolved=row("clevent001",{
   workItem:{title:"Review MFA",status:"DONE",
    finding:{title:"MFA gap",status:"RESOLVED",severity:"HIGH"}}
  });
  expect(countFeedConcerns([resolved]).completedWorkOpenFindings).toBe(0);
 });
 it("preserves absent actor identity without guessing",()=>{
  const result=countFeedConcerns([row("clevent001",{actorUserId:null,actor:null})]);
  expect(result.anonymous).toBe(1);
 });
 it("counts distinct work items, not just event volume",()=>{
  const result=countFeedConcerns([
   row("clevent001"),row("clevent002"),
   row("clevent003",{workItemId:"clwork67890"})
  ]);
  expect(result.distinctTasks).toBe(2);
 });
});
describe("feed aggregation and display digest",()=>{
 it("groups several changes on the same work item",()=>{
  const groups=groupFeedByWork([
   row("clevent001",{kind:"COMMENTED"}),
   row("clevent002",{kind:"UPDATED"}),
   row("clevent003",{workItemId:"clwork67890",kind:"COMMENTED"})
  ]);
  expect(groups).toHaveLength(2);
  expect(groups[0]).toMatchObject({
   workItemId:"clwork12345",events:2,comments:1
  });
 });
 it("uses stable sorting by counts and work identifier",()=>{
  const groups=groupFeedByWork([
   row("clevent001",{workItemId:"clwork99999"}),
   row("clevent002",{workItemId:"clwork11111"})
  ]);
  expect(groups.map(group=>group.workItemId)).toEqual([
   "clwork11111","clwork99999"
  ]);
 });
 it("keeps the latest event time per work item",()=>{
  const results=groupFeedByWork([
   row("clevent001",{occurredAt:new Date("2026-10-01")}),
   row("clevent002",{occurredAt:new Date("2026-10-30")})
  ]);
  expect(results[0]?.lastAt.toISOString()).toContain("2026-10-30");
 });
 it("returns compact readable digests with actor names",()=>{
  const digest=serializeFeedDigest([row("clevent001")]);
  expect(digest[0]).toMatchObject({
   eventId:"clevent001",workItemId:"clwork12345",kind:"UPDATED",
   title:"Review conditional access",actor:"Operator",
   findingStatus:"OPEN",workStatus:"IN_PROGRESS",warning:null
  });
 });
 it("shows an explicit warning for completed human work with open findings",()=>{
  const digest=serializeFeedDigest([row("clevent001",{
   workItem:{title:"Review",status:"DONE",
    finding:{title:"MFA",status:"OPEN",severity:"URGENT"}}
  })]);
  expect(digest[0]?.warning).toContain("finding remains open");
 });
 it("does not manufacture an actor name for missing users",()=>{
  expect(serializeFeedDigest([
   row("clevent001",{actorUserId:null,actor:null})
  ])[0]?.actor).toBeNull();
 });
 it("retains comments as historical statements, not verification",()=>{
  const digest=serializeFeedDigest([row("clevent001",{
   kind:"COMMENTED",comment:"Operator says this was performed"
  })]);
  expect(digest[0]?.comment).toBe("Operator says this was performed");
  expect(digest[0]?.warning).toBeNull();
 });
});
