import {describe,expect,it} from "vitest";
import {
 parseInboxFilter,inboxWhere,classifyInboxWork,orderInboxRows,summarizeInbox,
 type InboxWork,type InboxHandoff,type InboxRow,
} from "./remediation-work-inbox";
import type {WorkContext} from "./remediation-work-store";

const NOW=new Date("2026-11-01T12:00:00.000Z");
const DAY=86400000;
const context:WorkContext={
 organizationId:"organization_alpha",userId:"user_alpha",role:"MEMBER",
};
function date(days:number){return new Date(NOW.getTime()+days*DAY);}
function work(overrides:Partial<InboxWork>={}):InboxWork{
 return {
  id:"work_alpha",title:"Review access",description:"Coordinate the control review",
  status:"TODO",priority:"NORMAL",revision:3,
  assigneeUserId:"user_alpha",dueAt:null,completedAt:null,
  createdAt:date(-10),updatedAt:date(-1),
  finding:{title:"Access gap",severity:"MEDIUM",status:"OPEN"},
  remediation:{title:"Tighten access",status:"PROPOSED"},
  assignee:{id:"user_alpha",name:"Alice"},
  ...overrides,
 };
}
function handoff(overrides:Partial<InboxHandoff>={}):InboxHandoff{
 return {
  id:"handoff_alpha",workItemId:"work_alpha",recipientUserId:"user_alpha",
  requesterUserId:"user_beta",status:"REQUESTED",
  reason:"Please accept this operational responsibility.",
  requestedAt:date(-2),expiresAt:date(1),
  workItem:{id:"work_alpha",title:"Review access",status:"TODO",revision:3},
  ...overrides,
 };
}
function row(overrides:Partial<InboxWork>={},handoffs:InboxHandoff[]=[]){
 return classifyInboxWork(work(overrides),NOW,handoffs,context.userId);
}
const allAttention=["CRITICAL","HIGH","NORMAL","LOW","CLOSED"];
describe("inbox filters",()=>{
 it("defaults to personal active work",()=>{
  expect(parseInboxFilter({})).toEqual({
   view:"MINE",urgency:"ALL",sort:"ATTENTION",search:"",
   includeClosed:false,page:1,pageSize:20,
  });
 });
 it.each(["MINE","TEAM","UNASSIGNED","HANDOFFS"])(
  "accepts view %s",view=>{
   expect(parseInboxFilter({view}).view).toBe(view);
  },
 );
 it.each(["OVERDUE","DUE_SOON","BLOCKED","URGENT","NO_DATE"])(
  "accepts urgency %s",urgency=>{
   expect(parseInboxFilter({urgency}).urgency).toBe(urgency);
  },
 );
 it.each(["ATTENTION","DUE","UPDATED","PRIORITY"])(
  "accepts sort %s",sort=>{
   expect(parseInboxFilter({sort}).sort).toBe(sort);
  },
 );
 it.each(["OTHER",null,42,{},[],false])("rejects unsupported view %s",view=>{
  expect(parseInboxFilter({view}).view).toBe("MINE");
 });
 it.each(["OTHER",null,42,{},[],false])("rejects unsupported urgency %s",urgency=>{
  expect(parseInboxFilter({urgency}).urgency).toBe("ALL");
 });
 it.each(["OTHER",null,42,{},[],false])("rejects unsupported sort %s",sort=>{
  expect(parseInboxFilter({sort}).sort).toBe("ATTENTION");
 });
 it("trims and bounds search text",()=>{
  expect(parseInboxFilter({search:"  alpha  "}).search).toBe("alpha");
  expect(parseInboxFilter({search:"x".repeat(300)}).search).toHaveLength(100);
 });
 it("does not coerce non-text search values",()=>{
  expect(parseInboxFilter({search:{contains:"secret"}}).search).toBe("");
 });
 it("only accepts a literal closed-work flag",()=>{
  expect(parseInboxFilter({includeClosed:"true"}).includeClosed).toBe(true);
  expect(parseInboxFilter({includeClosed:"1"}).includeClosed).toBe(false);
  expect(parseInboxFilter({includeClosed:true}).includeClosed).toBe(false);
 });
 it.each(["0","-1","NaN","Infinity","1.5","abc",null])(
  "defaults invalid page %s",page=>{
   expect(parseInboxFilter({page}).page).toBe(1);
  },
 );
 it("caps extremely large pages",()=>{
  expect(parseInboxFilter({page:"999999"}).page).toBe(100000);
 });
 it.each(["20","50","100","999","-1"])("handles page size %s",pageSize=>{
  const expected=pageSize==="50"?50:pageSize==="100"?100:20;
  expect(parseInboxFilter({pageSize}).pageSize).toBe(expected);
 });
 it("always retains the organization boundary in default filtering",()=>{
  const where=inboxWhere(context,parseInboxFilter({}),NOW);
  expect(where.organizationId).toBe(context.organizationId);
  expect(where.assigneeUserId).toBe(context.userId);
 });
 it("restricts unassigned queries to null ownership",()=>{
  const where=inboxWhere(context,parseInboxFilter({view:"UNASSIGNED"}),NOW);
  expect(where.assigneeUserId).toBeNull();
 });
 it("restricts handoff queries to the current recipient",()=>{
  const where=inboxWhere(context,parseInboxFilter({view:"HANDOFFS"}),NOW);
  expect(where.handoffs).toEqual({some:{
   organizationId:context.organizationId,recipientUserId:context.userId,
   status:"REQUESTED",
  }});
 });
 it("permits team views without leaking organization scope",()=>{
  const where=inboxWhere(context,parseInboxFilter({view:"TEAM"}),NOW);
  expect(where.organizationId).toBe(context.organizationId);
  expect(where.assigneeUserId).toBeUndefined();
 });
 it("excludes closed work by default",()=>{
  const where=inboxWhere(context,parseInboxFilter({}),NOW);
  expect(where.status).toEqual({notIn:["DONE","CANCELLED"]});
 });
 it("includes closed work when explicitly requested",()=>{
  const where=inboxWhere(context,parseInboxFilter({includeClosed:"true"}),NOW);
  expect(where.status).toBeUndefined();
 });
 it("filters urgent work without changing status scope",()=>{
  const where=inboxWhere(context,parseInboxFilter({urgency:"URGENT"}),NOW);
  expect(where.priority).toBe("URGENT");
  expect(where.organizationId).toBe(context.organizationId);
 });
 it("filters blocked work",()=>{
  expect(inboxWhere(context,parseInboxFilter({urgency:"BLOCKED"}),NOW).status).toBe("BLOCKED");
 });
 it("filters undated work",()=>{
  expect(inboxWhere(context,parseInboxFilter({urgency:"NO_DATE"}),NOW).dueAt).toBeNull();
 });
 it("filters overdue against a fixed clock",()=>{
  const where=inboxWhere(context,parseInboxFilter({urgency:"OVERDUE"}),NOW);
  expect(where.dueAt).toEqual({lt:NOW});
  expect(where.status).toEqual({notIn:["DONE","CANCELLED"]});
 });
 it("filters upcoming work within seven days",()=>{
  const where=inboxWhere(context,parseInboxFilter({urgency:"DUE_SOON"}),NOW);
  expect(where.dueAt).toEqual({
   gte:NOW,lte:new Date(NOW.getTime()+7*DAY),
  });
 });
 it("searches task and linked finding without raw SQL",()=>{
  const where=inboxWhere(context,parseInboxFilter({search:"access"}),NOW);
  expect(where.OR).toHaveLength(4);
  expect(where.organizationId).toBe(context.organizationId);
 });
});
describe("personal attention classification",()=>{
 it("marks ordinary work with normal attention",()=>{
  expect(row().attention).toBe("LOW");
 });
 it("assigns critical attention to missed deadlines",()=>{
  const result=row({dueAt:date(-3)});
  expect(result.attention).toBe("CRITICAL");
  expect(result.attentionReasons).toContain("Past its target date");
 });
 it("computes overdue calendar offsets with a consistent clock",()=>{
  expect(row({dueAt:date(-4)}).dueDays).toBe(-4);
 });
 it("does not flag a future date as overdue",()=>{
  expect(row({dueAt:date(10)}).attentionReasons).not.toContain("Past its target date");
 });
 it("marks targets within seven days",()=>{
  expect(row({dueAt:date(7)}).attentionReasons).toContain("Target date within seven days");
 });
 it("does not mark targets eight days away",()=>{
  expect(row({dueAt:date(8)}).attentionReasons).not.toContain("Target date within seven days");
 });
 it("flags blocked work",()=>{
  const result=row({status:"BLOCKED"});
  expect(result.attention).toBe("HIGH");
  expect(result.attentionReasons).toContain("Work is blocked");
 });
 it("recognizes urgent priority",()=>{
  const result=row({priority:"URGENT"});
  expect(result.attention).toBe("HIGH");
  expect(result.attentionReasons).toContain("Marked urgent by the team");
 });
 it("escalates critical findings with urgent work priority",()=>{
  const result=row({priority:"URGENT",finding:{
   title:"Critical access",severity:"CRITICAL",status:"OPEN",
  }});
  expect(result.attention).toBe("CRITICAL");
 });
 it("distinguishes critical severity from verification",()=>{
  const result=row({finding:{title:"Important",severity:"CRITICAL",status:"OPEN"}});
  expect(result.findingStatus).toBe("OPEN");
  expect(result.remediationStatus).toBe("PROPOSED");
 });
 it("identifies unassigned tasks",()=>{
  const result=row({assigneeUserId:null,assignee:null});
  expect(result.attentionReasons).toContain("No assignee");
  expect(result.proposedNextAction).toMatch(/Assign/);
 });
 it("does not call completed work a verified finding",()=>{
  const result=row({status:"DONE",finding:{
   title:"Unresolved security gap",severity:"CRITICAL",status:"OPEN",
  }});
  expect(result.attention).toBe("CLOSED");
  expect(result.findingStatus).toBe("OPEN");
  expect(result.proposedNextAction).toMatch(/separately/);
 });
 it("does not mark cancelled work urgent even if past due",()=>{
  const result=row({status:"CANCELLED",dueAt:date(-30),priority:"URGENT"});
  expect(result.attention).toBe("CLOSED");
 });
 it("counts work age without negative time",()=>{
  expect(row({createdAt:date(1)}).ageDays).toBe(0);
  expect(row({createdAt:date(-12)}).ageDays).toBe(12);
 });
 it("preserves the persisted revision number",()=>{
  expect(row({revision:99}).revision).toBe(99);
 });
 it("preserves ownership details",()=>{
  const result=row();
  expect(result.assigneeUserId).toBe("user_alpha");
  expect(result.assigneeName).toBe("Alice");
 });
 it("never invents a deadline when none exists",()=>{
  expect(row().dueAt).toBeNull();
  expect(row().dueDays).toBeNull();
 });
 it("counts handoffs for the work item",()=>{
  const result=row({},[handoff(),handoff({
   id:"handoff_beta",recipientUserId:"user_beta",
  })]);
  expect(result.handoffCount).toBe(2);
  expect(result.pendingForMe).toBe(1);
 });
 it("ignores handoffs for other work items",()=>{
  const result=row({},[handoff({workItemId:"work_elsewhere"})]);
  expect(result.handoffCount).toBe(0);
 });
 it("ignores decided handoffs",()=>{
  const result=row({},[handoff({status:"ACCEPTED"})]);
  expect(result.pendingForMe).toBe(0);
 });
 it("flags expiring handoffs for the recipient",()=>{
  const result=row({},[handoff({expiresAt:date(1)})]);
  expect(result.handoffExpiresSoon).toBe(true);
  expect(result.attention).toBe("CRITICAL");
 });
 it("does not flag another user's expiring handoff",()=>{
  const result=row({},[handoff({
   recipientUserId:"user_beta",expiresAt:date(1),
  })]);
  expect(result.handoffExpiresSoon).toBe(false);
 });
 it("does not flag distant handoff expiry",()=>{
  const result=row({},[handoff({expiresAt:date(5)})]);
  expect(result.handoffExpiresSoon).toBe(false);
 });
 it("routes incoming handoffs to decision action",()=>{
  const result=row({},[handoff()]);
  expect(result.proposedNextAction).toMatch(/Accept or decline/);
 });
 it("routes blocked work to dependency resolution",()=>{
  expect(row({status:"BLOCKED"}).proposedNextAction).toMatch(/blocker/);
 });
 it("routes overdue work to review and replanning",()=>{
  expect(row({dueAt:date(-1)}).proposedNextAction).toMatch(/missed target/);
 });
 it("routes new assigned tasks to start confirmation",()=>{
  expect(row({status:"TODO"}).proposedNextAction).toMatch(/actually begins/);
 });
 it("routes active tasks to recorded work progress",()=>{
  expect(row({status:"IN_PROGRESS"}).proposedNextAction).toMatch(/document/);
 });
});
describe("sorting and summary invariants",()=>{
 const sample:InboxRow[]=[
  row({id:"work_001",priority:"LOW",dueAt:date(30)}),
  row({id:"work_002",priority:"URGENT",dueAt:date(10)}),
  row({id:"work_003",priority:"HIGH",dueAt:date(-2)}),
  row({id:"work_004",status:"DONE",dueAt:date(-100)}),
 ];
 it("sorts attention by critical before high and closed",()=>{
  const result=orderInboxRows(sample,"ATTENTION");
  expect(result[0]?.id).toBe("work_003");
  expect(result.at(-1)?.id).toBe("work_004");
 });
 it("sorts priority by urgent first",()=>{
  expect(orderInboxRows(sample,"PRIORITY")[0]?.id).toBe("work_002");
 });
 it("sorts due date deterministically",()=>{
  const result=orderInboxRows(sample,"DUE");
  expect(result[0]?.id).toBe("work_004");
 });
 it("sorts last updated first",()=>{
  const result=orderInboxRows([
   row({id:"work_001",updatedAt:date(-10)}),
   row({id:"work_002",updatedAt:date(-1)}),
  ],"UPDATED");
  expect(result[0]?.id).toBe("work_002");
 });
 it("does not modify the original array",()=>{
  const before=sample.map(item=>item.id);
  orderInboxRows(sample,"ATTENTION");
  expect(sample.map(item=>item.id)).toEqual(before);
 });
 it("provides a stable ordering under ties",()=>{
  const result=orderInboxRows([
   row({id:"work_z"}),row({id:"work_a"}),
  ],"ATTENTION");
  expect(result.map(item=>item.id)).toEqual(["work_a","work_z"]);
 });
 it("summarizes the matching set instead of a page count",()=>{
  const result=summarizeInbox(sample);
  expect(result.total).toBe(4);
  expect(result.closed).toBe(1);
  expect(result.open).toBe(3);
  expect(result.overdue).toBe(1);
  expect(result.urgent).toBe(1);
 });
 it("keeps all attention buckets present when empty",()=>{
  const result=summarizeInbox([]);
  expect(result.total).toBe(0);
  for(const level of allAttention)expect(result.attention[level as keyof typeof result.attention]).toBe(0);
 });
 it("counts pending handoffs for the current user only",()=>{
  const result=summarizeInbox([
   row({},[handoff()]),
   row({id:"work_beta"},[handoff({workItemId:"work_beta",recipientUserId:"user_beta"})]),
  ]);
  expect(result.pendingHandoffs).toBe(1);
 });
 it("does not double count closed work as an overdue operational task",()=>{
  const result=summarizeInbox([
   row({status:"DONE",dueAt:date(-5),priority:"URGENT"}),
  ]);
  expect(result.overdue).toBe(0);
  expect(result.urgent).toBe(0);
  expect(result.closed).toBe(1);
 });
 it("counts unassigned active work",()=>{
  const result=summarizeInbox([
   row({assigneeUserId:null,assignee:null}),
  ]);
  expect(result.unassigned).toBe(1);
 });
 it("accounts for urgent blocked work in both categories",()=>{
  const result=summarizeInbox([
   row({priority:"URGENT",status:"BLOCKED"}),
  ]);
  expect(result.urgent).toBe(1);
  expect(result.blocked).toBe(1);
 });
 it("keeps total attention buckets equal to row count",()=>{
  const result=summarizeInbox(sample);
  expect(Object.values(result.attention).reduce((a,b)=>a+b,0)).toBe(sample.length);
 });
});
