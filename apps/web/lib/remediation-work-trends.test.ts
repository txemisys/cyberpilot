import {describe,expect,it} from "vitest";
import {
 parseTrendFilter,trendStart,classifyTrendEvent,buildWorkTrends,
 type TrendEvent,type TrendWork,
} from "./remediation-work-trends";
const NOW=new Date("2026-11-01T18:00:00.000Z");
const DAY=86400000;
function date(days:number){return new Date(NOW.getTime()+days*DAY);}
function event(patch:Partial<TrendEvent>={}):TrendEvent{
 return {
  id:"event_alpha",workItemId:"work_alpha",kind:"UPDATED",
  occurredAt:date(-2),actorUserId:"user_alpha",before:null,after:null,
  comment:null,...patch,
 };
}
function work(patch:Partial<TrendWork>={}):TrendWork{
 return {id:"work_alpha",title:"Review access",status:"IN_PROGRESS",
  assigneeUserId:"user_alpha",createdAt:date(-30),updatedAt:date(-1),...patch};
}
const options=(patch:Record<string,unknown>={})=>parseTrendFilter(patch);
function category(patch:Partial<TrendEvent>={}){
 return classifyTrendEvent(event(patch)).category;
}
describe("trend input boundary",()=>{
 it("defaults to current member and 30 days",()=>{
  expect(options()).toEqual({
   days:30,scope:"MINE",metric:"ALL",includeComments:true,includeChecklist:true,
  });
 });
 it.each([null,undefined,42,"query",false,[]])("rejects nonobject request %s",v=>{
  expect(()=>parseTrendFilter(v)).toThrow();
 });
 it("rejects arbitrary unknown properties",()=>{
  expect(()=>options({organizationId:"foreign"})).toThrow();
 });
 it.each([7,14,30,60,90])("accepts supported window %s",days=>{
  expect(options({days}).days).toBe(days);
 });
 it.each([-1,0,1,8,15,31,91,"30",null,NaN])("rejects unsupported window %s",days=>{
  expect(()=>options({days})).toThrow();
 });
 it.each(["MINE","TEAM"])("accepts scope %s",scope=>{
  expect(options({scope}).scope).toBe(scope);
 });
 it.each([null,"ALL","ADMIN",0,false,{}])("rejects scope %s",scope=>{
  expect(()=>options({scope})).toThrow();
 });
 it.each(["ALL","CREATED","COMPLETED","REOPENED","OWNERSHIP","DEADLINE","PRIORITY"])(
  "accepts metric %s",metric=>expect(options({metric}).metric).toBe(metric));
 it.each(["UNKNOWN","CHECKLIST","INVALID",null,0,{}])("rejects metric %s",metric=>{
  expect(()=>options({metric})).toThrow();
 });
 it.each(["includeComments","includeChecklist"])("accepts explicit true for %s",field=>{
  expect(options({[field]:true})[field as "includeComments"|"includeChecklist"]).toBe(true);
 });
 it.each(["includeComments","includeChecklist"])("accepts explicit false for %s",field=>{
  expect(options({[field]:false})[field as "includeComments"|"includeChecklist"]).toBe(false);
 });
 it.each(["includeComments","includeChecklist"])("rejects nonboolean %s",field=>{
  for(const value of [null,0,1,"true",{}])
   expect(()=>options({[field]:value})).toThrow();
 });
});
describe("time window boundaries",()=>{
 it("starts one-day count at UTC midnight of today",()=>{
  expect(trendStart(NOW,7).toISOString()).toBe("2026-10-26T00:00:00.000Z");
 });
 it("includes the current day within a thirty day inclusive window",()=>{
  const first=trendStart(NOW,30);
  expect(Math.round((Date.UTC(2026,10,1)-first.getTime())/DAY)+1).toBe(30);
 });
 it("does not move UTC calendar dates based on local time",()=>{
  const late=new Date("2026-11-01T23:59:59.000Z");
  const first=trendStart(late,14);
  expect(first.toISOString()).toBe("2026-10-19T00:00:00.000Z");
 });
 it("handles year transitions",()=>{
  const date=new Date("2027-01-02T14:00:00Z");
  expect(trendStart(date,7).toISOString()).toBe("2026-12-27T00:00:00.000Z");
 });
});
describe("event classification uses real recorded changes",()=>{
 it("recognizes explicitly created work",()=>{
  expect(category({kind:"CREATED"})).toBe("CREATED");
 });
 it("recognizes task completion from status snapshots",()=>{
  expect(category({before:{status:"IN_PROGRESS"},after:{status:"DONE"}}))
   .toBe("COMPLETED");
 });
 it("does not call a comment task completion",()=>{
  expect(category({kind:"COMMENTED",comment:"done"})).toBe("COMMENT");
 });
 it("recognizes a reopening from DONE",()=>{
  expect(category({before:{status:"DONE"},after:{status:"IN_PROGRESS"}}))
   .toBe("REOPENED");
 });
 it("recognizes reopening into blocked work",()=>{
  expect(category({before:{status:"DONE"},after:{status:"BLOCKED"}}))
   .toBe("REOPENED");
 });
 it("does not infer completed work from unchanged status",()=>{
  expect(category({before:{status:"DONE"},after:{status:"DONE"}}))
   .not.toBe("COMPLETED");
 });
 it("recognizes a changed assignment",()=>{
  expect(category({before:{assigneeUserId:"user_alpha"},
   after:{assigneeUserId:"user_beta"}})).toBe("OWNERSHIP");
 });
 it("recognizes an assignment to previously unassigned work",()=>{
  expect(category({before:{assigneeUserId:null},
   after:{assigneeUserId:"user_beta"}})).toBe("OWNERSHIP");
 });
 it("recognizes clearing ownership",()=>{
  expect(category({before:{assigneeUserId:"user_alpha"},
   after:{assigneeUserId:null}})).toBe("OWNERSHIP");
 });
 it("recognizes date changes",()=>{
  expect(category({before:{dueAt:"2026-11-01"},
   after:{dueAt:"2026-11-15"}})).toBe("DEADLINE");
 });
 it("recognizes clearing a due date",()=>{
  expect(category({before:{dueAt:"2026-11-01"},after:{dueAt:null}}))
   .toBe("DEADLINE");
 });
 it("recognizes priority changes",()=>{
  expect(category({before:{priority:"LOW"},after:{priority:"URGENT"}}))
   .toBe("PRIORITY");
 });
 it("does not invent changes when snapshots are missing",()=>{
  expect(category({before:null,after:null,kind:"OTHER"})).toBe("UNKNOWN");
 });
 it("recognizes an ordinary recorded update",()=>{
  expect(category({kind:"UPDATED",before:{title:"old"},after:{title:"new"}}))
   .toBe("OTHER");
 });
 it("classifies explicitly checklist-labelled events",()=>{
  expect(category({kind:"UPDATED",comment:"Updated checklist entry"}))
   .toBe("CHECKLIST");
 });
 it("classifies a comment without before/after as explicit",()=>{
  const classified=classifyTrendEvent(event({kind:"COMMENTED"}));
  expect(classified.confidence).toBe("EXPLICIT");
 });
 it("classifies snapshot transitions as snapshot-derived",()=>{
  const classified=classifyTrendEvent(event({
   before:{priority:"LOW"},after:{priority:"HIGH"},
  }));
  expect(classified.confidence).toBe("SNAPSHOT");
  expect(classified.from).toBe("LOW");
  expect(classified.to).toBe("HIGH");
 });
 it("never labels unknown snapshots verified",()=>{
  const classified=classifyTrendEvent(event({kind:"UNSUPPORTED"}));
  expect(classified.confidence).toBe("UNKNOWN");
 });
 it("does not mutate historical snapshots",()=>{
  const source=event({before:{priority:"LOW"},after:{priority:"HIGH"}});
  const before=JSON.stringify(source);
  classifyTrendEvent(source);
  expect(JSON.stringify(source)).toBe(before);
 });
 it("preserves actor attribution when provided",()=>{
  expect(classifyTrendEvent(event()).actorUserId).toBe("user_alpha");
 });
 it("handles missing actor without fabricating identity",()=>{
  expect(classifyTrendEvent(event({actorUserId:null})).actorUserId).toBeNull();
 });
 it("retains original event and work identifiers",()=>{
  expect(classifyTrendEvent(event())).toMatchObject({
   id:"event_alpha",workItemId:"work_alpha",
  });
 });
 it("does not classify non-status changes as completion",()=>{
  expect(category({before:{status:"TODO",priority:"LOW"},
   after:{status:"TODO",priority:"HIGH"}})).toBe("PRIORITY");
 });
});
describe("daily activity aggregation",()=>{
 const events=[
  event({id:"created",kind:"CREATED",occurredAt:date(-5)}),
  event({id:"done",occurredAt:date(-4),
   before:{status:"TODO"},after:{status:"DONE"}}),
  event({id:"reopened",occurredAt:date(-3),
   before:{status:"DONE"},after:{status:"TODO"}}),
  event({id:"priority",occurredAt:date(-3),
   before:{priority:"LOW"},after:{priority:"HIGH"}}),
  event({id:"comment",kind:"COMMENTED",occurredAt:date(-2)}),
  event({id:"unknown",kind:"OTHER",occurredAt:date(-1)}),
 ];
 it("generates exactly one row for each selected calendar day",()=>{
  expect(buildWorkTrends(events,[work()],options({days:7}),NOW).days).toHaveLength(7);
 });
 it("includes empty days rather than hiding inactivity",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.days.find(day=>day.date==="2026-11-01")?.total).toBe(0);
 });
 it("counts creation and completion independently",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.summary.created).toBe(1);
  expect(result.summary.completed).toBe(1);
 });
 it("counts reopened work separately from completed work",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.summary.reopened).toBe(1);
 });
 it("counts priority changes in category total",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.summary.priority).toBe(1);
 });
 it("reports unknown event kinds explicitly",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.summary.unknown).toBe(1);
 });
 it("counts exactly six matching events",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.summary.totalEvents).toBe(6);
 });
 it("keeps sum of daily counts equal to summary",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.days.reduce((sum,day)=>sum+day.total,0))
   .toBe(result.summary.totalEvents);
 });
 it("filters to one event type",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7,metric:"COMPLETED"}),NOW);
  expect(result.events).toHaveLength(1);
  expect(result.summary.completed).toBe(1);
 });
 it("can exclude comment events",()=>{
  const result=buildWorkTrends(events,[work()],options({
   days:7,includeComments:false,
  }),NOW);
  expect(result.summary.comments).toBe(0);
  expect(result.summary.totalEvents).toBe(5);
 });
 it("orders events newest first",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.events[0]?.id).toBe("unknown");
 });
 it("does not alter source order",()=>{
  const before=events.map(item=>item.id);
  buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(events.map(item=>item.id)).toEqual(before);
 });
 it("ignores events outside selected window",()=>{
  const result=buildWorkTrends([
   ...events,event({id:"older",occurredAt:date(-40)}),
  ],[work()],options({days:7}),NOW);
  expect(result.events).toHaveLength(6);
 });
 it("does not include future-dated records",()=>{
  const result=buildWorkTrends([
   ...events,event({id:"future",occurredAt:date(1)}),
  ],[work()],options({days:7}),NOW);
  expect(result.events).toHaveLength(6);
 });
 it("preserves the report timestamp",()=>{
  const result=buildWorkTrends(events,[work()],options({days:7}),NOW);
  expect(result.generatedAt).toBe(NOW.toISOString());
 });
 it("counts distinct affected work IDs",()=>{
  const result=buildWorkTrends([
   event({id:"first",workItemId:"work_a"}),
   event({id:"second",workItemId:"work_b"}),
  ],[work()],options(),NOW);
  expect(result.summary.affectedWork).toBe(2);
 });
 it("counts distinct known actors only",()=>{
  const result=buildWorkTrends([
   event({id:"first",actorUserId:"user_alpha"}),
   event({id:"second",actorUserId:null}),
   event({id:"third",actorUserId:"user_beta"}),
  ],[work()],options(),NOW);
  expect(result.summary.actors).toBe(2);
 });
 it("counts current assigned and unassigned work separately",()=>{
  const result=buildWorkTrends([],[
   work({id:"work_assigned"}),
   work({id:"work_unassigned",assigneeUserId:null}),
  ],options(),NOW);
  expect(result.summary.openNow).toBe(2);
  expect(result.summary.unassignedNow).toBe(1);
 });
 it("does not include cancelled tasks in active count",()=>{
  const result=buildWorkTrends([],[
   work({id:"cancelled",status:"CANCELLED"}),
   work({id:"completed",status:"DONE"}),
  ],options(),NOW);
  expect(result.summary.openNow).toBe(0);
  expect(result.summary.doneNow).toBe(1);
 });
 it("reports complete bounded coverage",()=>{
  const result=buildWorkTrends(events,[work()],options(),NOW);
  expect(result.coverage).toMatchObject({
   complete:true,workLimit:2000,eventLimit:4000,
  });
 });
 it("explicitly warns that history is not independent security verification",()=>{
  const result=buildWorkTrends([],[],options(),NOW);
  expect(result.disclaimer).toMatch(/not scanner execution/);
 });
 it("supports an empty organization work list",()=>{
  const result=buildWorkTrends([],[],options(),NOW);
  expect(result.summary.totalEvents).toBe(0);
  expect(result.days).toHaveLength(30);
 });
 it("does not equate the event count to verified remediations",()=>{
  const result=buildWorkTrends(events,[work({status:"DONE"})],options(),NOW);
  expect(result.summary.doneNow).toBe(1);
  expect(result.disclaimer).toMatch(/verified remediation/);
 });
});
