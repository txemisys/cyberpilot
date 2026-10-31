import {describe,it,expect} from "vitest";
import {
 parseScheduleDate,parseScheduleInput,schedulePeriod,scheduleWhere,
 classifyScheduleTask,orderSchedule,summarizeSchedule,buildSchedule,scheduleCalendar,
 type ScheduleTask,type ScheduleInput,
} from "./remediation-work-schedule";
import type {WorkContext} from "./remediation-work-store";

const NOW=new Date("2026-10-31T12:00:00.000Z");
const context:WorkContext={
 organizationId:"organization_alpha",userId:"user_alpha",role:"ADMIN",
};
const day=(date:string)=>new Date(date+"T12:00:00.000Z");
const defaults=():ScheduleInput=>parseScheduleInput({},NOW);
function task(overrides:Partial<ScheduleTask>={}):ScheduleTask{
 return {
  id:"work_alpha",title:"Rotate credentials",description:"Follow approved runbook",
  revision:3,status:"TODO",priority:"NORMAL",
  assigneeUserId:"user_alpha",assigneeName:"Alice",
  dueAt:day("2026-11-03"),createdAt:day("2026-10-01"),updatedAt:NOW,
  findingTitle:"Credential lifecycle",findingSeverity:"HIGH",
  findingStatus:"OPEN",remediationTitle:"Credential rotation",
  remediationStatus:"PROPOSED",...overrides,
 };
}
function input(overrides:Record<string,unknown>={}):ScheduleInput{
 return parseScheduleInput(overrides,NOW);
}
function entry(overrides:Partial<ScheduleTask>={}){
 return classifyScheduleTask(task(overrides),"2026-10-31","2026-11-30");
}
function fails(raw:unknown){
 expect(()=>parseScheduleInput(raw,NOW)).toThrow();
}
describe("date validation and normalization",()=>{
 it.each(["2026-02-29","2026-04-31","2026-13-01","2026-00-01",
  "2026-1-1","2026/10/31","31-10-2026","bad","1999-12-31","2101-01-01"])(
  "rejects invalid date %s",value=>{
   expect(()=>parseScheduleDate(value)).toThrow();
  });
 it("accepts a valid leap day",()=>{
  expect(parseScheduleDate("2028-02-29")).toBe("2028-02-29");
 });
 it("does not shift a date based on local timezone",()=>{
  expect(parseScheduleDate("2026-10-31")).toBe("2026-10-31");
 });
 it.each([null,undefined,3,{},[],false])("rejects non-text dates",value=>{
  expect(()=>parseScheduleDate(value)).toThrow();
 });
 it("uses the supplied clock only when the date is omitted",()=>{
  expect(defaults().referenceDate).toBe("2026-10-31");
 });
});
describe("schedule request input",()=>{
 it("defaults to my current month",()=>{
  expect(defaults()).toEqual({
   range:"MONTH",scope:"MINE",referenceDate:"2026-10-31",
   includeClosed:false,priority:"ALL",search:"",assigneeUserId:null,
  });
 });
 it.each([null,undefined,42,[],false,"abc"])("rejects bad body %s",fails);
 it.each(["WEEK","MONTH","QUARTER"])("accepts range %s",range=>{
  expect(input({range}).range).toBe(range);
 });
 it.each(["MINE","TEAM","UNASSIGNED"])("accepts ownership scope %s",scope=>{
  expect(input({scope}).scope).toBe(scope);
 });
 it.each(["LOW","NORMAL","HIGH","URGENT","ALL"])("accepts priority %s",priority=>{
  expect(input({priority}).priority).toBe(priority);
 });
 it.each([null,"YEAR","monthly",0,true,{}])("rejects invalid range %s",range=>{
  fails({range});
 });
 it.each([null,"OTHER","ALL",0,true,{}])("rejects invalid scope %s",scope=>{
  fails({scope});
 });
 it.each([null,"CRITICAL","invalid",0,true,{}])("rejects invalid priority %s",priority=>{
  fails({priority});
 });
 it.each([null,"false",1,0,{}])("rejects invalid closed toggle %s",includeClosed=>{
  fails({includeClosed});
 });
 it("accepts explicit includeClosed true",()=>{
  expect(input({includeClosed:true}).includeClosed).toBe(true);
 });
 it("rejects unknown fields",()=>fails({organizationId:"another_tenant"}));
 it("bounds search inputs",()=>{
  fails({search:"x".repeat(121)});
  fails({search:42});
  fails({search:"newline\nforbidden"});
 });
 it("trims harmless search whitespace",()=>{
  expect(input({search:"  critical  "}).search).toBe("critical");
 });
 it("rejects malformed assignee references",()=>{
  fails({assigneeUserId:"/"});
  fails({assigneeUserId:42});
  fails({assigneeUserId:""});
 });
 it("accepts a properly formatted assignee identifier",()=>{
  expect(input({assigneeUserId:"user_alpha"}).assigneeUserId).toBe("user_alpha");
 });
 it("accepts explicit empty assignee filter",()=>{
  expect(input({assigneeUserId:null}).assigneeUserId).toBeNull();
 });
});
describe("calendar period boundaries",()=>{
 it("starts weeks on Monday",()=>{
  const period=schedulePeriod(input({range:"WEEK",referenceDate:"2026-10-31"}));
  expect(period.from).toBe("2026-10-26");
  expect(period.to).toBe("2026-11-01");
  expect(period.days).toBe(7);
 });
 it("handles a Monday without shifting",()=>{
  expect(schedulePeriod(input({
   range:"WEEK",referenceDate:"2026-11-02",
  })).from).toBe("2026-11-02");
 });
 it("handles Sunday at the end of week",()=>{
  expect(schedulePeriod(input({
   range:"WEEK",referenceDate:"2026-11-01",
  })).to).toBe("2026-11-01");
 });
 it("handles a 31-day month",()=>{
  const period=schedulePeriod(input({referenceDate:"2026-10-31"}));
  expect(period).toMatchObject({from:"2026-10-01",to:"2026-10-31",days:31});
 });
 it("handles February in a leap year",()=>{
  expect(schedulePeriod(input({referenceDate:"2028-02-29"})).days).toBe(29);
 });
 it("handles February in a non-leap year",()=>{
  expect(schedulePeriod(input({referenceDate:"2027-02-01"})).days).toBe(28);
 });
 it("handles a 30-day month",()=>{
  expect(schedulePeriod(input({referenceDate:"2026-04-01"})).days).toBe(30);
 });
 it("starts quarters on calendar quarter boundaries",()=>{
  expect(schedulePeriod(input({
   range:"QUARTER",referenceDate:"2026-05-07",
  }))).toMatchObject({from:"2026-04-01",to:"2026-06-30",days:91});
 });
 it("handles a quarter crossing a year boundary",()=>{
  expect(schedulePeriod(input({
   range:"QUARTER",referenceDate:"2026-12-31",
  }))).toMatchObject({from:"2026-10-01",to:"2026-12-31",days:92});
 });
});
describe("tenant scoped scheduling query",()=>{
 it("always includes the organization key",()=>{
  expect(scheduleWhere(context,defaults()).organizationId).toBe("organization_alpha");
 });
 it("restricts personal schedule to current user",()=>{
  expect(scheduleWhere(context,defaults()).assigneeUserId).toBe("user_alpha");
 });
 it("restricts unassigned schedule to null",()=>{
  expect(scheduleWhere(context,input({scope:"UNASSIGNED"})).assigneeUserId).toBeNull();
 });
 it("does not remove tenant boundary on team schedule",()=>{
  const where=scheduleWhere(context,input({scope:"TEAM"}));
  expect(where.organizationId).toBe("organization_alpha");
  expect(where.assigneeUserId).toBeUndefined();
 });
 it("rejects foreign assignee filtering of personal scope",()=>{
  expect(()=>scheduleWhere(context,input({
   assigneeUserId:"user_other",
  }))).toThrow();
 });
 it("rejects contradictory unassigned member selection",()=>{
  expect(()=>scheduleWhere(context,input({
   scope:"UNASSIGNED",assigneeUserId:"user_alpha",
  }))).toThrow();
 });
 it("permits filtering own personal schedule",()=>{
  expect(scheduleWhere(context,input({
   assigneeUserId:"user_alpha",
  })).assigneeUserId).toBe("user_alpha");
 });
 it("excludes completed and cancelled work by default",()=>{
  expect(scheduleWhere(context,defaults()).status).toEqual({notIn:["DONE","CANCELLED"]});
 });
 it("can include closed tasks explicitly",()=>{
  expect(scheduleWhere(context,input({includeClosed:true})).status).toBeUndefined();
 });
 it("applies priority and case-insensitive text filtering",()=>{
  const where=scheduleWhere(context,input({priority:"URGENT",search:"access"}));
  expect(where.priority).toBe("URGENT");
  expect(where.OR).toHaveLength(4);
 });
});
describe("classification of persisted task deadlines",()=>{
 it("classifies a past due active task as overdue",()=>{
  expect(entry({dueAt:day("2026-10-20")}).bucket).toBe("OVERDUE");
 });
 it("uses positive lateBy days",()=>{
  expect(entry({dueAt:day("2026-10-20")}).lateBy).toBe(11);
 });
 it("classifies the reference date as today",()=>{
  expect(entry({dueAt:day("2026-10-31")}).bucket).toBe("TODAY");
 });
 it("classifies seven days ahead as due soon",()=>{
  expect(entry({dueAt:day("2026-11-07")}).bucket).toBe("NEXT_7_DAYS");
 });
 it("classifies eight days ahead as later",()=>{
  expect(entry({dueAt:day("2026-11-08")}).bucket).toBe("LATER");
 });
 it("does not invent a deadline for undated work",()=>{
  expect(entry({dueAt:null})).toMatchObject({
   bucket:"UNSCHEDULED",dueDate:null,daysUntil:null,
  });
 });
 it("distinguishes task closure from finding status",()=>{
  expect(entry({status:"DONE"})).toMatchObject({
   bucket:"CLOSED",isActive:false,
  });
 });
 it("treats cancelled work as closed operational work",()=>{
  expect(entry({status:"CANCELLED"}).bucket).toBe("CLOSED");
 });
 it("keeps blocked tasks active",()=>{
  expect(entry({status:"BLOCKED"}).isActive).toBe(true);
 });
 it("keeps completed tasks closed even when overdue",()=>{
  expect(entry({status:"DONE",dueAt:day("2025-01-01")}).bucket).toBe("CLOSED");
 });
 it("identifies unassigned work without false owner",()=>{
  expect(entry({assigneeUserId:null,assigneeName:null}).needsOwner).toBe(true);
 });
 it("preserves revision for future audited rescheduling",()=>{
  expect(entry({revision:99}).revision).toBe(99);
 });
 it("preserves actual task and remediation status",()=>{
  expect(entry({status:"IN_PROGRESS",remediationStatus:"FAILED"})).toMatchObject({
   status:"IN_PROGRESS",remediationStatus:"FAILED",
  });
 });
});
describe("schedule summaries and calendar grouping",()=>{
 const tasks=[
  task({id:"work_overdue",dueAt:day("2026-10-20")}),
  task({id:"work_today",dueAt:day("2026-10-31"),priority:"URGENT"}),
  task({id:"work_soon",dueAt:day("2026-11-02"),status:"BLOCKED"}),
  task({id:"work_later",dueAt:day("2026-12-15")}),
  task({id:"work_none",dueAt:null,assigneeUserId:null}),
  task({id:"work_done",status:"DONE"}),
 ];
 it("builds calendar days for every day of month",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.days).toHaveLength(31);
  expect(result.days[0]?.date).toBe("2026-10-01");
 });
 it("does not omit undated tasks from overall coverage",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.allEntries).toHaveLength(6);
  expect(result.unscheduled).toHaveLength(1);
 });
 it("counts closed tasks separately from active work",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.summary.active).toBe(5);
  expect(result.summary.closed).toBe(1);
 });
 it("counts overdue and today separately",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.summary.overdue).toBe(1);
  expect(result.summary.today).toBe(1);
 });
 it("counts blocked work without equating it to completed work",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.summary.blocked).toBe(1);
 });
 it("counts urgent active work",()=>{
  expect(buildSchedule(tasks,defaults(),NOW).summary.urgent).toBe(1);
 });
 it("shows deadlines for the visible calendar period",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.days.find(day=>day.date==="2026-10-31")?.items.map(row=>row.id))
   .toContain("work_today");
 });
 it("does not add a date-less task to an arbitrary day",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.days.every(day=>day.items.every(item=>item.dueDate!==null))).toBe(true);
 });
 it("distinguishes future dates beyond visible period",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.later.some(item=>item.id==="work_later")).toBe(true);
 });
 it("reports full coverage for the supplied bounded snapshot",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.coverage).toMatchObject({complete:true,fetched:6,limit:2000});
 });
 it("emits a stable ordering by deadline",()=>{
  const result=buildSchedule(tasks,defaults(),NOW);
  expect(result.allEntries[0]?.id).toBe("work_overdue");
 });
 it("does not mutate source tasks",()=>{
  const before=[...tasks];
  buildSchedule(tasks,defaults(),NOW);
  expect(tasks).toEqual(before);
 });
 it("returns empty date buckets for empty data",()=>{
  const result=buildSchedule([],defaults(),NOW);
  expect(result.summary.total).toBe(0);
  expect(result.days).toHaveLength(31);
 });
 it("prevents schedule totals from implying verification",()=>{
  expect(buildSchedule(tasks,defaults(),NOW).disclaimer).toMatch(/not verification/);
 });
 it("sorts equal target dates deterministically",()=>{
  const rows=orderSchedule([
   entry({id:"work_z",title:"Zulu",dueAt:day("2026-11-01")}),
   entry({id:"work_a",title:"Alpha",dueAt:day("2026-11-01")}),
  ]);
  expect(rows.map(row=>row.id)).toEqual(["work_a","work_z"]);
 });
 it("does not count closed rows as urgent or blocked",()=>{
  const rows=[
   entry({status:"DONE",priority:"URGENT"}),
   entry({status:"CANCELLED",priority:"URGENT"}),
  ];
  expect(summarizeSchedule(rows).urgent).toBe(0);
 });
 it("preserves summary conservation",()=>{
  const summary=buildSchedule(tasks,defaults(),NOW).summary;
  expect(summary.active+summary.closed).toBe(summary.total);
  expect(summary.overdue+summary.today+summary.dueSoon+
   summary.later+summary.unscheduled).toBe(summary.active);
 });
});
describe("iCalendar export",()=>{
 it("creates a standards-shaped calendar",()=>{
  const ics=scheduleCalendar(buildSchedule([task()],defaults(),NOW),"organization");
  expect(ics).toContain("BEGIN:VCALENDAR\r\n");
  expect(ics).toContain("VERSION:2.0");
  expect(ics).toContain("BEGIN:VEVENT");
  expect(ics).toContain("END:VCALENDAR\r\n");
 });
 it("exports an all-day target date with exclusive following day",()=>{
  const ics=scheduleCalendar(buildSchedule([task()],defaults(),NOW),"organization");
  expect(ics).toContain("DTSTART;VALUE=DATE:20261103");
  expect(ics).toContain("DTEND;VALUE=DATE:20261104");
 });
 it("does not fabricate a date for undated work",()=>{
  const ics=scheduleCalendar(buildSchedule([task({dueAt:null})],defaults(),NOW),"organization");
  expect(ics).not.toContain("BEGIN:VEVENT");
 });
 it("escapes calendar special characters",()=>{
  const ics=scheduleCalendar(buildSchedule([
   task({title:"Review, access; tokens\\accounts"}),
  ],defaults(),NOW),"organization");
  expect(ics).toContain("Review\\, access\\; tokens\\\\accounts");
 });
 it("uses a stable UID for each task",()=>{
  const ics=scheduleCalendar(buildSchedule([task()],defaults(),NOW),"organization");
  expect(ics).toContain("UID:work_alpha@organization.cyberpilot.local");
 });
 it("contains a clear caution that work is not verification",()=>{
  const ics=scheduleCalendar(buildSchedule([task()],defaults(),NOW),"organization");
  expect(ics).toContain("not security verification");
 });
 it("does not include assignee email or evidence payload",()=>{
  const ics=scheduleCalendar(buildSchedule([task()],defaults(),NOW),"organization");
  expect(ics).not.toContain("alice@example");
 });
 it("uses CRLF line endings",()=>{
  const ics=scheduleCalendar(buildSchedule([],defaults(),NOW),"organization");
  expect(ics).toContain("\r\n");
  expect(ics.endsWith("\r\n")).toBe(true);
 });
 it("supports multiple persisted tasks",()=>{
  const ics=scheduleCalendar(buildSchedule([
   task({id:"work_a"}),task({id:"work_b"}),
  ],defaults(),NOW),"organization");
  expect(ics.match(/BEGIN:VEVENT/g)).toHaveLength(2);
 });
 it("works with no events",()=>{
  const ics=scheduleCalendar(buildSchedule([],defaults(),NOW),"organization");
  expect(ics).toContain("BEGIN:VCALENDAR");
  expect(ics).not.toContain("BEGIN:VEVENT");
 });
});
