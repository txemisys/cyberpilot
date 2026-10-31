import {describe,expect,it} from "vitest";
import {
 parseEscalationConfig,escalationWhere,classifyEscalation,orderEscalations,
 summarizeEscalations,buildEscalationReview,type EscalationWork,
} from "./remediation-work-escalations";
import type {WorkContext} from "./remediation-work-store";
const NOW=new Date("2026-11-01T12:00:00.000Z");
const DAY=86400000;
const date=(offset:number)=>new Date(NOW.getTime()+offset*DAY);
const context:WorkContext={
 organizationId:"organization_alpha",userId:"user_alpha",role:"ADMIN",
};
function work(patch:Partial<EscalationWork>={}):EscalationWork{
 return {
  id:"work_alpha",title:"Review shared access",description:"Coordinate follow-up",
  revision:2,status:"TODO",priority:"NORMAL",assigneeUserId:"user_alpha",
  assigneeName:"Alice",dueAt:null,createdAt:date(-20),updatedAt:date(-1),
  findingId:"finding_alpha",findingTitle:"Access review",findingSeverity:"MEDIUM",
  findingStatus:"OPEN",remediationId:"remediation_alpha",
  remediationTitle:"Review access",remediationStatus:"PROPOSED",
  pendingHandoffs:0,...patch,
 };
}
const config=(override:Record<string,unknown>={})=>parseEscalationConfig(override);
const decide=(patch:Partial<EscalationWork>={},override:Record<string,unknown>={})=>
 classifyEscalation(work(patch),config(override),NOW);
const reject=(raw:unknown)=>expect(()=>parseEscalationConfig(raw)).toThrow();
describe("escalation configuration parsing",()=>{
 it("defaults to assigned work with 14-day due threshold",()=>{
  expect(config()).toEqual({
   scope:"MINE",order:"SEVERITY",includeClosed:false,
   thresholdDays:14,staleDays:30,minLevel:"WATCH",search:"",
  });
 });
 it.each([null,undefined,42,[],false,"abc"])("rejects non-object input %s",reject);
 it("rejects unexpected properties",()=>reject({organizationId:"foreign"}));
 it.each(["MINE","TEAM","UNASSIGNED"])("accepts scope %s",scope=>{
  expect(config({scope}).scope).toBe(scope);
 });
 it.each(["SEVERITY","DEADLINE","AGE","LAST_UPDATE"])("accepts order %s",order=>{
  expect(config({order}).order).toBe(order);
 });
 it.each(["NONE","WATCH","ELEVATED","CRITICAL"])("accepts threshold %s",minLevel=>{
  expect(config({minLevel}).minLevel).toBe(minLevel);
 });
 it.each(["OTHER",null,1,{},false])("rejects scope %s",scope=>reject({scope}));
 it.each(["OTHER",null,1,{},false])("rejects order %s",order=>reject({order}));
 it.each(["OTHER",null,1,{},false])("rejects level %s",minLevel=>reject({minLevel}));
 it.each([7,14,30,60])("accepts deadline window %s",thresholdDays=>{
  expect(config({thresholdDays}).thresholdDays).toBe(thresholdDays);
 });
 it.each([7,14,30,60,90])("accepts inactivity window %s",staleDays=>{
  expect(config({staleDays}).staleDays).toBe(staleDays);
 });
 it.each([-1,0,1,8,15,365,"14",null])("rejects due threshold %s",thresholdDays=>{
  reject({thresholdDays});
 });
 it.each([-1,0,1,8,15,365,"30",null])("rejects idle threshold %s",staleDays=>{
  reject({staleDays});
 });
 it.each([null,0,1,"true",{},[]])("rejects nonboolean closed filter %s",includeClosed=>{
  reject({includeClosed});
 });
 it("accepts explicit inclusion of closed work",()=>{
  expect(config({includeClosed:true}).includeClosed).toBe(true);
 });
 it("trims a search string",()=>{
  expect(config({search:"  access  "}).search).toBe("access");
 });
 it("rejects overly long search",()=>reject({search:"a".repeat(121)}));
 it("rejects control characters in search",()=>reject({search:"bad\nsearch"}));
 it("rejects non-text search",()=>reject({search:123}));
});
describe("tenant query isolation",()=>{
 it("scopes all work by organization",()=>{
  expect(escalationWhere(context,config()).organizationId).toBe("organization_alpha");
 });
 it("limits personal view to authenticated user",()=>{
  expect(escalationWhere(context,config()).assigneeUserId).toBe("user_alpha");
 });
 it("limits unassigned view to null owner",()=>{
  expect(escalationWhere(context,config({scope:"UNASSIGNED"})).assigneeUserId).toBeNull();
 });
 it("keeps tenant isolation for team view",()=>{
  const where=escalationWhere(context,config({scope:"TEAM"}));
  expect(where.organizationId).toBe("organization_alpha");
  expect(where.assigneeUserId).toBeUndefined();
 });
 it("excludes closed work by default",()=>{
  expect(escalationWhere(context,config()).status).toEqual({
   notIn:["DONE","CANCELLED"],
  });
 });
 it("includes closed work when requested",()=>{
  expect(escalationWhere(context,config({includeClosed:true})).status).toBeUndefined();
 });
 it("applies case-insensitive matching for related findings",()=>{
  const where=escalationWhere(context,config({search:"access"}));
  expect(where.OR).toHaveLength(4);
  expect(where.organizationId).toBe("organization_alpha");
 });
});
describe("operational attention classification",()=>{
 it("does not invent a signal for ordinary active work",()=>{
  expect(decide()).toMatchObject({level:"NONE",score:0,reasons:[]});
 });
 it("identifies overdue work",()=>{
  const result=decide({dueAt:date(-4)});
  expect(result.reasons).toContain("OVERDUE");
  expect(result.overdueDays).toBe(4);
 });
 it("does not infer a target date when absent",()=>{
  expect(decide().dueAt).toBeNull();
  expect(decide().daysUntilDue).toBeNull();
 });
 it("records days until a future deadline",()=>{
  const result=decide({dueAt:date(4)});
  expect(result.daysUntilDue).toBe(4);
 });
 it("flags deadlines within configured threshold",()=>{
  expect(decide({dueAt:date(14)}).reasons).toContain("DUE_SOON");
  expect(decide({dueAt:date(15)}).reasons).not.toContain("DUE_SOON");
 });
 it("honors a shorter due window",()=>{
  expect(decide({dueAt:date(8)},{thresholdDays:7}).reasons).not.toContain("DUE_SOON");
 });
 it("flags blocked tasks independently of urgency",()=>{
  const result=decide({status:"BLOCKED"});
  expect(result.reasons).toContain("BLOCKED");
  expect(result.nextAction).toMatch(/blocking dependency/);
 });
 it("flags urgent priority",()=>{
  expect(decide({priority:"URGENT"}).reasons).toContain("URGENT");
 });
 it("flags missing assignment",()=>{
  const result=decide({assigneeUserId:null,assigneeName:null});
  expect(result.reasons).toContain("UNASSIGNED");
  expect(result.nextAction).toMatch(/Assign/);
 });
 it("flags stale work using recorded updatedAt",()=>{
  const result=decide({updatedAt:date(-31)});
  expect(result.reasons).toContain("STALE");
  expect(result.idleDays).toBe(31);
 });
 it("does not mark fresh work stale",()=>{
  expect(decide({updatedAt:date(-2)}).reasons).not.toContain("STALE");
 });
 it("ignores future timestamps instead of creating negative inactivity",()=>{
  expect(decide({updatedAt:date(2)}).idleDays).toBe(0);
 });
 it("honors chosen inactivity window",()=>{
  expect(decide({updatedAt:date(-8)},{staleDays:7}).reasons).toContain("STALE");
 });
 it("flags pending handoffs",()=>{
  const result=decide({pendingHandoffs:2});
  expect(result.reasons).toContain("HANDOFF");
  expect(result.nextAction).toMatch(/handoff/);
 });
 it("keeps completed human work separate from findings",()=>{
  const result=decide({status:"DONE",priority:"URGENT",dueAt:date(-20)});
  expect(result).toMatchObject({level:"NONE",score:0,reasons:[],findingStatus:"OPEN"});
 });
 it("does not escalate cancelled work",()=>{
  expect(decide({status:"CANCELLED",pendingHandoffs:3}).level).toBe("NONE");
 });
 it("does not equate a verified remediation to closed work",()=>{
  const result=decide({remediationStatus:"VERIFIED",status:"BLOCKED"});
  expect(result.reasons).toContain("BLOCKED");
 });
 it("preserves revision for optimistic concurrency",()=>{
  expect(decide({revision:14}).revision).toBe(14);
 });
 it("preserves reference to underlying finding",()=>{
  expect(decide().findingId).toBe("finding_alpha");
 });
 it("preserves reference to underlying remediation",()=>{
  expect(decide().remediationId).toBe("remediation_alpha");
 });
 it("uses a meaningful action for delayed targets",()=>{
  expect(decide({dueAt:date(-1)}).nextAction).toMatch(/revised target date/);
 });
 it("uses a meaningful action for near deadlines",()=>{
  expect(decide({dueAt:date(5)}).nextAction).toMatch(/planned work/);
 });
 it("uses a meaningful action for old updates",()=>{
  expect(decide({updatedAt:date(-35)}).nextAction).toMatch(/progress update/);
 });
 it("prioritizes blocked dependencies over missed dates in the explanation",()=>{
  expect(decide({status:"BLOCKED",dueAt:date(-1)}).nextAction)
   .toMatch(/blocking dependency/);
 });
 it("exposes multiple reasons without discarding the source",()=>{
  const result=decide({
   status:"BLOCKED",priority:"URGENT",assigneeUserId:null,
   updatedAt:date(-40),dueAt:date(-5),pendingHandoffs:1,
  });
  expect(result.reasons).toEqual([
   "OVERDUE","BLOCKED","UNASSIGNED","URGENT","STALE","HANDOFF",
  ]);
  expect(result.level).toBe("CRITICAL");
 });
 it("does not modify the supplied record",()=>{
  const source=work({dueAt:date(-10)});
  const before={...source};
  classifyEscalation(source,config(),NOW);
  expect(source).toEqual(before);
 });
});
describe("attention ordering and reporting",()=>{
 const sample=[
  decide({id:"work_one",priority:"LOW",dueAt:date(20)}),
  decide({id:"work_two",priority:"URGENT",dueAt:date(-4)}),
  decide({id:"work_three",status:"BLOCKED",updatedAt:date(-80)}),
  decide({id:"work_four",status:"DONE"}),
 ];
 it("sorts critical attention before low attention",()=>{
  expect(orderEscalations(sample,"SEVERITY")[0]?.id).toBe("work_two");
 });
 it("sorts earliest deadline first",()=>{
  expect(orderEscalations(sample,"DEADLINE")[0]?.id).toBe("work_two");
 });
 it("sorts inactivity descending",()=>{
  expect(orderEscalations(sample,"AGE")[0]?.id).toBe("work_three");
 });
 it("sorts oldest update first",()=>{
  expect(orderEscalations(sample,"LAST_UPDATE")[0]?.id).toBe("work_three");
 });
 it("does not mutate the input array",()=>{
  const before=sample.map(row=>row.id);
  orderEscalations(sample,"SEVERITY");
  expect(sample.map(row=>row.id)).toEqual(before);
 });
 it("summarizes a complete set without double counting levels",()=>{
  const result=summarizeEscalations(sample);
  expect(result.total).toBe(4);
  expect(result.critical+result.elevated+result.watch+result.none).toBe(4);
 });
 it("counts reasons independently",()=>{
  const result=summarizeEscalations(sample);
  expect(result.overdue).toBe(1);
  expect(result.blocked).toBe(1);
  expect(result.urgent).toBe(1);
  expect(result.stale).toBe(1);
 });
 it("handles an empty set",()=>{
  expect(summarizeEscalations([])).toMatchObject({total:0,critical:0,watch:0});
 });
 it("filters to elevated or worse",()=>{
  const result=buildEscalationReview([
   work(),work({id:"work_stale",status:"BLOCKED",updatedAt:date(-90)}),
  ],config({minLevel:"ELEVATED"}),NOW);
  expect(result.decisions.map(row=>row.id)).toEqual(["work_stale"]);
 });
 it("supports including low-signal work at NONE threshold",()=>{
  const result=buildEscalationReview([work()],config({minLevel:"NONE"}),NOW);
  expect(result.total).toBe(1);
 });
 it("does not mistake heuristic escalation for security assurance",()=>{
  const result=buildEscalationReview([],config(),NOW);
  expect(result.disclaimer).toMatch(/not security findings/);
 });
 it("counts the full set even when attention display is filtered",()=>{
  const result=buildEscalationReview([
   work(),work({id:"work_blocked",status:"BLOCKED"}),
  ],config({minLevel:"CRITICAL"}),NOW);
  expect(result.summary.total).toBe(2);
  expect(result.total).toBe(0);
 });
 it("reports a hard inventory bound",()=>{
  expect(buildEscalationReview([],config(),NOW).coverage.maxRecords).toBe(2000);
 });
 it("retains input configuration and the snapshot clock",()=>{
  const result=buildEscalationReview([],config(),NOW);
  expect(result.generatedAt).toBe(NOW.toISOString());
  expect(result.config.scope).toBe("MINE");
 });
});
