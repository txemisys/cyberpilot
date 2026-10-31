import {describe,it,expect} from "vitest";
import {
 parseGateFilter,gateWhere,assessGate,sortGateDecisions,
 summarizeGates,buildGateReview,type GateWork,
} from "./remediation-work-readiness";
import type {WorkContext} from "./remediation-work-store";
const NOW=new Date("2026-11-01T12:00:00.000Z");
const DAY=86400000;
const date=(days:number)=>new Date(NOW.getTime()+days*DAY);
const context:WorkContext={
 organizationId:"organization_alpha",userId:"user_alpha",role:"ADMIN",
};
function work(override:Partial<GateWork>={}):GateWork{
 return {
  id:"work_alpha",title:"Review access",revision:3,status:"IN_PROGRESS",
  priority:"NORMAL",assigneeUserId:"user_alpha",assigneeName:"Alice",
  createdAt:date(-20),updatedAt:date(-1),dueAt:date(10),completedAt:null,
  findingId:"finding_alpha",findingTitle:"Access rights",
  findingStatus:"OPEN",findingSeverity:"HIGH",
  remediationId:"remediation_alpha",remediationTitle:"Review access",
  remediationStatus:"PROPOSED",
  checklist:[{id:"check_001",title:"Review access",completedAt:date(-1)}],
  evidenceLinks:[{id:"link_001",evidenceId:"evidence_alpha",unlinkedAt:null}],
  handoffs:[],...override,
 };
}
const filter=(raw:Record<string,unknown>={})=>parseGateFilter(raw);
const assess=(override:Partial<GateWork>={},settings:Record<string,unknown>={})=>
 assessGate(work(override),filter(settings),NOW);
const invalid=(raw:unknown)=>expect(()=>parseGateFilter(raw)).toThrow();
describe("readiness filter validation",()=>{
 it("defaults to personal open work with supporting records required",()=>{
  expect(filter()).toEqual({
   scope:"MINE",includeClosed:false,requireEvidence:true,
   requireChecklist:true,onlyExceptions:false,search:"",
  });
 });
 it.each([null,undefined,1,false,[],"object"])("rejects non-object %s",invalid);
 it("rejects unknown fields",()=>invalid({organizationId:"foreign"}));
 it.each(["MINE","TEAM","UNASSIGNED"])("accepts scope %s",scope=>{
  expect(filter({scope}).scope).toBe(scope);
 });
 it.each([null,"ALL","OTHER",12,false,{}])("rejects invalid scope %s",scope=>{
  invalid({scope});
 });
 it.each(["includeClosed","requireEvidence","requireChecklist","onlyExceptions"])(
  "accepts explicit false for %s",name=>{
   expect(filter({[name]:false})[name as keyof ReturnType<typeof filter>]).toBe(false);
  },
 );
 it.each(["includeClosed","requireEvidence","requireChecklist","onlyExceptions"])(
  "accepts explicit true for %s",name=>{
   expect(filter({[name]:true})[name as keyof ReturnType<typeof filter>]).toBe(true);
  },
 );
 it.each(["includeClosed","requireEvidence","requireChecklist","onlyExceptions"])(
  "rejects explicit null for %s",name=>invalid({[name]:null}),
 );
 it.each(["includeClosed","requireEvidence","requireChecklist","onlyExceptions"])(
  "rejects string booleans for %s",name=>invalid({[name]:"true"}),
 );
 it("trims search whitespace",()=>{
  expect(filter({search:"  access  "}).search).toBe("access");
 });
 it("rejects excessive search length",()=>invalid({search:"x".repeat(121)}));
 it("rejects control characters",()=>invalid({search:"line\nbreak"}));
 it("rejects non-text search",()=>invalid({search:123}));
});
describe("organization query scoping",()=>{
 it("always limits data to current organization",()=>{
  expect(gateWhere(context,filter()).organizationId).toBe("organization_alpha");
 });
 it("limits personal review to authenticated member",()=>{
  expect(gateWhere(context,filter()).assigneeUserId).toBe("user_alpha");
 });
 it("limits unassigned review to null owner",()=>{
  expect(gateWhere(context,filter({scope:"UNASSIGNED"})).assigneeUserId).toBeNull();
 });
 it("permits manager team view without dropping organization scope",()=>{
  const where=gateWhere(context,filter({scope:"TEAM"}));
  expect(where.organizationId).toBe("organization_alpha");
  expect(where.assigneeUserId).toBeUndefined();
 });
 it("excludes closed tasks by default",()=>{
  expect(gateWhere(context,filter()).status).toEqual({notIn:["DONE","CANCELLED"]});
 });
 it("includes closed tasks explicitly when requested",()=>{
  expect(gateWhere(context,filter({includeClosed:true})).status).toBeUndefined();
 });
 it("searches through task and related finding records",()=>{
  const where=gateWhere(context,filter({search:"access"}));
  expect(where.OR).toHaveLength(4);
  expect(where.organizationId).toBe("organization_alpha");
 });
});
describe("real supporting-record readiness",()=>{
 it("allows a fully documented active task for human operational review",()=>{
  expect(assess().level).toBe("READY_FOR_HUMAN_REVIEW");
 });
 it("does not infer security verification from an active evidence link",()=>{
  const result=assess();
  expect(result.findingStatus).toBe("OPEN");
  expect(result.issues).toContain("UNCONFIRMED_FINDING");
 });
 it("counts a completed checklist item",()=>{
  expect(assess()).toMatchObject({
   totalChecklist:1,completedChecklist:1,remainingChecklist:0,
  });
 });
 it("counts missing checklist as a supporting-record gap",()=>{
  expect(assess({checklist:[]})).toMatchObject({
   level:"REQUIRES_ATTENTION",issues:["NO_CHECKLIST","UNCONFIRMED_FINDING"],
  });
 });
 it("counts outstanding checklist items",()=>{
  const result=assess({checklist:[{
   id:"check_001",title:"Review",completedAt:null,
  }]});
  expect(result.remainingChecklist).toBe(1);
  expect(result.issues).toContain("INCOMPLETE_CHECKLIST");
 });
 it("does not count a removed evidence reference as active",()=>{
  const result=assess({evidenceLinks:[{
   id:"link_001",evidenceId:"evidence_alpha",unlinkedAt:date(-1),
  }]});
  expect(result.activeEvidenceLinks).toBe(0);
  expect(result.issues).toContain("NO_EVIDENCE");
 });
 it("does not require an evidence link when policy is disabled",()=>{
  const result=assess({evidenceLinks:[]},{requireEvidence:false});
  expect(result.issues).not.toContain("NO_EVIDENCE");
 });
 it("does not require a checklist when policy is disabled",()=>{
  const result=assess({checklist:[]},{requireChecklist:false});
  expect(result.issues).not.toContain("NO_CHECKLIST");
 });
 it("counts two active evidence links and ignores removed references",()=>{
  const result=assess({evidenceLinks:[
   {id:"link_one",evidenceId:"one",unlinkedAt:null},
   {id:"link_two",evidenceId:"two",unlinkedAt:null},
   {id:"link_three",evidenceId:"three",unlinkedAt:date(-1)},
  ]});
  expect(result.activeEvidenceLinks).toBe(2);
 });
 it("flags missing responsible member",()=>{
  const result=assess({assigneeUserId:null,assigneeName:null});
  expect(result.issues).toContain("NO_OWNER");
  expect(result.recommendation).toMatch(/Assign/);
 });
 it("flags a blocked task as not ready for review",()=>{
  const result=assess({status:"BLOCKED"});
  expect(result.level).toBe("BLOCKED");
  expect(result.issues).toContain("BLOCKED");
 });
 it("flags a pending handoff as a blocking dependency",()=>{
  const result=assess({handoffs:[{
   id:"handoff_one",status:"REQUESTED",expiresAt:date(1),
  }]});
  expect(result.level).toBe("BLOCKED");
  expect(result.pendingHandoffs).toBe(1);
 });
 it("does not count accepted handoffs as pending",()=>{
  const result=assess({handoffs:[{
   id:"handoff_one",status:"ACCEPTED",expiresAt:date(1),
  }]});
  expect(result.pendingHandoffs).toBe(0);
 });
 it("does not count cancelled handoffs as pending",()=>{
  const result=assess({handoffs:[{
   id:"handoff_one",status:"CANCELLED",expiresAt:null,
  }]});
  expect(result.pendingHandoffs).toBe(0);
 });
 it("counts overdue days against supplied clock",()=>{
  expect(assess({dueAt:date(-5)}).overdueDays).toBe(5);
 });
 it("does not flag future task deadlines as overdue",()=>{
  expect(assess({dueAt:date(5)}).overdueDays).toBeNull();
 });
 it("does not fabricate an overdue date when absent",()=>{
  expect(assess({dueAt:null}).overdueDays).toBeNull();
 });
 it("does not equate completed work with finding resolution",()=>{
  const result=assess({status:"DONE",completedAt:date(-1)});
  expect(result.level).toBe("CLOSED_REVIEW");
  expect(result.findingStatus).toBe("OPEN");
 });
 it("flags historical closure with outstanding checklist gaps",()=>{
  const result=assess({
   status:"DONE",checklist:[{id:"check_one",title:"Check",completedAt:null}],
  });
  expect(result.issues).toContain("CLOSED_WITH_GAPS");
 });
 it("does not mark completed work as overdue",()=>{
  expect(assess({status:"DONE",dueAt:date(-30)}).overdueDays).toBeNull();
 });
 it("retains the original revision for concurrent change checks",()=>{
  expect(assess({revision:72}).revision).toBe(72);
 });
 it("does not mutate its source task",()=>{
  const source=work();
  const before={...source};
  assessGate(source,filter(),NOW);
  expect(source).toEqual(before);
 });
 it("preserves the original security finding identifiers",()=>{
  expect(assess().findingId).toBe("finding_alpha");
 });
 it("makes a clear recommendation for evidence gaps",()=>{
  expect(assess({evidenceLinks:[]}).recommendation).toMatch(/Link available evidence/);
 });
 it("keeps checklist completion separate from security testing",()=>{
  const result=assess({
   findingStatus:"OPEN",
   checklist:[{id:"c_one",title:"Completed",completedAt:date(-2)}],
  });
  expect(result.findingStatus).toBe("OPEN");
 });
});
describe("readiness aggregation",()=>{
 const tasks=[
  work({id:"task_ready"}),
  work({id:"task_blocked",status:"BLOCKED"}),
  work({id:"task_missing",assigneeUserId:null,checklist:[],evidenceLinks:[]}),
  work({id:"task_done",status:"DONE",checklist:[]}),
 ];
 it("counts every matching work item",()=>{
  const result=buildGateReview(tasks,filter(),NOW);
  expect(result.summary.total).toBe(4);
 });
 it("classifies all four readiness categories",()=>{
  const result=buildGateReview(tasks,filter(),NOW);
  expect(result.summary).toMatchObject({
   ready:1,attention:1,blocked:1,closedReview:1,
  });
 });
 it("keeps the complete inventory when filtering visible exceptions",()=>{
  const result=buildGateReview(tasks,filter({onlyExceptions:true}),NOW);
  expect(result.summary.total).toBe(4);
  expect(result.rows.length).toBe(3);
 });
 it("counts missing evidence and checklist separately",()=>{
  const result=buildGateReview(tasks,filter(),NOW);
  expect(result.summary.withoutEvidence).toBe(1);
  expect(result.summary.withoutChecklist).toBe(2);
 });
 it("maintains conservation of readiness levels",()=>{
  const summary=buildGateReview(tasks,filter(),NOW).summary;
  expect(summary.ready+summary.attention+summary.blocked+summary.closedReview)
   .toBe(summary.total);
 });
 it("prioritizes blocked work before routine review",()=>{
  const result=buildGateReview(tasks,filter(),NOW);
  expect(result.rows[0]?.id).toBe("task_blocked");
 });
 it("sorts deterministically on tied work records",()=>{
  const result=sortGateDecisions([
   assess({id:"work_z"}),assess({id:"work_a"}),
  ]);
  expect(result.map(row=>row.id)).toEqual(["work_a","work_z"]);
 });
 it("does not mutate source order",()=>{
  const before=tasks.map(row=>row.id);
  buildGateReview(tasks,filter(),NOW);
  expect(tasks.map(row=>row.id)).toEqual(before);
 });
 it("handles empty work inventory",()=>{
  const result=buildGateReview([],filter(),NOW);
  expect(result.rows).toHaveLength(0);
  expect(result.summary.total).toBe(0);
 });
 it("reports complete bounded coverage explicitly",()=>{
  const result=buildGateReview(tasks,filter(),NOW);
  expect(result.coverage).toMatchObject({complete:true,limit:2000});
 });
 it("does not assert independent security validation",()=>{
  const result=buildGateReview(tasks,filter(),NOW);
  expect(result.disclaimer).toMatch(/not evidence validation/);
 });
 it("exposes the snapshot time",()=>{
  expect(buildGateReview(tasks,filter(),NOW).generatedAt).toBe(NOW.toISOString());
 });
 it("counts unfinished checklist steps",()=>{
  const result=summarizeGates([
   assess({checklist:[{id:"incomplete",title:"Review",completedAt:null}]}),
  ]);
  expect(result.incompleteChecklist).toBe(1);
 });
 it("counts handoff decisions awaiting user response",()=>{
  const result=summarizeGates([
   assess({handoffs:[{id:"handoff_one",status:"REQUESTED",expiresAt:null}]}),
  ]);
  expect(result.pendingHandoffs).toBe(1);
 });
});
