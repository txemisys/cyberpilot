import {describe,expect,it} from "vitest";
import {buildCapacityReport,parseCapacityConfig,type CapacityWork,type CapacityMember} from "./remediation-work-capacity";
import {
 parseCapacityExportOptions,capacityCsv,capacityIntegrity,
 CAPACITY_MEMBER_COLUMNS,CAPACITY_TASK_COLUMNS,
} from "./remediation-work-capacity-export";
const NOW=new Date("2026-11-01T12:00:00Z");
const alice:CapacityMember={userId:"user_alice",name:"Alice",role:"ADMIN"};
const bob:CapacityMember={userId:"user_bob",name:"Bob",role:"MEMBER"};
function task(patch:Partial<CapacityWork>={}):CapacityWork{
 return {id:"work_alpha",title:"Review access",status:"TODO",priority:"NORMAL",
  assigneeUserId:"user_alice",dueAt:null,updatedAt:NOW,
  findingSeverity:"MEDIUM",checklist:[{completedAt:NOW}],handoffs:[],...patch};
}
function report(items:CapacityWork[]=[task()],maxTasks=50){
 return buildCapacityReport(items,[alice,bob],parseCapacityConfig({maxTasks}),NOW);
}
const opts=(raw:Record<string,unknown>={})=>parseCapacityExportOptions(raw);
describe("capacity export input",()=>{
 it("defaults to member rows including unassigned",()=>{
  expect(opts()).toEqual({mode:"MEMBERS",maxRows:2000,includeUnassigned:true});
 });
 it.each([null,undefined,12,[],false,"invalid"])("rejects nonobject %s",raw=>{
  expect(()=>parseCapacityExportOptions(raw)).toThrow();
 });
 it.each(["MEMBERS","TASKS"])("accepts format %s",mode=>{
  expect(opts({mode}).mode).toBe(mode);
 });
 it.each([null,"INVALID",12,{},[]])("rejects format %s",mode=>{
  expect(()=>opts({mode})).toThrow();
 });
 it.each([1,10,100,500,2000])("accepts row limit %s",maxRows=>{
  expect(opts({maxRows}).maxRows).toBe(maxRows);
 });
 it.each([0,-1,2001,1.5,NaN,null,"100"])("rejects row limit %s",maxRows=>{
  expect(()=>opts({maxRows})).toThrow();
 });
 it.each([null,"true",1,0,{}])("rejects unassigned flag %s",includeUnassigned=>{
  expect(()=>opts({includeUnassigned})).toThrow();
 });
 it("supports explicit excluding unassigned work",()=>{
  expect(opts({includeUnassigned:false}).includeUnassigned).toBe(false);
 });
 it("rejects unknown user-selected attributes",()=>{
  expect(()=>opts({organizationId:"foreign"})).toThrow();
 });
});
describe("CSV correctness and security",()=>{
 it("includes member count headers",()=>{
  const csv=capacityCsv(report(),opts());
  for(const heading of CAPACITY_MEMBER_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(heading);
 });
 it("includes task record headers",()=>{
  const csv=capacityCsv(report(),opts({mode:"TASKS"}));
  for(const heading of CAPACITY_TASK_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(heading);
 });
 it("exports member workloads with explicit role",()=>{
  const csv=capacityCsv(report(),opts());
  expect(csv).toContain("user_alice");
  expect(csv).toContain("ADMIN");
 });
 it("can exclude the unassigned bucket from member export",()=>{
  const csv=capacityCsv(report(),opts({includeUnassigned:false}));
  expect(csv).not.toContain("UNASSIGNED");
 });
 it("does not export underlying checklist bodies",()=>{
  const csv=capacityCsv(report(),opts({mode:"TASKS"}));
  expect(csv).not.toContain("checklist contents");
 });
 it("protects attacker-controlled task titles starting with formulas",()=>{
  for(const prefix of ["=","+","-","@"]){
   const csv=capacityCsv(report([task({title:prefix+"EXPLOIT()"})]),
    opts({mode:"TASKS"}));
   expect(csv).toContain("'"+prefix+"EXPLOIT()");
  }
 });
 it("protects attacker-controlled member names starting with formulas",()=>{
  const model=report();
  model.members.find(m=>m.id==="user_alice")!.name="=INJECT()";
  expect(capacityCsv(model,opts())).toContain("'=INJECT()");
 });
 it("quotes commas and double quotes in task titles",()=>{
  const csv=capacityCsv(report([task({title:'Review, "admin"'})]),opts({mode:"TASKS"}));
  expect(csv).toContain('Review, ""admin""');
 });
 it("preserves CRLF row endings",()=>{
  expect(capacityCsv(report(),opts())).toContain("\r\n");
 });
 it("does not silently truncate a member report",()=>{
  expect(()=>capacityCsv(report(),opts({maxRows:1}))).toThrow();
 });
 it("does not silently export incomplete task previews",()=>{
  const model=report([
   task({id:"work_one"}),task({id:"work_two"}),
  ],1);
  expect(()=>capacityCsv(model,opts({mode:"TASKS"}))).toThrow();
 });
 it("allows member summary even when task preview is truncated",()=>{
  const model=report([task({id:"work_one"}),task({id:"work_two"})],1);
  expect(capacityCsv(model,opts())).toContain("Assigned tasks");
 });
 it("refuses incomplete organization coverage",()=>{
  const model=report();model.coverage.complete=false;
  expect(()=>capacityCsv(model,opts())).toThrow();
 });
 it("refuses excessive task rows",()=>{
  const model=report([task({id:"work_one"}),task({id:"work_two"})]);
  expect(()=>capacityCsv(model,opts({mode:"TASKS",maxRows:1}))).toThrow();
 });
 it("supports a header-only empty inventory",()=>{
  const csv=capacityCsv(report([]),opts({mode:"TASKS"}));
  expect(csv).toContain("Work item ID");
  expect(csv).not.toContain("work_alpha");
 });
 it("does not modify reporting data",()=>{
  const model=report();const original=JSON.stringify(model);
  capacityCsv(model,opts());expect(JSON.stringify(model)).toBe(original);
 });
});
describe("workload consistency diagnostics",()=>{
 it("reconciles total assigned work",()=>{
  expect(capacityIntegrity(report()).countsReconcile).toBe(true);
 });
 it("reconciles open and closed records",()=>{
  expect(capacityIntegrity(report()).statesReconcile).toBe(true);
 });
 it("detects inconsistent inventory totals",()=>{
  const model=report();model.summary.tasks++;
  expect(capacityIntegrity(model).countsReconcile).toBe(false);
 });
 it("detects inconsistent status counts",()=>{
  const model=report();model.summary.active++;
  expect(capacityIntegrity(model).statesReconcile).toBe(false);
 });
 it("identifies truncated member task previews",()=>{
  const model=report([task({id:"work_one"}),task({id:"work_two"})],1);
  expect(capacityIntegrity(model).hasTruncatedMemberPreviews).toBe(true);
 });
 it("does not confuse preview completeness with full inventory",()=>{
  expect(capacityIntegrity(report()).hasTruncatedMemberPreviews).toBe(false);
 });
 it("keeps the report timestamp",()=>{
  expect(capacityIntegrity(report()).examinedAt).toBe(NOW.toISOString());
 });
 it("explicitly separates consistency from security assurance",()=>{
  expect(capacityIntegrity(report()).warning).toMatch(/does not measure/);
 });
});
