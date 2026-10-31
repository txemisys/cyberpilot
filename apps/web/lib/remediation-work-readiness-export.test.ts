import {describe,it,expect} from "vitest";
import {buildGateReview,parseGateFilter,type GateWork} from "./remediation-work-readiness";
import {
 parseReadinessExportSelection,selectReadinessExport,readinessCsv,
 READINESS_EXPORT_COLUMNS,
} from "./remediation-work-readiness-export";
const NOW=new Date("2026-11-01T12:00:00.000Z");
function work(patch:Partial<GateWork>={}):GateWork{
 return {
  id:"work_alpha",title:"Review access",revision:4,status:"TODO",priority:"HIGH",
  assigneeUserId:"user_alpha",assigneeName:"Alice",createdAt:NOW,updatedAt:NOW,
  dueAt:null,completedAt:null,
  findingId:"finding_alpha",findingTitle:"Access gap",
  findingStatus:"OPEN",findingSeverity:"HIGH",
  remediationId:"remediation_alpha",remediationTitle:"Review access",
  remediationStatus:"PROPOSED",
  checklist:[{id:"check_alpha",title:"Review",completedAt:NOW}],
  evidenceLinks:[{id:"link_alpha",evidenceId:"evidence_alpha",unlinkedAt:null}],
  handoffs:[],...patch,
 };
}
function review(items:GateWork[]=[work()]){
 return buildGateReview(items,parseGateFilter({}),NOW);
}
describe("readiness export input validation",()=>{
 it("defaults to all levels and issues with bounded rows",()=>{
  expect(parseReadinessExportSelection({})).toEqual({
   level:"ALL",issue:"ALL",maxRows:2000,
  });
 });
 it.each(["READY_FOR_HUMAN_REVIEW","REQUIRES_ATTENTION","BLOCKED","CLOSED_REVIEW"])(
  "accepts readiness level %s",level=>{
   expect(parseReadinessExportSelection({level}).level).toBe(level);
  });
 it.each(["NO_OWNER","NO_CHECKLIST","INCOMPLETE_CHECKLIST","NO_EVIDENCE",
  "PENDING_HANDOFF","BLOCKED","OVERDUE","UNCONFIRMED_FINDING","CLOSED_WITH_GAPS"])(
  "accepts issue code %s",issue=>{
   expect(parseReadinessExportSelection({issue}).issue).toBe(issue);
  });
 it.each([null,"INVALID",12,{},[]])("rejects invalid level %s",level=>{
  expect(()=>parseReadinessExportSelection({level})).toThrow();
 });
 it.each([null,"INVALID",12,{},[]])("rejects invalid issue %s",issue=>{
  expect(()=>parseReadinessExportSelection({issue})).toThrow();
 });
 it.each([0,-1,2001,Infinity,"bad",1.5])("rejects invalid bounds %s",maxRows=>{
  expect(()=>parseReadinessExportSelection({maxRows})).toThrow();
 });
 it("allows custom bounds within the supported range",()=>{
  expect(parseReadinessExportSelection({maxRows:50}).maxRows).toBe(50);
 });
});
describe("formula-safe readiness evidence references export",()=>{
 it("exports a complete CSV header",()=>{
  const csv=readinessCsv(review(),parseReadinessExportSelection({}));
  for(const column of READINESS_EXPORT_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(column);
 });
 it("does not export underlying evidence payload",()=>{
  const csv=readinessCsv(review(),parseReadinessExportSelection({}));
  expect(csv).toContain("1");
  expect(csv).not.toContain("evidence_alpha");
 });
 it("exports references to work and finding",()=>{
  const csv=readinessCsv(review(),parseReadinessExportSelection({}));
  expect(csv).toContain("work_alpha");
  expect(csv).toContain("finding_alpha");
 });
 it("neutralizes leading spreadsheet formula syntax",()=>{
  for(const prefix of ["=","+","-","@"]){
   const csv=readinessCsv(review([work({title:prefix+"FUNCTION()"})]),
    parseReadinessExportSelection({}));
   expect(csv).toContain("'"+prefix+"FUNCTION()");
  }
 });
 it("quotes embedded double quotes",()=>{
  const csv=readinessCsv(review([work({title:'Review "admin"'})]),
   parseReadinessExportSelection({}));
  expect(csv).toContain('Review ""admin""');
 });
 it("exports with CRLF row separators",()=>{
  expect(readinessCsv(review(),parseReadinessExportSelection({}))).toContain("\r\n");
 });
 it("rejects incomplete coverage",()=>{
  const model=review();model.coverage.complete=false;
  expect(()=>readinessCsv(model,parseReadinessExportSelection({}))).toThrow();
 });
 it("rejects truncation instead of silently omitting rows",()=>{
  const model=review([work({id:"work_one"}),work({id:"work_two"})]);
  expect(()=>readinessCsv(model,parseReadinessExportSelection({maxRows:1}))).toThrow();
 });
 it("supports level filtering",()=>{
  const model=review([work({id:"work_one"}),work({id:"work_two",status:"BLOCKED"})]);
  expect(selectReadinessExport(model,parseReadinessExportSelection({level:"BLOCKED"})))
   .toHaveLength(1);
 });
 it("supports issue filtering",()=>{
  const model=review([work({id:"work_one"}),work({id:"work_two",checklist:[]})]);
  expect(selectReadinessExport(model,parseReadinessExportSelection({issue:"NO_CHECKLIST"})))
   .toHaveLength(1);
 });
 it("does not mutate review records during CSV rendering",()=>{
  const model=review();const before=JSON.stringify(model);
  readinessCsv(model,parseReadinessExportSelection({}));
  expect(JSON.stringify(model)).toBe(before);
 });
 it("returns header-only file for empty inventories",()=>{
  const csv=readinessCsv(review([]),parseReadinessExportSelection({}));
  expect(csv).toContain("Work ID");
  expect(csv).not.toContain("work_alpha");
 });
});
