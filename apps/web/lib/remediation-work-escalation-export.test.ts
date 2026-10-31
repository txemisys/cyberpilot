import {describe,expect,it} from "vitest";
import {
 escalationCsv,parseExportSelection,selectEscalationExport,
 escalationExportSummary,ESCALATION_COLUMNS,MAX_ESCALATION_EXPORT,
} from "./remediation-work-escalation-export";
import {
 buildEscalationReview,parseEscalationConfig,type EscalationWork,
} from "./remediation-work-escalations";
const NOW=new Date("2026-11-01T12:00:00Z");
const day=(days:number)=>new Date(NOW.getTime()+days*86400000);
function work(patch:Partial<EscalationWork>={}):EscalationWork{
 return {
  id:"work_alpha",title:"Review access rights",description:"Review task",
  revision:2,status:"BLOCKED",priority:"URGENT",assigneeUserId:"user_alpha",
  assigneeName:"Alice",dueAt:day(-4),createdAt:day(-20),updatedAt:day(-40),
  findingId:"finding_alpha",findingTitle:"Access gap",findingSeverity:"HIGH",
  findingStatus:"OPEN",remediationId:"remediation_alpha",
  remediationTitle:"Review access",remediationStatus:"PROPOSED",
  pendingHandoffs:1,...patch,
 };
}
function review(items:EscalationWork[]= [work()]){
 return buildEscalationReview(items,parseEscalationConfig({
  minLevel:"NONE",includeClosed:true,
 }),NOW);
}
describe("bounded escalation export input",()=>{
 it("has an explicit 2000 row limit",()=>{
  expect(MAX_ESCALATION_EXPORT).toBe(2000);
 });
 it("provides conservative defaults",()=>{
  expect(parseExportSelection({})).toEqual({
   minLevel:"WATCH",includeClosed:false,onlyOverdue:false,maxRows:2000,
  });
 });
 it.each(["NONE","WATCH","ELEVATED","CRITICAL"])("accepts level %s",minLevel=>{
  expect(parseExportSelection({minLevel}).minLevel).toBe(minLevel);
 });
 it.each([null,"UNKNOWN",12,{},[]])("rejects invalid attention level %s",minLevel=>{
  expect(()=>parseExportSelection({minLevel})).toThrow();
 });
 it.each([-1,0,2001,"bad",1.5])("rejects invalid limit %s",maxRows=>{
  expect(()=>parseExportSelection({maxRows})).toThrow();
 });
 it.each([1,20,50,100,1000,2000])("accepts bound %s",maxRows=>{
  expect(parseExportSelection({maxRows}).maxRows).toBe(maxRows);
 });
 it("supports explicit due-only export",()=>{
  expect(parseExportSelection({onlyOverdue:"true"}).onlyOverdue).toBe(true);
 });
 it("does not enable due-only export for arbitrary strings",()=>{
  expect(parseExportSelection({onlyOverdue:"yes"}).onlyOverdue).toBe(false);
 });
 it("supports including completed work",()=>{
  expect(parseExportSelection({includeClosed:"true"}).includeClosed).toBe(true);
 });
});
describe("escalation export semantics",()=>{
 it("exports all declared columns",()=>{
  const csv=escalationCsv(review(),parseExportSelection({}));
  for(const column of ESCALATION_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(column);
 });
 it("always uses CRLF line endings",()=>{
  expect(escalationCsv(review(),parseExportSelection({}))).toContain("\r\n");
 });
 it("does not alter source decisions",()=>{
  const result=review();
  const before=JSON.stringify(result);
  escalationCsv(result,parseExportSelection({}));
  expect(JSON.stringify(result)).toBe(before);
 });
 it("does not export a work description or evidence JSON",()=>{
  const csv=escalationCsv(review([work({
   description:"PRIVATE_WORK_NOTES",findingTitle:"Access",
  })]),parseExportSelection({}));
  expect(csv).not.toContain("PRIVATE_WORK_NOTES");
 });
 it("neutralizes spreadsheet formulas in task titles",()=>{
  const csv=escalationCsv(review([work({title:"=DANGEROUS()"})]),parseExportSelection({}));
  expect(csv).toContain("'=DANGEROUS()");
 });
 it("neutralizes formulas beginning with plus",()=>{
  const csv=escalationCsv(review([work({title:"+SUM(1,1)"})]),parseExportSelection({}));
  expect(csv).toContain("'+SUM");
 });
 it("neutralizes formulas beginning with at sign",()=>{
  const csv=escalationCsv(review([work({title:"@import"})]),parseExportSelection({}));
  expect(csv).toContain("'@import");
 });
 it("neutralizes formulas beginning with minus",()=>{
  const csv=escalationCsv(review([work({title:"-2+3"})]),parseExportSelection({}));
  expect(csv).toContain("'-2+3");
 });
 it("quotes embedded commas and double quotes",()=>{
  const csv=escalationCsv(review([work({title:'Review, "admin" access'})]),
   parseExportSelection({}));
  expect(csv).toContain('Review, ""admin"" access');
 });
 it("retains tenant-scoped work identifiers for auditing",()=>{
  const csv=escalationCsv(review(),parseExportSelection({}));
  expect(csv).toContain("work_alpha");
  expect(csv).toContain("finding_alpha");
  expect(csv).toContain("remediation_alpha");
 });
 it("excludes closed work by default",()=>{
  const rows=selectEscalationExport(review([work({status:"DONE"})]),
   parseExportSelection({minLevel:"NONE"}));
  expect(rows).toHaveLength(0);
 });
 it("can include completed work explicitly",()=>{
  const rows=selectEscalationExport(review([work({status:"DONE"})]),
   parseExportSelection({minLevel:"NONE",includeClosed:true}));
  expect(rows).toHaveLength(1);
 });
 it("filters out non-overdue work on request",()=>{
  const rows=selectEscalationExport(review([work({dueAt:day(20)})]),
   parseExportSelection({onlyOverdue:true}));
  expect(rows).toHaveLength(0);
 });
 it("includes actually overdue active work",()=>{
  const rows=selectEscalationExport(review(),
   parseExportSelection({onlyOverdue:true}));
  expect(rows).toHaveLength(1);
 });
 it("preserves an empty file header",()=>{
  const csv=escalationCsv(review([]),parseExportSelection({}));
  expect(csv.split("\r\n")[0]).toContain("Work ID");
 });
 it("rejects a partial data snapshot",()=>{
  const model=review();
  model.coverage.complete=false;
  expect(()=>escalationCsv(model,parseExportSelection({}))).toThrow();
 });
 it("rejects silently truncated exports",()=>{
  const model=review([work({id:"work_one"}),work({id:"work_two"})]);
  expect(()=>escalationCsv(model,parseExportSelection({maxRows:1}))).toThrow();
 });
 it("reports complete export scope",()=>{
  const summary=escalationExportSummary(review(),parseExportSelection({}));
  expect(summary).toMatchObject({
   exported:1,matchingBeforeExportRules:1,maxRows:2000,
  });
 });
 it("includes an explicit non-attestation warning",()=>{
  const summary=escalationExportSummary(review(),parseExportSelection({}));
  expect(summary.caveat).toMatch(/not verified evidence/);
 });
});
