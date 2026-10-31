import {describe,expect,it} from "vitest";
import {buildDigest,parseDigestConfig,type DigestWork} from "./remediation-work-digest";
import {
 parseDigestExportOptions,selectedDigestRows,digestCsv,digestIntegrity,
 DIGEST_PRIORITY_COLUMNS,DIGEST_FOLLOW_UP_COLUMNS,
} from "./remediation-work-digest-export";
const NOW=new Date("2026-11-01T12:00:00Z");
const day=(offset:number)=>new Date(NOW.getTime()+offset*86400000);
function work(patch:Partial<DigestWork>={}):DigestWork{
 return {
  id:"work_alpha",title:"Review access",status:"BLOCKED",priority:"URGENT",
  assigneeUserId:"user_alpha",assigneeName:"Alice",dueAt:day(-3),
  createdAt:day(-30),updatedAt:day(-15),findingTitle:"Risk",findingSeverity:"HIGH",
  checklist:[{completedAt:null}],evidenceLinks:[],handoffs:[{
   status:"REQUESTED",expiresAt:day(3),
  }],...patch,
 };
}
function report(items:DigestWork[]=[work()],maxItems=100){
 return buildDigest(items,parseDigestConfig({maxItems}),NOW);
}
const options=(overrides:Record<string,unknown>={})=>parseDigestExportOptions(overrides);
describe("digest export validation",()=>{
 it("defaults to priorities with an explicit limit",()=>{
  expect(options()).toEqual({mode:"PRIORITIES",maxRows:100,onlyAttention:false});
 });
 it.each([null,undefined,42,[],false,"bad"])("rejects non-object parameters %s",raw=>{
  expect(()=>parseDigestExportOptions(raw)).toThrow();
 });
 it.each(["PRIORITIES","FOLLOW_UPS"])("supports output mode %s",mode=>{
  expect(options({mode}).mode).toBe(mode);
 });
 it.each(["UNKNOWN",null,1,{},[]])("rejects output mode %s",mode=>{
  expect(()=>options({mode})).toThrow();
 });
 it.each([1,10,30,50,100])("accepts row bound %s",maxRows=>{
  expect(options({maxRows}).maxRows).toBe(maxRows);
 });
 it.each([0,-1,101,1.5,"30",null,NaN])("rejects row bound %s",maxRows=>{
  expect(()=>options({maxRows})).toThrow();
 });
 it.each([null,"false",0,1,{}])("rejects bad attention flag %s",onlyAttention=>{
  expect(()=>options({onlyAttention})).toThrow();
 });
 it("allows attention-only export",()=>{
  expect(options({onlyAttention:true}).onlyAttention).toBe(true);
 });
 it("rejects unknown parameter properties",()=>{
  expect(()=>options({tenantId:"foreign"})).toThrow();
 });
});
describe("safe digest CSV",()=>{
 it("includes the full priority header",()=>{
  const csv=digestCsv(report(),options());
  for(const header of DIGEST_PRIORITY_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(header);
 });
 it("includes the full follow-up header",()=>{
  const csv=digestCsv(report(),options({mode:"FOLLOW_UPS"}));
  for(const header of DIGEST_FOLLOW_UP_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(header);
 });
 it("uses CRLF line endings",()=>{
  expect(digestCsv(report(),options())).toContain("\r\n");
 });
 it("includes actual task identifiers",()=>{
  expect(digestCsv(report(),options())).toContain("work_alpha");
 });
 it("does not export private finding descriptions",()=>{
  const csv=digestCsv(report([work({findingTitle:"PRIVATE_FINDING"})]),options());
  expect(csv).not.toContain("PRIVATE_FINDING");
 });
 it("protects spreadsheet formulas in task titles",()=>{
  for(const leading of ["=","+","-","@"]){
   const csv=digestCsv(report([work({title:leading+"EVIL()"})]),options());
   expect(csv).toContain("'"+leading+"EVIL()");
  }
 });
 it("quotes embedded double quotes",()=>{
  const csv=digestCsv(report([work({title:'Review "owner"'})]),options());
  expect(csv).toContain('Review ""owner""');
 });
 it("quotes embedded commas",()=>{
  const csv=digestCsv(report([work({title:"Review, all"})]),options());
  expect(csv).toContain('"Review, all"');
 });
 it("omits entries with no attention when requested",()=>{
  const rows=selectedDigestRows(report([
   work({id:"work_one"}),work({id:"work_two",status:"DONE"}),
  ]),true);
  expect(rows).toHaveLength(1);
 });
 it("retains closed records when attention filtering is disabled",()=>{
  const rows=selectedDigestRows(report([
   work({id:"work_one"}),work({id:"work_two",status:"DONE"}),
  ]),false);
  expect(rows).toHaveLength(2);
 });
 it("rejects incomplete inventory",()=>{
  const model=report();model.coverage.complete=false;
  expect(()=>digestCsv(model,options())).toThrow();
 });
 it("rejects incomplete priority previews",()=>{
  const model=report([work({id:"work_a"}),work({id:"work_b"})],1);
  expect(()=>digestCsv(model,options())).toThrow();
 });
 it("allows follow-up exports even with truncated priority preview",()=>{
  const model=report([work({id:"work_a"}),work({id:"work_b"})],1);
  expect(digestCsv(model,options({mode:"FOLLOW_UPS"}))).toContain("Operational signal");
 });
 it("rejects overly large priority exports",()=>{
  const model=report([work({id:"work_a"}),work({id:"work_b"})]);
  expect(()=>digestCsv(model,options({maxRows:1}))).toThrow();
 });
 it("rejects overly large follow-up exports",()=>{
  expect(()=>digestCsv(report(),options({mode:"FOLLOW_UPS",maxRows:1}))).toThrow();
 });
 it("supports header-only empty reports",()=>{
  const csv=digestCsv(report([]),options());
  expect(csv).toContain("Work ID");
  expect(csv).not.toContain("work_alpha");
 });
 it("does not mutate underlying records",()=>{
  const model=report();const serialized=JSON.stringify(model);
  digestCsv(model,options());expect(JSON.stringify(model)).toBe(serialized);
 });
});
describe("digest snapshot integrity",()=>{
 it("recognizes conserved open and closed totals",()=>{
  expect(digestIntegrity(report()).balanced).toBe(true);
 });
 it("reports impossible inconsistent totals",()=>{
  const model=report();model.summary.total++;
  expect(digestIntegrity(model).balanced).toBe(false);
 });
 it("confirms bounded previews",()=>{
  expect(digestIntegrity(report()).previewIsBounded).toBe(true);
 });
 it("reports incomplete review honestly",()=>{
  const model=report();model.coverage.complete=false;
  expect(digestIntegrity(model).complete).toBe(false);
 });
 it("recognizes truncated previews",()=>{
  const model=report([work({id:"work_a"}),work({id:"work_b"})],1);
  expect(digestIntegrity(model).hasExcludedPreviewItems).toBe(true);
 });
 it("retains exact snapshot clock",()=>{
  expect(digestIntegrity(report()).asOf).toBe(NOW.toISOString());
 });
 it("does not conflate count consistency with security testing",()=>{
  expect(digestIntegrity(report()).note).toMatch(/no security testing/);
 });
});
