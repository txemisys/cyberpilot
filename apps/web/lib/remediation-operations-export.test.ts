import {describe,expect,it} from "vitest";
import {serializeRemediationExport,describeRemediationExport} from "./remediation-operations-export";
import {parseActionPageInput} from "./action-pagination";
const row={
 id:"a1",title:"Protect admin accounts",status:"APPROVED",mode:"GUIDED",
 severity:"HIGH",findingTitle:"No MFA",findingStatus:"OPEN",
 createdAt:new Date("2026-01-01T00:00:00Z"),approvedAt:null,startedAt:null,
 completedAt:null,verifiedAt:null,guidedCompleted:2,guidedTotal:3,needsVerification:false,
};
describe("Operational CSV handoff",()=>{
 it("records workflow status and distinct evidence milestones",()=>{
  const csv=serializeRemediationExport([row]);
  expect(csv).toContain('"APPROVED"');
  expect(csv).toContain('"2","3","NO"');
  expect(csv).toContain('"2026-01-01T00:00:00.000Z"');
  expect(csv).toContain('"Verified UTC"');
 });
 it("neutralizes spreadsheet formulas in user-provided titles",()=>{
  const csv=serializeRemediationExport([{...row,title:'=HYPERLINK("https://example.invalid")',findingTitle:"+2+3"}]);
  expect(csv).toContain('"\'=HYPERLINK(""https://example.invalid"")"');
  expect(csv).toContain('"\'+2+3"');
 });
 it("preserves CSV rows when titles contain commas and line breaks",()=>{
  const csv=serializeRemediationExport([{...row,title:'Domain, "security"\nreview'}]);
  expect(csv).toContain('"Domain, ""security""\nreview"');
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
 it("clearly identifies operational rather than evidence-based verification output",()=>{
  const note=describeRemediationExport(parseActionPageInput({status:"attention",search:"admin"}),1);
  expect(note).toContain("not verification");
  expect(note).toContain("text search applied");
 });
});
