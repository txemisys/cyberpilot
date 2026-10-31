import {describe,expect,it} from "vitest";
import {
 buildChecklistCsv,checklistCoverage,checklistCsvRows,
 checklistFilename,CHECKLIST_EXPORT_COLUMNS,type ChecklistExportRecord
} from "./work-checklist-export";
const example:ChecklistExportRecord={
 position:0,title:"Review MFA enforcement",
 description:"Confirm change ticket and assigned owner",
 completedAt:new Date("2026-10-31T15:00:00.000Z"),
 completedBy:{name:"Reviewer",email:"reviewer@example.org"},
 createdAt:new Date("2026-10-29T10:00:00.000Z"),
 updatedAt:new Date("2026-10-31T15:00:00.000Z")
};
describe("human work checklist CSV exports",()=>{
 it("preserves explicit acknowledgment fields rather than verification claims",()=>{
  expect(CHECKLIST_EXPORT_COLUMNS).toHaveLength(9);
  expect(CHECKLIST_EXPORT_COLUMNS).toContain("Acknowledged");
  expect(CHECKLIST_EXPORT_COLUMNS).toContain("Acknowledged timestamp (UTC)");
  expect(CHECKLIST_EXPORT_COLUMNS).not.toContain("Verified");
  expect(CHECKLIST_EXPORT_COLUMNS).not.toContain("Security passed");
 });
 it("writes one row per work step and stable column count",()=>{
  const rows=checklistCsvRows([example,{...example,position:1,title:"Record handoff"}]);
  expect(rows).toHaveLength(2);
  expect(rows.every(x=>x.length===CHECKLIST_EXPORT_COLUMNS.length)).toBe(true);
  expect(rows[0]?.[0]).toBe("1");
  expect(rows[1]?.[0]).toBe("2");
 });
 it("retains UTC timestamps and responsible actor",()=>{
  const row=checklistCsvRows([example])[0];
  expect(row?.[3]).toBe("YES");
  expect(row?.[4]).toBe("2026-10-31T15:00:00.000Z");
  expect(row?.[5]).toBe("Reviewer");
  expect(row?.[6]).toBe("reviewer@example.org");
 });
 it("handles unacknowledged steps without inventing an actor",()=>{
  const row=checklistCsvRows([{
   ...example,completedAt:null,completedBy:null
  }])[0];
  expect(row?.[3]).toBe("NO");
  expect(row?.[4]).toBe("");
  expect(row?.[5]).toBe("");
  expect(row?.[6]).toBe("");
 });
 it("escapes line breaks, commas and quotes",()=>{
  const csv=buildChecklistCsv([{...example,title:'Review "A,B"',description:"Step 1\nStep 2"}]);
  expect(csv).toContain('"Review ""A,B"""');
  expect(csv).toContain('"Step 1\nStep 2"');
  expect(csv.endsWith("\r\n")).toBe(true);
 });
 it("neutralizes spreadsheet formulas in every user-controlled column",()=>{
  for(const formula of ["=1+1","+SUM(3)","-3*4","@SUM(2)","  =HYPERLINK(1)"]){
   const csv=buildChecklistCsv([{
    ...example,title:formula,description:formula,
    completedBy:{name:formula,email:"reviewer@example.org"}
   }]);
   expect(csv).toContain(`"'${formula}"`);
  }
 });
 it("returns headers only for empty checklists",()=>{
  const csv=buildChecklistCsv([]);
  expect(csv.split("\r\n")).toHaveLength(2);
 });
 it("does not count an empty checklist as complete",()=>{
  expect(checklistCoverage([])).toMatchObject({
   total:0,acknowledged:0,pending:0,allHumanStepsAcknowledged:false
  });
 });
 it("treats work progress as human acknowledgment, not verified security",()=>{
  expect(checklistCoverage([
   example,{...example,position:1,completedAt:null}
  ])).toMatchObject({
   total:2,acknowledged:1,pending:1,allHumanStepsAcknowledged:false
  });
  expect(checklistCoverage([example])).toMatchObject({
   total:1,acknowledged:1,pending:0,allHumanStepsAcknowledged:true
  });
  expect(checklistCoverage([example]).note).toContain("not verified controls");
 });
 it("sanitizes filename components",()=>{
  expect(checklistFilename("clwork1234")).toBe("cyberpilot-work-checklist-clwork1234.csv");
  expect(checklistFilename("../../outside")).not.toContain("/");
 });
});
