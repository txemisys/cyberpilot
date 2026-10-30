import { describe, expect, it } from "vitest";
import { exportActionOwnerWorkloadCsv } from "./evidence-action-owner-workload-export";
import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";
const summary:ActionOwnerWorkloadSummary={
 organizationId:"org-1",asOf:"2026-10-30",
 assigned:[
  {owner:"Alice",overdue:2,upcoming:1,highPriority:2,earliestDueDate:"2026-10-28"},
  {owner:"=HYPERLINK(\"https://example.com\")",overdue:0,upcoming:1,highPriority:1,earliestDueDate:"2026-11-01"},
 ],
 unassigned:{owner:null,overdue:1,upcoming:0,highPriority:1,earliestDueDate:"2026-10-29"},
 totalOverdue:3,totalUpcoming:2,
};
describe("CSV owner workload handoff",()=>{
 it("exports bounded tenant-scoped aggregated counts and a dated filename",()=>{
  const file=exportActionOwnerWorkloadCsv(summary,"org-1")!;
  expect(file.filename).toBe("action-owner-workload-2026-10-30.csv");
  expect(file.mimeType).toBe("text/csv; charset=utf-8");
  expect(file.content).toContain('"Alice","2","1","2","2026-10-28"');
  expect(file.content).toContain('"UNASSIGNED","1","0","1","2026-10-29"');
 });
 it("escapes formula-leading cells and embedded double quotes",()=>{
  const file=exportActionOwnerWorkloadCsv(summary,"org-1")!;
  expect(file.content).toContain("'=HYPERLINK");
  expect(file.content).toContain('""https://example.com""');
 });
 it("never exports data across organization boundaries",()=>{
  expect(exportActionOwnerWorkloadCsv(summary,"org-2")).toBeNull();
  expect(exportActionOwnerWorkloadCsv(summary,"")).toBeNull();
 });
 it("does not mutate workload input",()=>{
  const original=JSON.stringify(summary);
  exportActionOwnerWorkloadCsv(summary,"org-1");
  expect(JSON.stringify(summary)).toBe(original);
 });
});
