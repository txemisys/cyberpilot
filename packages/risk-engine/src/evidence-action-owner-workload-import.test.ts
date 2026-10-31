import { describe, expect, it } from "vitest";
import { exportActionOwnerWorkloadJson } from "./evidence-action-owner-workload-json";
import { importActionOwnerWorkloadJson } from "./evidence-action-owner-workload-import";
import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";
const summary:ActionOwnerWorkloadSummary={
 organizationId:"org",asOf:"2026-10-30",
 assigned:[{owner:"Ops",overdue:1,upcoming:2,highPriority:2,earliestDueDate:"2026-10-29"}],
 unassigned:{owner:null,overdue:0,upcoming:1,highPriority:1,earliestDueDate:"2026-11-01"},
 totalOverdue:1,totalUpcoming:3,
};
describe("portable workload JSON import",()=>{
 it("roundtrips exported workload without losing tenant provenance",()=>{
  const exported=exportActionOwnerWorkloadJson(summary,"org")!;
  const parsed=importActionOwnerWorkloadJson(exported.content,"org");
  expect(parsed?.workload).toEqual(summary);
  expect(parsed?.schemaVersion).toBe(1);
 });
 it("refuses foreign organization and unknown format versions",()=>{
  const exported=exportActionOwnerWorkloadJson(summary,"org")!;
  expect(importActionOwnerWorkloadJson(exported.content,"other")).toBeNull();
  const p=JSON.parse(exported.content);p.schemaVersion=2;
  expect(importActionOwnerWorkloadJson(JSON.stringify(p),"org")).toBeNull();
 });
 it("refuses inconsistent totals, forged owners, dates and malformed content",()=>{
  const original=JSON.parse(exportActionOwnerWorkloadJson(summary,"org")!.content);
  expect(importActionOwnerWorkloadJson("{bad","org")).toBeNull();
  expect(importActionOwnerWorkloadJson(JSON.stringify({...original,totalUpcoming:99}),"org")).toBeNull();
  expect(importActionOwnerWorkloadJson(JSON.stringify({...original,asOf:"2026-02-30"}),"org")).toBeNull();
  expect(importActionOwnerWorkloadJson(JSON.stringify({...original,assigned:[{...original.assigned[0],owner:null}]}),"org")).toBeNull();
 });
});