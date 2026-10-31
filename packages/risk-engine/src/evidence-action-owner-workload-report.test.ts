import { describe, expect, it } from "vitest";
import { buildOwnerWorkloadChangeReport } from "./evidence-action-owner-workload-report";
import type { ActionWorkloadComparison } from "./evidence-action-owner-workload-compare";
const comparison: ActionWorkloadComparison={
 organizationId:"org",previousAsOf:"2026-10-29",currentAsOf:"2026-10-30",
 overdueChange:-2,upcomingChange:3,highPriorityChange:-1,
 newlyAssignedOwners:["Bob"],removedOwners:["Alice"],unassignedChange:1
};
describe("management owner workload briefing",()=>{
 it("explains operational changes and preserves counts",()=>{
  const report=buildOwnerWorkloadChangeReport(comparison,"org")!;
  expect(report.headline).toBe("Overdue actions decreased by 2");
  expect(report.period).toEqual({from:"2026-10-29",to:"2026-10-30"});
  expect(report.changes.map(x=>x.direction)).toEqual(["DECREASE","INCREASE","DECREASE","INCREASE"]);
  expect(report.ownerChanges).toEqual({added:["Bob"],removed:["Alice"]});
 });
 it("refuses foreign tenant and reversed dates",()=>{
  expect(buildOwnerWorkloadChangeReport(comparison,"other")).toBeNull();
  expect(buildOwnerWorkloadChangeReport({...comparison,currentAsOf:"2026-10-28"},"org")).toBeNull();
 });
 it("handles unchanged and rising overdue counts",()=>{
  expect(buildOwnerWorkloadChangeReport({...comparison,overdueChange:0},"org")?.headline).toContain("unchanged");
  expect(buildOwnerWorkloadChangeReport({...comparison,overdueChange:4},"org")?.headline).toContain("increased by 4");
 });
});
