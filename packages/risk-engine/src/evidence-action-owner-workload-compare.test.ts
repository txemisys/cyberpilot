import { describe, expect, it } from "vitest";
import { compareActionOwnerWorkloads } from "./evidence-action-owner-workload-compare";
import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";
const previous:ActionOwnerWorkloadSummary={organizationId:"org",asOf:"2026-10-29",assigned:[{owner:"Alice",overdue:2,upcoming:1,highPriority:2,earliestDueDate:"2026-10-27"}],unassigned:{owner:null,overdue:1,upcoming:1,highPriority:1,earliestDueDate:"2026-10-28"},totalOverdue:3,totalUpcoming:2};
const current:ActionOwnerWorkloadSummary={organizationId:"org",asOf:"2026-10-30",assigned:[{owner:"Bob",overdue:1,upcoming:1,highPriority:1,earliestDueDate:"2026-10-29"}],unassigned:{owner:null,overdue:0,upcoming:1,highPriority:1,earliestDueDate:"2026-11-01"},totalOverdue:1,totalUpcoming:2};
describe("owner workload snapshot comparison",()=>{
 it("captures risk workload changes and ownership handoff",()=>{
  expect(compareActionOwnerWorkloads(previous,current,"org")).toEqual({organizationId:"org",previousAsOf:"2026-10-29",currentAsOf:"2026-10-30",overdueChange:-2,upcomingChange:0,highPriorityChange:-1,newlyAssignedOwners:["Bob"],removedOwners:["Alice"],unassignedChange:-1});
 });
 it("refuses mixed tenants and reversed dates",()=>{
  expect(compareActionOwnerWorkloads(previous,current,"different")).toBeNull();
  expect(compareActionOwnerWorkloads(current,previous,"org")).toBeNull();
 });
 it("does not mutate stored snapshots",()=>{
  const saved=JSON.stringify([previous,current]);compareActionOwnerWorkloads(previous,current,"org");
  expect(JSON.stringify([previous,current])).toBe(saved);
 });
});
