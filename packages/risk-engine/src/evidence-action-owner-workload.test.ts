import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { summarizeActionDeadlines } from "./evidence-action-deadlines";
import { summarizeActionOwnerWorkload } from "./evidence-action-owner-workload";
import type { EvidenceAction } from "./evidence-actions";

const a = (id:string, priority:"HIGH"|"MEDIUM"|"LOW"="HIGH"): EvidenceAction => ({
 id,domain:"WEB",controlId:id,source:"DOMAIN",scope:"example",priority,reason:"ERROR",state:"PROPOSED",verifiedRisk:false,
});
describe("action owner workload summary",()=>{
 it("groups overdue and upcoming by owner without losing unassigned items",()=>{
  const plan=buildActionPlan("org",[a("a"),a("b","LOW"),a("c"),a("d"),a("done")],{
   a:{owner:"Alice",dueDate:"2026-10-28"},
   b:{owner:"Alice",dueDate:"2026-11-02"},
   c:{owner:"Bob",dueDate:"2026-10-29"},
   d:{dueDate:"2026-10-30"},
   done:{owner:"Bob",dueDate:"2026-10-01",status:"DONE"}
  })!;
  const deadlines=summarizeActionDeadlines(plan,"org","2026-10-30")!;
  const summary=summarizeActionOwnerWorkload(deadlines,"org")!;
  expect(summary.totalOverdue).toBe(2);
  expect(summary.totalUpcoming).toBe(2);
  expect(summary.assigned.map(x=>[x.owner,x.overdue,x.upcoming,x.highPriority,x.earliestDueDate])).toEqual([
   ["Alice",1,1,1,"2026-10-28"],["Bob",1,0,1,"2026-10-29"]
  ]);
  expect(summary.unassigned).toMatchObject({overdue:0,upcoming:1,highPriority:1,earliestDueDate:"2026-10-30"});
 });
 it("rejects cross-tenant access",()=>{
  const plan=buildActionPlan("org",[a("a")])!;
  const deadlines=summarizeActionDeadlines(plan,"org","2026-10-30")!;
  expect(summarizeActionOwnerWorkload(deadlines,"other")).toBeNull();
 });
 it("handles empty workloads",()=>{
  const plan=buildActionPlan("org",[a("a")])!;
  const deadlines=summarizeActionDeadlines(plan,"org","2026-10-30")!;
  const result=summarizeActionOwnerWorkload(deadlines,"org")!;
  expect(result.assigned).toEqual([]);
  expect(result.totalOverdue).toBe(0);
  expect(result.unassigned.upcoming).toBe(0);
 });
});
