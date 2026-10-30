import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { summarizeActionDeadlines } from "./evidence-action-deadlines";
import type { EvidenceAction } from "./evidence-actions";
const action=(id:string, priority:"HIGH"|"MEDIUM"|"LOW"="HIGH"):EvidenceAction=>({
  id,domain:"WEB",controlId:id,source:"DOMAIN",scope:"example",priority,
  reason:"ERROR",state:"PROPOSED",verifiedRisk:false,
});
describe("offline action deadline scheduling",()=>{
  it("splits overdue and upcoming without including future or completed items",()=>{
    const plan=buildActionPlan("org",[
      action("overdue"),action("today"),action("soon"),action("future"),action("done")
    ],{
      overdue:{dueDate:"2026-10-28",owner:"Ops"},
      today:{dueDate:"2026-10-30"},
      soon:{dueDate:"2026-11-03",owner:"Alice"},
      future:{dueDate:"2026-11-30"},
      done:{dueDate:"2026-10-20",status:"DONE"},
    },"2026-10-30")!;
    const result=summarizeActionDeadlines(plan,"org","2026-10-30",7)!;
    expect(result.overdue.map(x=>[x.actionId,x.daysRemaining])).toEqual([["overdue",-2]]);
    expect(result.upcoming.map(x=>[x.actionId,x.daysRemaining])).toEqual([["today",0],["soon",4]]);
    expect(result.unassignedUpcoming).toBe(1);
    expect(plan.actions.find(x=>x.id==="today")?.status).toBe("TODO");
  });
  it("sorts by date, risk priority and action ID",()=>{
    const plan=buildActionPlan("org",[action("b","LOW"),action("c","HIGH"),action("a","HIGH")],{
      a:{dueDate:"2026-11-01"},b:{dueDate:"2026-11-01"},c:{dueDate:"2026-11-01"}
    })!;
    expect(summarizeActionDeadlines(plan,"org","2026-10-30")?.upcoming.map(x=>x.actionId)).toEqual(["a","c","b"]);
  });
  it("enforces tenant and valid scheduling windows",()=>{
    const plan=buildActionPlan("org",[action("a")])!;
    expect(summarizeActionDeadlines(plan,"other","2026-10-30")).toBeNull();
    expect(summarizeActionDeadlines(plan,"org","2026-02-30")).toBeNull();
    expect(summarizeActionDeadlines(plan,"org","2026-10-30",-1)).toBeNull();
    expect(summarizeActionDeadlines(plan,"org","2026-10-30",91)).toBeNull();
    expect(summarizeActionDeadlines(plan,"org","2026-10-30",1.5)).toBeNull();
  });
  it("accepts a zero-day window, excludes undated actions",()=>{
    const plan=buildActionPlan("org",[action("today"),action("undated")],{today:{dueDate:"2026-10-30"}})!;
    expect(summarizeActionDeadlines(plan,"org","2026-10-30",0)?.upcoming.map(x=>x.actionId)).toEqual(["today"]);
  });
  it("does not silently normalize forged impossible due dates",()=>{
    const plan=buildActionPlan("org",[action("a")])!;
    plan.actions[0]!.dueDate="2026-02-30";
    expect(summarizeActionDeadlines(plan,"org","2026-10-30")).toBeNull();
  });
});
