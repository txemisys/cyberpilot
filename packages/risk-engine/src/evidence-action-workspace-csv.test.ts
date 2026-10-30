import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { buildActionWorkspace } from "./evidence-action-workspace";
import type { EvidenceAction } from "./evidence-actions";
const action=(id:string):EvidenceAction=>({id,domain:"WEB",controlId:id,source:"DOMAIN",scope:"scope",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false});
describe("action workspace CSV handoff",()=>{
 it("includes aggregated owner workload and matching CSV",()=>{
  const plan=buildActionPlan("org",[action("a"),action("b")],{a:{owner:"Ops",dueDate:"2026-10-29"},b:{dueDate:"2026-11-01"}},"2026-10-30")!;
  const ws=buildActionWorkspace(plan,[],"org","2026-10-30");
  expect(ws?.ownerWorkload.totalOverdue).toBe(1);
  expect(ws?.ownerWorkload.totalUpcoming).toBe(1);
  expect(ws?.ownerWorkloadCsv.filename).toBe("action-owner-workload-2026-10-30.csv");
  expect(ws?.ownerWorkloadCsv.organizationId).toBe("org");
  expect(ws?.ownerWorkloadCsv.content).toContain('"Ops","1","0"');
  expect(ws?.ownerWorkloadCsv.content).toContain('"UNASSIGNED","0","1"');
 });
 it("refuses foreign-tenant workspace requests",()=>{
  const plan=buildActionPlan("org",[action("a")])!;
  expect(buildActionWorkspace(plan,[],"foreign","2026-10-30")).toBeNull();
 });
});
