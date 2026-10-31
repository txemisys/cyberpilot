import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { buildActionWorkspace } from "./evidence-action-workspace";
import { exportActionOwnerWorkloadJson } from "./evidence-action-owner-workload-json";
import type { EvidenceAction } from "./evidence-actions";
const action=(id:string):EvidenceAction=>({id,domain:"WEB",controlId:id,source:"DOMAIN",scope:"scope",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false});
describe("offline owner workload JSON handoff",()=>{
 it("exports stable machine-readable owner workload and date",()=>{
  const plan=buildActionPlan("org",[action("a"),action("b")],{a:{owner:"Ops",dueDate:"2026-10-29"},b:{dueDate:"2026-11-01"}},"2026-10-30")!;
  const ws=buildActionWorkspace(plan,[],"org","2026-10-30")!;
  expect(ws.ownerWorkloadJson.filename).toBe("action-owner-workload-2026-10-30.json");
  expect(ws.ownerWorkloadJson.mimeType).toBe("application/json");
  const payload=JSON.parse(ws.ownerWorkloadJson.content);
  expect(payload.schemaVersion).toBe(1);
  expect(payload.organizationId).toBe("org");
  expect(payload.totalOverdue).toBe(1);
  expect(payload.totalUpcoming).toBe(1);
  expect(payload.assigned[0].owner).toBe("Ops");
  expect(payload.unassigned.upcoming).toBe(1);
 });
 it("rejects cross-tenant export and does not mutate inputs",()=>{
  const plan=buildActionPlan("org",[action("a")])!;
  const ws=buildActionWorkspace(plan,[],"org","2026-10-29")!;
  const prior=JSON.stringify(ws.ownerWorkload);
  expect(exportActionOwnerWorkloadJson(ws.ownerWorkload,"foreign")).toBeNull();
  expect(JSON.stringify(ws.ownerWorkload)).toBe(prior);
 });
});
