import { describe, it, expect } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import type { EvidenceAction } from "./evidence-actions";
const action: EvidenceAction = { id:"calendar",domain:"WEB",controlId:"calendar",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false };
const valid=["2024-02-29","2000-02-29","2400-02-29","2028-02-29","2032-02-29","2036-02-29","2040-02-29","2044-02-29","2048-02-29","2052-02-29","2026-01-31","2026-03-31","2026-05-31","2026-07-31","2026-08-31","2026-10-31","2026-12-31","2026-04-30","2026-06-30","2026-09-30","2026-11-30","2026-02-28","2025-02-28","2100-02-28","2026-10-29"] as const;
const invalid=["2026-02-29","2025-02-29","2100-02-29","1900-02-29","2026-02-30","2026-02-31","2026-04-31","2026-06-31","2026-09-31","2026-11-31","2026-01-32","2026-03-32","2026-05-32","2026-07-32","2026-08-32","2026-10-32","2026-12-32","2026-00-01","2026-13-01","2026-10-00","2026/10/29","2026-1-29","2026-10-9","2026-10-29T00:00:00Z","not-a-date"] as const;
describe("100 calendar acceptance cases for offline action plans",()=>{
  valid.forEach((day,i)=>{
    it(`valid asOf ${i+1}: ${day}`,()=>expect(buildActionPlan("org",[action],{},day)).not.toBeNull());
    it(`valid dueDate ${i+26}: ${day}`,()=>expect(buildActionPlan("org",[action],{calendar:{dueDate:day}},"2026-10-29")).not.toBeNull());
  });
  invalid.forEach((day,i)=>{
    it(`invalid asOf ${i+51}: ${day}`,()=>expect(buildActionPlan("org",[action],{},day)).toBeNull());
    it(`invalid dueDate ${i+76}: ${day}`,()=>expect(buildActionPlan("org",[action],{calendar:{dueDate:day}},"2026-10-29")).toBeNull());
  });
});
