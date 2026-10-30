import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { applyActionProgress } from "./evidence-action-progress";
import type { EvidenceAction } from "./evidence-actions";
import type { ActionProgressEvent } from "./evidence-action-progress";
import type { PlannedAction } from "./evidence-action-plan";
const action:EvidenceAction={id:"status-guard",domain:"WEB",controlId:"status-guard",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false};
const make=()=>buildActionPlan("org-status",[action])!;
const event:ActionProgressEvent={organizationId:"org-status",actionId:"status-guard",status:"IN_PROGRESS",at:"2026-10-29T12:00:00Z"};
describe("100 forged action status fail-closed regression cases",()=>{
  Array.from({length:50},(_,i)=>`DONE_${i+1}`).forEach((status,i)=>{
    it(`invalid incoming status #${i+1}: ${status}`,()=>{
      const forged={...event,status:status as ActionProgressEvent["status"]};
      const result=applyActionProgress(make(),[forged],"2026-10-30");
      expect(result.applied).toBe(0);
      expect(result.rejected).toEqual([{index:0,reason:"INVALID_TRANSITION"}]);
      expect(result.plan.summary.todo).toBe(1);
    });
  });
  Array.from({length:50},(_,i)=>`TODO_${i+1}`).forEach((status,i)=>{
    it(`invalid stored status #${i+51}: ${status}`,()=>{
      const plan=make();
      plan.actions[0]!.status=status as PlannedAction["status"];
      const result=applyActionProgress(plan,[event],"2026-10-30");
      expect(result.applied).toBe(0);
      expect(result.rejected).toEqual([{index:0,reason:"INVALID_TRANSITION"}]);
    });
  });
});
