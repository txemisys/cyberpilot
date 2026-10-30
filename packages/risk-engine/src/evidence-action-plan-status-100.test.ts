import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import type { EvidenceAction } from "./evidence-actions";
import type { PlannedAction } from "./evidence-action-plan";
const make=(id:string):EvidenceAction=>({id,domain:"WEB",controlId:id,source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false});
const valid=["TODO","IN_PROGRESS","BLOCKED","DONE"] as const;
describe("100 offline action plan assignment status acceptance checks",()=>{
  Array.from({length:50},(_,i)=>"UNKNOWN_STATUS_"+String(i+1)).forEach((status,i)=>{
    it(`invalid assignment #${i+1}: ${status}`,()=>{
      const id="action-"+i;
      expect(buildActionPlan("org",[make(id)],{[id]:{status:status as PlannedAction["status"]}})).toBeNull();
    });
  });
  Array.from({length:50},(_,i)=>i).forEach(i=>{
    it(`valid assignment #${i+51}: ${valid[i%4]} on action ${i}`,()=>{
      const id="action-"+i; const status=valid[i%4]!;
      const plan=buildActionPlan("org",[make(id)],{[id]:{status}});
      expect(plan).not.toBeNull();
      expect(plan?.actions[0]?.status).toBe(status);
      expect(plan?.summary.total).toBe(1);
      expect(plan?.summary[status==="TODO"?"todo":status==="IN_PROGRESS"?"inProgress":status==="BLOCKED"?"blocked":"done"]).toBe(1);
    });
  });
});
