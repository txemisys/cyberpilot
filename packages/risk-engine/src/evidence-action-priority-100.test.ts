import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import type { EvidenceAction } from "./evidence-actions";
const make=(id:string,priority:EvidenceAction["priority"]):EvidenceAction=>({id,domain:"WEB",controlId:id,source:"DOMAIN",scope:"example",priority,reason:"ERROR",state:"PROPOSED",verifiedRisk:false});
describe("100 offline action plan priority acceptance checks",()=>{
  Array.from({length:50},(_,i)=>"FORGED_PRIORITY_"+(i+1)).forEach((priority,i)=>{
    it(`reject forged priority #${i+1}`,()=>{
      const plan=buildActionPlan("org",[make("a",priority as EvidenceAction["priority"])]);
      expect(plan).toBeNull();
    });
  });
  Array.from({length:50},(_,i)=>i).forEach(i=>{
    it(`accept recognized priority #${i+51}`,()=>{
      const priority=(["HIGH","MEDIUM","LOW"] as const)[i%3]!;
      const plan=buildActionPlan("org",[make("action-"+i,priority)]);
      expect(plan?.actions[0]?.priority).toBe(priority);
      expect(plan?.summary.high).toBe(priority==="HIGH"?1:0);
      expect(plan?.summary.medium).toBe(priority==="MEDIUM"?1:0);
      expect(plan?.summary.low).toBe(priority==="LOW"?1:0);
    });
  });
});
