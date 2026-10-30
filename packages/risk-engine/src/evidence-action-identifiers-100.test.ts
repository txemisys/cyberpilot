import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import type { EvidenceAction } from "./evidence-actions";
const action=(id:string):EvidenceAction=>({id,domain:"WEB",controlId:"control",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false});
describe("100 organization and action identifier acceptance checks",()=>{
  const invalid:unknown[]=[""," ","  ","\t","\n","\r","\u00a0","\u2003","\u202f","\ufeff",0,1,-1,false,true,null,undefined,{},[],["x"],{"id":"x"},new Date("2026-10-29"),Symbol("id"),0n,NaN];
  invalid.forEach((id,i)=>{
    it(`invalid organization ID #${i+1}`,()=>expect(buildActionPlan(id as string,[action("ok")])).toBeNull());
    it(`invalid action ID #${i+26}`,()=>expect(buildActionPlan("org",[action(id as string)])).toBeNull());
  });
  Array.from({length:25},(_,i)=>`org-${i+1}`).forEach((id,i)=>{
    it(`valid organization ID #${i+51}`,()=>{
      const plan=buildActionPlan(id,[action("ok")]);
      expect(plan?.organizationId).toBe(id);
      expect(plan?.summary.total).toBe(1);
    });
  });
  Array.from({length:25},(_,i)=>`action-${i+1}`).forEach((id,i)=>{
    it(`valid action ID #${i+76}`,()=>{
      const plan=buildActionPlan("org",[action(id)]);
      expect(plan?.actions[0]?.id).toBe(id);
      expect(plan?.summary.total).toBe(1);
    });
  });
});
