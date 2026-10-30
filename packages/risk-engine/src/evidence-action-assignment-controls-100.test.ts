import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import type { EvidenceAction } from "./evidence-actions";
const action:EvidenceAction={id:"control",domain:"WEB",controlId:"control",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false};
const build=(owner:string|null,notes:string|null)=>buildActionPlan("org",[action],{control:{owner,notes}});
const codes=[0,1,2,3,4,5,6,7,8,11,12,14,15,16,17,18,19,20,21,22,23,24,25,26,127] as const;
describe("100 action assignment text control character acceptance cases",()=>{
  codes.forEach((code,i)=>{
    it(`invalid owner #${i+1}: U+${code.toString(16)}`,()=>{
      expect(build("owner"+String.fromCharCode(code),null)).toBeNull();
    });
    it(`invalid note #${i+26}: U+${code.toString(16)}`,()=>{
      expect(build(null,"note"+String.fromCharCode(code))).toBeNull();
    });
  });
  Array.from({length:25},(_,i)=>"Owner "+(i+1)+" ✓").forEach((owner,i)=>{
    it(`valid owner #${i+51}`,()=>{
      expect(build(owner,null)?.actions[0]?.owner).toBe(owner);
    });
  });
  Array.from({length:25},(_,i)=>"Note "+(i+1)+" ✓").forEach((notes,i)=>{
    it(`valid note #${i+76}`,()=>{
      expect(build(null,notes)?.actions[0]?.notes).toBe(notes);
    });
  });
});
