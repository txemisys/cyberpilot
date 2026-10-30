import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { applyActionProgress } from "./evidence-action-progress";
import type { EvidenceAction } from "./evidence-actions";
import type { ActionProgressEvent } from "./evidence-action-progress";
const action:EvidenceAction={id:"note-test",domain:"WEB",controlId:"note-test",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false};
const plan=()=>buildActionPlan("org-notes",[action])!;
const event=(note:string):ActionProgressEvent=>({organizationId:"org-notes",actionId:"note-test",status:"IN_PROGRESS",at:"2026-10-29T12:00:00Z",note});
const controlCodes=[0,1,2,3,4,5,6,7,8,11,12,14,15,16,17,18,19,20,21,22,23,24,25,26,127];
describe("100 action progress note character acceptance checks",()=>{
  controlCodes.forEach((code,i)=>{
    for (const [position,create] of [["prefix",(s:string)=>s+"safe"],["suffix",(s:string)=>"safe"+s]] as const) {
      it(`invalid #${i+1} ${position} control U+${code.toString(16).padStart(4,"0")}`,()=>{
        const result=applyActionProgress(plan(),[event(create(String.fromCharCode(code)))],"2026-10-30");
        expect(result.applied).toBe(0);
        expect(result.rejected).toEqual([{index:0,reason:"INVALID_NOTE"}]);
      });
    }
  });
  Array.from({length:50},(_,i)=>"Update "+String(i+1).padStart(2,"0")+" — ✓ completed").forEach((note,i)=>{
    it(`valid #${i+51} readable note`,()=>{
      const result=applyActionProgress(plan(),[event(note)],"2026-10-30");
      expect(result.applied).toBe(1);
      expect(result.rejected).toEqual([]);
      expect(result.plan.actions[0]?.notes).toBe(note);
    });
  });
});
