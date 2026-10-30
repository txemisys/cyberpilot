import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { applyActionProgress } from "./evidence-action-progress";
import type { EvidenceAction } from "./evidence-actions";
import type { ActionProgressEvent } from "./evidence-action-progress";

const action: EvidenceAction={id:"precision",domain:"WEB",controlId:"precision",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false};
const plan=()=>buildActionPlan("org-precision",[action])!;
const event=(at:string):ActionProgressEvent=>({organizationId:"org-precision",actionId:"precision",status:"IN_PROGRESS",at});
// 50 representable timestamps across 1-, 2- and 3-digit millisecond precision.
const valid=Array.from({length:50},(_,i)=>{
  const fraction=i%3===0?String((i%9)+1):i%3===1?String(10+i):String(100+i);
  const minute=String(i%60).padStart(2,"0");
  return `2026-10-29T12:${minute}:00.${fraction}Z`;
});
// 50 4- to 6-digit fractions which JavaScript dates silently truncate to milliseconds.
const invalid=Array.from({length:50},(_,i)=>{
  const fraction=String(1000+i).padStart(4,"0")+"1".repeat(i%3);
  const minute=String(i%60).padStart(2,"0");
  return `2026-10-29T12:${minute}:00.${fraction}Z`;
});
describe("100 fractional UTC timestamp precision acceptance cases",()=>{
  valid.forEach((at,i)=>it(`valid #${i+1}: ${at}`,()=>{
    const result=applyActionProgress(plan(),[event(at)],"2026-10-30");
    expect(result.applied).toBe(1);
    expect(result.rejected).toEqual([]);
  }));
  invalid.forEach((at,i)=>it(`invalid #${i+51}: ${at}`,()=>{
    const result=applyActionProgress(plan(),[event(at)],"2026-10-30");
    expect(result.applied).toBe(0);
    expect(result.rejected).toEqual([{index:0,reason:"INVALID_TIME"}]);
  }));
});
