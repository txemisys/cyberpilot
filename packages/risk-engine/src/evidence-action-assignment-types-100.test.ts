import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import type { EvidenceAction } from "./evidence-actions";
const a:EvidenceAction={id:"assignment",domain:"WEB",controlId:"assignment",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false};
const build=(assignment:Record<string,unknown>)=>buildActionPlan("org",[a],{assignment:assignment as {owner?:string|null;notes?:string|null}});
const invalid:unknown[]=[0,1,-1,42,true,false,[],[1],{},{"x":1},()=>1,Symbol("x"),0n,NaN,Infinity,-Infinity,new Date("2026-10-29"),new Set(),new Map(),["name"],{trim:"x"},/regex/,Promise.resolve("a"),new Uint8Array([1]),["a","b"]];
describe("100 action-plan assignment field type acceptance checks",()=>{
  invalid.forEach((value,i)=>{
    it(`reject malformed owner #${i+1}`,()=>expect(build({owner:value})).toBeNull());
    it(`reject malformed notes #${i+26}`,()=>expect(build({notes:value})).toBeNull());
  });
  Array.from({length:25},(_,i)=>`owner-${i+1}`).forEach((value,i)=>{
    it(`accept owner string #${i+51}`,()=>{
      const result=build({owner:value});expect(result?.actions[0]?.owner).toBe(value);
    });
  });
  Array.from({length:25},(_,i)=>`note-${i+1}`).forEach((value,i)=>{
    it(`accept note string #${i+76}`,()=>{
      const result=build({notes:value});expect(result?.actions[0]?.notes).toBe(value);
    });
  });
});
