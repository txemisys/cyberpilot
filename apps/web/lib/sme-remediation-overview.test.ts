import { describe, expect, it } from "vitest";
import { buildSmeRemediationOverview } from "./sme-remediation-overview";
const item=(id:string,status:string,steps:unknown=["Check","Correct","Confirm"])=>({
 id,title:"Action "+id,mode:"GUIDED" as const,status,steps,finding:{status:"OPEN"},
});
describe("SME remediation progress overview",()=>{
 it("distinguishes acknowledgment from evidence-based verification",()=>{
  const progress=new Map([["a",new Set([0,1,2])]]);
  const result=buildSmeRemediationOverview([item("a","PROPOSED"),item("b","VERIFIED")],progress);
  expect(result.visibleCount).toBe(2);
  expect(result.verified).toBe(1);
  expect(result.items[0]).toMatchObject({id:"a",label:"Needs fresh evidence to verify",percentComplete:100,needsVerification:true});
  expect(result.items[1]).toMatchObject({id:"b",label:"Verified with evidence",needsVerification:false});
 });
 it("ignores invalid, duplicate and out-of-range acknowledgments",()=>{
  const result=buildSmeRemediationOverview([item("a","EXECUTING")],new Map([["a",new Set([-1,0,0,100])]]));
  expect(result.inProgress).toBe(1);
  expect(result.items[0]?.completedSteps).toBe(1);
  expect(result.items[0]?.percentComplete).toBe(33);
 });
 it("groups ready, ongoing and verification-needed work",()=>{
  const result=buildSmeRemediationOverview([item("a","APPROVED"),item("b","EXECUTING"),item("c","SUCCEEDED")],new Map());
  expect(result.waitingForAction).toBe(1);
  expect(result.inProgress).toBe(1);
  expect(result.awaitingVerification).toBe(1);
  expect(result.items[0]?.id).toBe("c");
 });
 it("returns no fabricated steps for automated remediation",()=>{
  const result=buildSmeRemediationOverview([{...item("a","PROPOSED"),mode:"AUTOMATED"}],new Map());
  expect(result.items[0]?.percentComplete).toBeNull();
  expect(result.items[0]?.completedSteps).toBe(0);
 });
 it("does not mutate operational records",()=>{
  const actions=[item("a","PROPOSED")];const before=JSON.stringify(actions);
  buildSmeRemediationOverview(actions,new Map());
  expect(JSON.stringify(actions)).toBe(before);
 });
});
