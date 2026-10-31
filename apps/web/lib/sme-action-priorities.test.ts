import { describe, expect, it } from "vitest";
import { buildSmeActionPriorities } from "./sme-action-priorities";
const source=(id:string)=>({id,lastSeenAt:new Date("2026-10-01T00:00:00Z")});
const action=(id:string)=>({id,title:"Finding "+id,severity:"HIGH"});
const remediation=(id:string,status:string)=>({
 id:"r-"+id,finding:{id,status:"OPEN"},status,createdAt:new Date("2026-10-02T00:00:00Z"),
});
describe("SME guided priorities",()=>{
 it("never implies scanned evidence before the first scan",()=>{
  expect(buildSmeActionPriorities(false,[action("a")],[source("a")],[])).toEqual([]);
 });
 it("presents at most three distinct findings with navigable evidence",()=>{
  const result=buildSmeActionPriorities(true,["a","a","b","c","d","e"].map(action),["a","b","c","d","e"].map(source),[]);
  expect(result.map(x=>x.id)).toEqual(["a","b","c"]);
  expect(result.every(x=>x.status==="NEEDS_REVIEW"&&x.href.startsWith("#finding-"))).toBe(true);
 });
 it("distinguishes active remediation from available proposal",()=>{
  const result=buildSmeActionPriorities(true,[action("a"),action("b")],[source("a"),source("b")],[remediation("a","EXECUTING"),remediation("b","PROPOSED")]);
  expect(result.map(x=>x.status)).toEqual(["IN_PROGRESS","READY"]);
  expect(result.map(x=>x.href)).toEqual(["#remediation-r-a","#remediation-r-b"]);
 });
 it("does not display unsupported or resolved evidence as active priorities",()=>{
  const result=buildSmeActionPriorities(true,[action("absent"),action("a")],[source("a")],[{...remediation("a","APPROVED"),finding:{id:"a",status:"RESOLVED"}}]);
  expect(result).toHaveLength(1);
  expect(result[0].status).toBe("NEEDS_REVIEW");
 });
});
