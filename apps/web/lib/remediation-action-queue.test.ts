import {describe,expect,it} from "vitest";
import {classifyActionQueue,prioritizeActionQueue,summarizeActionQueue,type ActionQueueRow} from "./remediation-action-queue";
const example=(id:string,status:string,severity="HIGH"):ActionQueueRow=>({
 id,title:"Action "+id,status,mode:"GUIDED",severity,findingStatus:"OPEN",
 createdAt:new Date("2026-01-01T00:00:00Z"),verifiedAt:null,
 stepCount:2,acknowledgedCount:0,
});
describe("SME remediation work queue",()=>{
 it("requires evidence review after all guided steps are acknowledged",()=>{
  const result=classifyActionQueue({...example("a","APPROVED"),acknowledgedCount:2});
  expect(result.bucket).toBe("verify");
  expect(result.nextAction).toContain("fresh evidence");
  expect(result.progressPercent).toBe(100);
 });
 it("does not present succeeded work as a verified security finding",()=>{
  const result=classifyActionQueue(example("a","SUCCEEDED"));
  expect(result.bucket).toBe("verify");
 });
 it("prioritizes evidence review, failed operations and critical findings",()=>{
  const list=prioritizeActionQueue([
   example("proposed","PROPOSED"),
   example("failed","FAILED","CRITICAL"),
   {...example("verify","APPROVED","MEDIUM"),acknowledgedCount:2},
   example("critical","PROPOSED","CRITICAL"),
  ]);
  expect(list.map(x=>x.id)).toEqual(["verify","failed","critical","proposed"]);
  expect(summarizeActionQueue(list)).toMatchObject({total:4,verify:1,failed:1,unstarted:2,needsAttention:4});
 });
 it("requires verified state and recorded timestamp to classify verified",()=>{
  expect(classifyActionQueue(example("v","VERIFIED")).bucket).not.toBe("verified");
  expect(classifyActionQueue({...example("v","VERIFIED"),verifiedAt:new Date()}).bucket).toBe("verified");
 });
 it("keeps original source order and values unchanged",()=>{
  const input=[example("b","PROPOSED"),example("a","PROPOSED")];
  const before=JSON.stringify(input);
  expect(prioritizeActionQueue(input).map(x=>x.id)).toEqual(["a","b"]);
  expect(JSON.stringify(input)).toBe(before);
 });
});
