import {describe,expect,it} from "vitest";
import {buildMonthlyWorkload,createWorkloadCsv,summarizeWorkload,workloadClosureRate} from "./remediation-workload";
const d=(value:string)=>new Date(value+"T00:00:00Z");
describe("SME management workload",()=>{
 it("counts recorded actions by state without treating successful execution as verified",()=>{
  const result=summarizeWorkload([
   {status:"PROPOSED",count:2},{status:"APPROVED",count:1},
   {status:"EXECUTING",count:3},{status:"SUCCEEDED",count:5},
   {status:"VERIFIED",count:4},{status:"FAILED",count:1},
  ]);
  expect(result).toEqual({total:16,verified:4,pending:3,inProgress:3,failed:1,other:5});
  expect(workloadClosureRate(result)).toBe(25);
 });
 it("never claims a verified rate for an empty organization",()=>{
  expect(workloadClosureRate(summarizeWorkload([]))).toBeNull();
 });
 it("counts creation month and verification month independently",()=>{
  const result=buildMonthlyWorkload([
   {createdAt:d("2026-01-31"),verifiedAt:d("2026-02-02"),status:"VERIFIED"},
   {createdAt:d("2026-02-05"),verifiedAt:d("2026-02-07"),status:"SUCCEEDED"},
  ]);
  expect(result).toEqual([
   {month:"2026-02",created:1,verified:1},
   {month:"2026-01",created:1,verified:0},
  ]);
 });
 it("uses an explicit 12-month history window and stable descending order",()=>{
  const events=Array.from({length:15},(_,i)=>({
   createdAt:new Date(Date.UTC(2025,i,1)),verifiedAt:null,status:"PROPOSED",
  }));
  const result=buildMonthlyWorkload(events);
  expect(result).toHaveLength(12);
  expect(result[0]?.month).toBe("2026-03");
  expect(result[11]?.month).toBe("2025-04");
 });
 it("generates a spreadsheet-safe numeric monthly CSV",()=>{
  const csv=createWorkloadCsv([{month:"2026-01",created:2,verified:1}]);
  expect(csv).toContain("2026-01,2,1");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
