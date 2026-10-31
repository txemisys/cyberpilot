import {describe,expect,it} from "vitest";
import {
 buildWeeklySecurityBriefing,formatWeeklySecurityBriefing,weeklyBriefingActionsCsv,
} from "./security-operations-briefing";
import {createWorkstreamPlan,workstreamPlanCsv,workstreamPlanText} from "./security-workstreams";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
const date=(day:string)=>new Date(day+"T12:00:00Z");
const remediation=(status:string):ReviewAction=>({
 id:"action1",title:"Protect administrator access",
 status,mode:"GUIDED",createdAt:date("2026-01-01"),
 approvedAt:date("2026-01-02"),startedAt:null,
 completedAt:status==="SUCCEEDED"?date("2026-01-05"):null,
 verifiedAt:status==="VERIFIED"?date("2026-01-06"):null,
 steps:["Enable MFA","Review sign in"],
 verification:["Observe MFA after policy update"],
 acknowledgedSteps:new Set([0]),
});
const signal=(source:ReviewEvidence["source"]):ReviewEvidence=>({
 id:source,source,category:"IDENTITY",summary:"MFA control",
 capturedAt:date("2026-01-02"),
 lastObservedAt:source==="OBSERVED"?date("2026-01-02"):null,
});
const finding=(overrides:Partial<ReviewFinding>={}):ReviewFinding=>({
 id:"finding1",title:"Privileged MFA disabled",
 description:"Missing multifactor authentication",
 severity:"CRITICAL",status:"OPEN",
 firstSeenAt:date("2026-01-01"),lastSeenAt:date("2026-01-03"),
 resolvedAt:null,evidence:[],actions:[],...overrides,
});
describe("Security operations leadership briefing",()=>{
 it("produces usable empty briefing without pretending security is verified",()=>{
  const result=buildWeeklySecurityBriefing([],"Example");
  expect(result.findings).toBe(0);
  expect(result.sections).toHaveLength(4);
  expect(result.nextActions).toHaveLength(0);
  expect(formatWeeklySecurityBriefing(result)).toContain("not a new scan");
 });
 it("combines operational decisions and verification evidence gaps",()=>{
  const result=buildWeeklySecurityBriefing([
   finding({actions:[remediation("SUCCEEDED")],evidence:[signal("OBSERVED")]}),
  ],"Example");
  expect(result.criticalFindings).toBe(1);
  expect(result.verificationBacklog).toBe(1);
  expect(result.nextActions[0]?.priority).toBe("critical");
  expect(result.evidenceGaps).toBeGreaterThanOrEqual(1);
 });
 it("keeps declared signals distinct from observed findings",()=>{
  const result=buildWeeklySecurityBriefing([
   finding({evidence:[signal("DECLARED")]}),
  ],"Example");
  expect(result.declarationOnlyFindings).toBe(1);
  expect(result.observedFindings).toBe(0);
 });
 it("does not mutate input when ranking sections",()=>{
  const input=[
   finding({id:"low",severity:"LOW"}),
   finding({id:"critical",severity:"CRITICAL"}),
  ];
  const ids=input.map(x=>x.id);
  buildWeeklySecurityBriefing(input,"Example");
  expect(input.map(x=>x.id)).toEqual(ids);
 });
 it("exports formula-safe briefing actions for spreadsheet handoff",()=>{
  const report=buildWeeklySecurityBriefing([
   finding({title:'=HYPERLINK("unsafe")'}),
  ],"Example");
  const csv=weeklyBriefingActionsCsv(report);
  expect(csv.startsWith("\uFEFF")).toBe(true);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv).toContain("Evidence criteria");
 });
 it("includes source limitations and actionable checks in the printed agenda",()=>{
  const report=buildWeeklySecurityBriefing([
   finding({actions:[remediation("PROPOSED")]}),
  ],"Example");
  const text=formatWeeklySecurityBriefing(report);
  expect(text).toContain("Approvals and pending operational work");
  expect(text).toContain("Next step:");
  expect(text).toContain("CyberScore");
 });
});
describe("Security responsibility workstream plan",()=>{
 it("organizes verification, investigation, approvals and execution roles",()=>{
  const report=createWorkstreamPlan([
   finding({id:"verify",actions:[remediation("SUCCEEDED")]}),
   finding({id:"investigate"}),
   finding({id:"approve",actions:[remediation("PROPOSED")]}),
   finding({id:"execute",actions:[remediation("APPROVED")]}),
  ]);
  expect(report.total).toBe(4);
  expect(report.streams.find(x=>x.stream==="evidence")?.total).toBe(1);
  expect(report.streams.find(x=>x.stream==="investigation")?.total).toBe(1);
  expect(report.streams.find(x=>x.stream==="approval")?.total).toBe(1);
  expect(report.streams.find(x=>x.stream==="execution")?.total).toBe(1);
 });
 it("explicitly describes suggested roles rather than assigning a user",()=>{
  const report=createWorkstreamPlan([finding()]);
  expect(report.items[0]?.ownerRole).toBe("Security investigator");
  expect(report.items[0]?.criteria.length).toBeGreaterThan(0);
  expect(workstreamPlanText(report)).toContain("Does not create staff assignments");
 });
 it("records evidence gaps without inventing new observed evidence",()=>{
  const report=createWorkstreamPlan([
   finding({evidence:[signal("DECLARED")]}),
  ]);
  expect(report.noMatchedEvidence).toBe(0);
  expect(report.items[0]?.workstream).toBe("investigation");
 });
 it("protects workstream exports against formula injection",()=>{
  const report=createWorkstreamPlan([
   finding({title:'=HYPERLINK("unsafe")'}),
  ]);
  const csv=workstreamPlanCsv(report);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
 it("produces a valid empty workstream report",()=>{
  const report=createWorkstreamPlan([]);
  expect(report.total).toBe(0);
  expect(report.streams).toHaveLength(5);
  expect(workstreamPlanText(report)).toContain("Findings assessed: 0");
 });
});
