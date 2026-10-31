import {describe,expect,it} from "vitest";
import {buildAuditPacket,buildAuditPortfolio,auditPortfolioCsv,auditPacketText} from "./audit-preparation";
import {buildDocumentationGapPlan,deriveDocumentationGaps,documentationGapCsv,documentationGapText} from "./documentation-gap-plan";
import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
const at=(day:string)=>new Date(day+"T12:00:00.000Z");
const action=(status:string):ReviewAction=>({
 id:"action1",title:"Enforce MFA",status,mode:"GUIDED",
 createdAt:at("2026-01-01"),approvedAt:at("2026-01-02"),
 startedAt:at("2026-01-03"),completedAt:status==="SUCCEEDED"?at("2026-01-04"):null,
 verifiedAt:status==="VERIFIED"?at("2026-01-05"):null,
 steps:["Set policy"],verification:["Observe fresh MFA signal"],
 acknowledgedSteps:new Set([0]),
});
const signal=(source:ReviewEvidence["source"]):ReviewEvidence=>({
 id:source,source,category:"IDENTITY",summary:"MFA configuration",
 capturedAt:at("2026-01-02"),lastObservedAt:source==="OBSERVED"?at("2026-01-02"):null,
});
const finding=(overrides:Partial<ReviewFinding>={}):ReviewFinding=>({
 id:"f1",title:"Administrator MFA disabled",
 description:"Privileged sign-in has no MFA",
 severity:"CRITICAL",status:"OPEN",firstSeenAt:at("2026-01-01"),
 lastSeenAt:at("2026-01-03"),resolvedAt:null,
 evidence:[],actions:[],...overrides,
});
describe("Security audit preparation packets",()=>{
 it("evaluates all fifteen documentation questions for a finding",()=>{
  const packet=buildAuditPacket(finding());
  expect(packet.questions).toHaveLength(15);
  expect(packet.questions.map(x=>x.id)).toContain("finding-closure");
  expect(packet.incomplete).toBeGreaterThan(0);
 });
 it("distinguishes documentary support from independent security verification",()=>{
  const packet=buildAuditPacket(finding({actions:[action("VERIFIED")]}));
  const verified=packet.questions.find(x=>x.id==="verified-action");
  expect(verified?.status).toBe("needs-review");
  expect(packet.status).toBe("OPEN");
  expect(packet.limitations.join(" ")).toContain("does not independently verify");
 });
 it("does not accept declarations as authoritative observed signals",()=>{
  const packet=buildAuditPacket(finding({evidence:[signal("DECLARED")]}));
  expect(packet.questions.find(x=>x.id==="observation")?.status).toBe("incomplete");
  expect(packet.questions.find(x=>x.id==="declarations")?.status).toBe("needs-review");
 });
 it("identifies observation timing gaps following completed work",()=>{
  const packet=buildAuditPacket(finding({
   evidence:[signal("OBSERVED")],actions:[action("SUCCEEDED")],
  }));
  expect(packet.questions.find(x=>x.id==="after-work")?.status).toBe("incomplete");
 });
 it("shows absent remediation as not applicable for approval checks",()=>{
  const packet=buildAuditPacket(finding());
  expect(packet.questions.find(x=>x.id==="authorization")?.status).toBe("not-applicable");
  expect(packet.questions.find(x=>x.id==="remediation")?.status).toBe("incomplete");
 });
 it("reports both documented facts and human reviewer requirements",()=>{
  const portfolio=buildAuditPortfolio([
   finding({id:"critical"}),
   finding({id:"low",severity:"LOW"}),
  ]);
  expect(portfolio.findings).toBe(2);
  expect(portfolio.questions).toBe(30);
  expect(portfolio.criticalWithGaps).toBe(1);
  expect(portfolio.packets[0]?.findingId).toBe("critical");
 });
 it("renders auditor handoff without raw evidence provider payloads",()=>{
  const packet=buildAuditPacket(finding());
  const text=auditPacketText(packet);
  expect(text).toContain("AUDIT PREPARATION PACKET");
  expect(text).toContain("Reviewer instruction:");
  expect(text).toContain("not a compliance certificate");
 });
 it("neutralizes formulas in the full audit matrix CSV",()=>{
  const report=buildAuditPortfolio([finding({title:'=HYPERLINK("bad")'})]);
  const csv=auditPortfolioCsv(report);
  expect(csv).toContain("'=HYPERLINK");
  expect(csv.startsWith("\uFEFF")).toBe(true);
 });
});
describe("Documentation gaps and auditor planning",()=>{
 it("generates review tasks for missing and unreviewed data",()=>{
  const tasks=deriveDocumentationGaps(finding());
  expect(tasks.length).toBeGreaterThan(5);
  expect(tasks.every(x=>x.recordedStatus!=="supported")).toBe(true);
  expect(tasks.every(x=>x.recordedStatus!=="not-applicable")).toBe(true);
 });
 it("includes precise record IDs and reviewer instructions for available evidence",()=>{
  const tasks=deriveDocumentationGaps(finding({evidence:[signal("OBSERVED")]}));
  const observation=tasks.find(x=>x.id==="f1:observation");
  expect(observation?.references).toContain("OBSERVED");
  expect(observation?.requiredReviewerAction).toContain("control");
 });
 it("prioritizes incomplete documentation over optional human review",()=>{
  const plan=buildDocumentationGapPlan([
   finding({id:"unaddressed"}),
   finding({id:"observed",evidence:[signal("OBSERVED")]}),
  ]);
  const incompleteIndex=plan.items.findIndex(x=>x.recordedStatus==="incomplete");
  const reviewIndex=plan.items.findIndex(x=>x.recordedStatus==="needs-review");
  expect(incompleteIndex).toBe(0);
  expect(reviewIndex).toBeGreaterThan(incompleteIndex);
 });
 it("counts distinct affected findings and category workloads",()=>{
  const plan=buildDocumentationGapPlan([
   finding({id:"critical"}),
   finding({id:"high",severity:"HIGH"}),
  ]);
  expect(plan.affectedFindings).toBe(2);
  expect(plan.categories).toHaveLength(5);
  expect(plan.total).toBe(plan.missing+plan.requiresReview);
  expect(plan.critical).toBeGreaterThan(0);
 });
 it("produces offline text and spreadsheet-safe CSV without changing inputs",()=>{
  const source=finding({title:'=HYPERLINK("bad")'});
  const before=source.actions.length;
  const plan=buildDocumentationGapPlan([source]);
  expect(source.actions.length).toBe(before);
  expect(documentationGapText(plan)).toContain("DOCUMENTATION GAPS");
  expect(documentationGapCsv(plan)).toContain("'=HYPERLINK");
 });
 it("supports empty selection without inventing compliance claims",()=>{
  const plan=buildDocumentationGapPlan([]);
  expect(plan.total).toBe(0);
  expect(plan.affectedFindings).toBe(0);
  expect(documentationGapText(plan)).toContain("Review questions: 0");
 });
});
