import{describe,it,expect}from "vitest";
import{buildTrendReport,verifyTrendReport,selectTrendPoints,
 compareTrendReports,exportTrendReport,type TrendInput}
 from "./offline-longitudinal-trends";
import{buildTrendReviewPlan,filterTrendReviewPlan}
 from "./offline-trend-review-plan";
const at="2026-11-17T10:00:00.000Z";
function fixture():TrendInput{
 return{
  organizationId:"org-test",evaluatedAt:at,
  assessments:[
   {id:"id-one",organizationId:"org-test",
    snapshotId:"snapshot-one",modelId:"cyberpilot.multisource.v2",
    modelRevision:1,evaluatedAt:"2026-11-15T10:00:00.000Z",
    score:null,status:"INSUFFICIENT_COVERAGE",
    coveragePercent:20,verifiedControls:2,totalControls:10,
    riskPoints:10,sourceClass:"SYNTHETIC_OFFLINE",
    reportDigest:"a".repeat(64),manifestDigest:"b".repeat(64)},
   {id:"id-two",organizationId:"org-test",
    snapshotId:"snapshot-two",modelId:"cyberpilot.multisource.v2",
    modelRevision:1,evaluatedAt:"2026-11-16T10:00:00.000Z",
    score:75,status:"ASSESSED_WITH_LIMITATIONS",
    coveragePercent:50,verifiedControls:5,totalControls:10,
    riskPoints:5,sourceClass:"SYNTHETIC_OFFLINE",
    reportDigest:"c".repeat(64),manifestDigest:"d".repeat(64)},
  ],
  actions:[],events:[],
  sourceCounts:{assessments:2,actions:0,events:0},
  caps:{assessments:200,actions:500,events:2000},
 };
}
describe("strictly bounded offline longitudinal comparisons",()=>{
 it("preserves null scores and synthetic origin",()=>{
  const report=buildTrendReport(fixture());
  expect(report.points).toHaveLength(2);
  expect(report.summary.syntheticSnapshots).toBe(2);
  expect(report.summary.nullScores).toBe(1);
  expect(report.pairs[0]?.comparable).toBe(false);
  expect(report.pairs[0]?.scoreDelta).toBeNull();
  expect(report.customerRiskReductionCertified).toBe(false);
  expect(verifyTrendReport(report,"org-test").valid).toBe(true);
 });
 it("allows an arithmetic delta only between compatible stored snapshots",()=>{
  const input=fixture();input.assessments[0]!.score=70;
  const report=buildTrendReport(input);
  expect(report.pairs[0]?.comparable).toBe(true);
  expect(report.pairs[0]?.scoreDelta).toBe(5);
  expect(report.pairs[0]?.coverageDelta).toBe(30);
  expect(report.pairs[0]?.externallyVerifiedImprovement).toBe(false);
 });
 it("blocks incompatible model, revision and source authenticity",()=>{
  const input=fixture();input.assessments[0]!.score=70;
  input.assessments[1]!.modelRevision=2;
  let report=buildTrendReport(input);
  expect(report.pairs[0]?.comparable).toBe(false);
  expect(report.pairs[0]?.comparisonClass)
   .toBe("INCOMPATIBLE_REVISION");
  input.assessments[1]!.modelRevision=1;
  input.assessments[1]!.sourceClass="AUTHENTICATED_LIVE";
  report=buildTrendReport(input);
  expect(report.pairs[0]?.comparisonClass)
   .toBe("INCOMPATIBLE_SOURCE_CLASS");
 });
 it("refuses cross-tenant history and marks truncated sources",()=>{
  const input=fixture();
  input.assessments[0]!.organizationId="foreign-org";
  expect(()=>buildTrendReport(input)).toThrow("CROSS_TENANT");
  input.assessments[0]!.organizationId="org-test";
  input.sourceCounts.assessments=250;
  const report=buildTrendReport(input);
  expect(report.outcome).toBe("INCOMPLETE");
  expect(report.sourceComplete).toBe(false);
 });
 it("never rewrites CyberScore or verifies actual reduction",()=>{
  const report=buildTrendReport(fixture());
  const plan=buildTrendReviewPlan(report);
  expect(plan.certifiedRiskReduction).toBe(false);
  expect(plan.externalCalls).toBe(0);
  expect(plan.summary.reviews).toBeGreaterThan(0);
  expect(filterTrendReviewPlan(plan,{urgency:"REVIEW"})
   .every(x=>x.urgency==="REVIEW")).toBe(true);
  expect(report.historicalCyberScoreChanged).toBe(false);
 });
 it("supports filtered paging without mixing model versions",()=>{
  const value=buildTrendReport(fixture());
  const page=selectTrendPoints(value,{
   sourceKinds:["SYNTHETIC"],offset:0,limit:1,
  });
  expect(page.items).toHaveLength(1);
  expect(page.nextOffset).toBe(1);
  expect(page.fullCoverageCertified).toBe(false);
  expect(()=>selectTrendPoints(value,{limit:201})).toThrow();
 });
 it("detects integrity tampering and exports safe formats",()=>{
  const value=buildTrendReport(fixture());
  expect(exportTrendReport(value,"CSV").content)
   .toContain("snapshot-two");
  expect(exportTrendReport(value,"MARKDOWN").content)
   .toContain("No actual customer security improvement");
  value.customerRiskReductionCertified=true as false;
  expect(verifyTrendReport(value).valid).toBe(false);
 });
 it("compares read windows without inventing a real security trend",()=>{
  const before=buildTrendReport(fixture());
  const input=fixture();
  input.evaluatedAt="2026-11-17T11:00:00.000Z";
  const after=buildTrendReport(input);
  const diff=compareTrendReports(before,after);
  expect(diff.scoreImprovementIndependentlyEstablished).toBe(false);
  expect(diff.historicalV1ScoreComparable).toBe(false);
 });
});
