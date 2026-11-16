import {describe,it,expect} from "vitest";
import {buildIntegratedRiskDigest,verifyIntegratedRiskDigest,
  compareIntegratedRiskDigests,exportIntegratedRiskDigest,
  type IntegratedRiskInput} from "./integrated-risk-engine";
const now="2026-11-16T17:00:00.000Z";
function fixture():IntegratedRiskInput{
  return{
    organizationId:"org-test",evaluatedAt:now,
    sourceLimits:{
      evidence:100,findings:100,assessments:20,declaredActions:100,
    },
    countOfRecords:{
      evidence:3,findings:2,assessments:1,declaredActions:1,
    },
    evidence:[
      {id:"evidence-one",organizationId:"org-test",source:"BASELINE",
        domain:"GOVERNANCE",controlId:"BACKUP_TEST",scope:"org",
        state:"DECLARED",observedAt:now,createdAt:now,details:{}},
      {id:"evidence-two",organizationId:"org-test",source:"ASSETS",
        domain:"ENDPOINT",controlId:"DEVICE_PATCH",scope:"device-01",
        state:"UNKNOWN",observedAt:null,createdAt:now,details:{}},
      {id:"evidence-three",organizationId:"org-test",source:"EXPOSURE",
        domain:"EMAIL",controlId:"SPF",scope:"example.com",
        state:"ERROR",observedAt:null,createdAt:now,details:{}},
    ],
    findings:[
      {id:"finding-one",organizationId:"org-test",ruleId:"BACKUP_TEST",
        key:"backup-in-scope",severity:"HIGH",status:"OPEN",
        title:"Backup not confirmed",description:"Declaration only",
        lastSeenAt:now,evidence:{}},
      {id:"finding-two",organizationId:"org-test",ruleId:"SPF",
        key:"spf-domain",severity:"MEDIUM",status:"RESOLVED",
        title:"SPF check",description:"Previously observed",
        lastSeenAt:now,evidence:{}},
    ],
    assessments:[{
      id:"assessment-one",organizationId:"org-test",
      snapshotId:"snapshot-synthetic",
      modelId:"cyberpilot.multisource.v2",modelRevision:1,
      status:"INSUFFICIENT_COVERAGE",score:null,
      coveragePercent:0,sourceClass:"SYNTHETIC_OFFLINE",
      evaluatedAt:now,reportDigest:"a".repeat(64),
      manifestDigest:"b".repeat(64),
      verifiedControls:0,totalControls:19,
    }],
    declaredActions:[{
      id:"action-one",organizationId:"org-test",
      questionId:"BACKUP_TEST",sourceDraftRevision:1,
      status:"IN_PROGRESS",revision:1,
      dueAt:"2026-11-15T10:00:00.000Z",
      ownerUserId:null,updatedAt:now,
    }],
  };
}
describe("real persisted risk-only reconciliation",()=>{
  it("never promotes declarations or synthetic scores to healthy",()=>{
    const report=buildIntegratedRiskDigest(fixture());
    expect(report.state).toBe("REVIEW_REQUIRED");
    expect(report.counts.syntheticAssessments).toBe(1);
    expect(report.counts.overdueDeclaredActions).toBe(1);
    expect(report.latestAssessment?.numericScore).toBeNull();
    expect(report.latestAssessment?.scoreVisibleAsCustomerHealth).toBe(false);
    expect(report.controls.find(x=>x.controlId==="BACKUP_TEST")
      ?.currentState).toBe("DECLARED_ONLY");
    expect(report.evidenceSecurityCertified).toBe(false);
    expect(report.historicalV1ScoreModified).toBe(false);
    expect(verifyIntegratedRiskDigest(report,"org-test").valid).toBe(true);
  });
  it("cannot accept a foreign record as tenant evidence",()=>{
    const input=fixture();
    input.evidence[0]!.organizationId="org-foreign";
    const report=buildIntegratedRiskDigest(input);
    expect(report.state).toBe("INCOMPLETE");
    expect(report.issues.some(x=>
      x.code==="CROSS_ORGANIZATION_SOURCE")).toBe(true);
  });
  it("fails closed when a database query was truncated",()=>{
    const input=fixture();
    input.countOfRecords.evidence=101;
    const report=buildIntegratedRiskDigest(input);
    expect(report.state).toBe("INCOMPLETE");
    expect(report.coverage.persistedRecordsComplete).toBe(false);
  });
  it("does not merge different subjects with the same rule title",()=>{
    const input=fixture();
    input.findings.push({...input.findings[0]!,
      id:"finding-three",key:"different-device"});
    input.countOfRecords.findings=3;
    const report=buildIntegratedRiskDigest(input);
    expect(report.risks).toHaveLength(3);
    expect(report.counts.deduplicated).toBe(0);
  });
  it("detects stale records without marking them safe",()=>{
    const input=fixture();
    input.evidence[0]!.observedAt="2025-11-16T17:00:00.000Z";
    const report=buildIntegratedRiskDigest(input);
    expect(report.counts.staleControls).toBeGreaterThan(0);
    expect(report.issues.some(x=>x.code==="EVIDENCE_STALE")).toBe(true);
  });
  it("detects contradictory observations for the same control",()=>{
    const input=fixture();
    input.evidence.push({...input.evidence[0]!,
      id:"evidence-extra",source:"LAB",state:"OBSERVED"});
    input.countOfRecords.evidence=4;
    const report=buildIntegratedRiskDigest(input);
    expect(report.counts.conflictControls).toBe(1);
    expect(report.issues.some(x=>
      x.code==="EVIDENCE_SOURCE_CONFLICT")).toBe(true);
  });
  it("never authenticates LIVE from a stored label",()=>{
    const input=fixture();
    input.assessments[0]!.sourceClass="AUTHENTICATED_LIVE";
    const report=buildIntegratedRiskDigest(input);
    expect(report.coverage.allSourcesAuthenticated).toBe(false);
    expect(report.counts.authenticatedLiveAssessments).toBe(1);
    expect(report.issues.some(x=>
      x.code==="LIVE_PROVENANCE_NOT_REVALIDATED")).toBe(true);
  });
  it("detects local digest tampering and prohibited claims",()=>{
    const report=buildIntegratedRiskDigest(fixture());
    report.evidenceSecurityCertified=true as false;
    const checked=verifyIntegratedRiskDigest(report);
    expect(checked.errors).toContain("DIGEST_MISMATCH");
    expect(checked.errors).toContain("FORBIDDEN_SECURITY_ASSERTION");
  });
  it("exports a safe CSV, JSON and Markdown with explicit status",()=>{
    const report=buildIntegratedRiskDigest(fixture());
    const json=exportIntegratedRiskDigest(report,"JSON");
    const csv=exportIntegratedRiskDigest(report,"CSV");
    const md=exportIntegratedRiskDigest(report,"MARKDOWN");
    expect(JSON.parse(json.content).customerConsentInferred).toBe(false);
    expect(csv.content).toContain("Backup not confirmed");
    expect(md.content).toContain("DECLARED_ONLY");
  });
  it("compares versions without reporting actual risk reduction",()=>{
    const before=buildIntegratedRiskDigest(fixture());
    const next=fixture();
    next.evaluatedAt="2026-11-16T18:00:00.000Z";
    next.findings[0]!.status="RESOLVED";
    const after=buildIntegratedRiskDigest(next);
    const comparison=compareIntegratedRiskDigests(before,after);
    expect(comparison.noLongerOpen).toHaveLength(1);
    expect(comparison.verifiedRiskReduction).toBe(false);
    expect(comparison.v1ScoreComparable).toBe(false);
  });
});
