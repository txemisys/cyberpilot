import {describe,it,expect} from "vitest";
import {buildExecutiveCockpit,verifyExecutiveCockpit,
  compareExecutiveCockpits,exportExecutiveCockpit} from
  "./integrated-executive-cockpit";
import {buildIntegratedRiskDigest,
  type IntegratedRiskInput} from "./integrated-risk-engine";
import type {ActionSnapshot} from "./integrated-action-domain";
const at="2026-11-16T10:00:00.000Z";
function source():IntegratedRiskInput{
  return{
    organizationId:"org-test",evaluatedAt:at,
    sourceLimits:{
      evidence:10,findings:10,assessments:10,declaredActions:10,
    },
    countOfRecords:{
      evidence:1,findings:1,assessments:1,declaredActions:0,
    },
    evidence:[{
      id:"evidence-one",organizationId:"org-test",
      source:"BASELINE",domain:"GOVERNANCE",
      controlId:"BACKUP_TEST",scope:"org",
      state:"DECLARED",observedAt:at,createdAt:at,details:{},
    }],
    findings:[{
      id:"finding-one",organizationId:"org-test",
      ruleId:"BACKUP_TEST",key:"backup-risk-key",
      severity:"HIGH",status:"OPEN",
      title:"Backups untested",description:"Declared controls only",
      lastSeenAt:at,evidence:{},
    }],
    assessments:[{
      id:"assessment-one",organizationId:"org-test",
      snapshotId:"synthetic-snapshot",
      modelId:"cyberpilot.multisource.v2",
      modelRevision:1,status:"INSUFFICIENT_COVERAGE",
      score:null,coveragePercent:0,
      sourceClass:"SYNTHETIC_OFFLINE",
      evaluatedAt:at,reportDigest:"a".repeat(64),
      manifestDigest:"b".repeat(64),
      verifiedControls:0,totalControls:19,
    }],
    declaredActions:[],
  };
}
function action(key:string):ActionSnapshot{
  return{
    actionId:"action-one",organizationId:"org-test",riskKey:key,
    title:"Backups untested",description:"Manual follow-up",
    severity:"HIGH",sourceFingerprint:"b".repeat(64),
    evidenceRefs:["evidence-one"],
    status:"IN_PROGRESS",priority:"HIGH",
    ownerUserId:"member-one",
    dueAt:"2026-11-15T10:00:00.000Z",
    rationale:"Assign testing owner",
    exceptionReason:null,exceptionExpiresAt:null,
    revision:1,createdById:"member-one",
    updatedById:"member-one",
    updatedAt:at,
    independentRemediationVerified:false,
    customerLegalAcceptanceProven:false,
    sourceEvidenceReevaluated:false,
  };
}
function fixture(){
  const report=buildIntegratedRiskDigest(source());
  return{
    organizationId:"org-test",
    generatedAt:"2026-11-16T11:00:00.000Z",
    reportId:"executive-one",
    riskDigest:report,
    actions:[action(report.risks[0]!.key)],
    auditIssues:[],actionsTruncated:false,
    includeResolved:false,
  };
}
describe("integrated SME executive reporting without tenants",()=>{
  it("reconciles real persisted-risk shape with owned overdue action",()=>{
    const report=buildExecutiveCockpit(fixture());
    expect(report.verdict).toBe("REQUIRES_REVIEW");
    expect(report.summary.openRisks).toBe(1);
    expect(report.summary.overdueActions).toBe(1);
    expect(report.summary.unresolvedWithoutActions).toBe(0);
    expect(report.risks[0]?.ownerUserId).toBe("member-one");
    expect(report.risks[0]?.isOverdue).toBe(true);
    expect(report.summary.v2Score).toBeNull();
    expect(report.summary.v1ScoreUnchanged).toBe(true);
    expect(report.externalProviderCalls).toBe(0);
    expect(verifyExecutiveCockpit(report,"org-test").valid).toBe(true);
  });
  it("never certifies a DECLARED control even with an action",()=>{
    const report=buildExecutiveCockpit(fixture());
    expect(report.coverage[0]?.declaredOnly).toBe(1);
    expect(report.coverage[0]?.healthyStatusPermitted).toBe(false);
    expect(report.coverage[0]?.independentlyVerifiedPercent).toBeNull();
    expect(report.risks[0]?.externallyRemediated).toBe(false);
  });
  it("reports untracked risk as an actionable gap",()=>{
    const input=fixture();input.actions=[];
    const report=buildExecutiveCockpit(input);
    expect(report.summary.unresolvedWithoutActions).toBe(1);
    expect(report.risks[0]?.actionId).toBeNull();
  });
  it("blocks cross-tenant actions instead of merging",()=>{
    const input=fixture();
    input.actions[0]!.organizationId="org-foreign";
    expect(()=>buildExecutiveCockpit(input)).toThrow();
  });
  it("declares incomplete when action audit is truncated",()=>{
    const input=fixture();
    input.actionsTruncated=true;
    input.auditIssues=["ACTION_AUDIT_INCOMPLETE"];
    const report=buildExecutiveCockpit(input);
    expect(report.verdict).toBe("INCOMPLETE");
    expect(report.audit.actionsSourceComplete).toBe(false);
    expect(report.summary.auditIssues).toBeGreaterThan(0);
  });
  it("does not turn DONE_REPORTED into technical remediation",()=>{
    const input=fixture();
    input.actions[0]!.status="DONE_REPORTED";
    const report=buildExecutiveCockpit(input);
    expect(report.summary.reportedCompletedActions).toBe(1);
    expect(report.risks[0]?.actionCompletedReported).toBe(true);
    expect(report.risks[0]?.externallyRemediated).toBe(false);
    expect(report.technicalRemediationExecuted).toBe(false);
  });
  it("detects expired human exceptions without legal approval",()=>{
    const input=fixture();
    input.actions[0]!.status="EXCEPTION";
    input.actions[0]!.exceptionReason=
      "Temporary exception with owner review needed";
    input.actions[0]!.exceptionExpiresAt=
      "2026-11-15T11:00:00.000Z";
    const report=buildExecutiveCockpit(input);
    expect(report.summary.expiredExceptions).toBe(1);
    expect(report.independentCustomerApprovalProven).toBe(false);
  });
  it("preserves provenance of synthetic v2 assessment",()=>{
    const report=buildExecutiveCockpit(fixture());
    expect(report.summary.syntheticSnapshots).toBe(1);
    expect(report.provenance.latestOptionalV2SourceClass)
      .toBe("SYNTHETIC_OFFLINE");
    expect(report.provenance.customerTenantAuthenticatedByThisReport)
      .toBe(false);
  });
  it("rejects forged certification, score and report digests",()=>{
    const report=buildExecutiveCockpit(fixture());
    report.customerCertificationGranted=true as false;
    report.summary.v1ScoreUnchanged=false as true;
    const check=verifyExecutiveCockpit(report);
    expect(check.errors).toContain("EXECUTIVE_DIGEST_INVALID");
    expect(check.errors).toContain("EXECUTIVE_FALSE_SECURITY_CLAIM");
    expect(check.errors).toContain("CROSS_VERSION_SCORE_OVERCLAIM");
  });
  it("exports CSV, JSON and Markdown with no compliance claim",()=>{
    const report=buildExecutiveCockpit(fixture());
    const json=exportExecutiveCockpit(report,"JSON");
    const csv=exportExecutiveCockpit(report,"CSV");
    const md=exportExecutiveCockpit(report,"MARKDOWN");
    expect(JSON.parse(json.content).externalProviderCalls).toBe(0);
    expect(csv.content).toContain("Backups untested");
    expect(md.content).toContain("declared completed");
    expect(md.content).toContain("CyberPilot");
  });
  it("compares snapshots without treating fewer risks as improvement",()=>{
    const before=buildExecutiveCockpit(fixture());
    const input=fixture();
    input.reportId="executive-two";
    input.generatedAt="2026-11-16T12:00:00.000Z";
    input.actions[0]!.dueAt=null;
    const after=buildExecutiveCockpit(input);
    const diff=compareExecutiveCockpits(before,after);
    expect(diff.actualRiskReductionEstablished).toBe(false);
    expect(diff.crossVersionScoreComparisonPermitted).toBe(false);
    expect(diff.legallyApprovedExceptionInferred).toBe(false);
  });
});
