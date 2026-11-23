import { describe,expect,it } from "vitest";
import { RECOVERY_POLICIES,assessManagedRestore,
  recoveryDigest,validateManagedRecoverySession,
  type RecoverySession,type RecoveryObservation,
  type RecoveryStage } from "./managed-recovery-objectives";
import { evaluateManagedRecoveryFaultMatrix,createManagedRestoreRunbook }
  from "./managed-recovery-fault-matrix";
import { buildManagedRecoveryDossier,exportManagedRecoveryDossier,
  compareRestoreHistory } from "./managed-recovery-dossier";
const started="2026-11-23T09:00:00.000Z",end="2026-11-23T10:00:00.000Z";
function source(stage:RecoveryStage):RecoveryObservation{
  return {id:"source-"+stage,stage,source:"DATABASE_QUERY",
    sourceReference:"local-evidence-"+stage,
    recordedById:"operator-1234",recordedAt:end,observedAt:end,
    signal:"OBSERVED",evidenceDigest:"a".repeat(64),
    independent:true,verifierId:"reviewer-1234",note:"Evidence check"};
}
function session():RecoverySession{
  return {schema:"cyberpilot.managed.restore.session.v1",
    id:"restore-1234",organizationId:"tenant-1234",
    tier:"STANDARD",environment:"MANAGED_STAGING",
    policy:RECOVERY_POLICIES.STANDARD,sourceName:"source-db",
    targetName:"staging-target",initiatedById:"operator-1234",
    evaluatorId:"reviewer-1234",initiatedAt:started,asOf:end,
    incidentStartedAt:started,
    latestRestorableBackupAt:"2026-11-23T08:30:00.000Z",
    backupCreatedAt:"2026-11-23T08:30:00.000Z",
    restoreStartedAt:started,restoreFinishedAt:"2026-11-23T09:40:00.000Z",
    applicationUsableAt:end,originalSourceRetained:true,
    targetIsolated:true,verifiedReadOnly:true,
    observations:RECOVERY_POLICIES.STANDARD.requiredStages.map(source),
    operatorApprovalRef:"approval-1234",
    actualExternalRestorePerformedByCyberPilot:false,
    customerTenantCredentialsUsed:false};
}
describe("RPO/RTO evidence-based readiness",()=>{
  it("preserves tier objectives, validates proof and does not certify production DR",()=>{
    const s=session();
    expect(validateManagedRecoverySession(s)).toEqual([]);
    const report=assessManagedRestore(s);
    expect(report.rpo.status).toBe("WITHIN_TARGET");
    expect(report.rto.status).toBe("WITHIN_TARGET");
    expect(report.rpo.observedMinutes).toBe(30);
    expect(report.rto.observedMinutes).toBe(60);
    expect(report.productionDRValidated).toBe(false);
    expect(report.managedRestoreProven).toBe(false);
  });
  it("rejects forged self-attestation and stale observations",()=>{
    const s=session();
    s.observations[0]!.verifierId=s.observations[0]!.recordedById;
    expect(validateManagedRecoverySession(s)).toContain(
      "RECOVERY_INDEPENDENCE_INCONSISTENT");
    const t=session();
    t.observations[0]!.observedAt="2026-01-01T00:00:00.000Z";
    expect(assessManagedRestore(t).gates.find(x=>
      x.id==="STAGE_BACKUP_IDENTIFIED")?.status).toBe("UNKNOWN");
  });
  it("blocks overwriting production and mismatched times",()=>{
    const a=session();a.targetName=a.sourceName;
    expect(assessManagedRestore(a).status).toBe("BLOCKED");
    const b=session();b.restoreFinishedAt="2026-11-23T08:00:00.000Z";
    expect(validateManagedRecoverySession(b)).toContain("RECOVERY_CLOCK_INVERTED");
  });
  it("synthetic CI evidence does not establish managed provider restoration",()=>{
    const s=session();s.environment="CI_SYNTHETIC";
    const a=assessManagedRestore(s);
    expect(a.rpo.status).toBe("UNKNOWN");
    expect(a.rto.status).toBe("UNKNOWN");
    expect(a.gates.find(x=>x.id==="MANAGED_PROVIDER_RESTORE")?.status)
      .toBe("UNKNOWN");
  });
  it("exercise sixteen memory faults without touching persisted rows",()=>{
    const s=session(),digest=recoveryDigest(s);
    const matrix=evaluateManagedRecoveryFaultMatrix(s);
    expect(matrix.scenarioCount).toBe(16);
    expect(matrix.sqlRestoreExecuted).toBe(false);
    expect(matrix.productionDRValidated).toBe(false);
    expect(recoveryDigest(s)).toBe(digest);
    expect(matrix.detectedCount).toBeGreaterThan(10);
  });
  it("generates runbook, export and longitudinal comparison",()=>{
    const s=session(),d=buildManagedRecoveryDossier(s);
    expect(d.serviceObjectiveClaim).toBe("NOT_PROVEN");
    expect(d.secretsTouched).toBe(false);
    for(const format of ["JSON","CSV","MARKDOWN"] as const){
      const artifact=exportManagedRecoveryDossier(d,format);
      expect(artifact.content.length).toBeGreaterThan(0);
      expect(artifact.digest).toMatch(/^[a-f0-9]{64}$/);
    }
    const next={...s,id:"restore-5678",asOf:"2026-11-23T11:00:00.000Z"};
    const trend=compareRestoreHistory([s,next]);
    expect(trend.samples).toBe(2);
    expect(trend.productionDRValidated).toBe(false);
    expect(createManagedRestoreRunbook("MANAGED_STAGING","STANDARD")
      .steps.length).toBe(8);
  });
});
