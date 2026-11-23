import { createHash } from "node:crypto";

export type RecoveryTier = "STANDARD" | "BUSINESS" | "CRITICAL";
export type RecoveryEnvironment = "CI_SYNTHETIC" | "LOCAL_LAB" |
  "MANAGED_STAGING" | "PRODUCTION";
export type RecoveryStage = "BACKUP_IDENTIFIED" | "RESTORE_STARTED" |
  "RESTORE_FINISHED" | "SCHEMA_VERIFIED" | "APP_STARTED" |
  "DATA_VERIFIED" | "ACCESS_REVIEWED" | "CLEANUP_CONFIRMED";
export type RecoverySignal = "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type RecoveryEvidenceSource = "CI_RUN" | "DATABASE_QUERY" |
  "BACKUP_PROVIDER" | "APPLICATION_HEALTH" | "OPERATOR_NOTE" |
  "ACCESS_CONTROL_REVIEW" | "EXTERNAL_ATTESTATION";
export type RecoveryPolicy = {
  tier: RecoveryTier; rpoMinutes: number; rtoMinutes: number;
  backupRetentionDays: number; maximumEvidenceAgeDays: number;
  requiredStages: RecoveryStage[]; requireRestoreTargetIsolation: boolean;
  requireRepresentativeData: boolean; requireIndependentVerifier: boolean;
  requireAccessReview: boolean; requireCleanup: boolean;
};
export const RECOVERY_POLICIES: Record<RecoveryTier, RecoveryPolicy> = {
  STANDARD: { tier: "STANDARD", rpoMinutes: 1440, rtoMinutes: 1440,
    backupRetentionDays: 7, maximumEvidenceAgeDays: 90,
    requiredStages: ["BACKUP_IDENTIFIED","RESTORE_STARTED","RESTORE_FINISHED",
      "SCHEMA_VERIFIED","APP_STARTED","DATA_VERIFIED","ACCESS_REVIEWED",
      "CLEANUP_CONFIRMED"], requireRestoreTargetIsolation: true,
    requireRepresentativeData: true, requireIndependentVerifier: true,
    requireAccessReview: true, requireCleanup: true },
  BUSINESS: { tier: "BUSINESS", rpoMinutes: 240, rtoMinutes: 480,
    backupRetentionDays: 30, maximumEvidenceAgeDays: 30,
    requiredStages: ["BACKUP_IDENTIFIED","RESTORE_STARTED","RESTORE_FINISHED",
      "SCHEMA_VERIFIED","APP_STARTED","DATA_VERIFIED","ACCESS_REVIEWED",
      "CLEANUP_CONFIRMED"], requireRestoreTargetIsolation: true,
    requireRepresentativeData: true, requireIndependentVerifier: true,
    requireAccessReview: true, requireCleanup: true },
  CRITICAL: { tier: "CRITICAL", rpoMinutes: 60, rtoMinutes: 240,
    backupRetentionDays: 35, maximumEvidenceAgeDays: 14,
    requiredStages: ["BACKUP_IDENTIFIED","RESTORE_STARTED","RESTORE_FINISHED",
      "SCHEMA_VERIFIED","APP_STARTED","DATA_VERIFIED","ACCESS_REVIEWED",
      "CLEANUP_CONFIRMED"], requireRestoreTargetIsolation: true,
    requireRepresentativeData: true, requireIndependentVerifier: true,
    requireAccessReview: true, requireCleanup: true },
};
export type RecoveryObservation = {
  id: string; stage: RecoveryStage; source: RecoveryEvidenceSource;
  sourceReference: string; recordedById: string; recordedAt: string;
  observedAt: string | null; signal: RecoverySignal;
  evidenceDigest: string | null; independent: boolean;
  verifierId: string | null; note: string;
};
export type RecoverySession = {
  schema: "cyberpilot.managed.restore.session.v1";
  id: string; organizationId: string; tier: RecoveryTier;
  environment: RecoveryEnvironment; policy: RecoveryPolicy;
  sourceName: string; targetName: string;
  initiatedById: string; evaluatorId: string | null;
  initiatedAt: string; asOf: string;
  incidentStartedAt: string | null;
  latestRestorableBackupAt: string | null;
  backupCreatedAt: string | null;
  restoreStartedAt: string | null; restoreFinishedAt: string | null;
  applicationUsableAt: string | null;
  originalSourceRetained: boolean;
  targetIsolated: boolean | null;
  verifiedReadOnly: boolean;
  observations: RecoveryObservation[];
  operatorApprovalRef: string | null;
  actualExternalRestorePerformedByCyberPilot: false;
  customerTenantCredentialsUsed: false;
};
export type RecoveryGate = {
  id: string; status: "PASS" | "BLOCK" | "UNKNOWN" |
    "NOT_APPLICABLE"; reason: string;
  evidenceIds: string[]; needsIndependentEvidence: boolean;
  requiresHumanIntervention: boolean;
};
export type RecoveryObjective = {
  objective: "RPO" | "RTO";
  targetMinutes: number; observedMinutes: number | null;
  status: "WITHIN_TARGET" | "OVER_TARGET" | "UNKNOWN";
  proof: "INDEPENDENT" | "DECLARED_ONLY" | "UNAVAILABLE";
  clockStart: string | null; clockEnd: string | null;
  warning: string | null;
};
export type RecoveryAssessment = {
  schema: "cyberpilot.managed.restore.assessment.v1";
  sessionId: string; organizationId: string; generatedAt: string;
  environment: RecoveryEnvironment; tier: RecoveryTier;
  sourceDigest: string; policyDigest: string;
  gates: RecoveryGate[]; rpo: RecoveryObjective; rto: RecoveryObjective;
  passed: number; blocked: number; unknown: number;
  requiredEvidenceCount: number; verifiedEvidenceCount: number;
  obsoleteEvidenceCount: number;
  status: "BLOCKED" | "INCOMPLETE" | "READY_FOR_OPERATOR_REVIEW";
  managedRestoreProven: false; productionDRValidated: false;
  independentManagedProviderEvidencePresent: boolean;
  externalWrites: 0; liveTenantClaims: false;
};
const validId=(s:unknown):s is string=>typeof s==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const date=(s:unknown):s is string=>typeof s==="string"&&
  Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
function canonical(v:unknown):string{
  if(v===null||typeof v==="boolean"||typeof v==="string"||typeof v==="number"){
    if(typeof v==="number"&&!Number.isFinite(v))throw Error("RECOVERY_NONFINITE");
    return JSON.stringify(v);
  }
  if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";
  if(v&&typeof v==="object")
    return "{"+Object.entries(v).sort(([a],[b])=>a.localeCompare(b))
      .map(([k,x])=>JSON.stringify(k)+":"+canonical(x)).join(",")+"}";
  throw Error("RECOVERY_NOT_JSON");
}
export const recoveryDigest=(v:unknown)=>createHash("sha256")
  .update(canonical(v)).digest("hex");
export function validateManagedRecoveryPolicy(p:RecoveryPolicy):string[]{
  const errors:string[]=[];
  if(!["STANDARD","BUSINESS","CRITICAL"].includes(p.tier)||
    !Number.isSafeInteger(p.rpoMinutes)||p.rpoMinutes<1||p.rpoMinutes>10080||
    !Number.isSafeInteger(p.rtoMinutes)||p.rtoMinutes<1||p.rtoMinutes>10080)
    errors.push("RECOVERY_OBJECTIVE_INVALID");
  if(!Number.isSafeInteger(p.backupRetentionDays)||
    p.backupRetentionDays<1||p.backupRetentionDays>3650||
    !Number.isSafeInteger(p.maximumEvidenceAgeDays)||
    p.maximumEvidenceAgeDays<1||p.maximumEvidenceAgeDays>365)
    errors.push("RECOVERY_RETENTION_INVALID");
  const stages:RecoveryStage[]=["BACKUP_IDENTIFIED","RESTORE_STARTED",
    "RESTORE_FINISHED","SCHEMA_VERIFIED","APP_STARTED","DATA_VERIFIED",
    "ACCESS_REVIEWED","CLEANUP_CONFIRMED"];
  if(!Array.isArray(p.requiredStages)||p.requiredStages.length<4||
    p.requiredStages.length>stages.length||new Set(p.requiredStages).size!==p.requiredStages.length||
    p.requiredStages.some(x=>!stages.includes(x)))
    errors.push("RECOVERY_STAGES_INVALID");
  for(const key of ["requireRestoreTargetIsolation","requireRepresentativeData",
    "requireIndependentVerifier","requireAccessReview","requireCleanup"] as const)
    if(typeof p[key]!=="boolean")errors.push("RECOVERY_FLAGS_INVALID");
  return [...new Set(errors)];
}
export function validateManagedRecoverySession(s:RecoverySession):string[]{
  const errors:string[]=[];
  if(s.schema!=="cyberpilot.managed.restore.session.v1"||
    !validId(s.id)||!validId(s.organizationId)||
    !validId(s.initiatedById)||s.evaluatorId!==null&&!validId(s.evaluatorId))
    errors.push("RECOVERY_SESSION_IDENTITY_INVALID");
  if(!["CI_SYNTHETIC","LOCAL_LAB","MANAGED_STAGING","PRODUCTION"].includes(s.environment)||
    !RECOVERY_POLICIES[s.tier]||validateManagedRecoveryPolicy(s.policy).length||
    s.tier!==s.policy.tier)errors.push("RECOVERY_SESSION_POLICY_INVALID");
  if(typeof s.sourceName!=="string"||s.sourceName.length>120||
    !s.sourceName.trim()||typeof s.targetName!=="string"||
    !s.targetName.trim()||s.targetName.length>120)
    errors.push("RECOVERY_SOURCE_OR_TARGET_INVALID");
  if(!date(s.initiatedAt)||!date(s.asOf)||s.asOf<s.initiatedAt)
    errors.push("RECOVERY_TIMELINE_INVALID");
  for(const x of [s.incidentStartedAt,s.latestRestorableBackupAt,
    s.backupCreatedAt,s.restoreStartedAt,s.restoreFinishedAt,s.applicationUsableAt])
    if(x!==null&&!date(x))errors.push("RECOVERY_CLOCK_INVALID");
  if(s.restoreFinishedAt&&s.restoreStartedAt&&
    s.restoreFinishedAt<s.restoreStartedAt)
    errors.push("RECOVERY_CLOCK_INVERTED");
  if(s.applicationUsableAt&&s.incidentStartedAt&&
    s.applicationUsableAt<s.incidentStartedAt)
    errors.push("RECOVERY_CLOCK_INVERTED");
  if(s.originalSourceRetained!==true||s.customerTenantCredentialsUsed!==false||
    s.actualExternalRestorePerformedByCyberPilot!==false)
    errors.push("RECOVERY_UNSUPPORTED_EXECUTION_CLAIM");
  if(s.targetIsolated!==null&&typeof s.targetIsolated!=="boolean"||
    typeof s.verifiedReadOnly!=="boolean")
    errors.push("RECOVERY_ISOLATION_INVALID");
  if(!Array.isArray(s.observations)||s.observations.length>120)
    return [...new Set([...errors,"RECOVERY_OBSERVATIONS_INVALID"])];
  const ids=new Set<string>();
  for(const e of s.observations){
    if(!validId(e.id)||ids.has(e.id)||!validId(e.recordedById)||
      !date(e.recordedAt)||e.observedAt!==null&&!date(e.observedAt)||
      !["OBSERVED","DECLARED","UNKNOWN","ERROR"].includes(e.signal)||
      !["CI_RUN","DATABASE_QUERY","BACKUP_PROVIDER","APPLICATION_HEALTH",
        "OPERATOR_NOTE","ACCESS_CONTROL_REVIEW","EXTERNAL_ATTESTATION"].includes(e.source)||
      !s.policy.requiredStages.includes(e.stage)||
      typeof e.sourceReference!=="string"||e.sourceReference.length>255||
      !e.sourceReference.trim()||typeof e.note!=="string"||e.note.length>1200||
      e.evidenceDigest!==null&&!/^[a-f0-9]{64}$/.test(e.evidenceDigest)||
      e.verifierId!==null&&!validId(e.verifierId))
      errors.push("RECOVERY_OBSERVATION_INVALID");
    if(e.independent&&(!e.verifierId||e.verifierId===e.recordedById||
      e.source==="OPERATOR_NOTE"||e.signal!=="OBSERVED"))
      errors.push("RECOVERY_INDEPENDENCE_INCONSISTENT");
    ids.add(e.id);
  }
  return [...new Set(errors)];
}
function stageEvidence(s:RecoverySession,stage:RecoveryStage) {
  const cutoff=Date.parse(s.asOf)-s.policy.maximumEvidenceAgeDays*86400000;
  return s.observations.filter(e=>e.stage===stage&&e.signal==="OBSERVED"&&
    e.independent&&e.observedAt!==null&&Date.parse(e.observedAt)>=cutoff&&
    Date.parse(e.observedAt)<=Date.parse(s.asOf)&&e.evidenceDigest!==null);
}
function stageGate(s:RecoverySession,stage:RecoveryStage):RecoveryGate{
  const candidates=stageEvidence(s,stage);
  const failed=s.observations.some(e=>e.stage===stage&&e.signal==="ERROR");
  return {id:"STAGE_"+stage,
    status:failed?"BLOCK":candidates.length?"PASS":"UNKNOWN",
    reason:failed?"Stage has explicit recorded error":
      candidates.length?"Independently observed source reference is present":
      "No independently verified and timely proof for stage",
    evidenceIds:candidates.map(e=>e.id),
    needsIndependentEvidence:!candidates.length,
    requiresHumanIntervention:failed||!candidates.length};
}
function objective(target:number,start:string|null,end:string|null,
  stage:RecoveryStage,s:RecoverySession,name:"RPO"|"RTO"):RecoveryObjective{
  const sourceProof=stageEvidence(s,stage).length>0;
  const minutes=start&&end&&Date.parse(end)>=Date.parse(start)?
    (Date.parse(end)-Date.parse(start))/60000:null;
  const proof:RecoveryObjective["proof"]=!sourceProof?"UNAVAILABLE":
    s.environment==="CI_SYNTHETIC"||s.environment==="LOCAL_LAB"?
      "DECLARED_ONLY":"INDEPENDENT";
  return {objective:name,targetMinutes:target,observedMinutes:minutes,
    status:minutes===null||proof!=="INDEPENDENT"?"UNKNOWN":
      minutes<=target?"WITHIN_TARGET":"OVER_TARGET",
    proof,clockStart:start,clockEnd:end,
    warning:minutes===null?"Required clocks unavailable":
      proof!=="INDEPENDENT"?"No independently verified managed recovery measurement":
      minutes>target?"Observed objective exceeds policy":null};
}
export function assessManagedRestore(s:RecoverySession):RecoveryAssessment{
  const errors=validateManagedRecoverySession(s);
  if(errors.length)throw Error("RECOVERY_SESSION_INVALID:"+errors.join(","));
  const gates=s.policy.requiredStages.map(stage=>stageGate(s,stage));
  function add(id:string,status:RecoveryGate["status"],reason:string){
    gates.push({id,status,reason,evidenceIds:[],
      needsIndependentEvidence:status!=="PASS",
      requiresHumanIntervention:status!=="PASS"});
  }
  add("ISOLATED_TARGET",s.targetIsolated===true?"PASS":
    s.targetIsolated===false?"BLOCK":"UNKNOWN",
    "A separate restore target needs isolation confirmation");
  add("DIFFERENT_SOURCE_TARGET",s.sourceName!==s.targetName?"PASS":"BLOCK",
    "Restore target must not overwrite original source");
  if(s.policy.requireAccessReview)
    add("ACCESS_CONTROL",stageEvidence(s,"ACCESS_REVIEWED").length?"PASS":"UNKNOWN",
      "Access control equivalence needs independent review");
  if(s.policy.requireCleanup)
    add("CLEANUP",stageEvidence(s,"CLEANUP_CONFIRMED").length?"PASS":"UNKNOWN",
      "Temporary restore copy must be disposed of or retained under policy");
  if(!s.evaluatorId||s.evaluatorId===s.initiatedById)
    add("SEPARATE_REVIEWER","UNKNOWN",
      "Independent reviewer is not assigned");
  else add("SEPARATE_REVIEWER","PASS","Distinct reviewer assigned");
  const rpo=objective(s.policy.rpoMinutes,s.latestRestorableBackupAt,
    s.incidentStartedAt,"BACKUP_IDENTIFIED",s,"RPO");
  const rto=objective(s.policy.rtoMinutes,s.incidentStartedAt,
    s.applicationUsableAt,"APP_STARTED",s,"RTO");
  add("RPO",rpo.status==="OVER_TARGET"?"BLOCK":
    rpo.status==="WITHIN_TARGET"?"PASS":"UNKNOWN",
    rpo.warning??"RPO objective measured within policy");
  add("RTO",rto.status==="OVER_TARGET"?"BLOCK":
    rto.status==="WITHIN_TARGET"?"PASS":"UNKNOWN",
    rto.warning??"RTO objective measured within policy");
  if(s.environment==="CI_SYNTHETIC"||s.environment==="LOCAL_LAB")
    add("MANAGED_PROVIDER_RESTORE","UNKNOWN",
      "Offline synthetic rehearsal cannot establish managed provider recovery");
  const blocked=gates.filter(x=>x.status==="BLOCK").length;
  const unknown=gates.filter(x=>x.status==="UNKNOWN").length;
  const cutoff=Date.parse(s.asOf)-s.policy.maximumEvidenceAgeDays*86400000;
  return {
    schema:"cyberpilot.managed.restore.assessment.v1",sessionId:s.id,
    organizationId:s.organizationId,generatedAt:s.asOf,
    environment:s.environment,tier:s.tier,
    sourceDigest:recoveryDigest(s),policyDigest:recoveryDigest(s.policy),
    gates,rpo,rto,passed:gates.filter(x=>x.status==="PASS").length,
    blocked,unknown,requiredEvidenceCount:s.policy.requiredStages.length,
    verifiedEvidenceCount:s.policy.requiredStages.filter(x=>stageEvidence(s,x).length>0).length,
    obsoleteEvidenceCount:s.observations.filter(e=>e.observedAt===null||
      Date.parse(e.observedAt)<cutoff).length,
    status:blocked?"BLOCKED":unknown?"INCOMPLETE":"READY_FOR_OPERATOR_REVIEW",
    managedRestoreProven:false,productionDRValidated:false,
    independentManagedProviderEvidencePresent:s.observations.some(e=>
      e.independent&&e.source==="BACKUP_PROVIDER"&&e.signal==="OBSERVED"),
    externalWrites:0,liveTenantClaims:false,
  };
}
