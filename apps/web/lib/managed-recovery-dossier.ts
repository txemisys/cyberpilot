import { recoveryDigest, assessManagedRestore,
  type RecoveryAssessment, type RecoverySession, type RecoveryObservation,
  type RecoveryStage, type RecoveryTier } from "./managed-recovery-objectives";
import { createManagedRestoreRunbook } from "./managed-recovery-fault-matrix";
export type RecoveryGap = {
  stage:RecoveryStage|null;code:string;
  severity:"CRITICAL"|"HIGH"|"MEDIUM"|"INFO";
  description:string;recommendedAction:string;
  owner:string;independentVerificationRequired:boolean;
};
export type RecoveryEvidenceDossier = {
  schema:"cyberpilot.managed.restore.evidence.dossier.v1";
  organizationId:string;sessionId:string;
  scope:"OPERATOR_SUPPLIED_READ_ONLY_EVIDENCE";
  assessedAt:string;sourceDigest:string;
  assessment:RecoveryAssessment;gaps:RecoveryGap[];
  status:"BLOCKED"|"INCOMPLETE"|"READY_FOR_MANUAL_REVIEW";
  sourceObservations:number;verifiedObservations:number;
  operatorDeclarations:number;unknownObservations:number;
  oldestEvidenceAt:string|null;newestEvidenceAt:string|null;
  sources:Array<{type:string;count:number;verified:number}>;
  reviewers:string[];
  serviceObjectiveClaim:"NOT_PROVEN";
  productionDatabaseRestoreConfirmed:false;
  secretsTouched:false;providerWrites:0;
};
const severity=(code:string):RecoveryGap["severity"]=>
  /RPO|RTO|ISOLATED|DIFFERENT_SOURCE|FAILED|BLOCK/.test(code)?
    "CRITICAL":/DATA|SCHEMA|APP|ACCESS/.test(code)?"HIGH":
    /BACKUP|CLEANUP|VERIFIER/.test(code)?"MEDIUM":"INFO";
const suggestions:Record<string,string>={
  ISOLATED_TARGET:"Confirm target isolation using separate provider-side access review",
  DIFFERENT_SOURCE_TARGET:"Provision a new target; never overwrite original data",
  ACCESS_CONTROL:"Record independent database, network and application RBAC review",
  CLEANUP:"Attach resource cleanup and temporary access revocation proofs",
  SEPARATE_REVIEWER:"Assign independent reviewer distinct from the operator",
  RPO:"Verify backup recovery point and incident start from independent timestamps",
  RTO:"Measure incident start through application usability with trusted clocks",
  MANAGED_PROVIDER_RESTORE:"Execute an authorized restore on managed staging and independently verify",
};
export function buildManagedRecoveryDossier(s:RecoverySession):RecoveryEvidenceDossier{
  const assessment=assessManagedRestore(s);
  const gaps=assessment.gates.filter(g=>g.status!=="PASS"&&
    g.status!=="NOT_APPLICABLE").map(g=>{
    const stage=g.id.startsWith("STAGE_")?
      g.id.slice(6) as RecoveryStage:null;
    return {stage,code:g.id,severity:severity(g.id),
      description:g.reason,
      recommendedAction:suggestions[g.id]??(stage?
        "Produce independent, recent evidence for "+stage:
        "Investigate the incomplete recovery gate"),
      owner:stage==="BACKUP_IDENTIFIED"?"Backup owner":
        stage==="ACCESS_REVIEWED"?"Security reviewer":"Operations owner",
      independentVerificationRequired:true};
  });
  const sourceMap=new Map<string,{count:number;verified:number}>();
  for(const e of s.observations){
    const n=sourceMap.get(e.source)??{count:0,verified:0};
    n.count++;if(e.independent&&e.signal==="OBSERVED")n.verified++;
    sourceMap.set(e.source,n);
  }
  const times=s.observations.map(x=>x.observedAt)
    .filter((x):x is string=>x!==null).sort();
  return {schema:"cyberpilot.managed.restore.evidence.dossier.v1",
    organizationId:s.organizationId,sessionId:s.id,
    scope:"OPERATOR_SUPPLIED_READ_ONLY_EVIDENCE",
    assessedAt:s.asOf,sourceDigest:recoveryDigest(s),
    assessment,gaps,
    status:assessment.status==="READY_FOR_OPERATOR_REVIEW"?
      "READY_FOR_MANUAL_REVIEW":assessment.status,
    sourceObservations:s.observations.length,
    verifiedObservations:s.observations.filter(x=>
      x.independent&&x.signal==="OBSERVED").length,
    operatorDeclarations:s.observations.filter(x=>
      x.signal==="DECLARED"||!x.independent).length,
    unknownObservations:s.observations.filter(x=>
      x.signal==="UNKNOWN"||x.signal==="ERROR").length,
    oldestEvidenceAt:times[0]??null,
    newestEvidenceAt:times.at(-1)??null,
    sources:[...sourceMap.entries()].map(([type,n])=>({type,...n}))
      .sort((a,b)=>a.type.localeCompare(b.type)),
    reviewers:[...new Set(s.observations.map(x=>x.verifierId)
      .filter((x):x is string=>x!==null))].sort(),
    serviceObjectiveClaim:"NOT_PROVEN",
    productionDatabaseRestoreConfirmed:false,
    secretsTouched:false,providerWrites:0};
}
export type RestoreTrend = {
  schema:"cyberpilot.managed.restore.trend.v1";
  organizationId:string;tier:RecoveryTier;
  samples:number;windowStart:string|null;windowEnd:string|null;
  comparable:boolean;unverifiedCount:number;
  verifiedRpoMinutes:number[];verifiedRtoMinutes:number[];
  meanRpoMinutes:number|null;meanRtoMinutes:number|null;
  p95RpoMinutes:number|null;p95RtoMinutes:number|null;
  rpoBreaches:number;rtoBreaches:number;sourceDigests:string[];
  scoreHistoryChanged:false;productionDRValidated:false;
};
function percentile(arr:number[],p:number){
  if(!arr.length)return null;
  const sorted=[...arr].sort((a,b)=>a-b);
  return sorted[Math.ceil(p*sorted.length)-1]??null;
}
export function compareRestoreHistory(sessions:RecoverySession[]):RestoreTrend{
  if(sessions.length>100)throw Error("RECOVERY_HISTORY_BOUND");
  if(!sessions.length)return{
    schema:"cyberpilot.managed.restore.trend.v1",organizationId:"",
    tier:"STANDARD",samples:0,windowStart:null,windowEnd:null,
    comparable:false,unverifiedCount:0,verifiedRpoMinutes:[],
    verifiedRtoMinutes:[],meanRpoMinutes:null,meanRtoMinutes:null,
    p95RpoMinutes:null,p95RtoMinutes:null,rpoBreaches:0,rtoBreaches:0,
    sourceDigests:[],scoreHistoryChanged:false,productionDRValidated:false};
  const org=sessions[0]!.organizationId,tier=sessions[0]!.tier;
  if(sessions.some(x=>x.organizationId!==org||x.tier!==tier))
    throw Error("RECOVERY_HISTORY_TENANT_TIER_MISMATCH");
  const assessments=sessions.map(assessManagedRestore);
  const rpos=assessments.filter(x=>x.rpo.proof==="INDEPENDENT"&&
    x.rpo.observedMinutes!==null).map(x=>x.rpo.observedMinutes!);
  const rtos=assessments.filter(x=>x.rto.proof==="INDEPENDENT"&&
    x.rto.observedMinutes!==null).map(x=>x.rto.observedMinutes!);
  const stamps=sessions.map(x=>x.initiatedAt).sort();
  return {schema:"cyberpilot.managed.restore.trend.v1",
    organizationId:org,tier,samples:sessions.length,
    windowStart:stamps[0]!,windowEnd:stamps.at(-1)!,
    comparable:sessions.every(x=>x.policy.rpoMinutes===sessions[0]!.policy.rpoMinutes&&
      x.policy.rtoMinutes===sessions[0]!.policy.rtoMinutes)&&
      sessions.every(x=>x.environment===sessions[0]!.environment),
    unverifiedCount:assessments.filter(x=>x.rpo.status==="UNKNOWN"||
      x.rto.status==="UNKNOWN").length,
    verifiedRpoMinutes:rpos,verifiedRtoMinutes:rtos,
    meanRpoMinutes:rpos.length?rpos.reduce((a,b)=>a+b,0)/rpos.length:null,
    meanRtoMinutes:rtos.length?rtos.reduce((a,b)=>a+b,0)/rtos.length:null,
    p95RpoMinutes:percentile(rpos,.95),p95RtoMinutes:percentile(rtos,.95),
    rpoBreaches:assessments.filter(x=>x.rpo.status==="OVER_TARGET").length,
    rtoBreaches:assessments.filter(x=>x.rto.status==="OVER_TARGET").length,
    sourceDigests:sessions.map(recoveryDigest),
    scoreHistoryChanged:false,productionDRValidated:false};
}
function csv(s:unknown){
  const raw=String(s??"");
  const safe=/^[=+\-@\t\r]/.test(raw)?"'"+raw:raw;
  return '"'+safe.replaceAll('"','""').replaceAll("\n"," ")
    .replaceAll("\r"," ")+'"';
}
export function exportManagedRecoveryDossier(d:RecoveryEvidenceDossier,
  format:"JSON"|"CSV"|"MARKDOWN"){
  const basename="managed-restore-"+d.sessionId;
  const digest=recoveryDigest(d);
  if(format==="JSON")return{
    filename:basename+".json",mime:"application/json",digest,
    content:JSON.stringify({...d,digest},null,2)};
  if(format==="CSV"){
    const rows=[["gate","status","reason","independentEvidenceCount"],
      ...d.assessment.gates.map(x=>[
        x.id,x.status,x.reason,String(x.evidenceIds.length)])];
    return {filename:basename+".csv",mime:"text/csv",digest,
      content:rows.map(row=>row.map(csv).join(",")).join("\r\n")};
  }
  if(format==="MARKDOWN"){
    const safe=(s:string)=>s.replaceAll("|","\\|")
      .replaceAll("<","&lt;").replaceAll(">","&gt;");
    const lines=["# Managed recovery readiness dossier",
      "Organization: "+safe(d.organizationId),
      "Session: "+safe(d.sessionId),
      "Status: "+d.status,
      "RPO: "+d.assessment.rpo.status+
        " / "+String(d.assessment.rpo.observedMinutes)+" minutes",
      "RTO: "+d.assessment.rto.status+
        " / "+String(d.assessment.rto.observedMinutes)+" minutes",
      "Production DR verified: NO",
      "Evidence digest: "+digest,"","## Gates",
      ...d.assessment.gates.map(x=>"- "+x.id+": "+x.status+" — "+safe(x.reason)),
      "","## Follow-up actions",
      ...d.gaps.map(x=>"- "+x.code+": "+safe(x.recommendedAction)),
      "","This dossier is not an execution receipt or a certification of backup restore."];
    return {filename:basename+".md",mime:"text/markdown",digest,
      content:lines.join("\n")};
  }
  throw Error("RECOVERY_DOSSIER_FORMAT_INVALID");
}
export function compareManagedRestoreDossiers(
  earlier:RecoveryEvidenceDossier,later:RecoveryEvidenceDossier){
  if(earlier.organizationId!==later.organizationId||
    earlier.assessedAt>later.assessedAt)throw Error("RESTORE_COMPARISON_SCOPE_INVALID");
  const oldGates=new Map(earlier.assessment.gates.map(x=>[x.id,x.status]));
  const newGates=new Map(later.assessment.gates.map(x=>[x.id,x.status]));
  return {schema:"cyberpilot.managed.restore.comparison.v1" as const,
    organizationId:earlier.organizationId,
    earlierDigest:recoveryDigest(earlier),laterDigest:recoveryDigest(later),
    improved:[...newGates].filter(([id,x])=>x==="PASS"&&oldGates.get(id)!=="PASS")
      .map(([id])=>id),
    worsened:[...newGates].filter(([id,x])=>x!=="PASS"&&oldGates.get(id)==="PASS")
      .map(([id])=>id),
    unknownBefore:earlier.assessment.unknown,
    unknownAfter:later.assessment.unknown,
    declaredImprovementConfirmedByProvider:false as const,
    actualDatabaseRestoreExecutedByComparison:false as const};
}
