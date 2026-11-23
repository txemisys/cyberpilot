import { recoveryDigest, assessManagedRestore, RECOVERY_POLICIES,
  type RecoverySession, type RecoveryTier, type RecoveryAssessment,
  type RecoveryEnvironment, type RecoveryObservation,
  type RecoveryStage } from "./managed-recovery-objectives";

export type ManagedRecoveryFaultId = "NO_BACKUP" | "OLD_BACKUP" |
  "EXCESSIVE_DOWNTIME" | "SOURCE_TARGET_EQUAL" |
  "UNISOLATED_RESTORE" | "MISSING_APPLICATION_PROOF" |
  "MISSING_DATABASE_PROOF" | "WRONG_ORGANIZATION" |
  "SELF_VERIFIED_EVIDENCE" | "MALFORMED_CHECKSUM" |
  "STALE_PROOF" | "MISSING_CLEANUP" |
  "UNKNOWN_RPO" | "UNKNOWN_RTO" |
  "FAILED_STAGE" | "FAKE_CI_RECOVERY";
export const MANAGED_RECOVERY_FAULT_IDS:readonly ManagedRecoveryFaultId[]=[
  "NO_BACKUP","OLD_BACKUP","EXCESSIVE_DOWNTIME","SOURCE_TARGET_EQUAL",
  "UNISOLATED_RESTORE","MISSING_APPLICATION_PROOF",
  "MISSING_DATABASE_PROOF","WRONG_ORGANIZATION",
  "SELF_VERIFIED_EVIDENCE","MALFORMED_CHECKSUM",
  "STALE_PROOF","MISSING_CLEANUP","UNKNOWN_RPO","UNKNOWN_RTO",
  "FAILED_STAGE","FAKE_CI_RECOVERY",
];
export type ManagedRecoveryFault = {
  id:ManagedRecoveryFaultId; gate:string;
  detected:boolean; detection:string;
  originalStatus:RecoveryAssessment["status"];
  injectedStatus:RecoveryAssessment["status"]|"REJECTED";
  blockersAdded:number; unknownsAdded:number;
  reason:string; mutatedPersistedRows:0;
  externalRestoreOperations:0; providerCalls:0;
};
export type ManagedRecoveryFaultMatrix = {
  schema:"cyberpilot.managed.restore.faults.v1";
  organizationId:string; sessionId:string; evaluatedAt:string;
  baselineDigest:string; scenarioCount:number;
  detectedCount:number; undetected:string[];
  faults:ManagedRecoveryFault[]; status:"PASS"|"INCOMPLETE";
  source:"IN_MEMORY_NEGATIVE_SCENARIOS";
  sqlRestoreExecuted:false; externalCustomerSystemsAccessed:false;
  productionDRValidated:false;
};
function incrementTime(x:string|null,deltaMinutes:number):string|null{
  return x===null?null:
    new Date(Date.parse(x)+deltaMinutes*60000).toISOString();
}
const emptyEvidence=(x:RecoverySession,stage:RecoveryStage)=>({
  ...x,observations:x.observations.filter(e=>e.stage!==stage),
});
function corruptedEvidence(s:RecoverySession,stage:RecoveryStage,
  patch:Partial<RecoveryObservation>):RecoverySession{
  const clone=structuredClone(s);
  const first=clone.observations.find(e=>e.stage===stage);
  if(first)Object.assign(first,patch);
  return clone;
}
function simulate(s:RecoverySession,id:ManagedRecoveryFaultId):RecoverySession{
  const x=structuredClone(s);
  switch(id){
  case "NO_BACKUP":
    return emptyEvidence({...x,backupCreatedAt:null,
      latestRestorableBackupAt:null},"BACKUP_IDENTIFIED");
  case "OLD_BACKUP":
    x.latestRestorableBackupAt=incrementTime(x.incidentStartedAt,
      -(x.policy.rpoMinutes+600));
    break;
  case "EXCESSIVE_DOWNTIME":
    x.applicationUsableAt=incrementTime(x.incidentStartedAt,
      x.policy.rtoMinutes+600);
    break;
  case "SOURCE_TARGET_EQUAL":x.targetName=x.sourceName;break;
  case "UNISOLATED_RESTORE":x.targetIsolated=false;break;
  case "MISSING_APPLICATION_PROOF":return emptyEvidence(x,"APP_STARTED");
  case "MISSING_DATABASE_PROOF":return emptyEvidence(x,"DATA_VERIFIED");
  case "WRONG_ORGANIZATION":x.organizationId="foreign-tenant-1234";break;
  case "SELF_VERIFIED_EVIDENCE":
    return corruptedEvidence(x,"BACKUP_IDENTIFIED",{
      verifierId:x.initiatedById,recordedById:x.initiatedById,independent:true,
    });
  case "MALFORMED_CHECKSUM":
    return corruptedEvidence(x,"DATA_VERIFIED",{evidenceDigest:"no-checksum"});
  case "STALE_PROOF":
    return corruptedEvidence(x,"BACKUP_IDENTIFIED",{
      observedAt:new Date(Date.parse(x.asOf)-
        (x.policy.maximumEvidenceAgeDays+30)*86400000).toISOString(),
    });
  case "MISSING_CLEANUP":return emptyEvidence(x,"CLEANUP_CONFIRMED");
  case "UNKNOWN_RPO":x.incidentStartedAt=null;break;
  case "UNKNOWN_RTO":x.applicationUsableAt=null;break;
  case "FAILED_STAGE":
    return corruptedEvidence(x,"SCHEMA_VERIFIED",{signal:"ERROR",independent:false,
      verifierId:null});
  case "FAKE_CI_RECOVERY":
    x.environment="CI_SYNTHETIC";break;
  }
  return x;
}
function detects(id:ManagedRecoveryFaultId,baseline:RecoveryAssessment,
  evaluated:RecoveryAssessment|null,rejected:boolean):boolean{
  if(rejected)return true;
  if(!evaluated)return false;
  const item=(key:string)=>evaluated.gates.find(x=>x.id===key);
  switch(id){
  case "NO_BACKUP":return item("STAGE_BACKUP_IDENTIFIED")?.status==="UNKNOWN";
  case "OLD_BACKUP":return evaluated.rpo.status==="OVER_TARGET"||
    evaluated.rpo.status==="UNKNOWN";
  case "EXCESSIVE_DOWNTIME":return evaluated.rto.status==="OVER_TARGET"||
    evaluated.rto.status==="UNKNOWN";
  case "SOURCE_TARGET_EQUAL":return item("DIFFERENT_SOURCE_TARGET")?.status==="BLOCK";
  case "UNISOLATED_RESTORE":return item("ISOLATED_TARGET")?.status==="BLOCK";
  case "MISSING_APPLICATION_PROOF":return item("STAGE_APP_STARTED")?.status==="UNKNOWN";
  case "MISSING_DATABASE_PROOF":return item("STAGE_DATA_VERIFIED")?.status==="UNKNOWN";
  case "WRONG_ORGANIZATION":return evaluated.organizationId!==baseline.organizationId;
  case "SELF_VERIFIED_EVIDENCE":return evaluated.verifiedEvidenceCount<
    baseline.verifiedEvidenceCount;
  case "MALFORMED_CHECKSUM":return rejected;
  case "STALE_PROOF":return evaluated.obsoleteEvidenceCount>
    baseline.obsoleteEvidenceCount;
  case "MISSING_CLEANUP":return item("STAGE_CLEANUP_CONFIRMED")?.status==="UNKNOWN";
  case "UNKNOWN_RPO":return evaluated.rpo.status==="UNKNOWN";
  case "UNKNOWN_RTO":return evaluated.rto.status==="UNKNOWN";
  case "FAILED_STAGE":return item("STAGE_SCHEMA_VERIFIED")?.status==="BLOCK";
  case "FAKE_CI_RECOVERY":return item("MANAGED_PROVIDER_RESTORE")?.status==="UNKNOWN";
  }
}
export function evaluateManagedRecoveryFaultMatrix(
  session:RecoverySession, ids:readonly ManagedRecoveryFaultId[]=
  MANAGED_RECOVERY_FAULT_IDS,
):ManagedRecoveryFaultMatrix{
  if(ids.length>MANAGED_RECOVERY_FAULT_IDS.length||
    new Set(ids).size!==ids.length||ids.some(x=>!MANAGED_RECOVERY_FAULT_IDS.includes(x)))
    throw Error("RECOVERY_FAULT_SELECTION_INVALID");
  const baseline=assessManagedRestore(session);
  const faults=ids.map(id=>{
    const original=structuredClone(session);
    const injected=simulate(original,id);
    let evaluated:RecoveryAssessment|null=null;
    let rejected=false,detection="";
    try{evaluated=assessManagedRestore(injected);}
    catch(error){rejected=true;detection=error instanceof Error?
      error.message:"INVALID_FAULT_INPUT";}
    const detected=detects(id,baseline,evaluated,rejected);
    const result:ManagedRecoveryFault={
      id,gate:id,detected,detection:detection||"EVALUATED_FROM_LOCAL_COPY",
      originalStatus:baseline.status,
      injectedStatus:rejected?"REJECTED":evaluated!.status,
      blockersAdded:Math.max(0,(evaluated?.blocked??0)-baseline.blocked),
      unknownsAdded:Math.max(0,(evaluated?.unknown??0)-baseline.unknown),
      reason:detected?"Fault observed by validation or restore gate":
        "Fault not distinguished from baseline; verify starting evidence",
      mutatedPersistedRows:0,externalRestoreOperations:0,providerCalls:0,
    };
    return result;
  });
  const undetected=faults.filter(x=>!x.detected).map(x=>x.id);
  return {schema:"cyberpilot.managed.restore.faults.v1",
    organizationId:session.organizationId,sessionId:session.id,
    evaluatedAt:session.asOf,baselineDigest:recoveryDigest(baseline),
    scenarioCount:faults.length,detectedCount:faults.length-undetected.length,
    undetected,faults,status:undetected.length?"INCOMPLETE":"PASS",
    source:"IN_MEMORY_NEGATIVE_SCENARIOS",
    sqlRestoreExecuted:false,externalCustomerSystemsAccessed:false,
    productionDRValidated:false};
}
export type ManagedRecoveryRunbook = {
  schema:"cyberpilot.managed.restore.runbook.v1";
  environment:RecoveryEnvironment;tier:RecoveryTier;
  steps:Array<{id:string;stage:RecoveryStage;
    title:string;instructions:string[];expectedProof:string[];
    actor:string;blocking:boolean;executed:false;
    providerWrites:0;requiresApproval:boolean}>;
  prerequisites:string[];abortConditions:string[];
  liveExecutionAuthorized:false;productionRestoreProven:false;
};
export function createManagedRestoreRunbook(
  environment:RecoveryEnvironment,tier:RecoveryTier,
):ManagedRecoveryRunbook{
  const policy=RECOVERY_POLICIES[tier];
  if(!policy||!["CI_SYNTHETIC","LOCAL_LAB","MANAGED_STAGING",
    "PRODUCTION"].includes(environment))throw Error("RESTORE_RUNBOOK_INPUT_INVALID");
  const templates:Record<RecoveryStage,{
    title:string;instructions:string[];expectedProof:string[];actor:string;
    requiresApproval:boolean
  }>={
    BACKUP_IDENTIFIED:{title:"Identify an independently dated backup",
      instructions:["Inspect configured retention without exposing secrets",
        "Confirm source, timestamp, region, encryption and tenant boundaries",
        "Preserve backup immutable identifier and chain of custody"],
      expectedProof:["Provider or isolated-database backup identifier",
        "Reliable backup timestamp"],actor:"Backup owner",requiresApproval:false},
    RESTORE_STARTED:{title:"Prepare an isolated restore target",
      instructions:["Verify target environment is isolated from production",
        "Confirm restore operator authorization", "Record start timestamp UTC"],
      expectedProof:["Target configuration snapshot","Execution start receipt"],
      actor:"Operations",requiresApproval:true},
    RESTORE_FINISHED:{title:"Complete restore and record provider receipt",
      instructions:["Avoid overwriting production source",
        "Record errors and partial results", "Capture completion timestamp"],
      expectedProof:["Restore completion acknowledgment","Backup source linkage"],
      actor:"Operations",requiresApproval:true},
    SCHEMA_VERIFIED:{title:"Verify migration and schema integrity",
      instructions:["Inspect Prisma migration status on target",
        "Verify expected relations and referential constraints",
        "Record incompatible migrations as blockers"],
      expectedProof:["Migration status from isolated target",
        "Database schema consistency outcome"],
      actor:"Database owner",requiresApproval:false},
    APP_STARTED:{title:"Start the application in isolation",
      instructions:["Use staging-only secrets and non-production routes",
        "Confirm authenticated health endpoint and application startup",
        "Record usable time after verification"],
      expectedProof:["Application health response","Trusted usable timestamp"],
      actor:"Application owner",requiresApproval:true},
    DATA_VERIFIED:{title:"Verify representative data",
      instructions:["Read organization-scoped sentinel evidence and findings",
        "Check integrity digests against source expectations",
        "Ensure no unexpected tenant crossover"],
      expectedProof:["Database checksums","Tenant isolation readback"],
      actor:"Security reviewer",requiresApproval:false},
    ACCESS_REVIEWED:{title:"Review recovery target permissions",
      instructions:["Review role-based database and app access",
        "Check retention, region and encryption requirements",
        "Confirm no customer production credentials have leaked"],
      expectedProof:["Independent access review","Cleanup owner appointment"],
      actor:"Security reviewer",requiresApproval:false},
    CLEANUP_CONFIRMED:{title:"Close and clean the recovery rehearsal",
      instructions:["Dispose temporary restore target per retention policy",
        "Revoke temporary access and verify independently",
        "Record unresolved risks and escalation owner"],
      expectedProof:["Resource cleanup receipt","Temporary access revocation proof"],
      actor:"Operations",requiresApproval:true},
  };
  return {schema:"cyberpilot.managed.restore.runbook.v1",
    environment,tier,prerequisites:[
      "Assign independent restore verifier and database operator",
      "Obtain authorization for the isolated environment",
      "Confirm data residency, privacy and retention obligations",
      "Record measured RPO/RTO targets and rollback criteria",
      "Confirm a restore cannot send customer notifications or integrations",
    ],abortConditions:[
      "Target is not isolated or source and target are identical",
      "Any external customer credential would be reused without consent",
      "Unreconciled data corruption or a failed checksum",
      "Access permissions exceed the managed staging policy",
      "Backup source or time cannot be independently established",
    ],steps:policy.requiredStages.map((stage,i)=>{
      const x=templates[stage];
      return {id:"RESTORE_STAGE_"+(i+1),stage,title:x.title,
        instructions:x.instructions,expectedProof:x.expectedProof,
        actor:x.actor,blocking:true,executed:false as const,
        providerWrites:0 as const,requiresApproval:x.requiresApproval};
    }),liveExecutionAuthorized:false,productionRestoreProven:false};
}
