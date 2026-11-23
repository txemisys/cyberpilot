import { db, type Prisma } from "@cyberpilot/database";
import type { IntegratedReviewer } from "./integrated-risk-service";
import type { OfflineCapture } from "./offline-report-capture-domain";
import {
  buildRecoveryFaultMatrix,
  buildRecoveryDevelopmentAcceptance,
  exportRecoveryFaultMatrix,
  verifyRecoveryFaultMatrix,
  type RecoveryFaultId,
} from "./offline-recovery-fault-matrix";
import {
  defaultRecoveryRehearsalPolicy,
  validateRecoveryPolicy,
  type RecoveryRehearsalPolicy,
} from "./offline-recovery-rehearsal-domain";

/** Read-only, tenant-scoped rehearsal over actual archived PostgreSQL rows. */
export class FaultRehearsalServiceError extends Error {
  constructor(public readonly code:string){
    super(code);
    this.name="FaultRehearsalServiceError";
  }
}
function fail(code:string):never{
  throw new FaultRehearsalServiceError(code);
}
const identifier=(x:unknown):x is string=>
  typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const faults:RecoveryFaultId[]=[
  "PAYLOAD_CHECKSUM_TAMPER","REPORT_SOURCE_CHECKSUM_TAMPER",
  "FOREIGN_TENANT_SUBSTITUTION","MISSING_LATEST_CAPTURE",
  "INCOMPLETE_CAPTURE","CAPTURE_OLDER_THAN_POLICY",
  "DUPLICATED_REPORT_KIND","MISMATCHED_REPORT_KIND",
  "CHANGED_EVIDENCE_SOURCE","EMPTY_ARCHIVE",
  "FUTURE_CAPTURE_TIMESTAMP","PAYLOAD_CAPTURE_TIME_TAMPER",
];
export type ReadFaultMatrixRequest={
  captureIds?:string[];
  latestPerKind?:boolean;
  selectedFaults?:RecoveryFaultId[];
  policy?:RecoveryRehearsalPolicy;
  format?:"JSON"|"CSV"|"MARKDOWN";
};
async function authorize(actor:IntegratedReviewer){
  if(!identifier(actor.organizationId)||!identifier(actor.userId))
    fail("RECOVERY_FAULT_ACTOR_INVALID");
  if(!["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    fail("RECOVERY_FAULT_ROLE_REQUIRED");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member||member.role!==actor.role)
    fail("RECOVERY_FAULT_MEMBERSHIP_REQUIRED");
}
type DbCapture=Awaited<ReturnType<
  typeof db.offlineReportCapture.findMany>>[number];
function map(row:DbCapture):OfflineCapture{
  return{
    id:row.id,
    organizationId:row.organizationId,
    kind:row.kind as OfflineCapture["kind"],
    schemaVersion:row.schemaVersion,
    originalDigest:row.originalDigest,
    payloadDigest:row.payloadDigest,
    payload:row.payload as unknown as OfflineCapture["payload"],
    sourceComplete:row.sourceComplete,
    createdById:row.createdById,
    createdAt:row.createdAt.toISOString(),
    externalAttestation:false,
    customerCertification:false,
  };
}
export async function readRecoveryFaultMatrix(
  actor:IntegratedReviewer,
  request:ReadFaultMatrixRequest={},
){
  await authorize(actor);
  const policy=request.policy??defaultRecoveryRehearsalPolicy();
  if(validateRecoveryPolicy(policy).length)
    fail("RECOVERY_FAULT_POLICY_INVALID");
  const ids=request.captureIds;
  if(ids!==undefined&&(
    !Array.isArray(ids)||ids.length<1||ids.length>40||
    ids.some(x=>!identifier(x))||new Set(ids).size!==ids.length))
    fail("RECOVERY_FAULT_CAPTURE_IDS_INVALID");
  if(request.latestPerKind!==undefined&&
    typeof request.latestPerKind!=="boolean")
    fail("RECOVERY_FAULT_SELECTION_INVALID");
  if(ids&&request.latestPerKind===true)
    fail("RECOVERY_FAULT_SELECTION_AMBIGUOUS");
  const selected=request.selectedFaults??faults;
  if(!Array.isArray(selected)||selected.length===0||
    selected.length>faults.length||
    selected.some(x=>!faults.includes(x))||
    new Set(selected).size!==selected.length)
    fail("RECOVERY_FAULT_SELECTION_INVALID");
  if(request.format!==undefined&&
    !["JSON","CSV","MARKDOWN"].includes(request.format))
    fail("RECOVERY_FAULT_FORMAT_INVALID");
  const rows=request.latestPerKind===true&&!ids?
    (await Promise.all((["INTEGRATED_RISKS","EVIDENCE_DECISIONS",
      "EXECUTIVE","LONGITUDINAL"] as const).map(kind=>
      db.offlineReportCapture.findMany({
        where:{organizationId:actor.organizationId,kind},
        take:1,orderBy:[{createdAt:"desc"},{id:"asc"}],
      })))).flat():
    await db.offlineReportCapture.findMany({
      where:{
        organizationId:actor.organizationId,
        ...(ids?{id:{in:ids}}:{}),
      },
      take:ids?.length??41,
      orderBy:[{createdAt:"desc"},{id:"asc"}],
    });
  if(ids&&rows.length!==ids.length)
    fail("RECOVERY_FAULT_CAPTURE_NOT_IN_TENANT");
  if(rows.some(x=>x.organizationId!==actor.organizationId))
    fail("RECOVERY_FAULT_DATABASE_SCOPE_VIOLATION");
  if(!ids&&request.latestPerKind!==true&&rows.length>40)
    fail("RECOVERY_FAULT_ARCHIVE_TRUNCATED_SELECT_EXPLICITLY");
  let captures=rows.map(map);
  if(request.latestPerKind===true){
    const selectedKinds=new Set<string>();
    captures=captures.filter(x=>{
      if(selectedKinds.has(x.kind))return false;
      selectedKinds.add(x.kind);return true;
    });
  }
  const evaluatedAt=new Date().toISOString();
  const matrix=buildRecoveryFaultMatrix({
    organizationId:actor.organizationId,
    executedAt:evaluatedAt,
    captures,policy,selectedFaults:selected,
  });
  if(!verifyRecoveryFaultMatrix(matrix,actor.organizationId).valid)
    fail("RECOVERY_FAULT_MATRIX_INTEGRITY");
  const acceptance=buildRecoveryDevelopmentAcceptance(matrix);
  const artifact=request.format?
    exportRecoveryFaultMatrix(matrix,request.format):null;
  return{
    schema:"cyberpilot.offline.recovery.fault.read.v1" as const,
    organizationId:actor.organizationId,
    archiveSource:"PERSISTED_CAPTURE_ROWS" as const,
    matrix,acceptance,artifact,
    selectedCaptureCount:captures.length,
    faultCount:matrix.totalFaults,
    faultDetectionCount:matrix.detectedFaults,
    sqlRestoreOperations:0 as const,
    providerOperations:0 as const,
    customerLiveValidated:false as const,
    productionRecoveryEstablished:false as const,
    historicalScoreWrites:0 as const,
  };
}
