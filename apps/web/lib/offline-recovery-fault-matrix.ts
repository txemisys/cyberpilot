import { createHash } from "node:crypto";
import {
  buildOfflineRecoveryRehearsal,
  defaultRecoveryRehearsalPolicy,
  verifyRecoveryRehearsal,
  type OfflineRecoveryRehearsal,
  type RecoveryRehearsalPolicy,
  type RecoveryGateId,
} from "./offline-recovery-rehearsal-domain";
import {
  verifyOfflineCapture, type OfflineCapture,
  type OfflineCaptureKind,
} from "./offline-report-capture-domain";

/**
 * Mutation-free fault matrix for archived offline evidence.
 *
 * Faults are applied only to in-memory clones. This module cannot
 * perform SQL restores, provider calls, customer authorization or
 * changes to stored CyberScore versions.
 */
export type RecoveryFaultId =
  | "PAYLOAD_CHECKSUM_TAMPER"
  | "REPORT_SOURCE_CHECKSUM_TAMPER"
  | "FOREIGN_TENANT_SUBSTITUTION"
  | "MISSING_LATEST_CAPTURE"
  | "INCOMPLETE_CAPTURE"
  | "CAPTURE_OLDER_THAN_POLICY"
  | "DUPLICATED_REPORT_KIND"
  | "MISMATCHED_REPORT_KIND"
  | "CHANGED_EVIDENCE_SOURCE"
  | "EMPTY_ARCHIVE"
  | "FUTURE_CAPTURE_TIMESTAMP"
  | "PAYLOAD_CAPTURE_TIME_TAMPER";

export type RecoveryFaultFinding = {
  fault: RecoveryFaultId;
  captureId: string | null;
  executedAt: string;
  expectedGate: RecoveryGateId | "INPUT_INVARIANT";
  detected: boolean;
  detector: "RECOVERY_GATE"|"VALIDATION"|"EXCEPTION"|"NOT_DETECTED";
  actualGateStatus: "PASS"|"BLOCK"|"NOT_VERIFIED"|"NOT_APPLICABLE"|null;
  effect: string;
  blockedBefore: boolean;
  blockedAfter: boolean;
  changedOnlyInMemory: true;
  sqlRowsModified: 0;
  providerWrites: 0;
  customerAuthorizationIssued: false;
};
export type RecoveryFaultMatrix = {
  schema: "cyberpilot.offline.recovery.fault.matrix.v1";
  organizationId: string;
  executedAt: string;
  policy: RecoveryRehearsalPolicy;
  selectedCaptureIds: string[];
  selectedKinds: OfflineCaptureKind[];
  baselineDigest: string | null;
  baselineStatus: OfflineRecoveryRehearsal["status"] | null;
  baselineValid: boolean;
  faults: RecoveryFaultFinding[];
  totalFaults: number;
  detectedFaults: number;
  undetectedFaults: RecoveryFaultId[];
  sourceCapturesValid: boolean;
  canAcceptJsonArchiveIntegrity: boolean;
  actualSqlRestoreExecuted: false;
  independentSqlRestoreEvidenceProvided: false;
  sqlRecoveryGate: "NOT_VERIFIED";
  liveAuthorizationGate: "NOT_VERIFIED";
  customerLiveAcceptance: false;
  providerCalls: 0;
  historicalCyberScoreWrites: 0;
  digest: string;
};
export type RecoveryFaultMatrixExport = {
  filename: string;
  mime: "application/json"|"text/csv"|"text/markdown";
  content: string;
  partial: boolean;
};
export type RecoveryAcceptanceItem = {
  id: string;
  required: boolean;
  status: "PASS"|"BLOCK"|"NOT_VERIFIED";
  reason: string;
  evidenceDigest: string | null;
  customerAttested: false;
};
export type RecoveryDevelopmentAcceptance = {
  schema: "cyberpilot.offline.recovery.development.acceptance.v1";
  organizationId: string;
  evaluatedAt: string;
  sourceDigest: string;
  items: RecoveryAcceptanceItem[];
  status: "PASS_OFFLINE_JSON"|"BLOCKED"|"INCOMPLETE";
  jsonRehearsalGate: "PASS"|"BLOCK"|"NOT_VERIFIED";
  faultDetectionGate: "PASS"|"BLOCK"|"NOT_VERIFIED";
  sqlRestoreGate: "NOT_VERIFIED";
  liveTenantGate: "NOT_VERIFIED";
  actionableProblems: string[];
  completeOfflineIntegrityOnly: boolean;
  productionRecoveryProven: false;
  tenantLiveAuthorized: false;
  certifiedBackup: false;
  CyberScoreV1Modified: false;
};
const faultIds: RecoveryFaultId[] = [
  "PAYLOAD_CHECKSUM_TAMPER",
  "REPORT_SOURCE_CHECKSUM_TAMPER",
  "FOREIGN_TENANT_SUBSTITUTION",
  "MISSING_LATEST_CAPTURE",
  "INCOMPLETE_CAPTURE",
  "CAPTURE_OLDER_THAN_POLICY",
  "DUPLICATED_REPORT_KIND",
  "MISMATCHED_REPORT_KIND",
  "CHANGED_EVIDENCE_SOURCE",
  "EMPTY_ARCHIVE",
  "FUTURE_CAPTURE_TIMESTAMP",
  "PAYLOAD_CAPTURE_TIME_TAMPER",
];
const kinds: OfflineCaptureKind[] = [
  "INTEGRATED_RISKS", "EVIDENCE_DECISIONS","EXECUTIVE","LONGITUDINAL",
];
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
const iso = (v: unknown): v is string =>
  typeof v==="string" && Number.isFinite(Date.parse(v)) &&
  new Date(v).toISOString()===v;
const key = (v: unknown) => typeof v==="string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const unique = <T>(items: readonly T[]) => [...new Set(items)];
const fakeDigest = "0".repeat(64);

function prepare(captures: readonly OfflineCapture[]) {
  return structuredClone(captures) as OfflineCapture[];
}
function source(captures: readonly OfflineCapture[]) {
  return captures[0] ?? null;
}
function anyOther(kind: OfflineCaptureKind): OfflineCaptureKind {
  return kinds.find(x => x !== kind) ?? "INTEGRATED_RISKS";
}
function changeInput(fault: RecoveryFaultId,
  original: readonly OfflineCapture[],
  organizationId: string,
  now: string,
  policy: RecoveryRehearsalPolicy,
): {captures: OfflineCapture[]; affected: string|null} {
  const captures=prepare(original);
  const first=source(captures);
  const affected=first?.id ?? null;
  if (fault === "EMPTY_ARCHIVE") return {captures:[],affected};
  if (!first) return {captures,affected:null};
  switch(fault) {
  case "PAYLOAD_CHECKSUM_TAMPER":
    first.payloadDigest=fakeDigest===first.payloadDigest?
      "1".repeat(64):fakeDigest;
    break;
  case "REPORT_SOURCE_CHECKSUM_TAMPER":
    first.originalDigest=fakeDigest===first.originalDigest?
      "1".repeat(64):fakeDigest;
    break;
  case "FOREIGN_TENANT_SUBSTITUTION":
    first.organizationId=organizationId+"-foreign";
    break;
  case "MISSING_LATEST_CAPTURE":
    captures.shift();
    break;
  case "INCOMPLETE_CAPTURE":
    first.sourceComplete=false;
    break;
  case "CAPTURE_OLDER_THAN_POLICY":
    first.createdAt=new Date(
      Date.parse(now)-(policy.maxAgeDays+30)*86400000).toISOString();
    break;
  case "DUPLICATED_REPORT_KIND": {
    const duplicate=structuredClone(first);
    duplicate.id=first.id+"-duplicate";
    captures.push(duplicate);
    break;
  }
  case "MISMATCHED_REPORT_KIND":
    first.kind=anyOther(first.kind);
    break;
  case "CHANGED_EVIDENCE_SOURCE":
    first.payload.reportDigest=fakeDigest===first.payload.reportDigest?
      "1".repeat(64):fakeDigest;
    break;
  case "FUTURE_CAPTURE_TIMESTAMP":
    first.createdAt=new Date(Date.parse(now)+86400000).toISOString();
    break;
  case "PAYLOAD_CAPTURE_TIME_TAMPER":
    first.payload.capturedAt=new Date(
      Date.parse(first.payload.capturedAt)+3600000).toISOString();
    break;
  }
  return {captures,affected};
}
function expectedFor(fault: RecoveryFaultId): RecoveryGateId|"INPUT_INVARIANT" {
  switch(fault) {
  case "PAYLOAD_CHECKSUM_TAMPER":return "PAYLOAD_DIGEST";
  case "REPORT_SOURCE_CHECKSUM_TAMPER":return "ORIGINAL_REPORT";
  case "FOREIGN_TENANT_SUBSTITUTION":return "TENANT_BOUNDARY";
  case "MISSING_LATEST_CAPTURE":return "SOURCE_PRESENT";
  case "INCOMPLETE_CAPTURE":return "SOURCE_COMPLETE";
  case "CAPTURE_OLDER_THAN_POLICY":return "CAPTURE_AGE";
  case "DUPLICATED_REPORT_KIND":return "KIND_DUPLICATION";
  case "MISMATCHED_REPORT_KIND":return "PAYLOAD_DIGEST";
  case "CHANGED_EVIDENCE_SOURCE":return "PAYLOAD_DIGEST";
  case "EMPTY_ARCHIVE":return "SOURCE_PRESENT";
  case "FUTURE_CAPTURE_TIMESTAMP":return "CAPTURE_AGE";
  case "PAYLOAD_CAPTURE_TIME_TAMPER":return "PAYLOAD_DIGEST";
  }
}
function faultEffect(fault:RecoveryFaultId) {
  const messages:Record<RecoveryFaultId,string>={
    PAYLOAD_CHECKSUM_TAMPER:"Stored payload digest no longer matches its bytes",
    REPORT_SOURCE_CHECKSUM_TAMPER:"Original report checksum was replaced",
    FOREIGN_TENANT_SUBSTITUTION:"A foreign-organization envelope was injected",
    MISSING_LATEST_CAPTURE:"One selected source was removed from memory",
    INCOMPLETE_CAPTURE:"Original source completeness flag was cleared",
    CAPTURE_OLDER_THAN_POLICY:"An archived capture was aged beyond policy",
    DUPLICATED_REPORT_KIND:"A source type was duplicated in memory",
    MISMATCHED_REPORT_KIND:"Capture kind was made incompatible with payload",
    CHANGED_EVIDENCE_SOURCE:"Original report provenance pointer was changed",
    EMPTY_ARCHIVE:"The complete selected archive was removed",
    FUTURE_CAPTURE_TIMESTAMP:"Archive creation time was moved to the future",
    PAYLOAD_CAPTURE_TIME_TAMPER:"Payload capture time was altered",
  };
  return messages[fault];
}
function gateFailure(
  report:OfflineRecoveryRehearsal,
  gate:RecoveryGateId|"INPUT_INVARIANT",
): {detected:boolean; status:RecoveryFaultFinding["actualGateStatus"]} {
  if(gate==="INPUT_INVARIANT")return {
    detected:report.status==="BLOCKED",status:null,
  };
  const matching=report.gates.filter(x=>x.id===gate);
  return {
    detected:matching.some(x=>x.status==="BLOCK"),
    status:matching.find(x=>x.status==="BLOCK")?.status ??
      matching[0]?.status ?? null,
  };
}
function observedFault(
  organizationId:string,
  executedAt:string,
  policy:RecoveryRehearsalPolicy,
  original:readonly OfflineCapture[],
  baseline:OfflineRecoveryRehearsal,
  fault:RecoveryFaultId,
):RecoveryFaultFinding {
  const expectedGate=expectedFor(fault);
  const changed=changeInput(fault,original,organizationId,executedAt,policy);
  let detector:RecoveryFaultFinding["detector"]="NOT_DETECTED";
  let detected=false;
  let status:RecoveryFaultFinding["actualGateStatus"]=null;
  let blockedAfter=false;
  // Tenant changes and invalid inputs must be rejected before constructing
  // any report, not silently converted into a successful rehearsal.
  try {
    if(changed.captures.some(x=>x.organizationId!==organizationId))
      throw Error("RECOVERY_TENANT_BOUNDARY");
    const invalidEnvelopes=changed.captures.filter(x=>
      !verifyOfflineCapture(x,organizationId).valid);
    if(invalidEnvelopes.length&&[
      "PAYLOAD_CHECKSUM_TAMPER","REPORT_SOURCE_CHECKSUM_TAMPER",
      "MISMATCHED_REPORT_KIND","CHANGED_EVIDENCE_SOURCE",
      "PAYLOAD_CAPTURE_TIME_TAMPER","INCOMPLETE_CAPTURE",
    ].includes(fault)){
      detected=true;detector="VALIDATION";blockedAfter=true;status="BLOCK";
    }
    const replay=buildOfflineRecoveryRehearsal({
      organizationId,executedAt,
      policy,captures:changed.captures,
    });
    const tested=gateFailure(replay,expectedGate);
    if(tested.detected){
      detected=true;detector="RECOVERY_GATE";status=tested.status;
    }
    blockedAfter=replay.status!=="PASS";
    // Source deletion is detected if required kinds are missing.
    if(fault==="MISSING_LATEST_CAPTURE"&&
      !changed.captures.some(x=>x.id===changed.affected)&&
      replay.overview.missingRequiredKinds>0){
      detected=true;detector="RECOVERY_GATE";status="BLOCK";
    }
    if(fault==="EMPTY_ARCHIVE"&&replay.status!=="PASS"){
      detected=true;detector="RECOVERY_GATE";status="BLOCK";
    }
  }catch{
    detected=true;detector="EXCEPTION";blockedAfter=true;status="BLOCK";
  }
  return {
    fault,captureId:changed.affected,executedAt,
    expectedGate,detected,detector,actualGateStatus:status,
    effect:faultEffect(fault),
    blockedBefore:baseline.status!=="PASS",
    blockedAfter,changedOnlyInMemory:true,
    sqlRowsModified:0,providerWrites:0,
    customerAuthorizationIssued:false,
  };
}
export function buildRecoveryFaultMatrix(input:{
  organizationId:string;executedAt:string;
  captures:OfflineCapture[];
  policy?:RecoveryRehearsalPolicy;
  selectedFaults?:RecoveryFaultId[];
}):RecoveryFaultMatrix {
  const policy=input.policy??defaultRecoveryRehearsalPolicy();
  if(!key(input.organizationId)||!iso(input.executedAt)||
    !Array.isArray(input.captures)||input.captures.length>40||
    input.captures.some(x=>x.organizationId!==input.organizationId))
    throw Error("RECOVERY_MATRIX_SCOPE_OR_BOUNDS_INVALID");
  const selected=input.selectedFaults??faultIds;
  if(!Array.isArray(selected)||selected.length>faultIds.length||
    new Set(selected).size!==selected.length||
    selected.some(x=>!faultIds.includes(x)))
    throw Error("RECOVERY_MATRIX_FAULTS_INVALID");
  const originals=prepare(input.captures);
  const sourceCapturesValid=originals.every(x=>
    verifyOfflineCapture(x,input.organizationId).valid);
  let baseline:OfflineRecoveryRehearsal|null=null;
  try {
    baseline=buildOfflineRecoveryRehearsal({
      organizationId:input.organizationId,
      executedAt:input.executedAt,
      captures:originals,policy,
    });
  }catch{baseline=null;}
  const findings=baseline?selected.map(fault=>observedFault(
    input.organizationId,input.executedAt,policy,
    originals,baseline!,fault)):selected.map(fault=>({
    fault,captureId:null,executedAt:input.executedAt,
    expectedGate:expectedFor(fault),detected:false,
    detector:"NOT_DETECTED" as const,actualGateStatus:null,
    effect:faultEffect(fault),blockedBefore:true,blockedAfter:true,
    changedOnlyInMemory:true as const,sqlRowsModified:0 as const,
    providerWrites:0 as const,customerAuthorizationIssued:false as const,
  }));
  const base={
    schema:"cyberpilot.offline.recovery.fault.matrix.v1" as const,
    organizationId:input.organizationId,
    executedAt:input.executedAt,
    policy,
    selectedCaptureIds:originals.map(x=>x.id),
    selectedKinds:unique(originals.map(x=>x.kind)),
    baselineDigest:baseline?.digest??null,
    baselineStatus:baseline?.status??null,
    baselineValid:Boolean(baseline&&
      verifyRecoveryRehearsal(baseline,input.organizationId).valid),
    faults:findings,
    totalFaults:findings.length,
    detectedFaults:findings.filter(x=>x.detected).length,
    undetectedFaults:findings.filter(x=>!x.detected).map(x=>x.fault),
    sourceCapturesValid,
    canAcceptJsonArchiveIntegrity:Boolean(originals.length&&
      sourceCapturesValid&&baseline&&
      verifyRecoveryRehearsal(baseline,input.organizationId).valid&&
      baseline.status==="PASS"&&findings.every(x=>x.detected)),
    actualSqlRestoreExecuted:false as const,
    independentSqlRestoreEvidenceProvided:false as const,
    sqlRecoveryGate:"NOT_VERIFIED" as const,
    liveAuthorizationGate:"NOT_VERIFIED" as const,
    customerLiveAcceptance:false as const,
    providerCalls:0 as const,
    historicalCyberScoreWrites:0 as const,
  };
  return {...base,digest:hash(JSON.stringify(base))};
}
export function verifyRecoveryFaultMatrix(
  matrix:RecoveryFaultMatrix,organizationId?:string,
): {valid:boolean;issues:string[]} {
  const errors:string[]=[];
  if(matrix.schema!=="cyberpilot.offline.recovery.fault.matrix.v1"||
    (organizationId&&matrix.organizationId!==organizationId))
    errors.push("RECOVERY_MATRIX_SCOPE_INVALID");
  const {digest,...base}=matrix;
  if(digest!==hash(JSON.stringify(base)))
    errors.push("RECOVERY_MATRIX_DIGEST_INVALID");
  if(matrix.faults.length!==matrix.totalFaults||
    matrix.detectedFaults!==matrix.faults.filter(x=>x.detected).length||
    matrix.undetectedFaults.join("|")!==
      matrix.faults.filter(x=>!x.detected).map(x=>x.fault).join("|"))
    errors.push("RECOVERY_MATRIX_COUNTERS_INVALID");
  if(matrix.actualSqlRestoreExecuted!==false||
    matrix.independentSqlRestoreEvidenceProvided!==false||
    matrix.sqlRecoveryGate!=="NOT_VERIFIED"||
    matrix.liveAuthorizationGate!=="NOT_VERIFIED"||
    matrix.customerLiveAcceptance!==false||
    matrix.providerCalls!==0||matrix.historicalCyberScoreWrites!==0)
    errors.push("RECOVERY_MATRIX_FALSE_EXTERNAL_CLAIM");
  if(matrix.faults.some(x=>x.changedOnlyInMemory!==true||
    x.sqlRowsModified!==0||x.providerWrites!==0||
    x.customerAuthorizationIssued!==false))
    errors.push("RECOVERY_MATRIX_MUTATION_CLAIM");
  if(matrix.canAcceptJsonArchiveIntegrity&&(
    !matrix.baselineValid||matrix.baselineStatus!=="PASS"||
    !matrix.sourceCapturesValid||matrix.undetectedFaults.length))
    errors.push("RECOVERY_MATRIX_FALSE_PASS");
  return {valid:errors.length===0,issues:unique(errors)};
}
export function buildRecoveryDevelopmentAcceptance(
  matrix:RecoveryFaultMatrix,
):RecoveryDevelopmentAcceptance {
  if(!verifyRecoveryFaultMatrix(matrix).valid)
    throw Error("RECOVERY_ACCEPTANCE_SOURCE_INVALID");
  const integrity=matrix.baselineValid&&matrix.baselineStatus==="PASS";
  const detected=matrix.totalFaults>0&&matrix.undetectedFaults.length===0;
  const items:RecoveryAcceptanceItem[]=[
    {
      id:"JSON_SOURCE_REPLAY",required:true,
      status:integrity?"PASS":matrix.baselineDigest?"BLOCK":"NOT_VERIFIED",
      reason:integrity?"Archived JSON checksum and lineage revalidated":
        "Local JSON rehearsal did not meet all integrity gates",
      evidenceDigest:matrix.baselineDigest,customerAttested:false,
    },{
      id:"FAULT_DETECTION_MATRIX",required:true,
      status:detected?"PASS":"BLOCK",
      reason:detected?"Selected in-memory faults were detected":
        "At least one injected failure escaped the local gate checks",
      evidenceDigest:matrix.digest,customerAttested:false,
    },{
      id:"ISOLATED_SQL_RESTORE_CI",required:false,
      status:"NOT_VERIFIED",
      reason:"SQL restore must be proved by the separate PostgreSQL CI workflow",
      evidenceDigest:null,customerAttested:false,
    },{
      id:"LIVE_TENANT_AUTHORIZATION",required:false,
      status:"NOT_VERIFIED",
      reason:"No real customer or LIVE provider authorization was evaluated",
      evidenceDigest:null,customerAttested:false,
    },
  ];
  const problems=items.filter(x=>x.status!=="PASS")
    .map(x=>x.id+":"+x.reason);
  const ready=integrity&&detected;
  return {
    schema:"cyberpilot.offline.recovery.development.acceptance.v1",
    organizationId:matrix.organizationId,evaluatedAt:matrix.executedAt,
    sourceDigest:matrix.digest,items,
    status:ready?"PASS_OFFLINE_JSON":
      matrix.baselineDigest?"BLOCKED":"INCOMPLETE",
    jsonRehearsalGate:integrity?"PASS":"BLOCK",
    faultDetectionGate:detected?"PASS":"BLOCK",
    sqlRestoreGate:"NOT_VERIFIED",
    liveTenantGate:"NOT_VERIFIED",
    actionableProblems:problems,
    completeOfflineIntegrityOnly:ready,
    productionRecoveryProven:false,
    tenantLiveAuthorized:false,
    certifiedBackup:false,
    CyberScoreV1Modified:false,
  };
}
const csv=(value:unknown)=>'"'+String(value??"")
  .replaceAll('"','""').replace(/^[=+@\-]/,x=>"'"+x)+'"';
export function exportRecoveryFaultMatrix(
  matrix:RecoveryFaultMatrix,format:"JSON"|"CSV"|"MARKDOWN",
):RecoveryFaultMatrixExport {
  if(!verifyRecoveryFaultMatrix(matrix).valid)
    throw Error("RECOVERY_MATRIX_EXPORT_SOURCE_INVALID");
  const filename="cyberpilot-recovery-faults-"+matrix.executedAt.slice(0,10);
  const partial=matrix.undetectedFaults.length>0||
    !matrix.baselineValid||matrix.baselineStatus!=="PASS";
  if(format==="JSON")return {
    filename:filename+".json",mime:"application/json",
    content:JSON.stringify({
      matrix,acceptance:buildRecoveryDevelopmentAcceptance(matrix),
    },null,2),partial,
  };
  if(format==="CSV")return {
    filename:filename+".csv",mime:"text/csv",
    content:[
      "fault,expectedGate,detected,detector,actualStatus,effect",
      ...matrix.faults.map(x=>[
        x.fault,x.expectedGate,x.detected,x.detector,
        x.actualGateStatus,x.effect,
      ].map(csv).join(",")),
    ].join("\n"),partial,
  };
  if(format!=="MARKDOWN")throw Error("RECOVERY_MATRIX_FORMAT_INVALID");
  const acceptance=buildRecoveryDevelopmentAcceptance(matrix);
  return {
    filename:filename+".md",mime:"text/markdown",
    content:[
      "# Offline recovery fault injection evidence",
      "Organization: "+matrix.organizationId,
      "Executed: "+matrix.executedAt,
      "Digest: "+matrix.digest,
      "Selected archive captures: "+matrix.selectedCaptureIds.length,
      "Faults detected: "+matrix.detectedFaults+"/"+matrix.totalFaults,
      "Acceptance: "+acceptance.status,
      "",
      "| Fault | Expected | Detected | Detector |",
      "| --- | --- | --- | --- |",
      ...matrix.faults.map(x=>"| "+x.fault+" | "+x.expectedGate+
        " | "+x.detected+" | "+x.detector+" |"),
      "",
      "SQL restore: NOT VERIFIED by this module.",
      "External tenant authorization: NOT VERIFIED.",
      "No provider writes, production restore, or security certification.",
    ].join("\n"),partial,
  };
}
