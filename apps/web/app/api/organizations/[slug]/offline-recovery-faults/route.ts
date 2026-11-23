import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import {
  FaultRehearsalServiceError,
  readRecoveryFaultMatrix,
  type ReadFaultMatrixRequest,
} from "../../../../../lib/offline-recovery-fault-service";
import type { RecoveryFaultId } from "../../../../../lib/offline-recovery-fault-matrix";
type Context={params:Promise<{slug:string}>};
const headers={
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
};
function reject(code:string,status:number) {
  return NextResponse.json({
    code,sqlRestoreOperations:0,providerOperations:0,
    customerLiveValidated:false,productionRecoveryEstablished:false,
    historicalScoreWrites:0,
  },{status,headers});
}
const validFaults=new Set<RecoveryFaultId>([
  "PAYLOAD_CHECKSUM_TAMPER","REPORT_SOURCE_CHECKSUM_TAMPER",
  "FOREIGN_TENANT_SUBSTITUTION","MISSING_LATEST_CAPTURE",
  "INCOMPLETE_CAPTURE","CAPTURE_OLDER_THAN_POLICY",
  "DUPLICATED_REPORT_KIND","MISMATCHED_REPORT_KIND",
  "CHANGED_EVIDENCE_SOURCE","EMPTY_ARCHIVE",
  "FUTURE_CAPTURE_TIMESTAMP","PAYLOAD_CAPTURE_TIME_TAMPER",
]);
const keys=new Set(["ids","latest","faults","format","maxAgeDays"]);
const identifier=(x:string)=>/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
function parseQuery(request:NextRequest):ReadFaultMatrixRequest {
  const params=new URL(request.url).searchParams;
  if([...params.keys()].some(x=>!keys.has(x))||
     [...keys].some(x=>params.getAll(x).length>1))
    throw Error("RECOVERY_FAULT_QUERY_FIELDS_INVALID");
  const ids=params.get("ids");
  const latest=params.get("latest");
  const chosenFaults=params.get("faults");
  const format=params.get("format");
  const maxAgeDays=params.get("maxAgeDays");
  if(latest!==null&&latest!=="true"&&latest!=="false")
    throw Error("RECOVERY_FAULT_LATEST_INVALID");
  if(ids!==null&&latest==="true")
    throw Error("RECOVERY_FAULT_SELECTION_AMBIGUOUS");
  if(format!==null&&!["JSON","CSV","MARKDOWN"].includes(format))
    throw Error("RECOVERY_FAULT_FORMAT_INVALID");
  const queryRequest:ReadFaultMatrixRequest={
    latestPerKind:latest===null?true:latest==="true",
  };
  if(ids!==null) {
    const list=ids.split(",");
    if(list.length<1||list.length>40||
       list.some(x=>!identifier(x))||new Set(list).size!==list.length)
      throw Error("RECOVERY_FAULT_IDS_INVALID");
    queryRequest.latestPerKind=false;
    queryRequest.captureIds=list;
  }
  if(chosenFaults!==null){
    const list=chosenFaults.split(",") as RecoveryFaultId[];
    if(list.length===0||list.length>12||
       list.some(x=>!validFaults.has(x))||new Set(list).size!==list.length)
      throw Error("RECOVERY_FAULT_SET_INVALID");
    queryRequest.selectedFaults=list;
  }
  if(format!==null)queryRequest.format=format as "JSON"|"CSV"|"MARKDOWN";
  if(maxAgeDays!==null){
    if(!/^\d{1,4}$/.test(maxAgeDays)||
       Number(maxAgeDays)<1||Number(maxAgeDays)>3650)
      throw Error("RECOVERY_FAULT_MAX_AGE_INVALID");
    queryRequest.policy={
      requiredKinds:["INTEGRATED_RISKS","EVIDENCE_DECISIONS",
        "EXECUTIVE","LONGITUDINAL"],
      maxAgeDays:Number(maxAgeDays),
      requireCompleteSources:true,
      requireCrossReportBindings:true,
      refuseDuplicateKinds:true,
      failOnSourceClassChanges:true,
    };
  }
  return queryRequest;
}
export async function GET(request:NextRequest,context:Context) {
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)
    return reject("CROSS_ORIGIN",403);
  let requestBody:ReadFaultMatrixRequest;
  try{requestBody=parseQuery(request);}
  catch(error){return reject(error instanceof Error?error.message:
    "RECOVERY_FAULT_QUERY_INVALID",400);}
  try {
    const {membership,session}=await requireOrganizationAccess(
      (await context.params).slug,
    );
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return reject("RECOVERY_FAULT_PERMISSION_REQUIRED",403);
    const data=await readRecoveryFaultMatrix({
      organizationId:membership.organization.id,
      userId:session.user.id,
      role:membership.role,
    },requestBody);
    return NextResponse.json({
      data,sqlRestoreOperations:0,providerOperations:0,
      customerLiveValidated:false,productionRecoveryEstablished:false,
      historicalScoreWrites:0,
    },{headers});
  }catch(error){
    if(error instanceof FaultRehearsalServiceError)
      return reject(error.code,409);
    return reject("RECOVERY_FAULT_READER_UNAVAILABLE",503);
  }
}
export async function POST(){return reject("READ_ONLY_FAULT_MATRIX",405);}
export async function PUT(){return reject("READ_ONLY_FAULT_MATRIX",405);}
export async function PATCH(){return reject("READ_ONLY_FAULT_MATRIX",405);}
export async function DELETE(){return reject("NO_ARCHIVE_DELETIONS",405);}
