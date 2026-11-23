import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { assessManagedRestore, validateManagedRecoverySession,
  RECOVERY_POLICIES, type RecoverySession, type RecoveryTier }
  from "../../../../../lib/managed-recovery-objectives";
import { evaluateManagedRecoveryFaultMatrix, createManagedRestoreRunbook }
  from "../../../../../lib/managed-recovery-fault-matrix";
import { buildManagedRecoveryDossier, exportManagedRecoveryDossier }
  from "../../../../../lib/managed-recovery-dossier";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"};
function reject(code:string,status:number){
  return NextResponse.json({code,sqlRestoreOperations:0,
    customerTenantCalls:0,productionDrVerified:false},{status,headers});
}
async function actor(context:Context){
  const {session,membership}=await requireOrganizationAccess((await context.params).slug);
  if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
    return null;
  return {userId:session.user.id,organizationId:membership.organization.id,
    role:membership.role};
}
export async function GET(request:NextRequest,context:Context){
  try{
    const current=await actor(context);
    if(!current)return reject("RESTORE_REVIEW_ROLE_REQUIRED",403);
    const q=new URL(request.url).searchParams;
    if([...q.keys()].some(x=>x!=="tier"&&x!=="environment"))
      return reject("RESTORE_QUERY_INVALID",400);
    const tier=(q.get("tier")??"STANDARD") as RecoveryTier;
    const environment=q.get("environment")??"MANAGED_STAGING";
    if(!RECOVERY_POLICIES[tier]||!["CI_SYNTHETIC",
      "LOCAL_LAB","MANAGED_STAGING","PRODUCTION"].includes(environment))
      return reject("RESTORE_POLICY_SELECTION_INVALID",400);
    return NextResponse.json({data:{
      policy:RECOVERY_POLICIES[tier],
      runbook:createManagedRestoreRunbook(environment as RecoverySession["environment"],tier),
      scope:"READ_ONLY_OPERATOR_GUIDANCE",
      databaseRestorePerformed:false,
      productionAssuranceProven:false,
    }},{headers});
  }catch{return reject("RESTORE_READ_UNAVAILABLE",503);}
}
export async function POST(request:NextRequest,context:Context){
  const origin=request.headers.get("origin");
  if(origin&&origin!==new URL(request.url).origin)return reject("CROSS_ORIGIN",403);
  const type=request.headers.get("content-type")?.split(";")[0]?.trim();
  if(type!=="application/json")return reject("RESTORE_JSON_REQUIRED",415);
  const length=request.headers.get("content-length");
  if(length&&(!/^\d+$/.test(length)||Number(length)>40000))
    return reject("RESTORE_INPUT_TOO_LARGE",413);
  try{
    const current=await actor(context);
    if(!current)return reject("RESTORE_REVIEW_ROLE_REQUIRED",403);
    const raw=await request.text();
    if(Buffer.byteLength(raw)>40000)return reject("RESTORE_INPUT_TOO_LARGE",413);
    let value:unknown;
    try{value=JSON.parse(raw);}catch{return reject("RESTORE_INVALID_JSON",400);}
    if(!value||typeof value!=="object"||Array.isArray(value))
      return reject("RESTORE_INPUT_INVALID",400);
    const payload=value as Record<string,unknown>;
    if(Object.keys(payload).some(k=>!["session","format","faults"].includes(k)))
      return reject("RESTORE_UNKNOWN_FIELD",400);
    const s=payload.session as RecoverySession;
    if(!s||typeof s!=="object"||Array.isArray(s))
      return reject("RESTORE_SESSION_REQUIRED",400);
    if(s.organizationId!==current.organizationId)
      return reject("RESTORE_TENANT_SCOPE_DENIED",403);
    // The browser may supply declarations. It cannot confer independent trust
    // or an authenticated verifier for itself, even with a valid session.
    if(s.observations?.some(x=>x.independent===true)||
      s.actualExternalRestorePerformedByCyberPilot!==false||
      s.customerTenantCredentialsUsed!==false)
      return reject("RESTORE_CLIENT_ATTESTATION_NOT_TRUSTED",403);
    const errors=validateManagedRecoverySession(s);
    if(errors.length)return NextResponse.json({code:"RESTORE_SESSION_INVALID",
      errors},{status:400,headers});
    if(s.initiatedById!==current.userId)
      return reject("RESTORE_OPERATOR_IDENTITY_MISMATCH",403);
    const format=payload.format??null;
    if(format!==null&&!["JSON","CSV","MARKDOWN"].includes(String(format)))
      return reject("RESTORE_EXPORT_FORMAT_INVALID",400);
    if(format&&current.role==="AUDITOR")
      return reject("RESTORE_EXPORT_MANAGER_REQUIRED",403);
    const dossier=buildManagedRecoveryDossier(s);
    const faults=payload.faults===true?
      evaluateManagedRecoveryFaultMatrix(s):null;
    const artifact=format?exportManagedRecoveryDossier(dossier,
      format as "JSON"|"CSV"|"MARKDOWN"):null;
    return NextResponse.json({data:{
      dossier,faults,artifact,assessment:assessManagedRestore(s),
      authorizationSource:"CURRENT_ORGANIZATION_MEMBERSHIP",
      evidenceTrust:"CLIENT_DECLARATIONS_NOT_INDEPENDENTLY_VERIFIED",
      databaseRowsModified:0,
      remoteDatabaseRestore:0,providerCalls:0,
      noCustomerLiveAcceptance:true,
    }},{headers});
  }catch{return reject("RESTORE_ASSESSMENT_UNAVAILABLE",503);}
}
export async function PUT(){return reject("RESTORE_WRITES_NOT_SUPPORTED",405);}
export async function DELETE(){return reject("RESTORE_DELETES_NOT_SUPPORTED",405);}
