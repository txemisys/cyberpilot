import { NextRequest,NextResponse } from "next/server";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {readIntegratedActions,createIntegratedAction,
  updateIntegratedAction,RiskActionError,
} from "../../../../../lib/integrated-action-service";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function denied(code:string,status:number){
  return NextResponse.json({code,providerWrites:0,
    verifiedRemediation:false,customerRiskAcceptance:false,
    legacyCyberScoreChanged:false},{status,headers});
}
async function membership(context:Context){
  const result=await requireOrganizationAccess((await context.params).slug);
  return{
    actor:{
      organizationId:result.membership.organization.id,
      userId:result.session.user.id,
      role:result.membership.role,
    },
    role:result.membership.role,
  };
}
export async function GET(request:NextRequest,context:Context){
  if(request.headers.get("origin")&&
    request.headers.get("origin")!==new URL(request.url).origin)
    return denied("CROSS_ORIGIN",403);
  try{
    const {actor,role}=await membership(context);
    if(!["OWNER","ADMIN","AUDITOR"].includes(role))
      return denied("REVIEW_PERMISSION_REQUIRED",403);
    const report=await readIntegratedActions(actor);
    return NextResponse.json({
      data:report,providerWrites:0,verifiedRemediation:false,
      customerRiskAcceptance:false,legacyCyberScoreChanged:false,
    },{headers});
  }catch(error){
    if(error instanceof RiskActionError)return denied(error.code,403);
    return denied("INTEGRATED_ACTIONS_UNAVAILABLE",503);
  }
}
export async function POST(request:NextRequest,context:Context){
  if(request.headers.get("origin")&&
    request.headers.get("origin")!==new URL(request.url).origin)
    return denied("CROSS_ORIGIN",403);
  if(request.headers.get("content-type")?.split(";")[0]?.trim()!==
    "application/json")
    return denied("JSON_REQUIRED",415);
  const size=request.headers.get("content-length");
  if(size&&(!/^\d+$/.test(size)||Number(size)>8192))
    return denied("BODY_TOO_LARGE",413);
  try{
    const {actor,role}=await membership(context);
    if(!["OWNER","ADMIN"].includes(role))
      return denied("MANAGER_PERMISSION_REQUIRED",403);
    const raw=await request.text();
    if(Buffer.byteLength(raw)>8192)return denied("BODY_TOO_LARGE",413);
    let data:unknown;
    try{data=JSON.parse(raw);}catch{return denied("INVALID_JSON",400);}
    if(!data||typeof data!=="object"||Array.isArray(data))
      return denied("COMMAND_REQUIRED",400);
    const command=data as Record<string,unknown>;
    if(typeof command.operation!=="string")
      return denied("OPERATION_REQUIRED",400);
    const safe=command.operation==="CREATE"?
      ["operation","riskKey","priority","ownerUserId","dueAt","rationale"]:
      ["operation","actionId","expectedRevision","kind",
        "nextOwnerUserId","nextPriority","nextDueAt","reason",
        "exceptionExpiresAt"];
    if(Object.keys(command).some(x=>!safe.includes(x)))
      return denied("EXTRA_FIELD_DENIED",400);
    const result=command.operation==="CREATE"?
      await createIntegratedAction(actor,{
        riskKey:command.riskKey as string,
        priority:command.priority as "LOW"|"NORMAL"|"HIGH"|"URGENT",
        ownerUserId:command.ownerUserId as string|null,
        dueAt:command.dueAt as string|null,
        rationale:command.rationale as string|null,
      }):
      command.operation==="UPDATE"?
      await updateIntegratedAction(actor,{
        actionId:command.actionId as string,
        expectedRevision:command.expectedRevision as number,
        kind:command.kind as "ASSIGN",
        ...(Object.hasOwn(command,"nextOwnerUserId")?
          {nextOwnerUserId:command.nextOwnerUserId as string|null}:{}),
        ...(Object.hasOwn(command,"nextPriority")?
          {nextPriority:command.nextPriority as "LOW"|"NORMAL"|"HIGH"|"URGENT"}:{}),
        ...(Object.hasOwn(command,"nextDueAt")?
          {nextDueAt:command.nextDueAt as string|null}:{}),
        ...(Object.hasOwn(command,"reason")?
          {reason:command.reason as string}:{}),
        ...(Object.hasOwn(command,"exceptionExpiresAt")?
          {exceptionExpiresAt:command.exceptionExpiresAt as string|null}:{}),
      }):null;
    if(!result)return denied("UNSUPPORTED_OPERATION",400);
    return NextResponse.json({data:result,providerWrites:0,
      verifiedRemediation:false,customerRiskAcceptance:false,
      legacyCyberScoreChanged:false},{headers});
  }catch(error){
    if(error instanceof RiskActionError)return denied(error.code,409);
    return denied("ACTION_WRITE_UNAVAILABLE",503);
  }
}
export async function PUT(){return denied("METHOD_NOT_SUPPORTED",405);}
export async function DELETE(){return denied("AUDIT_IMMUTABLE",405);}
