import{NextRequest,NextResponse}from "next/server";
import{requireOrganizationAccess}from "../../../../../lib/organizations";
import{readEvidenceDecisionCases,createEvidenceDecisionCase,
 updateEvidenceDecisionCase,DecisionCaseServiceError}
 from "../../../../../lib/evidence-decision-case-service";
import{exportDecisionCaseBoard}from
 "../../../../../lib/evidence-decision-case-domain";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
 "X-Content-Type-Options":"nosniff"};
const denied=(code:string,status:number)=>NextResponse.json({
 code,providerCalls:0,remediationVerified:false,
 customerApprovalCreated:false,scoreV1Modified:false,
},{status,headers});
async function actor(context:Context){
 const {membership,session}=await requireOrganizationAccess(
 (await context.params).slug);
 return{
 organizationId:membership.organization.id,userId:session.user.id,
 role:membership.role,
 };
}
function originAccepted(request:NextRequest){
 const origin=request.headers.get("origin");
 return !origin||origin===new URL(request.url).origin;
}
export async function GET(request:NextRequest,context:Context){
 if(!originAccepted(request))return denied("CROSS_ORIGIN",403);
 const format=new URL(request.url).searchParams.get("format");
 if(format&&!["JSON","CSV","MARKDOWN"].includes(format))
 return denied("FORMAT_INVALID",400);
 try{
 const current=await actor(context);
 if(!["OWNER","ADMIN","AUDITOR"].includes(current.role))
 return denied("REVIEW_PERMISSION_REQUIRED",403);
 const report=await readEvidenceDecisionCases(current);
 if(format){
 const artifact=exportDecisionCaseBoard(report.board,
 format as "JSON"|"CSV"|"MARKDOWN");
 return NextResponse.json({artifact,providerCalls:0,
 remediationVerified:false,customerApprovalCreated:false,
 scoreV1Modified:false},{headers});
 }
 return NextResponse.json({data:report,providerCalls:0,
 remediationVerified:false,customerApprovalCreated:false,
 scoreV1Modified:false},{headers});
 }catch(error){
 if(error instanceof DecisionCaseServiceError)
 return denied(error.code,403);
 return denied("DECISION_CASE_READER_UNAVAILABLE",503);
 }
}
export async function POST(request:NextRequest,context:Context){
 if(!originAccepted(request))return denied("CROSS_ORIGIN",403);
 if(request.headers.get("content-type")?.split(";")[0]?.trim()!==
 "application/json")return denied("JSON_REQUIRED",415);
 const length=request.headers.get("content-length");
 if(length&&(!/^\d+$/.test(length)||Number(length)>8192))
 return denied("BODY_TOO_LARGE",413);
 try{
 const current=await actor(context);
 if(!["OWNER","ADMIN"].includes(current.role))
 return denied("CASE_MANAGER_REQUIRED",403);
 const raw=await request.text();
 if(Buffer.byteLength(raw)>8192)return denied("BODY_TOO_LARGE",413);
 let parsed:unknown;
 try{parsed=JSON.parse(raw);}catch{return denied("INVALID_JSON",400);}
 if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))
 return denied("INVALID_COMMAND",400);
 const cmd=parsed as Record<string,unknown>;
 if(cmd.operation!=="CREATE"&&cmd.operation!=="UPDATE")
 return denied("OPERATION_INVALID",400);
 const allowed=cmd.operation==="CREATE"?
 ["operation","decisionKey","ownerUserId","dueAt","relatedActionId","reviewNote"]:
 ["operation","caseId","expectedRevision","kind","reason",
 "nextOwnerUserId","nextDueAt","relatedActionId"];
 if(Object.keys(cmd).some(k=>!allowed.includes(k)))
 return denied("UNKNOWN_COMMAND_FIELD",400);
 const result=cmd.operation==="CREATE"?
 await createEvidenceDecisionCase(current,{
 decisionKey:cmd.decisionKey as string,
 ownerUserId:cmd.ownerUserId as string|null,
 dueAt:cmd.dueAt as string|null,
 relatedActionId:cmd.relatedActionId as string|null,
 reviewNote:cmd.reviewNote as string|null,
 }):
 await updateEvidenceDecisionCase(current,{
 caseId:cmd.caseId as string,
 expectedRevision:cmd.expectedRevision as number,
 kind:cmd.kind as "START",
 ...(Object.hasOwn(cmd,"reason")?{reason:cmd.reason as string}:{}),
 ...(Object.hasOwn(cmd,"nextOwnerUserId")?
 {nextOwnerUserId:cmd.nextOwnerUserId as string|null}:{}),
 ...(Object.hasOwn(cmd,"nextDueAt")?
 {nextDueAt:cmd.nextDueAt as string|null}:{}),
 ...(Object.hasOwn(cmd,"relatedActionId")?
 {relatedActionId:cmd.relatedActionId as string|null}:{}),
 });
 return NextResponse.json({data:result,providerCalls:0,
 remediationVerified:false,customerApprovalCreated:false,
 scoreV1Modified:false},{headers});
 }catch(error){
 if(error instanceof DecisionCaseServiceError)
 return denied(error.code,409);
 return denied("DECISION_CASE_WRITE_UNAVAILABLE",503);
 }
}
export async function PUT(){return denied("READ_ONLY_METHOD",405);}
export async function DELETE(){return denied("AUDIT_IMMUTABLE",405);}
