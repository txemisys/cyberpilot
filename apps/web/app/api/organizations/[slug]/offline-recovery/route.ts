import{NextRequest,NextResponse}from "next/server";
import{requireOrganizationAccess}from "../../../../../lib/organizations";
import{runOfflineRecoveryRehearsal,
 readOfflineRecoveryRehearsal,listOfflineRecoveryRehearsals,
 compareStoredRehearsals,buildRecoveryAcceptanceMatrix,
 auditRecoveryRehearsalInventory,RecoveryRehearsalError}
 from "../../../../../lib/offline-recovery-rehearsal-service";
import{exportRecoveryRehearsal}from
 "../../../../../lib/offline-recovery-rehearsal-domain";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
 "X-Content-Type-Options":"nosniff"};
const denied=(code:string,status:number)=>NextResponse.json({
 code,providerCalls:0,databaseRestores:0,
 customerCertified:false,scoreV1Writes:0,
},{status,headers});
function origin(request:NextRequest){
 const origin=request.headers.get("origin");
 return !origin||origin===new URL(request.url).origin;
}
async function actor(context:Context){
 const{membership,session}=await requireOrganizationAccess(
 (await context.params).slug);
 return{
 organizationId:membership.organization.id,userId:session.user.id,
 role:membership.role,
 };
}
export async function GET(request:NextRequest,context:Context){
 if(!origin(request))return denied("FOREIGN_ORIGIN",403);
 const params=new URL(request.url).searchParams;
 const mode=params.get("mode")??"LIST";
 if(!["LIST","DETAIL","COMPARE","MATRIX","AUDIT","EXPORT"].includes(mode))
 return denied("RECOVERY_MODE_INVALID",400);
 try{
 const current=await actor(context);
 if(!["OWNER","ADMIN","AUDITOR"].includes(current.role))
 return denied("RECOVERY_REVIEW_DENIED",403);
 let data:unknown;
 if(mode==="DETAIL"||mode==="EXPORT"){
 const id=params.get("id");
 if(!id)return denied("RECOVERY_ID_REQUIRED",400);
 const result=await readOfflineRecoveryRehearsal(current,id);
 if(mode==="EXPORT"){
 const format=params.get("format");
 if(!format||!["JSON","CSV","MARKDOWN"].includes(format))
 return denied("RECOVERY_FORMAT_INVALID",400);
 data={artifact:exportRecoveryRehearsal(
 result.report,format as "JSON"|"CSV"|"MARKDOWN")};
 }else data=result;
 }else if(mode==="COMPARE"){
 const a=params.get("earlier"),b=params.get("later");
 if(!a||!b)return denied("RECOVERY_PAIR_REQUIRED",400);
 data=await compareStoredRehearsals(current,a,b);
 }else if(mode==="MATRIX"){
 data=await buildRecoveryAcceptanceMatrix(current);
 }else if(mode==="AUDIT"){
 data=await auditRecoveryRehearsalInventory(current);
 }else data=await listOfflineRecoveryRehearsals(current,50);
 return NextResponse.json({
 data,providerCalls:0,databaseRestores:0,
 customerCertified:false,scoreV1Writes:0,
 },{headers});
 }catch(error){
 if(error instanceof RecoveryRehearsalError)
 return denied(error.code,409);
 return denied("RECOVERY_READER_UNAVAILABLE",503);
 }
}
export async function POST(request:NextRequest,context:Context){
 if(!origin(request))return denied("FOREIGN_ORIGIN",403);
 if(request.headers.get("content-type")?.split(";")[0]?.trim()!==
 "application/json")return denied("JSON_REQUIRED",415);
 const declared=request.headers.get("content-length");
 if(declared&&(!/^\d+$/.test(declared)||Number(declared)>8192))
 return denied("RECOVERY_BODY_TOO_LARGE",413);
 try{
 const current=await actor(context);
 if(!["OWNER","ADMIN"].includes(current.role))
 return denied("RECOVERY_MANAGER_REQUIRED",403);
 const raw=await request.text();
 if(Buffer.byteLength(raw)>8192)return denied("RECOVERY_BODY_TOO_LARGE",413);
 let parsed:unknown;
 try{parsed=JSON.parse(raw);}catch{return denied("INVALID_JSON",400);}
 if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))
 return denied("RECOVERY_COMMAND_INVALID",400);
 const cmd=parsed as Record<string,unknown>;
 if(Object.keys(cmd).some(x=>![
 "captureIds","expectedCaptureDigests","policy"].includes(x)))
 return denied("RECOVERY_UNEXPECTED_FIELD",400);
 const result=await runOfflineRecoveryRehearsal(current,{
 captureIds:cmd.captureIds as string[],
 ...(Object.hasOwn(cmd,"expectedCaptureDigests")?
 {expectedCaptureDigests:cmd.expectedCaptureDigests as Record<string,string>}:
 {}),
 ...(Object.hasOwn(cmd,"policy")?
 {policy:cmd.policy as Parameters<typeof runOfflineRecoveryRehearsal>[1]["policy"]}:
 {}),
 });
 return NextResponse.json({
 data:result,providerCalls:0,databaseRestores:0,
 customerCertified:false,scoreV1Writes:0,
 },{headers});
 }catch(error){
 if(error instanceof RecoveryRehearsalError)
 return denied(error.code,409);
 return denied("RECOVERY_REHEARSAL_UNAVAILABLE",503);
 }
}
export async function PATCH(){return denied("IMMUTABLE_REHEARSALS",405);}
export async function PUT(){return denied("IMMUTABLE_REHEARSALS",405);}
export async function DELETE(){return denied("IMMUTABLE_REHEARSALS",405);}
