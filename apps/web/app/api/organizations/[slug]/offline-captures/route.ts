import{NextRequest,NextResponse}from "next/server";
import{requireOrganizationAccess}from "../../../../../lib/organizations";
import{listOfflineCaptures,captureOfflineReport,
 readOfflineCapture,comparePersistedCaptures,
 auditOfflineCaptureInventory,OfflineCaptureError}
 from "../../../../../lib/offline-report-capture-service";
import{exportOfflineCaptures}from "../../../../../lib/offline-report-capture-domain";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store",
 "X-Content-Type-Options":"nosniff"};
const denied=(code:string,status:number)=>NextResponse.json({
 code,providerCalls:0,customerCertified:false,
 backupRestorePerformed:false,scoreV1Writes:0,
},{status,headers});
function origin(request:NextRequest){
 const value=request.headers.get("origin");
 return !value||value===new URL(request.url).origin;
}
async function actor(context:Context){
 const {membership,session}=await requireOrganizationAccess(
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
 if(!["LIST","DETAIL","COMPARE","AUDIT","EXPORT"].includes(mode))
 return denied("CAPTURE_MODE_INVALID",400);
 try{
 const current=await actor(context);
 if(!["OWNER","ADMIN","AUDITOR"].includes(current.role))
 return denied("CAPTURE_REVIEW_DENIED",403);
 let data:unknown;
 if(mode==="DETAIL"){
 const id=params.get("id");
 if(!id)return denied("CAPTURE_ID_REQUIRED",400);
 data=await readOfflineCapture(current,id);
 }else if(mode==="COMPARE"){
 const a=params.get("earlier"),b=params.get("later");
 if(!a||!b)return denied("CAPTURE_PAIR_REQUIRED",400);
 data=await comparePersistedCaptures(current,a,b);
 }else if(mode==="AUDIT"){
 data=await auditOfflineCaptureInventory(current);
 }else if(mode==="EXPORT"){
 const format=params.get("format");
 if(!format||!["JSON","CSV","MARKDOWN"].includes(format))
 return denied("CAPTURE_EXPORT_FORMAT_INVALID",400);
 const list=await listOfflineCaptures(current,{
 limit:100,includePayload:true,
 });
 if(list.sourceTruncated)
 return denied("CAPTURE_EXPORT_SOURCE_TRUNCATED",409);
 data={artifact:exportOfflineCaptures(
 list.captures as Parameters<typeof exportOfflineCaptures>[0],
 current.organizationId,format as "JSON"|"CSV"|"MARKDOWN")};
 }else{
 data=await listOfflineCaptures(current,{limit:100});
 }
 return NextResponse.json({data,
 providerCalls:0,customerCertified:false,
 backupRestorePerformed:false,scoreV1Writes:0},{headers});
 }catch(error){
 if(error instanceof OfflineCaptureError)
 return denied(error.code,409);
 return denied("CAPTURE_READ_UNAVAILABLE",503);
 }
}
export async function POST(request:NextRequest,context:Context){
 if(!origin(request))return denied("FOREIGN_ORIGIN",403);
 if(request.headers.get("content-type")?.split(";")[0]?.trim()!==
 "application/json")return denied("JSON_REQUIRED",415);
 const declared=request.headers.get("content-length");
 if(declared&&(!/^\d+$/.test(declared)||Number(declared)>4096))
 return denied("CAPTURE_REQUEST_TOO_LARGE",413);
 try{
 const current=await actor(context);
 if(!["OWNER","ADMIN"].includes(current.role))
 return denied("CAPTURE_CREATOR_DENIED",403);
 const raw=await request.text();
 if(Buffer.byteLength(raw)>4096)return denied("CAPTURE_REQUEST_TOO_LARGE",413);
 let parsed:unknown;
 try{parsed=JSON.parse(raw);}catch{return denied("INVALID_JSON",400);}
 if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))
 return denied("INVALID_CAPTURE_REQUEST",400);
 const command=parsed as Record<string,unknown>;
 if(Object.keys(command).some(key=>![
 "kind","strictComplete","expectedOriginalDigest"].includes(key)))
 return denied("UNKNOWN_CAPTURE_FIELD",400);
 const created=await captureOfflineReport(current,{
 kind:command.kind as "INTEGRATED_RISKS",
 strictComplete:command.strictComplete as boolean,
 ...(Object.hasOwn(command,"expectedOriginalDigest")?
 {expectedOriginalDigest:command.expectedOriginalDigest as string}:{}),
 });
 return NextResponse.json({data:created,providerCalls:0,
 customerCertified:false,backupRestorePerformed:false,
 scoreV1Writes:0},{headers});
 }catch(error){
 if(error instanceof OfflineCaptureError)
 return denied(error.code,409);
 return denied("CAPTURE_CREATION_UNAVAILABLE",503);
 }
}
export async function PUT(){return denied("CAPTURES_IMMUTABLE",405);}
export async function PATCH(){return denied("CAPTURES_IMMUTABLE",405);}
export async function DELETE(){return denied("CAPTURES_IMMUTABLE",405);}
