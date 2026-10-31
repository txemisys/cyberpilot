import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {loadDigest} from "../../../../../../../../lib/remediation-work-digest";
import {digestCsv,parseDigestExportOptions} from "../../../../../../../../lib/remediation-work-digest-export";
import {WorkInputError} from "../../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {membership,session}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const report=await loadDigest({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",
   days:q.has("days")?Number(q.get("days")):14,
   includeClosed:q.get("includeClosed")==="true",
   maxItems:q.has("maxItems")?Number(q.get("maxItems")):100,
  });
  const options=parseDigestExportOptions({
   mode:q.get("mode")??"PRIORITIES",
   maxRows:q.has("maxRows")?Number(q.get("maxRows")):100,
   onlyAttention:q.get("onlyAttention")==="true",
  });
  return new NextResponse(digestCsv(report,options),{headers:{
   ...headers,"Content-Type":"text/csv; charset=utf-8",
   "Content-Disposition":'attachment; filename="cyberpilot-work-digest.csv"',
  }});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json(
   {code:error.code,error:error.message},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Digest export",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to export operational digest."},
   {status:500,headers});
 }
}
