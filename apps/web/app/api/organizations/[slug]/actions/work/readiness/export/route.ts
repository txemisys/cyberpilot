import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {loadGateReview} from "../../../../../../../../lib/remediation-work-readiness";
import {parseReadinessExportSelection,readinessCsv} from "../../../../../../../../lib/remediation-work-readiness-export";
import {WorkInputError} from "../../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const review=await loadGateReview({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",search:q.get("search")??"",
   includeClosed:q.get("includeClosed")==="true",
   requireEvidence:q.get("requireEvidence")!=="false",
   requireChecklist:q.get("requireChecklist")!=="false",
   onlyExceptions:q.get("onlyExceptions")==="true",
  });
  const selection=parseReadinessExportSelection({
   level:q.get("level")??"ALL",
   issue:q.get("issue")??"ALL",
   maxRows:q.get("maxRows")??undefined,
  });
  return new NextResponse(readinessCsv(review,selection),{headers:{
   ...headers,"Content-Type":"text/csv; charset=utf-8",
   "Content-Disposition":'attachment; filename="cyberpilot-work-readiness.csv"',
  }});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json(
   {error:error.message,code:error.code},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Readiness export",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to export readiness."},{status:500,headers});
 }
}
