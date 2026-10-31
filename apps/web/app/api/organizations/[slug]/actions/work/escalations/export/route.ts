import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {loadEscalationReview} from "../../../../../../../../lib/remediation-work-escalations";
import {parseExportSelection,escalationCsv} from "../../../../../../../../lib/remediation-work-escalation-export";
import {WorkInputError} from "../../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const review=await loadEscalationReview({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",order:q.get("order")??"SEVERITY",
   minLevel:"NONE",search:q.get("search")??"",
   thresholdDays:q.has("thresholdDays")?Number(q.get("thresholdDays")):14,
   staleDays:q.has("staleDays")?Number(q.get("staleDays")):30,
   includeClosed:q.get("includeClosed")==="true",
  });
  const selection=parseExportSelection({
   minLevel:q.get("minLevel")??"WATCH",
   includeClosed:q.get("includeClosed")==="true",
   onlyOverdue:q.get("onlyOverdue")==="true",
   maxRows:q.get("maxRows")??undefined,
  });
  return new NextResponse(escalationCsv(review,selection),{
   headers:{...headers,"Content-Type":"text/csv; charset=utf-8",
    "Content-Disposition":'attachment; filename="cyberpilot-work-escalations.csv"'},
  });
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json(
   {code:error.code,error:error.message},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Escalation CSV export",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to export escalation review."},{status:500,headers});
 }
}
