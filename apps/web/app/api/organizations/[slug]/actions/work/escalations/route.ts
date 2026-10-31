import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadEscalationReview} from "../../../../../../../lib/remediation-work-escalations";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {membership,session}=await requireOrganizationAccess(slug);
  const query=request.nextUrl.searchParams;
  const raw={
   scope:query.get("scope")??undefined,
   order:query.get("order")??undefined,
   minLevel:query.get("minLevel")??undefined,
   thresholdDays:query.has("thresholdDays")?Number(query.get("thresholdDays")):undefined,
   staleDays:query.has("staleDays")?Number(query.get("staleDays")):undefined,
   includeClosed:query.get("includeClosed")==="true",
   search:query.get("search")??"",
  };
  const result=await loadEscalationReview({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },raw);
  return NextResponse.json(result,{headers});
 }catch(error){
  if(error instanceof WorkInputError)
   return NextResponse.json({error:error.message,code:error.code},
    {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Escalation review failed",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Could not load work escalation review."},
   {status:500,headers});
 }
}
