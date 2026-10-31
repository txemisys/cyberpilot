import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {loadDigest} from "../../../../../../../../lib/remediation-work-digest";
import {buildDigestQualityReview} from "../../../../../../../../lib/remediation-work-digest-quality";
import {WorkInputError} from "../../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
/** Evaluate currently recorded human task metadata without changing it. */
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const report=await loadDigest({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",days:q.has("days")?Number(q.get("days")):14,
   includeClosed:q.get("includeClosed")==="true",
   maxItems:q.has("maxItems")?Number(q.get("maxItems")):100,
  });
  return NextResponse.json(buildDigestQualityReview(report),{headers});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json({
   code:error.code,error:error.message,
  },{status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Work digest hygiene",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to review work record completeness."},
   {status:500,headers});
 }
}
