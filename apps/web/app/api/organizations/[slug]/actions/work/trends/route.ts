import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadWorkTrends} from "../../../../../../../lib/remediation-work-trends";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const result=await loadWorkTrends({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   days:q.has("days")?Number(q.get("days")):30,
   scope:q.get("scope")??"MINE",
   metric:q.get("metric")??"ALL",
   includeComments:q.get("includeComments")!=="false",
   includeChecklist:q.get("includeChecklist")!=="false",
  });
  return NextResponse.json(result,{headers});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json({
   error:error.message,code:error.code,
  },{status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Work trends request",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to load operational activity trends."},
   {status:500,headers});
 }
}
