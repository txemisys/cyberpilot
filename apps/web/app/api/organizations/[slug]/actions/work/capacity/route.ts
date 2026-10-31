import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadCapacityReport} from "../../../../../../../lib/remediation-work-capacity";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const report=await loadCapacityReport({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",sort:q.get("sort")??"ATTENTION",
   includeClosed:q.get("includeClosed")==="true",
   horizonDays:q.has("horizonDays")?Number(q.get("horizonDays")):14,
   maxTasks:q.has("maxTasks")?Number(q.get("maxTasks")):10,
  });
  return NextResponse.json(report,{headers});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json({
   error:error.message,code:error.code,
  },{status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Capacity review",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to load team work capacity."},{status:500,headers});
 }
}
