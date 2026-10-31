import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {buildPlanningScenario} from "../../../../../../../lib/remediation-assignment-planner";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";

type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function POST(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const length=Number(request.headers.get("content-length"));
  if(length>65536)return NextResponse.json({error:"Planning input too large."},{status:413,headers});
  const body:unknown=await request.json();
  const scenario=await buildPlanningScenario({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role
  },body);
  return NextResponse.json(scenario,{headers});
 }catch(error){
  if(error instanceof SyntaxError)return NextResponse.json(
   {error:"Invalid JSON request."},{status:400,headers});
  if(error instanceof WorkInputError)return NextResponse.json(
   {error:error.message,code:error.code},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Assignment planning failed",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to calculate assignment scenario."},{status:500,headers});
 }
}
