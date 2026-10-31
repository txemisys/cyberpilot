import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadDigest} from "../../../../../../../lib/remediation-work-digest";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const result=await loadDigest({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",days:q.has("days")?Number(q.get("days")):14,
   includeClosed:q.get("includeClosed")==="true",
   maxItems:q.has("maxItems")?Number(q.get("maxItems")):30,
  });
  return NextResponse.json(result,{headers});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json(
   {error:error.message,code:error.code},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Work digest",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to load operational digest."},{status:500,headers});
 }
}
