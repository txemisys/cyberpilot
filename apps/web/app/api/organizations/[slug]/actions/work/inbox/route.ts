import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {getWorkInbox} from "../../../../../../../lib/remediation-work-inbox";
import {WorkInputError} from "../../../../../../../lib/remediation-work-input";

type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const scope={
   organizationId:membership.organization.id,
   userId:session.user.id,
   role:membership.role,
  };
  return NextResponse.json(
   await getWorkInbox(scope,Object.fromEntries(request.nextUrl.searchParams)),
   {headers},
  );
 }catch(error){
  if(error instanceof WorkInputError){
   return NextResponse.json({
    error:error.message,code:error.code,
   },{status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  }
  console.error("Work inbox failure",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Work inbox could not be loaded."},{status:500,headers});
 }
}
