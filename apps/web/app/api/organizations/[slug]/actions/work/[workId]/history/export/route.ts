import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../../lib/organizations";
import {HistoryInputError} from "../../../../../../../../../lib/work-audit-history";
import {exportWorkAuditHistory} from "../../../../../../../../../lib/work-audit-store";
type Route={params:Promise<{slug:string;workId:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const data=await exportWorkAuditHistory({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role
  },workId,Object.fromEntries(request.nextUrl.searchParams));
  return new NextResponse(data.body,{status:200,headers:{
   ...headers,"Content-Type":"text/csv; charset=utf-8",
   "Content-Disposition":`attachment; filename="cyberpilot-work-audit-${workId.replace(/[^a-zA-Z0-9_-]/g,"_")}.csv"`
  }});
 }catch(error){
  if(error instanceof HistoryInputError)
   return NextResponse.json({error:error.message,code:error.code},{
    status:error.code==="NOT_FOUND"?404:error.code==="CAPACITY"?413:400,headers
   });
  console.error("Work audit export",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Unable to export work history."},{status:500,headers});
 }
}
