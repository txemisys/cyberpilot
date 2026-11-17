import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {collectOfflineActionSla} from "../../../../../lib/offline-action-sla-service";
import {exportSlaOperationalReport} from "../../../../../lib/offline-action-sla";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
const deny=(code:string,status:number)=>NextResponse.json({
  code,providerCalls:0,notificationsSent:0,remediationsVerified:0,
},{status,headers});
export async function GET(request:NextRequest,context:Context){
  if(request.headers.get("origin")&&
     request.headers.get("origin")!==new URL(request.url).origin)
    return deny("FOREIGN_ORIGIN",403);
  const format=new URL(request.url).searchParams.get("format");
  if(format&&!["JSON","CSV","MARKDOWN"].includes(format))
    return deny("INVALID_FORMAT",400);
  try{
    const {membership,session}=await requireOrganizationAccess(
      (await context.params).slug);
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return deny("REVIEWER_REQUIRED",403);
    const report=await collectOfflineActionSla({
      organizationId:membership.organization.id,userId:session.user.id,
      role:membership.role,
    });
    if(format)return NextResponse.json({
      artifact:exportSlaOperationalReport(report,
        format as "JSON"|"CSV"|"MARKDOWN"),
      providerCalls:0,notificationsSent:0,remediationsVerified:0,
    },{headers});
    return NextResponse.json({
      report,providerCalls:0,notificationsSent:0,remediationsVerified:0,
    },{headers});
  }catch{return deny("SLA_READER_UNAVAILABLE",503);}
}
export async function POST(){return deny("READ_ONLY",405);}
export async function PATCH(){return deny("READ_ONLY",405);}
export async function DELETE(){return deny("READ_ONLY",405);}
