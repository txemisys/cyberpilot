import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from
  "../../../../../lib/organizations";
import {collectExecutiveCockpit} from
  "../../../../../lib/integrated-executive-cockpit-service";
import {exportExecutiveCockpit,verifyExecutiveCockpit} from
  "../../../../../lib/integrated-executive-cockpit";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function denied(code:string,status:number){
  return NextResponse.json({
    code,externalProviderCalls:0,
    acceptedCustomerRisk:false,legacyScoreChanged:false,
    independentlyVerifiedRemediation:false,
  },{status,headers});
}
export async function GET(request:NextRequest,context:Context){
  if(request.headers.get("origin")&&
    request.headers.get("origin")!==new URL(request.url).origin)
    return denied("CROSS_ORIGIN_DENIED",403);
  const format=new URL(request.url).searchParams.get("format");
  if(format&&!["JSON","CSV","MARKDOWN"].includes(format))
    return denied("INVALID_EXECUTIVE_FORMAT",400);
  try{
    const {membership,session}=await requireOrganizationAccess(
      (await context.params).slug);
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return denied("REVIEW_PERMISSION_REQUIRED",403);
    const report=await collectExecutiveCockpit({
      organizationId:membership.organization.id,
      userId:session.user.id,role:membership.role,
    });
    if(!verifyExecutiveCockpit(report,membership.organization.id).valid)
      return denied("INTEGRITY_VERIFICATION_FAILED",500);
    if(format){
      const artifact=exportExecutiveCockpit(report,
        format as "JSON"|"CSV"|"MARKDOWN");
      return NextResponse.json({artifact,digest:report.digest,
        externalProviderCalls:0,acceptedCustomerRisk:false,
        legacyScoreChanged:false,
        independentlyVerifiedRemediation:false},{headers});
    }
    return NextResponse.json({report,
      externalProviderCalls:0,acceptedCustomerRisk:false,
      legacyScoreChanged:false,independentlyVerifiedRemediation:false
    },{headers});
  }catch{
    return denied("EXECUTIVE_DASHBOARD_UNAVAILABLE",503);
  }
}
export async function POST(){return denied("READ_ONLY_REPORT",405);}
export async function PUT(){return denied("READ_ONLY_REPORT",405);}
export async function DELETE(){return denied("READ_ONLY_REPORT",405);}
