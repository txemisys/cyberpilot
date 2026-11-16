import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { IntegratedAccessError,collectIntegratedRiskDigest } from
  "../../../../../lib/integrated-risk-service";
import { exportIntegratedRiskDigest,verifyIntegratedRiskDigest } from
  "../../../../../lib/integrated-risk-engine";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function denied(code:string,status:number){
  return NextResponse.json({code,liveProviderCalls:0,
    legacyScoreWrites:0,customerApprovalSigned:false},{status,headers});
}
export async function GET(request:NextRequest,context:Context){
  const origin=request.headers.get("origin");
  if(origin && origin!==new URL(request.url).origin)
    return denied("ORIGIN_NOT_ALLOWED",403);
  const format=new URL(request.url).searchParams.get("format");
  if(format&&!["JSON","CSV","MARKDOWN"].includes(format))
    return denied("EXPORT_FORMAT_INVALID",400);
  try{
    const {membership,session}=await requireOrganizationAccess(
      (await context.params).slug);
    if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return denied("REVIEW_PERMISSION_REQUIRED",403);
    const digest=await collectIntegratedRiskDigest({
      organizationId:membership.organization.id,
      userId:session.user.id,role:membership.role,
    });
    if(!verifyIntegratedRiskDigest(
      digest,membership.organization.id).valid)
      return denied("REPORT_INTEGRITY_INVALID",500);
    if(!format)return NextResponse.json({report:digest,
      liveProviderCalls:0,legacyScoreWrites:0,
      customerApprovalSigned:false}, {headers});
    const artifact=exportIntegratedRiskDigest(digest,
      format as "JSON"|"CSV"|"MARKDOWN");
    return NextResponse.json({artifact,reportDigest:digest.digest,
      liveProviderCalls:0,legacyScoreWrites:0,
      customerApprovalSigned:false}, {headers});
  }catch(error){
    if(error instanceof IntegratedAccessError)
      return denied(error.code,403);
    return denied("INTEGRATED_RISKS_UNAVAILABLE",503);
  }
}
export async function POST(){return denied("READ_ONLY",405);}
export async function PATCH(){return denied("READ_ONLY",405);}
export async function DELETE(){return denied("READ_ONLY",405);}
