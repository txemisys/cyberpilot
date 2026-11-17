import {NextRequest,NextResponse} from "next/server";
import {buildTrendReviewPlan} from "../../../../../lib/offline-trend-review-plan";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {collectOfflineLongitudinalTrends} from
 "../../../../../lib/offline-longitudinal-trends-service";
import {exportTrendReport} from "../../../../../lib/offline-longitudinal-trends";
type Context={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
const deny=(code:string,status:number)=>NextResponse.json({
 code,providerCalls:0,v1Writes:0,customerImprovementCertified:false,
},{status,headers});
export async function GET(request:NextRequest,context:Context){
 if(request.headers.get("origin")&&
    request.headers.get("origin")!==new URL(request.url).origin)
  return deny("FOREIGN_ORIGIN",403);
 const format=new URL(request.url).searchParams.get("format");
 if(format&&!["JSON","CSV","MARKDOWN"].includes(format))
  return deny("INVALID_FORMAT",400);
 try{
  const{membership,session}=await requireOrganizationAccess(
   (await context.params).slug);
  if(!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
   return deny("REVIEWER_REQUIRED",403);
  const report=await collectOfflineLongitudinalTrends({
   organizationId:membership.organization.id,userId:session.user.id,
   role:membership.role,
  });
  if(format)return NextResponse.json({
   artifact:exportTrendReport(report,
    format as "JSON"|"CSV"|"MARKDOWN"),
   providerCalls:0,v1Writes:0,customerImprovementCertified:false,
  },{headers});
  const plan=buildTrendReviewPlan(report);
  return NextResponse.json({
   report,plan,providerCalls:0,v1Writes:0,
   customerImprovementCertified:false,
  },{headers});
 }catch{return deny("TREND_READER_UNAVAILABLE",503);}
}
export async function POST(){return deny("READ_ONLY",405);}
export async function PUT(){return deny("READ_ONLY",405);}
export async function DELETE(){return deny("READ_ONLY",405);}
