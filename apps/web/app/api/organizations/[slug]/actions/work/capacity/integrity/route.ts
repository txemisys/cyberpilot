import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {loadCapacityReport} from "../../../../../../../../lib/remediation-work-capacity";
import {capacityIntegrity} from "../../../../../../../../lib/remediation-work-capacity-export";
import {WorkInputError} from "../../../../../../../../lib/remediation-work-input";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
/**
 * Verify the arithmetic of the complete persisted work snapshot.
 * This endpoint cannot measure hours, productivity or effective remediations.
 */
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {membership,session}=await requireOrganizationAccess(slug);
  const q=request.nextUrl.searchParams;
  const report=await loadCapacityReport({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },{
   scope:q.get("scope")??"MINE",sort:q.get("sort")??"ATTENTION",
   includeClosed:q.get("includeClosed")==="true",
   horizonDays:q.has("horizonDays")?Number(q.get("horizonDays")):14,
   maxTasks:q.has("maxTasks")?Number(q.get("maxTasks")):10,
  });
  const integrity=capacityIntegrity(report);
  return NextResponse.json({
   integrity,
   summary:report.summary,
   coverage:report.coverage,
   snapshotAt:report.generatedAt,
   warnings:[
    ...(!integrity.countsReconcile?["Assigned and unassigned task totals do not reconcile."]:[]),
    ...(!integrity.statesReconcile?["Active and closed work totals do not reconcile."]:[]),
    ...(integrity.hasTruncatedMemberPreviews?[
     "Task preview is incomplete although aggregate totals use complete inventory.",
    ]:[]),
   ],
   explanation:"Diagnostic of operational metadata only. No security controls were verified.",
  },{headers});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json(
   {error:error.message,code:error.code},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Capacity integrity",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to check work capacity consistency."},
   {status:500,headers});
 }
}
