import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {loadDigest} from "../../../../../../../../lib/remediation-work-digest";
import {digestIntegrity} from "../../../../../../../../lib/remediation-work-digest-export";
import {WorkInputError} from "../../../../../../../../lib/remediation-work-input";

/** Read-only consistency and coverage diagnostics for digest consumers. */
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {membership,session}=await requireOrganizationAccess(slug);
  const query=request.nextUrl.searchParams;
  const config={
   scope:query.get("scope")??"MINE",
   days:query.has("days")?Number(query.get("days")):14,
   includeClosed:query.get("includeClosed")==="true",
   maxItems:query.has("maxItems")?Number(query.get("maxItems")):100,
  };
  const report=await loadDigest({
   organizationId:membership.organization.id,userId:session.user.id,role:membership.role,
  },config);
  const integrity=digestIntegrity(report);
  return NextResponse.json({
   integrity,
   summary:report.summary,
   coverage:report.coverage,
   configuration:report.config,
   snapshotAt:report.generatedAt,
   validationScope:"Only the internal consistency of persisted operational data.",
   warnings:[
    ...(integrity.hasExcludedPreviewItems?[
     "The selected priority preview omits records; the summary still includes them.",
    ]:[]),
    ...(!integrity.balanced?[
     "Operational totals do not reconcile; investigate the snapshot.",
    ]:[]),
   ],
  },{headers});
 }catch(error){
  if(error instanceof WorkInputError)return NextResponse.json(
   {code:error.code,error:error.message},
   {status:{INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code],headers});
  console.error("Digest consistency diagnostics",error instanceof Error?error.name:"unknown");
  return NextResponse.json({error:"Unable to evaluate operational digest integrity."},
   {status:500,headers});
 }
}
