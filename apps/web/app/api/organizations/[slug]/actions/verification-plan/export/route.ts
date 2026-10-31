import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {parseReviewListOptions,loadReviewData} from "../../../../../../../lib/finding-review-data";
import {buildVerificationPlan,renderVerificationPlanText} from "../../../../../../../lib/verification-plan";

/** Server-authorized complete plan export with an explicit upper bound. */
export async function GET(request:Request,{params}:{params:Promise<{slug:string}>}){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const input=new URL(request.url).searchParams;
 const settings=parseReviewListOptions(input);
 const where={
  organizationId,
  ...(settings.includeResolved?{}:{status:"OPEN" as const}),
  ...(settings.severity?{severity:settings.severity}:{}),
  ...(settings.search?{OR:[
   {title:{contains:settings.search,mode:"insensitive" as const}},
   {ruleId:{contains:settings.search,mode:"insensitive" as const}},
   {description:{contains:settings.search,mode:"insensitive" as const}},
  ]}:{}),
 };
 const total=await db.securityFinding.count({where});
 if(total>500){
  return new Response(
   "More than 500 findings matched. Narrow the filters before exporting a plan.",
   {status:422,headers:{"Cache-Control":"private, no-store"}},
  );
 }
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total){
  return new Response("Findings changed during export. Retry.",{
   status:409,headers:{"Cache-Control":"private, no-store"},
  });
 }
 const plan=buildVerificationPlan(findings);
 const output=renderVerificationPlanText(plan);
 return new Response(output,{headers:{
  "Content-Type":"text/plain; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-verification-plan.txt"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
