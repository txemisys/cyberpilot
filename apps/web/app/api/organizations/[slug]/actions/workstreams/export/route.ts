import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {createWorkstreamPlan,workstreamPlanCsv,workstreamPlanText,buildWorkstreamHandoffs,renderWorkstreamHandoffs} from "../../../../../../../lib/security-workstreams";
export async function GET(request:Request,{params}:{params:Promise<{slug:string}>}){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const url=new URL(request.url);
 const settings=parseReviewListOptions(url.searchParams);
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
 if(total>500)return new Response(
  "More than 500 findings match. Narrow the filters before exporting a complete plan.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "Findings changed during export. Retry to obtain the complete plan.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const plan=createWorkstreamPlan(findings);
 const csv=url.searchParams.get("format")==="csv";
 const handoff=url.searchParams.get("format")==="handoff";
 const content=csv?workstreamPlanCsv(plan):handoff?
  renderWorkstreamHandoffs(buildWorkstreamHandoffs(plan)):workstreamPlanText(plan);
 return new Response(content,{
  headers:{
   "Content-Type":csv?"text/csv; charset=utf-8":"text/plain; charset=utf-8",
   "Content-Disposition":csv?
    'attachment; filename="cyberpilot-security-workstreams.csv"':
    handoff?'attachment; filename="cyberpilot-responsibility-handoff.txt"':
    'attachment; filename="cyberpilot-security-workstreams.txt"',
   "Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff",
  },
 });
}
