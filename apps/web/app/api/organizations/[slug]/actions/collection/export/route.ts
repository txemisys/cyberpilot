import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildEvidenceCollectionPlan,evidenceCollectionPlanCsv,evidenceCollectionPlanText,buildEvidenceCollectionHandoffs,renderEvidenceCollectionHandoffs} from "../../../../../../../lib/evidence-collection-planner";
export async function GET(request:Request,{params}:{params:Promise<{slug:string}>}){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const url=new URL(request.url);
 const options=parseReviewListOptions(url.searchParams);
 const where={
  organizationId,
  ...(options.includeResolved?{}:{status:"OPEN" as const}),
  ...(options.severity?{severity:options.severity}:{}),
  ...(options.search?{OR:[
   {title:{contains:options.search,mode:"insensitive" as const}},
   {ruleId:{contains:options.search,mode:"insensitive" as const}},
   {description:{contains:options.search,mode:"insensitive" as const}},
  ]}:{}),
 };
 const total=await db.securityFinding.count({where});
 if(total>500)return new Response(
  "More than 500 findings match. Narrow filters before exporting a complete plan.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...options,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "Findings changed during export. Retry for complete results.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const plan=buildEvidenceCollectionPlan(findings);
 const csv=url.searchParams.get("format")==="csv";
 const handoff=url.searchParams.get("format")==="handoff";
 const content=csv?evidenceCollectionPlanCsv(plan):handoff?
  renderEvidenceCollectionHandoffs(buildEvidenceCollectionHandoffs(plan)):
  evidenceCollectionPlanText(plan);
 return new Response(content,{
  headers:{
   "Content-Type":csv?"text/csv; charset=utf-8":"text/plain; charset=utf-8",
   "Content-Disposition":csv?
    'attachment; filename="cyberpilot-evidence-collection.csv"':
    handoff?'attachment; filename="cyberpilot-evidence-collection-handoff.txt"':
    'attachment; filename="cyberpilot-evidence-collection.txt"',
   "Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff",
  },
 });
}
