import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildReconciliationPortfolio,reconciliationCsv,reconciliationText} from "../../../../../../../lib/remediation-reconciliation";
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
  "More than 500 findings matched. Narrow filters for a complete export.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...options,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "Findings changed during export. Retry for a complete snapshot.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const report=buildReconciliationPortfolio(findings);
 const asText=url.searchParams.get("format")==="text";
 return new Response(asText?reconciliationText(report):reconciliationCsv(report),{
  headers:{
   "Content-Type":asText?"text/plain; charset=utf-8":"text/csv; charset=utf-8",
   "Content-Disposition":asText?
    'attachment; filename="cyberpilot-reconciliation.txt"':
    'attachment; filename="cyberpilot-reconciliation.csv"',
   "Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff",
  },
 });
}
