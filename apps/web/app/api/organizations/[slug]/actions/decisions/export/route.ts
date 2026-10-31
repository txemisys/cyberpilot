import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildManagementDecisionBoard,managementDecisionsCsv,managementDecisionsText} from "../../../../../../../lib/management-decision-board";
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
  "More than 500 findings match. Narrow the filters before exporting.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "Findings changed during generation. Retry for a consistent report.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const decisions=buildManagementDecisionBoard(findings);
 const asText=url.searchParams.get("format")==="text";
 return new Response(asText?managementDecisionsText(decisions.items):
  managementDecisionsCsv(decisions.items),{headers:{
  "Content-Type":asText?"text/plain; charset=utf-8":"text/csv; charset=utf-8",
  "Content-Disposition":asText?
   'attachment; filename="cyberpilot-management-decisions.txt"':
   'attachment; filename="cyberpilot-management-decisions.csv"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
