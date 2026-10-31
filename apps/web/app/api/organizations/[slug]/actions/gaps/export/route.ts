import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildEvidenceGapReport,exportEvidenceGaps} from "../../../../../../../lib/evidence-gap-report";

export async function GET(request:Request,{params}:{params:Promise<{slug:string}>}){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const settings=parseReviewListOptions(new URL(request.url).searchParams);
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
 const count=await db.securityFinding.count({where});
 if(count>500)return new Response(
  "More than 500 findings match. Narrow your selection before exporting.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<count;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==count)return new Response(
  "The findings changed during export. Retry with the latest data.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const report=buildEvidenceGapReport(findings);
 return new Response(exportEvidenceGaps(report.items),{headers:{
  "Content-Type":"text/csv; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-evidence-gaps.csv"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
