import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildAuditPortfolio,auditPortfolioCsv} from "../../../../../../../lib/audit-preparation";
export async function GET(request:Request,{params}:{params:Promise<{slug:string}>}){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const options=parseReviewListOptions(new URL(request.url).searchParams);
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
 if(total>500)return new Response("More than 500 findings match; narrow the filters.",{
  status:422,headers:{"Cache-Control":"private, no-store"},
 });
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...options,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "Finding records changed during export; retry.",{
   status:409,headers:{"Cache-Control":"private, no-store"},
  });
 const portfolio=buildAuditPortfolio(findings);
 return new Response(auditPortfolioCsv(portfolio),{headers:{
  "Content-Type":"text/csv; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-audit-readiness.csv"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
