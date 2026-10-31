import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {parseReviewListOptions,loadReviewData} from "../../../../../../../lib/finding-review-data";
import {buildWeeklySecurityBriefing,formatWeeklySecurityBriefing,weeklyBriefingActionsCsv} from "../../../../../../../lib/security-operations-briefing";
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
 const count=await db.securityFinding.count({where});
 if(count>500)return new Response(
  "More than 500 findings matched. Narrow the filters before exporting a complete briefing.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<count;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==count)return new Response(
  "The findings changed during export. Retry for a complete snapshot.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const report=buildWeeklySecurityBriefing(
  findings,membership.organization.name,"All matching findings");
 const csv=url.searchParams.get("format")==="csv";
 return new Response(csv?weeklyBriefingActionsCsv(report):formatWeeklySecurityBriefing(report),{
  headers:{
   "Content-Type":csv?"text/csv; charset=utf-8":"text/plain; charset=utf-8",
   "Content-Disposition":csv?
    'attachment; filename="cyberpilot-operations-agenda.csv"':
    'attachment; filename="cyberpilot-operations-briefing.txt"',
   "Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff",
  },
 });
}
