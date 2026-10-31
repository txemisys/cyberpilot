import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildControlAssurancePortfolio,exportControlAssuranceCsv,exportControlAssuranceText} from "../../../../../../../lib/control-assurance";

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
  "More than 500 findings match; narrow your filters before exporting.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "Finding records changed during export. Retry for a complete report.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const {controls}=buildControlAssurancePortfolio(findings);
 const asText=url.searchParams.get("format")==="text";
 const payload=asText?exportControlAssuranceText(controls):exportControlAssuranceCsv(controls);
 return new Response(payload,{headers:{
  "Content-Type":asText?"text/plain; charset=utf-8":"text/csv; charset=utf-8",
  "Content-Disposition":asText?
   'attachment; filename="cyberpilot-control-assurance.txt"':
   'attachment; filename="cyberpilot-control-assurance.csv"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
