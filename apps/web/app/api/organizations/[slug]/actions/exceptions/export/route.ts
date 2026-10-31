import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildReviewExceptionRegister,exportExceptionRegister} from "../../../../../../../lib/review-exceptions";
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
 if(total>500)return new Response(
  "Too many matching findings. Narrow the filters before exporting.",
  {status:422,headers:{"Cache-Control":"private, no-store"}},
 );
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...options,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total)return new Response(
  "The findings changed during export. Retry.",
  {status:409,headers:{"Cache-Control":"private, no-store"}},
 );
 const register=buildReviewExceptionRegister(findings);
 return new Response(exportExceptionRegister(register.items),{headers:{
  "Content-Type":"text/csv; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-review-exceptions.csv"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
