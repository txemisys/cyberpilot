import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../../../lib/finding-review-data";
import {buildPortfolioDossier,serializePortfolioDossier,serializePortfolioDossierCsv} from "../../../../../../../lib/finding-dossier";

/**
 * Complete, explicitly bounded management dossier.
 * Uses the same organization authorization and data attribution rules as
 * individual finding reports; refuses incomplete exports.
 */
export async function GET(
 request:Request,
 {params}:{params:Promise<{slug:string}>},
){
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
 const total=await db.securityFinding.count({where});
 if(total>500){
  return new Response(
   "More than 500 findings match. Narrow the filters before downloading a complete dossier.",
   {status:422,headers:{"Cache-Control":"private, no-store"}},
  );
 }
 const findings=[];
 for(let offset=0;offset<total;offset+=50){
  const page=await loadReviewData(organizationId,{...settings,limit:50,offset});
  findings.push(...page.findings);
 }
 if(findings.length!==total){
  return new Response("Findings changed during dossier generation. Retry.",{
   status:409,headers:{"Cache-Control":"private, no-store"},
  });
 }
 const dossier=buildPortfolioDossier(findings);
 const asCsv=new URL(request.url).searchParams.get("format")==="csv";
 const output=asCsv?serializePortfolioDossierCsv(dossier):serializePortfolioDossier(dossier);
 return new Response(output,{headers:{
  "Content-Type":asCsv?"text/csv; charset=utf-8":"text/plain; charset=utf-8",
  "Content-Disposition":asCsv?'attachment; filename="cyberpilot-evidence-dossier.csv"':
   'attachment; filename="cyberpilot-evidence-dossier.txt"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
