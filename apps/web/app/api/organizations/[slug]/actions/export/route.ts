import { db } from "@cyberpilot/database";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { serializeRemediationExport } from "../../../../../../lib/remediation-operations-export";
import { buildSmeRemediationOverview } from "../../../../../../lib/sme-remediation-overview";
import { parseActionPageInput } from "../../../../../../lib/action-pagination";
import { buildScopedActionQuery } from "../../../../../../lib/action-database-query";

/**
 * Authorized, tenant-scoped export of a bounded operational overview.
 * Contains workflow metadata only; never includes raw evidence, credentials or action payloads.
 */
export async function GET(request:Request,{params}:{params:Promise<{slug:string}>}) {
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const queryParams=new URL(request.url).searchParams;
  const settings=parseActionPageInput({
    status:queryParams.get("status")??queryParams.get("view")??undefined,
    search:queryParams.get("search")??undefined,
    severity:queryParams.get("severity")??undefined,
    sort:queryParams.get("sort")??undefined,
  });
  const {where,orderBy}=buildScopedActionQuery(membership.organization.id,settings);
  const count=await db.remediation.count({where});
  if(count>2000)return new Response(
    "The export exceeds 2000 actions. Narrow the filters and try again.",
    {status:422,headers:{"Cache-Control":"private, no-store"}},
  );
  const records=await db.remediation.findMany({
    where,orderBy,take:2000,
    select:{
      id:true,title:true,status:true,mode:true,steps:true,
      createdAt:true,approvedAt:true,startedAt:true,completedAt:true,verifiedAt:true,
      finding:{select:{title:true,status:true,severity:true}},
    },
  });
  const acknowledgements=await db.guidedRemediationStep.findMany({
    where:{organizationId:membership.organization.id,remediationId:{in:records.map(x=>x.id)}},
    select:{remediationId:true,stepIndex:true},
  });
  const progress=new Map<string,Set<number>>();
  for(const item of acknowledgements){
    const seen=progress.get(item.remediationId)??new Set<number>();
    seen.add(item.stepIndex);
    progress.set(item.remediationId,seen);
  }
  const overview=buildSmeRemediationOverview(records,progress);
  const needsVerification=new Map(overview.items.map(item=>[item.id,item.needsVerification]));
  const rows=records.map(item=>{
    const steps=Array.isArray(item.steps)?item.steps.filter((step):step is string=>typeof step==="string"):[];
    const completed=steps.filter((_,index)=>progress.get(item.id)?.has(index)).length;
    return {
      id:item.id,title:item.title,status:item.status,mode:item.mode,
      severity:item.finding.severity,findingTitle:item.finding.title,
      findingStatus:item.finding.status,
      createdAt:item.createdAt,approvedAt:item.approvedAt,startedAt:item.startedAt,
      completedAt:item.completedAt,verifiedAt:item.verifiedAt,
      guidedCompleted:completed,guidedTotal:steps.length,
      needsVerification:needsVerification.get(item.id)??false,
    };
  });
  const content=serializeRemediationExport(rows);
  return new Response(content,{
    headers:{
      "Content-Type":"text/csv; charset=utf-8",
      "Content-Disposition":"attachment; filename=\"cyberpilot-actions-filtered.csv\"",
      "Cache-Control":"private, no-store",
      "X-Content-Type-Options":"nosniff",
    },
  });
}
