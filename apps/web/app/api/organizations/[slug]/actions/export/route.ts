import { db } from "@cyberpilot/database";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { exportActionCenterCsv } from "../../../../../../lib/action-center";
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
  const params=new URL(request.url).searchParams;
  const settings=parseActionPageInput({
    status:params.get("status")??params.get("view")??undefined,
    search:params.get("search")??undefined,
    severity:params.get("severity")??undefined,
    sort:params.get("sort")??undefined,
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
      finding:{select:{status:true,severity:true}},
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
  const rows=records.map(item=>({
    id:item.id,title:item.title,status:item.status,
    severity:item.finding.severity,
    findingStatus:item.finding.status,
    needsVerification:needsVerification.get(item.id)??false,
  }));
  const content=exportActionCenterCsv(rows,membership.organization.id);
  if(content===null)return new Response("Invalid export",{status:422});
  return new Response(content,{
    headers:{
      "Content-Type":"text/csv; charset=utf-8",
      "Content-Disposition":"attachment; filename=\"cyberpilot-actions-filtered.csv\"",
      "Cache-Control":"private, no-store",
      "X-Content-Type-Options":"nosniff",
    },
  });
}
