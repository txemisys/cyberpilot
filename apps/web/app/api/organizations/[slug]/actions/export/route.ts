import { db } from "@cyberpilot/database";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { exportActionCenterCsv } from "../../../../../../lib/action-center";
import { buildSmeRemediationOverview } from "../../../../../../lib/sme-remediation-overview";

/**
 * Authorized, tenant-scoped export of a bounded operational overview.
 * Contains workflow metadata only; never includes raw evidence, credentials or action payloads.
 */
export async function GET(_request:Request,{params}:{params:Promise<{slug:string}>}) {
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const records=await db.remediation.findMany({
    where:{organizationId:membership.organization.id},
    take:200,
    orderBy:[{createdAt:"desc"},{id:"asc"}],
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
      "Content-Disposition":"attachment; filename=\"cyberpilot-actions.csv\"",
      "Cache-Control":"private, no-store",
      "X-Content-Type-Options":"nosniff",
    },
  });
}
