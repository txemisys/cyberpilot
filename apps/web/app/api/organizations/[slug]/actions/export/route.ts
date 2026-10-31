import { db } from "@cyberpilot/database";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { exportActionCenterCsv } from "../../../../../../lib/action-center";

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
      id:true,title:true,status:true,
      finding:{select:{status:true,severity:true}},
    },
  });
  const rows=records.map(item=>({
    id:item.id,title:item.title,status:item.status,
    severity:item.finding.severity,
    findingStatus:item.finding.status,
    // We cannot infer verification readiness from a status alone.
    needsVerification:item.status==="SUCCEEDED",
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
