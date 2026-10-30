import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";

export type ActionWorkloadJsonExport = {
 organizationId:string; filename:string; mimeType:"application/json"; content:string;
};
/** Machine-readable, read-only snapshot for authorized offline operational handoffs. */
export function exportActionOwnerWorkloadJson(
 summary:ActionOwnerWorkloadSummary, organizationId:string,
):ActionWorkloadJsonExport|null {
 if(!organizationId || summary.organizationId!==organizationId ||
   !/^\d{4}-\d{2}-\d{2}$/.test(summary.asOf))return null;
 return {
  organizationId,filename:"action-owner-workload-"+summary.asOf+".json",
  mimeType:"application/json",
  content:JSON.stringify({
   schemaVersion:1,organizationId,asOf:summary.asOf,
   totalOverdue:summary.totalOverdue,totalUpcoming:summary.totalUpcoming,
   assigned:summary.assigned,unassigned:summary.unassigned,
  },null,2),
 };
}
