import type { ActionAlert } from "./evidence-action-alerts";
/** Offline and tenant-bound alert digest. No scheduling, messaging or external calls. */
export type ActionAlertDigest = {
 organizationId: string; total: number; high: number; medium: number; low: number;
 byCode: { OVERDUE: number; DUE_SOON: number; BLOCKED: number; HIGH_PRIORITY_OPEN: number };
 items: { actionId: string; code: ActionAlert["code"]; priority: ActionAlert["priority"] }[];
};
export function summarizeActionAlerts(organizationId: string, alerts: readonly ActionAlert[]): ActionAlertDigest | null {
 if (!organizationId || alerts.some(item => item.organizationId !== organizationId || !item.actionId.trim())) return null;
 const seen = new Set<string>();
 const items: ActionAlertDigest["items"] = [];
 for (const alert of alerts) {
   const key = JSON.stringify([alert.actionId, alert.code]);
   if (seen.has(key)) continue;
   seen.add(key);
   items.push({ actionId:alert.actionId, code:alert.code, priority:alert.priority });
 }
 const rank = {HIGH:0,MEDIUM:1,LOW:2};
 items.sort((a,b)=>rank[a.priority]-rank[b.priority] || a.actionId.localeCompare(b.actionId) || a.code.localeCompare(b.code));
 const count = (code:ActionAlert["code"])=>items.filter(x=>x.code===code).length;
 return {organizationId,total:items.length,
  high:items.filter(x=>x.priority==="HIGH").length,
  medium:items.filter(x=>x.priority==="MEDIUM").length,
  low:items.filter(x=>x.priority==="LOW").length,
  byCode:{OVERDUE:count("OVERDUE"),DUE_SOON:count("DUE_SOON"),BLOCKED:count("BLOCKED"),HIGH_PRIORITY_OPEN:count("HIGH_PRIORITY_OPEN")},
  items};
}
