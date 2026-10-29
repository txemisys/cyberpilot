import type { ActionPlan } from "./evidence-action-plan";
/** Offline alert suggestions: no notifications are sent. */
export type ActionAlert = { actionId:string; code:"OVERDUE"|"DUE_SOON"|"BLOCKED"|"HIGH_PRIORITY_OPEN"; priority:"HIGH"|"MEDIUM"|"LOW"; organizationId:string };
export function suggestActionAlerts(plan:ActionPlan,organizationId:string,asOf:string,warningDays=7):ActionAlert[]|null {
 if(!organizationId||organizationId!==plan.organizationId||!/^\d{4}-\d{2}-\d{2}$/.test(asOf)||!Number.isFinite(Date.parse(asOf+"T00:00:00Z")))return null;
 if(!Number.isInteger(warningDays)||warningDays<0||warningDays>365)return null;
 if(plan.summary.total!==plan.actions.length)return null;
 const today=Date.parse(asOf+"T00:00:00Z"),out:ActionAlert[]=[];
 const seen=new Set<string>();
 for(const action of plan.actions){
  if(!action.id||seen.has(action.id))return null;
  seen.add(action.id);
  if(action.status==="DONE")continue;
  const emit=(code:ActionAlert["code"],priority:ActionAlert["priority"])=>out.push({actionId:action.id,code,priority,organizationId});
  if(action.status==="BLOCKED")emit("BLOCKED","HIGH");
  if(action.priority==="HIGH")emit("HIGH_PRIORITY_OPEN","MEDIUM");
  if(action.dueDate){
   if(!/^\d{4}-\d{2}-\d{2}$/.test(action.dueDate)||!Number.isFinite(Date.parse(action.dueDate+"T00:00:00Z")))return null;
   const days=Math.round((Date.parse(action.dueDate+"T00:00:00Z")-today)/86400000);
   if(days<0)emit("OVERDUE","HIGH");
   else if(days<=warningDays)emit("DUE_SOON","MEDIUM");
  }
 }
 const rank={HIGH:0,MEDIUM:1,LOW:2};return out.sort((a,b)=>rank[a.priority]-rank[b.priority]||a.actionId.localeCompare(b.actionId)||a.code.localeCompare(b.code));
}
