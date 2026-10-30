import type { EvidenceAction } from "./evidence-actions";
/** Pure action planning; no persistence, automatic changes, or verified findings. */
export type PlannedAction = EvidenceAction & { owner: string | null; dueDate: string | null; status: "TODO" | "IN_PROGRESS" | "BLOCKED" | "DONE"; notes: string | null };
export type ActionPlan = { organizationId: string; schemaVersion: 1; actions: PlannedAction[]; summary: {total:number;todo:number;inProgress:number;blocked:number;done:number;high:number;medium:number;low:number;overdue:number} };
/** Reject dates that Date.parse would silently roll over (for example February 30). */
function isExactUtcDay(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = Date.parse(value + "T00:00:00Z");
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 10) === value;
}
export function buildActionPlan(organizationId:string, actions:readonly EvidenceAction[], assignments:Readonly<Record<string,{owner?:string|null;dueDate?:string|null;status?:"TODO"|"IN_PROGRESS"|"BLOCKED"|"DONE";notes?:string|null}>> = {}, asOf:string="2026-10-29"):ActionPlan|null {
  if(typeof organizationId!=="string" || !organizationId.trim() || !isExactUtcDay(asOf)) return null;
  const seen=new Set<string>();const planned:PlannedAction[]=[];
  for(const action of actions){
    if(typeof action.id!=="string" || !action.id.trim() || seen.has(action.id) || action.state!=="PROPOSED" || action.verifiedRisk!==false || (action.priority!=="HIGH"&&action.priority!=="MEDIUM"&&action.priority!=="LOW")) return null;
    seen.add(action.id);
    const value=Object.hasOwn(assignments,action.id)?assignments[action.id]:undefined;
    const dueDate=value?.dueDate??null;
    if(dueDate!==null && !isExactUtcDay(dueDate)) return null;
    if(value?.owner!=null&&typeof value.owner!=="string")return null;
    if(value?.notes!=null&&typeof value.notes!=="string")return null;
    const forbidden=/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
    if((value?.owner!=null&&forbidden.test(value.owner))||(value?.notes!=null&&forbidden.test(value.notes)))return null;
    const owner=value?.owner?.trim()||null,notes=value?.notes?.trim()||null;
    if((owner?.length??0)>160||(notes?.length??0)>2000)return null;
    const status=value?.status??"TODO";
    if(status!=="TODO"&&status!=="IN_PROGRESS"&&status!=="BLOCKED"&&status!=="DONE")return null;
    planned.push({...action,owner,dueDate,status,notes});
  }
  const rank={HIGH:0,MEDIUM:1,LOW:2};
  planned.sort((a,b)=>rank[a.priority]-rank[b.priority] || a.id.localeCompare(b.id));
  const count=(status:PlannedAction["status"])=>planned.filter(x=>x.status===status).length;
  return {organizationId,schemaVersion:1,actions:planned,summary:{
    total:planned.length,todo:count("TODO"),inProgress:count("IN_PROGRESS"),blocked:count("BLOCKED"),done:count("DONE"),
    high:planned.filter(x=>x.priority==="HIGH").length,medium:planned.filter(x=>x.priority==="MEDIUM").length,low:planned.filter(x=>x.priority==="LOW").length,
    overdue:planned.filter(x=>x.dueDate!==null && x.dueDate<asOf && x.status!=="DONE").length,
  }};
}
