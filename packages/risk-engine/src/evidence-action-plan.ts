import type { EvidenceAction } from "./evidence-actions";
/** Pure action planning; no persistence, automatic changes, or verified findings. */
export type PlannedAction = EvidenceAction & { owner: string | null; dueDate: string | null; status: "TODO" | "IN_PROGRESS" | "BLOCKED" | "DONE"; notes: string | null };
export type ActionPlan = { organizationId: string; schemaVersion: 1; actions: PlannedAction[]; summary: {total:number;todo:number;inProgress:number;blocked:number;done:number;high:number;medium:number;low:number;overdue:number} };
export function buildActionPlan(organizationId:string, actions:readonly EvidenceAction[], assignments:Readonly<Record<string,{owner?:string|null;dueDate?:string|null;status?:"TODO"|"IN_PROGRESS"|"BLOCKED"|"DONE";notes?:string|null}>> = {}, asOf:string="2026-10-29"):ActionPlan|null {
  if(!organizationId || !/^\d{4}-\d{2}-\d{2}$/.test(asOf) || !Number.isFinite(Date.parse(asOf+"T00:00:00Z"))) return null;
  const seen=new Set<string>();const planned:PlannedAction[]=[];
  for(const action of actions){
    if(!action.id || seen.has(action.id) || action.state!=="PROPOSED" || action.verifiedRisk!==false) return null;
    seen.add(action.id);
    const value=Object.hasOwn(assignments,action.id)?assignments[action.id]:undefined;
    const dueDate=value?.dueDate??null;
    if(dueDate!==null && (!/^\d{4}-\d{2}-\d{2}$/.test(dueDate) || !Number.isFinite(Date.parse(dueDate+"T00:00:00Z")))) return null;
    const owner=value?.owner?.trim()||null,notes=value?.notes?.trim()||null;
    if((owner?.length??0)>160||(notes?.length??0)>2000)return null;
    planned.push({...action,owner,dueDate,status:value?.status??"TODO",notes});
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
