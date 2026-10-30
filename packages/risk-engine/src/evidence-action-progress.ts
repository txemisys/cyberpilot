import type { ActionPlan, PlannedAction } from "./evidence-action-plan";
/** Immutable, offline action progress tracking for a single organization. */
export type ActionProgressEvent = {
  organizationId: string; actionId: string; at: string;
  status: PlannedAction["status"]; note?: string | null;
};
export type ActionProgressResult = { plan: ActionPlan; applied: number; rejected: { index: number; reason: "FOREIGN_TENANT" | "UNKNOWN_ACTION" | "INVALID_TIME" | "OUT_OF_ORDER" | "INVALID_TRANSITION" | "DUPLICATE_EVENT" | "INVALID_NOTE" }[] };
const allowed: Record<PlannedAction["status"], readonly PlannedAction["status"][]> = {
  TODO: ["IN_PROGRESS","BLOCKED"], IN_PROGRESS: ["BLOCKED","DONE"], BLOCKED: ["IN_PROGRESS"], DONE: [],
};
export function applyActionProgress(plan: ActionPlan, events: readonly ActionProgressEvent[], asOf: string): ActionProgressResult {
  const current = new Map(plan.actions.map(x=>[x.id,{...x}]));
  const timestamps = new Map<string,number>();
  const seen = new Set<string>();
  const rejected: ActionProgressResult["rejected"] = [];
  let applied=0;
  for(let i=0;i<events.length;i++){
    const event=events[i]!;
    const reject=(reason:ActionProgressResult["rejected"][number]["reason"])=>rejected.push({index:i,reason});
    if(event.organizationId!==plan.organizationId){reject("FOREIGN_TENANT");continue;}
    const action=current.get(event.actionId);
    if(!action){reject("UNKNOWN_ACTION");continue;}
    if(typeof event.at!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(event.at)||!Number.isFinite(Date.parse(event.at))||new Date(Date.parse(event.at)).toISOString().slice(0,19)!==event.at.slice(0,19)){reject("INVALID_TIME");continue;}
    const ts=Date.parse(event.at);
    const fingerprint=JSON.stringify([event.actionId,event.at,event.status]);
    if(seen.has(fingerprint)){reject("DUPLICATE_EVENT");continue;}
    if((timestamps.get(event.actionId)??-Infinity)>=ts){reject("OUT_OF_ORDER");continue;}
    if(!allowed[action.status].includes(event.status)){reject("INVALID_TRANSITION");continue;}
    if(event.note!==undefined&&event.note!==null&&(typeof event.note!=="string"||event.note.length>2000)){reject("INVALID_NOTE");continue;}
    current.set(event.actionId,{...action,status:event.status,notes:event.note?.trim()||action.notes});
    timestamps.set(event.actionId,ts);seen.add(fingerprint);applied++;
  }
  const actions=plan.actions.map(a=>current.get(a.id)!).filter(Boolean);
  const count=(s:PlannedAction["status"])=>actions.filter(x=>x.status===s).length;
  return {applied,rejected,plan:{...plan,actions,summary:{
    ...plan.summary,total:actions.length,todo:count("TODO"),inProgress:count("IN_PROGRESS"),blocked:count("BLOCKED"),done:count("DONE"),
    overdue:actions.filter(x=>x.dueDate!==null&&x.dueDate<asOf&&x.status!=="DONE").length,
  }}};
}
