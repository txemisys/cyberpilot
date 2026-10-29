import type { ActionPlan } from "./evidence-action-plan";
const statuses=new Set(["TODO","IN_PROGRESS","BLOCKED","DONE"]);
const priorities=new Set(["HIGH","MEDIUM","LOW"]);
const date=(value:string)=>/^\d{4}-\d{2}-\d{2}$/.test(value)&&Number.isFinite(Date.parse(value+"T00:00:00Z"))&&new Date(value+"T00:00:00Z").toISOString().slice(0,10)===value;
/** Reject inconsistent or forged action plan input before computing workspace views. */
export function validateActionWorkspacePlan(plan:ActionPlan,organizationId:string,asOf:string):boolean {
 if(!organizationId||plan.organizationId!==organizationId||plan.schemaVersion!==1||!date(asOf))return false;
 if(!Array.isArray(plan.actions)||plan.summary.total!==plan.actions.length)return false;
 const ids=new Set<string>();
 for(const a of plan.actions){
  if(!a.id||ids.has(a.id)||a.state!=="PROPOSED"||a.verifiedRisk!==false||
   !statuses.has(a.status)||!priorities.has(a.priority)||!["WEB","EMAIL","IDENTITY","ENDPOINT","CLOUD","DATA","GOVERNANCE"].includes(a.domain)||
   (a.owner!==null&&(typeof a.owner!=="string"||a.owner.length>160))||
   (a.notes!==null&&(typeof a.notes!=="string"||a.notes.length>2000))||
   (a.dueDate!==null&&!date(a.dueDate)))return false;
  ids.add(a.id);
 }
 const count=(field:"status"|"priority",value:string)=>plan.actions.filter(a=>a[field]===value).length;
 const s=plan.summary;
 return s.todo===count("status","TODO")&&s.inProgress===count("status","IN_PROGRESS")&&
 s.blocked===count("status","BLOCKED")&&s.done===count("status","DONE")&&
 s.high===count("priority","HIGH")&&s.medium===count("priority","MEDIUM")&&s.low===count("priority","LOW")&&
 s.overdue===plan.actions.filter(a=>a.dueDate!==null&&a.dueDate<asOf&&a.status!=="DONE").length;
}
