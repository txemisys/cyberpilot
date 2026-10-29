import type { ActionPlan } from "./evidence-action-plan";
/** Offline plan export, tenant-bound; CSV values are formula guarded. */
export type ActionPlanExport = { ok:true; mimeType:string; filename:string; content:string } | { ok:false; error:"TENANT_MISMATCH"|"INVALID_PLAN" };
function valid(plan:ActionPlan,organizationId:string):boolean {
 if(!organizationId||plan.organizationId!==organizationId||plan.schemaVersion!==1||plan.summary.total!==plan.actions.length)return false;
 const statuses=["TODO","IN_PROGRESS","BLOCKED","DONE"] as const;
 if(statuses.some(status=>plan.actions.filter(x=>x.status===status).length!==({
  TODO:plan.summary.todo,IN_PROGRESS:plan.summary.inProgress,BLOCKED:plan.summary.blocked,DONE:plan.summary.done,
 }[status])))return false;
 if(new Set(plan.actions.map(x=>x.id)).size!==plan.actions.length)return false;
 return plan.actions.every(x=>x.verifiedRisk===false&&x.state==="PROPOSED");
}
const safe=(value:string):string=>'"'+(/^[\s]*[=+@\-]/.test(value)?"'"+value:value).replace(/"/g,'""')+'"';
export function exportActionPlanCsv(plan:ActionPlan,organizationId:string):ActionPlanExport {
 if(plan.organizationId!==organizationId||!organizationId)return {ok:false,error:"TENANT_MISMATCH"};
 if(!valid(plan,organizationId))return {ok:false,error:"INVALID_PLAN"};
 const keys=["id","domain","controlId","source","scope","priority","reason","status","owner","dueDate","notes"] as const;
 const rows=plan.actions.map(item=>keys.map(key=>safe(item[key]??"")).join(","));
 return {ok:true,mimeType:"text/csv; charset=utf-8",filename:"action-plan.csv",content:[keys.join(","),...rows].join("\r\n")+"\r\n"};
}
export function exportActionPlanJson(plan:ActionPlan,organizationId:string):ActionPlanExport {
 if(plan.organizationId!==organizationId||!organizationId)return {ok:false,error:"TENANT_MISMATCH"};
 if(!valid(plan,organizationId))return {ok:false,error:"INVALID_PLAN"};
 const actions=plan.actions.map(x=>({id:x.id,domain:x.domain,controlId:x.controlId,source:x.source,scope:x.scope,priority:x.priority,reason:x.reason,status:x.status,owner:x.owner,dueDate:x.dueDate,notes:x.notes}));
 return {ok:true,mimeType:"application/json",filename:"action-plan.json",content:JSON.stringify({schemaVersion:1,organizationId,summary:plan.summary,actions})};
}
