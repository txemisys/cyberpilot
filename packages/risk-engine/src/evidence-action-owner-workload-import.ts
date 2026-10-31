import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";

/** Safely read a portable workload handoff without making any verified-risk claims. */
export type ActionWorkloadImport = { schemaVersion: 1; organizationId: string; asOf: string; workload: ActionOwnerWorkloadSummary };
const isCounter=(value:unknown):value is number=>Number.isSafeInteger(value)&&Number(value)>=0;
const isDay=(value:unknown):value is string=>typeof value==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&
 Number.isFinite(Date.parse(value+"T00:00:00Z"))&&new Date(value+"T00:00:00Z").toISOString().slice(0,10)===value;

/** Validate JSON handoff before use; reject cross-organization, malformed or inconsistent summaries. */
export function importActionOwnerWorkloadJson(content:string,organizationId:string):ActionWorkloadImport|null {
 if(!organizationId||typeof content!=="string"||content.length>1_000_000)return null;
 let payload:unknown;
 try {payload=JSON.parse(content);} catch{return null;}
 if(!payload||typeof payload!=="object"||Array.isArray(payload))return null;
 const p=payload as Record<string,unknown>;
 if(p.schemaVersion!==1||p.organizationId!==organizationId||!isDay(p.asOf)||
  !isCounter(p.totalOverdue)||!isCounter(p.totalUpcoming)||!Array.isArray(p.assigned)||
  !p.unassigned||typeof p.unassigned!=="object"||Array.isArray(p.unassigned)||
  p.assigned.length>10000)return null;
 const validRow=(r:unknown,unassigned:boolean)=>{
  if(!r||typeof r!=="object"||Array.isArray(r))return false;
  const x=r as Record<string,unknown>;
  if(unassigned?x.owner!==null:typeof x.owner!=="string"||!x.owner.trim())return false;
  return isCounter(x.overdue)&&isCounter(x.upcoming)&&isCounter(x.highPriority)&&
   Number(x.highPriority)<=Number(x.overdue)+Number(x.upcoming)&&
   (x.earliestDueDate===null||isDay(x.earliestDueDate));
 };
 if(!validRow(p.unassigned,true)||!p.assigned.every(x=>validRow(x,false)))return null;
 const rows=[...p.assigned,p.unassigned] as Record<string,unknown>[];
 const overdue=rows.reduce((n,x)=>n+Number(x.overdue),0);
 const upcoming=rows.reduce((n,x)=>n+Number(x.upcoming),0);
 if(overdue!==p.totalOverdue||upcoming!==p.totalUpcoming)return null;
 const ownerNames=p.assigned.map((x:Record<string,unknown>)=>x.owner as string);
 if(new Set(ownerNames).size!==ownerNames.length)return null;
 const workload:ActionOwnerWorkloadSummary={
  organizationId,asOf:p.asOf as string,assigned:p.assigned as ActionOwnerWorkloadSummary["assigned"],
  unassigned:p.unassigned as ActionOwnerWorkloadSummary["unassigned"],
  totalOverdue:p.totalOverdue as number,totalUpcoming:p.totalUpcoming as number,
 };
 return {schemaVersion:1,organizationId,asOf:p.asOf as string,workload};
}
