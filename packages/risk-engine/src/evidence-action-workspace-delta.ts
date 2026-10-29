import type { ActionWorkspaceSnapshot } from "./evidence-action-workspace-snapshot";
/** Compares two offline snapshots for the same tenant; positive deltas mean an increase. */
export type ActionWorkspaceDelta = {
 organizationId:string; from:string; to:string;
 actions:number; open:number; completed:number; blocked:number; overdue:number;
 completionPoints:number; acceptedEvents:number; rejectedEvents:number;
 alerts:number; highAlerts:number; selected:number;
 addedSelection:string[]; removedSelection:string[];
};
const valid=(s:ActionWorkspaceSnapshot):boolean=>
 s.schemaVersion===1 &&
 /^\d{4}-\d{2}-\d{2}$/.test(s.asOf) &&
 Number.isFinite(Date.parse(s.asOf+"T00:00:00Z")) &&
 new Date(s.asOf+"T00:00:00Z").toISOString().slice(0,10)===s.asOf &&
 [s.totals.actions,s.totals.open,s.totals.completed,s.totals.blocked,s.totals.overdue,
 s.totals.completionPercent,s.events.accepted,s.events.rejected,s.alerts.total,s.alerts.high,
 s.alerts.medium,s.alerts.low,s.selection.total].every(x=>Number.isSafeInteger(x)&&x>=0) &&
 s.totals.open+s.totals.completed===s.totals.actions &&
 s.totals.blocked<=s.totals.open && s.totals.overdue<=s.totals.open &&
 s.totals.completionPercent<=100 &&
 s.alerts.high+s.alerts.medium+s.alerts.low===s.alerts.total &&
 s.selection.total<=s.totals.actions &&
 s.selection.ids.length<=s.selection.total &&
 s.selection.ids.every(id=>typeof id==="string"&&id.length>0) &&
 new Set(s.selection.ids).size===s.selection.ids.length;
export function compareActionWorkspaceSnapshots(
 before:ActionWorkspaceSnapshot,after:ActionWorkspaceSnapshot,organizationId:string
):ActionWorkspaceDelta|null {
 if(!organizationId||before.organizationId!==organizationId||after.organizationId!==organizationId||
 !valid(before)||!valid(after)||before.asOf>after.asOf)return null;
 const prior=new Set(before.selection.ids),next=new Set(after.selection.ids);
 return {organizationId,from:before.asOf,to:after.asOf,
 actions:after.totals.actions-before.totals.actions,
 open:after.totals.open-before.totals.open,
 completed:after.totals.completed-before.totals.completed,
 blocked:after.totals.blocked-before.totals.blocked,
 overdue:after.totals.overdue-before.totals.overdue,
 completionPoints:after.totals.completionPercent-before.totals.completionPercent,
 acceptedEvents:after.events.accepted-before.events.accepted,
 rejectedEvents:after.events.rejected-before.events.rejected,
 alerts:after.alerts.total-before.alerts.total,
 highAlerts:after.alerts.high-before.alerts.high,
 selected:after.selection.total-before.selection.total,
 addedSelection:after.selection.ids.filter(x=>!prior.has(x)),
 removedSelection:before.selection.ids.filter(x=>!next.has(x))};
}
