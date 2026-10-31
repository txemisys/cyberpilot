import {WorkInputError} from "./remediation-work-input";
import type {CapacityReport,MemberLoad,CapacityTask} from "./remediation-work-capacity";

/**
 * CSV extracts never include evidence content or private task descriptions.
 * Every row is escaped to reduce spreadsheet formula injection risk.
 */
export const CAPACITY_MEMBER_COLUMNS=[
 "Member ID","Display name","Organization role","Assigned tasks","Active tasks",
 "Closed tasks","Urgent tasks","Blocked tasks","Overdue tasks","Upcoming targets",
 "Inactive tasks","Pending handoffs","Checklist gaps","Operational attention index",
] as const;
export const CAPACITY_TASK_COLUMNS=[
 "Member ID","Member name","Work item ID","Work title","Status","Priority",
 "Recorded target date","Days until target","Operational attention index","Reasons",
] as const;
export type CapacityExportOptions={
 mode:"MEMBERS"|"TASKS";maxRows:number;includeUnassigned:boolean;
};
export function parseCapacityExportOptions(raw:unknown):CapacityExportOptions{
 if(!raw||typeof raw!=="object"||Array.isArray(raw))
  throw new WorkInputError("INVALID","Capacity export configuration must be an object.");
 const data=raw as Record<string,unknown>;
 for(const key of Object.keys(data))
  if(!["mode","maxRows","includeUnassigned"].includes(key))
   throw new WorkInputError("INVALID",`Unsupported capacity export field: ${key}.`);
 const mode=data.mode===undefined?"MEMBERS":data.mode;
 const maxRows=data.maxRows===undefined?2000:data.maxRows;
 const includeUnassigned=data.includeUnassigned===undefined?true:data.includeUnassigned;
 if(mode!=="MEMBERS"&&mode!=="TASKS")
  throw new WorkInputError("INVALID","Unsupported capacity export mode.");
 if(typeof maxRows!=="number"||!Number.isSafeInteger(maxRows)||maxRows<1||maxRows>2000)
  throw new WorkInputError("INVALID","Export row limit must be 1–2,000.");
 if(typeof includeUnassigned!=="boolean")
  throw new WorkInputError("INVALID","Unassigned switch must be boolean.");
 return {mode,maxRows,includeUnassigned};
}
function cell(value:unknown):string{
 const raw=value===null||value===undefined?"":String(value);
 const sanitized=raw.replace(/\u0000/g,"");
 const safe=/^\s*[=+@-]/.test(sanitized)?"'"+sanitized:sanitized;
 return '"'+safe.replace(/"/g,'""')+'"';
}
function csvLine(data:readonly unknown[]):string{return data.map(cell).join(",");}
function members(report:CapacityReport,includeUnassigned:boolean):MemberLoad[]{
 return includeUnassigned?[...report.members,report.unassigned]:[...report.members];
}
export function capacityCsv(report:CapacityReport,options:CapacityExportOptions):string{
 if(!report.coverage.complete)
  throw new WorkInputError("CONFLICT","Cannot export an incomplete work inventory.");
 const people=members(report,options.includeUnassigned);
 if(options.mode==="MEMBERS"){
  if(people.length>options.maxRows)
   throw new WorkInputError("CONFLICT","Member export exceeds the configured limit.");
  return [csvLine(CAPACITY_MEMBER_COLUMNS),...people.map(item=>csvLine([
   item.id,item.name,item.role,item.assigned,item.active,item.closed,
   item.urgent,item.blocked,item.overdue,item.upcoming,item.stale,
   item.pendingHandoffs,item.checklistGaps,item.attentionPoints,
  ]))].join("\r\n")+"\r\n";
 }
 // Per-member task previews are not a complete task inventory.
 // Refuse any task export that would hide matching work items.
 if(people.some(person=>person.assigned>person.tasks.length))
  throw new WorkInputError("CONFLICT",
   "Task export needs complete per-member previews; narrow work scope.");
 const rows=people.flatMap(person=>person.tasks.map(task=>({person,task})));
 if(rows.length>options.maxRows)
  throw new WorkInputError("CONFLICT","Task export exceeds the explicit limit.");
 return [csvLine(CAPACITY_TASK_COLUMNS),...rows.map(({person,task})=>csvLine([
  person.id,person.name,task.id,task.title,task.status,task.priority,
  task.dueAt,task.daysUntilDue,task.attentionPoints,task.reasons.join("; "),
 ]))].join("\r\n")+"\r\n";
}
export function capacityIntegrity(report:CapacityReport){
 const sum=report.summary;
 const counts=report.members.reduce((acc,item)=>acc+item.assigned,report.unassigned.assigned);
 const active=report.members.reduce((acc,item)=>acc+item.active,report.unassigned.active);
 const closed=report.members.reduce((acc,item)=>acc+item.closed,report.unassigned.closed);
 return {
  countsReconcile:counts===sum.tasks&&sum.assigned+sum.unassigned===sum.tasks,
  statesReconcile:active===sum.active&&closed===sum.closed&&
   sum.active+sum.closed===sum.tasks,
  complete:report.coverage.complete,
  hasTruncatedMemberPreviews:members(report,true).some(item=>item.assigned>item.tasks.length),
  examinedAt:report.generatedAt,
  warning:"Consistency of operational task metadata does not measure employee hours or security.",
 };
}
