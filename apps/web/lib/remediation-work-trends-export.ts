import {WorkInputError} from "./remediation-work-input";
import type {TrendResult,TrendClassification,TrendCategory} from "./remediation-work-trends";

/** Server-safe, formula-neutralized historical exports with complete-coverage gates. */
export type TrendExportMode="EVENTS"|"DAILY";
export type TrendExportOptions={
 mode:TrendExportMode;limit:number;includeUnclassified:boolean;
};
const MAX_EXPORT=4000;
export const EVENT_COLUMNS=[
 "Event ID","Work item ID","Occurred UTC","Event category","Classification quality",
 "Actor user ID","Previous value","New value","Description",
] as const;
export const DAY_COLUMNS=[
 "Date UTC","Work created","Work marked complete","Work reopened","Ownership changes",
 "Deadline changes","Priority changes","Comments","Checklist changes",
 "Other updates","Unclassified","Total events",
] as const;
function cell(value:unknown):string{
 const raw=value===undefined||value===null?"":String(value);
 const plain=raw.replace(/\u0000/g,"");
 const safe=/^[\s]*[=+@-]/.test(plain)?"'"+plain:plain;
 return '"'+safe.replace(/"/g,'""')+'"';
}
function line(values:readonly unknown[]):string{
 return values.map(cell).join(",");
}
export function parseTrendExportOptions(value:unknown):TrendExportOptions{
 if(value===null||typeof value!=="object"||Array.isArray(value))
  throw new WorkInputError("INVALID","Export options must be an object.");
 const data=value as Record<string,unknown>;
 for(const key of Object.keys(data))
  if(!["mode","limit","includeUnclassified"].includes(key))
   throw new WorkInputError("INVALID",`Unknown trend export field: ${key}.`);
 const mode=data.mode===undefined?"EVENTS":data.mode;
 if(mode!=="EVENTS"&&mode!=="DAILY")
  throw new WorkInputError("INVALID","Unknown trend export mode.");
 const limit=data.limit===undefined?MAX_EXPORT:data.limit;
 if(typeof limit!=="number"||!Number.isInteger(limit)||limit<1||limit>MAX_EXPORT)
  throw new WorkInputError("INVALID","Export limit must be between 1 and 4,000.");
 const includeUnclassified=data.includeUnclassified===undefined?
  true:data.includeUnclassified;
 if(typeof includeUnclassified!=="boolean")
  throw new WorkInputError("INVALID","Unknown event selection flag.");
 return {mode,limit,includeUnclassified};
}
export function selectTrendEvents(
 report:TrendResult,options:TrendExportOptions,
):TrendClassification[]{
 return report.events.filter(item=>
  options.includeUnclassified||item.category!=="UNKNOWN");
}
export function trendCsv(report:TrendResult,options:TrendExportOptions):string{
 if(!report.coverage.complete)
  throw new WorkInputError("CONFLICT","Cannot export an incomplete historical event snapshot.");
 if(options.mode==="DAILY"){
  if(report.days.length>options.limit)
   throw new WorkInputError("CONFLICT","Daily export would exceed the configured limit.");
  return [
   line(DAY_COLUMNS),
   ...report.days.map(day=>line([
    day.date,day.created,day.completed,day.reopened,day.ownership,
    day.deadline,day.priority,day.comments,day.checklist,day.other,
    day.unknown,day.total,
   ])),
  ].join("\r\n")+"\r\n";
 }
 const events=selectTrendEvents(report,options);
 if(events.length>options.limit)
  throw new WorkInputError("CONFLICT","Historical event export exceeds limit; shorten the window.");
 return [
  line(EVENT_COLUMNS),
  ...events.map(item=>line([
   item.id,item.workItemId,item.occurredAt,item.category,item.confidence,
   item.actorUserId,item.from,item.to,item.label,
  ])),
 ].join("\r\n")+"\r\n";
}
export function trendIntegrity(report:TrendResult):{
 equalTotals:boolean;unknown:number;classifications:Record<TrendCategory,number>;
}{
 const categories:Record<TrendCategory,number>={
  CREATED:0,COMPLETED:0,REOPENED:0,OWNERSHIP:0,DEADLINE:0,PRIORITY:0,
  COMMENT:0,CHECKLIST:0,OTHER:0,UNKNOWN:0,
 };
 for(const item of report.events)categories[item.category]++;
 const daily=report.days.reduce((sum,day)=>sum+day.total,0);
 return {
  equalTotals:daily===report.summary.totalEvents&&
   report.events.length===report.summary.totalEvents,
  unknown:categories.UNKNOWN,classifications:categories,
 };
}
