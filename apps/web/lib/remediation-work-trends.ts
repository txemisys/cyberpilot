import {db} from "@cyberpilot/database";
import {WorkInputError} from "./remediation-work-input";
import type {WorkContext} from "./remediation-work-store";

/**
 * Historical throughput from real work event records, not reconstructed
 * scanner executions. Snapshot gaps are explicitly unknown, never guessed.
 */
export type TrendWindow=7|14|30|60|90;
export type TrendScope="MINE"|"TEAM";
export type TrendMetric="ALL"|"CREATED"|"COMPLETED"|"REOPENED"|"OWNERSHIP"|"DEADLINE"|"PRIORITY";
export type TrendFilter={
 days:TrendWindow;scope:TrendScope;metric:TrendMetric;
 includeComments:boolean;includeChecklist:boolean;
};
export type TrendEvent={
 id:string;workItemId:string;kind:string;occurredAt:Date;
 actorUserId:string|null;before:unknown;after:unknown;comment:string|null;
};
export type TrendWork={
 id:string;title:string;status:string;assigneeUserId:string|null;
 createdAt:Date;updatedAt:Date;
};
export type TrendCategory="CREATED"|"COMPLETED"|"REOPENED"|"OWNERSHIP"|
 "DEADLINE"|"PRIORITY"|"COMMENT"|"CHECKLIST"|"OTHER"|"UNKNOWN";
export type TrendClassification={
 id:string;workItemId:string;occurredAt:string;actorUserId:string|null;
 category:TrendCategory;label:string;confidence:"EXPLICIT"|"SNAPSHOT"|"UNKNOWN";
 from:string|null;to:string|null;
};
export type TrendDay={
 date:string;created:number;completed:number;reopened:number;ownership:number;
 deadline:number;priority:number;comments:number;checklist:number;other:number;
 unknown:number;total:number;
};
export type TrendSummary={
 totalEvents:number;created:number;completed:number;reopened:number;
 ownership:number;deadline:number;priority:number;comments:number;
 checklist:number;other:number;unknown:number;
 affectedWork:number;actors:number;openNow:number;doneNow:number;
 overdueNow:number;unassignedNow:number;
};
export type TrendResult={
 filter:TrendFilter;from:string;to:string;generatedAt:string;
 days:TrendDay[];events:TrendClassification[];summary:TrendSummary;
 coverage:{complete:boolean;workCount:number;eventCount:number;
  workLimit:number;eventLimit:number;note:string};
 disclaimer:string;
};
const DAY=86400000;
const MAX_EVENTS=4000;
const MAX_WORK=2000;
const windows=[7,14,30,60,90] as const;
const scopes=["MINE","TEAM"] as const;
const metrics=["ALL","CREATED","COMPLETED","REOPENED","OWNERSHIP","DEADLINE","PRIORITY"] as const;
function record(value:unknown):Record<string,unknown>|null{
 return value!==null&&typeof value==="object"&&!Array.isArray(value)?
  value as Record<string,unknown>:null;
}
function snapshotField(value:unknown,key:string):string|null{
 const entry=record(value);
 const field=entry?.[key];
 return typeof field==="string"?field:null;
}
export function parseTrendFilter(raw:unknown):TrendFilter{
 if(!record(raw))throw new WorkInputError("INVALID","Trend filter must be an object.");
 const data=raw as Record<string,unknown>;
 for(const key of Object.keys(data))
  if(!["days","scope","metric","includeComments","includeChecklist"].includes(key))
   throw new WorkInputError("INVALID",`Unknown trend filter ${key}.`);
 const days=data.days===undefined?30:data.days;
 const scope=data.scope===undefined?"MINE":data.scope;
 const metric=data.metric===undefined?"ALL":data.metric;
 const includeComments=data.includeComments===undefined?true:data.includeComments;
 const includeChecklist=data.includeChecklist===undefined?true:data.includeChecklist;
 if(typeof days!=="number"||!windows.some(value=>value===days))
  throw new WorkInputError("INVALID","Trend window must be 7, 14, 30, 60 or 90 days.");
 if(typeof scope!=="string"||!scopes.some(value=>value===scope))
  throw new WorkInputError("INVALID","Unknown trend scope.");
 if(typeof metric!=="string"||!metrics.some(value=>value===metric))
  throw new WorkInputError("INVALID","Unknown event metric.");
 if(typeof includeComments!=="boolean"||typeof includeChecklist!=="boolean")
  throw new WorkInputError("INVALID","Event visibility flags must be boolean.");
 return {days:days as TrendWindow,scope:scope as TrendScope,
  metric:metric as TrendMetric,includeComments,includeChecklist};
}
export function trendStart(now:Date,days:TrendWindow):Date{
 const today=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()));
 return new Date(today.getTime()-(days-1)*DAY);
}
function dayKey(date:Date){return date.toISOString().slice(0,10);}
export function classifyTrendEvent(event:TrendEvent):TrendClassification{
 const before=record(event.before),after=record(event.after);
 const fromStatus=snapshotField(before,"status");
 const toStatus=snapshotField(after,"status");
 const statusChanged=fromStatus!==null&&toStatus!==null&&fromStatus!==toStatus;
 const changed=(field:string)=>
  before!==null&&after!==null&&
  Object.hasOwn(before,field)&&Object.hasOwn(after,field)&&
  JSON.stringify(before[field])!==JSON.stringify(after[field]);
 let category:TrendCategory="UNKNOWN";
 let confidence:TrendClassification["confidence"]="UNKNOWN";
 let from:string|null=null,to:string|null=null;
 if(event.kind==="CREATED"){
  category="CREATED";confidence="EXPLICIT";
 }else if(statusChanged&&toStatus==="DONE"){
  category="COMPLETED";confidence="SNAPSHOT";from=fromStatus;to=toStatus;
 }else if(statusChanged&&fromStatus==="DONE"&&toStatus!=="DONE"){
  category="REOPENED";confidence="SNAPSHOT";from=fromStatus;to=toStatus;
 }else if(changed("assigneeUserId")){
  category="OWNERSHIP";confidence="SNAPSHOT";
  from=snapshotField(before,"assigneeUserId");to=snapshotField(after,"assigneeUserId");
 }else if(changed("dueAt")){
  category="DEADLINE";confidence="SNAPSHOT";
  from=snapshotField(before,"dueAt");to=snapshotField(after,"dueAt");
 }else if(changed("priority")){
  category="PRIORITY";confidence="SNAPSHOT";
  from=snapshotField(before,"priority");to=snapshotField(after,"priority");
 }else if(event.kind==="COMMENTED"){
  category="COMMENT";confidence="EXPLICIT";
 }else if(event.comment!==null&&/checklist/i.test(event.comment)){
  category="CHECKLIST";confidence="EXPLICIT";
 }else if(event.kind==="UPDATED"||event.kind==="REOPENED"){
  category="OTHER";confidence="EXPLICIT";
 }
 const names:Record<TrendCategory,string>={
  CREATED:"Work created",COMPLETED:"Work marked complete",
  REOPENED:"Completed work reopened",OWNERSHIP:"Owner changed",
  DEADLINE:"Deadline changed",PRIORITY:"Priority changed",
  COMMENT:"Work comment",CHECKLIST:"Checklist activity",
  OTHER:"Other recorded work update",UNKNOWN:"Unclassified record",
 };
 return {id:event.id,workItemId:event.workItemId,
  occurredAt:event.occurredAt.toISOString(),actorUserId:event.actorUserId,
  category,confidence,from,to,label:names[category]};
}
function eligible(item:TrendClassification,filter:TrendFilter){
 if(!filter.includeComments&&item.category==="COMMENT")return false;
 if(!filter.includeChecklist&&item.category==="CHECKLIST")return false;
 return filter.metric==="ALL"||item.category===filter.metric;
}
export function buildWorkTrends(
 events:readonly TrendEvent[],work:readonly TrendWork[],
 filter:TrendFilter,now=new Date(),
):TrendResult{
 const first=trendStart(now,filter.days);
 const last=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()));
 const dayMap=new Map<string,TrendDay>();
 for(let offset=0;offset<filter.days;offset++){
  const key=dayKey(new Date(first.getTime()+offset*DAY));
  dayMap.set(key,{date:key,created:0,completed:0,reopened:0,ownership:0,
   deadline:0,priority:0,comments:0,checklist:0,other:0,unknown:0,total:0});
 }
 const classifications=events.filter(item=>
  item.occurredAt>=first&&item.occurredAt.getTime()<=now.getTime())
  .map(classifyTrendEvent).filter(item=>eligible(item,filter))
  .sort((a,b)=>b.occurredAt.localeCompare(a.occurredAt)||a.id.localeCompare(b.id));
 const field:Record<TrendCategory,keyof Omit<TrendDay,"date"|"total">>={
  CREATED:"created",COMPLETED:"completed",REOPENED:"reopened",
  OWNERSHIP:"ownership",DEADLINE:"deadline",PRIORITY:"priority",
  COMMENT:"comments",CHECKLIST:"checklist",OTHER:"other",UNKNOWN:"unknown",
 };
 for(const item of classifications){
  const day=dayMap.get(item.occurredAt.slice(0,10));
  if(!day)continue;
  day[field[item.category]]++;
  day.total++;
 }
 const days=[...dayMap.values()];
 const sum=(key:keyof Omit<TrendDay,"date">)=>days.reduce((acc,row)=>acc+row[key],0);
 const closed=new Set(["DONE","CANCELLED"]);
 const open=work.filter(item=>!closed.has(item.status));
 const affected=new Set(classifications.map(item=>item.workItemId));
 const actors=new Set(classifications.map(item=>item.actorUserId).filter(Boolean));
 return {
  filter,from:dayKey(first),to:dayKey(last),generatedAt:now.toISOString(),
  days,events:classifications,
  summary:{
   totalEvents:sum("total"),created:sum("created"),completed:sum("completed"),
   reopened:sum("reopened"),ownership:sum("ownership"),deadline:sum("deadline"),
   priority:sum("priority"),comments:sum("comments"),checklist:sum("checklist"),
   other:sum("other"),unknown:sum("unknown"),affectedWork:affected.size,
   actors:actors.size,openNow:open.length,
   doneNow:work.filter(item=>item.status==="DONE").length,
   overdueNow:0,unassignedNow:open.filter(item=>item.assigneeUserId===null).length,
  },
  coverage:{
   complete:true,workCount:work.length,eventCount:events.length,
   workLimit:MAX_WORK,eventLimit:MAX_EVENTS,
   note:"A bounded complete snapshot was used. Missing historical snapshots remain explicitly unclassified.",
  },
  disclaimer:"Operational activity is not scanner execution, verified remediation, or a security effectiveness measure.",
 };
}
export async function loadWorkTrends(context:WorkContext,raw:unknown,now=new Date()):Promise<TrendResult>{
 const filter=parseTrendFilter(raw);
 if(filter.scope==="TEAM"&&context.role!=="OWNER"&&context.role!=="ADMIN"&&context.role!=="AUDITOR")
  throw new WorkInputError("FORBIDDEN","Team trends require management or audit access.");
 const where={organizationId:context.organizationId,
  ...(filter.scope==="MINE"?{assigneeUserId:context.userId}:{})};
 const [workCount,work]=await db.$transaction([
  db.remediationWorkItem.count({where}),
  db.remediationWorkItem.findMany({where,select:{
   id:true,title:true,status:true,assigneeUserId:true,createdAt:true,updatedAt:true,dueAt:true,
  },take:MAX_WORK+1,orderBy:{id:"asc"}}),
 ]);
 if(workCount>MAX_WORK||work.length!==workCount)
  throw new WorkInputError("CONFLICT","Work inventory exceeds 2,000 records; narrow the scope.");
 const ids=work.map(item=>item.id);
 const since=trendStart(now,filter.days);
 const eventWhere={organizationId:context.organizationId,
  workItemId:{in:ids},occurredAt:{gte:since,lte:now}};
 const [eventCount,events]=await db.$transaction([
  db.remediationWorkEvent.count({where:eventWhere}),
  db.remediationWorkEvent.findMany({where:eventWhere,take:MAX_EVENTS+1,
   orderBy:[{occurredAt:"desc"},{id:"desc"}],
   select:{id:true,workItemId:true,kind:true,occurredAt:true,actorUserId:true,
    before:true,after:true,comment:true}}),
 ]);
 if(eventCount>MAX_EVENTS||events.length!==eventCount)
  throw new WorkInputError("CONFLICT","Event history exceeds 4,000 records; choose a shorter window.");
 const result=buildWorkTrends(events,work,filter,now);
 result.summary.overdueNow=work.filter(item=>!["DONE","CANCELLED"].includes(item.status)
  &&item.dueAt!==null&&item.dueAt<now).length;
 return result;
}
