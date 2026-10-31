import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {WorkInputError,canManageWork,type WorkStatus,type WorkPriority} from "./remediation-work-input";
import type {WorkContext} from "./remediation-work-store";

/**
 * A bounded scheduling view over persisted human work.
 * Dates are task targets, never a statement of security effectiveness.
 * Calendar snapshots contain no secret evidence payload or personal email.
 */
export type ScheduleRange="WEEK"|"MONTH"|"QUARTER";
export type ScheduleScope="MINE"|"TEAM"|"UNASSIGNED";
export type ScheduleBucket="OVERDUE"|"TODAY"|"NEXT_7_DAYS"|"LATER"|"UNSCHEDULED"|"CLOSED";
export type ScheduleInput={
 range:ScheduleRange;scope:ScheduleScope;
 referenceDate:string;includeClosed:boolean;priority:WorkPriority|"ALL";
 search:string;assigneeUserId:string|null;
};
export type ScheduleTask={
 id:string;title:string;description:string;
 revision:number;status:WorkStatus;priority:WorkPriority;
 assigneeUserId:string|null;assigneeName:string|null;
 dueAt:Date|null;createdAt:Date;updatedAt:Date;
 findingTitle:string;findingSeverity:string;findingStatus:string;
 remediationTitle:string;remediationStatus:string;
};
export type ScheduleEntry={
 id:string;title:string;revision:number;status:WorkStatus;
 priority:WorkPriority;dueDate:string|null;assigneeUserId:string|null;
 assigneeName:string|null;findingTitle:string;findingSeverity:string;
 remediationTitle:string;remediationStatus:string;
 bucket:ScheduleBucket;daysUntil:number|null;lateBy:number;
 needsOwner:boolean;isActive:boolean;
};
export type ScheduleDay={
 date:string;items:ScheduleEntry[];active:number;
 blocked:number;urgent:number;completed:number;unassigned:number;
};
export type ScheduleSummary={
 total:number;active:number;closed:number;overdue:number;
 today:number;dueSoon:number;later:number;unscheduled:number;
 blocked:number;urgent:number;unassigned:number;
};
export type ScheduleResult={
 input:ScheduleInput;generatedAt:string;
 period:{from:string;to:string;days:number};
 summary:ScheduleSummary;days:ScheduleDay[];
 overdue:ScheduleEntry[];unscheduled:ScheduleEntry[];
 later:ScheduleEntry[];closed:ScheduleEntry[];
 allEntries:ScheduleEntry[];
 coverage:{complete:boolean;fetched:number;limit:number;message:string};
 disclaimer:string;
};
const LIMIT=2000;
const DAY=86400000;
const CLOSED=new Set<WorkStatus>(["DONE","CANCELLED"]);
const PRIORITIES=new Set(["LOW","NORMAL","HIGH","URGENT"]);
const DATE_PATTERN=/^\d{4}-\d{2}-\d{2}$/;
export function parseScheduleDate(value:unknown):string{
 if(typeof value!=="string"||!DATE_PATTERN.test(value))
  throw new WorkInputError("INVALID","Date must be YYYY-MM-DD.");
 const parsed=new Date(value+"T12:00:00.000Z");
 if(Number.isNaN(parsed.getTime())||parsed.toISOString().slice(0,10)!==value)
  throw new WorkInputError("INVALID","Invalid calendar date.");
 if(parsed.getUTCFullYear()<2000||parsed.getUTCFullYear()>2100)
  throw new WorkInputError("INVALID","Date outside supported range.");
 return value;
}
function plainObject(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=="object"||Array.isArray(value))
  throw new WorkInputError("INVALID","Expected schedule input object.");
 return value as Record<string,unknown>;
}
export function parseScheduleInput(raw:unknown,now=new Date()):ScheduleInput{
 const data=plainObject(raw);
 for(const key of Object.keys(data)){
  if(!["range","scope","referenceDate","includeClosed","priority","search","assigneeUserId"].includes(key))
   throw new WorkInputError("INVALID",`Unknown schedule field: ${key}.`);
 }
 const range=data.range===undefined?"MONTH":data.range;
 const scope=data.scope===undefined?"MINE":data.scope;
 if(range!=="WEEK"&&range!=="MONTH"&&range!=="QUARTER")
  throw new WorkInputError("INVALID","Unknown schedule range.");
 if(scope!=="MINE"&&scope!=="TEAM"&&scope!=="UNASSIGNED")
  throw new WorkInputError("INVALID","Unknown schedule scope.");
 const referenceDate=parseScheduleDate(data.referenceDate===undefined?
  now.toISOString().slice(0,10):data.referenceDate);
 const includeClosed=data.includeClosed===undefined?false:data.includeClosed;
 if(typeof includeClosed!=="boolean")
  throw new WorkInputError("INVALID","includeClosed must be boolean.");
 const priority=data.priority===undefined?"ALL":data.priority;
 if(priority!=="ALL"&&(typeof priority!=="string"||!PRIORITIES.has(priority)))
  throw new WorkInputError("INVALID","Invalid schedule priority.");
 const search=data.search===undefined?"":data.search;
 if(typeof search!=="string"||search.length>120||
  /[\u0000-\u001f\u007f]/.test(search))
  throw new WorkInputError("INVALID","Invalid schedule search.");
 const assignee=data.assigneeUserId===undefined?null:data.assigneeUserId;
 if(assignee!==null&&(typeof assignee!=="string"||
  !/^[a-zA-Z0-9_-]{5,100}$/.test(assignee)))
  throw new WorkInputError("INVALID","Invalid schedule assignee.");
 return {
  range,scope,referenceDate,includeClosed,
  priority:priority as ScheduleInput["priority"],
  search:search.trim(),assigneeUserId:assignee,
 };
}
export function schedulePeriod(input:ScheduleInput){
 const year=Number(input.referenceDate.slice(0,4));
 const month=Number(input.referenceDate.slice(5,7))-1;
 const day=Number(input.referenceDate.slice(8,10));
 const current=new Date(Date.UTC(year,month,day));
 let start:Date,end:Date;
 if(input.range==="WEEK"){
  const weekday=(current.getUTCDay()+6)%7;
  start=new Date(current.getTime()-weekday*DAY);
  end=new Date(start.getTime()+7*DAY);
 }else if(input.range==="MONTH"){
  start=new Date(Date.UTC(year,month,1));
  end=new Date(Date.UTC(year,month+1,1));
 }else{
  const quarter=Math.floor(month/3)*3;
  start=new Date(Date.UTC(year,quarter,1));
  end=new Date(Date.UTC(year,quarter+3,1));
 }
 return {
  from:start.toISOString().slice(0,10),
  to:new Date(end.getTime()-DAY).toISOString().slice(0,10),
  days:Math.round((end.getTime()-start.getTime())/DAY),
  start,end,
 };
}
export function scheduleWhere(
 context:WorkContext,input:ScheduleInput,
):Prisma.RemediationWorkItemWhereInput{
 const where:Prisma.RemediationWorkItemWhereInput={
  organizationId:context.organizationId,
 };
 if(input.scope==="MINE")where.assigneeUserId=context.userId;
 if(input.scope==="UNASSIGNED")where.assigneeUserId=null;
 if(input.assigneeUserId!==null){
  if(input.scope==="MINE"&&input.assigneeUserId!==context.userId)
   throw new WorkInputError("FORBIDDEN","Cannot override personal schedule ownership.");
  if(input.scope==="UNASSIGNED")
   throw new WorkInputError("INVALID","Cannot combine unassigned scope and member filter.");
  where.assigneeUserId=input.assigneeUserId;
 }
 if(!input.includeClosed)where.status={notIn:["DONE","CANCELLED"]};
 if(input.priority!=="ALL")where.priority=input.priority;
 if(input.search)where.OR=[
  {title:{contains:input.search,mode:"insensitive"}},
  {description:{contains:input.search,mode:"insensitive"}},
  {finding:{title:{contains:input.search,mode:"insensitive"}}},
  {remediation:{title:{contains:input.search,mode:"insensitive"}}},
 ];
 return where;
}
function isoDay(date:Date){return date.toISOString().slice(0,10);}
function dayDiff(from:string,to:string){
 return Math.round((Date.parse(to+"T00:00:00Z")-Date.parse(from+"T00:00:00Z"))/DAY);
}
export function classifyScheduleTask(
 task:ScheduleTask,referenceDate:string,periodEnd:string,
):ScheduleEntry{
 const closed=CLOSED.has(task.status);
 const dueDate=task.dueAt?isoDay(task.dueAt):null;
 const daysUntil=dueDate===null?null:dayDiff(referenceDate,dueDate);
 let bucket:ScheduleBucket;
 if(closed)bucket="CLOSED";
 else if(daysUntil===null)bucket="UNSCHEDULED";
 else if(daysUntil<0)bucket="OVERDUE";
 else if(daysUntil===0)bucket="TODAY";
 else if(daysUntil<=7)bucket="NEXT_7_DAYS";
 else bucket="LATER";
 return {
  id:task.id,title:task.title,revision:task.revision,
  status:task.status,priority:task.priority,dueDate,
  assigneeUserId:task.assigneeUserId,assigneeName:task.assigneeName,
  findingTitle:task.findingTitle,findingSeverity:task.findingSeverity,
  remediationTitle:task.remediationTitle,remediationStatus:task.remediationStatus,
  bucket,daysUntil,lateBy:daysUntil!==null&&daysUntil<0?-daysUntil:0,
  needsOwner:task.assigneeUserId===null,isActive:!closed,
 };
}
const rank:Record<WorkPriority,number>={URGENT:0,HIGH:1,NORMAL:2,LOW:3};
export function orderSchedule(entries:readonly ScheduleEntry[]){
 return [...entries].sort((a,b)=>{
  const aDue=a.dueDate??"9999-12-31",bDue=b.dueDate??"9999-12-31";
  return aDue.localeCompare(bDue)||
   rank[a.priority]-rank[b.priority]||
   a.title.localeCompare(b.title)||a.id.localeCompare(b.id);
 });
}
export function summarizeSchedule(entries:readonly ScheduleEntry[]):ScheduleSummary{
 const summary:ScheduleSummary={
  total:entries.length,active:0,closed:0,overdue:0,today:0,
  dueSoon:0,later:0,unscheduled:0,blocked:0,urgent:0,unassigned:0,
 };
 for(const entry of entries){
  if(!entry.isActive){summary.closed++;continue;}
  summary.active++;
  if(entry.bucket==="OVERDUE")summary.overdue++;
  if(entry.bucket==="TODAY")summary.today++;
  if(entry.bucket==="NEXT_7_DAYS")summary.dueSoon++;
  if(entry.bucket==="LATER")summary.later++;
  if(entry.bucket==="UNSCHEDULED")summary.unscheduled++;
  if(entry.status==="BLOCKED")summary.blocked++;
  if(entry.priority==="URGENT")summary.urgent++;
  if(entry.needsOwner)summary.unassigned++;
 }
 return summary;
}
export function buildSchedule(
 tasks:readonly ScheduleTask[],input:ScheduleInput,now=new Date(),
):ScheduleResult{
 const period=schedulePeriod(input);
 const entries=orderSchedule(tasks.map(task=>
  classifyScheduleTask(task,input.referenceDate,period.to)));
 const days:ScheduleDay[]=[];
 for(let offset=0;offset<period.days;offset++){
  const date=new Date(period.start.getTime()+offset*DAY).toISOString().slice(0,10);
  const matching=entries.filter(entry=>entry.dueDate===date);
  days.push({
   date,items:matching,active:matching.filter(entry=>entry.isActive).length,
   blocked:matching.filter(entry=>entry.isActive&&entry.status==="BLOCKED").length,
   urgent:matching.filter(entry=>entry.isActive&&entry.priority==="URGENT").length,
   completed:matching.filter(entry=>!entry.isActive).length,
   unassigned:matching.filter(entry=>entry.isActive&&entry.needsOwner).length,
  });
 }
 return {
  input,generatedAt:now.toISOString(),
  period:{from:period.from,to:period.to,days:period.days},
  summary:summarizeSchedule(entries),days,
  overdue:entries.filter(entry=>entry.bucket==="OVERDUE"),
  unscheduled:entries.filter(entry=>entry.bucket==="UNSCHEDULED"),
  later:entries.filter(entry=>entry.bucket==="LATER"&&
   entry.dueDate!==null&&entry.dueDate>period.to),
  closed:entries.filter(entry=>entry.bucket==="CLOSED"),
  allEntries:entries,
  coverage:{
   complete:true,fetched:tasks.length,limit:LIMIT,
   message:"All matching work records included. Dates are manually recorded task targets.",
  },
  disclaimer:"Human work scheduling is not verification of controls or closure of security findings.",
 };
}
export async function loadWorkSchedule(
 context:WorkContext,raw:unknown,now=new Date(),
):Promise<ScheduleResult>{
 const input=parseScheduleInput(raw,now);
 if(input.scope==="TEAM"&&!canManageWork(context.role)&&context.role!=="AUDITOR")
  throw new WorkInputError("FORBIDDEN","Team scheduling requires management or audit access.");
 const where=scheduleWhere(context,input);
 if(input.assigneeUserId){
  const member=await db.membership.findFirst({
   where:{organizationId:context.organizationId,userId:input.assigneeUserId},
   select:{userId:true},
  });
  if(!member)throw new WorkInputError("INVALID","Assignee is not a member of this organization.");
 }
 const [count,rows]=await db.$transaction([
  db.remediationWorkItem.count({where}),
  db.remediationWorkItem.findMany({
   where,orderBy:[{dueAt:"asc"},{id:"asc"}],take:LIMIT+1,
   select:{
    id:true,title:true,description:true,revision:true,status:true,priority:true,
    assigneeUserId:true,dueAt:true,createdAt:true,updatedAt:true,
    assignee:{select:{name:true}},
    finding:{select:{title:true,severity:true,status:true}},
    remediation:{select:{title:true,status:true}},
   },
  }),
 ]);
 if(count>LIMIT||count!==rows.length)
  throw new WorkInputError("CONFLICT",
   "Schedule exceeds 2,000 work records. Narrow the scope before exporting.");
 return buildSchedule(rows.map(row=>({
  id:row.id,title:row.title,description:row.description,
  revision:row.revision,status:row.status,priority:row.priority,
  assigneeUserId:row.assigneeUserId,assigneeName:row.assignee?.name??null,
  dueAt:row.dueAt,createdAt:row.createdAt,updatedAt:row.updatedAt,
  findingTitle:row.finding.title,findingSeverity:row.finding.severity,
  findingStatus:row.finding.status,
  remediationTitle:row.remediation.title,remediationStatus:row.remediation.status,
 })),input,now);
}
function escapeIcs(value:string):string{
 return value.replace(/\\/g,"\\\\").replace(/\r?\n/g,"\\n")
  .replace(/,/g,"\\,").replace(/;/g,"\\;");
}
function foldIcs(line:string):string{
 // RFC 5545 recommends lines no longer than 75 octets. ASCII-delimiters
 // are safe to fold; UTF-8 code points are never split.
 const segments:string[]=[];
 let chunk="",size=0;
 for(const char of line){
  const bytes=Buffer.byteLength(char,"utf8");
  if(size+bytes>75){segments.push(chunk);chunk=" ";size=1;}
  chunk+=char;size+=bytes;
 }
 if(chunk)segments.push(chunk);
 return segments.join("\r\n");
}
function icsDate(iso:string){return iso.replace(/-/g,"");}
export function scheduleCalendar(
 result:ScheduleResult,organizationSlug:string,
):string{
 const generated=result.generatedAt.replace(/[-:]/g,"").replace(/\.\d{3}/,"");
 const lines=[
  "BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//CyberPilot//Work Scheduling//EN",
  "CALSCALE:GREGORIAN","METHOD:PUBLISH",
  "X-WR-CALNAME:CyberPilot operational work targets",
 ];
 for(const entry of result.allEntries){
  if(!entry.dueDate)continue;
  const next=new Date(entry.dueDate+"T00:00:00.000Z");
  next.setUTCDate(next.getUTCDate()+1);
  lines.push(
   "BEGIN:VEVENT",
   `UID:${entry.id}@${organizationSlug}.cyberpilot.local`,
   `DTSTAMP:${generated}`,
   `DTSTART;VALUE=DATE:${icsDate(entry.dueDate)}`,
   `DTEND;VALUE=DATE:${icsDate(next.toISOString().slice(0,10))}`,
   `SUMMARY:${escapeIcs("Work target: "+entry.title)}`,
   `DESCRIPTION:${escapeIcs(
    `Operational task only. Status: ${entry.status}. Priority: ${entry.priority}. Related finding: ${entry.findingTitle}. Completion is not security verification.`
   )}`,
   "TRANSP:TRANSPARENT",
   "END:VEVENT",
  );
 }
 lines.push("END:VCALENDAR");
 return lines.map(foldIcs).join("\r\n")+"\r\n";
}
