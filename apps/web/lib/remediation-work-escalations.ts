import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {WorkInputError,canManageWork} from "./remediation-work-input";
import type {WorkContext} from "./remediation-work-store";

/** Decision records describe operational triage, never security attestation. */
export type EscalationLevel="NONE"|"WATCH"|"ELEVATED"|"CRITICAL";
export type EscalationReason="OVERDUE"|"DUE_SOON"|"BLOCKED"|"UNASSIGNED"|"URGENT"|"STALE"|"HANDOFF";
export type EscalationScope="MINE"|"TEAM"|"UNASSIGNED";
export type EscalationOrder="SEVERITY"|"DEADLINE"|"AGE"|"LAST_UPDATE";
export type EscalationConfig={
 scope:EscalationScope;
 order:EscalationOrder;
 includeClosed:boolean;
 thresholdDays:7|14|30|60;
 staleDays:7|14|30|60|90;
 minLevel:EscalationLevel;
 search:string;
};
export type EscalationWork={
 id:string;title:string;description:string;revision:number;
 status:"TODO"|"IN_PROGRESS"|"BLOCKED"|"DONE"|"CANCELLED";
 priority:"LOW"|"NORMAL"|"HIGH"|"URGENT";
 assigneeUserId:string|null;assigneeName:string|null;
 dueAt:Date|null;createdAt:Date;updatedAt:Date;
 findingId:string;findingTitle:string;findingSeverity:string;findingStatus:string;
 remediationId:string;remediationTitle:string;remediationStatus:string;
 pendingHandoffs:number;
};
export type EscalationDecision={
 id:string;title:string;revision:number;status:EscalationWork["status"];
 priority:EscalationWork["priority"];assigneeUserId:string|null;
 assigneeName:string|null;dueAt:string|null;updatedAt:string;
 findingId:string;findingTitle:string;findingSeverity:string;findingStatus:string;
 remediationId:string;remediationTitle:string;remediationStatus:string;
 level:EscalationLevel;score:number;reasons:EscalationReason[];
 overdueDays:number|null;daysUntilDue:number|null;idleDays:number;
 pendingHandoffs:number;nextAction:string;
};
export type EscalationSummary={
 total:number;critical:number;elevated:number;watch:number;none:number;
 overdue:number;blocked:number;unassigned:number;stale:number;
 handoff:number;urgent:number;dueSoon:number;
};
export type EscalationResult={
 config:EscalationConfig;generatedAt:string;total:number;
 summary:EscalationSummary;decisions:EscalationDecision[];
 coverage:{complete:boolean;maxRecords:number;note:string};
 disclaimer:string;
};
const MS_DAY=86400000;
const maxRows=2000;
const levels:EscalationLevel[]=["NONE","WATCH","ELEVATED","CRITICAL"];
const scopes:EscalationScope[]=["MINE","TEAM","UNASSIGNED"];
const orders:EscalationOrder[]=["SEVERITY","DEADLINE","AGE","LAST_UPDATE"];
const thresholdDays=[7,14,30,60] as const;
const staleDays=[7,14,30,60,90] as const;
const closed=new Set(["DONE","CANCELLED"]);
function object(value:unknown):Record<string,unknown>{
 if(value===null||typeof value!=="object"||Array.isArray(value))
  throw new WorkInputError("INVALID","Escalation configuration must be an object.");
 return value as Record<string,unknown>;
}
function isOneOf<T extends string>(value:unknown,values:readonly T[]):value is T{
 return typeof value==="string"&&values.includes(value as T);
}
export function parseEscalationConfig(raw:unknown):EscalationConfig{
 const data=object(raw);
 for(const key of Object.keys(data)){
  if(!["scope","order","includeClosed","thresholdDays","staleDays","minLevel","search"].includes(key))
   throw new WorkInputError("INVALID",`Unknown escalation setting: ${key}.`);
 }
 const scope=data.scope===undefined?"MINE":data.scope;
 const order=data.order===undefined?"SEVERITY":data.order;
 const minLevel=data.minLevel===undefined?"WATCH":data.minLevel;
 const includeClosed=data.includeClosed===undefined?false:data.includeClosed;
 const threshold=data.thresholdDays===undefined?14:data.thresholdDays;
 const stale=data.staleDays===undefined?30:data.staleDays;
 const search=data.search===undefined?"":data.search;
 if(!isOneOf(scope,scopes)||!isOneOf(order,orders)||!isOneOf(minLevel,levels))
  throw new WorkInputError("INVALID","Invalid escalation scope, ordering or level.");
 if(typeof includeClosed!=="boolean")
  throw new WorkInputError("INVALID","includeClosed must be boolean.");
 if(typeof threshold!=="number"||!thresholdDays.some(n=>n===threshold))
  throw new WorkInputError("INVALID","Unsupported due threshold.");
 if(typeof stale!=="number"||!staleDays.some(n=>n===stale))
  throw new WorkInputError("INVALID","Unsupported inactivity threshold.");
 if(typeof search!=="string"||search.length>120||/[\u0000-\u001f\u007f]/.test(search))
  throw new WorkInputError("INVALID","Search must be printable text up to 120 characters.");
 return {scope,order,includeClosed,thresholdDays:threshold as EscalationConfig["thresholdDays"],
  staleDays:stale as EscalationConfig["staleDays"],minLevel,search:search.trim()};
}
export function escalationWhere(context:WorkContext,config:EscalationConfig):Prisma.RemediationWorkItemWhereInput{
 const where:Prisma.RemediationWorkItemWhereInput={organizationId:context.organizationId};
 if(config.scope==="MINE")where.assigneeUserId=context.userId;
 if(config.scope==="UNASSIGNED")where.assigneeUserId=null;
 if(!config.includeClosed)where.status={notIn:["DONE","CANCELLED"]};
 if(config.search)where.OR=[
  {title:{contains:config.search,mode:"insensitive"}},
  {description:{contains:config.search,mode:"insensitive"}},
  {finding:{title:{contains:config.search,mode:"insensitive"}}},
  {remediation:{title:{contains:config.search,mode:"insensitive"}}},
 ];
 return where;
}
function utcDays(now:Date,past:Date){return Math.max(0,Math.floor((now.getTime()-past.getTime())/MS_DAY));}
export function classifyEscalation(work:EscalationWork,config:EscalationConfig,now:Date):EscalationDecision{
 const inactive=utcDays(now,work.updatedAt);
 const dueDays=work.dueAt===null?null:Math.ceil((work.dueAt.getTime()-now.getTime())/MS_DAY);
 const overdueDays=dueDays!==null&&dueDays<0?-dueDays:null;
 const reasons:EscalationReason[]=[];
 const isClosed=closed.has(work.status);
 if(!isClosed){
  if(overdueDays!==null)reasons.push("OVERDUE");
  else if(dueDays!==null&&dueDays<=config.thresholdDays)reasons.push("DUE_SOON");
  if(work.status==="BLOCKED")reasons.push("BLOCKED");
  if(work.assigneeUserId===null)reasons.push("UNASSIGNED");
  if(work.priority==="URGENT")reasons.push("URGENT");
  if(inactive>=config.staleDays)reasons.push("STALE");
  if(work.pendingHandoffs>0)reasons.push("HANDOFF");
 }
 let score=0;
 if(reasons.includes("OVERDUE"))score+=Math.min(50,20+(overdueDays??0)*2);
 if(reasons.includes("BLOCKED"))score+=25;
 if(reasons.includes("UNASSIGNED"))score+=15;
 if(reasons.includes("URGENT"))score+=20;
 if(reasons.includes("STALE"))score+=15;
 if(reasons.includes("HANDOFF"))score+=15;
 if(reasons.includes("DUE_SOON"))score+=10;
 if(!isClosed&&work.findingSeverity==="CRITICAL")score+=15;
 else if(!isClosed&&work.findingSeverity==="HIGH")score+=8;
 const level:EscalationLevel=isClosed||score===0?"NONE":
  score>=65?"CRITICAL":score>=35?"ELEVATED":"WATCH";
 const nextAction=isClosed
  ?"Review the task outcome separately from the security finding and verification."
  :reasons.includes("HANDOFF")
  ?"Review and decide the pending responsibility handoff."
  :reasons.includes("BLOCKED")
  ?"Document and resolve the blocking dependency with the responsible team."
  :reasons.includes("OVERDUE")
  ?"Agree a revised target date and document why the work missed its deadline."
  :reasons.includes("UNASSIGNED")
  ?"Assign the task to an authorized organization member."
  :reasons.includes("STALE")
  ?"Request a progress update and record the current work status."
  :reasons.includes("DUE_SOON")
  ?"Confirm the planned work can meet its recorded target date."
  :"Continue the documented remediation work and keep its owner informed.";
 return {
  id:work.id,title:work.title,revision:work.revision,status:work.status,
  priority:work.priority,assigneeUserId:work.assigneeUserId,
  assigneeName:work.assigneeName,dueAt:work.dueAt?.toISOString()??null,
  updatedAt:work.updatedAt.toISOString(),findingId:work.findingId,
  findingTitle:work.findingTitle,findingSeverity:work.findingSeverity,
  findingStatus:work.findingStatus,remediationId:work.remediationId,
  remediationTitle:work.remediationTitle,remediationStatus:work.remediationStatus,
  level,score,reasons,overdueDays,daysUntilDue:dueDays,idleDays:inactive,
  pendingHandoffs:work.pendingHandoffs,nextAction,
 };
}
export function orderEscalations(rows:readonly EscalationDecision[],order:EscalationOrder){
 const rank:Record<EscalationLevel,number>={CRITICAL:0,ELEVATED:1,WATCH:2,NONE:3};
 return [...rows].sort((a,b)=>{
  const due=(a.dueAt===null?Infinity:Date.parse(a.dueAt))-
   (b.dueAt===null?Infinity:Date.parse(b.dueAt));
  const idle=b.idleDays-a.idleDays;
  const update=Date.parse(a.updatedAt)-Date.parse(b.updatedAt);
  if(order==="DEADLINE")return due||b.score-a.score||a.id.localeCompare(b.id);
  if(order==="AGE")return idle||b.score-a.score||a.id.localeCompare(b.id);
  if(order==="LAST_UPDATE")return update||b.score-a.score||a.id.localeCompare(b.id);
  return rank[a.level]-rank[b.level]||b.score-a.score||due||a.id.localeCompare(b.id);
 });
}
export function summarizeEscalations(rows:readonly EscalationDecision[]):EscalationSummary{
 const sum:EscalationSummary={total:rows.length,critical:0,elevated:0,watch:0,none:0,
  overdue:0,blocked:0,unassigned:0,stale:0,handoff:0,urgent:0,dueSoon:0};
 for(const row of rows){
  if(row.level==="CRITICAL")sum.critical++;
  if(row.level==="ELEVATED")sum.elevated++;
  if(row.level==="WATCH")sum.watch++;
  if(row.level==="NONE")sum.none++;
  for(const reason of row.reasons){
   if(reason==="OVERDUE")sum.overdue++;
   if(reason==="BLOCKED")sum.blocked++;
   if(reason==="UNASSIGNED")sum.unassigned++;
   if(reason==="STALE")sum.stale++;
   if(reason==="HANDOFF")sum.handoff++;
   if(reason==="URGENT")sum.urgent++;
   if(reason==="DUE_SOON")sum.dueSoon++;
  }
 }
 return sum;
}
export function buildEscalationReview(
 work:readonly EscalationWork[],config:EscalationConfig,now:Date,
):EscalationResult{
 const all=work.map(item=>classifyEscalation(item,config,now));
 const rank=levels.indexOf(config.minLevel);
 const relevant=orderEscalations(all.filter(item=>levels.indexOf(item.level)>=rank),config.order);
 return {
  config,generatedAt:now.toISOString(),total:relevant.length,
  summary:summarizeEscalations(all),decisions:relevant,
  coverage:{complete:true,maxRecords:maxRows,note:"Review covers all matching work records within the bounded organization snapshot."},
  disclaimer:"Attention levels are operational scheduling heuristics, not security findings, scanner evidence, or certification.",
 };
}
export async function loadEscalationReview(
 context:WorkContext,raw:unknown,now=new Date(),
):Promise<EscalationResult>{
 const config=parseEscalationConfig(raw);
 if(config.scope==="TEAM"&&!canManageWork(context.role)&&context.role!=="AUDITOR")
  throw new WorkInputError("FORBIDDEN","Team escalation review requires manager or audit access.");
 const where=escalationWhere(context,config);
 const [count,records]=await db.$transaction([
  db.remediationWorkItem.count({where}),
  db.remediationWorkItem.findMany({
   where,take:maxRows+1,orderBy:[{id:"asc"}],
   select:{
    id:true,title:true,description:true,revision:true,status:true,priority:true,
    assigneeUserId:true,dueAt:true,createdAt:true,updatedAt:true,
    assignee:{select:{name:true}},
    finding:{select:{id:true,title:true,severity:true,status:true}},
    remediation:{select:{id:true,title:true,status:true}},
    handoffs:{where:{organizationId:context.organizationId,status:"REQUESTED"},
     select:{id:true}},
   },
  }),
 ]);
 if(count>maxRows||records.length!==count)
  throw new WorkInputError("CONFLICT","Too many matching work items; narrow the escalation review.");
 return buildEscalationReview(records.map(record=>({
  id:record.id,title:record.title,description:record.description,revision:record.revision,
  status:record.status,priority:record.priority,
  assigneeUserId:record.assigneeUserId,assigneeName:record.assignee?.name??null,
  dueAt:record.dueAt,createdAt:record.createdAt,updatedAt:record.updatedAt,
  findingId:record.finding.id,findingTitle:record.finding.title,
  findingSeverity:record.finding.severity,findingStatus:record.finding.status,
  remediationId:record.remediation.id,remediationTitle:record.remediation.title,
  remediationStatus:record.remediation.status,pendingHandoffs:record.handoffs.length,
 })),config,now);
}
