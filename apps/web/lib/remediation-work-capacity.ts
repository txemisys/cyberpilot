import {db} from "@cyberpilot/database";
import {WorkInputError,canManageWork} from "./remediation-work-input";
import type {WorkContext} from "./remediation-work-store";

/** Team capacity is a factual count of assigned records, never fabricated person-hours. */
export type CapacityScope="TEAM"|"MINE";
export type CapacitySort="ATTENTION"|"OVERDUE"|"ACTIVE"|"MEMBER";
export type CapacityConfig={scope:CapacityScope;sort:CapacitySort;
 includeClosed:boolean;horizonDays:7|14|30|60;maxTasks:number};
export type CapacityWork={id:string;title:string;status:string;priority:string;
 assigneeUserId:string|null;dueAt:Date|null;updatedAt:Date;
 findingSeverity:string;checklist:{completedAt:Date|null}[];
 handoffs:{status:string}[]};
export type CapacityMember={userId:string;name:string;role:string};
export type MemberLoad={id:string;name:string;role:string;
 assigned:number;active:number;closed:number;urgent:number;blocked:number;
 overdue:number;upcoming:number;stale:number;pendingHandoffs:number;
 checklistGaps:number;attentionPoints:number;tasks:CapacityTask[]};
export type CapacityTask={id:string;title:string;priority:string;status:string;
 dueAt:string|null;daysUntilDue:number|null;attentionPoints:number;reasons:string[]};
export type CapacitySummary={members:number;tasks:number;active:number;closed:number;
 assigned:number;unassigned:number;overdue:number;urgent:number;
 blocked:number;upcoming:number;stale:number;pendingHandoffs:number;
 attentionPoints:number;maxActive:number;minActive:number};
export type CapacityReport={config:CapacityConfig;generatedAt:string;
 members:MemberLoad[];unassigned:MemberLoad;summary:CapacitySummary;
 coverage:{complete:boolean;taskLimit:number;memberLimit:number;
 taskPreviewLimit:number;note:string};
 disclaimer:string};
const DAY=86400000;
const MAX_WORK=2000,MAX_MEMBERS=500;
const sorts=["ATTENTION","OVERDUE","ACTIVE","MEMBER"] as const;
const horizons=[7,14,30,60] as const;
function object(raw:unknown):Record<string,unknown>{
 if(!raw||typeof raw!=="object"||Array.isArray(raw))
  throw new WorkInputError("INVALID","Capacity configuration must be an object.");
 return raw as Record<string,unknown>;
}
export function parseCapacityConfig(raw:unknown):CapacityConfig{
 const data=object(raw);
 for(const key of Object.keys(data))
  if(!["scope","sort","includeClosed","horizonDays","maxTasks"].includes(key))
   throw new WorkInputError("INVALID",`Unknown capacity option: ${key}.`);
 const scope=data.scope===undefined?"TEAM":data.scope;
 const sort=data.sort===undefined?"ATTENTION":data.sort;
 const includeClosed=data.includeClosed===undefined?false:data.includeClosed;
 const horizonDays=data.horizonDays===undefined?14:data.horizonDays;
 const maxTasks=data.maxTasks===undefined?10:data.maxTasks;
 if(scope!=="TEAM"&&scope!=="MINE")throw new WorkInputError("INVALID","Invalid capacity scope.");
 if(typeof sort!=="string"||!sorts.some(item=>item===sort))
  throw new WorkInputError("INVALID","Invalid capacity ordering.");
 if(typeof includeClosed!=="boolean")
  throw new WorkInputError("INVALID","Closed work switch must be boolean.");
 if(typeof horizonDays!=="number"||!horizons.some(item=>item===horizonDays))
  throw new WorkInputError("INVALID","Invalid scheduling horizon.");
 if(typeof maxTasks!=="number"||!Number.isSafeInteger(maxTasks)||maxTasks<1||maxTasks>50)
  throw new WorkInputError("INVALID","Preview accepts 1 to 50 tasks per member.");
 return {scope,sort:sort as CapacitySort,includeClosed,
  horizonDays:horizonDays as CapacityConfig["horizonDays"],maxTasks};
}
export function scoreCapacityWork(work:CapacityWork,now:Date,horizon:number):CapacityTask{
 const closed=work.status==="DONE"||work.status==="CANCELLED";
 const daysUntilDue=work.dueAt===null?null:Math.ceil((work.dueAt.getTime()-now.getTime())/DAY);
 const idleDays=Math.max(0,Math.floor((now.getTime()-work.updatedAt.getTime())/DAY));
 const reasons:string[]=[];
 if(!closed){
  if(daysUntilDue!==null&&daysUntilDue<0)reasons.push("OVERDUE");
  else if(daysUntilDue!==null&&daysUntilDue<=horizon)reasons.push("DUE_SOON");
  if(work.status==="BLOCKED")reasons.push("BLOCKED");
  if(work.priority==="URGENT")reasons.push("URGENT");
  if(idleDays>=14)reasons.push("STALE");
  if(work.handoffs.some(row=>row.status==="REQUESTED"))reasons.push("HANDOFF");
  if(work.checklist.length===0||work.checklist.some(row=>row.completedAt===null))
   reasons.push("CHECKLIST_GAP");
 }
 const points:Record<string,number>={OVERDUE:35,DUE_SOON:10,BLOCKED:25,
  URGENT:20,STALE:12,HANDOFF:18,CHECKLIST_GAP:5};
 const severity=closed?0:work.findingSeverity==="CRITICAL"?15:
  work.findingSeverity==="HIGH"?8:0;
 return {id:work.id,title:work.title,status:work.status,priority:work.priority,
  dueAt:work.dueAt?.toISOString()??null,daysUntilDue,
  reasons,attentionPoints:reasons.reduce((a,b)=>a+(points[b]??0),severity)};
}
export function summarizeMemberLoad(member:CapacityMember,work:readonly CapacityWork[],
 config:CapacityConfig,now:Date):MemberLoad{
 const tasks=work.map(row=>scoreCapacityWork(row,now,config.horizonDays));
 let active=0,closed=0,urgent=0,blocked=0,overdue=0,upcoming=0;
 let stale=0,pendingHandoffs=0,checklistGaps=0,attentionPoints=0;
 for(const item of tasks){
  const finished=item.status==="DONE"||item.status==="CANCELLED";
  if(finished)closed++;else active++;
  if(item.reasons.includes("URGENT"))urgent++;
  if(item.reasons.includes("BLOCKED"))blocked++;
  if(item.reasons.includes("OVERDUE"))overdue++;
  if(item.reasons.includes("DUE_SOON"))upcoming++;
  if(item.reasons.includes("STALE"))stale++;
  if(item.reasons.includes("HANDOFF"))pendingHandoffs++;
  if(item.reasons.includes("CHECKLIST_GAP"))checklistGaps++;
  attentionPoints+=item.attentionPoints;
 }
 const sorted=tasks.sort((a,b)=>b.attentionPoints-a.attentionPoints||
  (a.dueAt??"9999").localeCompare(b.dueAt??"9999")||a.id.localeCompare(b.id));
 return {id:member.userId,name:member.name,role:member.role,
  assigned:tasks.length,active,closed,urgent,blocked,overdue,upcoming,
  stale,pendingHandoffs,checklistGaps,attentionPoints,
  tasks:sorted.slice(0,config.maxTasks)};
}
export function buildCapacityReport(work:readonly CapacityWork[],
 members:readonly CapacityMember[],config:CapacityConfig,now=new Date()):CapacityReport{
 const byOwner=new Map<string,CapacityWork[]>();
 for(const member of members)byOwner.set(member.userId,[]);
 const unassignedWork:CapacityWork[]=[];
 for(const item of work){
  if(item.assigneeUserId===null){unassignedWork.push(item);continue;}
  const rows=byOwner.get(item.assigneeUserId);
  if(rows)rows.push(item);else unassignedWork.push(item);
 }
 const loads=members.map(member=>summarizeMemberLoad(member,byOwner.get(member.userId)??[],config,now));
 const unassigned=summarizeMemberLoad({
  userId:"UNASSIGNED",name:"Unassigned or no longer a member",role:"NONE",
 },unassignedWork,config,now);
 const sort=(a:MemberLoad,b:MemberLoad)=>{
  if(config.sort==="MEMBER")return a.name.localeCompare(b.name)||a.id.localeCompare(b.id);
  if(config.sort==="ACTIVE")return b.active-a.active||a.id.localeCompare(b.id);
  if(config.sort==="OVERDUE")return b.overdue-a.overdue||a.id.localeCompare(b.id);
  return b.attentionPoints-a.attentionPoints||a.id.localeCompare(b.id);
 };
 loads.sort(sort);
 const totals=[...loads,unassigned];
 const add=(key:keyof Pick<MemberLoad,"active"|"closed"|"urgent"|"blocked"|
  "overdue"|"upcoming"|"stale"|"pendingHandoffs"|"attentionPoints">)=>
  totals.reduce((sum,member)=>sum+member[key],0);
 const activeLoads=loads.map(item=>item.active);
 return {config,generatedAt:now.toISOString(),members:loads,unassigned,
  summary:{members:loads.length,tasks:work.length,active:add("active"),
   closed:add("closed"),assigned:work.length-unassignedWork.length,
   unassigned:unassignedWork.length,overdue:add("overdue"),urgent:add("urgent"),
   blocked:add("blocked"),upcoming:add("upcoming"),stale:add("stale"),
   pendingHandoffs:add("pendingHandoffs"),attentionPoints:add("attentionPoints"),
   maxActive:Math.max(0,...activeLoads),minActive:activeLoads.length?
    Math.min(...activeLoads):0},
  coverage:{complete:true,taskLimit:MAX_WORK,memberLimit:MAX_MEMBERS,
   taskPreviewLimit:config.maxTasks,
   note:"The full bounded inventory informs totals; per-person task lists are previews."},
  disclaimer:"Assigned task counts are not working hours, personal productivity ratings or independent control verification."};
}
export async function loadCapacityReport(context:WorkContext,raw:unknown,now=new Date()):Promise<CapacityReport>{
 const config=parseCapacityConfig(raw);
 if(config.scope==="TEAM"&&!canManageWork(context.role)&&context.role!=="AUDITOR")
  throw new WorkInputError("FORBIDDEN","Team workload requires management or auditor access.");
 const where={organizationId:context.organizationId,
  ...(config.scope==="MINE"?{assigneeUserId:context.userId}:{}),
  ...(!config.includeClosed?{status:{notIn:["DONE","CANCELLED"] as ["DONE","CANCELLED"]}}:{})};
 const [count,work,memberCount,members]=await db.$transaction([
  db.remediationWorkItem.count({where}),
  db.remediationWorkItem.findMany({where,take:MAX_WORK+1,orderBy:{id:"asc"},
   select:{id:true,title:true,status:true,priority:true,assigneeUserId:true,
    dueAt:true,updatedAt:true,finding:{select:{severity:true}},
    checklist:{where:{organizationId:context.organizationId},select:{completedAt:true}},
    handoffs:{where:{organizationId:context.organizationId,status:"REQUESTED"},
     select:{status:true}}}}),
  db.membership.count({where:{organizationId:context.organizationId}}),
  db.membership.findMany({where:{organizationId:context.organizationId},
   take:MAX_MEMBERS+1,orderBy:{userId:"asc"},
   select:{userId:true,role:true,user:{select:{name:true}}}}),
 ]);
 if(count>MAX_WORK||work.length!==count||memberCount>MAX_MEMBERS||members.length!==memberCount)
  throw new WorkInputError("CONFLICT","Workload inventory exceeds complete reporting limits.");
 const eligible=config.scope==="MINE"?
  members.filter(member=>member.userId===context.userId):members;
 return buildCapacityReport(work.map(item=>({
  id:item.id,title:item.title,status:item.status,priority:item.priority,
  assigneeUserId:item.assigneeUserId,dueAt:item.dueAt,updatedAt:item.updatedAt,
  findingSeverity:item.finding.severity,checklist:item.checklist,handoffs:item.handoffs,
 })),eligible.map(member=>({userId:member.userId,
  name:member.user.name??member.userId,role:member.role})),config,now);
}
