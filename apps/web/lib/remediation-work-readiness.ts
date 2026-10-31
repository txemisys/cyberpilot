import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {WorkInputError,canManageWork,type WorkStatus,type WorkPriority} from "./remediation-work-input";
import type {WorkContext} from "./remediation-work-store";

/** A readiness review informs humans; it never changes security state. */
export type GateIssue="NO_OWNER"|"NO_CHECKLIST"|"INCOMPLETE_CHECKLIST"|"NO_EVIDENCE"|
 "PENDING_HANDOFF"|"BLOCKED"|"OVERDUE"|"UNCONFIRMED_FINDING"|"CLOSED_WITH_GAPS";
export type GateLevel="READY_FOR_HUMAN_REVIEW"|"REQUIRES_ATTENTION"|"BLOCKED"|"CLOSED_REVIEW";
export type GateScope="MINE"|"TEAM"|"UNASSIGNED";
export type GateFilter={
 scope:GateScope;includeClosed:boolean;requireEvidence:boolean;
 requireChecklist:boolean;onlyExceptions:boolean;search:string;
};
export type GateWork={
 id:string;title:string;revision:number;status:WorkStatus;
 priority:WorkPriority;assigneeUserId:string|null;assigneeName:string|null;
 createdAt:Date;updatedAt:Date;dueAt:Date|null;completedAt:Date|null;
 findingId:string;findingTitle:string;findingStatus:string;findingSeverity:string;
 remediationId:string;remediationTitle:string;remediationStatus:string;
 checklist:{id:string;title:string;completedAt:Date|null}[];
 evidenceLinks:{id:string;evidenceId:string;unlinkedAt:Date|null}[];
 handoffs:{id:string;status:string;expiresAt:Date|null}[];
};
export type GateDecision={
 id:string;title:string;revision:number;status:WorkStatus;priority:WorkPriority;
 assigneeUserId:string|null;assigneeName:string|null;
 findingId:string;findingTitle:string;findingStatus:string;
 findingSeverity:string;remediationId:string;remediationTitle:string;
 remediationStatus:string;level:GateLevel;issues:GateIssue[];
 totalChecklist:number;completedChecklist:number;remainingChecklist:number;
 activeEvidenceLinks:number;pendingHandoffs:number;
 overdueDays:number|null;dateDue:string|null;
 completedAt:string|null;updatedAt:string;recommendation:string;
};
export type GateSummary={
 total:number;ready:number;attention:number;blocked:number;closedReview:number;
 withoutOwner:number;withoutEvidence:number;withoutChecklist:number;
 incompleteChecklist:number;pendingHandoffs:number;overdue:number;
};
export type GateReview={
 generatedAt:string;filter:GateFilter;summary:GateSummary;
 rows:GateDecision[];totalRows:number;
 coverage:{complete:boolean;limit:number;message:string};
 disclaimer:string;
};
const LIMIT=2000;
const DAY=86400000;
const CLOSED=new Set<WorkStatus>(["DONE","CANCELLED"]);
const scopes=["MINE","TEAM","UNASSIGNED"] as const;
const issueOrder:GateIssue[]=[
 "BLOCKED","PENDING_HANDOFF","NO_OWNER","INCOMPLETE_CHECKLIST",
 "NO_CHECKLIST","NO_EVIDENCE","OVERDUE","UNCONFIRMED_FINDING","CLOSED_WITH_GAPS",
];
const ranks:Record<GateLevel,number>={
 BLOCKED:0,REQUIRES_ATTENTION:1,READY_FOR_HUMAN_REVIEW:2,CLOSED_REVIEW:3,
};
export function parseGateFilter(value:unknown):GateFilter{
 if(value===null||typeof value!=="object"||Array.isArray(value))
  throw new WorkInputError("INVALID","Gate filters must be an object.");
 const input=value as Record<string,unknown>;
 for(const key of Object.keys(input))
  if(!["scope","includeClosed","requireEvidence","requireChecklist","onlyExceptions","search"].includes(key))
   throw new WorkInputError("INVALID",`Unknown readiness option: ${key}.`);
 const scope=input.scope===undefined?"MINE":input.scope;
 if(typeof scope!=="string"||!scopes.some(v=>v===scope))
  throw new WorkInputError("INVALID","Invalid readiness scope.");
 const readBool=(field:string,fallback:boolean)=>{
  const raw=input[field];
  if(raw===undefined)return fallback;
  if(typeof raw!=="boolean")throw new WorkInputError("INVALID",`${field} must be boolean.`);
  return raw;
 };
 const search=input.search===undefined?"":input.search;
 if(typeof search!=="string"||search.length>120||/[\u0000-\u001f\u007f]/.test(search))
  throw new WorkInputError("INVALID","Search must be printable text up to 120 characters.");
 return {
  scope:scope as GateScope,
  includeClosed:readBool("includeClosed",false),
  requireEvidence:readBool("requireEvidence",true),
  requireChecklist:readBool("requireChecklist",true),
  onlyExceptions:readBool("onlyExceptions",false),
  search:search.trim(),
 };
}
export function gateWhere(context:WorkContext,filter:GateFilter):Prisma.RemediationWorkItemWhereInput{
 const where:Prisma.RemediationWorkItemWhereInput={organizationId:context.organizationId};
 if(filter.scope==="MINE")where.assigneeUserId=context.userId;
 if(filter.scope==="UNASSIGNED")where.assigneeUserId=null;
 if(!filter.includeClosed)where.status={notIn:["DONE","CANCELLED"]};
 if(filter.search)where.OR=[
  {title:{contains:filter.search,mode:"insensitive"}},
  {description:{contains:filter.search,mode:"insensitive"}},
  {finding:{title:{contains:filter.search,mode:"insensitive"}}},
  {remediation:{title:{contains:filter.search,mode:"insensitive"}}},
 ];
 return where;
}
export function assessGate(task:GateWork,filter:GateFilter,now:Date):GateDecision{
 const isClosed=CLOSED.has(task.status);
 const checklist=task.checklist;
 const remaining=checklist.filter(entry=>entry.completedAt===null).length;
 const activeEvidence=task.evidenceLinks.filter(link=>link.unlinkedAt===null).length;
 const pendingHandoffs=task.handoffs.filter(handoff=>handoff.status==="REQUESTED").length;
 const overdueDays=!isClosed&&task.dueAt&&task.dueAt.getTime()<now.getTime()
  ?Math.max(1,Math.ceil((now.getTime()-task.dueAt.getTime())/DAY)):null;
 const issues:GateIssue[]=[];
 if(task.status==="BLOCKED")issues.push("BLOCKED");
 if(pendingHandoffs>0)issues.push("PENDING_HANDOFF");
 if(task.assigneeUserId===null)issues.push("NO_OWNER");
 if(filter.requireChecklist){
  if(!checklist.length)issues.push("NO_CHECKLIST");
  else if(remaining)issues.push("INCOMPLETE_CHECKLIST");
 }
 if(filter.requireEvidence&&!activeEvidence)issues.push("NO_EVIDENCE");
 if(overdueDays!==null)issues.push("OVERDUE");
 if(task.findingStatus!=="RESOLVED"&&task.findingStatus!=="VERIFIED")
  issues.push("UNCONFIRMED_FINDING");
 const hardBlock=issues.some(x=>x==="BLOCKED"||x==="PENDING_HANDOFF");
 const operationalGaps=issues.some(x=>[
  "NO_OWNER","NO_CHECKLIST","INCOMPLETE_CHECKLIST","NO_EVIDENCE","OVERDUE"
 ].includes(x));
 if(isClosed&&operationalGaps)issues.push("CLOSED_WITH_GAPS");
 const level:GateLevel=isClosed?"CLOSED_REVIEW":hardBlock?"BLOCKED":
  operationalGaps?"REQUIRES_ATTENTION":"READY_FOR_HUMAN_REVIEW";
 const recommendation=isClosed
  ?"Review recorded work closure and outstanding supporting records separately from finding verification."
  :hardBlock
  ?"Resolve blocked work and outstanding responsibility handoffs before closure review."
  :task.assigneeUserId===null
  ?"Assign a responsible organization member before proceeding."
  :remaining>0&&filter.requireChecklist
  ?"Complete or review remaining checklist steps with their supporting records."
  :checklist.length===0&&filter.requireChecklist
  ?"Create a work checklist that documents the expected operational steps."
  :activeEvidence===0&&filter.requireEvidence
  ?"Link available evidence references before requesting independent security review."
  :overdueDays!==null
  ?"Review the missed deadline and record an updated operational plan."
  :"Ready for a human operational review; independently verify the finding in its own workflow.";
 return {
  id:task.id,title:task.title,revision:task.revision,status:task.status,
  priority:task.priority,assigneeUserId:task.assigneeUserId,
  assigneeName:task.assigneeName,findingId:task.findingId,
  findingTitle:task.findingTitle,findingStatus:task.findingStatus,
  findingSeverity:task.findingSeverity,remediationId:task.remediationId,
  remediationTitle:task.remediationTitle,remediationStatus:task.remediationStatus,
  level,issues:issueOrder.filter(issue=>issues.includes(issue)),
  totalChecklist:checklist.length,completedChecklist:checklist.length-remaining,
  remainingChecklist:remaining,activeEvidenceLinks:activeEvidence,
  pendingHandoffs,overdueDays,dateDue:task.dueAt?.toISOString()??null,
  completedAt:task.completedAt?.toISOString()??null,
  updatedAt:task.updatedAt.toISOString(),recommendation,
 };
}
export function sortGateDecisions(rows:readonly GateDecision[]):GateDecision[]{
 return [...rows].sort((a,b)=>ranks[a.level]-ranks[b.level]||
  b.issues.length-a.issues.length||
  (a.dateDue??"9999").localeCompare(b.dateDue??"9999")||
  a.id.localeCompare(b.id));
}
export function summarizeGates(rows:readonly GateDecision[]):GateSummary{
 const result:GateSummary={
  total:rows.length,ready:0,attention:0,blocked:0,closedReview:0,
  withoutOwner:0,withoutEvidence:0,withoutChecklist:0,
  incompleteChecklist:0,pendingHandoffs:0,overdue:0,
 };
 for(const row of rows){
  if(row.level==="READY_FOR_HUMAN_REVIEW")result.ready++;
  if(row.level==="REQUIRES_ATTENTION")result.attention++;
  if(row.level==="BLOCKED")result.blocked++;
  if(row.level==="CLOSED_REVIEW")result.closedReview++;
  if(row.issues.includes("NO_OWNER"))result.withoutOwner++;
  if(row.issues.includes("NO_EVIDENCE"))result.withoutEvidence++;
  if(row.issues.includes("NO_CHECKLIST"))result.withoutChecklist++;
  if(row.issues.includes("INCOMPLETE_CHECKLIST"))result.incompleteChecklist++;
  if(row.issues.includes("PENDING_HANDOFF"))result.pendingHandoffs++;
  if(row.issues.includes("OVERDUE"))result.overdue++;
 }
 return result;
}
export function buildGateReview(
 tasks:readonly GateWork[],filter:GateFilter,now=new Date(),
):GateReview{
 const classified=sortGateDecisions(tasks.map(task=>assessGate(task,filter,now)));
 const rows=filter.onlyExceptions?classified.filter(row=>
  row.level==="BLOCKED"||row.level==="REQUIRES_ATTENTION"||
  row.issues.includes("CLOSED_WITH_GAPS")):classified;
 return {
  generatedAt:now.toISOString(),filter,totalRows:rows.length,
  summary:summarizeGates(classified),rows,
  coverage:{complete:true,limit:LIMIT,
   message:"All matching organization work records were included in this bounded review."},
  disclaimer:"Operational readiness is not evidence validation, independent finding verification or security certification.",
 };
}
export async function loadGateReview(
 context:WorkContext,raw:unknown,now=new Date(),
):Promise<GateReview>{
 const filter=parseGateFilter(raw);
 if(filter.scope==="TEAM"&&!canManageWork(context.role)&&context.role!=="AUDITOR")
  throw new WorkInputError("FORBIDDEN","Team readiness review requires management or audit access.");
 const where=gateWhere(context,filter);
 const [count,rows]=await db.$transaction([
  db.remediationWorkItem.count({where}),
  db.remediationWorkItem.findMany({
   where,orderBy:[{id:"asc"}],take:LIMIT+1,
   select:{
    id:true,title:true,revision:true,status:true,priority:true,
    assigneeUserId:true,createdAt:true,updatedAt:true,dueAt:true,completedAt:true,
    assignee:{select:{name:true}},
    finding:{select:{id:true,title:true,status:true,severity:true}},
    remediation:{select:{id:true,title:true,status:true}},
    checklist:{where:{organizationId:context.organizationId},
     select:{id:true,title:true,completedAt:true}},
    evidenceLinks:{where:{organizationId:context.organizationId,unlinkedAt:null},
     select:{id:true,evidenceId:true,unlinkedAt:true}},
    handoffs:{where:{organizationId:context.organizationId,status:"REQUESTED"},
     select:{id:true,status:true,expiresAt:true}},
   },
  }),
 ]);
 if(count>LIMIT||rows.length!==count)
  throw new WorkInputError("CONFLICT","Readiness review exceeds 2,000 records; narrow the scope.");
 return buildGateReview(rows.map(row=>({
  id:row.id,title:row.title,revision:row.revision,status:row.status,
  priority:row.priority,assigneeUserId:row.assigneeUserId,
  assigneeName:row.assignee?.name??null,
  createdAt:row.createdAt,updatedAt:row.updatedAt,dueAt:row.dueAt,
  completedAt:row.completedAt,
  findingId:row.finding.id,findingTitle:row.finding.title,
  findingStatus:row.finding.status,findingSeverity:row.finding.severity,
  remediationId:row.remediation.id,remediationTitle:row.remediation.title,
  remediationStatus:row.remediation.status,
  checklist:row.checklist,evidenceLinks:row.evidenceLinks,handoffs:row.handoffs,
 })),filter,now);
}
