import {db} from "@cyberpilot/database";
import {WorkInputError} from "./remediation-work-input";
import type {WorkContext} from "./remediation-work-store";

/** A digest summarizes real operational records, not security verification. */
export type DigestWindow=7|14|30|60|90;
export type DigestScope="MINE"|"TEAM"|"UNASSIGNED";
export type DigestConfig={scope:DigestScope;days:DigestWindow;includeClosed:boolean;maxItems:number;};
export type DigestWork={
 id:string;title:string;status:string;priority:string;
 assigneeUserId:string|null;assigneeName:string|null;
 dueAt:Date|null;createdAt:Date;updatedAt:Date;
 findingTitle:string;findingSeverity:string;
 checklist:{completedAt:Date|null}[];
 evidenceLinks:{unlinkedAt:Date|null}[];
 handoffs:{status:string;expiresAt:Date|null}[];
};
export type DigestItem={
 id:string;title:string;status:string;priority:string;
 owner:string;dueAt:string|null;reasons:string[];weight:number;
 daysOverdue:number|null;daysIdle:number;
 checklistDone:number;checklistTotal:number;activeEvidence:number;pendingHandoffs:number;
};
export type DigestSummary={
 total:number;open:number;closed:number;overdue:number;blocked:number;unassigned:number;
 urgent:number;stale:number;missingEvidence:number;incompleteChecklist:number;
 pendingHandoffs:number;dueWithinWindow:number;
};
export type DigestResult={
 config:DigestConfig;generatedAt:string;cutoff:string;
 summary:DigestSummary;priorities:DigestItem[];
 followUps:{kind:string;count:number;recommendation:string}[];
 coverage:{complete:boolean;inventory:number;limit:number;excludedFromPreview:number};
 disclaimer:string;
};
const DAY=86400000;
const WINDOWS=[7,14,30,60,90] as const;
const SCOPES=["MINE","TEAM","UNASSIGNED"] as const;
const LIMIT=2000;
export function parseDigestConfig(raw:unknown):DigestConfig{
 if(raw===null||typeof raw!=="object"||Array.isArray(raw))
  throw new WorkInputError("INVALID","Digest parameters must be an object.");
 const data=raw as Record<string,unknown>;
 for(const key of Object.keys(data)){
  if(!["scope","days","includeClosed","maxItems"].includes(key))
   throw new WorkInputError("INVALID",`Unsupported digest option: ${key}.`);
 }
 const scope=data.scope===undefined?"MINE":data.scope;
 const days=data.days===undefined?14:data.days;
 const includeClosed=data.includeClosed===undefined?false:data.includeClosed;
 const maxItems=data.maxItems===undefined?30:data.maxItems;
 if(typeof scope!=="string"||!SCOPES.some(x=>x===scope))
  throw new WorkInputError("INVALID","Unknown digest ownership scope.");
 if(typeof days!=="number"||!WINDOWS.some(x=>x===days))
  throw new WorkInputError("INVALID","Invalid digest horizon.");
 if(typeof includeClosed!=="boolean")
  throw new WorkInputError("INVALID","Closed work switch must be boolean.");
 if(typeof maxItems!=="number"||!Number.isSafeInteger(maxItems)||maxItems<1||maxItems>100)
  throw new WorkInputError("INVALID","Digest preview limit must be between 1 and 100.");
 return {scope:scope as DigestScope,days:days as DigestWindow,includeClosed,maxItems};
}
export function evaluateDigestWork(work:DigestWork,now:Date,days:DigestWindow):DigestItem{
 const finished=work.status==="DONE"||work.status==="CANCELLED";
 const dueDays=work.dueAt===null?null:Math.ceil((work.dueAt.getTime()-now.getTime())/DAY);
 const daysOverdue=finished||dueDays===null||dueDays>=0?null:-dueDays;
 const daysIdle=Math.max(0,Math.floor((now.getTime()-work.updatedAt.getTime())/DAY));
 const checklistTotal=work.checklist.length;
 const checklistDone=work.checklist.filter(item=>item.completedAt!==null).length;
 const activeEvidence=work.evidenceLinks.filter(item=>item.unlinkedAt===null).length;
 const pendingHandoffs=work.handoffs.filter(item=>item.status==="REQUESTED").length;
 const reasons:string[]=[];
 if(!finished){
  if(daysOverdue!==null)reasons.push("OVERDUE");
  else if(dueDays!==null&&dueDays<=days)reasons.push("DUE_WITHIN_WINDOW");
  if(work.status==="BLOCKED")reasons.push("BLOCKED");
  if(work.assigneeUserId===null)reasons.push("UNASSIGNED");
  if(work.priority==="URGENT")reasons.push("URGENT");
  if(daysIdle>=14)reasons.push("STALE");
  if(activeEvidence===0)reasons.push("MISSING_EVIDENCE_LINK");
  if(checklistTotal===0||checklistDone<checklistTotal)reasons.push("CHECKLIST_GAP");
  if(pendingHandoffs>0)reasons.push("PENDING_HANDOFF");
 }
 const weights:Record<string,number>={
  OVERDUE:35,DUE_WITHIN_WINDOW:12,BLOCKED:25,UNASSIGNED:18,URGENT:22,
  STALE:15,MISSING_EVIDENCE_LINK:8,CHECKLIST_GAP:8,PENDING_HANDOFF:20,
 };
 const weight=reasons.reduce((score,reason)=>score+(weights[reason]??0),0)+
  (finished?0:work.findingSeverity==="CRITICAL"?15:work.findingSeverity==="HIGH"?8:0);
 return {id:work.id,title:work.title,status:work.status,priority:work.priority,
  owner:work.assigneeName??"Unassigned",dueAt:work.dueAt?.toISOString()??null,
  reasons,weight,daysOverdue,daysIdle,checklistDone,checklistTotal,
  activeEvidence,pendingHandoffs};
}
export function buildDigest(work:readonly DigestWork[],config:DigestConfig,now:Date):DigestResult{
 const evaluated=work.map(item=>evaluateDigestWork(item,now,config.days));
 const summary:DigestSummary={total:work.length,open:0,closed:0,overdue:0,blocked:0,
  unassigned:0,urgent:0,stale:0,missingEvidence:0,incompleteChecklist:0,
  pendingHandoffs:0,dueWithinWindow:0};
 for(let index=0;index<work.length;index++){
  const item=work[index]!,result=evaluated[index]!;
  if(item.status==="DONE"||item.status==="CANCELLED"){summary.closed++;continue;}
  summary.open++;
  for(const [reason,key] of [
   ["OVERDUE","overdue"],["BLOCKED","blocked"],["UNASSIGNED","unassigned"],
   ["URGENT","urgent"],["STALE","stale"],["MISSING_EVIDENCE_LINK","missingEvidence"],
   ["CHECKLIST_GAP","incompleteChecklist"],["PENDING_HANDOFF","pendingHandoffs"],
   ["DUE_WITHIN_WINDOW","dueWithinWindow"],
  ] as const){if(result.reasons.includes(reason))summary[key]++;}
 }
 const prioritized=[...evaluated].sort((a,b)=>b.weight-a.weight||
  (a.dueAt??"9999").localeCompare(b.dueAt??"9999")||a.id.localeCompare(b.id));
 const followUps=[
  {kind:"OVERDUE",count:summary.overdue,recommendation:"Review overdue targets and record revised plans."},
  {kind:"BLOCKED",count:summary.blocked,recommendation:"Resolve tracked blockers with responsible owners."},
  {kind:"UNASSIGNED",count:summary.unassigned,recommendation:"Assign eligible organization members."},
  {kind:"PENDING_HANDOFF",count:summary.pendingHandoffs,recommendation:"Request explicit recipient handoff decisions."},
  {kind:"STALE",count:summary.stale,recommendation:"Request updates for inactive operational records."},
  {kind:"MISSING_EVIDENCE_LINK",count:summary.missingEvidence,
   recommendation:"Link available supporting evidence; verify independently."},
  {kind:"CHECKLIST_GAP",count:summary.incompleteChecklist,
   recommendation:"Review required operational checklist steps."},
 ].filter(item=>item.count>0);
 return {config,generatedAt:now.toISOString(),
  cutoff:new Date(now.getTime()+config.days*DAY).toISOString(),
  summary,priorities:prioritized.slice(0,config.maxItems),followUps,
  coverage:{complete:true,inventory:work.length,limit:LIMIT,
   excludedFromPreview:Math.max(0,work.length-config.maxItems)},
  disclaimer:"Digest is a live snapshot of recorded coordination, not a scheduled notification or security certification."};
}
export async function loadDigest(context:WorkContext,raw:unknown,now=new Date()):Promise<DigestResult>{
 const config=parseDigestConfig(raw);
 if(config.scope==="TEAM"&&context.role!=="OWNER"&&context.role!=="ADMIN"&&context.role!=="AUDITOR")
  throw new WorkInputError("FORBIDDEN","Team digest requires admin, owner or auditor access.");
 const where={organizationId:context.organizationId,
  ...(config.scope==="MINE"?{assigneeUserId:context.userId}:{}),
  ...(config.scope==="UNASSIGNED"?{assigneeUserId:null}:{}),
  ...(!config.includeClosed?{status:{notIn:["DONE","CANCELLED"] as ["DONE","CANCELLED"]}}:{}),
 };
 const [count,records]=await db.$transaction([
  db.remediationWorkItem.count({where}),
  db.remediationWorkItem.findMany({where,take:LIMIT+1,orderBy:{id:"asc"},
   select:{id:true,title:true,status:true,priority:true,assigneeUserId:true,
    dueAt:true,createdAt:true,updatedAt:true,assignee:{select:{name:true}},
    finding:{select:{severity:true}},
    checklist:{where:{organizationId:context.organizationId},select:{completedAt:true}},
    evidenceLinks:{where:{organizationId:context.organizationId},select:{unlinkedAt:true}},
    handoffs:{where:{organizationId:context.organizationId,status:"REQUESTED"},
     select:{status:true,expiresAt:true}},
   }}),
 ]);
 if(count>LIMIT||records.length!==count)
  throw new WorkInputError("CONFLICT","Digest exceeds 2,000 work records; choose a narrower scope.");
 return buildDigest(records.map(item=>({
  id:item.id,title:item.title,status:item.status,priority:item.priority,
  assigneeUserId:item.assigneeUserId,assigneeName:item.assignee?.name??null,
  dueAt:item.dueAt,createdAt:item.createdAt,updatedAt:item.updatedAt,
  findingTitle:"",findingSeverity:item.finding.severity,
  checklist:item.checklist,evidenceLinks:item.evidenceLinks,handoffs:item.handoffs,
 })),config,now);
}
