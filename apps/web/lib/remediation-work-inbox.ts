import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { WorkInputError, type WorkStatus, type WorkPriority } from "./remediation-work-input";
import type { WorkContext } from "./remediation-work-store";

/**
 * Actionable personal operations inbox.
 * Every query is scoped to the authenticated membership's organization.
 * This reads existing work and handoffs; it does not infer verification.
 */
export const INBOX_LIMITS = [20, 50, 100] as const;
export type InboxView = "MINE" | "TEAM" | "UNASSIGNED" | "HANDOFFS";
export type InboxUrgency = "ALL" | "OVERDUE" | "DUE_SOON" | "BLOCKED" | "URGENT" | "NO_DATE";
export type InboxSort = "ATTENTION" | "DUE" | "UPDATED" | "PRIORITY";
export type InboxFilter = {
  view: InboxView;
  urgency: InboxUrgency;
  sort: InboxSort;
  search: string;
  includeClosed: boolean;
  page: number;
  pageSize: 20 | 50 | 100;
};
export type InboxWork = {
  id: string;
  title: string;
  description: string;
  status: WorkStatus;
  priority: WorkPriority;
  revision: number;
  assigneeUserId: string | null;
  dueAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  finding: { title: string; severity: string; status: string };
  remediation: { title: string; status: string };
  assignee: { id: string; name: string } | null;
};
export type InboxHandoff = {
  id: string;
  workItemId: string;
  recipientUserId: string;
  requesterUserId: string | null;
  status: string;
  reason: string;
  requestedAt: Date;
  expiresAt: Date | null;
  workItem: { id: string; title: string; status: WorkStatus; revision: number };
};
export type InboxAttention = "CRITICAL" | "HIGH" | "NORMAL" | "LOW" | "CLOSED";
export type InboxRow = {
  id: string;
  title: string;
  description: string;
  status: WorkStatus;
  priority: WorkPriority;
  revision: number;
  dueAt: string | null;
  updatedAt: string;
  assigneeUserId: string | null;
  assigneeName: string | null;
  findingTitle: string;
  findingSeverity: string;
  findingStatus: string;
  remediationTitle: string;
  remediationStatus: string;
  attention: InboxAttention;
  attentionReasons: string[];
  ageDays: number;
  dueDays: number | null;
  handoffCount: number;
  pendingForMe: number;
  handoffExpiresSoon: boolean;
  proposedNextAction: string;
};
export type InboxSummary = {
  total: number;
  open: number;
  blocked: number;
  overdue: number;
  dueSoon: number;
  urgent: number;
  unassigned: number;
  closed: number;
  pendingHandoffs: number;
  attention: Record<InboxAttention, number>;
};
export type InboxPage = {
  filter: InboxFilter;
  page: number;
  pages: number;
  pageSize: number;
  total: number;
  rows: InboxRow[];
  summary: InboxSummary;
  handoffs: {
    pendingForMe: number;
    expiringSoon: number;
    rows: {
      id: string;
      workItemId: string;
      title: string;
      reason: string;
      requestedAt: string;
      expiresAt: string | null;
    }[];
    truncated: boolean;
  };
  coverage: {
    summaryScope: "MATCHING_FILTER";
    resultScope: "ONE_PAGE";
    snapshotAt: string;
    note: string;
  };
};
const MS_DAY = 86400000;
const CLOSED: WorkStatus[] = ["DONE", "CANCELLED"];
const urgencySet = ["ALL", "OVERDUE", "DUE_SOON", "BLOCKED", "URGENT", "NO_DATE"] as const;
const views = ["MINE", "TEAM", "UNASSIGNED", "HANDOFFS"] as const;
const sorts = ["ATTENTION", "DUE", "UPDATED", "PRIORITY"] as const;
const priorityRank: Record<WorkPriority,number> = {
  URGENT: 4, HIGH: 3, NORMAL: 2, LOW: 1,
};
const severityRank: Record<string,number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};
function choice<T extends string>(value:unknown, allowed:readonly T[], fallback:T):T {
  return typeof value === "string" && allowed.includes(value as T) ? value as T : fallback;
}
function numberField(value:unknown, defaultValue:number, maximum:number):number {
  if (typeof value !== "string" || !/^\d{1,6}$/.test(value)) return defaultValue;
  return Math.min(maximum, Math.max(1, Number(value)));
}
export function parseInboxFilter(raw:Record<string,unknown>):InboxFilter {
  const view=choice(raw.view,views,"MINE");
  const urgency=choice(raw.urgency,urgencySet,"ALL");
  const sort=choice(raw.sort,sorts,"ATTENTION");
  const search=typeof raw.search==="string"?raw.search.trim().slice(0,100):"";
  const includeClosed=raw.includeClosed==="true";
  const page=numberField(raw.page,1,100000);
  const pageSize=raw.pageSize==="50"?50:raw.pageSize==="100"?100:20;
  return {view,urgency,sort,search,includeClosed,page,pageSize};
}
export function inboxWhere(
  context:WorkContext,filter:InboxFilter,now:Date,
):Prisma.RemediationWorkItemWhereInput {
  const where:Prisma.RemediationWorkItemWhereInput={organizationId:context.organizationId};
  if(!filter.includeClosed)where.status={notIn:CLOSED};
  if(filter.view==="MINE")where.assigneeUserId=context.userId;
  if(filter.view==="UNASSIGNED")where.assigneeUserId=null;
  if(filter.view==="HANDOFFS")where.handoffs={some:{
    organizationId:context.organizationId,
    recipientUserId:context.userId,status:"REQUESTED",
  }};
  if(filter.search)where.OR=[
    {title:{contains:filter.search,mode:"insensitive"}},
    {description:{contains:filter.search,mode:"insensitive"}},
    {finding:{title:{contains:filter.search,mode:"insensitive"}}},
    {remediation:{title:{contains:filter.search,mode:"insensitive"}}},
  ];
  if(filter.urgency==="BLOCKED")where.status="BLOCKED";
  if(filter.urgency==="URGENT")where.priority="URGENT";
  if(filter.urgency==="NO_DATE")where.dueAt=null;
  if(filter.urgency==="OVERDUE"){
    where.status={notIn:CLOSED};where.dueAt={lt:now};
  }
  if(filter.urgency==="DUE_SOON"){
    where.status={notIn:CLOSED};
    where.dueAt={gte:now,lte:new Date(now.getTime()+7*MS_DAY)};
  }
  return where;
}
export function classifyInboxWork(
  work:InboxWork,now:Date,handoffs:readonly InboxHandoff[]=[],userId="",
):InboxRow {
  const closed=CLOSED.includes(work.status);
  const dueDays=work.dueAt===null?null:
    Math.ceil((work.dueAt.getTime()-now.getTime())/MS_DAY);
  const ageDays=Math.max(0,Math.floor((now.getTime()-work.createdAt.getTime())/MS_DAY));
  const pending=handoffs.filter(item=>item.workItemId===work.id &&
    item.status==="REQUESTED");
  const pendingForMe=pending.filter(item=>item.recipientUserId===userId).length;
  const expiring=pending.some(item=>item.recipientUserId===userId &&
    item.expiresAt!==null && item.expiresAt.getTime()<=now.getTime()+2*MS_DAY);
  const reasons:string[]=[];
  let attention:InboxAttention="NORMAL";
  if(closed)attention="CLOSED";
  else {
    if(dueDays!==null&&dueDays<0)reasons.push("Past its target date");
    if(work.status==="BLOCKED")reasons.push("Work is blocked");
    if(work.priority==="URGENT")reasons.push("Marked urgent by the team");
    if(work.finding.severity==="CRITICAL")reasons.push("Related finding is critical");
    if(pendingForMe)reasons.push("A handoff awaits your decision");
    if(expiring)reasons.push("Handoff expiry is approaching or passed");
    if(work.assigneeUserId===null)reasons.push("No assignee");
    if(dueDays!==null&&dueDays>=0&&dueDays<=7)reasons.push("Target date within seven days");
    if(dueDays!==null&&dueDays<0 || expiring ||
       work.finding.severity==="CRITICAL"&&work.priority==="URGENT")
      attention="CRITICAL";
    else if(work.status==="BLOCKED"||pendingForMe>0||
      work.priority==="URGENT"||dueDays!==null&&dueDays<=2)
      attention="HIGH";
    else if(dueDays!==null&&dueDays<=7||
      work.assigneeUserId===null||work.priority==="HIGH")
      attention="NORMAL";
    else attention="LOW";
  }
  const proposedNextAction=closed
    ?"Review the recorded work outcome separately from finding verification."
    :pendingForMe>0
    ?"Accept or decline the requested handoff before changing ownership."
    :work.status==="BLOCKED"
    ?"Record the blocker and coordinate the dependency with the responsible person."
    :dueDays!==null&&dueDays<0
    ?"Review the missed target date, update the plan and record the reason."
    :work.assigneeUserId===null
    ?"Assign an organization member who can take responsibility."
    :work.status==="TODO"
    ?"Confirm the task owner and record when work actually begins."
    :"Continue the assigned work and document what was completed.";
  return {
    id:work.id,title:work.title,description:work.description,
    status:work.status,priority:work.priority,revision:work.revision,
    dueAt:work.dueAt?.toISOString()??null,updatedAt:work.updatedAt.toISOString(),
    assigneeUserId:work.assigneeUserId,assigneeName:work.assignee?.name??null,
    findingTitle:work.finding.title,findingSeverity:work.finding.severity,
    findingStatus:work.finding.status,remediationTitle:work.remediation.title,
    remediationStatus:work.remediation.status,
    attention,attentionReasons:reasons,ageDays,dueDays,
    handoffCount:pending.length,pendingForMe,handoffExpiresSoon:expiring,
    proposedNextAction,
  };
}
const attentionRank:Record<InboxAttention,number>={
  CRITICAL:0,HIGH:1,NORMAL:2,LOW:3,CLOSED:4,
};
export function orderInboxRows(rows:readonly InboxRow[],sort:InboxSort):InboxRow[]{
  return [...rows].sort((a,b)=>{
    const attention=attentionRank[a.attention]-attentionRank[b.attention];
    const due=(a.dueAt===null?Infinity:Date.parse(a.dueAt))-
      (b.dueAt===null?Infinity:Date.parse(b.dueAt));
    const updated=Date.parse(b.updatedAt)-Date.parse(a.updatedAt);
    const priority=priorityRank[b.priority]-priorityRank[a.priority];
    const severity=(severityRank[b.findingSeverity]??0)-
      (severityRank[a.findingSeverity]??0);
    if(sort==="DUE")return due||attention||priority||a.id.localeCompare(b.id);
    if(sort==="UPDATED")return updated||attention||a.id.localeCompare(b.id);
    if(sort==="PRIORITY")return priority||severity||attention||a.id.localeCompare(b.id);
    return attention||priority||severity||due||updated||a.id.localeCompare(b.id);
  });
}
export function summarizeInbox(rows:readonly InboxRow[]):InboxSummary{
  const attention:Record<InboxAttention,number>={
    CRITICAL:0,HIGH:0,NORMAL:0,LOW:0,CLOSED:0,
  };
  const result:InboxSummary={
    total:rows.length,open:0,blocked:0,overdue:0,dueSoon:0,
    urgent:0,unassigned:0,closed:0,pendingHandoffs:0,attention,
  };
  for(const row of rows){
    attention[row.attention]++;
    if(row.attention==="CLOSED")result.closed++;
    else {
      result.open++;
      if(row.status==="BLOCKED")result.blocked++;
      if(row.dueDays!==null&&row.dueDays<0)result.overdue++;
      if(row.dueDays!==null&&row.dueDays>=0&&row.dueDays<=7)result.dueSoon++;
      if(row.priority==="URGENT")result.urgent++;
      if(row.assigneeUserId===null)result.unassigned++;
      result.pendingHandoffs+=row.pendingForMe;
    }
  }
  return result;
}
const select={
  id:true,title:true,description:true,status:true,priority:true,revision:true,
  assigneeUserId:true,dueAt:true,completedAt:true,createdAt:true,updatedAt:true,
  finding:{select:{title:true,severity:true,status:true}},
  remediation:{select:{title:true,status:true}},
  assignee:{select:{id:true,name:true}},
} as const;
export async function getWorkInbox(context:WorkContext,query:Record<string,unknown>,now=new Date()):Promise<InboxPage>{
  const filter=parseInboxFilter(query);
  const where=inboxWhere(context,filter,now);
  // The summary covers the entire matching set, not only the visible page.
  // Limit to 2,000 and reject incomplete snapshots instead of hiding omissions.
  const [count,items,handoffCount,handoffs]=await db.$transaction([
    db.remediationWorkItem.count({where}),
    db.remediationWorkItem.findMany({
      where,select,orderBy:[{updatedAt:"desc"},{id:"asc"}],take:2001,
    }),
    db.workHandoff.count({where:{
      organizationId:context.organizationId,recipientUserId:context.userId,
      status:"REQUESTED",
    }}),
    db.workHandoff.findMany({
      where:{organizationId:context.organizationId,recipientUserId:context.userId,status:"REQUESTED"},
      select:{
        id:true,workItemId:true,recipientUserId:true,requesterUserId:true,
        status:true,reason:true,requestedAt:true,expiresAt:true,
        workItem:{select:{id:true,title:true,status:true,revision:true}},
      },
      orderBy:[{requestedAt:"desc"},{id:"desc"}],take:101,
    }),
  ]);
  if(count>2000 || items.length!==count)
    throw new WorkInputError("CONFLICT",
      "Inbox inventory exceeds the complete-snapshot limit (2,000); narrow the filters.");
  const relevantHandoffs=await db.workHandoff.findMany({
    where:{
      organizationId:context.organizationId,status:"REQUESTED",
      workItemId:{in:items.map(item=>item.id)},
    },
    select:{
      id:true,workItemId:true,recipientUserId:true,requesterUserId:true,
      status:true,reason:true,requestedAt:true,expiresAt:true,
      workItem:{select:{id:true,title:true,status:true,revision:true}},
    },
    take:2001,
  });
  if(relevantHandoffs.length>2000)
    throw new WorkInputError("CONFLICT","Too many unresolved handoffs for a complete inbox snapshot.");
  const rows=orderInboxRows(
    items.map(item=>classifyInboxWork(item,now,relevantHandoffs,context.userId)),
    filter.sort,
  );
  const page=Math.min(filter.page,Math.max(1,Math.ceil(count/filter.pageSize)));
  const start=(page-1)*filter.pageSize;
  return {
    filter,page,pages:Math.max(1,Math.ceil(count/filter.pageSize)),
    pageSize:filter.pageSize,total:count,rows:rows.slice(start,start+filter.pageSize),
    summary:summarizeInbox(rows),
    handoffs:{
      pendingForMe:handoffCount,
      expiringSoon:handoffs.filter(item=>item.expiresAt!==null &&
        item.expiresAt.getTime()<=now.getTime()+2*MS_DAY).length,
      rows:handoffs.slice(0,100).map(item=>({
        id:item.id,workItemId:item.workItemId,title:item.workItem.title,
        reason:item.reason,requestedAt:item.requestedAt.toISOString(),
        expiresAt:item.expiresAt?.toISOString()??null,
      })),
      truncated:handoffCount>100,
    },
    coverage:{
      summaryScope:"MATCHING_FILTER",resultScope:"ONE_PAGE",
      snapshotAt:now.toISOString(),
      note:"Operational records only; no evidence was freshly collected or independently verified.",
    },
  };
}
